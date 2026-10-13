"""Authentication monitoring prototype. All response actions are simulations.

Collectors are read-only. No model output is accepted as a command or policy.
The store is separate from the existing incident database.
"""
from __future__ import annotations

from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parent
MAX_BYTES = 16 * 1024 * 1024


def utcnow():
    return datetime.now(timezone.utc)


def stamp(value):
    try:
        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return dt.astimezone(timezone.utc) if dt.tzinfo else None
    except (ValueError, TypeError):
        return None


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def address(value):
    try:
        ip = ipaddress.ip_address(str(value))
        return str(getattr(ip, 'ipv4_mapped', None) or ip)
    except ValueError:
        return None


class TaskStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY, created TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS actions (
                    key TEXT PRIMARY KEY, task_id TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY, task_id TEXT NOT NULL, role TEXT NOT NULL,
                    content TEXT NOT NULL, created TEXT NOT NULL, model TEXT NOT NULL);
            ''')

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def create(self, source, demo=False):
        task = dict(id=uuid.uuid4().hex[:12], created=utcnow().isoformat(), source=source,
                    demo=demo, mode='simulate', status='collecting', stages=[], findings=[], actions=[])
        self.save(task)
        return task

    def save(self, task):
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO tasks VALUES (?, ?, ?)',
                       (task['id'], task['created'], json.dumps(task, ensure_ascii=False)))

    def get(self, task_id):
        with self.connect() as db:
            row = db.execute('SELECT payload FROM tasks WHERE id=?', (task_id,)).fetchone()
        if not row:
            raise ValueError('任务不存在，请先查看任务列表')
        return json.loads(row[0])

    def recent(self, limit=20):
        with self.connect() as db:
            return [json.loads(r[0]) for r in db.execute(
                'SELECT payload FROM tasks ORDER BY created DESC LIMIT ?', (limit,))]

    def commit_actions(self, task):
        # Claim and persist in one transaction. A process restart cannot repeat
        # the same evidence/policy proposal as a new simulated action.
        with self.connect() as db:
            for action in task['actions']:
                if action['status'] != 'simulated':
                    continue
                cursor = db.execute('INSERT OR IGNORE INTO actions VALUES (?, ?)', (action['key'], task['id']))
                if not cursor.rowcount:
                    action['status'] = 'duplicate_skipped'
                    action['previous_task'] = db.execute('SELECT task_id FROM actions WHERE key=?', (action['key'],)).fetchone()[0]
            db.execute('INSERT OR REPLACE INTO tasks VALUES (?, ?, ?)',
                       (task['id'], task['created'], json.dumps(task, ensure_ascii=False)))

    def message(self, task_id, role, content, model):
        self.get(task_id)
        with self.connect() as db:
            db.execute('INSERT INTO messages(task_id,role,content,created,model) VALUES(?,?,?,?,?)',
                       (task_id, role, content, utcnow().isoformat(), model))

    def history(self, task_id, limit=12):
        with self.connect() as db:
            rows = db.execute('SELECT role,content FROM messages WHERE task_id=? ORDER BY id DESC LIMIT ?',
                              (task_id, limit)).fetchall()
        return [dict(role=role, content=content) for role, content in reversed(rows)]


def linux_events(text):
    from server_logs import SSH_FAILURE, SSH_SUCCESS, _host
    events, rejected = [], 0
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            if line.lstrip().startswith('{'):
                row = json.loads(line)
                message = row.get('MESSAGE', '')
                host = row.get('_HOSTNAME', '')
                when = datetime.fromtimestamp(int(row['__REALTIME_TIMESTAMP']) / 1_000_000, timezone.utc)
                identity = row.get('__CURSOR') or digest(line)
                process = row.get('SYSLOG_IDENTIFIER') or row.get('_COMM', '')
                trusted_process = process in ('sshd', 'sshd-session', 'sshd-auth')
            else:
                message, host = line, _host(line)
                when = stamp(line.split(' ', 1)[0])
                identity = digest(line)
                trusted_process = bool(re.match(r'^\S+\s+\S+\s+sshd(?:-session|-auth)?\[\d+\]:', line))
            failure, success = SSH_FAILURE.search(message), SSH_SUCCESS.search(message)
            match = failure or success
            ip = address(match['ip']) if match else None
            if not (trusted_process and match and ip and host and when):
                rejected += 1
                continue
            events.append(dict(platform='linux', host=host, account=match['account'], ip=ip,
                               kind='failure' if failure else 'success', time=when.isoformat(),
                               identity=str(identity), ref=f'ssh:{number}', raw=line[:4096],
                               raw_sha256=hashlib.sha256(line.encode()).hexdigest(), raw_truncated=len(line) > 4096))
        except (ValueError, TypeError, KeyError, OverflowError, OSError, AttributeError):
            rejected += 1
    return events, rejected


def windows_events(rows):
    sys.path.insert(0, str(ROOT / 'backend')) if str(ROOT / 'backend') not in sys.path else None
    from app.agents.event_context import extract_event_context
    events, rejected = [], 0
    for number, row in enumerate(rows, 1):
        raw = json.dumps(row, ensure_ascii=False)
        r = extract_event_context(raw)
        when, ip = stamp(r['timestamp']), address(r['source_ip'])
        if (str(r['channel']).casefold() != 'security' or r['event_id'] not in ('4624', '4625')
                or r['record_id'] is None or not (when and ip and r['computer'] and r['username'])):
            rejected += 1
            continue
        events.append(dict(platform='windows', host=r['computer'],
                           account='\\'.join(filter(None, [r['account_domain'], r['username']])),
                           ip=ip, kind='failure' if r['event_id'] == '4625' else 'success',
                           time=when.isoformat(), identity=f"Security:{r['record_id']}:{when.isoformat()}",
                           ref=f"Security:{r['record_id']}", raw=raw[:4096],
                           raw_sha256=hashlib.sha256(raw.encode()).hexdigest(), raw_truncated=len(raw) > 4096))
    return events, rejected


def ssh_target(value):
    if not re.fullmatch(r'(?:[A-Za-z0-9_][A-Za-z0-9_.-]*@)?[A-Za-z0-9][A-Za-z0-9_.-]*', value):
        raise ValueError('SSH 目标应为已配置的别名或 user@主机；端口和密钥请放在 SSH config')
    return value


def collect_linux(target=None, minutes=15, limit=1000):
    if not 1 <= minutes <= 1440 or not 1 <= limit <= 5000:
        raise ValueError('采集范围应为 1–1440 分钟、1–5000 条')
    command = ['journalctl', '--no-pager', '--output=json', '--since', f'{minutes} minutes ago',
               '-n', str(limit), '_COMM=sshd', '_COMM=sshd-session', '_COMM=sshd-auth']
    if target:
        # Only the numeric bounds above enter the fixed remote command. Never
        # insert log text or model text. SSH authenticates with existing keys.
        remote = f"LC_ALL=C journalctl --no-pager --output=json --since '{minutes} minutes ago' -n {limit} _COMM=sshd _COMM=sshd-session _COMM=sshd-auth"
        command = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                   '-o', 'ConnectTimeout=10', ssh_target(target), remote]
    try:
        result = subprocess.run(command, capture_output=True, timeout=45)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('日志采集超时；本轮没有可验证的采集结果') from exc
    if result.returncode:
        detail = result.stderr.decode('utf-8', errors='replace')[:1000]
        raise RuntimeError(f'SSH/journalctl 读取失败（{result.returncode}）：{detail}')
    if len(result.stdout) > MAX_BYTES:
        raise ValueError('本轮日志超过 16 MiB，请缩小时间或条数范围')
    text = result.stdout.decode('utf-8', errors='replace')
    events, rejected = linux_events(text)
    warnings = [result.stderr.decode('utf-8', errors='replace').strip()] if result.stderr.strip() else []
    if len(text.splitlines()) >= limit:
        warnings.append('达到采集上限；更早记录可能未读取，未读数量未知')
    warnings.append(f'仅覆盖 SSH journal，最近 {minutes} 分钟；未采集应用和文件审计日志')
    return dict(events=events, rejected=rejected, warnings=warnings)


def collect_export(directory):
    path = Path(directory).expanduser().resolve() / 'ssh.journal.log'
    if not path.is_file():
        raise ValueError('导出目录缺少 ssh.journal.log；此入口仅分析 SSH 登录')
    if path.stat().st_size > MAX_BYTES:
        raise ValueError('SSH 导出超过 16 MiB，请缩小导出范围')
    data = path.read_bytes()
    events, rejected = linux_events(data.decode('utf-8', errors='replace'))
    return dict(events=events, rejected=rejected, source_sha256=hashlib.sha256(data).hexdigest(),
                warnings=['历史导出仅用于复盘；防护建议不代表当前服务器状态'])


def collect_windows(limit=1000):
    import platform
    if platform.system() != 'Windows':
        raise ValueError('本机 Windows 采集需要在 Windows 上运行')
    sys.path.insert(0, str(ROOT / 'backend')) if str(ROOT / 'backend') not in sys.path else None
    from app.services.log_reader import read_windows_logs
    result = read_windows_logs(channels=['Security'], max_events=limit, suspicious_only=False)
    if result.get('is_mock') or result.get('read_status') == 'failed':
        details = '; '.join(str(row.get('message') or row.get('status')) for row in result.get('channel_results', []))
        raise RuntimeError('未取得真实 Security 日志；请在有读取权限的终端运行。' + details[:1000])
    events, rejected = windows_events(result['events'])
    warnings = ['仅覆盖本机最近的 Security 登录事件；未读事件不能据此判断安全']
    for channel in result.get('channel_results', []):
        if channel.get('status') != 'success':
            warnings.append(str(channel.get('message') or channel.get('status')))
        if channel.get('events_read', 0) >= limit:
            warnings.append('达到采集上限；更早记录可能未读取，未读数量未知')
    return dict(events=events, rejected=rejected, warnings=warnings)


def demo_events(platform):
    base = utcnow().replace(microsecond=0) - timedelta(minutes=3)
    host = 'DEMO-LINUX' if platform == 'linux' else 'DEMO-WINDOWS'
    events = [dict(platform=platform, host=host, account='root' if platform == 'linux' else 'LAB\\demo',
                   ip='192.0.2.50', kind='failure' if i < 6 else 'success',
                   time=(base + timedelta(seconds=i * 20)).isoformat(), identity=f'demo:{i}',
                   ref=f'demo:{i}', raw=f'[合成演示数据] {platform} authentication event {i}') for i in range(7)]
    return dict(events=events, rejected=0, warnings=['合成演示数据，未连接真实主机'])


def detect(collection):
    buckets = defaultdict(list)
    for event in collection['events']:
        buckets[(event['platform'], event['host'], event['identity'])].append(event)
    rows, duplicates, conflicts = [], 0, 0
    for group in buckets.values():
        semantics = [{k: v for k, v in r.items() if k not in ('raw', 'ref', 'raw_sha256', 'raw_truncated')} for r in group]
        if any(r != semantics[0] for r in semantics[1:]):
            conflicts += len(group)
        else:
            rows.append(group[0])
            duplicates += len(group) - 1
    rows.sort(key=lambda r: r['time'])
    groups = defaultdict(list)
    for event in rows:
        if event['kind'] == 'failure':
            groups[(event['platform'], event['host'], event['account'], event['ip'])].append(event)
    findings = []
    for (platform, host, account, ip), failures in groups.items():
        best, left = [], 0
        for right, event in enumerate(failures):
            while (stamp(event['time']) - stamp(failures[left]['time'])).total_seconds() > 300:
                left += 1
            if right - left + 1 >= len(best):
                best = failures[left:right + 1]
        if len(best) < 5:
            continue
        successes = [r for r in rows if (r['platform'], r['host'], r['account'], r['ip']) == (platform, host, account, ip)
                     and r['kind'] == 'success' and 0 < (stamp(r['time']) - stamp(best[-1]['time'])).total_seconds() <= 900]
        evidence = best + successes[:1]
        findings.append(dict(rule='auth_failure_then_success' if successes else 'auth_repeated_failure',
                             title='连续失败后出现成功登录，需核对授权' if successes else '5 分钟内重复登录失败，疑似密码猜测',
                             platform=platform, host=host, account=account, ip=ip,
                             failure_count=len(best), start=best[0]['time'], end=evidence[-1]['time'],
                             refs=[r['ref'] for r in evidence], identities=[r['identity'] for r in evidence],
                             next_steps=['核对来源 IP 与运维授权', '核对登录会话及随后执行的命令', '检查管理入口是否仍可用']))
    return dict(events=rows, findings=findings, coverage=dict(input=len(collection['events']) + collection.get('rejected', 0),
                retained=len(rows), excluded=collection.get('rejected', 0), duplicates=duplicates, conflicts=conflicts),
                time_range=dict(start=rows[0]['time'] if rows else None, end=rows[-1]['time'] if rows else None))


def plan(findings, protected=(), ttl=600, demo=False, source=''):
    if not 60 <= ttl <= 3600:
        raise ValueError('建议封禁期限应为 60–3600 秒')
    networks = [ipaddress.ip_network(item, strict=False) for item in protected]
    actions = []
    for finding in findings:
        ip = ipaddress.ip_address(finding['ip'])
        blocked = (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local
                   or any(ip in network for network in networks))
        action = dict(tool='simulate.block_source_ip', target=finding['host'], platform=finding['platform'],
                      ip=str(ip), ttl_seconds=ttl, evidence_refs=finding['refs'],
                      status='protected_skipped' if blocked else 'simulated',
                      verification='not_performed', actual_system_change=False,
                      reason='管理/保护地址，禁止提出封禁' if blocked else '规则达到阈值；等待核实来源授权',
                      verification_plan=['确认目标主机与 IP', '检查规则是否存在及到期时间',
                                         '从独立管理通道检查可达性', '复查登录失败趋势，不能仅凭日志减少认定有效'],
                      rollback_plan='如后续人工实施，需记录规则标识以便撤销并验证；当前尚未执行，无需恢复')
        action['key'] = digest([source, finding['platform'], finding['host'], str(ip), sorted(finding['identities']),
                                sorted(protected), ttl, demo])
        actions.append(action)
    return actions


class SimulationFirewall:
    """In-memory tool adapter, intentionally has no real execution backend."""
    def __init__(self):
        self.rules = {}

    def apply(self, action, now):
        if action['tool'] != 'simulate.block_source_ip' or action['status'] != 'simulated':
            raise ValueError('模拟执行器仅接受通过本地策略的固定工具')
        self.rules[action['key']] = dict(target=action['target'], ip=action['ip'],
                                         expires=(now + timedelta(seconds=action['ttl_seconds'])).isoformat())

    def verify(self, action, now):
        row = self.rules.get(action['key'])
        return bool(row and row['target'] == action['target'] and row['ip'] == action['ip']
                    and stamp(row['expires']) > now)

    def rollback(self, action):
        self.rules.pop(action['key'], None)


def simulate(actions):
    sandbox = SimulationFirewall()
    now = utcnow()
    for action in actions:
        if action['status'] != 'simulated':
            continue
        sandbox.apply(action, now)
        action['simulation_checks'] = dict(rule_present=sandbox.verify(action, now),
                                           expired_rule_inactive=not sandbox.verify(action, now + timedelta(seconds=action['ttl_seconds'])))
        sandbox.rollback(action)
        action['simulation_checks']['rollback_removed_rule'] = not sandbox.verify(action, now)
        action['simulation_verified'] = all(action['simulation_checks'].values())
        # This verifies only the adapter's memory state, never a host firewall.


def run_task(store, source, collector, protected=(), ttl=600, demo=False, analyst=None):
    task = store.create(source, demo)
    try:
        collection = collector()
        task.update(detect(collection))
        task['warnings'] = collection.get('warnings', [])
        task['source_sha256'] = collection.get('source_sha256')
        if not task['events']:
            task['warnings'].append('没有符合关联条件的登录记录；需核对权限、时间范围和日志格式')
        task['stages'].append(dict(stage='collect', status='complete', at=utcnow().isoformat()))
        task['stages'].append(dict(stage='rules', status='complete', at=utcnow().isoformat()))
        task['status'] = 'analyzing'
        store.save(task)
        if analyst:
            try:
                task['model_answer'] = analyst(task['id'])
                task['stages'].append(dict(stage='model', status='complete'))
            except (ValueError, OSError, RuntimeError) as exc:
                task['model_error'] = str(exc)
                from guard_models import ModelError
                if isinstance(exc, ModelError):
                    task['model_diagnostic'] = exc.diagnostic
                task['stages'].append(dict(stage='model', status='failed'))
                task['warnings'].append('模型未完成；以下防护建议仅依据固定规则，不能视为模型分析成功')
        else:
            task['stages'].append(dict(stage='model', status='not_requested'))
        task['policy'] = dict(protected=list(protected), ttl_seconds=ttl, failure_threshold=5, window_seconds=300)
        task['actions'] = plan(task['findings'], protected, ttl, demo, source)
        simulate(task['actions'])
        task['stages'].extend([dict(stage='policy', status='complete'), dict(stage='execute', status='simulated'),
                               dict(stage='verify', status='simulation_only')])
        task['status'] = 'completed_simulation'
        store.commit_actions(task)
    except (Exception, KeyboardInterrupt) as exc:
        task['status'] = 'interrupted' if isinstance(exc, KeyboardInterrupt) else 'failed'
        task['error'] = str(exc)[:2000]
        store.save(task)
        raise
    return task
