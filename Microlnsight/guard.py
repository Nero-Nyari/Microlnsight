"""Authentication monitoring prototype. All response actions are simulations.

Collectors are read-only. No model output is accepted as a command or policy.
The store is separate from the existing incident database.
"""
from __future__ import annotations

from collections import Counter, defaultdict
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
import windows_security as security

ROOT = Path(__file__).resolve().parent
MAX_BYTES = 16 * 1024 * 1024
MAX_EXCLUDED_RECORDS = 1000
MAX_EXCLUDED_BYTES = 1024 * 1024
MAX_EXCLUDED_RAW_BYTES = 4096


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


def capture_excluded(capture, line, number, reason):
    """Bound retained raw bytes and record count independently of input size."""
    capture['total'] = capture.get('total', 0) + 1
    records = capture.setdefault('records', [])
    used = capture.get('raw_bytes', 0)
    raw = line.encode('utf-8')
    if len(records) >= MAX_EXCLUDED_RECORDS or used >= MAX_EXCLUDED_BYTES:
        capture['omitted'] = capture.get('omitted', 0) + 1
        return
    excerpt = raw[:min(MAX_EXCLUDED_RAW_BYTES, MAX_EXCLUDED_BYTES - used)].decode('utf-8', errors='ignore')
    capture['raw_bytes'] = used + len(excerpt.encode('utf-8'))
    records.append(dict(ref=f'ssh:{number}', reason=reason, raw=excerpt,
                        raw_sha256=hashlib.sha256(raw).hexdigest(),
                        raw_truncated=len(excerpt.encode('utf-8')) < len(raw)))


def linux_events(text, rejected_reasons=None, excluded_capture=None):
    from server_logs import parse_ssh_line
    events, rejected = [], 0
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        event, reason = parse_ssh_line(line)
        if event is None:
            rejected += 1
            if rejected_reasons is not None:
                rejected_reasons[reason] = rejected_reasons.get(reason, 0) + 1
            if excluded_capture is not None:
                capture_excluded(excluded_capture, line, number, reason)
            continue
        events.append(dict(platform='linux', host=event['host'], account=event['account'], ip=event['ip'],
                           kind=event['kind'], time=event['time'].isoformat(),
                           identity=str(event['identity'] or digest(line)), ref=f'ssh:{number}', raw=line[:4096],
                           raw_sha256=hashlib.sha256(line.encode()).hexdigest(), raw_truncated=len(line) > 4096))
        if event['kind'] == 'ssh_activity':
            events[-1].update(activity=event['activity'], activity_label=event['activity_label'])
    return events, rejected


def task_scope(task):
    """One read-only explanation for UI, reports and model context, including old tasks."""
    coverage = task.get('coverage') or {}
    collection = coverage.get('collection') or {}
    reasons = []

    def add(code, label, detail, count=None):
        reasons.append(dict(code=code, label=label, detail=detail, count=count))

    collected = any(s.get('stage') == 'collect' and s.get('status') == 'complete'
                    for s in task.get('stages', []))
    if task.get('status') in ('failed', 'interrupted') and not collected:
        add('collection_failed', '采集未完成', '采集失败或中断；具体原因见失败信息，不能仅据此判断为权限不足。')
    if not coverage:
        add('coverage_unknown', '范围统计缺失', '此任务未保存可核实的范围统计，需重新采集。')
        return dict(summary='没有可核实的分析范围统计', reasons=reasons, incomplete=True)

    # Older tasks only kept the fixed limit warning and an aggregate rejected count.
    limit_reached = collection.get('limit_reached') or any(
        str(w).startswith('达到采集上限；') for w in task.get('warnings', []))
    if limit_reached:
        add('collection_limit', '达到采集上限', '更早记录可能未读取；未读数量未知。')
    if collection.get('warning'):
        add('collection_warning', '采集返回警告', '请查看范围说明中的采集原始提示；警告不一定涉及权限。')
    diagnostics = coverage.get('windows_diagnostics') or {}
    remaining = coverage.get('excluded', 0)
    labels = {
        'unsupported': ('消息暂不支持', '已读取，但当前解析规则不支持这类消息；不代表没有安全价值。'),
        'missing_metadata': ('必要字段缺失或无效', '账户、主机、IP、时间或记录标识不符合关联要求。'),
        'unknown_source': ('来源无法确认', '无法确认记录来自支持的日志通道或 SSH 进程。'),
        'invalid': ('日志格式无效', '无法按当前日志格式解析。'),
    }
    for code, (label, detail) in labels.items():
        count = min(remaining, (coverage.get('excluded_reasons') or {}).get(code, 0))
        if count:
            if code == 'unsupported' and diagnostics.get('unsupported_event_ids'):
                detail += ' 事件 ID：' + '，'.join(f'{eid}：{n} 条' for eid, n in sorted(diagnostics['unsupported_event_ids'].items())) + '。'
            if code == 'missing_metadata' and diagnostics.get('missing_fields'):
                names = {'record_id': '记录编号', 'timestamp': '时间', 'computer': '主机', 'username': '目标账户'}
                detail = '具体字段：' + '，'.join(f'{names.get(k, k)} {n} 条' for k, n in sorted(diagnostics['missing_fields'].items())) + '；同一记录可缺少多个字段。'
            add(code, f'{label} {count} 条', detail, count)
            remaining -= count
    if remaining:
        add('excluded_unknown', f'排除原因未细分 {remaining} 条',
            '此任务只保存了排除总数，无法还原具体类别；重新采集可记录分类。', remaining)
    if coverage.get('conflicts'):
        count = coverage['conflicts']
        add('conflicting_records', f'记录冲突 {count} 条', '相同记录标识对应不同内容，未参与关联分析。', count)
    if coverage.get('retained_without_ip'):
        count = coverage['retained_without_ip']
        add('source_ip_unavailable', f'已保留但无可用来源 IP {count} 条',
            '登录记录已保留为证据；来源 IP 未提供或无效，不参与按来源 IP 关联的重复失败规则，也不生成封禁建议。服务登录等事件可以不记录来源 IP，不代表整条日志无效。', count)
    for item in task.get('security_analysis', {}).get('event_types', []):
        if item.get('missing_details'):
            labels = {'actor_account': '操作账户', 'target_account': '目标账户或组', 'read_operation': '读取操作',
                      'return_code': '返回码', 'subject_sid': '操作账户标识', 'privilege_list': '特权列表',
                      'group_membership': '组成员列表', 'caller_process_name': '调用进程路径', 'operation': '操作类型'}
            add('audit_details_missing', f"{item['event_id']} 审计细节不完整",
                '事件已保留；部分判断所需字段缺失：' + '，'.join(f'{labels.get(k, k)} {v} 条' for k, v in item['missing_details'].items()))
    if (coverage.get('scope_incomplete') or task.get('scope_incomplete')) and not (
            limit_reached or collection.get('warning')):
        add('collection_unknown', '采集范围原因未细分', '保存的范围标记不完整，无法确认是否有未读取内容；不推断为权限问题。')
    summary = (f"已读取 {coverage.get('input', 0)} 条，{coverage.get('retained', 0)} 条参与分析，"
               f"{coverage.get('excluded', 0)} 条排除，{coverage.get('duplicates', 0)} 条重复合并，"
               f"{coverage.get('conflicts', 0)} 条冲突")
    if 'ip_rule_eligible' in coverage:
        summary += f"；其中 {coverage['ip_rule_eligible']} 条可按来源 IP 关联"
    if 'ssh_activity_retained' in coverage:
        summary = (f"已读取 {coverage.get('input', 0)} 条，保留 {coverage.get('retained', 0)} 条证据"
                   f"（登录认证 {coverage['ssh_auth_retained']} 条，会话活动 {coverage['ssh_activity_retained']} 条）；"
                   f"{coverage.get('excluded', 0)} 条排除，{coverage.get('duplicates', 0)} 条重复合并，"
                   f"{coverage.get('conflicts', 0)} 条冲突。会话活动仅作上下文，不参与登录失败关联规则。")
    return dict(summary=summary, reasons=reasons, incomplete=bool(reasons))


def task_assessment(task):
    """Derive a current verdict, including failed and legacy tasks, without writes."""
    state = task.get('status')
    coverage = task.get('coverage') or {}
    incomplete = task_scope(task)['incomplete']
    if state == 'failed':
        collected = any(s.get('stage') == 'collect' and s.get('status') == 'complete' for s in task.get('stages', []))
        status, label = 'failed', '分析失败，本次未完成分析' if collected else '采集失败，本次未完成分析'
    elif state == 'interrupted':
        status, label = 'interrupted', '分析中断，本次未完成分析'
    elif state == 'collecting':
        status, label = 'pending', '采集中，尚无分析结论'
    elif task.get('findings'):
        status, label = 'findings', '发现待核查线索'
    elif not coverage.get('retained'):
        status, label = 'insufficient_data', '数据不足，无法判断'
    elif coverage.get('ssh_activity_retained') and not coverage.get('ssh_auth_retained'):
        status, label = 'insufficient_data', '仅保留 SSH 会话活动，缺少登录认证证据，当前登录规则无法判断'
    elif coverage.get('ip_rule_eligible') == 0 and not coverage.get('security_audit_retained'):
        status, label = 'insufficient_data', '已保留登录证据，但无可用来源 IP，当前关联规则无法判断'
    else:
        status, label = 'no_findings', '在已分析范围内未发现规则线索'
    if not coverage:
        incomplete = True
    return dict(status=status, label=label, scope_incomplete=incomplete)


def windows_events(rows, rejected_reasons=None, diagnostics=None):
    sys.path.insert(0, str(ROOT / 'backend')) if str(ROOT / 'backend') not in sys.path else None
    from app.agents.event_context import extract_event_context
    events, rejected = [], 0
    diagnostics = diagnostics if diagnostics is not None else {}
    def count(group, key):
        counts = diagnostics.setdefault(group, {})
        counts[str(key)] = counts.get(str(key), 0) + 1
    for number, row in enumerate(rows, 1):
        raw = json.dumps(row, ensure_ascii=False)
        r = extract_event_context(raw)
        when, ip = stamp(r['timestamp']), address(r['source_ip'])
        count('event_ids', r['event_id'] or 'unknown')
        missing = [name for name, valid in (
            ('record_id', str(r['record_id']).isdigit() and int(r['record_id']) > 0),
            ('timestamp', when), ('computer', r['computer']),
            ('username', r['username'] or r['event_id'] not in ('4624', '4625'))) if not valid]
        reason = ('unknown_source' if str(r['channel']).casefold() != 'security' else
                  'unsupported' if r['event_id'] not in security.SPECS else
                  'missing_metadata' if missing else None)
        if reason:
            if reason == 'unsupported':
                count('unsupported_event_ids', r['event_id'] or 'unknown')
            elif reason == 'missing_metadata':
                for name in missing:
                    count('missing_fields', name)
            rejected += 1
            if rejected_reasons is not None:
                rejected_reasons[reason] = rejected_reasons.get(reason, 0) + 1
            continue
        logon_type = str(r.get('logon_type')) if r.get('logon_type') is not None else None
        auth = r['event_id'] in ('4624', '4625')
        details = security.fields(r)
        if auth:
            count('logon_types', logon_type or 'unknown')
        else:
            ip = None
        ip_status = ('present' if ip else 'not_recorded' if r['source_ip'] is None else 'invalid') if auth else 'not_applicable'
        count('source_ip_status', ip_status)
        events.append(dict(platform='windows', host=r['computer'],
                           account=details['target_account'] if auth or r['event_id'] == '4627' else details['actor_account'],
                           ip=ip, source_ip_status=ip_status, event_id=r['event_id'], logon_type=logon_type,
                           kind=security.SPECS[r['event_id']][1], security=details,
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
    rejected_reasons, excluded_capture = {}, {}
    events, rejected = linux_events(text, rejected_reasons, excluded_capture)
    warnings = [result.stderr.decode('utf-8', errors='replace').strip()] if result.stderr.strip() else []
    if len(text.splitlines()) >= limit:
        warnings.append('达到采集上限；更早记录可能未读取，未读数量未知')
    warnings.append(f'仅覆盖 SSH journal，最近 {minutes} 分钟；未采集应用和文件审计日志')
    return dict(events=events, rejected=rejected, rejected_reasons=rejected_reasons,
                excluded_capture=excluded_capture, warnings=warnings,
                collection=dict(limit=limit, minutes=minutes, limit_reached=len(text.splitlines()) >= limit,
                                warning=bool(result.stderr.strip())),
                scope_incomplete=bool(result.stderr.strip() or len(text.splitlines()) >= limit))


def collect_export(directory):
    path = Path(directory).expanduser().resolve() / 'ssh.journal.log'
    if not path.is_file():
        raise ValueError('导出目录缺少 ssh.journal.log；此入口仅分析 SSH 登录')
    if path.stat().st_size > MAX_BYTES:
        raise ValueError('SSH 导出超过 16 MiB，请缩小导出范围')
    data = path.read_bytes()
    rejected_reasons, excluded_capture = {}, {}
    events, rejected = linux_events(data.decode('utf-8', errors='replace'), rejected_reasons, excluded_capture)
    return dict(events=events, rejected=rejected, rejected_reasons=rejected_reasons,
                excluded_capture=excluded_capture, source_sha256=hashlib.sha256(data).hexdigest(),
                warnings=['历史导出仅用于复盘；防护建议不代表当前服务器状态'])


def collect_windows(limit=1000):
    import platform
    if platform.system() != 'Windows':
        raise ValueError('本机 Windows 采集需要在 Windows 上运行')
    sys.path.insert(0, str(ROOT / 'backend')) if str(ROOT / 'backend') not in sys.path else None
    from app.services.log_reader import read_windows_logs
    rows, partitions = [], []
    warnings = ['按类别限额查询本机 Security 4624/4625、5379、4672、4627、4798、4799、5058、5061；其他事件未采集，不能据此判断整机安全']
    for ids, quota in security.query_plan(limit):
        result = read_windows_logs(channels=['Security'], max_events=quota, suspicious_only=False, event_ids=ids)
        if result.get('is_mock') or result.get('read_status') == 'failed':
            details = '; '.join(str(row.get('message') or row.get('status')) for row in result.get('channel_results', []))
            raise RuntimeError('未取得真实 Security 日志；请在有读取权限的终端运行。' + details[:1000])
        rows.extend(result['events'])
        warning = any(c.get('status') != 'success' for c in result.get('channel_results', []))
        partitions.append(dict(event_ids=ids, limit=quota, read=len(result['events']),
                               limit_reached=len(result['events']) >= quota, warning=warning))
        warnings.extend(str(c.get('message') or c.get('status')) for c in result.get('channel_results', []) if c.get('status') != 'success')
    reached = any(p['limit_reached'] for p in partitions)
    warning = any(p['warning'] for p in partitions)
    if reached:
        warnings.append('达到采集上限；部分事件类别达到独立额度，更早记录可能未读取，未读数量未知')
    omitted = [int(eid) for eid in security.SPECS if int(eid) not in {eid for p in partitions for eid in p['event_ids']}]
    if omitted:
        warnings.append('条数额度不足，未查询事件：' + ', '.join(map(str, omitted)))
    rejected_reasons, diagnostics = {}, {}
    events, rejected = windows_events(rows, rejected_reasons, diagnostics)
    return dict(events=events, rejected=rejected, rejected_reasons=rejected_reasons, warnings=warnings,
                windows_diagnostics=diagnostics,
                collection=dict(limit=limit, event_ids=[eid for p in partitions for eid in p['event_ids']], channel='Security',
                                partitions=partitions, omitted_event_ids=omitted, limit_reached=reached, warning=warning),
                scope_incomplete=bool(reached or warning or omitted))


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
        if event['kind'] == 'failure' and address(event.get('ip')):
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
    result = dict(events=rows, findings=findings, coverage=dict(input=len(collection['events']) + collection.get('rejected', 0),
                retained=len(rows), excluded=collection.get('rejected', 0), duplicates=duplicates, conflicts=conflicts),
                time_range=dict(start=rows[0]['time'] if rows else None, end=rows[-1]['time'] if rows else None))
    result['coverage']['scope_incomplete'] = bool(collection.get('scope_incomplete'))
    result['coverage']['excluded_reasons'] = dict(collection.get('rejected_reasons', {}))
    result['coverage']['collection'] = dict(collection.get('collection', {}))
    if 'excluded_capture' in collection:
        capture = collection['excluded_capture']
        result['excluded_records'] = list(capture.get('records', []))
        result['coverage']['excluded_evidence'] = dict(
            total=capture.get('total', 0), saved=len(result['excluded_records']), omitted=capture.get('omitted', 0),
            truncated=sum(r['raw_truncated'] for r in result['excluded_records']),
            raw_bytes=capture.get('raw_bytes', 0), max_records=MAX_EXCLUDED_RECORDS,
            max_raw_bytes=MAX_EXCLUDED_BYTES, max_record_bytes=MAX_EXCLUDED_RAW_BYTES)
    if any(r['platform'] == 'linux' for r in rows):
        result['coverage']['ssh_auth_retained'] = sum(r['kind'] in ('success', 'failure') for r in rows)
        result['coverage']['ssh_activity_retained'] = sum(r['kind'] == 'ssh_activity' for r in rows)
        result['coverage']['ssh_activity_types'] = dict(Counter(
            r['activity_label'] for r in rows if r['kind'] == 'ssh_activity'))
        result['coverage']['ip_rule_eligible'] = sum(
            r['kind'] in ('success', 'failure') and bool(address(r.get('ip'))) for r in rows)
    if 'windows_diagnostics' in collection or any(r['platform'] == 'windows' for r in rows):
        result['coverage']['windows_diagnostics'] = dict(collection.get('windows_diagnostics', {}))
        auth_rows = [r for r in rows if r['kind'] in ('success', 'failure')]
        result['coverage']['ip_rule_eligible'] = sum(bool(address(r.get('ip'))) for r in auth_rows)
        result['coverage']['retained_without_ip'] = len(auth_rows) - result['coverage']['ip_rule_eligible']
        result['coverage']['security_audit_retained'] = sum(r.get('event_id') in {str(e) for e in security.AUDIT_IDS} for r in rows)
        result['security_analysis'], audit_findings = security.review(rows, findings)
        result['findings'].extend(audit_findings)
    result['assessment'] = task_assessment(result)
    return result


def plan(findings, protected=(), ttl=600, demo=False, source=''):
    if not 60 <= ttl <= 3600:
        raise ValueError('建议封禁期限应为 60–3600 秒')
    networks = [ipaddress.ip_network(item, strict=False) for item in protected]
    actions = []
    for finding in findings:
        if finding.get('rule') not in ('auth_repeated_failure', 'auth_failure_then_success') or not address(finding.get('ip')):
            continue
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


def run_task(store, source, collector, protected=(), ttl=600, demo=False, analyst=None, *, on_task=None):
    task = store.create(source, demo)
    try:
        if on_task:
            on_task(task)
        collection = collector()
        task.update(detect(collection))
        task['warnings'] = collection.get('warnings', [])
        task['source_sha256'] = collection.get('source_sha256')
        if not task['events']:
            task['warnings'].append('没有符合当前解析条件的记录；请查看分析覆盖明细，核对时间范围和消息类型')
        task['stages'].append(dict(stage='collect', status='complete', at=utcnow().isoformat()))
        task['stages'].append(dict(stage='rules', status='complete', at=utcnow().isoformat()))
        task['status'] = 'analyzing'
        task['assessment'] = task_assessment(task)
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
        task['assessment'] = task_assessment(task)
        store.save(task)
        raise
    return task
