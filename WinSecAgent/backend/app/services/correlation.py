"""Bounded, local Windows evidence analysis. No model calls or OS changes."""
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import ipaddress
import re

from sqlalchemy.orm import joinedload
from app import models
from app.agents.event_context import extract_event_context

RULE_VERSION = 1
FAILURE_THRESHOLD = 5
FAILURE_WINDOW_SECONDS = 300
MAX_CANDIDATES = 5000


def timestamp(value):
    try:
        result = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return result.astimezone(timezone.utc) if result.tzinfo else None
    except (ValueError, TypeError):
        return None


def record(alert, incident_id=None):
    raw = alert.raw_content or ''
    context = extract_event_context(raw)
    return {**context, 'alert_id': alert.id, 'incident_id': incident_id,
            'raw_content': raw, 'raw_sha256': hashlib.sha256(raw.encode()).hexdigest(),
            'is_demo': context['is_demo'] or 'demo' in (alert.source_type or '')}


def deduplicate(records):
    buckets = defaultdict(list)
    for r in records:
        # Host/channel/record/time prevent duplicate imports inflating counts.
        key = (str(r.get('computer') or '').casefold(), str(r.get('channel') or '').casefold(),
               str(r.get('record_id')), str(timestamp(r.get('timestamp')) or r.get('timestamp'))) if r.get('record_id') is not None else ('raw', r['raw_sha256'])
        buckets[key].append(r)
    unique, duplicates, conflicts = [], 0, 0
    for rows in buckets.values():
        semantic = [{k: (str(timestamp(v) or v) if k == 'timestamp' else v) for k, v in row.items() if k not in ('alert_id', 'incident_id', 'raw_content', 'raw_sha256')} for row in rows]
        if any(item != semantic[0] for item in semantic[1:]):
            conflicts += len(rows)
            continue
        unique.append(rows[0])
        duplicates += len(rows) - 1
    return unique, duplicates, conflicts


def source_ip(value):
    try:
        ip = ipaddress.ip_address(str(value))
        if ip.is_unspecified:
            return None
        return str(getattr(ip, 'ipv4_mapped', None) or ip)
    except ValueError:
        return None


def account_key(r):
    return (str(r.get('account_domain') or '').casefold(), str(r.get('username') or '').casefold())


def service_binary(command):
    command = str(command or '').strip()
    if command.startswith('"'):
        return command[1:].split('"', 1)[0]
    match = re.match(r'^(.+?\.(?:exe|sys|com))(?=\s|$)', command, re.I)
    return match.group(1) if match else command.split(' ', 1)[0]


def analysis_coverage(records, rows, duplicates, conflicts):
    supported = {('4625', 'security'), ('4624', 'security'), ('4697', 'security'), ('7045', 'system')}
    sources = {}
    for r in rows:
        key = (str(r.get('computer') or '主机未知'), str(r.get('channel') or '通道未知'))
        info = sources.setdefault(key, dict(host=key[0], channel=key[1], retained=0,
                                           identified=0, unsupported=0, missing_time=0, start=None, end=None))
        info['retained'] += 1
        identified = r.get('platform') == 'Windows' and bool(r.get('event_id') and r.get('channel'))
        info['identified'] += int(identified)
        info['unsupported'] += int(not identified or (str(r.get('event_id')), str(r.get('channel')).casefold()) not in supported)
        when = timestamp(r.get('timestamp'))
        if when:
            value = when.isoformat()
            info['start'] = min(info['start'], value) if info['start'] else value
            info['end'] = max(info['end'], value) if info['end'] else value
        else:
            info['missing_time'] += 1
    identified = sum(info['identified'] for info in sources.values())
    return dict(input_records=len(records), retained=len(rows), identified=identified,
                unparsed=len(rows) - identified, duplicates=duplicates, conflicts=conflicts,
                unsupported=sum(info['unsupported'] for info in sources.values()),
                missing_time=sum(info['missing_time'] for info in sources.values()),
                failure_records_excluded=sum(r.get('event_id') == '4625' and not (
                    r.get('platform') == 'Windows' and str(r.get('channel') or '').casefold() == 'security'
                    and r.get('record_id') is not None and r.get('computer') and r.get('username')
                    and timestamp(r.get('timestamp')) and source_ip(r.get('source_ip'))) for r in rows),
                sources=list(sources.values()))


def analyze_records(records, window_minutes=15, warnings=None):
    records = list(records)
    rows, duplicates, conflicts = deduplicate(records)
    rows.sort(key=lambda r: (timestamp(r.get('timestamp')) or datetime.min.replace(tzinfo=timezone.utc), r['alert_id']))
    warnings = list(warnings or [])
    if duplicates:
        warnings.append(f'已排除 {duplicates} 条重复导入记录，重复记录不增加失败次数。')
    if conflicts:
        warnings.append(f'{conflicts} 条记录标识相同但字段冲突，已排除计数，需核对原始日志。')
    findings, groups = [], defaultdict(list)
    for r in rows:
        if r.get('platform') != 'Windows' or str(r.get('channel') or '').casefold() != 'security':
            continue
        if r.get('event_id') == '4625' and r.get('record_id') is not None and r.get('computer') and r.get('username') and timestamp(r.get('timestamp')) and source_ip(r.get('source_ip')):
            groups[(str(r['computer']).casefold(), r['is_demo'], account_key(r), source_ip(r['source_ip']))].append(r)
    for (_, _, _, ip), failures in groups.items():
        # Largest exact five-minute window, not a claim based on free-text counts.
        best, left = [], 0
        for right, end in enumerate(failures):
            while (timestamp(end['timestamp']) - timestamp(failures[left]['timestamp'])).total_seconds() > FAILURE_WINDOW_SECONDS:
                left += 1
            if right - left + 1 > len(best):
                best = failures[left:right + 1]
        if len(best) < FAILURE_THRESHOLD:
            continue
        first, last = best[0], best[-1]
        finding = {'rule_id': 'repeated_failed_logon', 'title': '疑似密码猜测：短时间内重复登录失败',
                   'reason': f'同主机、账户和来源 IP 在 5 分钟内有 {len(best)} 条去重后的 4625 记录；可能是密码猜测，也可能是失效凭据重试。',
                   'failure_count': len(best), 'start': first['timestamp'], 'end': last['timestamp'],
                   'source_ip': ip, 'account': '\\'.join(filter(None, [first.get('account_domain'), first.get('username')])),
                   'record_refs': [r['alert_id'] for r in best],
                   'missing_evidence': ['核实账户授权、计划任务及保存凭据是否失效', '核实来源 IP 的资产归属与登录类型'],
                   'recommendation': '先核实失败原因与来源设备，检查是否有对应成功登录；暂不自动封禁。'}
        findings.append(finding)
        successes = [r for r in rows if r.get('event_id') == '4624' and str(r.get('channel') or '').casefold() == 'security'
                     and str(r.get('computer') or '').casefold() == str(last['computer']).casefold()
                     and r['is_demo'] == last['is_demo'] and account_key(r) == account_key(last)
                     and source_ip(r.get('source_ip')) == ip and timestamp(r.get('timestamp'))
                     and 0 < (timestamp(r['timestamp']) - timestamp(last['timestamp'])).total_seconds() <= window_minutes * 60]
        if successes:
            success = successes[0]
            services = [r for r in rows if r.get('event_id') in ('7045', '4697')
                        and ((r['event_id'] == '7045' and str(r.get('channel') or '').casefold() == 'system')
                             or (r['event_id'] == '4697' and str(r.get('channel') or '').casefold() == 'security'))
                        and str(r.get('computer') or '').casefold() == str(last['computer']).casefold()
                        and r['is_demo'] == last['is_demo'] and timestamp(r.get('timestamp'))
                        and 0 < (timestamp(r['timestamp']) - timestamp(success['timestamp'])).total_seconds() <= window_minutes * 60]
            findings.append({**finding, 'rule_id': 'failure_success_service' if services else 'failure_then_success',
                             'title': '登录失败 → 登录成功' + (' → 同主机新建服务（时间关联）' if services else ''),
                             'reason': '相同账户和来源 IP 的登录失败后出现登录成功。' + ('随后同主机出现服务安装；仅时间相邻，尚未证实由该登录会话创建。' if services else '成功登录不等于入侵成功。'),
                             'end': (services[0] if services else success)['timestamp'],
                             'record_refs': finding['record_refs'] + [success['alert_id']] + ([services[0]['alert_id']] if services else []),
                             'missing_evidence': finding['missing_evidence'] + ['核对 LogonId、进程创建记录、服务安装账户及变更审批，确认是否为同一操作链']})
    for r in rows:
        path = service_binary(r.get('service_path')).replace('/', '\\').casefold()
        service_event = (r.get('event_id'), str(r.get('channel') or '').casefold()) in (('7045', 'system'), ('4697', 'security'))
        if service_event and str(r.get('service_start')).casefold() in ('2', '0x2', '自动启动', 'auto start') and any(p in path for p in ('\\temp\\', '\\users\\public\\', '\\appdata\\')):
            findings.append({'rule_id': 'service_writable_path', 'title': '自动启动服务指向临时或用户可写位置',
                             'reason': f'记录中的服务路径为 {r["service_path"]}，启动类型为自动。位置可疑但不能单独证明恶意。',
                             'record_refs': [r['alert_id']], 'start': r.get('timestamp'), 'end': r.get('timestamp'),
                             'missing_evidence': ['服务文件签名、哈希、实际目录权限及变更审批', '服务创建父进程、执行账户和运行结果'],
                             'recommendation': '核对服务文件签名及审批记录，确认前不删除或停止服务。'})
    missing = list(dict.fromkeys(item for f in findings for item in f['missing_evidence']))
    if not findings:
        missing = ['本地规则未发现覆盖范围内的异常；需核对操作授权、父进程和实际执行结果', '补充同主机、账户的 Security 日志及采集完整性']
    if any(not timestamp(r.get('timestamp')) for r in rows):
        missing.append('补充带时区的事件时间；缺失或无时区的时间不参与关联计数')
    if any(r.get('event_id') == '4625' and r.get('record_id') is None for r in rows):
        missing.append('补充 EventRecordID；缺少独立记录标识的登录失败不参与次数阈值判断')
    times = [timestamp(r.get('timestamp')) for r in rows if timestamp(r.get('timestamp'))]
    coverage = analysis_coverage(records, rows, duplicates, conflicts)
    if coverage['unparsed'] or coverage['missing_time'] or coverage['failure_records_excluded']:
        warnings.append(f"数据质量：{coverage['unparsed']} 条未识别事件结构，{coverage['missing_time']} 条缺少带时区时间，"
                        f"{coverage['failure_records_excluded']} 条登录失败缺少关联所需字段或通道不符；缺失项可重叠。")
    if coverage['unsupported']:
        warnings.append(f"{coverage['unsupported']} 条记录不在当前 Windows 联合规则覆盖的事件类型内，未据此判断安全。")
    assessment = {'classification': 'suspicious' if findings else 'unknown',
                  'label': '发现异常线索' if findings else '证据不足，待核实',
                  'queue': 'alerts' if findings else 'logs', 'risk_level': 'medium' if findings else 'info',
                  'confidence': 0.0, 'event_type': 'Windows 本地联合分析',
                  'reasoning': '；'.join(f['title'] for f in findings) if findings else '本地规则未发现明确异常线索；这不等于确认主机安全。',
                  'findings': [{'quote': '', 'reason': f['reason'], 'record_refs': f['record_refs']} for f in findings],
                  'missing_evidence': missing, 'disposition': 'needs_review'}
    return {'rule_version': RULE_VERSION, 'analyzed_at': datetime.now(timezone.utc).isoformat(),
            'coverage': coverage,
            'window_minutes': window_minutes, 'records': rows, 'findings': findings, 'assessment': assessment,
            'duplicates_excluded': duplicates, 'conflicts_excluded': conflicts, 'warnings': warnings,
            'time_range': {'start': min(times).isoformat() if times else None, 'end': max(times).isoformat() if times else None},
            'recommendations': list(dict.fromkeys(f['recommendation'] for f in findings)) or ['保留日志，核对授权与执行上下文；证据不足时不执行封禁、隔离或删除。']}


def collect_related(db, incident, window_minutes=15):
    seed = record(incident.alert, incident.id)
    time = timestamp(seed.get('timestamp'))
    warnings = ['仅分析已导入数据库的记录，不代表完整系统日志；未读通道和未导入记录不在本次范围内。']
    if not seed.get('computer') or not time or seed.get('platform') != 'Windows':
        return analyze_records([seed], window_minutes, warnings + ['种子记录缺少 Windows 主机或带时区的时间，无法跨记录关联。'])
    candidates = db.query(models.Alert).options(joinedload(models.Alert.incidents)).order_by(models.Alert.id.desc()).limit(MAX_CANDIDATES + 1).all()
    if len(candidates) > MAX_CANDIDATES:
        warnings.append(f'仅扫描最新 {MAX_CANDIDATES} 条导入日志及当前记录，结果可能不完整。')
    selected = [seed]
    for alert in candidates[:MAX_CANDIDATES]:
        if alert.id == seed['alert_id']:
            continue
        r = record(alert, min((i.id for i in alert.incidents), default=None))
        t = timestamp(r.get('timestamp'))
        if r.get('platform') == 'Windows' and r['is_demo'] == seed['is_demo'] and str(r.get('computer') or '').casefold() == str(seed['computer']).casefold() and t and abs((t - time).total_seconds()) <= window_minutes * 60:
            selected.append(r)
    return analyze_records(selected, window_minutes, warnings)


def save_analysis(db, incident, window_minutes):
    result = collect_related(db, incident, window_minutes)
    now = datetime.utcnow()
    run = models.AgentRun(incident_id=incident.id, agent_name='Correlation', status='success',
                          input_data={'window_minutes': window_minutes, 'mode': 'local_rules'},
                          output_data=result, started_at=now, finished_at=now)
    db.add(run)
    for r in result['records']:
        db.add(models.EvidenceItem(incident_id=incident.id, type='log',
                                  title=f"关联日志 #{r['alert_id']} · 事件 {r.get('event_id')}",
                                  content=r['raw_content'], source=f"imported_log:{r['alert_id']}", confidence=1.0))
    assessment = result['assessment']
    incident.status = 'review' if assessment['queue'] == 'alerts' else 'needs_review'
    incident.summary = assessment['reasoning']
    incident.risk_level = assessment['risk_level']
    incident.confidence = 0.0
    incident.event_type = assessment['event_type']
    incident.attack_stage = '时间关联线索，未确认攻击成功' if result['findings'] else '证据不足，待核实'
    from app.agents.report_agent import generate_report
    content = generate_report(incident.alert.title, extract_event_context(incident.alert.raw_content or ''),
                              assessment, [], {}, [], correlation=result)
    db.add(models.Report(incident_id=incident.id, content=content, format='markdown'))
    db.commit()
    return result
