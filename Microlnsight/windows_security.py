"""Bounded Windows Security interpretations. Audit activity is not proof of attack."""
from collections import defaultdict
from datetime import datetime
import re


SPECS = {
    '4624': ('登录成功', 'success', '登录会话建立；不单独证明访问已获授权。'),
    '4625': ('登录失败', 'failure', '登录失败；单次失败不等于密码猜测。'),
    '5379': ('凭据管理器读取', 'credential_read', '记录凭据读取操作；次数多或返回错误不单独证明凭据窃取。'),
    '4672': ('登录会话特权分配', 'privileged_logon', '会话获得列出的特权；系统账户和管理员正常登录也会产生此事件。'),
    '4627': ('登录账户组成员信息', 'group_membership', '登录时的组成员快照，不是新增组成员或权限变更。'),
    '4798': ('用户所属本地组枚举', 'user_group_enumeration', '进程查询用户所属本地组；正常管理操作也会产生。'),
    '4799': ('本地安全组成员枚举', 'local_group_enumeration', '进程查询安全组的成员；不代表修改了成员。'),
    '5058': ('密钥文件操作', 'key_file_operation', '密钥文件访问审计；根据返回码区分操作成功、失败或未知。'),
    '5061': ('加密操作', 'cryptographic_operation', '加密接口操作审计；操作失败不等于攻击。'),
}
AUDIT_IDS = [5379, 4672, 4627, 4798, 4799, 5058, 5061]
BUILTIN_SIDS = {'S-1-5-18', 'S-1-5-19', 'S-1-5-20'}
SENSITIVE_PRIVILEGES = {'SeDebugPrivilege', 'SeTcbPrivilege', 'SeLoadDriverPrivilege',
                        'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege',
                        'SeImpersonatePrivilege'}
DETAIL_FIELDS = {'5379': ('actor_account', 'read_operation', 'return_code'),
                 '4672': ('subject_sid', 'privilege_list'),
                 '4627': ('target_account', 'group_membership'),
                 '4798': ('actor_account', 'target_account', 'caller_process_name'),
                 '4799': ('actor_account', 'target_account', 'caller_process_name'),
                 '5058': ('actor_account', 'operation', 'return_code'),
                 '5061': ('actor_account', 'operation', 'return_code')}


def query_plan(limit):
    """Keep the total bounded while reserving room for rare event types."""
    if type(limit) is not int or not 1 <= limit <= 5000:
        raise ValueError('Windows 采集上限应为 1–5000 条')
    auth = max(1, limit // 2)
    remaining = limit - auth
    result = [([4624, 4625], auth)]
    for index, event_id in enumerate(AUDIT_IDS):
        quota = remaining // len(AUDIT_IDS) + (index < remaining % len(AUDIT_IDS))
        if quota:
            result.append(([event_id], quota))
    return result


def account(user, domain):
    return '\\'.join(str(x) for x in (domain, user) if x) if user else None


def numeric(value):
    text = str(value).strip()
    if re.fullmatch(r'0[xX][0-9a-fA-F]+', text):
        return int(text, 16)
    if re.fullmatch(r'[0-9]+', text):
        return int(text)
    return None


def fields(context):
    """Whitelist useful evidence fields; never confuse the actor with the target."""
    keys = ('subject_sid', 'target_sid', 'subject_logon_id', 'target_logon_id',
            'privilege_list', 'group_membership', 'caller_process_name', 'caller_process_id',
            'client_process_id', 'process_creation_time', 'credential_target', 'credentials_returned',
            'read_operation', 'return_code', 'key_name', 'key_file_path', 'operation', 'algorithm_name')
    result = {key: str(context[key])[:1024] for key in keys if context.get(key) is not None}
    result['actor_account'] = account(context.get('subject_user'), context.get('subject_domain'))
    result['target_account'] = account(context.get('username'), context.get('account_domain'))
    truncated = [key for key in keys if context.get(key) is not None and len(str(context[key])) > 1024]
    if truncated:
        result['truncated_fields'] = truncated
    return result


def review(events, auth_findings=()):
    """Produce per-type facts and conservative, evidence-backed review findings."""
    rows = [e for e in events if e.get('platform') == 'windows' and e.get('event_id') in SPECS]
    summaries, grouped = {}, defaultdict(list)
    for row in rows:
        eid = row['event_id']
        details = row.get('security', {})
        summary = summaries.setdefault(eid, dict(event_id=eid, label=SPECS[eid][0], count=0,
            meaning=SPECS[eid][2], refs=[], return_codes={}, related_logons=0, missing_details={}))
        summary['count'] += 1
        for key in DETAIL_FIELDS.get(eid, ()):
            if not details.get(key):
                summary['missing_details'][key] = summary['missing_details'].get(key, 0) + 1
        if len(summary['refs']) < 3:
            summary['refs'].append(row['ref'])
        code = numeric(details.get('return_code'))
        if eid in ('5379', '5058', '5061'):
            label = 'unknown' if code is None else 'success' if code == 0 else 'nonzero'
            summary['return_codes'][label] = summary['return_codes'].get(label, 0) + 1
        rule = None
        if eid in ('4798', '4799'):
            path = details.get('caller_process_name', '').replace('/', '\\').casefold()
            if re.search(r'\\(?:temp|downloads)\\|\\users\\public\\', path):
                rule = 'windows_group_enumeration_review'
        elif eid in ('5058', '5061') and code is not None and code != 0:
            rule = 'windows_crypto_operation_failed'
        if rule:
            grouped[(rule, row['host'], row.get('account'), details.get('caller_process_name'),
                     code if rule == 'windows_crypto_operation_failed' else None)].append(row)

    # Link only an unambiguous, nearby session with the same host and SID/account.
    logons = defaultdict(list)
    for row in rows:
        details = row.get('security', {})
        session = numeric(details.get('target_logon_id'))
        actor = details.get('target_sid') or row.get('account')
        if row['event_id'] == '4624' and session and actor:
            logons[(row['host'], session, actor.casefold())].append(row)
    correlations, linked_logons = [], {}
    for row in rows:
        if row['event_id'] not in ('4672', '4627'):
            continue
        details = row.get('security', {})
        target = row['event_id'] == '4627'
        session = numeric(details.get('target_logon_id' if target else 'subject_logon_id'))
        actor = details.get('target_sid' if target else 'subject_sid') or row.get('account')
        if not session or not actor:
            continue
        candidates = [e for e in logons.get((row['host'], session, actor.casefold()), [])
                      if abs((datetime.fromisoformat(row['time']) - datetime.fromisoformat(e['time'])).total_seconds()) <= 5]
        if len(candidates) == 1:
            linked_logons[row['identity']] = candidates[0]
            summaries[row['event_id']]['related_logons'] += 1
            if len(correlations) < 100:
                correlations.append(dict(event_ref=row['ref'], logon_ref=candidates[0]['ref'],
                                         basis='相同主机、会话及账户标识，时间相差不超过 5 秒'))

    # Privilege assignment alone is an observation, not evidence of escalation.
    # Require an independently detected failure-then-success chain for the exact
    # linked logon. Do not infer authorization from an account name or logon type.
    supports = {}
    privilege_context = dict(standalone_observations=0, correlated_auth_reviews=0,
                             builtin_service_events=0, without_unique_logon=0)
    for row in rows:
        if row['event_id'] != '4672':
            continue
        details = row.get('security', {})
        sid = details.get('subject_sid', '').upper()
        privileges = set(re.findall(r'Se\w+Privilege', details.get('privilege_list', '')))
        login = linked_logons.get(row['identity'])
        if not login:
            privilege_context['without_unique_logon'] += 1
        if sid in BUILTIN_SIDS:
            privilege_context['builtin_service_events'] += 1
        matches = [f for f in auth_findings if login and sid and sid not in BUILTIN_SIDS
                   and privileges & SENSITIVE_PRIVILEGES
                   and f.get('rule') == 'auth_failure_then_success'
                   and f.get('platform') == 'windows' and f.get('host') == row['host']
                   and login['identity'] in f.get('identities', [])]
        if matches:
            privilege_context['correlated_auth_reviews'] += 1
            grouped[('windows_sensitive_privileges', row['host'], row.get('account'), None, None)].append(row)
            supports[row['identity']] = matches
        else:
            privilege_context['standalone_observations'] += 1

    definitions = {
        'windows_sensitive_privileges': ('连续登录失败后成功的会话获得敏感特权，需核查',
            '4672 关联到同主机、同账户、同会话的 4624，且该登录已命中连续失败后成功规则；特权分配本身不构成异常，尚未确认未授权访问。',
            ['核对失败来源、登录会话及运维授权', '结合该会话的进程审计核查实际用途']),
        'windows_group_enumeration_review': ('临时或下载目录中的进程枚举本地组，需核查来源',
            '调用进程路径位于临时、下载或公共用户目录；合法安装程序也可能命中。',
            ['核对调用进程的完整路径、数字签名和来源', '结合 4688 进程审计核查父进程与启动人；本入口未采集 4688']),
        'windows_crypto_operation_failed': ('密钥或加密操作返回错误，需核查',
            '操作返回非零代码；可能是权限、密钥状态或应用问题，不能单独判定攻击。',
            ['核对返回码及对应操作', '核对应用配置、密钥权限和同一时段应用日志']),
    }
    findings = []
    for (rule, host, actor, process, code), group in grouped.items():
        title, explanation, steps = definitions[rule]
        supporting = [f for r in group for f in supports.get(r['identity'], [])]
        refs = list(dict.fromkeys([r['ref'] for r in group] + [ref for f in supporting for ref in f['refs']]))
        identities = list(dict.fromkeys([r['identity'] for r in group] + [v for f in supporting for v in f['identities']]))
        findings.append(dict(rule=rule, category='windows_security', title=title,
            platform='windows', host=host, account=actor, ip=None, count=len(group),
            start=group[0]['time'], end=group[-1]['time'], explanation=explanation,
            refs=refs, identities=identities, next_steps=steps))
    return dict(event_types=list(summaries.values()), correlations=correlations,
                privilege_context=privilege_context,
                interpretation='活动统计与待核查线索，不等于确认攻击；未采集的事件和上下文仍未知。'), findings
