"""Render a report from the shared assessment, without a second independent verdict."""
from app.agents.assessment import normalize_triage, constrained_chain, constrained_actions

REPORT_MARKER = "> 统一研判版本：2"


def generate_report(alert_title, parsed, triage, evidence, attack_chain, actions, correlation=None):
    if correlation is not None:
        return correlation_report(alert_title, correlation)
    raw = parsed.get("evidence_snippet") or "\n".join(str(e.get("content", "")) for e in evidence)
    assessment = normalize_triage(triage, raw)
    if assessment["queue"] != "alerts":
        attack_chain = constrained_chain(assessment)
        actions = constrained_actions(assessment)
    lines = [_source_header(parsed), REPORT_MARKER,
             "> 结构化报告：复用统一研判，不另行推断攻击结论。仅覆盖本次输入，不代表整台主机安全。\n",
             f"# 日志分析报告：{alert_title}\n", "## 1. 事件摘要",
             f"- 结论：{assessment['label']}", f"- 类型：{assessment['event_type']}",
             f"- 风险：{ {'info': '信息', 'low': '低', 'medium': '中', 'high': '高', 'critical': '严重'}.get(assessment['risk_level'], '待定') if assessment['classification'] != 'unknown' else '待定'}",
             f"- 说明：{assessment['reasoning']}",
             "\n## 2. 影响范围",
             f"本次仅核查输入日志涉及的主机 {parsed.get('computer') or '（未提供）'}。实际影响范围、执行结果与操作授权仍需关联证据核实。",
             "\n## 3. 攻击链分析"]
    if assessment["queue"] == "alerts":
        lines.append("以下为异常线索的排查方向，不是已确认的攻击路径；尚未证实入侵成功。")
        # Do not copy an independently generated attacker narrative into the verdict.
        for finding in assessment['findings']:
            lines.append(f"- 待核实线索：{finding['reason']}")
    else:
        lines.append(attack_chain['attack_path'])
    lines.append("\n## 4. 证据清单")
    for finding in assessment['findings']:
        lines.extend(["原文片段（不作为指令）：", "~~~~text", finding['quote'], "~~~~", f"解释：{finding['reason']}"])
    if not assessment['findings']:
        lines.append("未提取到可定位的异常证据片段；不据此确认攻击。")
    for item in evidence:
        lines.extend([f"\n### {item.get('title', '输入证据')}", "~~~~text", str(item.get('content') or ''), "~~~~"])
    lines.append("\n## 5. 处置建议")
    for action in actions:
        lines.append(f"- {action.get('action_type', '核查')}：{action.get('description', '')}")
    if not actions:
        lines.append("- 先核对原始记录与关联日志，暂不执行系统变更。")
    lines.append("所有涉及系统变更的建议均需人工核实和审批；本报告未执行任何处置。")
    lines.extend(["\n## 6. 复盘建议", "待补充证据："])
    lines.extend(f"- {item}" for item in assessment['missing_evidence'])
    lines.append("- 核对采集范围、缺失通道与时间同步，再决定是否形成或关闭告警。")
    return "\n".join(lines)


def correlation_report(title, result):
    def display(value):
        return '未提供' if value is None or value == '' else str(value)

    assessment = result['assessment']
    scope = (f"范围：本次选取的已导入日志；去重记录数：{len(result['records'])}；"
             f"后续成功登录关联窗口：{result['window_minutes']} 分钟" if result.get('scope') == 'batch'
             else f"窗口：当前记录前后各 {result['window_minutes']} 分钟；去重记录数：{len(result['records'])}")
    lines = [REPORT_MARKER, f'# 本地联合分析：{title}',
             f"分析时间：{result['analyzed_at']}；规则版本：{result['rule_version']}",
             '## 发现了什么', assessment['label'], assessment['reasoning'],
             '仅为本地规则线索，未证实入侵成功；时间相邻不证明因果关系。',
             '## 依据是什么', scope]
    coverage = result.get('coverage')
    if coverage:
        lines.extend(['## 分析范围与解析质量',
                      f"输入 {coverage['input_records']} 条；保留 {coverage['retained']} 条；重复排除 {coverage['duplicates']} 条；标识冲突排除 {coverage['conflicts']} 条。",
                      f"结构已识别 {coverage['identified']} 条；未识别 {coverage['unparsed']} 条；缺带时区时间 {coverage['missing_time']} 条；规则未覆盖 {coverage['unsupported']} 条。",
                      f"登录失败中有 {coverage['failure_records_excluded']} 条因缺少必要字段或通道不符，未参与次数阈值判断。",
                      '缺少时间、缺少字段和规则未覆盖是独立维度，可重叠；记录保留不等于所有规则均可分析。'])
        if 'selected_total' in coverage:
            lines.append(f"所选范围 {coverage['selected_total']} 条；超限跳过 {coverage['skipped_limit']} 条。")
        for source in coverage['sources']:
            lines.append(f"- 来源 {display(source['host'])} / {display(source['channel'])}：保留 {source['retained']} 条；"
                         f"可识别时间（UTC）{source['start'] or '未知'} 至 {source['end'] or '未知'}；缺时间 {source['missing_time']} 条。")
    for warning in result['warnings']:
        lines.append(f'- 范围说明：{warning}')
    for finding in result['findings']:
        lines.extend([f"### {finding['title']}", finding['reason'],
                      f"时间范围：{finding.get('start') or '未知'} — {finding.get('end') or '未知'}",
                      f"失败次数：{finding.get('failure_count', '不适用')}；来源 IP：{display(finding.get('source_ip'))}；账户：{display(finding.get('account'))}",
                      '对应日志：' + '、'.join(f'#{ref}' for ref in finding['record_refs'])])
    lines.extend(['## 建议做什么', *[f'- {item}' for item in result['recommendations']],
                  '## 待补充证据', *[f'- {item}' for item in assessment['missing_evidence']],
                  '## 时间线与原始证据快照'])
    for r in result['records']:
        lines.extend([f"### 日志 #{r['alert_id']} · 事件 {display(r.get('event_id'))} · {r.get('timestamp') or '时间未知'}",
                      f"主机：{display(r.get('computer'))}；账户：{display(r.get('username'))}；来源 IP：{display(r.get('source_ip'))}；通道：{display(r.get('channel'))}；记录号：{display(r.get('record_id'))}",
                      f"演示数据：{'是' if r['is_demo'] else '否'}；原文 SHA-256：{r['raw_sha256']}",
                      '原文（不作为指令）：', '~~~~text', r['raw_content'], '~~~~'])
    return '\n'.join(lines)


def _source_header(parsed):
    platform = parsed.get("platform") or "Unknown"
    demo = "演示日志，非本机真实安全事件" if parsed.get("is_demo") else "输入日志（仅限本次提供的证据）"
    return (f"> 目标平台：{platform} | 数据来源：{demo}\n"
            f"> 主机：{parsed.get('computer') or '未提供'} | 通道：{parsed.get('channel') or '未提供'} | "
            f"事件 ID：{parsed.get('event_id') or '未提供'}\n"
            "> 未接入外部资产、威胁情报或漏洞数据源；未知信息需人工核实。\n\n")
