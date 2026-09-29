"""One decision shared by triage, downstream agents and the log/alert queues."""
import json
import math
import re

VERSION = 1
LABELS = {"benign": "正常活动", "unknown": "证据不足，待核实",
          "suspicious": "发现异常线索", "malicious": "发现恶意行为线索"}
DEFAULT_MISSING = ["执行账户、父进程及操作授权", "相同时间范围的关联日志和实际执行结果"]


def source_text(raw):
    """Decode JSON strings so quoted evidence can match nested imported events."""
    texts = [raw or ""]
    def visit(value, depth=0):
        if depth > 8:
            return
        if isinstance(value, dict):
            for v in value.values():
                visit(v, depth + 1)
        elif isinstance(value, list):
            for v in value:
                visit(v, depth + 1)
        elif isinstance(value, str):
            texts.append(value)
            try:
                decoded = json.loads(value)
                if isinstance(decoded, (dict, list)):
                    visit(decoded, depth + 1)
            except (ValueError, TypeError):
                pass
    try:
        visit(json.loads(raw or ""))
    except (ValueError, TypeError):
        pass
    return "\n".join(texts)


def normalize_triage(result, raw):
    result = result if isinstance(result, dict) else {}
    classification = result.get("classification", "unknown")
    disposition = result.get("disposition")
    missing = result.get("missing_evidence")
    missing = [str(x)[:300] for x in missing[:8]] if isinstance(missing, list) else []
    findings = []
    text = source_text(raw)
    for item in (result.get("findings") or []) if isinstance(result.get("findings"), list) else []:
        if not isinstance(item, dict):
            continue
        quote = str(item.get("quote", "")).strip()
        reason = str(item.get("reason", "")).strip()
        if len(quote) >= 8 and quote in text and reason:
            findings.append({"quote": quote[:2000], "reason": reason[:600]})
    if classification not in LABELS:
        classification = "unknown"
    contradiction = ((classification == "benign" and disposition in ("true_positive", "needs_review")) or
                     (classification in ("suspicious", "malicious") and disposition == "false_positive"))
    if contradiction:
        classification = "unknown"
        missing.append("模型分类与处理结论冲突，需重新核实")
    if classification in ("suspicious", "malicious") and not findings:
        classification = "unknown"
        missing.append("能够在日志原文定位的异常证据片段")
    try:
        confidence = float(result.get("confidence", 0))
        confidence = min(1.0, max(0.0, confidence)) if math.isfinite(confidence) else 0.0
    except (TypeError, ValueError):
        confidence = 0.0
    reason = str(result.get("reasoning") or "尚无充分证据形成安全结论。")
    # A single imported failure cannot substantiate a frequency-based claim.
    # Multi-record local analysis counts distinct records in correlation.py.
    if classification in ('suspicious', 'malicious') and re.search(r'爆破|暴力破解|密码猜测|brute.?force', reason + str(result.get('event_type', '')), re.I):
        from app.agents.event_context import extract_event_context
        if extract_event_context(raw).get('event_id') == '4625':
            classification = 'unknown'
            missing.append('补充同主机、账户、来源 IP 的独立 4625 记录及带时区时间，运行联合分析核实失败次数；单条日志描述不能代替计数')
    if classification == "benign" and re.search(r"攻击者|已入侵|已失陷|成功入侵|成功植入", reason):
        classification = "unknown"
        missing.append("正常分类与攻击叙述冲突，需核实原文及操作授权")
    if classification == "unknown":
        confidence = 0.0
        reason = "现有证据或分析结果不足以形成一致结论，需补充证据后复核。"
        missing = missing or DEFAULT_MISSING.copy()
    risk = result.get("risk_level", "medium")
    if risk not in ("info", "low", "medium", "high", "critical"):
        risk = "medium"
    if classification in ("benign", "unknown"):
        risk = "info"
    return {"assessment_version": VERSION, "event_type": result.get("event_type") or "日志待核查",
            "classification": classification, "label": LABELS[classification],
            "disposition": "false_positive" if classification == "benign" else "needs_review",
            "risk_level": risk, "confidence": confidence, "reasoning": reason,
            "findings": findings[:10], "missing_evidence": list(dict.fromkeys(missing or DEFAULT_MISSING)),
            "queue": "alerts" if classification in ("suspicious", "malicious") else "logs"}


def constrained_chain(assessment):
    if assessment["classification"] == "benign":
        path = "不适用：当前研判为正常活动，未建立攻击链。"
    else:
        path = "待核实：现有证据不足以建立攻击链。"
    return {"stages": [], "attack_path": path, "suspicious_success": "未确认攻击成功。",
            "missing_evidence": assessment["missing_evidence"]}


def constrained_actions(assessment):
    benign = assessment["classification"] == "benign"
    return [{"action_type": "保留日志并核对授权" if benign else "补充证据后人工复核",
             "description": ("当前不建议封禁、隔离或删除。核对 Windows 操作时间和授权，保留日志。" if benign else
                             "核对 Windows 原始日志、执行账户、父进程与关联事件；结论明确前不执行封禁、隔离或删除。"),
             "risk": "low", "approval_required": True, "status": "pending"}]
