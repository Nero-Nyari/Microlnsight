"""风险研判智能体: 风险评估."""
import json
import re
from typing import Any, Dict

from app.agents.context import benign_internal_debug_result, looks_like_internal_debug_log
from app.core.llm_provider import get_llm_provider
from app.agents.event_context import PLATFORM_RULES

SYSTEM_PROMPT = """你是一名资深安全研判分析师。
请评估已解析的告警，仅返回 JSON 格式：
{
  "event_type": "事件类型",
  "risk_level": "critical/high/medium/low/info",
  "confidence": 0.0,
  "priority": "P0/P1/P2/P3",
  "classification": "malicious/suspicious/benign/unknown",
  "disposition": "true_positive/false_positive/needs_review",
  "reasoning": "简短的基于证据的解释",
  "findings": [{"quote": "从原始日志逐字引用的完整异常片段，不少于8个字符", "reason": "该片段为何构成异常线索"}],
  "missing_evidence": ["还需要哪些证据才能确认结论"]
}

误报控制规则：
- 没有异常线索时 findings 使用空数组；不得用事件 ID、工具名称或日志等级本身证明恶意。
- benign 仅表示当前日志行为正常，disposition 必须为 false_positive；无法判断时使用 unknown/needs_review。
- suspicious/malicious 必须提供可逐字定位的异常证据 findings。malicious 也不等于已证明入侵成功。
- Add-Type、进程枚举、ROT13 和 UserAssist 读取均可用于正常管理，不单独作为恶意证据。
- 不要仅凭 SQL 关键字就将事件判定为 SQL 注入。
- 在应用日志、数据库调试消息、开发者调试模式、
  最后查询、SQL 审计日志、SQL 日志、内部服务、后端服务、
  调度器、定时任务、报告服务或"未检测到外部请求"上下文中的 SQL，
  通常是正常的内部/调试日志。
- 仅当 SQL 关键字出现在外部 HTTP
  URL/参数/请求体/Cookie/请求头输入中，且存在注入结构如
  OR 1=1、UNION SELECT、SLEEP、注释、sqlmap、异常 SQL 错误、
  异常返回行数、延迟、认证绕过或数据泄露
  影响时，才判定为 SQL 注入尝试。
- 如果证据是内部服务调试日志且未检测到外部请求，
  使用 risk_level low 或 info，classification benign，disposition
  false_positive。
"""


def triage(parsed: Dict[str, Any], raw_content: str) -> Dict[str, Any]:
    if looks_like_internal_debug_log(parsed, raw_content):
        return benign_internal_debug_result(parsed, raw_content)

    llm = get_llm_provider()
    prompt = (
        "原始告警:\n"
        f"{raw_content}\n\n"
        "解析字段:\n"
        f"{json.dumps(parsed, ensure_ascii=False, indent=2)}\n\n"
        "请进行风险研判。特别注意这是外部攻击记录还是内部/调试/应用日志。"
    )
    try:
        raw = llm.generate(prompt, system=SYSTEM_PROMPT + PLATFORM_RULES, max_tokens=1024)
        match = re.search(r"```json\s*(.*?)\s*```", raw, re.DOTALL)
        if match:
            raw = match.group(1)
        result = json.loads(raw)
        result["confidence"] = float(result.get("confidence", 0.8))
        return _guard_triage_result(result, parsed, raw_content)
    except Exception:
        return _fallback_triage(parsed, raw_content)


def _guard_triage_result(result: Dict[str, Any], parsed: Dict[str, Any], raw_content: str) -> Dict[str, Any]:
    if looks_like_internal_debug_log(parsed, raw_content):
        return benign_internal_debug_result(parsed, raw_content)
    return result


def _fallback_triage(parsed: Dict[str, Any], raw_content: str) -> Dict[str, Any]:
    if looks_like_internal_debug_log(parsed, raw_content):
        return benign_internal_debug_result(parsed, raw_content)

    if parsed.get("platform") == "Windows" and parsed.get("event_id"):
        return {
            "event_type": parsed.get("alert_type") or "Windows 事件待核查",
            "risk_level": "medium", "confidence": 0.5, "priority": "P2",
            "classification": "unknown", "disposition": "needs_review",
            "reasoning": "模型研判不可用，已保留 Windows 事件字段供人工核查。事件 ID 本身不足以判断攻击成功，需关联时间范围、次数及处置结果。",
        }

    text = raw_content.lower()

    has_sql_keyword = any(k in text for k in ("select ", " union ", " from ", " admin", "password"))
    has_sql_attack_context = any(
        k in text
        for k in (
            "sql injection",
            "payload:",
            "sqlmap",
            "' or '1'='1",
            " union select ",
            " sleep(",
            "--",
            "/*",
            "impact: 200 ok returned",
            "sql error",
        )
    )
    has_external_context = any(k in text for k in ("waf alert", "http", "uri:", "url:", "body:", "cookie:", "header:"))

    if has_sql_keyword and not (has_sql_attack_context and has_external_context):
        return {
            "event_type": "需要审查的应用或数据库日志",
            "risk_level": "low",
            "confidence": 0.75,
            "priority": "P3",
            "classification": "benign",
            "disposition": "needs_review",
            "reasoning": "发现了 SQL 关键字，但没有明确的外部请求或注入载荷证据。",
        }

    if re.search(r"\brce\b|reverse shell|log4j", text):
        return {
            "event_type": "高危漏洞利用尝试",
            "risk_level": "critical",
            "confidence": 0.95,
            "priority": "P0",
            "classification": "malicious",
            "disposition": "true_positive",
            "reasoning": "发现了远程执行或命令控制证据。",
        }
    if has_sql_attack_context and has_external_context:
        return {
            "event_type": "SQL 注入尝试",
            "risk_level": "critical",
            "confidence": 0.9,
            "priority": "P0",
            "classification": "malicious",
            "disposition": "true_positive",
            "reasoning": "在外部请求上下文中发现了 SQL 注入载荷证据。",
        }
    if any(k in text for k in ("brute force", "mimikatz", "lateral movement", "psexec", "wmi")):
        return {
            "event_type": "入侵或横向移动",
            "risk_level": "high",
            "confidence": 0.88,
            "priority": "P1",
            "classification": "suspicious",
            "disposition": "needs_review",
            "reasoning": "发现了认证攻击或横向移动指标。",
        }
    if any(k in text for k in ("miner", "cryptominer")):
        return {
            "event_type": "恶意软件或挖矿",
            "risk_level": "medium",
            "confidence": 0.82,
            "priority": "P2",
            "classification": "suspicious",
            "disposition": "needs_review",
            "reasoning": "发现了挖矿指标。",
        }
    return {
        "event_type": "未知或低信号事件",
        "risk_level": "low",
        "confidence": 0.5,
        "priority": "P3",
        "classification": "benign",
        "disposition": "needs_review",
        "reasoning": "未发现明确的攻击证据。",
    }
