"""攻击链智能体: 将事件映射到 MITRE ATT&CK 阶段."""
import json
import re
from typing import Any, Dict, List

from app.agents.context import looks_like_internal_debug_log
from app.core.llm_provider import get_llm_provider
from app.agents.event_context import PLATFORM_RULES

SYSTEM_PROMPT = """你是一名攻击链分析专家。请根据安全事件信息，将事件映射到 MITRE ATT&CK 框架的简化攻击阶段，并以 JSON 格式输出：
{
  "stages": [
    {"stage": "阶段名称(如 Initial Access)", "evidence": "对应证据", "confidence": 0.9}
  ],
  "attack_path": "攻击路径文字描述",
  "suspicious_success": "最可疑的成功点"
}
只输出 JSON，不要任何解释。"""


def analyze_attack_chain(parsed: Dict[str, Any], raw_content: str, evidence: List[Dict[str, Any]], assessment=None) -> Dict[str, Any]:
    if looks_like_internal_debug_log(parsed, raw_content):
        return {
            "stages": [],
            "attack_path": "无 / 不适用",
            "suspicious_success": "未识别到攻击链",
        }

    llm = get_llm_provider()
    evidence_text = "\n".join([f"- {e['title']}: {e['content']}" for e in evidence[:4]])
    prompt = f"原始告警：\n{raw_content}\n\n解析字段：\n{json.dumps(parsed, ensure_ascii=False)}\n\n证据：\n{evidence_text}\n\n请分析攻击链。"
    prompt += f"\n统一研判（不得重新下结论）：{json.dumps(assessment, ensure_ascii=False)}。只描述可能的阶段和待核实线索，不把猜测写成已发生的攻击。"
    try:
        raw = llm.generate(prompt, system=SYSTEM_PROMPT + PLATFORM_RULES, max_tokens=1200)
        match = re.search(r"```json\s*(.*?)\s*```", raw, re.DOTALL)
        if match:
            raw = match.group(1)
        return json.loads(raw)
    except Exception:
        return _fallback_chain(parsed, raw_content)


def _fallback_chain(parsed: Dict[str, Any], raw_content: str) -> Dict[str, Any]:
    if looks_like_internal_debug_log(parsed, raw_content):
        return {
            "stages": [],
            "attack_path": "无 / 不适用",
            "suspicious_success": "未识别到攻击链",
        }

    if parsed.get("platform") == "Windows":
        return {"stages": [], "attack_path": "待核实", "suspicious_success": "现有事件不足以确认攻击成功；请补充关联日志。"}
    text = raw_content.lower()
    stages = []
    if any(k in text for k in ("brute force", "爆破", "jndi", "sql injection", "payload")):
        stages.append({"stage": "Initial Access", "evidence": "攻击者通过漏洞或暴力破解进入", "confidence": 0.9})
    if any(k in text for k in ("execution", "脚本", "shell", "mimikatz")):
        stages.append({"stage": "Execution", "evidence": "检测到命令执行或工具运行", "confidence": 0.85})
    if any(k in text for k in ("lateral movement", "横向移动", "psexec", "wmi")):
        stages.append({"stage": "Lateral Movement", "evidence": "检测到横向登录或远程执行", "confidence": 0.88})
    if any(k in text for k in ("c2", "reverse shell", "外联", "sustained connection")):
        stages.append({"stage": "Command and Control", "evidence": "检测到反向 Shell 或持久外联", "confidence": 0.9})
    if any(k in text for k in ("miner", "cpu", "cryptominer")):
        stages.append({"stage": "Impact", "evidence": "资源滥用/挖矿", "confidence": 0.82})
    if not stages:
        stages.append({"stage": "Reconnaissance", "evidence": "检测到可疑扫描或探测行为", "confidence": 0.6})
    return {
        "stages": stages,
        "attack_path": " -> ".join([s["stage"] for s in stages]),
        "suspicious_success": stages[0]["evidence"] if stages else "未知",
    }
