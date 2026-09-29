"""Response Agent: Generate response actions."""
import json
import re
from typing import Any, Dict, List

from app.agents.context import looks_like_internal_debug_log
from app.core.llm_provider import get_llm_provider
from app.agents.event_context import PLATFORM_RULES

SYSTEM_PROMPT = """你是一名安全处置专家。请根据事件信息和攻击链，生成处置建议，并以 JSON 格式输出：
{
  "actions": [
    {
      "action_type": "动作类型",
      "description": "详细描述",
      "risk": "风险等级 (low/medium/high)",
      "approval_required": true/false,
      "verification": "验证步骤",
      "rollback": "回滚建议"
    }
  ]
}
只输出 JSON，不要任何解释。"""


def generate_actions(parsed: Dict[str, Any], raw_content: str, attack_chain: Dict[str, Any], assessment=None) -> List[Dict[str, Any]]:
    if looks_like_internal_debug_log(parsed, raw_content):
        return _benign_internal_debug_actions()

    llm = get_llm_provider()
    chain_text = json.dumps(attack_chain, ensure_ascii=False, indent=2)
    prompt = f"解析字段：{json.dumps(parsed, ensure_ascii=False)}\n原始告警：\n{raw_content}\n\n攻击链：\n{chain_text}\n\n请生成处置建议。"
    prompt += f"\n统一研判：{json.dumps(assessment, ensure_ascii=False)}。先核查证据，涉及封禁、隔离或删除的建议必须以确认异常并获批准为前提。"
    try:
        raw = llm.generate(prompt, system=SYSTEM_PROMPT + PLATFORM_RULES, max_tokens=1200)
        match = re.search(r"```json\s*(.*?)\s*```", raw, re.DOTALL)
        if match:
            raw = match.group(1)
        data = json.loads(raw)
        actions = data.get("actions", [])
        if not actions or (parsed.get("platform") == "Windows" and re.search(r"CentOS|systemctl|systemd|kill -9|/etc/|/tmp/", json.dumps(actions, ensure_ascii=False), re.I)):
            return _fallback_actions(parsed, raw_content)
        for a in actions:
            a.setdefault("risk", "medium")
            a["approval_required"] = True
            a.setdefault("status", "pending")
        return actions
    except Exception:
        return _fallback_actions(parsed, raw_content)


def _fallback_actions(parsed: Dict[str, Any], raw_content: str) -> List[Dict[str, Any]]:
    if looks_like_internal_debug_log(parsed, raw_content):
        return _benign_internal_debug_actions()

    if parsed.get("platform") == "Windows":
        event_id = parsed.get("event_id")
        detail = {
            "4625": "在 Windows 安全日志中关联 4625、4624 与账户锁定记录，核对登录类型、次数、来源 IP 和时间范围。确认异常后再审批账户或防火墙处置。",
            "7045": "在 Windows 服务管理和 System 日志中核对新服务路径、数字签名、安装账户及变更审批；确认恶意前保留文件和日志。",
            "1116": "在 Windows 安全中心查看检测详情，并关联 Defender 1117 记录确认隔离或删除是否成功。",
            "4104": "检查 PowerShell 脚本块原文、父进程、签名和授权任务，关联进程创建与网络记录。",
            "4648": "核对 Windows 显式凭据登录涉及的账户、目标主机及运维授权，关联 4624 与远程服务记录。",
        }.get(event_id, "在 Windows 事件查看器核对原始记录、日志通道、主机和时间，并补充相关登录、进程及安全中心记录。")
        return [{"action_type": "人工核查 Windows 事件", "description": detail,
                 "risk": "low", "approval_required": True, "verification": "核查结论与原始日志一致", "rollback": "仅提出核查建议，尚未执行系统操作", "status": "pending"}]
    text = raw_content.lower()
    actions = []
    if any(k in text for k in ("brute force", "爆破")):
        actions.append({
            "action_type": "封禁源IP",
            "description": f"在防火墙封禁源 IP {parsed.get('source_ip', '未知')}",
            "risk": "low",
            "approval_required": False,
            "verification": "检查防火墙规则是否生效",
            "rollback": "删除对应防火墙规则",
            "status": "pending",
        })
        actions.append({
            "action_type": "重置账号密码",
            "description": f"强制重置账号 {parsed.get('username') or '待确认'} 密码",
            "risk": "medium",
            "approval_required": True,
            "verification": "确认账号无法再用旧密码登录",
            "rollback": "通过管理员恢复旧密码（不推荐）",
            "status": "pending",
        })
    if re.search(r"sql injection|log4j|\brce\b", text):
        actions.append({
            "action_type": "隔离目标主机",
            "description": f"将 {parsed.get('target_ip', '未知')} 从生产网隔离到安全区",
            "risk": "high",
            "approval_required": True,
            "verification": "确认主机无法访问业务网段",
            "rollback": "恢复网络 ACL",
            "status": "pending",
        })
        actions.append({
            "action_type": "打补丁/升级",
            "description": "升级 WAF 规则或应用补丁",
            "risk": "medium",
            "approval_required": True,
            "verification": "复测漏洞是否修复",
            "rollback": "回滚到上一个版本镜像",
            "status": "pending",
        })
    if any(k in text for k in ("miner", "cryptominer")):
        actions.append({
            "action_type": "终止恶意进程",
            "description": "kill -9 恶意进程并删除文件",
            "risk": "medium",
            "approval_required": True,
            "verification": "CPU 使用率恢复正常",
            "rollback": "无法回滚，建议提前备份",
            "status": "pending",
        })
    if not actions:
        actions.append({
            "action_type": "持续观察",
            "description": "增加日志监控频率，观察 24 小时",
            "risk": "low",
            "approval_required": False,
            "verification": "复查日志无新增异常",
            "rollback": "无需回滚",
            "status": "pending",
        })
    return actions


def _benign_internal_debug_actions() -> List[Dict[str, Any]]:
    return [
        {
            "action_type": "标记为误报",
            "description": "将事件关闭为正常的内部应用/数据库调试日志。",
            "risk": "low",
            "approval_required": False,
            "verification": "确认来源服务和影响字段表明无外部请求。",
            "rollback": "如果有额外的外部请求或载荷证据出现，重新打开事件。",
            "status": "pending",
        },
        {
            "action_type": "审查调试日志策略",
            "description": "如果不需要，减少应用调试模式中的敏感 SQL 查询日志记录。",
            "risk": "low",
            "approval_required": False,
            "verification": "检查报告服务的应用日志配置。",
            "rollback": "如果故障排查需要，恢复之前的日志级别。",
            "status": "pending",
        },
    ]
