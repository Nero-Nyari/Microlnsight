"""Windows 事件日志读取器.

通过 pywin32 读取本地 Windows 事件日志中的安全/系统/应用/Defender 日志。
非 Windows 平台使用明确标记的演示数据；Windows 读取失败不生成假数据。
"""
from __future__ import annotations

import json
import platform
import random
from xml.etree import ElementTree
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

# ---------- suspicious event IDs ----------
SUSPICIOUS_IDS = {
    4104,  # PowerShell script block
    4625,  # failed logon
    4648,  # explicit credentials logon
    4740,  # account locked out
    4720,  # user account created
    4722,  # user account enabled
    4724,  # password reset attempt
    4726,  # user account deleted
    4732,  # member added to local group
    7045,  # new service installed
    1116,  # Defender malware detected
    1117,  # Defender malware action
    4697,  # service installed in security log
    5156,  # Windows Filtering Platform connection
}

CHANNELS = ["Security", "System", "Application", "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-PowerShell/Operational"]

# ---------- Mock data generation ----------

_MOCK_TEMPLATES: List[Dict[str, Any]] = [
    {"EventID": 4625, "Level": 2, "Channel": "Security",
     "Message": "账户登录失败。\n主体: security agent\n目标账户: admin\n源网络地址: 192.168.1.105\n失败原因: 用户名未知或密码错误。"},
    {"EventID": 4625, "Level": 2, "Channel": "Security",
     "Message": "账户登录失败。\n主体: security agent\n目标账户: administrator\n源网络地址: 10.0.0.22\n失败原因: 账户锁定。"},
    {"EventID": 4648, "Level": 3, "Channel": "Security",
     "Message": "使用显式凭据尝试登录。\n主体: WIN10-PC\\user1\n目标服务器: LOCALHOST\n使用了新凭据。"},
    {"EventID": 4740, "Level": 2, "Channel": "Security",
     "Message": "用户账户被锁定。\n目标账户: administrator\n调用计算机名: WIN10-PC"},
    {"EventID": 7045, "Level": 3, "Channel": "System",
     "Message": "系统中安装了新服务。\n服务名: SuspiciousService\n服务类型: 用户模式服务\n启动类型: 自动启动\n服务路径: C:\\Temp\\svc.exe"},
    {"EventID": 1116, "Level": 2, "Channel": "Microsoft-Windows-Windows Defender/Operational",
     "Message": "Windows Defender 检测到恶意软件。\n检测名称: Trojan:Win32/Emotet\n资源: C:\\Users\\Public\\payload.exe\n操作: 失败"},
    {"EventID": 1117, "Level": 2, "Channel": "Microsoft-Windows-Windows Defender/Operational",
     "Message": "Windows Defender 已采取操作保护系统免受恶意软件侵害。\n检测名称: Ransom:Win32/WannaCry\n资源: D:\\data\\file.doc\n操作: 已隔离"},
    {"EventID": 4720, "Level": 4, "Channel": "Security",
     "Message": "创建了新用户账户。\n新账户名: backdoor_admin\n新账户域: WIN10-PC"},
    {"EventID": 4697, "Level": 3, "Channel": "Security",
     "Message": "系统中安装了服务。\n服务名: StealthService\n服务文件名: C:\\Windows\\Temp\\stealth.exe"},
]


def _generate_mock_events(count: int = 25) -> List[Dict[str, Any]]:
    """生成合成 Windows 事件用于演示 / 非 Windows 环境."""
    events = []
    now = datetime.now()
    for i in range(count):
        tpl = random.choice(_MOCK_TEMPLATES)
        event = dict(tpl)
        event["TimeCreated"] = (now - timedelta(minutes=random.randint(1, 1440))).strftime("%Y-%m-%d %H:%M:%S")
        event["RecordId"] = 100000 + i
        event["ProviderName"] = "Microsoft-Windows-Security-Auditing"
        events.append(event)
    events.sort(key=lambda e: e["TimeCreated"], reverse=True)
    return events


def _filter_suspicious(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """仅保留 EventID 在 SUSPICIOUS_IDS 中的事件."""
    return [e for e in events if e.get("EventID") in SUSPICIOUS_IDS]


# ---------- Real Windows reading ----------

def _error_code(exc):
    code = getattr(exc, "winerror", None)
    if code is None and exc.args and isinstance(exc.args[0], int):
        code = exc.args[0]
    return code


def _channel_error(channel, exc):
    code = _error_code(exc)
    if code == 5:
        kind, message = "access_denied", f"{channel} 日志读取权限不足。"
    elif code == 15007:
        kind, message = "channel_not_found", f"{channel} 通道不存在，请检查通道名称或系统组件。"
    else:
        kind, message = "read_error", f"{channel} 未完整读取，请展开查看详情。"
    return {"error_kind": kind, "error_code": code, "message": message, "detail": str(exc)}


def _reader_context():
    """Inspect the backend process token without enabling privileges."""
    context = {"account": None, "elevated": None}
    token = None
    try:
        import win32api
        import win32security
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), 8)  # TOKEN_QUERY
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        name, domain, _ = win32security.LookupAccountSid(None, sid)
        context["account"] = f"{domain}\\{name}" if domain else name
        context["elevated"] = bool(win32security.GetTokenInformation(token, win32security.TokenElevation))
    except Exception:
        pass  # Unknown diagnostics must not prevent reading.
    finally:
        if token is not None:
            token.Close()
    return context


def _read_real_logs(channels=None, max_events=200):
    results = []
    channels = list(dict.fromkeys(channels or CHANNELS))
    try:
        import win32evtlog
    except ImportError:
        return [], [{"channel": channel, "status": "failed", "events_read": 0,
                     "error_kind": "dependency_missing", "error_code": None,
                     "message": "未安装 pywin32，无法读取 Windows 日志。未生成模拟数据。"}
                    for channel in channels]
    events = []
    for channel in channels:
        query = None
        count = 0
        result = {"channel": channel, "status": "success", "events_read": 0}
        try:
            query = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryReverseDirection, "*")
            while count < max_events:
                try:
                    batch = win32evtlog.EvtNext(query, min(32, max_events - count))
                except Exception as exc:
                    if _error_code(exc) == 259:  # ERROR_NO_MORE_ITEMS is normal EOF.
                        break
                    raise
                if not batch:
                    break
                try:
                    for event in batch:
                        root = ElementTree.fromstring(win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml))
                        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                        system = root.find("e:System", ns)
                        def text(name):
                            return system.findtext("e:" + name, default="", namespaces=ns)
                        data = {item.get("Name", str(i)): item.text or "" for i, item in enumerate(root.findall("e:EventData/e:Data", ns))}
                        provider = system.find("e:Provider", ns)
                        timestamp = system.find("e:TimeCreated", ns)
                        message = root.findtext("e:RenderingInfo/e:Message", default="", namespaces=ns)
                        if not message:
                            message = json.dumps(data, ensure_ascii=False) if data else "事件未提供格式化消息，请核对原始 XML。"
                        events.append({"TimeCreated": timestamp.get("SystemTime", "") if timestamp is not None else "",
                            "EventID": int(text("EventID")), "Level": int(text("Level") or 4),
                            "Channel": text("Channel") or channel, "Computer": text("Computer"),
                            "ProviderName": provider.get("Name", "") if provider is not None else "",
                            "RecordId": int(text("EventRecordID") or 0), "Message": message, "EventData": data,
                            "OriginalXml": ElementTree.tostring(root, encoding="unicode")})
                        count += 1
                finally:
                    # Also close remaining handles if rendering one event failed.
                    for event in batch:
                        event.Close()
        except Exception as exc:
            result.update(_channel_error(channel, exc))
            result["status"] = "partial" if count else "failed"
        finally:
            if query is not None:
                query.Close()
        result["events_read"] = count
        results.append(result)
    return events, results


# ---------- Public API ----------

def read_windows_logs(
    channels: Optional[List[str]] = None,
    suspicious_only: bool = True,
    max_events: int = 200,
) -> Dict[str, Any]:
    """Read Windows logs and return structured result.

    Returns dict with keys: events, stats, timestamp, is_mock.
    """
    is_windows = platform.system() == "Windows"

    channel_results = []
    reader_context = None
    if is_windows:
        raw_events, channel_results = _read_real_logs(channels, max_events)
        reader_context = _reader_context()
        is_mock = False
    else:
        raw_events = _generate_mock_events(max_events)
        is_mock = True

    warnings = [r["message"] for r in channel_results if r["status"] != "success"]
    read_status = "demo" if is_mock else "success"
    if warnings:
        read_status = "partial" if raw_events or any(r["status"] == "success" for r in channel_results) else "failed"

    if suspicious_only:
        events = _filter_suspicious(raw_events)
    else:
        events = raw_events

    # Build stats
    id_counts: Dict[int, int] = {}
    channel_counts: Dict[str, int] = {}
    for e in events:
        eid = e.get("EventID", 0)
        id_counts[eid] = id_counts.get(eid, 0) + 1
        ch = e.get("Channel", "Unknown")
        channel_counts[ch] = channel_counts.get(ch, 0) + 1

    return {
        "events": events,
        "warnings": warnings,
        "read_status": read_status,
        "channel_results": channel_results,
        "reader_context": reader_context,
        "total_raw": len(raw_events),
        "total_filtered": len(events),
        "event_id_stats": id_counts,
        "channel_stats": channel_counts,
        "timestamp": datetime.now().isoformat(),
        "is_mock": is_mock,
        "platform": platform.system(),
    }


def format_events_for_llm(events: List[Dict[str, Any]], max_events: int = 30) -> str:
    """将事件格式化为适合 LLM 提示的文本块."""
    lines = []
    for e in events[:max_events]:
        lines.append(
            f"[{e.get('TimeCreated', '?')}] EventID={e.get('EventID')} "
            f"Channel={e.get('Channel', '?')} Level={e.get('Level', '?')}\n"
            f"  {e.get('Message', '')[:300]}"
        )
    return "\n\n".join(lines)
