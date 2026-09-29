"""Source metadata is independent of the computer running WinSecAgent."""
import json
import re
from xml.etree import ElementTree


def extract_event_context(raw, _depth=0):
    fields = {}
    original_context = {}
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            if isinstance(data.get("OriginalLog"), str) and _depth < 3:
                original_context = extract_event_context(data["OriginalLog"], _depth + 1)
            fields.update(data)
            if isinstance(data.get("EventData"), dict):
                fields.update(data["EventData"])
    except (ValueError, TypeError):
        pass
    if raw.lstrip().startswith("<"):
        try:
            for elem in ElementTree.fromstring(raw).iter():
                tag = elem.tag.rsplit("}", 1)[-1]
                if tag == "Data" and elem.get("Name"):
                    fields[elem.get("Name")] = elem.text
                elif tag == "TimeCreated":
                    fields[tag] = elem.get("SystemTime")
                elif tag == "Provider":
                    fields["ProviderName"] = elem.get("Name")
                elif tag in ("EventID", "Channel", "Computer", "EventRecordID"):
                    fields[tag] = elem.text
        except ElementTree.ParseError:
            pass
    for line in raw.splitlines():
        match = re.match(r"^\s*([\w\s]+?)\s*[:：]\s*(.+?)\s*$", line)
        if match:
            fields.setdefault(match.group(1).strip(), match.group(2))
    normalized = {re.sub(r"[\s_]", "", str(k)).lower(): v for k, v in fields.items()}

    def value(*names):
        for name in names:
            v = normalized.get(re.sub(r"[\s_]", "", name).lower())
            if v is not None and str(v).strip() not in ("", "-", "unknown", "未知"):
                return v
        return None

    explicit = str(value("Platform", "平台", "操作系统") or "").lower()
    event_id = value("EventID", "事件ID")
    channel = value("Channel", "日志名称", "通道")
    text = raw.lower()
    if explicit in ("windows", "linux", "macos"):
        platform = {"windows": "Windows", "linux": "Linux", "macos": "macOS"}[explicit]
    elif "microsoft-windows" in text or (event_id and str(channel).lower() in ("security", "system", "application")):
        platform = "Windows"
    elif re.search(r"\b(?:centos|ubuntu|linux|systemd)\b|/tmp/|/etc/", text):
        platform = "Linux"
    elif re.search(r"[a-z]:\\|\b(?:powershell|psexec|winlogon)\b", text):
        platform = "Windows"
    else:
        platform = "Unknown"
    result = {
        "platform": platform,
        "event_id": str(event_id) if event_id is not None else None,
        "channel": channel,
        "computer": value("Computer", "计算机", "主机名", "Host"),
        "provider_name": value("ProviderName", "Provider", "来源"),
        "source_ip": value("IpAddress", "SourceAddress", "SourceIP", "源网络地址"),
        "target_ip": value("TargetIP", "DestinationIp"),
        "target_port": value("DestinationPort", "TargetPort", "目标端口"),
        "username": value("TargetUserName", "Account", "UserName", "目标账户", "账户名"),
        "timestamp": value("TimeCreated", "SystemTime", "Time", "时间"),
        "record_id": value("RecordId", "EventRecordID"),
        "account_domain": value("TargetDomainName", "AccountDomain"),
        "subject_user": value("SubjectUserName"),
        "subject_domain": value("SubjectDomainName"),
        "logon_id": value("TargetLogonId", "SubjectLogonId"),
        "service_name": value("ServiceName"),
        "service_path": value("ServiceFileName", "ImagePath"),
        "service_start": value("StartType", "ServiceStartType"),
        "script_text": value("ScriptBlockText"),
        "is_demo": value("IsDemo") is True or str(value("IsDemo")).lower() == "true" or "[演示数据]" in raw,
    }
    for key, value in original_context.items():
        if result.get(key) is None or (key == "platform" and result[key] == "Unknown"):
            result[key] = value
    result['is_demo'] = result['is_demo'] or original_context.get('is_demo', False)
    return result


def serialize_windows_event(event, is_demo=False):
    return json.dumps({**event, "Platform": "Windows", "IsDemo": is_demo}, ensure_ascii=False, indent=2)


PLATFORM_RULES = """
平台与证据规则：以解析字段 platform 和原始日志为准，不根据本程序运行环境推断目标平台。
Windows 事件使用 Windows 事件查看器、Security/System/Defender/PowerShell 日志语境。
不要为 Windows 目标编造 CentOS、systemd、/tmp、/etc 或 kill -9 等 Linux 信息和命令。
平台 Unknown 时标注待确认。未提供的系统版本、资产、威胁情报和漏洞均为未知。
演示输入只能作为演示分析；不能声称已查询外部日志、CMDB、IOC 数据库或已执行处置。
事件 ID 表示事件类型，不单独证明攻击成功。单次失败登录不等于暴力破解。
"""
