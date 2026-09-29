"""Windows examples, explicitly marked as synthetic input."""
from app.agents.event_context import serialize_windows_event


def _case(case_id, title, event_id, channel, message, data, severity="high"):
    return {
        "id": case_id, "title": title, "severity": severity,
        "raw_content": serialize_windows_event({
            "EventID": event_id, "Channel": channel, "Computer": "WIN-LAB-01",
            "ProviderName": "Microsoft-Windows-Security-Auditing" if channel == "Security" else channel,
            "TimeCreated": "2026-09-29T02:00:00Z", "Message": message, "EventData": data,
        }, is_demo=True),
    }


DEMO_CASES = [
    _case("windows_failed_logon", "Windows 登录失败激增 · 4625", 4625, "Security",
          "[演示数据] 5 分钟内同一来源出现 120 次登录失败，LogonType=10；未提供成功登录记录，需核实是否为远程桌面暴力破解。",
          {"TargetUserName": "lab_admin", "IpAddress": "192.0.2.10", "LogonType": 10}),
    _case("windows_service", "可疑服务安装 · 7045", 7045, "System",
          r"[演示数据] 新安装自动启动服务 LabUpdater，路径 C:\ProgramData\Lab\updater.exe；签名与变更审批待核实。",
          {"ServiceName": "LabUpdater", "ImagePath": r"C:\ProgramData\Lab\updater.exe"}),
    _case("windows_defender", "Defender 威胁检测 · 1116", 1116, "Microsoft-Windows-Windows Defender/Operational",
          r"[演示数据] Defender 检测到测试威胁，资源 C:\Users\Public\sample.exe。未提供 1117 处置结果，不能确认已隔离。",
          {"Path": r"C:\Users\Public\sample.exe"}),
    _case("windows_powershell", "PowerShell 可疑脚本 · 4104", 4104, "Microsoft-Windows-PowerShell/Operational",
          "[演示数据] 脚本块包含编码参数及下载行为描述；完整脚本、父进程和网络证据待核实，尚未确认恶意执行。",
          {"ScriptBlockId": "lab-demo-script", "TargetUserName": "lab_user"}, "medium"),
    _case("windows_credentials", "显式凭据登录 · 4648", 4648, "Security",
          "[演示数据] 服务账户从非日常来源使用显式凭据访问 WIN-FILE-02，需核对运维任务与登录授权；未确认横向移动。",
          {"TargetUserName": "svc_backup", "IpAddress": "192.0.2.20", "TargetServerName": "WIN-FILE-02"}),
]


def get_demo_case(case_id):
    return next((case for case in DEMO_CASES if case["id"] == case_id), None)
