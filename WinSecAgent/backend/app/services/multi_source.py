"""Read Windows host information; failures must never become synthetic evidence."""
import json
import platform
import subprocess


def _powershell(script):
    if platform.system() != "Windows":
        raise RuntimeError("此版本仅支持 Windows 本机采集")
    command = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); $ErrorActionPreference='Stop'; " + script + " | ConvertTo-Json -Depth 5 -Compress"
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, encoding="utf-8", errors="replace", timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise RuntimeError("采集命令失败，请检查当前账户的读取权限及 Windows 管理服务状态")
    data = json.loads(result.stdout.strip() or "[]")
    return data if isinstance(data, list) else [data]


def collect_processes():
    rows = _powershell("Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CommandLine")
    return [{"type": "process", "pid": row.get("ProcessId"), "name": row.get("Name"), "path": row.get("ExecutablePath") or "路径不可读", "command_line": row.get("CommandLine") or ""} for row in rows]


def collect_services():
    rows = _powershell("Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,PathName")
    return [{"type": "service", "name": row.get("Name"), "display_name": row.get("DisplayName"), "state": row.get("State"), "path": row.get("PathName")} for row in rows]


def collect_network_connections():
    if platform.system() != "Windows":
        raise RuntimeError("此版本仅支持 Windows 本机采集")
    result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise RuntimeError("网络连接读取失败")
    rows = []
    for line in result.stdout.splitlines():
        p = line.split()
        if p and ((p[0] == "TCP" and len(p) >= 5) or (p[0] == "UDP" and len(p) >= 4)):
            rows.append({"type": "network", "protocol": p[0], "local": p[1], "remote": p[2], "state": p[3] if p[0] == "TCP" else "", "pid": p[-1]})
    return rows


def collect_scheduled_tasks():
    rows = _powershell("Get-ScheduledTask | Select-Object TaskName,TaskPath,State")
    return [{"type": "scheduled_task", "name": str(row.get("TaskPath", "")) + str(row.get("TaskName", "")), "status": row.get("State"), "next_run": "未读取"} for row in rows]


def collect_registry_suspicious():
    import winreg
    rows = []
    for hive, prefix in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
        for suffix in ("Run", "RunOnce"):
            path = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\{suffix}"
            try:
                with winreg.OpenKey(hive, path) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, i)
                        rows.append({"type": "registry", "key": prefix + "\\" + path, "value": f"{name}: {value}"})
            except FileNotFoundError:
                continue
    return rows


def collect_all():
    result = {"platform": platform.system(), "is_mock": False, "warnings": []}
    for name, collector in (("processes", collect_processes), ("network_connections", collect_network_connections),
                            ("services", collect_services), ("scheduled_tasks", collect_scheduled_tasks), ("registry", collect_registry_suspicious)):
        try:
            result[name] = collector()
        except Exception as exc:
            result[name] = []
            result["warnings"].append(f"{name} 未成功读取：{exc}。未使用演示数据替代。")
    return result
