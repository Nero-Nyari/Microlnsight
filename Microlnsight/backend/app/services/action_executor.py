"""Real system action executor for approved response actions.

Executes actual Windows system commands (firewall rules, account management,
file quarantine) when actions are approved.  Supports dry-run mode.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


class ActionExecutor:
    """在 Windows 上执行真实的系统级响应动作."""

    def __init__(self, dry_run: bool = True, quarantine_dir: str = "./data/quarantine"):
        self.dry_run = dry_run
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.is_windows = platform.system() == "Windows"

    def execute(self, action_type: str, description: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """执行动作并返回结果."""
        params = params or {}
        executor_map = {
            "封禁源IP": self._block_ip,
            "block_ip": self._block_ip,
            "隔离目标主机": self._isolate_host,
            "隔离文件": self._quarantine_file,
            "terminate_malicious_process": self._kill_process,
            "重置账号密码": self._reset_password,
            "禁用账户": self._disable_account,
            "终止恶意进程": self._kill_process,
        }

        executor = executor_map.get(action_type)
        if not executor:
            return {
                "success": False,
                "action_type": action_type,
                "message": f"未知的动作类型: {action_type}",
                "dry_run": self.dry_run,
                "timestamp": datetime.now().isoformat(),
            }

        return executor(description=description, params=params)

    def _block_ip(self, description: str = "", params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """通过 Windows 防火墙封禁 IP 地址."""
        ip = params.get("ip", "") if params else ""
        if not ip:
            # Try to extract from description
            for part in description.replace(",", " ").split():
                if part.count(".") == 3 and all(p.isdigit() for p in part.split(".")):
                    ip = part
                    break

        if not ip:
            return {"success": False, "action_type": "封禁源IP", "message": "未提供 IP 地址", "dry_run": self.dry_run}

        rule_name = f"Microlnsight_Block_{ip.replace('.', '_')}"

        if self.dry_run:
            return {
                "success": True,
                "action_type": "封禁源IP",
                "message": f"[DRY RUN] Would block IP {ip} with rule '{rule_name}'",
                "command": f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}',
                "dry_run": True,
                "timestamp": datetime.now().isoformat(),
            }

        if not self.is_windows:
            return {"success": False, "action_type": "封禁源IP", "message": "非 Windows 系统，无法执行", "dry_run": False}

        try:
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return {
                "success": result.returncode == 0,
                "action_type": "封禁源IP",
                "message": f"Blocked IP {ip}" if result.returncode == 0 else result.stderr,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "dry_run": False,
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {"success": False, "action_type": "封禁源IP", "message": str(e), "dry_run": False}

    def _quarantine_file(self, description: str = "", params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """将可疑文件移动到隔离目录."""
        file_path = params.get("file_path", "") if params else ""
        if not file_path:
            for part in description.split():
                if os.path.sep in part or part.endswith((".exe", ".dll", ".bat", ".ps1", ".vbs")):
                    file_path = part
                    break

        if not file_path:
            return {"success": False, "action_type": "隔离文件", "message": "未提供文件路径", "dry_run": self.dry_run}

        src = Path(file_path)
        if self.dry_run:
            return {
                "success": True,
                "action_type": "隔离文件",
                "message": f"[DRY RUN] Would quarantine {file_path}",
                "dry_run": True,
                "timestamp": datetime.now().isoformat(),
            }

        if not src.exists():
            return {"success": False, "action_type": "隔离文件", "message": f"文件未找到: {file_path}", "dry_run": False}

        try:
            dest = self.quarantine_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{src.name}"
            shutil.move(str(src), str(dest))
            return {
                "success": True,
                "action_type": "隔离文件",
                "message": f"Quarantined {file_path} -> {dest}",
                "quarantine_path": str(dest),
                "dry_run": False,
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {"success": False, "action_type": "隔离文件", "message": str(e), "dry_run": False}

    def _disable_account(self, description: str = "", params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """禁用 Windows 用户账户."""
        username = params.get("username", "") if params else ""
        if not username:
            for part in description.split():
                if not part.startswith(("[", "禁用", "账户")) and len(part) > 1 and not part.startswith("http"):
                    username = part.strip(".")
                    break

        if not username:
            return {"success": False, "action_type": "禁用账户", "message": "未提供用户名", "dry_run": self.dry_run}

        if self.dry_run:
            return {
                "success": True,
                "action_type": "禁用账户",
                "message": f"[DRY RUN] Would disable account '{username}'",
                "command": f"net user {username} /active:no",
                "dry_run": True,
                "timestamp": datetime.now().isoformat(),
            }

        if not self.is_windows:
            return {"success": False, "action_type": "禁用账户", "message": "非 Windows 系统", "dry_run": False}

        try:
            result = subprocess.run(f"net user {username} /active:no", shell=True, capture_output=True, text=True, timeout=15)
            return {
                "success": result.returncode == 0,
                "action_type": "禁用账户",
                "message": f"Disabled account '{username}'" if result.returncode == 0 else result.stderr,
                "dry_run": False,
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {"success": False, "action_type": "禁用账户", "message": str(e), "dry_run": False}

    def _kill_process(self, description: str = "", params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Terminate a malicious process."""
        pid = params.get("pid", "") if params else ""
        process_name = params.get("process_name", "") if params else ""

        if self.dry_run:
            return {
                "success": True,
                "action_type": "终止恶意进程",
                "message": f"[DRY RUN] Would kill process {process_name or pid}",
                "dry_run": True,
                "timestamp": datetime.now().isoformat(),
            }

        if not self.is_windows:
            return {"success": False, "action_type": "终止恶意进程", "message": "非 Windows 系统", "dry_run": False}

        try:
            if pid:
                result = subprocess.run(f"taskkill /PID {pid} /F", shell=True, capture_output=True, text=True, timeout=15)
            elif process_name:
                result = subprocess.run(f"taskkill /IM {process_name} /F", shell=True, capture_output=True, text=True, timeout=15)
            else:
                return {"success": False, "action_type": "终止恶意进程", "message": "未提供 PID 或进程名", "dry_run": False}

            return {
                "success": result.returncode == 0,
                "action_type": "终止恶意进程",
                "message": f"Killed process {process_name or pid}" if result.returncode == 0 else result.stderr,
                "dry_run": False,
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {"success": False, "action_type": "终止恶意进程", "message": str(e), "dry_run": False}

    def _reset_password(self, description: str = "", params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """重置用户密码（管理员操作）."""
        username = params.get("username", "") if params else ""
        if self.dry_run:
            return {
                "success": True,
                "action_type": "重置账号密码",
                "message": f"[DRY RUN] Would reset password for '{username}'",
                "dry_run": True,
                "timestamp": datetime.now().isoformat(),
            }
        return {
            "success": False,
            "action_type": "重置账号密码",
            "message": "密码重置需要管理员手动操作以确保安全",
            "dry_run": False,
            "timestamp": datetime.now().isoformat(),
        }

    def _isolate_host(self, description: str = "", params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Isolate a host from the network."""
        target = params.get("target_ip", "") if params else ""
        if self.dry_run:
            return {
                "success": True,
                "action_type": "隔离目标主机",
                "message": f"[DRY RUN] Would isolate host {target}",
                "dry_run": True,
                "timestamp": datetime.now().isoformat(),
            }
        return {
            "success": False,
            "action_type": "隔离目标主机",
            "message": "网络隔离需要网络设备 API 访问权限",
            "dry_run": False,
            "timestamp": datetime.now().isoformat(),
        }
