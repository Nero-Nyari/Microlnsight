"""Autonomous agent scheduler.

Provides periodic scanning of Windows logs and automatic incident creation
for suspicious events.  Runs as a background thread.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional


class AgentScheduler:
    """Background scheduler that periodically triggers log scans."""

    def __init__(self, scan_interval: int = 300):
        self.scan_interval = scan_interval  # seconds
        self._running = False
        self._paused = False
        self._thread: Optional[threading.Thread] = None
        self._scan_callback: Optional[Callable] = None
        self._scan_count = 0
        self._last_scan: Optional[str] = None
        self._auto_threshold: float = 0.85  # confidence above which auto-execute

    def set_scan_callback(self, callback: Callable):
        """设置每个扫描周期调用的函数."""
        self._scan_callback = callback

    def start(self):
        """启动后台调度器."""
        if self._running:
            return
        self._running = True
        self._paused = False
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """停止后台调度器."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def pause(self):
        """Pause scanning without stopping the thread."""
        self._paused = True

    def resume(self):
        """Resume scanning."""
        self._paused = False

    def _run_loop(self):
        """Main scheduler loop."""
        while self._running:
            if not self._paused:
                try:
                    self._do_scan()
                except Exception:
                    pass
            time.sleep(self.scan_interval)

    def _do_scan(self):
        """执行单次扫描周期."""
        self._scan_count += 1
        self._last_scan = datetime.now().isoformat()
        if self._scan_callback:
            self._scan_callback()

    def get_status(self) -> Dict[str, Any]:
        """获取调度器状态."""
        return {
            "running": self._running,
            "paused": self._paused,
            "scan_interval": self.scan_interval,
            "scan_count": self._scan_count,
            "last_scan": self._last_scan,
            "auto_threshold": self._auto_threshold,
        }

    def set_interval(self, seconds: int):
        """Update scan interval."""
        self.scan_interval = max(30, seconds)

    def set_auto_threshold(self, threshold: float):
        """设置自动执行的置信度阈值."""
        self._auto_threshold = max(0.0, min(1.0, threshold))


# Global scheduler instance
scheduler = AgentScheduler()
