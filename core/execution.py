"""
Execution context for subprocess isolation, timeouts, and event/finding emission.
"""

import subprocess
import time
from typing import Callable, List, Optional
from core.base_module import Finding


class ExecutionContext:
    """
    Provides isolated execution environment, subprocess execution wrapper,
    and event emitting mechanisms.
    """

    def __init__(self, run_id: str, target: str, emit_callback: Optional[Callable[[dict], None]] = None):
        self.run_id = run_id
        self.target = target
        self.emit_callback = emit_callback
        self.findings: List[Finding] = []

    def emit(self, event_type: str, data: dict) -> None:
        """Emit real-time status/log event to registered listener."""
        payload = {
            "run_id": self.run_id,
            "target": self.target,
            "timestamp": time.time(),
            "event_type": event_type,
            "data": data,
        }
        if self.emit_callback:
            self.emit_callback(payload)

    def add_finding(self, finding: Finding) -> None:
        """Record finding and emit finding event."""
        self.findings.append(finding)
        self.emit("finding", {"title": finding.title, "severity": finding.severity})

    def run_subprocess(self, cmd: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
        """Run external CLI tool securely within isolation wrapper."""
        self.emit("log", {"message": f"Executing command: {' '.join(cmd)}"})
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
