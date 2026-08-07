"""
Execution context for subprocess isolation, timeouts, and event emission.

:class:`ExecutionContext` is created by the runner for every module
invocation and passed as the single ``ctx`` argument to both
:meth:`~core.base_module.BaseModule.check` and
:meth:`~core.base_module.BaseModule.run`.
"""

from __future__ import annotations

import subprocess
import time
from typing import Callable, List, Optional

from core.base_module import Finding


class ExecutionContext:
    """Per-run container for findings, live event streaming, and subprocess execution.

    Attributes:
        run_id:   Unique identifier for this specific module invocation.
        target:   The host / IP / URL the module is operating against.
        findings: Accumulates :class:`~core.base_module.Finding` objects
                  produced during the run.
    """

    def __init__(
        self,
        run_id: str,
        target: str,
        emit_callback: Optional[Callable[[dict], None]] = None,
    ) -> None:
        """
        Args:
            run_id:        Unique identifier for this run (UUIDv4 recommended).
            target:        Target host or IP string.
            emit_callback: Optional callable that receives every event payload
                           dict; used by the API WebSocket layer to stream
                           output to connected GUI clients.
        """
        self.run_id: str = run_id
        self.target: str = target
        self._emit_callback: Optional[Callable[[dict], None]] = emit_callback
        self.findings: List[Finding] = []

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    def emit(self, message: str, event_type: str = "log") -> None:
        """Broadcast a plain-text log message to all connected listeners.

        This is the primary way for a module to report progress.  The
        architecture spec deliberately keeps the signature simple::

            ctx.emit("still working...")
            ctx.emit("Port 22 is open", event_type="info")

        Args:
            message:    Human-readable status / log line.
            event_type: Optional discriminator tag (default ``"log"``).
                        Common values: ``"log"``, ``"info"``, ``"warning"``,
                        ``"error"``, ``"finding"``.
        """
        payload: dict = {
            "run_id": self.run_id,
            "target": self.target,
            "timestamp": time.time(),
            "event_type": event_type,
            "message": message,
        }
        if self._emit_callback is not None:
            self._emit_callback(payload)

    # ------------------------------------------------------------------
    # Finding management
    # ------------------------------------------------------------------

    def add_finding(self, finding: Finding) -> None:
        """Append *finding* to the run's result set and emit a finding event.

        Args:
            finding: A :class:`~core.base_module.Finding` produced by the module.
        """
        self.findings.append(finding)
        self.emit(
            f"[finding] {finding.severity.upper()} – {finding.title}",
            event_type="finding",
        )

    # ------------------------------------------------------------------
    # Subprocess execution
    # ------------------------------------------------------------------

    def run_subprocess(
        self,
        cmd: List[str],
        timeout: int = 300,
    ) -> subprocess.CompletedProcess:
        """Run an external command inside a managed subprocess.

        Emits a ``"log"`` event before execution and captures both stdout
        and stderr so the module can inspect output without side effects.

        Args:
            cmd:     Command and arguments as a list of strings
                     (never use ``shell=True``).
            timeout: Maximum wall-clock seconds to wait; raises
                     :exc:`subprocess.TimeoutExpired` on breach.

        Returns:
            A :class:`subprocess.CompletedProcess` with ``stdout`` and
            ``stderr`` available as strings.
        """
        self.emit(f"Executing: {' '.join(cmd)}")
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
