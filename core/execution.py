"""
Execution context — per-run container for the emit queue, findings, and
subprocess execution helpers.

:class:`ExecutionContext` is created for every module invocation and passed
as the ``ctx`` argument to both :meth:`~core.base_module.BaseModule.check`
and :meth:`~core.base_module.BaseModule.run`.

Design
------
``ctx.emit(message)`` is intentionally synchronous from the module's
perspective.  Internally it:

1. Puts a dict onto an :class:`asyncio.Queue` via ``put_nowait`` (used by
   the queue-based runner / WebSocket layer).
2. Optionally calls a synchronous ``emit_callback`` (used by
   :class:`~core.run_manager.RunManager` for its subscriber fan-out).

Both channels are optional; at least one should be provided.

A ``cancelled`` :class:`threading.Event` lets the runner signal a timeout to
the module without killing the OS thread — modules should check
``ctx.cancelled.is_set()`` inside long loops and return early.
"""

from __future__ import annotations

import subprocess
import threading
import time
from asyncio import Queue
from typing import Callable, List, Optional

from core.base_module import Finding

#: Sentinel placed onto the queue by the runner to signal end-of-stream.
QUEUE_SENTINEL: None = None


class ExecutionContext:
    """Per-run container for findings, live event streaming, and subprocess execution.

    Attributes:
        run_id:    Unique identifier for this specific module invocation.
        target:    The host / IP / URL the module is operating against.
        queue:     Optional :class:`asyncio.Queue` of event dicts; drained by
                   the WebSocket layer.  Ends with a ``None`` sentinel.
        cancelled: :class:`threading.Event` set by the runner when the module
                   timeout fires.  Modules may check this flag to abort early.
        findings:  Accumulates :class:`~core.base_module.Finding` objects
                   produced during the run.
    """

    def __init__(
        self,
        run_id: str,
        target: str,
        queue: Optional[Queue] = None,
        emit_callback: Optional[Callable[[dict], None]] = None,
        cancelled: Optional[threading.Event] = None,
    ) -> None:
        """
        Args:
            run_id:        Unique identifier for this run (UUIDv4 recommended).
            target:        Target host or IP string.
            queue:         Optional pre-created :class:`asyncio.Queue`; shared
                           with the runner and the WebSocket handler.
            emit_callback: Optional synchronous callable receiving every event
                           payload dict; used by :class:`~core.run_manager.RunManager`
                           for live subscriber fan-out.
            cancelled:     Optional :class:`threading.Event` controlled by the
                           runner.  Defaults to a new event (never set) if omitted.
        """
        self.run_id: str = run_id
        self.target: str = target
        self.queue: Optional[Queue] = queue
        self._emit_callback: Optional[Callable[[dict], None]] = emit_callback
        self.cancelled: threading.Event = cancelled or threading.Event()
        self.findings: List[Finding] = []

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    def emit(self, message: str, event_type: str = "log") -> None:
        """Put a log event onto the queue and/or call the emit callback.

        This is the primary way for a module to report progress::

            ctx.emit("still working...")
            ctx.emit("Port 22 is open", event_type="info")

        The call is **non-blocking** — it uses ``queue.put_nowait()`` when a
        queue is present and never raises even if the queue is full.

        Args:
            message:    Human-readable status / log line.
            event_type: Discriminator tag (default ``"log"``).
                        Common values: ``"log"``, ``"info"``,
                        ``"warning"``, ``"error"``, ``"finding"``,
                        ``"skipped"``, ``"timeout"``.
        """
        payload: dict = {
            "run_id": self.run_id,
            "target": self.target,
            "timestamp": time.time(),
            "event_type": event_type,
            "message": message,
        }
        if self.queue is not None:
            self.queue.put_nowait(payload)
        if self._emit_callback is not None:
            self._emit_callback(payload)

    # ------------------------------------------------------------------
    # Finding management
    # ------------------------------------------------------------------

    def add_finding(self, finding: Finding) -> None:
        """Append *finding* to the result set and emit a ``"finding"`` event.

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
        """Run an external command in a managed subprocess.

        Emits a ``"log"`` event before execution.  Checks ``self.cancelled``
        after the subprocess returns so callers can short-circuit.

        Raises :exc:`subprocess.TimeoutExpired` when the command exceeds
        *timeout* seconds — callers should catch this and return ``[]``.

        Args:
            cmd:     Command and arguments as a list of strings.
                     **Never** pass ``shell=True``.
            timeout: Max seconds to wait; raises
                     :exc:`subprocess.TimeoutExpired` on breach.

        Returns:
            :class:`subprocess.CompletedProcess` with ``stdout``/``stderr``
            as strings.

        Raises:
            subprocess.TimeoutExpired: If the process exceeds *timeout* seconds.
            RuntimeError: If the binary is not found (``FileNotFoundError``)
                or the caller lacks permission to execute it
                (``PermissionError``).  These are converted so that modules
                receive a consistent error type rather than an OS-level
                exception leaking through.
        """
        self.emit(f"Executing: {' '.join(cmd)}")
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            msg = f"Binary not found: {cmd[0]!r}. Ensure it is installed and on PATH."
            self.emit(msg, event_type="error")
            raise RuntimeError(msg) from None
        except PermissionError:
            msg = f"Permission denied executing {cmd[0]!r}."
            self.emit(msg, event_type="error")
            raise RuntimeError(msg) from None
        # subprocess.TimeoutExpired is deliberately NOT caught here — callers
        # must handle it so they can return [] cleanly and let the runner
        # decide whether the module as a whole has timed out.
