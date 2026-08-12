"""
Run manager for module execution, event buffering, and WebSocket live broadcasting.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from core.base_module import BaseModule, Finding
from core.execution import ExecutionContext

logger = logging.getLogger("sentrypack.run_manager")


def _serialize_finding(f: Finding) -> dict:
    if hasattr(f, "__dict__"):
        return {
            "title": getattr(f, "title", ""),
            "severity": getattr(f, "severity", "Info"),
            "description": getattr(f, "description", ""),
            "cve": getattr(f, "cve", None),
            "cpe": getattr(f, "cpe", None),
            "remediation": getattr(f, "remediation", None),
            "evidence": getattr(f, "evidence", None),
        }
    return dict(f)


class RunManager:
    """Manages module run lifecycle, buffered event history, and active client subscribers."""

    def __init__(self) -> None:
        self.runs: Dict[str, Dict[str, Any]] = {}

    def start_run(
        self,
        run_id: str,
        module_class: type[BaseModule],
        options: Dict[str, Any],
        target: str,
        target_id: Any = None,
        on_finish: Optional[Callable[[str, Any, str, list], None]] = None,
    ) -> str:
        """Kick off background execution of module_class in a thread executor."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.get_event_loop()

        self.runs[run_id] = {
            "status": "pending",
            "buffer": [],
            "subscribers": set(),
            "findings": [],
            "module_id": getattr(getattr(module_class, "meta", None), "id", ""),
            "target": target,
            "target_id": target_id,
            "on_finish": on_finish,
        }

        def emit_callback(payload: dict) -> None:
            event = {
                "type": payload.get("event_type", payload.get("type", "log")),
                "run_id": payload.get("run_id", run_id),
                "timestamp": payload.get("timestamp", time.time()),
                "message": payload.get("message", ""),
            }
            asyncio.run_coroutine_threadsafe(
                self._record_and_broadcast(run_id, event),
                loop,
            )

        def _worker() -> None:
            asyncio.run_coroutine_threadsafe(
                self._set_status(run_id, "running"),
                loop,
            )

            import threading as _threading
            cancelled_flag = _threading.Event()

            # Resolve timeout: meta.timeout → DEFAULT (60 s)
            meta_obj = getattr(module_class, "meta", None)
            timeout_secs: int = getattr(meta_obj, "timeout", None) or 60

            try:
                mod_instance = module_class(options=options)
                ctx = ExecutionContext(
                    run_id=run_id,
                    target=target,
                    emit_callback=emit_callback,
                    cancelled=cancelled_flag,
                )

                can_run = mod_instance.check(ctx)
                if not can_run:
                    err_event = {
                        "type": "error",
                        "run_id": run_id,
                        "message": "Pre-flight check failed",
                    }
                    asyncio.run_coroutine_threadsafe(
                        self._finish_run(run_id, "failed", err_event),
                        loop,
                    )
                    return

                # --- Run with timeout via a nested thread + Event ---
                result_holder: list = []
                exc_holder: list = []

                def _run_with_timeout() -> None:
                    try:
                        result_holder.append(mod_instance.run(ctx))
                    except Exception as e:
                        exc_holder.append(e)

                import threading as _t
                worker_thread = _t.Thread(target=_run_with_timeout, daemon=True)
                worker_thread.start()
                worker_thread.join(timeout=timeout_secs)

                if worker_thread.is_alive():
                    # Timed out — signal cooperative cancellation
                    cancelled_flag.set()
                    from core.base_module import Finding as _Finding
                    timeout_finding = _Finding(
                        title="Module Timeout",
                        severity="High",
                        description=(
                            f"Module did not complete within {timeout_secs}s. "
                            "The run was forcibly terminated."
                        ),
                        remediation=(
                            "Increase the module timeout in module.toml or "
                            "narrow the target scope."
                        ),
                    )
                    ctx.findings.append(timeout_finding)
                    asyncio.run_coroutine_threadsafe(
                        self._record_and_broadcast(run_id, {
                            "type": "timeout",
                            "run_id": run_id,
                            "message": f"Module timed out after {timeout_secs}s",
                        }),
                        loop,
                    )
                    err_event = {
                        "type": "error",
                        "run_id": run_id,
                        "message": f"Module timed out after {timeout_secs}s",
                    }
                    asyncio.run_coroutine_threadsafe(
                        self._finish_run(run_id, "timeout", err_event, findings=ctx.findings),
                        loop,
                    )
                    return

                if exc_holder:
                    raise exc_holder[0]

                serialized_findings = [_serialize_finding(f) for f in ctx.findings]
                comp_event = {
                    "type": "complete",
                    "run_id": run_id,
                    "findings": serialized_findings,
                }
                asyncio.run_coroutine_threadsafe(
                    self._finish_run(
                        run_id,
                        "completed",
                        comp_event,
                        findings=ctx.findings,
                    ),
                    loop,
                )
            except Exception as exc:
                err_event = {
                    "type": "error",
                    "run_id": run_id,
                    "message": str(exc),
                }
                asyncio.run_coroutine_threadsafe(
                    self._finish_run(run_id, "failed", err_event),
                    loop,
                )

        loop.run_in_executor(None, _worker)
        return run_id

    async def _set_status(self, run_id: str, status: str) -> None:
        run_data = self.runs.get(run_id)
        if run_data:
            run_data["status"] = status

    async def _record_and_broadcast(self, run_id: str, event: dict) -> None:
        run_data = self.runs.get(run_id)
        if not run_data:
            return
        run_data["buffer"].append(event)
        subscribers: Set[asyncio.Queue] = set(run_data["subscribers"])
        for q in subscribers:
            await q.put(event)

    async def _finish_run(
        self,
        run_id: str,
        status: str,
        terminal_event: dict,
        findings: Optional[List[Finding]] = None,
    ) -> None:
        run_data = self.runs.get(run_id)
        if not run_data:
            return
        run_data["status"] = status
        if findings is not None:
            run_data["findings"] = findings
        run_data["buffer"].append(terminal_event)

        # Fire the on_finish callback before broadcasting, but never let it
        # block or break the subscriber broadcast.
        on_finish = run_data.get("on_finish")
        stored_target_id = run_data.get("target_id")
        if on_finish is not None:
            try:
                on_finish(run_id, stored_target_id, status, run_data.get("findings") or [])
            except Exception:
                logger.exception(
                    "on_finish callback raised for run_id=%s; subscriber broadcast will continue",
                    run_id,
                )

        subscribers: Set[asyncio.Queue] = set(run_data["subscribers"])
        for q in subscribers:
            await q.put(terminal_event)

    def subscribe(
        self, run_id: str
    ) -> Tuple[Optional[asyncio.Queue], Optional[List[dict]]]:
        """Subscribe to run events. Returns (queue, snapshot_list) or (None, None)."""
        run_data = self.runs.get(run_id)
        if not run_data:
            return None, None
        q: asyncio.Queue = asyncio.Queue()
        snapshot = list(run_data["buffer"])
        run_data["subscribers"].add(q)
        return q, snapshot

    def unsubscribe(self, run_id: str, queue: Optional[asyncio.Queue]) -> None:
        """Safely unsubscribe a queue from run broadcasts."""
        if not queue:
            return
        run_data = self.runs.get(run_id)
        if run_data and queue in run_data["subscribers"]:
            run_data["subscribers"].discard(queue)


run_manager = RunManager()
