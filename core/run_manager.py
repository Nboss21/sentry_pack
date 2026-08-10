"""
Run manager for module execution, event buffering, and WebSocket live broadcasting.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from core.base_module import BaseModule, Finding
from core.execution import ExecutionContext


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
            try:
                mod_instance = module_class(options=options)
                ctx = ExecutionContext(
                    run_id=run_id,
                    target=target,
                    emit_callback=emit_callback,
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

                findings = mod_instance.run(ctx)
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
