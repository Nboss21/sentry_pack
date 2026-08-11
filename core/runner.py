"""
Module runner — sandboxed execution with enforced timeouts.

Public surface
--------------
.. code-block:: python

    findings, queue = await run_module(
        module_cls=Module,
        options={"TARGET": "10.0.0.1"},
        run_id="run-abc123",
        target="10.0.0.1",
        timeout_seconds=None,   # None → use meta.timeout, else 60 s
    )

    # Stream events while the run is in-flight:
    while (event := await queue.get()) is not None:
        print(event["message"])

Design
------
Each run executes inside a **daemon thread** managed by
``asyncio.to_thread`` (Python 3.10+).  The thread is wrapped in
``asyncio.wait_for`` with the configured timeout.

On timeout:
  * ``ctx.cancelled`` is set so the module can cooperate and exit early.
  * A timeout :class:`~core.base_module.Finding` (severity ``"High"``) is
    appended.
  * A ``"timeout"`` event is emitted.
  * The coroutine returns normally — the caller is **never** blocked.

The queue always ends with a :data:`~core.execution.QUEUE_SENTINEL` (``None``)
so consumers know when to stop reading.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from typing import List, Optional, Tuple, Type

from core.base_module import BaseModule, Finding, ModuleMeta
from core.execution import ExecutionContext, QUEUE_SENTINEL

logger = logging.getLogger("sentrypack.runner")

#: Runner-level default timeout when neither the call-site nor ModuleMeta
#: specifies one.
DEFAULT_TIMEOUT_SECONDS: int = 60


def _resolve_timeout(meta: ModuleMeta, override: Optional[int]) -> int:
    """Return the effective timeout in seconds for this run.

    Priority: call-site override > ``meta.timeout`` > ``DEFAULT_TIMEOUT_SECONDS``.
    """
    if override is not None:
        return override
    if meta.timeout is not None:
        return meta.timeout
    return DEFAULT_TIMEOUT_SECONDS


def _run_module_in_thread(
    module: BaseModule,
    ctx: ExecutionContext,
) -> List[Finding]:
    """Execute ``module.run(ctx)`` synchronously.

    This function is designed to be called via ``asyncio.to_thread`` so it
    runs in a worker thread without blocking the event loop.

    Returns the list of :class:`~core.base_module.Finding` objects produced.
    """
    return module.run(ctx)


async def run_module(
    module_cls: Type[BaseModule],
    options: dict,
    run_id: str,
    target: str,
    timeout_seconds: Optional[int] = None,
) -> Tuple[List[Finding], asyncio.Queue]:
    """Run a module in an isolated thread with an enforced timeout.

    The caller receives both the findings list **and** the queue immediately
    after the coroutine completes.  The queue may still have unconsumed events
    if the caller did not drain it concurrently; the sentinel (``None``) is
    always the last item.

    Args:
        module_cls:      The :class:`~core.base_module.BaseModule` subclass to
                         instantiate and run.
        options:         User-supplied option values passed to the module.
        run_id:          Unique identifier for this run.  Generate with
                         ``str(uuid.uuid4())`` if you don't have one.
        target:          Target host / IP / URL string stored in every event.
        timeout_seconds: Hard wall-clock limit.  ``None`` means "read from
                         ``module_cls.meta.timeout`` or fall back to 60 s".

    Returns:
        A ``(findings, queue)`` tuple.

        * ``findings`` — all :class:`~core.base_module.Finding` objects
          produced during the run (including any timeout finding).
        * ``queue`` — :class:`asyncio.Queue` of event dicts, terminated by a
          ``None`` sentinel.  Safe to drain even after the run has finished.
    """
    queue: asyncio.Queue = asyncio.Queue()
    cancelled_event = threading.Event()
    ctx = ExecutionContext(
        run_id=run_id,
        target=target,
        queue=queue,
        cancelled=cancelled_event,
    )

    module = module_cls(options=options)
    meta: ModuleMeta = module_cls.meta
    timeout = _resolve_timeout(meta, timeout_seconds)

    ctx.emit(
        f"Starting module '{meta.id}' on target '{target}' (timeout={timeout}s)",
        event_type="info",
    )

    # ------------------------------------------------------------------
    # Pre-flight check
    # ------------------------------------------------------------------
    try:
        check_passed = module.check(ctx)
    except Exception as exc:
        logger.exception("check() raised for module '%s': %s", meta.id, exc)
        ctx.emit(f"check() raised an exception: {exc}", event_type="error")
        check_passed = False

    if not check_passed:
        ctx.emit(
            f"Module '{meta.id}' check() returned False — skipping run.",
            event_type="skipped",
        )
        queue.put_nowait(QUEUE_SENTINEL)
        return ctx.findings, queue

    # ------------------------------------------------------------------
    # Sandboxed execution with timeout
    # ------------------------------------------------------------------
    ctx.emit("check() passed — starting run()", event_type="info")

    try:
        findings: List[Finding] = await asyncio.wait_for(
            asyncio.to_thread(_run_module_in_thread, module, ctx),
            timeout=float(timeout),
        )
        ctx.findings = findings  # sync back
        ctx.emit(
            f"run() completed — {len(findings)} finding(s) produced.",
            event_type="info",
        )

    except asyncio.TimeoutError:
        # Signal the thread to cooperate and exit early.
        cancelled_event.set()

        logger.warning(
            "Module '%s' exceeded timeout (%ds) for run '%s'.",
            meta.id,
            timeout,
            run_id,
        )
        ctx.emit(
            f"Module '{meta.id}' timed out after {timeout}s.",
            event_type="timeout",
        )
        timeout_finding = Finding(
            title="Module Timeout",
            severity="High",
            description=(
                f"Module '{meta.id}' did not complete within the "
                f"configured timeout of {timeout} seconds. "
                "The run was forcibly terminated."
            ),
            remediation=(
                "Increase the module timeout in module.toml, narrow the "
                "target scope, or investigate slow external dependencies."
            ),
        )
        ctx.findings.append(timeout_finding)

    except Exception as exc:
        logger.exception(
            "Unexpected error in module '%s' run '%s': %s", meta.id, run_id, exc
        )
        ctx.emit(f"run() raised an unexpected error: {exc}", event_type="error")

    finally:
        # Always place the sentinel so queue consumers terminate cleanly.
        queue.put_nowait(QUEUE_SENTINEL)

    return ctx.findings, queue


def new_run_id() -> str:
    """Generate a fresh, unique run identifier."""
    return str(uuid.uuid4())
