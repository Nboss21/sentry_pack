"""
Tests for core/runner.py — sandboxed execution, queue ordering, timeouts.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, List

import pytest

from core.base_module import BaseModule, Finding, ModuleMeta
from core.execution import QUEUE_SENTINEL
from core.runner import new_run_id, run_module
from core.run_store import RunStore


def _make_meta(module_id: str = "test.mod", timeout: int | None = None) -> ModuleMeta:
    return ModuleMeta(
        id=module_id,
        name="Test Module",
        description="Test",
        author="Tester",
        version="0.1.0",
        category="dev",
        timeout=timeout,
    )


class _QuickModule(BaseModule):
    """Emits three messages in order and returns one Finding."""

    meta = _make_meta("test.quick")

    def check(self, ctx: Any) -> bool:
        return True

    def run(self, ctx: Any) -> List[Finding]:
        ctx.emit("step-1")
        ctx.emit("step-2")
        ctx.emit("step-3")
        f = Finding(title="Quick Finding", severity="Info", description="done")
        ctx.add_finding(f)
        return [f]


class _SkipModule(BaseModule):
    """check() always returns False."""

    meta = _make_meta("test.skip")

    def check(self, ctx: Any) -> bool:
        return False

    def run(self, ctx: Any) -> List[Finding]:
        raise AssertionError("run() called on SkipModule")


class _SlowModule(BaseModule):
    """Sleeps longer than the timeout to trigger timeout enforcement."""

    meta = _make_meta("test.slow", timeout=None)

    def check(self, ctx: Any) -> bool:
        return True

    def run(self, ctx: Any) -> List[Finding]:
        for _ in range(100):
            if ctx.cancelled.is_set():
                break
            time.sleep(0.1)
        return []


async def _drain(queue: asyncio.Queue) -> list[dict]:
    events = []
    while True:
        item = await asyncio.wait_for(queue.get(), timeout=10)
        if item is QUEUE_SENTINEL:
            break
        events.append(item)
    return events


@pytest.mark.asyncio
async def test_normal_run_returns_findings():
    run_id = new_run_id()
    findings, queue = await run_module(
        module_cls=_QuickModule,
        options={},
        run_id=run_id,
        target="127.0.0.1",
    )
    assert len(findings) == 1
    assert findings[0].title == "Quick Finding"


@pytest.mark.asyncio
async def test_normal_run_events_in_order():
    run_id = new_run_id()
    findings, queue = await run_module(
        module_cls=_QuickModule,
        options={},
        run_id=run_id,
        target="127.0.0.1",
    )
    events = await _drain(queue)
    step_msgs = [e["message"] for e in events if e.get("message", "").startswith("step-")]
    assert step_msgs == ["step-1", "step-2", "step-3"]


@pytest.mark.asyncio
async def test_normal_run_queue_ends_with_sentinel():
    run_id = new_run_id()
    findings, queue = await run_module(
        module_cls=_QuickModule,
        options={},
        run_id=run_id,
        target="127.0.0.1",
    )
    items = []
    while True:
        item = queue.get_nowait() if not queue.empty() else await queue.get()
        items.append(item)
        if item is QUEUE_SENTINEL:
            break
    assert items[-1] is QUEUE_SENTINEL


@pytest.mark.asyncio
async def test_check_false_skips_run():
    run_id = new_run_id()
    findings, queue = await run_module(
        module_cls=_SkipModule,
        options={},
        run_id=run_id,
        target="127.0.0.1",
    )
    assert findings == []
    events = await _drain(queue)
    event_types = [e.get("event_type") for e in events]
    assert "skipped" in event_types


@pytest.mark.asyncio
async def test_timeout_produces_finding():
    run_id = new_run_id()
    findings, queue = await run_module(
        module_cls=_SlowModule,
        options={},
        run_id=run_id,
        target="127.0.0.1",
        timeout_seconds=1,
    )
    titles = [f.title for f in findings]
    assert "Module Timeout" in titles


@pytest.mark.asyncio
async def test_timeout_run_completes_within_deadline():
    run_id = new_run_id()
    start = time.monotonic()
    await run_module(
        module_cls=_SlowModule,
        options={},
        run_id=run_id,
        target="127.0.0.1",
        timeout_seconds=1,
    )
    elapsed = time.monotonic() - start
    assert elapsed < 4.0



def test_run_store_crud():
    store = RunStore()
    q: asyncio.Queue = asyncio.Queue()
    store.register("run-001", q)
    assert store.get("run-001") is q
    assert store.active_run_ids() == ["run-001"]
    store.release("run-001")
    assert store.get("run-001") is None


# ---------------------------------------------------------------------------
# None-return guard (bug fix: Phase 7)
# ---------------------------------------------------------------------------


class _NoneReturnModule(BaseModule):
    """Buggy module that returns None from run() instead of a list."""

    meta = _make_meta("test.none_return")

    def check(self, ctx: Any) -> bool:
        return True

    def run(self, ctx: Any) -> List[Finding]:  # type: ignore[return]
        return None  # type: ignore[return-value]  # deliberate bug


@pytest.mark.asyncio
async def test_none_return_from_run_does_not_crash_runner():
    """Module returning None must not raise TypeError in the runner."""
    run_id = new_run_id()
    findings, queue = await run_module(
        module_cls=_NoneReturnModule,
        options={},
        run_id=run_id,
        target="127.0.0.1",
    )
    assert findings == []


@pytest.mark.asyncio
async def test_none_return_emits_error_event():
    """None return must emit an 'error' event so the issue is visible."""
    run_id = new_run_id()
    _findings, queue = await run_module(
        module_cls=_NoneReturnModule,
        options={},
        run_id=run_id,
        target="127.0.0.1",
    )
    events = []
    while True:
        item = await asyncio.wait_for(queue.get(), timeout=5)
        if item is QUEUE_SENTINEL:
            break
        events.append(item)
    error_events = [e for e in events if e.get("event_type") == "error"]
    assert len(error_events) >= 1, "Expected an 'error' event for None return from run()"


# ---------------------------------------------------------------------------
# execution.py run_subprocess error-wrapping (bug fix: Phase 7)
# ---------------------------------------------------------------------------


def test_run_subprocess_wraps_file_not_found():
    """FileNotFoundError in run_subprocess must become RuntimeError."""
    import threading
    from core.execution import ExecutionContext

    ctx = ExecutionContext(
        run_id="test-fnf",
        target="127.0.0.1",
        queue=asyncio.Queue(),
        cancelled=threading.Event(),
    )
    with pytest.raises(RuntimeError, match="not found"):
        ctx.run_subprocess(["__nonexistent_binary_xyz__"])


def test_run_subprocess_file_not_found_emits_error_event():
    """FileNotFoundError must also emit an error event to the queue."""
    import threading
    from core.execution import ExecutionContext

    q: asyncio.Queue = asyncio.Queue()
    ctx = ExecutionContext(
        run_id="test-fnf-event",
        target="127.0.0.1",
        queue=q,
        cancelled=threading.Event(),
    )
    with pytest.raises(RuntimeError):
        ctx.run_subprocess(["__nonexistent_binary_xyz__"])
    items = []
    while not q.empty():
        items.append(q.get_nowait())
    error_events = [i for i in items if isinstance(i, dict) and i.get("event_type") == "error"]
    assert len(error_events) >= 1
