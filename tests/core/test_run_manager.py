"""
Tests for core/run_manager.py.
"""

from __future__ import annotations

import asyncio
import time
from typing import List

import pytest

from core.base_module import BaseModule, Finding, ModuleMeta
from core.run_manager import RunManager, run_manager


class DummyModule(BaseModule):
    meta = ModuleMeta(
        id="test.dummy",
        name="Dummy",
        description="Dummy test module",
        author="Test",
        version="0.1.0",
        category="test",
    )

    def check(self, ctx) -> bool:
        return True

    def run(self, ctx) -> List[Finding]:
        ctx.emit("Step 1 starting")
        finding = Finding(title="Dummy Finding", severity="Low", description="Test details")
        ctx.add_finding(finding)
        ctx.emit("Step 2 completed")
        return [finding]


@pytest.mark.asyncio
async def test_run_manager_execution_and_subscribers():
    rm = RunManager()
    run_id = "test-run-mgr-001"

    rm.start_run(run_id, DummyModule, options={}, target="127.0.0.1")
    queue, snapshot = rm.subscribe(run_id)

    assert queue is not None
    assert isinstance(snapshot, list)

    events = []
    # Collect snapshot events
    events.extend(snapshot)

    # Wait for completion terminal event if not in snapshot
    done = any(e.get("type") in ("complete", "error") for e in events)
    while not done:
        try:
            event = await asyncio.wait_for(queue.get(), timeout=3.0)
            events.append(event)
            if event.get("type") in ("complete", "error"):
                done = True
        except asyncio.TimeoutError:
            pytest.fail("Timed out waiting for run to complete")

    rm.unsubscribe(run_id, queue)

    event_types = [e["type"] for e in events]
    assert "log" in event_types
    assert "finding" in event_types
    assert "complete" in event_types

    complete_event = next(e for e in events if e["type"] == "complete")
    assert "findings" in complete_event
    assert len(complete_event["findings"]) == 1
    assert complete_event["findings"][0]["title"] == "Dummy Finding"


@pytest.mark.asyncio
async def test_run_manager_late_subscriber_replay():
    rm = RunManager()
    run_id = "test-run-mgr-002"

    rm.start_run(run_id, DummyModule, options={}, target="127.0.0.1")

    # Sleep briefly to allow background execution to complete
    await asyncio.sleep(0.5)

    queue, snapshot = rm.subscribe(run_id)
    assert queue is not None
    assert len(snapshot) > 0

    snapshot_types = [e["type"] for e in snapshot]
    assert "complete" in snapshot_types
    complete_event = next(e for e in snapshot if e["type"] == "complete")
    assert len(complete_event["findings"]) == 1

    rm.unsubscribe(run_id, queue)


@pytest.mark.asyncio
async def test_run_manager_multiple_subscribers_broadcast():
    rm = RunManager()
    run_id = "test-run-mgr-003"

    rm.start_run(run_id, DummyModule, options={}, target="127.0.0.1")

    queue1, snapshot1 = rm.subscribe(run_id)
    queue2, snapshot2 = rm.subscribe(run_id)

    assert queue1 is not None
    assert queue2 is not None

    async def _collect(q, initial_snapshot):
        collected = list(initial_snapshot)
        while not any(e.get("type") in ("complete", "error") for e in collected):
            ev = await asyncio.wait_for(q.get(), timeout=3.0)
            collected.append(ev)
        return collected

    events1, events2 = await asyncio.gather(
        _collect(queue1, snapshot1),
        _collect(queue2, snapshot2),
    )

    rm.unsubscribe(run_id, queue1)
    rm.unsubscribe(run_id, queue2)

    assert len(events1) == len(events2)
    assert [e["type"] for e in events1] == [e["type"] for e in events2]


# ---------------------------------------------------------------------------
# on_finish callback tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_finish_called_once_with_correct_args():
    """on_finish must be called exactly once with (run_id, target_id, status, findings)."""
    rm = RunManager()
    run_id = "test-run-mgr-finish-001"
    target_id = 42

    calls: list = []

    def _spy(rid, tid, status, findings):
        calls.append((rid, tid, status, findings))

    rm.start_run(
        run_id,
        DummyModule,
        options={},
        target="127.0.0.1",
        target_id=target_id,
        on_finish=_spy,
    )

    # Wait for the run to complete
    await asyncio.sleep(1.0)

    assert len(calls) == 1
    called_run_id, called_target_id, called_status, called_findings = calls[0]
    assert called_run_id == run_id
    assert called_target_id == target_id
    assert called_status == "completed"
    assert isinstance(called_findings, list)
    assert len(called_findings) == 1
    assert called_findings[0].title == "Dummy Finding"


@pytest.mark.asyncio
async def test_raising_on_finish_does_not_block_subscriber_broadcast():
    """A callback that raises must NOT prevent subscribers from receiving the terminal event."""
    rm = RunManager()
    run_id = "test-run-mgr-finish-002"

    def _bad_callback(rid, tid, status, findings):
        raise RuntimeError("Intentional callback failure")

    rm.start_run(
        run_id,
        DummyModule,
        options={},
        target="127.0.0.1",
        target_id=99,
        on_finish=_bad_callback,
    )

    queue, snapshot = rm.subscribe(run_id)
    assert queue is not None

    events = list(snapshot)
    done = any(e.get("type") in ("complete", "error") for e in events)
    while not done:
        try:
            event = await asyncio.wait_for(queue.get(), timeout=5.0)
            events.append(event)
            if event.get("type") in ("complete", "error"):
                done = True
        except asyncio.TimeoutError:
            pytest.fail("Timed out — raising callback may have blocked subscriber broadcast")

    rm.unsubscribe(run_id, queue)

    event_types = [e["type"] for e in events]
    # Subscriber must have received the terminal event despite the callback raising
    assert "complete" in event_types
