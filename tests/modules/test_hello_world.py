"""
Tests for the hello_world module.

Verifies the exact behaviour specified in the task:
  * One string option (GREETING, optional, has a default).
  * check() always returns True.
  * run() sleeps ~2 seconds, emits "still working..." exactly once,
    returns a list with exactly one Finding (severity="Info").
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, List

import pytest

from core.base_module import Finding, OptionType
from core.execution import ExecutionContext


def _make_ctx() -> ExecutionContext:
    """Create a test ExecutionContext backed by a fresh asyncio.Queue."""
    return ExecutionContext(
        run_id="test-run-001",
        target="127.0.0.1",
        queue=asyncio.Queue(),
    )


def _drain_queue(ctx: ExecutionContext) -> list[dict]:
    """Synchronously drain all events currently in ctx.queue."""
    events = []
    while not ctx.queue.empty():
        events.append(ctx.queue.get_nowait())
    return events


def _load_module():
    """Dynamically import the hello_world Module class."""
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "hello_world.module",
        Path(__file__).resolve().parents[2] / "modules" / "hello_world" / "module.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.Module


class TestHelloWorldModule:
    def setup_method(self):
        self.Module = _load_module()

    # ------------------------------------------------------------------
    # Meta / option contract
    # ------------------------------------------------------------------

    def test_meta_id(self):
        assert self.Module.meta.id == "dev.hello_world"

    def test_exactly_one_option(self):
        assert len(self.Module.meta.options) == 1

    def test_option_is_string_type(self):
        opt = self.Module.meta.options[0]
        assert opt.option_type is OptionType.STRING

    def test_option_is_not_required(self):
        opt = self.Module.meta.options[0]
        assert opt.required is False

    def test_option_has_default(self):
        opt = self.Module.meta.options[0]
        assert opt.default is not None

    # ------------------------------------------------------------------
    # check()
    # ------------------------------------------------------------------

    def test_check_always_true(self):
        mod = self.Module()
        ctx = _make_ctx()
        assert mod.check(ctx) is True

    def test_check_always_true_regardless_of_options(self):
        mod = self.Module(options={"GREETING": "anything"})
        ctx = _make_ctx()
        assert mod.check(ctx) is True

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def test_run_returns_one_finding(self):
        mod = self.Module()
        ctx = _make_ctx()
        findings = mod.run(ctx)
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_run_finding_severity_info(self):
        mod = self.Module()
        ctx = _make_ctx()
        findings = mod.run(ctx)
        assert findings[0].severity == "Info"

    def test_run_finding_is_Finding_instance(self):
        mod = self.Module()
        ctx = _make_ctx()
        findings = mod.run(ctx)
        assert isinstance(findings[0], Finding)

    def test_run_emits_still_working_exactly_once(self):
        mod = self.Module()
        ctx = _make_ctx()
        mod.run(ctx)
        # Drain all events from the queue
        events = _drain_queue(ctx)
        log_msgs = [e["message"] for e in events if "still working" in e.get("message", "")]
        assert len(log_msgs) == 1
        assert "still working" in log_msgs[0]

    def test_run_takes_approximately_two_seconds(self):
        mod = self.Module()
        ctx = _make_ctx()
        start = time.monotonic()
        mod.run(ctx)
        elapsed = time.monotonic() - start
        # Allow generous tolerance (CI jitter): 1.8 s ≤ elapsed ≤ 5 s
        assert 1.8 <= elapsed <= 5.0

    def test_run_greeting_appears_in_finding_description(self):
        greeting = "Hi from the test suite!"
        mod = self.Module(options={"GREETING": greeting})
        ctx = _make_ctx()
        findings = mod.run(ctx)
        assert greeting in findings[0].description

    def test_run_uses_default_greeting_when_not_set(self):
        default = self.Module.meta.options[0].default
        mod = self.Module()
        ctx = _make_ctx()
        findings = mod.run(ctx)
        assert default in findings[0].description

    def test_finding_added_to_ctx(self):
        mod = self.Module()
        ctx = _make_ctx()
        findings = mod.run(ctx)
        assert len(ctx.findings) == 1
        assert ctx.findings[0] is findings[0]
