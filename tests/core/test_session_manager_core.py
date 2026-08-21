"""
Task 2 verification tests: Core Session Manager.

Verifies:
  ✓ SessionManager starts session with MockTransport (no network)
  ✓ Task sent via session.transport.send() — audit event recorded
  ✓ Result received via session.transport.receive() — audit event recorded
  ✓ Session ended cleanly — audit event recorded
  ✓ Audit log populated with every lifecycle step
  ✓ Red-flag anti-leak test: no transport-specific strings in SessionManager source
  ✓ Backwards compatibility: register_session, emit_event, subscribe, unsubscribe
"""

from __future__ import annotations

import asyncio
import ast
import inspect
from pathlib import Path
from typing import Any, Optional, Union
import pytest

from core.transport_base import (
    AgentConfig,
    AgentIdentity,
    ITransport,
    SessionStatus,
    Task,
    TaskResult,
    TransportMeta,
)
from core.session_manager import SessionManager, ConcreteAgentSession


# ---------------------------------------------------------------------------
# MockTransport for unit tests — no real network required
# ---------------------------------------------------------------------------

class MockTransport(ITransport):
    """
    In-memory echo transport for SessionManager unit tests.

    send() stores the payload; receive() returns the last stored payload as TaskResult.
    """
    meta = TransportMeta(id="mock", name="Mock Transport", version="0.1.0", description="test echo transport")

    def __init__(self) -> None:
        self._connected = False
        self._sent: list = []
        self._results: list = []

    def connect(self, host_or_config: Any, port=None, options=None, **kw) -> bool:
        self._connected = True
        return True

    def send(self, data: Any) -> int:
        self._sent.append(data)
        # Pre-load a matching result for the next receive()
        if isinstance(data, Task):
            self._results.append(TaskResult(
                task_id=data.id,
                output=f"echo: {data.payload}",
                status="completed",
            ))
        return 1

    def receive(self, size: int = 4096) -> Optional[TaskResult]:
        if self._results:
            return self._results.pop(0)
        return None

    def disconnect(self) -> None:
        self._connected = False

    def is_alive(self) -> bool:
        return self._connected


class FailingTransport(ITransport):
    """Transport that always fails to connect — used to test error path."""
    meta = TransportMeta(id="failing", name="Failing Transport", version="0.1.0", description="always fails")

    def connect(self, *a, **kw): return False
    def send(self, data): return 0
    def receive(self, size=4096): return None
    def disconnect(self): pass
    def is_alive(self): return False


# ---------------------------------------------------------------------------
# Full lifecycle tests
# ---------------------------------------------------------------------------

class TestSessionManagerLifecycle:
    def setup_method(self):
        self.mgr = SessionManager()

    def test_start_session_returns_agent_session(self):
        transport = MockTransport()
        identity = AgentIdentity(agent_id="agent-001", name="Test Agent")
        session = self.mgr.start_session(identity, transport, config={})
        assert session is not None
        assert session.session_key == "agent-001"
        assert session.is_active() is True

    def test_start_session_stores_in_manager(self):
        transport = MockTransport()
        identity = AgentIdentity(agent_id="agent-002")
        self.mgr.start_session(identity, transport)
        assert self.mgr.get_session("agent-002") is not None

    def test_start_session_failing_transport_records_error_status(self):
        transport = FailingTransport()
        identity = AgentIdentity(agent_id="bad-agent")
        session = self.mgr.start_session(identity, transport)
        assert session.status == SessionStatus.ERROR

    def test_send_task_returns_task_object(self):
        transport = MockTransport()
        identity = AgentIdentity(agent_id="send-agent")
        self.mgr.start_session(identity, transport)
        task = self.mgr.send_task("send-agent", "whoami")
        assert isinstance(task, Task)
        assert task.payload == "whoami"

    def test_send_task_accepts_task_object(self):
        transport = MockTransport()
        identity = AgentIdentity(agent_id="task-obj-agent")
        self.mgr.start_session(identity, transport)
        t = Task(id="manual-001", payload="id -a")
        returned = self.mgr.send_task("task-obj-agent", t)
        assert returned.id == "manual-001"

    def test_receive_result_returns_task_result(self):
        transport = MockTransport()
        identity = AgentIdentity(agent_id="recv-agent")
        self.mgr.start_session(identity, transport)
        self.mgr.send_task("recv-agent", "echo hello")
        result = self.mgr.receive_result("recv-agent")
        assert result is not None
        assert isinstance(result, TaskResult)
        assert "echo hello" in result.output

    def test_end_session_terminates_session(self):
        transport = MockTransport()
        identity = AgentIdentity(agent_id="end-agent")
        session = self.mgr.start_session(identity, transport)
        self.mgr.end_session("end-agent")
        assert session.status == SessionStatus.TERMINATED
        assert transport.is_alive() is False

    def test_full_lifecycle_with_mock_transport(self):
        """
        Core integration test: start -> send -> receive -> end.
        Everything must work without any real network connection.
        """
        transport = MockTransport()
        identity = AgentIdentity(agent_id="lifecycle-full", name="Full Test Agent")
        session = self.mgr.start_session(identity, transport, config={})

        # Verify session is active
        assert session.is_active() is True

        # Send a task
        task = self.mgr.send_task(session.session_key, "cat /etc/passwd")
        assert task.payload == "cat /etc/passwd"

        # Receive result
        result = self.mgr.receive_result(session.session_key)
        assert result is not None
        assert result.status == "completed"

        # End session
        self.mgr.end_session(session.session_key)
        assert session.status == SessionStatus.TERMINATED


class TestSessionManagerAuditLog:
    """
    Audit log tests: verify every lifecycle step writes to the audit log.
    This is non-negotiable per Phase 5 spec.
    """
    def setup_method(self):
        self.mgr = SessionManager()

    def test_session_start_writes_audit_event(self):
        transport = MockTransport()
        identity = AgentIdentity(agent_id="audit-start")
        self.mgr.start_session(identity, transport)
        log = self.mgr.get_audit_log("audit-start")
        assert len(log) >= 1
        assert any(e["event_type"] == "session_start" for e in log)

    def test_task_sent_writes_audit_event(self):
        transport = MockTransport()
        identity = AgentIdentity(agent_id="audit-send")
        self.mgr.start_session(identity, transport)
        self.mgr.send_task("audit-send", "uptime")
        log = self.mgr.get_audit_log("audit-send")
        assert any(e["event_type"] == "task_sent" for e in log)

    def test_result_received_writes_audit_event(self):
        transport = MockTransport()
        identity = AgentIdentity(agent_id="audit-recv")
        self.mgr.start_session(identity, transport)
        self.mgr.send_task("audit-recv", "uname -a")
        self.mgr.receive_result("audit-recv")
        log = self.mgr.get_audit_log("audit-recv")
        assert any(e["event_type"] == "result_received" for e in log)

    def test_session_end_writes_audit_event(self):
        transport = MockTransport()
        identity = AgentIdentity(agent_id="audit-end")
        self.mgr.start_session(identity, transport)
        self.mgr.end_session("audit-end")
        log = self.mgr.get_audit_log("audit-end")
        assert any(e["event_type"] == "session_end" for e in log)

    def test_all_four_lifecycle_events_present(self):
        """All four audit events must appear for a complete lifecycle."""
        transport = MockTransport()
        identity = AgentIdentity(agent_id="audit-full")
        self.mgr.start_session(identity, transport)
        self.mgr.send_task("audit-full", "id")
        self.mgr.receive_result("audit-full")
        self.mgr.end_session("audit-full")
        log = self.mgr.get_audit_log("audit-full")
        event_types = {e["event_type"] for e in log}
        assert "session_start" in event_types
        assert "task_sent" in event_types
        assert "result_received" in event_types
        assert "session_end" in event_types

    def test_audit_log_has_timestamps(self):
        transport = MockTransport()
        identity = AgentIdentity(agent_id="audit-ts")
        self.mgr.start_session(identity, transport)
        log = self.mgr.get_audit_log("audit-ts")
        for entry in log:
            assert "timestamp" in entry
            assert isinstance(entry["timestamp"], float)

    def test_audit_log_per_session_isolation(self):
        """Audit log for session A must not contain events from session B."""
        t1, t2 = MockTransport(), MockTransport()
        id1 = AgentIdentity(agent_id="session-a")
        id2 = AgentIdentity(agent_id="session-b")
        self.mgr.start_session(id1, t1)
        self.mgr.start_session(id2, t2)
        self.mgr.send_task("session-a", "cmd-a")
        self.mgr.send_task("session-b", "cmd-b")

        log_a = self.mgr.get_audit_log("session-a")
        log_b = self.mgr.get_audit_log("session-b")

        for entry in log_a:
            assert entry["session_key"] == "session-a"
        for entry in log_b:
            assert entry["session_key"] == "session-b"


class TestSessionManagerAgentConfig:
    """Test starting sessions via AgentConfig (Task 4 integration)."""
    def setup_method(self):
        self.mgr = SessionManager()

    def test_start_session_via_agent_config(self):
        transport = MockTransport()
        identity = AgentIdentity(agent_id="cfg-agent", name="Config Agent")
        cfg = AgentConfig(
            identity=identity,
            transport_type="mock",
            transport_config={"host": "10.0.0.1", "port": 9999},
        )
        session = self.mgr.start_session(cfg, transport)
        assert session.session_key == "cfg-agent"
        assert session.is_active() is True

    def test_transport_config_passed_opaque_to_transport(self):
        """
        The SessionManager must pass transport_config directly to transport.connect()
        without inspecting it. We verify this by using a custom config that only
        MockTransport accepts.
        """
        class RecordingTransport(ITransport):
            meta = TransportMeta(id="rec", name="Recorder", version="0.1.0", description="records call")
            received_config = None
            def connect(self, cfg, *a, **kw):
                RecordingTransport.received_config = cfg
                return True
            def send(self, data): return 1
            def receive(self, size=4096): return None
            def disconnect(self): pass

        transport = RecordingTransport()
        opaque_blob = {"custom_token": "abc123", "weird_param": [1, 2, 3]}
        identity = AgentIdentity(agent_id="opaque-pass")
        cfg = AgentConfig(identity=identity, transport_type="rec", transport_config=opaque_blob)
        self.mgr.start_session(cfg, transport)

        # The manager must have passed the blob through unchanged
        assert RecordingTransport.received_config == opaque_blob


class TestSessionManagerRedFlagAntiLeak:
    """
    Red-flag test: verify no transport-specific protocol strings exist
    in the SessionManager source file. This is a core architectural invariant.
    """
    FORBIDDEN_STRINGS = ["tls", "http", "dns", "icmp", "ssl", "ssh", "tcp", "udp"]
    SOURCE_FILE = Path(__file__).resolve().parent.parent.parent / "core" / "session_manager.py"

    def test_no_transport_names_in_session_manager_source(self):
        source = self.SOURCE_FILE.read_text(encoding="utf-8").lower()

        # Remove docstring and comment lines from check (these may legitimately reference transports)
        tree = ast.parse(source)
        lines = source.splitlines()
        code_only_lines = []
        for line in lines:
            stripped = line.strip()
            # Skip pure comment lines
            if not stripped.startswith("#"):
                code_only_lines.append(line)
        code_source = "\n".join(code_only_lines)

        violations = []
        for forbidden in self.FORBIDDEN_STRINGS:
            # Check for string literals only, not variable names that happen to match
            # e.g. 'tls' as a string literal is a leak; "transport" is fine
            for variant in [f'"{forbidden}"', f"'{forbidden}'"]:
                if variant in code_source:
                    violations.append(f"Found forbidden literal {variant!r} in session_manager.py")

        assert not violations, (
            "SessionManager contains transport-specific leaks!\n" + "\n".join(violations)
        )


class TestSessionManagerBackwardsCompat:
    """Ensure existing pub-sub and register APIs still work unchanged."""

    def setup_method(self):
        self.mgr = SessionManager()

    def test_register_session_creates_state(self):
        state = self.mgr.register_session("old-key", "tcp")
        assert self.mgr.get_session("old-key") is not None
        assert state.transport == "tcp"

    def test_register_session_idempotent(self):
        self.mgr.register_session("idem-key", "tcp")
        self.mgr.register_session("idem-key", "updated")
        assert self.mgr.get_session("idem-key").transport == "updated"

    def test_all_sessions_returns_list(self):
        self.mgr.register_session("s1", "tcp")
        self.mgr.register_session("s2", "dns")
        sessions = self.mgr.all_sessions()
        keys = [s.session_key for s in sessions]
        assert "s1" in keys
        assert "s2" in keys

    @pytest.mark.asyncio
    async def test_emit_and_subscribe(self):
        self.mgr.register_session("sub-key", "tcp")
        q, snapshot = self.mgr.subscribe("sub-key")
        assert q is not None
        assert snapshot == []

        await self.mgr.emit_event("sub-key", {"type": "test", "data": "payload"})
        event = await asyncio.wait_for(q.get(), timeout=1.0)
        assert event["type"] == "test"
        assert event["data"] == "payload"

    def test_unsubscribe_removes_queue(self):
        self.mgr.register_session("unsub-key", "tcp")
        q, _ = self.mgr.subscribe("unsub-key")
        self.mgr.unsubscribe("unsub-key", q)
        state = self.mgr.get_session("unsub-key")
        assert q not in state.subscribers
