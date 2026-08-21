"""
Task 1 verification tests: Core C2 Interfaces and Data Contracts.

Verifies:
  ✓ Task data contract — creation, serialisation, deserialisation
  ✓ TaskResult data contract — creation, serialisation, deserialisation
  ✓ AgentIdentity — typed fields, to_dict / from_dict round-trip
  ✓ AgentConfig — typed identity + opaque transport_config, JSON round-trip
  ✓ SessionStatus enum — all expected values present
  ✓ TransportMeta — metadata structure correct
  ✓ ITransport — abstract, cannot be instantiated directly
  ✓ IAgentSession — abstract, cannot be instantiated directly
  ✓ transport_config opacity — AgentConfig never validates or inspects its contents
"""

from __future__ import annotations

import json
import time
import pytest

from core.transport_base import (
    AgentConfig,
    AgentIdentity,
    IAgentSession,
    ITransport,
    SessionStatus,
    Task,
    TaskResult,
    TransportMeta,
)


# ---------------------------------------------------------------------------
# Task
# ---------------------------------------------------------------------------

class TestTask:
    def test_task_creation_minimal(self):
        t = Task(id="t1", payload="whoami")
        assert t.id == "t1"
        assert t.payload == "whoami"
        assert isinstance(t.timestamp, float)
        assert t.metadata == {}

    def test_task_creation_full(self):
        ts = 1234567890.0
        t = Task(id=42, payload=b"\x00\xff", timestamp=ts, metadata={"priority": "high"})
        assert t.id == 42
        assert t.payload == b"\x00\xff"
        assert t.timestamp == ts
        assert t.metadata["priority"] == "high"

    def test_task_to_dict(self):
        t = Task(id="x", payload="ls -la", timestamp=1.0)
        d = t.to_dict()
        assert d["id"] == "x"
        assert d["payload"] == "ls -la"
        assert d["timestamp"] == 1.0
        assert isinstance(d["metadata"], dict)

    def test_task_from_dict_roundtrip(self):
        original = Task(id="rt", payload="net user", timestamp=9999.0, metadata={"tag": "recon"})
        restored = Task.from_dict(original.to_dict())
        assert restored.id == original.id
        assert restored.payload == original.payload
        assert restored.timestamp == original.timestamp
        assert restored.metadata == original.metadata

    def test_task_from_dict_defaults(self):
        t = Task.from_dict({})
        assert t.id == ""
        assert t.payload == ""
        assert isinstance(t.timestamp, float)


# ---------------------------------------------------------------------------
# TaskResult
# ---------------------------------------------------------------------------

class TestTaskResult:
    def test_result_creation_minimal(self):
        r = TaskResult(task_id="t1", output="root")
        assert r.task_id == "t1"
        assert r.output == "root"
        assert r.status == "completed"
        assert r.error is None

    def test_result_creation_failure(self):
        r = TaskResult(task_id=99, output=None, status="failed", error="timeout")
        assert r.task_id == 99
        assert r.status == "failed"
        assert r.error == "timeout"

    def test_result_to_dict(self):
        r = TaskResult(task_id="t2", output="output_value", status="completed")
        d = r.to_dict()
        assert d["task_id"] == "t2"
        assert d["output"] == "output_value"
        assert d["status"] == "completed"
        assert d["error"] is None

    def test_result_from_dict_roundtrip(self):
        original = TaskResult(task_id="rt", output="data", status="failed", error="err", timestamp=55.5)
        restored = TaskResult.from_dict(original.to_dict())
        assert restored.task_id == original.task_id
        assert restored.output == original.output
        assert restored.status == original.status
        assert restored.error == original.error
        assert restored.timestamp == original.timestamp


# ---------------------------------------------------------------------------
# SessionStatus
# ---------------------------------------------------------------------------

class TestSessionStatus:
    def test_all_values_present(self):
        assert SessionStatus.ACTIVE == "active"
        assert SessionStatus.INACTIVE == "inactive"
        assert SessionStatus.ERROR == "error"
        assert SessionStatus.TERMINATED == "terminated"

    def test_is_string_subclass(self):
        assert isinstance(SessionStatus.ACTIVE, str)

    def test_comparison(self):
        assert SessionStatus.ACTIVE == "active"
        assert SessionStatus.TERMINATED != "active"


# ---------------------------------------------------------------------------
# AgentIdentity
# ---------------------------------------------------------------------------

class TestAgentIdentity:
    def test_creation_minimal(self):
        ai = AgentIdentity(agent_id="agent-001")
        assert ai.agent_id == "agent-001"
        assert ai.name == ""
        assert ai.project_id is None
        assert ai.tags == []

    def test_creation_full(self):
        ai = AgentIdentity(
            agent_id="a1",
            name="Primary Agent",
            project_id=42,
            hostname="10.0.0.5",
            platform="linux/amd64",
            tags=["pivot", "highval"],
        )
        assert ai.hostname == "10.0.0.5"
        assert "pivot" in ai.tags
        assert ai.project_id == 42

    def test_to_dict_from_dict_roundtrip(self):
        ai = AgentIdentity(agent_id="rt", name="Agent RT", project_id=7, tags=["a", "b"])
        restored = AgentIdentity.from_dict(ai.to_dict())
        assert restored.agent_id == ai.agent_id
        assert restored.name == ai.name
        assert restored.project_id == ai.project_id
        assert restored.tags == ai.tags


# ---------------------------------------------------------------------------
# AgentConfig (Task 4 core verification)
# ---------------------------------------------------------------------------

class TestAgentConfig:
    def test_creation_basic(self):
        identity = AgentIdentity(agent_id="cfg-001")
        cfg = AgentConfig(
            identity=identity,
            transport_type="tls",
            transport_config={"host": "10.0.0.1", "port": 4443, "verify_cert": False},
        )
        assert cfg.transport_type == "tls"
        assert cfg.identity.agent_id == "cfg-001"
        # transport_config is stored as-is, completely opaque
        assert cfg.transport_config["host"] == "10.0.0.1"

    def test_transport_config_is_opaque(self):
        """
        CRITICAL: transport_config must be stored/retrieved without any
        inspection, validation, or modification by AgentConfig itself.
        Any arbitrary dict must pass through unchanged.
        """
        weird_config = {
            "super_secret_field": "only_tls_knows",
            "nested": {"deep": {"value": [1, 2, 3]}},
            "bytes_flag": True,
        }
        identity = AgentIdentity(agent_id="opaque-test")
        cfg = AgentConfig(identity=identity, transport_type="custom_transport", transport_config=weird_config)
        assert cfg.transport_config == weird_config

    def test_to_dict_roundtrip(self):
        identity = AgentIdentity(agent_id="rd1", name="RT Agent", project_id=5)
        cfg = AgentConfig(
            identity=identity,
            transport_type="tls",
            transport_config={"host": "192.168.1.1", "port": 4443},
        )
        d = cfg.to_dict()
        restored = AgentConfig.from_dict(d)
        assert restored.identity.agent_id == cfg.identity.agent_id
        assert restored.transport_type == cfg.transport_type
        assert restored.transport_config == cfg.transport_config

    def test_json_roundtrip(self):
        identity = AgentIdentity(agent_id="json-agent", name="JSON Test", tags=["pentest"])
        cfg = AgentConfig(
            identity=identity,
            transport_type="dns",
            transport_config={"resolver": "8.8.8.8", "domain": "c2.example.com", "interval": 30},
        )
        json_str = cfg.to_json()
        # Verify it's valid JSON
        data = json.loads(json_str)
        assert "identity" in data
        assert data["transport_type"] == "dns"

        # Roundtrip restore
        restored = AgentConfig.from_json(json_str)
        assert restored.identity.agent_id == "json-agent"
        assert restored.transport_config["resolver"] == "8.8.8.8"

    def test_from_dict_with_identity_object(self):
        identity = AgentIdentity(agent_id="obj-identity")
        cfg = AgentConfig.from_dict({
            "identity": identity,
            "transport_type": "tcp",
            "transport_config": {},
        })
        assert cfg.identity.agent_id == "obj-identity"

    def test_transport_config_never_modified(self):
        """Ensures AgentConfig does not add, remove, or transform keys in transport_config."""
        original_cfg = {"alpha": 1, "beta": "two", "gamma": [3, 4]}
        identity = AgentIdentity(agent_id="integrity-check")
        agent_cfg = AgentConfig(identity=identity, transport_type="test", transport_config=original_cfg)
        # Stored config must equal input exactly
        assert agent_cfg.transport_config is not original_cfg  # should be a separate reference
        assert agent_cfg.transport_config == original_cfg


# ---------------------------------------------------------------------------
# ITransport and IAgentSession — abstract enforcement
# ---------------------------------------------------------------------------

class TestAbstractInterfaces:
    def test_itransport_cannot_be_instantiated(self):
        with pytest.raises(TypeError):
            ITransport()  # type: ignore

    def test_iagentsession_cannot_be_instantiated(self):
        with pytest.raises(TypeError):
            IAgentSession()  # type: ignore

    def test_itransport_requires_all_methods(self):
        """Partial implementation must not be instantiable."""
        class PartialTransport(ITransport):
            meta = TransportMeta(id="partial", name="P", version="0.1.0", description="test")
            def connect(self, *a, **kw): return True
            def send(self, data): return 0
            # missing receive and disconnect

        with pytest.raises(TypeError):
            PartialTransport()  # type: ignore

    def test_itransport_concrete_subclass_works(self):
        """Complete implementation must be instantiable."""
        class MockTransport(ITransport):
            meta = TransportMeta(id="mock", name="Mock", version="0.1.0", description="test")
            def connect(self, *a, **kw): return True
            def send(self, data): return 1
            def receive(self, size=4096): return b"result"
            def disconnect(self): pass

        t = MockTransport()
        assert t.connect({}) is True
        assert t.send(b"x") == 1
        assert t.receive() == b"result"
        assert t.is_alive() is True  # default implementation

    def test_transport_meta_structure(self):
        meta = TransportMeta(id="test", name="Test", version="1.0.0", description="desc")
        assert meta.id == "test"
        assert meta.name == "Test"
        assert meta.version == "1.0.0"
        assert meta.author == "unknown"
        assert meta.options == []
