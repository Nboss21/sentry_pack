"""
Verification tests for TransportRegistry.
Criteria:
  ✓ Manager loads valid transports
  ✓ Skips broken ones without crashing
  ✓ API can list available transports
  ✓ Logs are produced for failures
"""

import logging
from pathlib import Path
import pytest
from core.transport_registry import TransportRegistry, transport_registry
from core.transport_base import ITransport, TransportMeta


# --- Fixtures: use tmp_path to build fake plugin dirs inline ---

def make_valid_plugin(tmp_path: Path, transport_id: str = "mock_tcp") -> Path:
    """Write a minimal valid transport plugin to a temp directory."""
    plugin_dir = tmp_path / transport_id
    plugin_dir.mkdir(exist_ok=True)
    (plugin_dir / "transport.py").write_text(f"""
from core.transport_base import ITransport, TransportMeta

class MockTransport(ITransport):
    meta = TransportMeta(id="{transport_id}", name="Mock", version="0.1.0", description="test")
    def connect(self, host, port, options): return True
    def send(self, data): return len(data)
    def receive(self, size=4096): return b""
    def disconnect(self): pass
""")
    return plugin_dir


def make_broken_plugin(tmp_path: Path, name: str = "broken") -> Path:
    """Write a plugin with a syntax error."""
    plugin_dir = tmp_path / name
    plugin_dir.mkdir(exist_ok=True)
    (plugin_dir / "transport.py").write_text("this is not valid python !!!@#$")
    return plugin_dir


def make_no_meta_plugin(tmp_path: Path, name: str = "no_meta") -> Path:
    """Write a plugin class that doesn't inherit ITransport and has no meta."""
    plugin_dir = tmp_path / name
    plugin_dir.mkdir(exist_ok=True)
    (plugin_dir / "transport.py").write_text("""
class NotATransport:
    pass
""")
    return plugin_dir


def make_empty_plugin(tmp_path: Path, name: str = "empty") -> Path:
    """A plugin directory with no transport.py at all."""
    plugin_dir = tmp_path / name
    plugin_dir.mkdir(exist_ok=True)
    return plugin_dir


# --- Tests ---

def test_loads_valid_transport(tmp_path):
    make_valid_plugin(tmp_path, "mock_tcp")
    registry = TransportRegistry()
    registry.scan(tmp_path)
    assert registry.get_transport("mock_tcp") is not None


def test_skips_broken_plugin_without_crashing(tmp_path):
    make_broken_plugin(tmp_path, "broken")
    registry = TransportRegistry()
    registry.scan(tmp_path)   # must not raise
    assert registry.list_transports() == []


def test_skips_no_meta_plugin_without_crashing(tmp_path):
    make_no_meta_plugin(tmp_path, "no_meta")
    registry = TransportRegistry()
    registry.scan(tmp_path)
    assert registry.list_transports() == []


def test_skips_empty_directory_without_crashing(tmp_path):
    make_empty_plugin(tmp_path, "empty_dir")
    registry = TransportRegistry()
    registry.scan(tmp_path)
    assert registry.list_transports() == []


def test_loads_valid_and_skips_broken_mixed(tmp_path):
    """Core scenario: valid + broken in same dir — loads one, skips one, no crash."""
    make_valid_plugin(tmp_path, "good_transport")
    make_broken_plugin(tmp_path, "bad_transport")
    registry = TransportRegistry()
    registry.scan(tmp_path)
    assert len(registry.list_transports()) == 1
    assert registry.get_transport("good_transport") is not None
    assert registry.get_transport("bad_transport") is None


def test_logs_failure_for_broken_plugin(tmp_path, caplog):
    make_broken_plugin(tmp_path, "syntax_error_plugin")
    registry = TransportRegistry()
    with caplog.at_level(logging.WARNING, logger="sentrypack.transport_registry"):
        registry.scan(tmp_path)
    assert len(caplog.records) > 0, "Expected at least one log record for the broken plugin"


def test_duplicate_id_keeps_first(tmp_path):
    make_valid_plugin(tmp_path, "dup")
    # Create a second plugin with the same id
    plugin_dir = tmp_path / "dup2"
    plugin_dir.mkdir(exist_ok=True)
    (plugin_dir / "transport.py").write_text("""
from core.transport_base import ITransport, TransportMeta
class DupTransport(ITransport):
    meta = TransportMeta(id="dup", name="Duplicate", version="0.2.0", description="dup")
    def connect(self, h, p, o): return True
    def send(self, d): return 0
    def receive(self, s=4096): return b""
    def disconnect(self): pass
""")
    registry = TransportRegistry()
    registry.scan(tmp_path)
    loaded = registry.list_transports()
    assert len(loaded) == 1
    assert loaded[0].version == "0.1.0"  # first one wins


def test_list_transports_returns_meta_objects(tmp_path):
    make_valid_plugin(tmp_path, "listed")
    registry = TransportRegistry()
    registry.scan(tmp_path)
    metas = registry.list_transports()
    assert len(metas) == 1
    assert metas[0].id == "listed"
    assert isinstance(metas[0], TransportMeta)


def test_get_nonexistent_transport_returns_none(tmp_path):
    registry = TransportRegistry()
    registry.scan(tmp_path)
    assert registry.get_transport("does_not_exist") is None


def test_scan_actual_modules_transports_directory():
    """Scans the repository's modules/transports directory and ensures tcp is loaded and broken_example is skipped."""
    transports_dir = Path(__file__).resolve().parent.parent.parent / "modules" / "transports"
    registry = TransportRegistry()
    registry.scan(transports_dir)

    # tcp must be present
    tcp_cls = registry.get_transport("tcp")
    assert tcp_cls is not None
    assert tcp_cls.meta.id == "tcp"
    assert tcp_cls.meta.name == "TCP Raw Socket"

    # broken_example must not be loaded
    assert registry.get_transport("broken_example") is None


def test_tcp_transport_methods():
    """Test TcpTransport methods error handling and contract."""
    from modules.transports.tcp.transport import TcpTransport
    t = TcpTransport()
    # connect to unreachable port/host
    res = t.connect("127.0.0.1", 59999, {"timeout": 0.1})
    assert res is False
    # send / recv on closed socket should return 0 / b""
    assert t.send(b"hello") == 0
    assert t.receive(1024) == b""
    t.disconnect()
    assert t._sock is None


# --- API integration test ---

def test_api_lists_available_transports():
    """GET /api/transports returns a transports list and detail endpoint works."""
    from fastapi.testclient import TestClient
    from api.main import app
    client = TestClient(app)

    # Trigger scan for singleton if not done
    transports_dir = Path(__file__).resolve().parent.parent.parent / "modules" / "transports"
    transport_registry.scan(transports_dir)

    resp = client.get("/api/transports/")
    assert resp.status_code == 200
    body = resp.json()
    assert "transports" in body
    assert "count" in body
    assert isinstance(body["transports"], list)
    assert body["count"] >= 1

    transport_ids = [t["id"] for t in body["transports"]]
    assert "tcp" in transport_ids

    # Test detail endpoint
    detail_resp = client.get("/api/transports/tcp")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["id"] == "tcp"
    assert detail["name"] == "TCP Raw Socket"

    # Test 404 for nonexistent transport
    err_resp = client.get("/api/transports/nonexistent_proto")
    assert err_resp.status_code == 404
