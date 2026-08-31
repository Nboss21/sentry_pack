"""
Task 3 verification tests: TLS Transport Module.

Verifies:
  ✓ TLSTransport implements the full ITransport interface
  ✓ TLSTransport has correct metadata (id, name, version, author)
  ✓ TransportRegistry discovers TLSTransport from modules/c2/transports/
  ✓ module.toml manifest is valid and declares correct transport id
  ✓ connect() accepts both dict config and positional arguments
  ✓ is_alive() returns False before connect, True after, False after disconnect
  ✓ send()/receive() return 0/b"" gracefully when not connected
  ✓ disconnect() is safe to call multiple times
  ✓ End-to-end TLS session with ephemeral self-signed SSL server
  ✓ TLSTransport integrates with SessionManager
"""

from __future__ import annotations
from modules.c2.transports.tls_transport.transport import TLSTransport
import ssl
import socket
import threading
import time
import tempfile
import os
from pathlib import Path
from typing import Any, Optional

import pytest

from core.transport_base import (
    AgentConfig,
    AgentIdentity,
    ITransport,
    Task,
    TaskResult,
    TransportMeta,
)
from core.transport_registry import TransportRegistry
from core.session_manager import SessionManager


# TLS_TRANSPORT_DIR = Path(__file__).resolve().parent.parent.parent / "modules" / "c2" / "transports"
# TLS_PLUGIN_DIR = TLS_TRANSPORT_DIR / "tls_transport"
TLS_TRANSPORT_DIR = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "modules" / "c2" / "transports"
)

TLS_PLUGIN_DIR = TLS_TRANSPORT_DIR / "tls_transport"

# ---------------------------------------------------------------------------
# Helpers: generate self-signed certificate pair for testing
# ---------------------------------------------------------------------------

def _generate_self_signed_cert() -> tuple[str, str]:
    """
    Generate a temporary self-signed certificate + key pair.
    Returns (certfile_path, keyfile_path).
    Requires cryptography package (or falls back to a pre-baked PEM string).
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256())
        )

        tmpdir = tempfile.mkdtemp()
        certfile = os.path.join(tmpdir, "cert.pem")
        keyfile = os.path.join(tmpdir, "key.pem")

        with open(certfile, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(keyfile, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        return certfile, keyfile

    except ImportError:
        pytest.skip("cryptography package not available for self-signed cert generation")


def _start_echo_ssl_server(certfile: str, keyfile: str) -> tuple[int, threading.Thread]:
    """
    Start a minimal SSL echo server on an ephemeral port in a background thread.
    Returns (port, thread).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

    raw_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_server.bind(("127.0.0.1", 0))
    port = raw_server.getsockname()[1]
    raw_server.listen(1)
    raw_server.settimeout(5)

    def _serve():
        try:
            with ctx.wrap_socket(raw_server, server_side=True) as ssl_server:
                try:
                    conn, _ = ssl_server.accept()
                    with conn:
                        data = conn.recv(4096)
                        if data:
                            conn.sendall(b"echo: " + data)
                except Exception:
                    pass
        except Exception:
            pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return port, t


# ---------------------------------------------------------------------------
# Interface compliance tests (no network required)
# ---------------------------------------------------------------------------

class TestTLSTransportInterface:
    def _make_transport(self):
        from modules.c2.transports.tls_transport.transport import TLSTransport
        return TLSTransport()

    def test_is_itransport_subclass(self):
        from modules.c2.transports.tls_transport.transport import TLSTransport
        assert issubclass(TLSTransport, ITransport)

    def test_meta_attributes(self):
        t = self._make_transport()
        assert t.meta.id == "tls"
        assert t.meta.name == "TLS Encrypted Transport"
        assert t.meta.version == "0.1.0"
        assert isinstance(t.meta, TransportMeta)

    def test_is_alive_false_before_connect(self):
        t = self._make_transport()
        assert t.is_alive() is False

    def test_send_returns_zero_when_not_connected(self):
        t = self._make_transport()
        assert t.send(b"hello") == 0

    def test_receive_returns_empty_when_not_connected(self):
        t = self._make_transport()
        assert t.receive() == b""

    def test_disconnect_safe_when_not_connected(self):
        t = self._make_transport()
        t.disconnect()  # Must not raise
        t.disconnect()  # Must be idempotent

    def test_connect_to_unreachable_host_returns_false(self):
        t = self._make_transport()
        result = t.connect({"host": "127.0.0.1", "port": 59876, "verify_cert": False, "timeout": 0.5})
        assert result is False
        assert t.is_alive() is False

    def test_connect_accepts_dict_config(self):
        """connect() with dict config must handle missing key gracefully."""
        t = self._make_transport()
        result = t.connect({"host": "127.0.0.1", "port": 59876, "verify_cert": False, "timeout": 0.2})
        assert isinstance(result, bool)

    def test_connect_accepts_positional_args(self):
        t = self._make_transport()
        result = t.connect("127.0.0.1", 59876, {"verify_cert": False, "timeout": 0.2})
        assert isinstance(result, bool)

    def test_send_task_object(self):
        t = self._make_transport()
        task = Task(id="t001", payload="test payload")
        result = t.send(task)
        assert result == 0  # not connected, safe fallback

    def test_all_abstract_methods_implemented(self):
        import inspect
        from modules.c2.transports.tls_transport.transport import TLSTransport
        assert not inspect.isabstract(TLSTransport)
        assert not getattr(TLSTransport, "__abstractmethods__", set())


# ---------------------------------------------------------------------------
# Registry discovery tests
# ---------------------------------------------------------------------------

class TestTLSTransportRegistryDiscovery:
    def test_registry_discovers_tls_from_c2_transports(self):
        registry = TransportRegistry()
        registry.scan(TLS_TRANSPORT_DIR)
        cls = registry.get_transport("tls")
        assert cls is not None
        assert cls.meta.id == "tls"
        assert cls.meta.name == "TLS Encrypted Transport"

    def test_registry_lists_tls(self):
        registry = TransportRegistry()
        registry.scan(TLS_TRANSPORT_DIR)
        ids = [t.id for t in registry.list_transports()]
        assert "tls" in ids

    def test_scan_many_discovers_both_tcp_and_tls(self):
        #tcp_dir = Path(__file__).resolve().parent.parent.parent / "modules" / "transports"
        tcp_dir = Path(__file__).resolve().parents[3] / "modules" / "transports"
        registry = TransportRegistry()
        registry.scan_many([tcp_dir, TLS_TRANSPORT_DIR])
        ids = [t.id for t in registry.list_transports()]
        assert "tcp" in ids
        assert "tls" in ids

    def test_tls_class_instantiable(self):
        registry = TransportRegistry()
        registry.scan(TLS_TRANSPORT_DIR)
        cls = registry.get_transport("tls")
        instance = cls()
        assert instance is not None

    def test_module_toml_declares_transport_type(self):
        import sys
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli as tomllib

        toml_path = TLS_PLUGIN_DIR / "module.toml"
        assert toml_path.exists(), "module.toml not found for tls_transport"
        with open(toml_path, "rb") as f:
            data = tomllib.load(f)
        assert data.get("transport", {}).get("id") == "tls"
        assert data.get("transport", {}).get("type") == "transport"

    def test_module_toml_has_option_schema(self):
        import sys
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli as tomllib

        toml_path = TLS_PLUGIN_DIR / "module.toml"
        with open(toml_path, "rb") as f:
            data = tomllib.load(f)
        options = data.get("options", [])
        option_names = [o.get("name") for o in options]
        assert "host" in option_names
        assert "port" in option_names
        assert "certfile" in option_names
        assert "verify_cert" in option_names


# ---------------------------------------------------------------------------
# End-to-end TLS session test
# ---------------------------------------------------------------------------

class TestTLSTransportE2E:
    """End-to-end test: spin up an in-process SSL echo server, connect, send, receive, disconnect."""

    @pytest.fixture(autouse=True)
    def setup(self):
        try:
            self.certfile, self.keyfile = _generate_self_signed_cert()
        except Exception:
            pytest.skip("Cannot generate self-signed cert; skipping E2E TLS tests")

    def test_e2e_tls_session_send_receive(self):
        from modules.c2.transports.tls_transport.transport import TLSTransport

        port, server_thread = _start_echo_ssl_server(self.certfile, self.keyfile)
        time.sleep(0.15)  # Allow server to start

        t = TLSTransport()
        cfg = {
            "host": "127.0.0.1",
            "port": port,
            "ca_certs": self.certfile,
            "verify_cert": True,
            "server_hostname": "localhost",
            "timeout": 5,
        }
        connected = t.connect(cfg)
        assert connected is True, "TLS connection must succeed to ephemeral echo server"
        assert t.is_alive() is True

        sent = t.send(b"hello tls")
        assert sent > 0

        # Give server time to echo
        time.sleep(0.1)
        received = t.receive()
        assert received == b"echo: hello tls"

        t.disconnect()
        assert t.is_alive() is False
        server_thread.join(timeout=2)

    def test_e2e_tls_with_task_object(self):
        from modules.c2.transports.tls_transport.transport import TLSTransport

        port, server_thread = _start_echo_ssl_server(self.certfile, self.keyfile)
        time.sleep(0.15)

        t = TLSTransport()
        cfg = {
            "host": "127.0.0.1",
            "port": port,
            "ca_certs": self.certfile,
            "verify_cert": True,
            "server_hostname": "localhost",
            "timeout": 5,
        }
        t.connect(cfg)
        task = Task(id="e2e-001", payload="e2e task payload")
        sent = t.send(task)
        assert sent > 0

        time.sleep(0.1)
        received = t.receive()
        assert b"e2e task payload" in received

        t.disconnect()
        server_thread.join(timeout=2)


# ---------------------------------------------------------------------------
# SessionManager integration with TLS transport
# ---------------------------------------------------------------------------

class TestTLSTransportSessionManagerIntegration:
    def test_session_manager_starts_tls_session(self):
        """SessionManager must work with TLSTransport just like MockTransport — no special casing."""
        from modules.c2.transports.tls_transport.transport import TLSTransport

        transport = TLSTransport()
        identity = AgentIdentity(agent_id="tls-agent-sm", name="TLS SessionManager Test")
        cfg = AgentConfig(
            identity=identity,
            transport_type="tls",
            transport_config={"host": "127.0.0.1", "port": 59875, "verify_cert": False, "timeout": 0.2},
        )
        mgr = SessionManager()
        session = mgr.start_session(cfg, transport)

        # Connect will fail (no server), but session must be created with ERROR status
        assert session.session_key == "tls-agent-sm"
        assert session.status.value in ("active", "error")

        # Audit log must have the start event regardless
        log = mgr.get_audit_log("tls-agent-sm")
        assert any(e["event_type"] == "session_start" for e in log)

    def test_session_manager_transport_agnostic(self):
        """Verify SessionManager source has no reference to 'tls' as a string literal."""
        #source = Path(__file__).resolve().parent.parent.parent / "core" / "session_manager.py"
        source = Path(__file__).resolve().parents[3] / "core" / "session_manager.py"
        content = source.read_text()
        assert '"tls"' not in content
        assert "'tls'" not in content
def test_tls_transport_from_socket() -> None:
    from unittest.mock import MagicMock

    sock = MagicMock(spec=ssl.SSLSocket)

    transport = TLSTransport.from_socket(sock)

    assert transport.is_alive() is True
    assert transport._sock is sock
def test_tls_transport_from_socket_can_send() -> None:
    from unittest.mock import MagicMock

    sock = MagicMock(spec=ssl.SSLSocket)
    transport = TLSTransport.from_socket(sock)

    sent = transport.send(b"hello")

    assert sent == 5
    sock.sendall.assert_called_once_with(b"hello")


def test_tls_transport_from_socket_can_receive() -> None:
    from unittest.mock import MagicMock

    sock = MagicMock(spec=ssl.SSLSocket)
    sock.recv.return_value = b"hello"

    transport = TLSTransport.from_socket(sock)

    received = transport.receive()

    assert received == b"hello"
    sock.recv.assert_called_once_with(4096)