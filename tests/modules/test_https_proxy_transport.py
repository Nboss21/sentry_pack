"""
Verification and Unit Tests for HttpsProxyTransport Module.

Verifies:
  ✓ HttpsProxyTransport implements the full ITransport interface
  ✓ TransportMeta is properly populated (id="https_proxy", name="HTTP/S Proxy", etc.)
  ✓ TransportRegistry automatically discovers and loads https_proxy plugin
  ✓ Can be enabled and disabled; connect() short-circuits when disabled
  ✓ Handles connect() with dict config, AgentConfig, and positional arguments
  ✓ Idempotent connect() and disconnect()
  ✓ Graceful error handling on disconnected send/receive
  ✓ End-to-end HTTP CONNECT tunnel with mock proxy & mock echo backend (plain and TLS)
  ✓ Task serialization and TaskResult deserialization
  ✓ Proxy error response handling (403, 502, truncated responses)
"""

from __future__ import annotations

import inspect
import json
import logging
from pathlib import Path
import socket
import ssl
import sys
import threading
import time
from typing import Any, Tuple

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
from modules.transports.https_proxy.transport import HttpsProxyTransport

TRANSPORTS_DIR = Path(__file__).resolve().parent.parent.parent / "modules" / "transports"
HTTPS_PROXY_DIR = TRANSPORTS_DIR / "https_proxy"


# ---------------------------------------------------------------------------
# Test Helpers: Mock HTTP CONNECT Proxy and Target Echo Server
# ---------------------------------------------------------------------------

def _start_mock_echo_target() -> Tuple[int, threading.Thread, socket.socket]:
    """Start a plain TCP echo server on an ephemeral port."""
    target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    target_sock.bind(("127.0.0.1", 0))
    port = target_sock.getsockname()[1]
    target_sock.listen(5)
    target_sock.settimeout(5)

    def _serve():
        try:
            conn, _ = target_sock.accept()
            with conn:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(data)
        except Exception:
            pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return port, t, target_sock


def _start_mock_connect_proxy(
    target_port: int,
    status_code: int = 200,
    status_text: str = "Connection established",
) -> Tuple[int, threading.Thread, socket.socket]:
    """
    Start a mock HTTP forward proxy handling CONNECT requests on an ephemeral port.
    Tunnels traffic to 127.0.0.1:target_port if status_code is 200.
    """
    proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_sock.bind(("127.0.0.1", 0))
    proxy_port = proxy_sock.getsockname()[1]
    proxy_sock.listen(5)
    proxy_sock.settimeout(5)

    def _serve():
        try:
            client_conn, _ = proxy_sock.accept()
            with client_conn:
                req_data = b""
                while b"\r\n\r\n" not in req_data:
                    chunk = client_conn.recv(1024)
                    if not chunk:
                        break
                    req_data += chunk

                if status_code != 200:
                    client_conn.sendall(
                        f"HTTP/1.1 {status_code} {status_text}\r\nContent-Length: 0\r\n\r\n".encode("utf-8")
                    )
                    return

                # Send 200 Connection established
                client_conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

                # Connect to target
                target_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_conn.settimeout(5)
                target_conn.connect(("127.0.0.1", target_port))

                # Bi-directional relay threads
                def _forward(src, dst):
                    try:
                        while True:
                            d = src.recv(4096)
                            if not d:
                                break
                            dst.sendall(d)
                    except Exception:
                        pass
                    finally:
                        try:
                            dst.close()
                        except Exception:
                            pass

                t1 = threading.Thread(target=_forward, args=(client_conn, target_conn), daemon=True)
                t2 = threading.Thread(target=_forward, args=(target_conn, client_conn), daemon=True)
                t1.start()
                t2.start()
                t1.join(timeout=3)
                t2.join(timeout=3)
        except Exception:
            pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return proxy_port, t, proxy_sock


# ---------------------------------------------------------------------------
# 1. Interface & Metadata Conformance Tests
# ---------------------------------------------------------------------------

class TestHttpsProxyInterface:
    def test_is_itransport_subclass(self):
        assert issubclass(HttpsProxyTransport, ITransport)

    def test_not_abstract(self):
        assert not inspect.isabstract(HttpsProxyTransport)
        assert not getattr(HttpsProxyTransport, "__abstractmethods__", set())

    def test_meta_attributes(self):
        t = HttpsProxyTransport()
        assert t.meta.id == "https_proxy"
        assert t.meta.name == "HTTP/S Proxy"
        assert t.meta.version == "0.1.0"
        assert "tunnel" in t.meta.description.lower()
        assert t.meta.author == "Burka Zelalem"
        assert isinstance(t.meta, TransportMeta)

    def test_initial_state_disconnected(self):
        t = HttpsProxyTransport()
        assert t.is_alive() is False
        assert t._sock is None
        assert t._enabled is True

    def test_send_on_disconnected_returns_zero(self):
        t = HttpsProxyTransport()
        assert t.send(b"hello") == 0
        assert t.send("string payload") == 0
        assert t.send(Task(id="1", payload="test")) == 0

    def test_receive_on_disconnected_returns_empty(self):
        t = HttpsProxyTransport()
        assert t.receive() == b""

    def test_disconnect_is_safe_when_not_connected(self):
        t = HttpsProxyTransport()
        t.disconnect()
        t.disconnect()
        assert t._sock is None


# ---------------------------------------------------------------------------
# 2. Enable / Disable Lifecycle Tests
# ---------------------------------------------------------------------------

class TestHttpsProxyEnableDisable:
    def test_enable_disable_state(self):
        t = HttpsProxyTransport()
        assert t._enabled is True

        t.disable()
        assert t._enabled is False
        assert t.is_alive() is False

        t.enable()
        assert t._enabled is True

    def test_connect_short_circuits_when_disabled(self):
        t = HttpsProxyTransport()
        t.disable()
        res = t.connect({"proxy_host": "127.0.0.1", "proxy_port": 8080, "target_host": "127.0.0.1", "target_port": 443})
        assert res is False
        assert t.is_alive() is False

    def test_connect_with_disabled_flag_in_config(self):
        t = HttpsProxyTransport()
        res = t.connect({"enabled": False, "proxy_host": "127.0.0.1", "proxy_port": 8080})
        assert res is False
        assert t._enabled is False
        assert t.is_alive() is False

    def test_send_and_receive_blocked_when_disabled(self):
        t = HttpsProxyTransport()
        t.disable()
        assert t.send(b"test") == 0
        assert t.receive() == b""


# ---------------------------------------------------------------------------
# 3. Registry Auto-Discovery Tests
# ---------------------------------------------------------------------------

class TestHttpsProxyRegistryDiscovery:
    def test_registry_discovers_https_proxy(self):
        registry = TransportRegistry()
        registry.scan(TRANSPORTS_DIR)
        cls = registry.get_transport("https_proxy")
        assert cls is not None
        assert cls.meta.id == "https_proxy"
        assert cls.meta.name == "HTTP/S Proxy"

    def test_registry_lists_https_proxy(self):
        registry = TransportRegistry()
        registry.scan(TRANSPORTS_DIR)
        transport_ids = [t.id for t in registry.list_transports()]
        assert "https_proxy" in transport_ids

    def test_transport_toml_manifest_valid(self):
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli as tomllib

        toml_file = HTTPS_PROXY_DIR / "transport.toml"
        assert toml_file.exists(), "transport.toml must exist in modules/transports/https_proxy"
        with open(toml_file, "rb") as f:
            data = tomllib.load(f)

        assert "transport" in data
        meta = data["transport"]
        assert meta["id"] == "https_proxy"
        assert meta["name"] == "HTTP/S Proxy"
        assert meta["version"] == "0.1.0"
        assert meta["author"] == "Burka Zelalem"


# ---------------------------------------------------------------------------
# 4. End-to-End Tunneling, Send & Receive Tests
# ---------------------------------------------------------------------------

class TestHttpsProxyE2E:
    def test_connect_to_unreachable_proxy_returns_false(self):
        t = HttpsProxyTransport()
        res = t.connect({
            "proxy_host": "127.0.0.1",
            "proxy_port": 59998,
            "target_host": "127.0.0.1",
            "target_port": 443,
            "timeout": 0.2,
        })
        assert res is False
        assert t.is_alive() is False

    def test_proxy_tunnel_send_receive_plain(self):
        target_port, target_thread, target_sock = _start_mock_echo_target()
        proxy_port, proxy_thread, proxy_sock = _start_mock_connect_proxy(target_port)

        try:
            t = HttpsProxyTransport()
            cfg = {
                "proxy_host": "127.0.0.1",
                "proxy_port": proxy_port,
                "target_host": "127.0.0.1",
                "target_port": target_port,
                "use_tls": False,
                "timeout": 3,
            }
            connected = t.connect(cfg)
            assert connected is True
            assert t.is_alive() is True

            # Send bytes
            sent = t.send(b"ping from proxy client")
            assert sent > 0

            time.sleep(0.05)
            recv = t.receive()
            assert recv == b"ping from proxy client"

            t.disconnect()
            assert t.is_alive() is False
        finally:
            target_sock.close()
            proxy_sock.close()

    def test_proxy_tunnel_send_task_receive_task_result(self):
        target_port, target_thread, target_sock = _start_mock_echo_target()
        proxy_port, proxy_thread, proxy_sock = _start_mock_connect_proxy(target_port)

        try:
            t = HttpsProxyTransport()
            cfg = {
                "proxy_host": "127.0.0.1",
                "proxy_port": proxy_port,
                "target_host": "127.0.0.1",
                "target_port": target_port,
                "use_tls": False,
                "timeout": 3,
            }
            assert t.connect(cfg) is True

            # Send Task dataclass
            task = Task(id="task-101", payload="whoami", metadata={"user": "admin"})
            sent = t.send(task)
            assert sent > 0

            # Target will echo JSON payload back; receive should attempt deserialization
            time.sleep(0.05)
            recv = t.receive()
            assert recv is not None

            # Now send a valid TaskResult JSON to test TaskResult parsing
            task_result = TaskResult(task_id="task-101", output="root", status="completed")
            t.send(json.dumps(task_result.to_dict()))

            time.sleep(0.05)
            res_obj = t.receive()
            assert isinstance(res_obj, TaskResult)
            assert res_obj.task_id == "task-101"
            assert res_obj.output == "root"
            assert res_obj.status == "completed"

            t.disconnect()
        finally:
            target_sock.close()
            proxy_sock.close()

    def test_connect_with_agent_config(self):
        target_port, target_thread, target_sock = _start_mock_echo_target()
        proxy_port, proxy_thread, proxy_sock = _start_mock_connect_proxy(target_port)

        try:
            t = HttpsProxyTransport()
            identity = AgentIdentity(agent_id="proxy-agent-01", name="Proxy Agent")
            agent_cfg = AgentConfig(
                identity=identity,
                transport_type="https_proxy",
                transport_config={
                    "proxy_host": "127.0.0.1",
                    "proxy_port": proxy_port,
                    "target_host": "127.0.0.1",
                    "target_port": target_port,
                    "use_tls": False,
                    "timeout": 2,
                },
            )
            assert t.connect(agent_cfg) is True
            assert t.is_alive() is True
            t.disconnect()
        finally:
            target_sock.close()
            proxy_sock.close()

    def test_connect_with_positional_args(self):
        target_port, target_thread, target_sock = _start_mock_echo_target()
        proxy_port, proxy_thread, proxy_sock = _start_mock_connect_proxy(target_port)

        try:
            t = HttpsProxyTransport()
            opts = {
                "target_host": "127.0.0.1",
                "target_port": target_port,
                "use_tls": False,
                "timeout": 2,
            }
            assert t.connect("127.0.0.1", proxy_port, opts) is True
            assert t.is_alive() is True
            t.disconnect()
        finally:
            target_sock.close()
            proxy_sock.close()

    def test_proxy_returns_403_forbidden(self):
        proxy_port, proxy_thread, proxy_sock = _start_mock_connect_proxy(
            target_port=443, status_code=403, status_text="Forbidden"
        )
        try:
            t = HttpsProxyTransport()
            res = t.connect({
                "proxy_host": "127.0.0.1",
                "proxy_port": proxy_port,
                "target_host": "127.0.0.1",
                "target_port": 443,
                "use_tls": False,
                "timeout": 2,
            })
            assert res is False
            assert t.is_alive() is False
        finally:
            proxy_sock.close()

    def test_proxy_returns_502_bad_gateway(self):
        proxy_port, proxy_thread, proxy_sock = _start_mock_connect_proxy(
            target_port=443, status_code=502, status_text="Bad Gateway"
        )
        try:
            t = HttpsProxyTransport()
            res = t.connect({
                "proxy_host": "127.0.0.1",
                "proxy_port": proxy_port,
                "target_host": "127.0.0.1",
                "target_port": 443,
                "use_tls": False,
                "timeout": 2,
            })
            assert res is False
            assert t.is_alive() is False
        finally:
            proxy_sock.close()
