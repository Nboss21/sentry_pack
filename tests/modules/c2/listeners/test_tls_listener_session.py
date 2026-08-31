
import socket
import ssl
import threading
from pathlib import Path

from core.session_manager import SessionManager
from modules.c2.listeners.tls_listener.listener import TLSListener
from modules.c2.listeners.tls_listener.handler import handle_tls_connection


PROJECT_ROOT = Path(__file__).resolve().parents[4]
CERT_FILE = PROJECT_ROOT / "tests" / "certs" / "cert.pem"
KEY_FILE = PROJECT_ROOT / "tests" / "certs" / "key.pem"


def test_tls_listener_registers_inbound_session():
    listener = TLSListener()
    manager = SessionManager()

    connected = threading.Event()

    # def on_connection(connection):
    #     # handle_tls_connection(connection, manager)
    #     # connected.set()
    #     try:
    #         handle_tls_connection(connection, manager)
    #     except Exception as exc:
    #         print(f"CALLBACK ERROR: {type(exc).__name__}: {exc}")
    #         raise
    #     finally:
    #         connected.set()
    def on_connection(connection):
        handle_tls_connection(connection, manager)
        connected.set()

    listener.start(
        {
            "host": "127.0.0.1",
            "port": 0,
            "certfile": str(CERT_FILE),
            "keyfile": str(KEY_FILE),
        },
        on_connection,
    )

    try:
        port = listener._server_socket.getsockname()[1]

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        raw_socket = socket.create_connection(
            ("127.0.0.1", port)
        )

        client_socket = context.wrap_socket(
            raw_socket,
            server_hostname="localhost",
        )

        try:
            assert connected.wait(timeout=2)

            session = manager.get_session("tls-inbound")

            assert session is not None
            assert session.session_key == "tls-inbound"
            assert session.status.value == "active"
            assert session.transport.is_alive() is True
            assert session.metadata["direction"] == "inbound"
            assert session.metadata["listener"] == "tls"

            

        finally:
            client_socket.close()

    finally:
        listener.stop()

def test_tls_listener_receives_inbound_data():
    listener = TLSListener()
    manager = SessionManager()

    connected = threading.Event()

    def on_connection(connection):
        handle_tls_connection(connection, manager)
        connected.set()

    listener.start(
        {
            "host": "127.0.0.1",
            "port": 0,
            "certfile": str(CERT_FILE),
            "keyfile": str(KEY_FILE),
        },
        on_connection,
    )

    try:
        port = listener._server_socket.getsockname()[1]

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        raw_socket = socket.create_connection(
            ("127.0.0.1", port)
        )

        client_socket = context.wrap_socket(
            raw_socket,
            server_hostname="localhost",
        )

        try:
            assert connected.wait(timeout=2)

            payload = b"hello from inbound agent"

            client_socket.sendall(payload)

            result = manager.receive_result("tls-inbound")

            assert result is not None
            assert result.output == payload
            assert result.status == "completed"

        finally:
            client_socket.close()

    finally:
        listener.stop()