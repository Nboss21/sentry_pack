import socket
import ssl
import threading
from pathlib import Path

from modules.c2.listeners.tls_listener.listener import TLSListener


PROJECT_ROOT = Path(__file__).resolve().parents[4]
CERT_FILE = PROJECT_ROOT / "tests" / "certs" / "cert.pem"
KEY_FILE = PROJECT_ROOT / "tests" / "certs" / "key.pem"


def test_tls_listener_accepts_connection() -> None:
    listener = TLSListener()

    received = []
    connected = threading.Event()

    def on_connection(connection):
        received.append(connection)
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
        server_address = listener._server_socket.getsockname()
        port = server_address[1]

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
            assert len(received) == 1
            assert isinstance(
                received[0],
                ssl.SSLSocket,
            )
        finally:
            client_socket.close()

    finally:
        listener.stop()

def test_tls_listener_connection_can_be_wrapped_as_transport() -> None:
    from modules.c2.transports.tls_transport.transport import TLSTransport

    listener = TLSListener()

    received = []
    connected = threading.Event()

    def on_connection(connection):
        transport = TLSTransport.from_socket(connection)
        received.append(transport)
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
            assert len(received) == 1
            assert isinstance(received[0], TLSTransport)
            assert received[0].is_alive() is True
        finally:
            client_socket.close()

    finally:
        listener.stop()