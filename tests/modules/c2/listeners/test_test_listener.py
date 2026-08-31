from modules.c2.listeners.test_listener.listener import TestListener


def test_listener_starts() -> None:
    listener = TestListener()

    result = listener.start(
        {},
        lambda connection: None,
    )

    assert result is True
    assert listener.is_running() is True


def test_listener_stops() -> None:
    listener = TestListener()

    listener.start({}, lambda connection: None)
    listener.stop()

    assert listener.is_running() is False


def test_listener_connection_callback() -> None:
    listener = TestListener()

    received = []

    def callback(connection):
        received.append(connection)

    listener.start({}, callback)

    listener.simulate_connection("test-connection")

    assert received == ["test-connection"]