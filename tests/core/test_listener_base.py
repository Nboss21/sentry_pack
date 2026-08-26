import pytest

from core.listener_base import IListener


class DummyListener(IListener):
    """Minimal concrete listener for interface tests."""

    def __init__(self) -> None:
        self.running = False
        self.callback = None

    @property
    def listener_id(self) -> str:
        return "dummy"

    def start(self, config, on_connection) -> bool:
        self.callback = on_connection
        self.running = True
        return True

    def stop(self) -> None:
        self.running = False

    def is_running(self) -> bool:
        return self.running


def test_listener_can_start() -> None:
    listener = DummyListener()

    result = listener.start({}, lambda connection: None)

    assert result is True
    assert listener.is_running() is True


def test_listener_can_stop() -> None:
    listener = DummyListener()

    listener.start({}, lambda connection: None)
    listener.stop()

    assert listener.is_running() is False


def test_listener_stores_connection_callback() -> None:
    listener = DummyListener()

    def callback(connection):
        pass

    listener.start({}, callback)

    assert listener.callback is callback


def test_listener_id() -> None:
    listener = DummyListener()

    assert listener.listener_id == "dummy"


def test_listener_is_abstract() -> None:
    with pytest.raises(TypeError):
        IListener()
        IListener()