import pytest

from core.listener_base import IListener
from core.listener_registry import ListenerRegistry
from modules.c2.listeners.test_listener.listener import TestListener


class DummyListener(IListener):
    @property
    def listener_id(self) -> str:
        return "dummy"

    def start(self, config, on_connection) -> bool:
        return True

    def stop(self) -> None:
        pass

    def is_running(self) -> bool:
        return False


def test_register_and_get_listener() -> None:
    registry = ListenerRegistry()
    listener = DummyListener()

    registry.register(listener)

    assert registry.get("dummy") is listener


def test_list_listeners() -> None:
    registry = ListenerRegistry()
    registry.register(DummyListener())

    assert registry.list() == ["dummy"]


def test_unknown_listener() -> None:
    registry = ListenerRegistry()

    with pytest.raises(KeyError):
        registry.get("missing")


def test_duplicate_listener() -> None:
    registry = ListenerRegistry()

    registry.register(DummyListener())

    with pytest.raises(ValueError):
        registry.register(DummyListener())


def test_invalid_listener() -> None:
    registry = ListenerRegistry()

    with pytest.raises(TypeError):
        registry.register(object())


def test_unregister_listener() -> None:
    registry = ListenerRegistry()
    registry.register(DummyListener())

    registry.unregister("dummy")

    assert registry.list() == []


def test_unregister_unknown_listener() -> None:
    registry = ListenerRegistry()

    with pytest.raises(KeyError):
        registry.unregister("missing")



def test_register_test_listener() -> None:
    registry = ListenerRegistry()
    listener = TestListener()

    registry.register(listener)

    assert "test" in registry.list()
    assert registry.get("test") is listener