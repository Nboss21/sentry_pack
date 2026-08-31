from core.listener_manager import ListenerManager
from core.listener_registry import ListenerRegistry
from modules.c2.listeners.test_listener.listener import TestListener


def test_register_and_get_listener():
    registry = ListenerRegistry()
    manager = ListenerManager(registry)

    listener = TestListener()

    manager.register(listener)

    assert manager.get("test") is listener
    assert manager.list() == ["test"]


def test_start_listener():
    registry = ListenerRegistry()
    manager = ListenerManager(registry)

    listener = TestListener()
    manager.register(listener)

    result = manager.start(
        "test",
        {},
        lambda connection: None,
    )

    assert result is True
    assert listener.is_running() is True


def test_stop_listener():
    registry = ListenerRegistry()
    manager = ListenerManager(registry)

    listener = TestListener()
    manager.register(listener)

    manager.start(
        "test",
        {},
        lambda connection: None,
    )

    manager.stop("test")

    assert listener.is_running() is False