from core.listener_manager import ListenerManager
from core.listener_registry import ListenerRegistry
from modules.c2.listeners.tls_listener.listener import TLSListener


def test_register_tls_listener():
    registry = ListenerRegistry()
    manager = ListenerManager(registry)

    listener = TLSListener()

    manager.register(listener)

    assert manager.get("tls") is listener
    assert manager.list() == ["tls"]
    assert manager.is_running("tls") is False