from typing import Any, Callable

from core.listener_base import IListener
from core.listener_registry import ListenerRegistry


class ListenerManager:
    """Coordinates the lifecycle of registered C2 listeners."""

    def __init__(self, registry: ListenerRegistry) -> None:
        self._registry = registry
    def register(self, listener: IListener) -> None:
        self._registry.register(listener)

    def get(self, listener_id: str) -> IListener:
        return self._registry.get(listener_id)

    def list(self) -> list[str]:
        return self._registry.list()

    def start(
        self,
        listener_id: str,
        config: dict[str, Any],
        on_connection: Callable[[Any], None],
    ) -> bool:
        listener = self.get(listener_id)
        return listener.start(config, on_connection)

    def stop(self, listener_id: str) -> None:
        listener = self.get(listener_id)
        listener.stop()

    def is_running(self, listener_id: str) -> bool:
        listener = self.get(listener_id)
        return listener.is_running()
#listener_manager = ListenerManager()
from core.listener_registry import listener_registry

listener_manager = ListenerManager(listener_registry)