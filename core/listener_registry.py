"""
Registry for SentryPack C2 listeners.
"""

from typing import Dict, List

from core.listener_base import IListener


class ListenerRegistry:
    """Registry of available C2 listener implementations."""

    def __init__(self) -> None:
        self._listeners: Dict[str, IListener] = {}

    def register(self, listener: IListener) -> None:
        """Register a listener implementation."""

        if not isinstance(listener, IListener):
            raise TypeError(
                "Listener must implement IListener"
            )

        listener_id = listener.listener_id

        if not listener_id:
            raise ValueError(
                "Listener ID cannot be empty"
            )

        if listener_id in self._listeners:
            raise ValueError(
                f"Listener already registered: {listener_id}"
            )

        self._listeners[listener_id] = listener

    def get(self, listener_id: str) -> IListener:
        """Return a registered listener by ID."""

        try:
            return self._listeners[listener_id]
        except KeyError:
            raise KeyError(
                f"Unknown listener: {listener_id}"
            ) from None

    def list(self) -> List[str]:
        """Return the IDs of all registered listeners."""

        return list(self._listeners.keys())

    def unregister(self, listener_id: str) -> None:
        """Remove a registered listener."""

        if listener_id not in self._listeners:
            raise KeyError(
                f"Unknown listener: {listener_id}"
            )

        del self._listeners[listener_id]