"""
Test listener implementation for the C2 listener abstraction.
"""

from typing import Any, Callable, Optional

from core.listener_base import IListener


class TestListener(IListener):
    """In-memory listener used to test listener lifecycle and callbacks."""

    def __init__(self) -> None:
        self._running = False
        self._on_connection: Optional[Callable[[Any], None]] = None

    @property
    def listener_id(self) -> str:
        return "test"

    def start(
        self,
        config: dict[str, Any],
        on_connection: Callable[[Any], None],
    ) -> bool:
        """Start the test listener."""

        del config

        self._on_connection = on_connection
        self._running = True

        return True

    def stop(self) -> None:
        """Stop the test listener."""

        self._running = False
        self._on_connection = None

    def is_running(self) -> bool:
        """Return whether the listener is running."""

        return self._running

    def simulate_connection(self, connection: Any) -> None:
        """
        Simulate an inbound connection.

        This is only for testing the listener callback pipeline.
        """

        if not self._running:
            raise RuntimeError("Listener is not running")

        if self._on_connection is None:
            raise RuntimeError("Connection callback is not configured")

        self._on_connection(connection)