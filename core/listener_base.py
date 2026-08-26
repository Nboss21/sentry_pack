"""
Abstract base interface for SentryPack C2 listeners.
"""

from __future__ import annotations

import abc
from typing import Any, Callable, Optional


class IListener(abc.ABC):
    """
    Abstract interface for inbound C2 listeners.

    A listener is responsible for accepting inbound agent connections.
    It does not own session lifecycle or task handling.
    """

    @abc.abstractmethod
    def start(
        self,
        config: dict[str, Any],
        on_connection: Callable[[Any], None],
    ) -> bool:
        """
        Start listening for inbound connections.

        Args:
            config: Listener-specific configuration.
            on_connection: Callback invoked when a connection is accepted.

        Returns:
            True if the listener started successfully.
        """

    @abc.abstractmethod
    def stop(self) -> None:
        """Stop the listener and release its resources."""

    @abc.abstractmethod
    def is_running(self) -> bool:
        """Return True when the listener is currently running."""

    @property
    @abc.abstractmethod
    def listener_id(self) -> str:
        """Return the unique listener identifier."""