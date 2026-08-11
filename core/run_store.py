"""
In-memory run registry — maps ``run_id`` → ``asyncio.Queue``.

Usage
-----
The API route registers a new run::

    from core.run_store import run_store

    run_store.register(run_id, queue)

The WebSocket handler looks up the queue::

    queue = run_store.get(run_id)
    if queue is None:
        await websocket.close(code=4404, reason="run not found")
        return
    while (event := await queue.get()) is not None:
        await websocket.send_json(event)

The run is cleaned up automatically when the sentinel is consumed::

    run_store.release(run_id)

Thread-safety
-------------
Queue lookup and registration happen on the asyncio event-loop thread only
(FastAPI routes and WebSocket handlers are both async), so no additional
locking is required.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, Optional

logger = logging.getLogger("sentrypack.run_store")


class RunStore:
    """Singleton registry mapping active run IDs to their event queues."""

    def __init__(self) -> None:
        self._runs: Dict[str, asyncio.Queue] = {}

    def register(self, run_id: str, queue: asyncio.Queue) -> None:
        """Register a new run's queue under *run_id*.

        If a queue is already registered for *run_id* it is silently replaced.

        Args:
            run_id: Unique run identifier (UUID string).
            queue:  The :class:`asyncio.Queue` created by the runner.
        """
        self._runs[run_id] = queue
        logger.debug("Registered run '%s' in RunStore.", run_id)

    def get(self, run_id: str) -> Optional[asyncio.Queue]:
        """Return the queue for *run_id*, or ``None`` if not found.

        Args:
            run_id: Unique run identifier.

        Returns:
            The :class:`asyncio.Queue` or ``None``.
        """
        return self._runs.get(run_id)

    def release(self, run_id: str) -> None:
        """Remove *run_id* from the store once its run has finished.

        Safe to call even if *run_id* is not present (no-op).

        Args:
            run_id: Unique run identifier to remove.
        """
        removed = self._runs.pop(run_id, None)
        if removed is not None:
            logger.debug("Released run '%s' from RunStore.", run_id)

    def active_run_ids(self) -> list[str]:
        """Return a list of all currently registered run IDs."""
        return list(self._runs.keys())

    def __len__(self) -> int:
        return len(self._runs)


#: Module-level singleton shared across the whole application.
run_store: RunStore = RunStore()
