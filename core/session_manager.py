"""
Transport-agnostic session manager for C2 session lifecycle, event buffering, and WebSocket live broadcasting.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import logging
import time
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("sentrypack.session_manager")


@dataclass
class SessionState:
    session_key: str
    transport: str
    status: str = "active"
    buffer: List[dict] = field(default_factory=list)
    subscribers: Set[asyncio.Queue] = field(default_factory=set)


class SessionManager:
    """Manages C2 session event bus, subscriber queues, and event buffering."""

    def __init__(self) -> None:
        self.sessions: Dict[str, SessionState] = {}

    def register_session(self, session_key: str, transport: str) -> SessionState:
        """Register a new or existing session in the manager."""
        if session_key in self.sessions:
            state = self.sessions[session_key]
            state.transport = transport
            return state
        state = SessionState(session_key=session_key, transport=transport)
        self.sessions[session_key] = state
        return state

    def get_session(self, session_key: str) -> Optional[SessionState]:
        """Retrieve the SessionState for a given session_key."""
        return self.sessions.get(session_key)

    def all_sessions(self) -> List[SessionState]:
        """Return all active session states."""
        return list(self.sessions.values())

    async def emit_event(self, session_key: str, event: dict) -> None:
        """Buffer and broadcast an event to all subscribers of session_key."""
        state = self.sessions.get(session_key)
        if not state:
            return

        formatted_event = {
            "type": event.get("type", "event"),
            "session_key": event.get("session_key", session_key),
            "timestamp": event.get("timestamp", time.time()),
            "data": event.get("data", ""),
        }

        state.buffer.append(formatted_event)
        subscribers: Set[asyncio.Queue] = set(state.subscribers)
        for q in subscribers:
            await q.put(formatted_event)

    def emit_event_threadsafe(
        self,
        session_key: str,
        event: dict,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        """Thread-safe event emitter for transport background workers/threads."""
        if loop is None:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.get_event_loop()

        asyncio.run_coroutine_threadsafe(
            self.emit_event(session_key, event),
            loop,
        )

    def subscribe(
        self, session_key: str
    ) -> Tuple[Optional[asyncio.Queue], Optional[List[dict]]]:
        """Subscribe to session events. Returns (queue, snapshot_list) or (None, None)."""
        state = self.sessions.get(session_key)
        if not state:
            return None, None
        q: asyncio.Queue = asyncio.Queue()
        snapshot = list(state.buffer)
        state.subscribers.add(q)
        return q, snapshot

    def unsubscribe(self, session_key: str, queue: Optional[asyncio.Queue]) -> None:
        """Safely unsubscribe a queue from session broadcasts."""
        if not queue:
            return
        state = self.sessions.get(session_key)
        if state and queue in state.subscribers:
            state.subscribers.discard(queue)


session_manager = SessionManager()
