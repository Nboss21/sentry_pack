"""
Project-scoped C2 WebSocket channel hub.

Responsibilities:
  - Verify a session belongs to a given project before allowing subscription
  - Maintain per-project subscriber sets so events are scoped correctly
  - Provide authorize_subscription() for the WS handler to call on connect
  - Wrap event emission with project scope validation and buffer capping
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional, Set, Tuple

from api.db.models import C2Session, Project, Target

logger = logging.getLogger("sentrypack.c2_channel")


class C2Channel:
    """
    Per-project WebSocket broadcast hub.

    Usage in WS handler:
        ok, reason = await channel.authorize_subscription(project_id, session_key, token, db)
        if not ok:
            # reject the connection
            return
        queue, snapshot = channel.subscribe(project_id, session_key)
        ...drain queue...
        channel.unsubscribe(project_id, session_key, queue)
    """

    _MAX_BUFFER_SIZE = 500

    def __init__(self) -> None:
        # project_id -> session_key -> set of subscriber queues
        self._subscribers: Dict[int, Dict[str, Set[asyncio.Queue]]] = {}
        # project_id -> session_key -> event buffer (for late joiners, capped at 500)
        self._buffers: Dict[int, Dict[str, List[dict]]] = {}

    async def authorize_subscription(
        self,
        project_id: int,
        session_key: str,
        token: Optional[str],
        db,  # SQLAlchemy session
    ) -> Tuple[bool, str]:
        """
        Check that:
          1. The project exists in the DB
          2. The project has an auth token configured
          3. The token matches the project's auth_token
          4. The session exists and belongs to that project

        Returns (True, "") on success, (False, reason_string) on failure.
        """
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            return False, f"Project {project_id} not found"

        if not project.auth_token:
            return False, "project has no auth token configured"

        if not token or token != project.auth_token:
            return False, "invalid auth token"

        sess = db.query(C2Session).filter(C2Session.session_key == session_key).first()
        if not sess:
            return False, f"session '{session_key}' not found"

        if not sess.target_id:
            return False, "session not in project"

        target = db.query(Target).filter(Target.id == sess.target_id).first()
        if not target or target.project_id != project_id:
            return False, "session not in project"

        return True, ""

    def subscribe(
        self, project_id: int, session_key: str
    ) -> Tuple[asyncio.Queue, List[dict]]:
        """Register a new WS subscriber. Returns (queue, snapshot_of_buffer)."""
        queue: asyncio.Queue = asyncio.Queue()
        proj_subs = self._subscribers.setdefault(project_id, {})
        sess_subs = proj_subs.setdefault(session_key, set())
        sess_subs.add(queue)

        snapshot = list(self._buffers.get(project_id, {}).get(session_key, []))
        return queue, snapshot

    def unsubscribe(
        self, project_id: int, session_key: str, queue: Optional[asyncio.Queue]
    ) -> None:
        """Remove a WS subscriber queue."""
        if not queue:
            return
        proj_subs = self._subscribers.get(project_id)
        if proj_subs and session_key in proj_subs:
            proj_subs[session_key].discard(queue)

    async def emit(
        self, project_id: int, session_key: str, event: dict
    ) -> None:
        """
        Buffer the event and fan out to all subscribers for this project+session.
        """
        proj_bufs = self._buffers.setdefault(project_id, {})
        buf = proj_bufs.setdefault(session_key, [])
        buf.append(event)
        if len(buf) > self._MAX_BUFFER_SIZE:
            buf.pop(0)

        subscribers: Set[asyncio.Queue] = set(
            self._subscribers.get(project_id, {}).get(session_key, set())
        )
        for q in subscribers:
            await q.put(event)

    def subscriber_count(self, project_id: int, session_key: str) -> int:
        """Return number of active subscribers for a project+session. Useful for tests."""
        return len(self._subscribers.get(project_id, {}).get(session_key, set()))


c2_channel = C2Channel()  # module-level singleton
