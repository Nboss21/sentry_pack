"""
Transport-agnostic session manager for C2 session lifecycle, event buffering,
audit logging to session_events, and live broadcasting.

Guarantees:
  1. Complete transport agnosticism: Zero protocol-specific logic or leaks.
  2. Non-negotiable audit logging: Every lifecycle action (start, send task,
     receive result, terminate) writes an audit event record.
  3. Coordinates sessions strictly through ITransport and IAgentSession interfaces.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from core.transport_base import (
    AgentConfig,
    AgentIdentity,
    IAgentSession,
    ITransport,
    SessionStatus,
    Task,
    TaskResult,
)

logger = logging.getLogger("sentrypack.session_manager")


@dataclass
class SessionState:
    """Legacy compatibility state for lightweight session tracking."""
    session_key: str
    transport: str
    status: str = "active"
    buffer: List[dict] = field(default_factory=list)
    subscribers: Set[asyncio.Queue] = field(default_factory=set)


class ConcreteAgentSession(IAgentSession):
    """Concrete implementation of IAgentSession wrapping an active transport."""

    def __init__(
        self,
        session_key: str,
        identity: AgentIdentity,
        transport: ITransport,
        status: SessionStatus = SessionStatus.ACTIVE,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._session_key = session_key
        self._identity = identity
        self._transport = transport
        self._status = status
        self._last_seen = time.time()
        self._metadata = metadata or {}
        self.buffer: List[dict] = []
        self.subscribers: Set[asyncio.Queue] = set()

    @property
    def session_key(self) -> str:
        return self._session_key

    @property
    def identity(self) -> AgentIdentity:
        return self._identity

    @property
    def transport(self) -> ITransport:
        return self._transport

    @property
    def status(self) -> SessionStatus:
        return self._status

    @status.setter
    def status(self, val: SessionStatus) -> None:
        self._status = val

    @property
    def last_seen(self) -> float:
        return self._last_seen

    @last_seen.setter
    def last_seen(self, val: float) -> None:
        self._last_seen = val

    @property
    def metadata(self) -> Dict[str, Any]:
        return self._metadata

    def send_task(self, task: Task) -> bool:
        """Send a task through the transport."""
        sent = self._transport.send(task)
        self._last_seen = time.time()
        return bool(sent)

    def get_next_result(self) -> Optional[TaskResult]:
        """Poll the transport for available task results."""
        res = self._transport.receive()
        if res:
            self._last_seen = time.time()
            if isinstance(res, TaskResult):
                return res
            elif isinstance(res, dict):
                return TaskResult.from_dict(res)
            elif isinstance(res, (bytes, str)):
                return TaskResult(
                    task_id="auto",
                    output=res,
                    status="completed",
                    timestamp=time.time(),
                )
        return None

    def is_active(self) -> bool:
        """Check if session and transport are alive."""
        return self._status == SessionStatus.ACTIVE and self._transport.is_alive()

    def close(self) -> None:
        """Tear down transport and update session status."""
        self._status = SessionStatus.TERMINATED
        try:
            self._transport.disconnect()
        except Exception as exc:
            logger.debug("Error during transport disconnect on session close: %s", exc)


class SessionManager:
    """
    Central coordinator of all C2 session activity.

    Manages session lifecycle, task dispatching, result retrieval,
    audit event persistence, and WebSocket live broadcasting.
    """

    def __init__(self) -> None:
        self.sessions: Dict[str, Union[ConcreteAgentSession, SessionState]] = {}
        self.audit_log: List[Dict[str, Any]] = []

    # -----------------------------------------------------------------------
    # Core Session Lifecycle Coordination
    # -----------------------------------------------------------------------

    def start_session(
        self,
        identity_or_config: Union[AgentIdentity, AgentConfig, str],
        transport: ITransport,
        config: Optional[Dict[str, Any]] = None,
    ) -> IAgentSession:
        """
        Start an active C2 session using the provided transport and agent identity.

        Calls transport.connect() and creates an active IAgentSession.
        Records a 'session_start' audit log event.
        """
        if isinstance(identity_or_config, AgentConfig):
            identity = identity_or_config.identity
            connect_cfg = config or identity_or_config.transport_config
        elif isinstance(identity_or_config, AgentIdentity):
            identity = identity_or_config
            connect_cfg = config or {}
        else:
            identity = AgentIdentity(agent_id=str(identity_or_config))
            connect_cfg = config or {}

        session_key = identity.agent_id

        # Connect the underlying transport
        is_connected = transport.connect(connect_cfg)
        status = SessionStatus.ACTIVE if is_connected else SessionStatus.ERROR

        session = ConcreteAgentSession(
            session_key=session_key,
            identity=identity,
            transport=transport,
            status=status,
        )
        self.sessions[session_key] = session

        # Mandatory audit logging
        self._record_audit(
            session_key=session_key,
            event_type="session_start",
            data={
                "agent_id": identity.agent_id,
                "name": identity.name,
                "status": status.value,
                "connected": is_connected,
            },
        )

        return session

    def send_task(
        self,
        session_key: str,
        task: Union[Task, str, Dict[str, Any]],
    ) -> Task:
        """
        Route and send a task through an active session's transport.
        Records a 'task_sent' audit log event.
        """
        session = self.sessions.get(session_key)
        if not session:
            raise KeyError(f"Session '{session_key}' not found")

        if isinstance(task, Task):
            task_obj = task
        elif isinstance(task, dict):
            task_obj = Task.from_dict(task)
        else:
            task_obj = Task(id=f"task-{int(time.time()*1000)}", payload=str(task))

        if isinstance(session, ConcreteAgentSession):
            session.send_task(task_obj)
        else:
            # Fallback for mock/generic states
            pass

        self._record_audit(
            session_key=session_key,
            event_type="task_sent",
            data={
                "task_id": task_obj.id,
                "payload": task_obj.payload,
            },
        )

        return task_obj

    def receive_result(
        self,
        session_key: str,
        size: int = 4096,
    ) -> Optional[TaskResult]:
        """
        Collect incoming task execution results from the session's transport.
        Records a 'result_received' audit log event if a result is returned.
        """
        session = self.sessions.get(session_key)
        if not session:
            return None

        result: Optional[TaskResult] = None
        if isinstance(session, ConcreteAgentSession):
            result = session.get_next_result()

        if result:
            self._record_audit(
                session_key=session_key,
                event_type="result_received",
                data={
                    "task_id": result.task_id,
                    "status": result.status,
                    "output": result.output,
                },
            )

        return result

    def end_session(self, session_key: str) -> None:
        """
        Cleanly terminate an active session and release its transport.
        Records a 'session_end' audit log event.
        """
        session = self.sessions.get(session_key)
        if session:
            if isinstance(session, ConcreteAgentSession):
                session.close()
            else:
                session.status = "terminated"

            self._record_audit(
                session_key=session_key,
                event_type="session_end",
                data={"status": "terminated"},
            )

    # -----------------------------------------------------------------------
    # Audit Logging Subsystem
    # -----------------------------------------------------------------------

    def _record_audit(self, session_key: str, event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Persist an audit log event into memory, database, and event stream."""
        event = {
            "session_key": session_key,
            "event_type": event_type,
            "data": data,
            "timestamp": time.time(),
        }
        self.audit_log.append(event)

        # Attempt to persist to database if available
        try:
            from api.db.models import SessionEvent
            from api.db.session import SessionLocal
            db = SessionLocal()
            try:
                db_event = SessionEvent(
                    session_key=session_key,
                    event_type=event_type,
                    data=data,
                    timestamp=datetime.now(timezone.utc),
                )
                db.add(db_event)
                db.commit()
            except Exception:
                db.rollback()
            finally:
                db.close()
        except Exception:
            # Standalone or unit-test environments without active DB
            pass

        # Broadcast event through pub-sub bus
        self.emit_event_threadsafe(
            session_key,
            {"type": event_type, "data": data, "session_key": session_key},
        )

        return event

    def get_audit_log(self, session_key: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve audit log entries, optionally filtered by session key."""
        if session_key is None:
            return list(self.audit_log)
        return [entry for entry in self.audit_log if entry.get("session_key") == session_key]

    # -----------------------------------------------------------------------
    # Backwards-Compatible Pub-Sub & Subscriber Management
    # -----------------------------------------------------------------------

    def register_session(self, session_key: str, transport: str) -> Union[ConcreteAgentSession, SessionState]:
        """Register a session key in the manager."""
        if session_key in self.sessions:
            state = self.sessions[session_key]
            if isinstance(state, SessionState):
                state.transport = transport
            return state
        state = SessionState(session_key=session_key, transport=transport)
        self.sessions[session_key] = state
        return state

    def get_session(self, session_key: str) -> Optional[Union[ConcreteAgentSession, SessionState]]:
        """Retrieve the active session object for a given session key."""
        return self.sessions.get(session_key)

    def all_sessions(self) -> List[Union[ConcreteAgentSession, SessionState]]:
        """Return all managed session instances."""
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
        """Thread-safe event emitter for transport workers/threads."""
        if loop is None:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    return

        try:
            asyncio.run_coroutine_threadsafe(
                self.emit_event(session_key, event),
                loop,
            )
        except Exception:
            pass

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
