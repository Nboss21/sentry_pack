"""
Abstract base interfaces and data contracts for all SentryPack C2 transport components.

This module defines the architectural contracts for C2 operations:
  1. Data contracts: Task, TaskResult, SessionStatus, AgentIdentity, AgentConfig
  2. ITransport: The abstract base class that every transport plugin must implement
  3. IAgentSession: The abstract base class representing an active agent session
  4. TransportMeta: Metadata and dynamic configuration schema declaration for transports
"""

from __future__ import annotations

import abc
from dataclasses import asdict, dataclass, field
from enum import Enum
import json
import time
from typing import Any, Dict, List, Optional, Union


class SessionStatus(str, Enum):
    """Lifecycle status states for an active agent session."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    TERMINATED = "terminated"


@dataclass
class Task:
    """
    Data contract representing a command/action to be executed by an agent.

    Attributes:
        id: Unique identifier for the task.
        payload: Command string, payload bytes, or structured instruction dictionary.
        timestamp: Epoch timestamp when the task was scheduled/created.
        metadata: Optional auxiliary parameters, flags, or execution tags.
    """
    id: Union[str, int]
    payload: Any
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Task:
        return cls(
            id=data.get("id", ""),
            payload=data.get("payload", ""),
            timestamp=data.get("timestamp", time.time()),
            metadata=data.get("metadata", {}),
        )


@dataclass
class TaskResult:
    """
    Data contract representing the result/output returned from an agent task.

    Attributes:
        task_id: Identifier of the task this result corresponds to.
        output: Execution stdout/stderr, return data, or status details.
        status: Execution status (e.g. 'completed', 'failed', 'queued', 'running').
        timestamp: Epoch timestamp when the result was received.
        error: Optional error description if execution failed.
    """
    task_id: Union[str, int]
    output: Any
    status: str = "completed"
    timestamp: float = field(default_factory=time.time)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "output": self.output,
            "status": self.status,
            "timestamp": self.timestamp,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TaskResult:
        return cls(
            task_id=data.get("task_id", ""),
            output=data.get("output", ""),
            status=data.get("status", "completed"),
            timestamp=data.get("timestamp", time.time()),
            error=data.get("error"),
        )


@dataclass
class AgentIdentity:
    """
    Typed identity section for an agent deployment.

    Attributes:
        agent_id: Unique identifier for the agent instance.
        name: Human-friendly display name or alias.
        project_id: Associated project database ID.
        hostname: Optional hostname/IP where the agent is running.
        platform: Operating system / architecture identifier.
        tags: List of descriptive tags or labels.
    """
    agent_id: str
    name: str = ""
    project_id: Optional[int] = None
    hostname: Optional[str] = None
    platform: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AgentIdentity:
        return cls(
            agent_id=data.get("agent_id", ""),
            name=data.get("name", ""),
            project_id=data.get("project_id"),
            hostname=data.get("hostname"),
            platform=data.get("platform"),
            tags=data.get("tags", []),
        )


@dataclass
class AgentConfig:
    """
    Generic configuration structure for an agent deployment.

    CRITICAL ARCHITECTURAL GUARANTEE:
    An agent deployment consists of two logical parts:
      1. A typed identity section (`identity`).
      2. An opaque transport-specific configuration dictionary (`transport_config`).

    The core application (SessionManager, REST API routes, Database layers)
    stores and passes `transport_config` around strictly as raw, uninspected data.
    Core code MUST NEVER inspect, validate, or make assumptions about the contents
    of `transport_config`. When a session is initiated, this blob is handed directly
    to `transport.connect(config)` and only the selected concrete `ITransport`
    implementation parses and consumes it.

    This ensures that new transport mechanisms (TLS, HTTP, DNS, ICMP, etc.)
    can be introduced with completely arbitrary parameter requirements without
    requiring modifications to the core architecture.
    """
    identity: AgentIdentity
    transport_type: str
    transport_config: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        # Always store a shallow copy of transport_config so that the caller's
        # original dict cannot be mutated by anything downstream, and so that
        # identity checks (is not) behave as expected in tests and introspection.
        object.__setattr__(self, "transport_config", dict(self.transport_config))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize configuration into a Python dictionary."""
        return {
            "identity": self.identity.to_dict(),
            "transport_type": self.transport_type,
            "transport_config": dict(self.transport_config),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AgentConfig:
        """Construct an AgentConfig from a dictionary."""
        raw_identity = data.get("identity", {})
        if isinstance(raw_identity, AgentIdentity):
            identity = raw_identity
        elif isinstance(raw_identity, dict):
            identity = AgentIdentity.from_dict(raw_identity)
        else:
            identity = AgentIdentity(agent_id=str(raw_identity))

        return cls(
            identity=identity,
            transport_type=data.get("transport_type", "tcp"),
            transport_config=data.get("transport_config", {}),
            created_at=data.get("created_at", time.time()),
        )

    def to_json(self) -> str:
        """Serialize configuration into a JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> AgentConfig:
        """Construct an AgentConfig from a JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class TransportMeta:
    """
    Metadata declaration and option schema for a transport plugin.

    Attributes:
        id: Machine-readable unique transport ID (e.g. "tcp", "tls", "http", "dns").
        name: Human-readable transport name (e.g. "TLS Encrypted Transport").
        version: Semantic version string.
        description: High-level overview of the transport mechanism.
        author: Author or organization name.
        options: List of ModuleOption objects specifying the configurable options schema.
    """
    id: str
    name: str
    version: str
    description: str
    author: str = "unknown"
    options: list = field(default_factory=list)


class ITransport(abc.ABC):
    """
    Abstract Base Class for all C2 transport plugins.

    The ITransport contract decouples the SessionManager from network/channel
    protocols. Every concrete transport plugin (e.g. TLS, TCP, HTTP, DNS) must
    inherit from ITransport and implement all abstract methods.
    """
    meta: TransportMeta  # must be set at class level by every subclass

    @abc.abstractmethod
    def connect(self, host_or_config: Any, port: Optional[int] = None, options: Optional[dict] = None, **kwargs) -> bool:
        """
        Establish the transport connection.

        Guarantees:
            - Must accept transport configuration either as positional parameters (host, port, options)
              or as a single configuration dictionary/AgentConfig object.
            - Must return True on successful connection/handshake, False otherwise.
            - Must be safe to call again (cleaning up previous resources if already open).
        """

    @abc.abstractmethod
    def send(self, data: Union[bytes, str, Task, Any]) -> int:
        """
        Send a task or raw data over the transport channel.

        Guarantees:
            - Must be non-blocking or respect configured timeouts.
            - Returns the number of bytes sent or positive integer indicator on success, 0 on failure.
        """

    @abc.abstractmethod
    def receive(self, size: int = 4096) -> Union[bytes, str, TaskResult, Optional[Any]]:
        """
        Receive incoming data or task results from the agent.

        Guarantees:
            - Must return raw bytes, decoded message, or TaskResult object if data is available.
            - Must return empty bytes (b"") or None if no result is ready or on EOF.
            - Must handle timeouts gracefully without raising unhandled socket exceptions.
        """

    @abc.abstractmethod
    def disconnect(self) -> None:
        """
        Tear down the connection cleanly and release all underlying network resources.
        """

    def is_alive(self) -> bool:
        """
        Check if the transport channel is active and connected.

        Default implementation returns True if not overridden.
        """
        return True


class IAgentSession(abc.ABC):
    """
    Abstract Base Class representing an active C2 session from the outside.

    The SessionManager coordinates a collection of IAgentSession instances.
    """

    @property
    @abc.abstractmethod
    def session_key(self) -> str:
        """Unique session key identifying this active session."""

    @property
    @abc.abstractmethod
    def identity(self) -> AgentIdentity:
        """The identity of the connected agent."""

    @property
    @abc.abstractmethod
    def transport(self) -> ITransport:
        """The underlying ITransport implementation handling communication."""

    @property
    @abc.abstractmethod
    def status(self) -> SessionStatus:
        """Current lifecycle status of the session."""

    @property
    @abc.abstractmethod
    def last_seen(self) -> float:
        """Epoch timestamp of the most recent interaction or heartbeat."""

    @property
    @abc.abstractmethod
    def metadata(self) -> Dict[str, Any]:
        """Additional session metadata and state."""

    @abc.abstractmethod
    def send_task(self, task: Task) -> bool:
        """
        Send a task through the session's transport. Returns True on success.
        """

    @abc.abstractmethod
    def get_next_result(self) -> Optional[TaskResult]:
        """
        Retrieve the next available task result from the transport, or None if none ready.
        """

    @abc.abstractmethod
    def is_active(self) -> bool:
        """
        Return True if the session is currently active and healthy.
        """

    @abc.abstractmethod
    def close(self) -> None:
        """
        Cleanly terminate the session and disconnect the underlying transport.
        """
