"""
Abstract Base Classes and Data Contracts for SentryPack Infrastructure Modules.

Infrastructure modules represent persistent, controllable background services
(e.g., HTTP/S proxy tunnels, port forwarders, DNS relays, CDN fronters) that support
and route penetration testing and C2 operations.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum
import logging
from typing import Any, Dict, List, Optional

from core.base_module import ModuleOption, OptionType

logger = logging.getLogger("sentrypack.infra_module_base")


# ---------------------------------------------------------------------------
# Infrastructure Module Status
# ---------------------------------------------------------------------------


class InfraModuleStatus(str, Enum):
    """Lifecycle status states for an infrastructure module."""

    ENABLED = "enabled"
    """Module is actively running and operational."""

    DISABLED = "disabled"
    """Module is stopped/inactive and consuming minimal resources."""

    ERROR = "error"
    """Module has encountered an unrecoverable runtime or initialization error."""

    STARTING = "starting"
    """Transient state: Module is in the process of starting up/connecting."""

    STOPPING = "stopping"
    """Transient state: Module is in the process of tearing down/disconnecting."""


# ---------------------------------------------------------------------------
# Infrastructure Module Metadata
# ---------------------------------------------------------------------------


@dataclass
class InfraModuleMeta:
    """
    Metadata declaration and capability descriptor for an infrastructure module.

    Attributes:
        id: Globally unique dot-separated identifier slug (e.g., 'infra.https_proxy').
        name: Human-readable display name (e.g., 'HTTP/S Proxy').
        version: Semantic version string (e.g., '0.1.0').
        description: High-level overview of what the infrastructure service does.
        author: Author or maintainer name/organization.
        category: Functional category classification (e.g., 'proxy', 'tunnel', 'relay', 'cdn').
        capabilities: List of protocol or feature capabilities (e.g., ['http', 'https', 'tls']).
        options: Ordered list of configurable options (List[ModuleOption]) that drives dynamic GUI form generation.
    """

    id: str
    """Globally unique dot-separated identifier slug (e.g., 'infra.https_proxy')."""

    name: str
    """Human-readable display name shown in GUI and CLI."""

    version: str
    """Semantic version string following semver (e.g., '0.1.0')."""

    description: str
    """Comprehensive description of the infrastructure service functionality."""

    author: str
    """Primary author, team, or maintainer handle."""

    category: str
    """Category classification: 'proxy', 'tunnel', 'relay', 'cdn', etc."""

    capabilities: List[str] = field(default_factory=list)
    """List of protocol or feature capabilities provided (e.g., ['http', 'https', 'tls'])."""

    options: List[ModuleOption] = field(default_factory=list)
    """Dynamic configuration schema driving PyQt6 GUI form rendering."""

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize metadata and option schemas into a Python dictionary.

        Returns:
            Dict[str, Any]: Dictionary containing all metadata fields and serialized options.
        """
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "category": self.category,
            "capabilities": list(self.capabilities),
            "options": [
                {
                    "name": opt.name,
                    "description": opt.description,
                    "type": opt.option_type.value if hasattr(opt.option_type, "value") else str(opt.option_type),
                    "required": opt.required,
                    "default": opt.default,
                    "choices": opt.choices,
                }
                for opt in self.options
            ],
        }


# ---------------------------------------------------------------------------
# Infrastructure Module Abstract Base Class
# ---------------------------------------------------------------------------


class IInfrastructureModule(abc.ABC):
    """
    Abstract Base Class for all SentryPack infrastructure modules.

    An infrastructure module provides controllable services with lifecycle hooks
    (enable, disable, configure, status, health_check) that operators can associate
    with specific projects or transports.

    Contract Rules:
        1. Every subclass MUST declare `meta` at class level as an instance of `InfraModuleMeta`.
        2. `enable()` must be idempotent: calling it while `ENABLED` is a no-op and returns True.
        3. `disable()` must never raise exceptions; swallow and log all errors internally.
        4. `configure()` must be callable BEFORE `enable()` to pre-load configuration parameters.
        5. `health_check()` must be safe to call at any time, in any lifecycle status.
        6. A module that crashes during `enable()` must set its own status to `ERROR` before
           propagating or swallowing the exception.
        7. `get_schema()` returns options in declaration order — the GUI renders fields in that exact order.
    """

    meta: InfraModuleMeta  # Must be set at class level by every subclass

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the infrastructure module with optional pre-loaded configuration.

        Parameters:
            config: Optional initial configuration dictionary.
        """
        self.config: Dict[str, Any] = config or {}

    # ── Core lifecycle (all abstract) ──────────────────────────────────────

    @abc.abstractmethod
    def enable(self) -> bool:
        """
        Activate the infrastructure service.

        Must be idempotent: calling enable() when already ENABLED is a no-op and returns True.
        If an unrecoverable failure occurs during startup, must set status to ERROR and return False.

        Returns:
            bool: True if successfully enabled and operational, False otherwise.
        """

    @abc.abstractmethod
    def disable(self) -> None:
        """
        Deactivate the infrastructure service cleanly and release all resources.

        Shuts down background threads, listeners, sockets, and associated processes.
        Must never raise exceptions; all errors must be caught and logged.
        """

    @abc.abstractmethod
    def status(self) -> InfraModuleStatus:
        """
        Query current lifecycle status of the infrastructure module.

        Returns:
            InfraModuleStatus: The current state (ENABLED, DISABLED, ERROR, STARTING, STOPPING).
        """

    @abc.abstractmethod
    def configure(self, config: Dict[str, Any]) -> bool:
        """
        Apply and validate runtime configuration for the module.

        Must be callable before enable() to pre-load configuration parameters.

        Parameters:
            config: Key-value configuration dictionary matching the module's option schema.

        Returns:
            bool: True if configuration is valid and accepted, False otherwise.
        """

    # ── Optional overrides (have defaults) ─────────────────────────────────

    def health_check(self) -> bool:
        """
        Perform a liveness/readiness probe of the service.

        Must be safe to call at any time and in any status state without throwing exceptions.

        Returns:
            bool: True if healthy, False if degraded or unresponsive. Default is True.
        """
        return True

    def get_schema(self) -> List[ModuleOption]:
        """
        Return the configuration option schema.

        Returns:
            List[ModuleOption]: List of configurable options in declaration order (default: meta.options).
        """
        return self.meta.options

    def describe(self) -> Dict[str, Any]:
        """
        Return complete metadata dictionary augmented with current lifecycle status.

        Returns:
            Dict[str, Any]: Metadata dictionary containing meta fields, serialized options, and status.
        """
        return {
            **self.meta.to_dict(),
            "status": self.status().value,
        }
