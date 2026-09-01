"""
HTTP/S Proxy Infrastructure Module for SentryPack.

Provides a controllable, persistent infrastructure service wrapping the
HttpsProxyTransport to establish managed CONNECT tunnels across forward proxies.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from core.infra_module_base import IInfrastructureModule, InfraModuleMeta, InfraModuleStatus
from modules.transports.https_proxy.transport import HttpsProxyTransport

logger = logging.getLogger("sentrypack.infra.https_proxy")


class HttpsProxyInfraModule(IInfrastructureModule):
    """
    Concrete infrastructure module wrapping the HTTP/S Proxy transport.

    Allows operators to configure, enable, disable, and monitor an HTTP/S
    CONNECT proxy tunnel as a managed background infrastructure service.
    """

    meta = InfraModuleMeta(
        id="infra.https_proxy",
        name="HTTP/S Proxy Infrastructure Module",
        version="0.1.0",
        description="Manages the HTTP/S proxy transport as a controllable infra service.",
        author="Burka Zelalem",
        category="proxy",
        capabilities=["http", "https", "tls", "connect_tunnel"],
    )

    def __init__(self) -> None:
        """Initialize the HTTP/S Proxy infrastructure module in a disabled state."""
        self._transport: Optional[HttpsProxyTransport] = None
        self._config: Dict[str, Any] = {}
        self._status: InfraModuleStatus = InfraModuleStatus.DISABLED

    def configure(self, config: Dict[str, Any]) -> bool:
        """
        Validate and store runtime configuration for the proxy tunnel.

        Parameters:
            config: Configuration dictionary containing proxy and target connection keys.

        Returns:
            bool: True if configuration dictionary is valid, False otherwise.
        """
        if not isinstance(config, dict):
            logger.warning("Invalid configuration payload for HttpsProxyInfraModule: expected dict")
            return False

        self._config = dict(config)
        logger.info("HttpsProxyInfraModule configured with keys: %s", list(self._config.keys()))
        return True

    def enable(self) -> bool:
        """
        Activate the infrastructure service and establish the underlying proxy tunnel.

        Returns:
            bool: True if proxy connection and handshake succeeded, False otherwise.
        """
        logger.info("Activating HttpsProxyInfraModule")
        try:
            # Clean up any existing connection before initiating a new one
            if self._transport is not None:
                try:
                    self._transport.disconnect()
                except Exception:
                    pass
                self._transport = None

            transport = HttpsProxyTransport()
            connected = transport.connect(self._config)
            if connected:
                self._transport = transport
                self._status = InfraModuleStatus.ENABLED
                logger.info("HttpsProxyInfraModule successfully enabled")
                return True
            else:
                self._transport = None
                self._status = InfraModuleStatus.ERROR
                logger.warning("HttpsProxyInfraModule failed to establish connection")
                return False
        except Exception as exc:
            logger.warning("Exception during HttpsProxyInfraModule enable(): %s", exc)
            self._transport = None
            self._status = InfraModuleStatus.ERROR
            return False

    def disable(self) -> None:
        """
        Deactivate the proxy infrastructure service and tear down the network tunnel.
        """
        logger.info("Deactivating HttpsProxyInfraModule")
        try:
            if self._transport is not None:
                self._transport.disconnect()
                self._transport = None
            self._status = InfraModuleStatus.DISABLED
            logger.info("HttpsProxyInfraModule successfully disabled")
        except Exception as exc:
            logger.warning("Exception during HttpsProxyInfraModule disable(): %s", exc)
            self._status = InfraModuleStatus.ERROR

    def status(self) -> InfraModuleStatus:
        """
        Query the active lifecycle status, validating liveness if currently enabled.

        Returns:
            InfraModuleStatus: Current status (ENABLED, DISABLED, or ERROR).
        """
        if self._status == InfraModuleStatus.ENABLED:
            if self._transport is None or not self._transport.is_alive():
                logger.warning("HttpsProxyInfraModule marked ENABLED but underlying transport is not alive")
                self._status = InfraModuleStatus.ERROR
        return self._status

    def health_check(self) -> bool:
        """
        Perform a liveness probe on the underlying transport tunnel.

        Returns:
            bool: True if transport exists and socket is alive, False otherwise.
        """
        return bool(self._transport is not None and self._transport.is_alive())
