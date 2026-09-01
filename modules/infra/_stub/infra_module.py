"""
Minimal reference stub infrastructure module for SentryPack.

Validates the IInfrastructureModule interface contract and provides a working
template for Phase 6 infrastructure module implementers (proxies, tunnels, relays, CDN fronters).
"""

from __future__ import annotations

import logging
from pathlib import Path
import sys
from typing import Any, Dict, Optional

# Ensure project root is in sys.path when executed directly as a standalone script
_project_root = str(Path(__file__).resolve().parent.parent.parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from core.base_module import ModuleOption, OptionType
from core.infra_module_base import (
    IInfrastructureModule,
    InfraModuleMeta,
    InfraModuleStatus,
)

logger = logging.getLogger("sentrypack.infra.stub")


class StubInfraModule(IInfrastructureModule):
    """
    Minimal reference stub infrastructure module.

    Validates the IInfrastructureModule interface contract and provides
    a concrete reference implementation demonstrating option declaration,
    configuration validation, and lifecycle management.
    """

    meta = InfraModuleMeta(
        id="infra.stub",
        name="Stub Infrastructure Module",
        version="0.1.0",
        description="Minimal reference stub — validates the IInfrastructureModule interface.",
        author="Burka Zelalem",
        category="proxy",
        capabilities=["stub"],
        options=[
            ModuleOption(
                name="HOST",
                description="Target hostname or IP",
                option_type=OptionType.STRING,
                required=True,
                default="127.0.0.1",
            ),
            ModuleOption(
                name="PORT",
                description="Target port",
                option_type=OptionType.INTEGER,
                required=True,
                default=8080,
            ),
            ModuleOption(
                name="USE_TLS",
                description="Wrap connection in TLS",
                option_type=OptionType.BOOLEAN,
                required=False,
                default=False,
            ),
            ModuleOption(
                name="MODE",
                description="Proxy operation mode",
                option_type=OptionType.ENUM,
                required=False,
                default="forward",
                choices=["forward", "reverse", "transparent"],
            ),
        ],
    )

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the stub module with disabled status and optional configuration.

        Parameters:
            config: Optional initial configuration dictionary.
        """
        super().__init__(config)
        self._status: InfraModuleStatus = InfraModuleStatus.DISABLED

    def enable(self) -> bool:
        """
        Activate the stub infrastructure service.

        Idempotent: calling enable() while ENABLED is a no-op and returns True.

        Returns:
            bool: True on successful activation.
        """
        if self._status == InfraModuleStatus.ENABLED:
            return True  # idempotent
        self._status = InfraModuleStatus.ENABLED
        return True

    def disable(self) -> None:
        """
        Deactivate the stub module cleanly.

        Must not raise exceptions.
        """
        self._status = InfraModuleStatus.DISABLED

    def status(self) -> InfraModuleStatus:
        """
        Return the current lifecycle status of the stub module.

        Returns:
            InfraModuleStatus: Current status (e.g. ENABLED or DISABLED).
        """
        return self._status

    def configure(self, config: Dict[str, Any]) -> bool:
        """
        Validate and apply runtime configuration.

        Ensures required 'HOST' and 'PORT' keys are provided.

        Parameters:
            config: Key-value configuration dictionary.

        Returns:
            bool: True if configuration contains required keys, False otherwise.
        """
        required = {"HOST", "PORT"}
        if not required.issubset(config.keys()):
            return False
        self.config.update(config)
        return True


if __name__ == "__main__":
    stub = StubInfraModule()
    stub.configure({"HOST": "10.0.0.1", "PORT": 3128})
    stub.enable()
    print(stub.describe())
    # Also prove the GUI can read its schema:
    schema = stub.get_schema()
    assert len(schema) == 4
    print("Schema OK — ConfigFormGenerator can render", len(schema), "fields")
