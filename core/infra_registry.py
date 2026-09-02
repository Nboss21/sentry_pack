"""
Infrastructure Module Registry for SentryPack.

Provides dynamic scanning, validation, lifecycle orchestration, and project/transport
association management for infrastructure modules with strict fault-tolerance guarantees.
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type

from core.infra_module_base import IInfrastructureModule, InfraModuleMeta, InfraModuleStatus

logger = logging.getLogger("sentrypack.infra_registry")


class InfrastructureModuleRegistry:
    """
    Registry for scanning, validating, managing, and orchestrating infrastructure modules.

    Resilience Guarantees:
        - scan() never raises an exception regardless of malformed modules or directories.
        - Broken modules are logged with warnings and skipped without crashing the system.
        - Every public method returns safe fallback values (None, False, [], {}) on error.
    """

    def __init__(self) -> None:
        """Initialize an empty infrastructure module registry."""
        self._modules: Dict[str, Type[IInfrastructureModule]] = {}
        self._statuses: Dict[str, InfraModuleStatus] = {}
        self._configs: Dict[str, Dict[str, Any]] = {}
        self._associations: Dict[str, List[Dict[str, Any]]] = {}
        self._instances: Dict[str, IInfrastructureModule] = {}

    def scan(self, infra_dir: Path) -> None:
        """
        Scan a directory tree for infrastructure module plugins in immediate subdirectories.

        Each subdirectory containing an `infra_module.py` file is treated as a candidate plugin.
        All exceptions are caught and logged so the application never fails to start.

        Parameters:
            infra_dir: Path to the root directory containing infrastructure module subdirectories.
        """
        try:
            i_dir = Path(infra_dir)
            if not i_dir.exists() or not i_dir.is_dir():
                logger.info("Infrastructure modules directory %s does not exist or is not a directory", i_dir)
                return

            for plugin_dir in sorted(i_dir.iterdir()):
                if not plugin_dir.is_dir() or plugin_dir.name.startswith((".", "_")):
                    continue
                try:
                    module_cls = self.load_module(plugin_dir)
                    if module_cls is not None:
                        m_id = module_cls.meta.id
                        if m_id in self._modules:
                            logger.warning(
                                "Duplicate infrastructure module ID '%s' found in %s. Keeping previously registered module.",
                                m_id,
                                plugin_dir,
                            )
                        else:
                            self._modules[m_id] = module_cls
                            self._statuses[m_id] = InfraModuleStatus.DISABLED
                            self._configs.setdefault(m_id, {})
                            self._associations.setdefault(m_id, [])
                            logger.info("Loaded infrastructure module '%s' from %s", m_id, plugin_dir)
                except Exception as exc:
                    logger.warning("Failed to load infrastructure module from %s: %s", plugin_dir, exc)
        except Exception as exc:
            logger.warning("Unexpected error scanning infrastructure directory %s: %s", infra_dir, exc)

    def scan_many(self, infra_dirs: List[Path]) -> None:
        """
        Scan multiple infrastructure module directories sequentially.

        Parameters:
            infra_dirs: List of directory paths to scan.
        """
        for d in infra_dirs:
            self.scan(Path(d))

    def load_module(self, plugin_dir: Path) -> Optional[Type[IInfrastructureModule]]:
        """
        Dynamically import and validate an IInfrastructureModule subclass from plugin_dir/infra_module.py.

        Parameters:
            plugin_dir: Directory containing the plugin's infra_module.py file.

        Returns:
            Type[IInfrastructureModule] if a valid module is found, None otherwise.
        """
        try:
            p_dir = Path(plugin_dir)
            if not p_dir.is_dir():
                logger.warning("%s is not a directory", p_dir)
                return None

            module_file = p_dir / "infra_module.py"
            if not module_file.exists():
                logger.debug("infra_module.py not found in %s", p_dir)
                return None

            spec = importlib.util.spec_from_file_location(
                f"infra_modules.{p_dir.name}.infra_module", module_file
            )
            if spec is None or spec.loader is None:
                logger.warning("Could not create import spec for %s", module_file)
                return None

            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            # Inspect imported module for valid IInfrastructureModule classes
            candidates: List[Type[IInfrastructureModule]] = []
            for name in dir(mod):
                obj = getattr(mod, name)
                is_valid, _ = self._validate_module(obj)
                if is_valid:
                    candidates.append(obj)

            if not candidates:
                logger.warning("No valid IInfrastructureModule subclass found in %s", module_file)
                return None

            return candidates[0]

        except Exception as exc:
            logger.warning("Error dynamically loading infrastructure module from %s: %s", plugin_dir, exc)
            return None

    def _validate_module(self, cls: Any) -> Tuple[bool, str]:
        """
        Validate that cls is a concrete IInfrastructureModule subclass with valid InfraModuleMeta.

        Parameters:
            cls: Object to inspect.

        Returns:
            Tuple[bool, str]: (True, "") if valid, (False, reason) otherwise.
        """
        if not isinstance(cls, type):
            return False, "Object is not a class"

        try:
            if not issubclass(cls, IInfrastructureModule) or cls is IInfrastructureModule:
                return False, "Class does not subclass IInfrastructureModule"
        except TypeError:
            return False, "Object is not a valid class type"

        if not hasattr(cls, "meta"):
            return False, "Class is missing 'meta' attribute"

        meta = getattr(cls, "meta")
        if not isinstance(meta, InfraModuleMeta):
            return False, f"'meta' attribute is not of type InfraModuleMeta (got {type(meta).__name__})"

        if not getattr(meta, "id", None) or not isinstance(meta.id, str):
            return False, "InfraModuleMeta 'id' must be a non-empty string"

        if inspect.isabstract(cls) or getattr(cls, "__abstractmethods__", None):
            return False, f"Class has unimplemented abstract methods: {getattr(cls, '__abstractmethods__', set())}"

        for method_name in ("enable", "disable", "status", "configure"):
            if not callable(getattr(cls, method_name, None)):
                return False, f"Class is missing required callable method '{method_name}'"

        return True, ""

    def _get_or_create_instance(self, module_id: str) -> Optional[IInfrastructureModule]:
        """Retrieve existing module instance or instantiate a new one."""
        if module_id not in self._modules:
            return None

        if module_id not in self._instances:
            try:
                cls = self._modules[module_id]
                inst = cls()
                # Apply stored config if available
                if module_id in self._configs and self._configs[module_id]:
                    inst.configure(self._configs[module_id])
                self._instances[module_id] = inst
            except Exception as exc:
                logger.warning("Failed to instantiate infrastructure module '%s': %s", module_id, exc)
                self._statuses[module_id] = InfraModuleStatus.ERROR
                return None

        return self._instances.get(module_id)

    def enable_module(self, module_id: str) -> bool:
        """
        Activate an infrastructure module by calling its enable() method.

        Parameters:
            module_id: Identifier of the module to enable.

        Returns:
            bool: True on successful activation, False on failure or error.
        """
        if module_id not in self._modules:
            logger.warning("Cannot enable unregistered module '%s'", module_id)
            return False

        try:
            inst = self._get_or_create_instance(module_id)
            if inst is None:
                self._statuses[module_id] = InfraModuleStatus.ERROR
                return False

            if module_id in self._configs and self._configs[module_id]:
                inst.configure(self._configs[module_id])

            success = inst.enable()
            if success:
                self._statuses[module_id] = InfraModuleStatus.ENABLED
                logger.info("Infrastructure module '%s' enabled successfully", module_id)
                return True
            else:
                self._statuses[module_id] = InfraModuleStatus.ERROR
                logger.warning("Infrastructure module '%s' enable() returned False", module_id)
                return False
        except Exception as exc:
            logger.warning("Exception while enabling infrastructure module '%s': %s", module_id, exc)
            self._statuses[module_id] = InfraModuleStatus.ERROR
            return False

    def disable_module(self, module_id: str) -> None:
        """
        Deactivate an infrastructure module cleanly.

        Parameters:
            module_id: Identifier of the module to disable.
        """
        if module_id not in self._modules:
            logger.warning("Cannot disable unregistered module '%s'", module_id)
            return

        try:
            inst = self._instances.get(module_id)
            if inst is not None:
                inst.disable()
            self._statuses[module_id] = InfraModuleStatus.DISABLED
            logger.info("Infrastructure module '%s' disabled successfully", module_id)
        except Exception as exc:
            logger.warning("Exception while disabling infrastructure module '%s': %s", module_id, exc)
            self._statuses[module_id] = InfraModuleStatus.ERROR

    def get_status(self, module_id: str) -> Optional[InfraModuleStatus]:
        """
        Query current status of an infrastructure module.

        Parameters:
            module_id: Identifier of the module.

        Returns:
            Optional[InfraModuleStatus]: Current status or None if not registered.
        """
        if module_id not in self._modules:
            return None

        inst = self._instances.get(module_id)
        if inst is not None:
            try:
                current = inst.status()
                if isinstance(current, InfraModuleStatus):
                    self._statuses[module_id] = current
            except Exception as exc:
                logger.warning("Exception querying status for module '%s': %s", module_id, exc)
                self._statuses[module_id] = InfraModuleStatus.ERROR

        return self._statuses.get(module_id, InfraModuleStatus.DISABLED)

    def get_module(self, module_id: str) -> Optional[Type[IInfrastructureModule]]:
        """Retrieve loaded infrastructure module class by its ID."""
        return self._modules.get(module_id)

    def get_instance(self, module_id: str) -> Optional[IInfrastructureModule]:
        """Retrieve active infrastructure module instance by its ID."""
        return self._instances.get(module_id)

    def list_modules(self) -> List[Dict[str, Any]]:
        """
        Return summarized descriptor list for all registered infrastructure modules.

        Returns:
            List[Dict[str, Any]]: List of dictionary representations containing metadata and status.
        """
        results: List[Dict[str, Any]] = []
        for m_id, cls in self._modules.items():
            try:
                meta = cls.meta
                status = self.get_status(m_id)
                results.append({
                    "id": meta.id,
                    "name": meta.name,
                    "version": meta.version,
                    "description": meta.description,
                    "author": meta.author,
                    "category": meta.category,
                    "capabilities": list(meta.capabilities),
                    "status": status.value if status else "disabled",
                })
            except Exception as exc:
                logger.warning("Error generating summary for module '%s': %s", m_id, exc)
        return results

    def associate(
        self,
        module_id: str,
        project_id: Optional[int] = None,
        transport_id: Optional[str] = None,
    ) -> bool:
        """
        Record an association between an infrastructure module and a project and/or transport.

        Parameters:
            module_id: Identifier of the infrastructure module.
            project_id: Optional project database ID.
            transport_id: Optional transport identifier slug.

        Returns:
            bool: True on successful association, False if module is not registered.
        """
        if module_id not in self._modules:
            logger.warning("Cannot associate unregistered module '%s'", module_id)
            return False

        assoc = {"project_id": project_id, "transport_id": transport_id}
        assoc_list = self._associations.setdefault(module_id, [])
        if assoc not in assoc_list:
            assoc_list.append(assoc)
            logger.info("Associated module '%s' with project=%s, transport=%s", module_id, project_id, transport_id)
        return True

    def get_associations(self, module_id: str) -> List[Dict[str, Any]]:
        """
        Retrieve all recorded associations for a specific infrastructure module.

        Parameters:
            module_id: Identifier of the module.

        Returns:
            List[Dict[str, Any]]: List of association dictionaries.
        """
        if module_id not in self._modules:
            return []
        return list(self._associations.get(module_id, []))

    def configure_module(self, module_id: str, config: Dict[str, Any]) -> bool:
        """
        Apply configuration to an infrastructure module.

        Parameters:
            module_id: Identifier of the module.
            config: Configuration dictionary.

        Returns:
            bool: True if configuration was accepted, False otherwise.
        """
        if module_id not in self._modules:
            logger.warning("Cannot configure unregistered module '%s'", module_id)
            return False

        try:
            self._configs[module_id] = dict(config)
            inst = self._get_or_create_instance(module_id)
            if inst is None:
                return False

            success = inst.configure(config)
            logger.info("Configuration for module '%s' applied (result=%s)", module_id, success)
            return bool(success)
        except Exception as exc:
            logger.warning("Exception configuring module '%s': %s", module_id, exc)
            self._statuses[module_id] = InfraModuleStatus.ERROR
            return False


infra_registry = InfrastructureModuleRegistry()
