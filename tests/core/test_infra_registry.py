"""
Unit and resilience tests for InfrastructureModuleRegistry and IInfrastructureModule.

Verifies:
  ✓ Manager loads valid infrastructure modules
  ✓ Supports enable / disable / configure / status lifecycle
  ✓ Broken modules do not crash the registry or app
  ✓ Associates modules with projects and transports
  ✓ Duplicate IDs keep the first-registered module
  ✓ Logging is produced on module load and execution failures
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

import pytest

from core.infra_module_base import (
    IInfrastructureModule,
    InfraModuleMeta,
    InfraModuleStatus,
)
from core.infra_registry import InfrastructureModuleRegistry


# ---------------------------------------------------------------------------
# Test Fixtures: Generating mock plugin directories inline
# ---------------------------------------------------------------------------

def make_valid_infra_plugin(tmp_path: Path, module_id: str = "infra.mock") -> Path:
    """Write a minimal valid infrastructure module plugin to a temp directory."""
    plugin_dir = tmp_path / module_id.replace(".", "_")
    plugin_dir.mkdir(exist_ok=True)
    (plugin_dir / "infra_module.py").write_text(f"""
from core.infra_module_base import IInfrastructureModule, InfraModuleMeta, InfraModuleStatus

class MockInfraModule(IInfrastructureModule):
    meta = InfraModuleMeta(
        id="{module_id}",
        name="Mock Infrastructure Module",
        version="0.1.0",
        description="Test mock infra service",
        author="Tester",
        category="mock",
        capabilities=["mock_cap"],
    )

    def __init__(self):
        self._enabled = False
        self._config = {{}}

    def enable(self) -> bool:
        self._enabled = True
        return True

    def disable(self) -> None:
        self._enabled = False

    def status(self) -> InfraModuleStatus:
        return InfraModuleStatus.ENABLED if self._enabled else InfraModuleStatus.DISABLED

    def configure(self, config: dict) -> bool:
        self._config = dict(config)
        return True
""")
    return plugin_dir


def make_broken_syntax_plugin(tmp_path: Path, name: str = "broken_syntax") -> Path:
    """Write an infrastructure module with invalid Python syntax."""
    plugin_dir = tmp_path / name
    plugin_dir.mkdir(exist_ok=True)
    (plugin_dir / "infra_module.py").write_text("invalid python code syntax error !!!@#$")
    return plugin_dir


def make_unimplemented_plugin(tmp_path: Path, name: str = "unimplemented") -> Path:
    """Write an infrastructure module missing abstract methods."""
    plugin_dir = tmp_path / name
    plugin_dir.mkdir(exist_ok=True)
    (plugin_dir / "infra_module.py").write_text("""
from core.infra_module_base import IInfrastructureModule, InfraModuleMeta

class UnimplementedModule(IInfrastructureModule):
    meta = InfraModuleMeta(id="infra.unimplemented", name="Bad", version="0.1.0", description="d", author="a", category="c")
    # missing enable, disable, status, configure
""")
    return plugin_dir


def make_exploding_plugin(tmp_path: Path, module_id: str = "infra.exploding") -> Path:
    """Write an infrastructure module that raises exceptions in all methods."""
    plugin_dir = tmp_path / module_id.replace(".", "_")
    plugin_dir.mkdir(exist_ok=True)
    (plugin_dir / "infra_module.py").write_text(f"""
from core.infra_module_base import IInfrastructureModule, InfraModuleMeta, InfraModuleStatus

class ExplodingModule(IInfrastructureModule):
    meta = InfraModuleMeta(
        id="{module_id}",
        name="Exploding Module",
        version="0.1.0",
        description="Raises exceptions",
        author="Tester",
        category="chaos",
    )

    def enable(self) -> bool:
        raise RuntimeError("Chaos on enable")

    def disable(self) -> None:
        raise RuntimeError("Chaos on disable")

    def status(self) -> InfraModuleStatus:
        raise RuntimeError("Chaos on status")

    def configure(self, config: dict) -> bool:
        raise RuntimeError("Chaos on configure")
""")
    return plugin_dir


# ---------------------------------------------------------------------------
# 1. Scanning and Resilience Tests
# ---------------------------------------------------------------------------

class TestInfraRegistryScanning:
    def test_loads_valid_module(self, tmp_path):
        make_valid_infra_plugin(tmp_path, "infra.valid1")
        registry = InfrastructureModuleRegistry()
        registry.scan(tmp_path)

        assert registry.get_module("infra.valid1") is not None
        assert registry.get_status("infra.valid1") == InfraModuleStatus.DISABLED

    def test_skips_broken_syntax_without_crashing(self, tmp_path):
        make_broken_syntax_plugin(tmp_path, "broken")
        registry = InfrastructureModuleRegistry()
        registry.scan(tmp_path)  # Must not raise

        assert registry.list_modules() == []

    def test_skips_unimplemented_module_without_crashing(self, tmp_path):
        make_unimplemented_plugin(tmp_path, "bad_class")
        registry = InfrastructureModuleRegistry()
        registry.scan(tmp_path)

        assert registry.list_modules() == []

    def test_nonexistent_directory_is_safe(self, tmp_path):
        registry = InfrastructureModuleRegistry()
        registry.scan(tmp_path / "does_not_exist")
        assert registry.list_modules() == []

    def test_loads_valid_and_skips_broken_mixed(self, tmp_path):
        make_valid_infra_plugin(tmp_path, "infra.good")
        make_broken_syntax_plugin(tmp_path, "infra.bad")
        make_unimplemented_plugin(tmp_path, "infra.unimplemented")

        registry = InfrastructureModuleRegistry()
        registry.scan(tmp_path)

        modules = registry.list_modules()
        assert len(modules) == 1
        assert modules[0]["id"] == "infra.good"
        assert registry.get_module("infra.good") is not None
        assert registry.get_module("infra.bad") is None

    def test_duplicate_module_id_keeps_first(self, tmp_path):
        plugin_dir1 = tmp_path / "dup1"
        plugin_dir1.mkdir(exist_ok=True)
        (plugin_dir1 / "infra_module.py").write_text("""
from core.infra_module_base import IInfrastructureModule, InfraModuleMeta, InfraModuleStatus

class DupFirst(IInfrastructureModule):
    meta = InfraModuleMeta(id="infra.dup", name="Duplicate 1", version="0.1.0", description="d", author="a", category="c")
    def enable(self): return True
    def disable(self): pass
    def status(self): return InfraModuleStatus.DISABLED
    def configure(self, c): return True
""")

        plugin_dir2 = tmp_path / "dup2"
        plugin_dir2.mkdir(exist_ok=True)
        (plugin_dir2 / "infra_module.py").write_text("""
from core.infra_module_base import IInfrastructureModule, InfraModuleMeta, InfraModuleStatus

class DupSecond(IInfrastructureModule):
    meta = InfraModuleMeta(id="infra.dup", name="Duplicate 2", version="0.2.0", description="d", author="a", category="c")
    def enable(self): return True
    def disable(self): pass
    def status(self): return InfraModuleStatus.DISABLED
    def configure(self, c): return True
""")
        registry = InfrastructureModuleRegistry()
        registry.scan(tmp_path)

        cls = registry.get_module("infra.dup")
        assert cls is not None
        assert cls.meta.name == "Duplicate 1"  # First registered wins
        assert cls.meta.version == "0.1.0"

    def test_logs_produced_for_failures(self, tmp_path, caplog):
        make_broken_syntax_plugin(tmp_path, "log_error_plugin")
        registry = InfrastructureModuleRegistry()
        with caplog.at_level(logging.WARNING, logger="sentrypack.infra_registry"):
            registry.scan(tmp_path)
        assert len(caplog.records) > 0


# ---------------------------------------------------------------------------
# 2. Lifecycle and Associations Tests
# ---------------------------------------------------------------------------

class TestInfraRegistryLifecycle:
    def test_enable_disable_lifecycle(self, tmp_path):
        make_valid_infra_plugin(tmp_path, "infra.life")
        registry = InfrastructureModuleRegistry()
        registry.scan(tmp_path)

        # Initial state
        assert registry.get_status("infra.life") == InfraModuleStatus.DISABLED

        # Enable
        assert registry.enable_module("infra.life") is True
        assert registry.get_status("infra.life") == InfraModuleStatus.ENABLED

        # Disable
        registry.disable_module("infra.life")
        assert registry.get_status("infra.life") == InfraModuleStatus.DISABLED

    def test_configure_module(self, tmp_path):
        make_valid_infra_plugin(tmp_path, "infra.cfg")
        registry = InfrastructureModuleRegistry()
        registry.scan(tmp_path)

        res = registry.configure_module("infra.cfg", {"host": "10.0.0.1", "port": 8080})
        assert res is True

    def test_associations_management(self, tmp_path):
        make_valid_infra_plugin(tmp_path, "infra.assoc")
        registry = InfrastructureModuleRegistry()
        registry.scan(tmp_path)

        # Associate with project
        assert registry.associate("infra.assoc", project_id=1) is True
        # Associate with transport
        assert registry.associate("infra.assoc", transport_id="tcp") is True
        # Associate with both
        assert registry.associate("infra.assoc", project_id=2, transport_id="https_proxy") is True

        assocs = registry.get_associations("infra.assoc")
        assert len(assocs) == 3
        assert {"project_id": 1, "transport_id": None} in assocs
        assert {"project_id": None, "transport_id": "tcp"} in assocs
        assert {"project_id": 2, "transport_id": "https_proxy"} in assocs

    def test_unregistered_module_actions_return_safe_defaults(self):
        registry = InfrastructureModuleRegistry()
        assert registry.get_module("nonexistent") is None
        assert registry.get_status("nonexistent") is None
        assert registry.enable_module("nonexistent") is False
        registry.disable_module("nonexistent")  # Must not raise
        assert registry.configure_module("nonexistent", {"key": "val"}) is False
        assert registry.associate("nonexistent", project_id=1) is False
        assert registry.get_associations("nonexistent") == []

    def test_exploding_module_does_not_crash_registry(self, tmp_path):
        make_exploding_plugin(tmp_path, "infra.boom")
        registry = InfrastructureModuleRegistry()
        registry.scan(tmp_path)

        assert registry.get_module("infra.boom") is not None

        # enable() raises in plugin -> handled safely, returns False, sets ERROR
        assert registry.enable_module("infra.boom") is False
        assert registry.get_status("infra.boom") == InfraModuleStatus.ERROR

        # configure() raises in plugin -> handled safely, returns False
        assert registry.configure_module("infra.boom", {"a": 1}) is False

        # disable() raises in plugin -> handled safely, sets ERROR
        registry.disable_module("infra.boom")
        assert registry.get_status("infra.boom") == InfraModuleStatus.ERROR


# ---------------------------------------------------------------------------
# 3. Reference Implementation Scan Test
# ---------------------------------------------------------------------------

def test_scan_actual_modules_infra_directory():
    """Scans the repository's modules/infra directory and verifies https_proxy is discovered."""
    infra_dir = Path(__file__).resolve().parent.parent.parent / "modules" / "infra"
    registry = InfrastructureModuleRegistry()
    registry.scan(infra_dir)

    cls = registry.get_module("infra.https_proxy")
    assert cls is not None
    assert cls.meta.id == "infra.https_proxy"
    assert cls.meta.name == "HTTP/S Proxy Infrastructure Module"
    assert cls.meta.category == "proxy"
    assert "connect_tunnel" in cls.meta.capabilities
