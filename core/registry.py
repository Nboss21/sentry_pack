"""
Module registry for scanning module directories, parsing module.toml manifests,
and dynamically loading/validating modules.
"""

import importlib.util
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Type, Any
import sys

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from core.base_module import BaseModule, ModuleMeta, ModuleOption, OptionType

logger = logging.getLogger("sentrypack.registry")


class ModuleRegistry:
    """Scans, validates, loads, and manages available SentryPack modules."""

    REQUIRED_MANIFEST_FIELDS = ["id", "name", "description", "author", "version", "category"]

    def __init__(self, modules_dir: Path):
        self.modules_dir = Path(modules_dir)
        self.loaded_modules: Dict[str, ModuleMeta] = {}
        self.loaded_classes: Dict[str, Type[BaseModule]] = {}

    def validate_manifest(self, manifest_path: Path) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Validate module.toml manifest structure and required fields.
        Returns (is_valid, error_reason, parsed_data).
        """
        if not manifest_path.exists():
            return False, f"Manifest file missing at '{manifest_path}'", None

        try:
            with open(manifest_path, "rb") as f:
                data = tomllib.load(f)
        except Exception as e:
            return False, f"Malformed TOML manifest: {e}", None

        meta_data = data.get("module")
        if not isinstance(meta_data, dict):
            return False, "Missing [module] section in manifest", None

        for field in self.REQUIRED_MANIFEST_FIELDS:
            if field not in meta_data or not meta_data[field]:
                return False, f"Missing or empty required field '{field}' in [module] manifest", None

        return True, None, data

    def _parse_options(self, raw_options: list) -> List[ModuleOption]:
        """Helper to parse [[options]] list into ModuleOption dataclasses."""
        options = []
        if not isinstance(raw_options, list):
            return options

        for opt in raw_options:
            if not isinstance(opt, dict):
                continue
            name = opt.get("name")
            description = opt.get("description", "")
            type_str = opt.get("type", "string")

            if isinstance(type_str, str):
                try:
                    opt_type = OptionType(type_str.lower())
                except ValueError:
                    opt_type = OptionType.STRING
            else:
                opt_type = OptionType.STRING

            if name:
                options.append(
                    ModuleOption(
                        name=name,
                        description=description,
                        option_type=opt_type,
                        required=bool(opt.get("required", True)),
                        default=opt.get("default"),
                        choices=opt.get("choices"),
                    )
                )
        return options

    def _load_module_class(self, module_py_path: Path, module_id: str) -> Tuple[bool, Optional[str], Optional[Type[BaseModule]]]:
        """
        Dynamically import module.py file and extract BaseModule subclass named 'Module'.
        Returns (success, error_reason, module_class).
        """
        if not module_py_path.exists():
            return False, f"Entry point file missing at '{module_py_path}'", None

        module_name = f"sentrypack_module_{module_id.replace('.', '_')}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, module_py_path)
            if spec is None or spec.loader is None:
                return False, f"Could not create spec for '{module_py_path}'", None

            mod = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = mod
            spec.loader.exec_module(mod)

            module_cls = getattr(mod, "Module", None)
            if module_cls is None:
                return False, f"Module entry point '{module_py_path}' does not define a 'Module' class", None

            if not (isinstance(module_cls, type) and issubclass(module_cls, BaseModule)):
                return False, f"Class 'Module' in '{module_py_path}' must inherit from BaseModule", None

            return True, None, module_cls
        except Exception as e:
            return False, f"Error importing module entry point: {e}", None

    def scan(self) -> Dict[str, ModuleMeta]:
        """
        Scan directory tree for module folders containing module.toml.
        Validates, imports, and registers valid modules, logging errors for skipped ones.
        """
        self.loaded_modules.clear()
        self.loaded_classes.clear()

        total_found = 0
        total_loaded = 0
        skipped: List[Tuple[str, str]] = []

        # Find candidate module folders (folders containing module.toml)
        for manifest_path in self.modules_dir.glob("**/module.toml"):
            module_folder = manifest_path.parent
            if module_folder.name == "_template":
                continue
            total_found += 1

            # Validate manifest
            is_valid, err_msg, data = self.validate_manifest(manifest_path)
            if not is_valid:
                logger.error(f"Failed to load module at '{module_folder}': {err_msg}")
                skipped.append((str(module_folder), err_msg))
                continue

            meta_data = data["module"]
            module_id = meta_data["id"]

            # Load Python entry point module.py
            module_py_path = module_folder / "module.py"
            is_loaded, err_msg, module_cls = self._load_module_class(module_py_path, module_id)
            if not is_loaded:
                logger.error(f"Failed to import module at '{module_folder}': {err_msg}")
                skipped.append((str(module_folder), err_msg))
                continue

            parsed_options = self._parse_options(data.get("options", []))

            # Build metadata object
            meta = ModuleMeta(
                id=module_id,
                name=meta_data["name"],
                description=meta_data["description"],
                author=meta_data["author"],
                version=meta_data["version"],
                category=meta_data["category"],
                options=parsed_options,
            )

            # Store in registry keyed by module_id (and name if needed)
            self.loaded_modules[module_id] = meta
            self.loaded_classes[module_id] = module_cls
            total_loaded += 1

        logger.info(
            f"Module Registry Scan complete: Total found={total_found}, Loaded={total_loaded}, Skipped={len(skipped)}"
        )
        for folder, reason in skipped:
            logger.warning(f"Skipped module '{folder}': {reason}")

        return self.loaded_modules

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve metadata and class for a loaded module by ID or Name.
        Returns dictionary containing 'meta' and 'class'.
        """
        module_id = name
        if module_id not in self.loaded_modules:
            # Search by name if module_id lookup fails
            for m_id, meta in self.loaded_modules.items():
                if meta.name == name:
                    module_id = m_id
                    break

        if module_id in self.loaded_modules:
            return {
                "meta": self.loaded_modules[module_id],
                "class": self.loaded_classes[module_id],
            }
        return None

    def get_module(self, module_id: str) -> Optional[ModuleMeta]:
        """Retrieve module metadata by module ID (backwards compatibility)."""
        entry = self.get(module_id)
        return entry["meta"] if entry else None

    def is_loaded(self, name: str) -> bool:
        """Check if a module is loaded by module ID or Name."""
        return self.get(name) is not None

    def list_all(self) -> List[ModuleMeta]:
        """List all loaded module metadata objects."""
        return list(self.loaded_modules.values())

