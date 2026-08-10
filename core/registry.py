"""
Module registry for scanning module directories, parsing module.toml manifests,
and dynamically loading/validating modules.
"""

import importlib.util
from pathlib import Path
from typing import Dict, List, Optional
import sys

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from core.base_module import BaseModule, ModuleMeta


class ModuleRegistry:
    """Scans and manages available SentryPack modules."""

    def __init__(self, modules_dir: Path):
        self.modules_dir = Path(modules_dir)
        self.loaded_modules: Dict[str, ModuleMeta] = {}

    def scan(self) -> Dict[str, ModuleMeta]:
        """Scan directory tree for module.toml manifests."""
        self.loaded_modules.clear()
        for manifest_path in self.modules_dir.glob("**/module.toml"):
            if manifest_path.parent.name == "_template":
                continue
            try:
                with open(manifest_path, "rb") as f:
                    data = tomllib.load(f)
                meta_data = data.get("module", {})
                module_id = meta_data.get("id")
                if module_id:
                    self.loaded_modules[module_id] = ModuleMeta(
                        id=module_id,
                        name=meta_data.get("name", ""),
                        description=meta_data.get("description", ""),
                        author=meta_data.get("author", ""),
                        version=meta_data.get("version", "0.1.0"),
                        category=meta_data.get("category", "utility"),
                    )
            except Exception as e:
                print(f"Error loading manifest {manifest_path}: {e}")
        return self.loaded_modules

    def get_module(self, module_id: str) -> Optional[ModuleMeta]:
        """Retrieve module metadata by module ID."""
        return self.loaded_modules.get(module_id)
