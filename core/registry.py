"""
Module registry for scanning module directories, parsing module.toml manifests,
and dynamically loading/validating modules.
"""

import importlib.util
import logging
from pathlib import Path
from typing import Dict, List, Optional
import sys

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from core.base_module import BaseModule, ModuleMeta, ModuleOption, OptionType

logger = logging.getLogger("sentrypack.registry")


class ModuleRegistry:
    """Scans and manages available SentryPack modules."""

    def __init__(self, modules_dir: Path):
        self.modules_dir = Path(modules_dir)
        self.loaded_modules: Dict[str, ModuleMeta] = {}
        self.module_paths: Dict[str, Path] = {}

    def scan(self) -> Dict[str, ModuleMeta]:
        """Scan directory tree for module.toml manifests."""
        self.loaded_modules.clear()
        self.module_paths.clear()
        for manifest_path in self.modules_dir.glob("**/module.toml"):
            if manifest_path.parent.name == "_template":
                continue
            try:
                with open(manifest_path, "rb") as f:
                    data = tomllib.load(f)
                meta_data = data.get("module", {})
                module_id = meta_data.get("id")
                if module_id:
                    options_data = data.get("options", [])
                    parsed_options: List[ModuleOption] = []
                    for opt in options_data:
                        opt_type_str = opt.get("type", "string")
                        try:
                            opt_type = OptionType(opt_type_str)
                        except ValueError:
                            opt_type = OptionType.STRING
                        parsed_options.append(
                            ModuleOption(
                                name=opt.get("name", ""),
                                description=opt.get("description", ""),
                                option_type=opt_type,
                                required=opt.get("required", True),
                                default=opt.get("default"),
                                choices=opt.get("choices"),
                            )
                        )
                    self.loaded_modules[module_id] = ModuleMeta(
                        id=module_id,
                        name=meta_data.get("name", ""),
                        description=meta_data.get("description", ""),
                        author=meta_data.get("author", ""),
                        version=meta_data.get("version", "0.1.0"),
                        category=meta_data.get("category", "utility"),
                        options=parsed_options,
                    )
                    self.module_paths[module_id] = manifest_path.parent
            except Exception as e:
                logger.warning("Error loading manifest %s: %s", manifest_path, e)
        return self.loaded_modules

    def get_module(self, module_id: str) -> Optional[ModuleMeta]:
        """Retrieve module metadata by module ID."""
        return self.loaded_modules.get(module_id)

    def get_module_dir(self, module_id: str) -> Optional[Path]:
        """Retrieve module directory path by module ID."""
        return self.module_paths.get(module_id)


def load_module_class(module_dir: Path):
    """Dynamically import the Module class from a module directory.

    Raises:
        FileNotFoundError: If module.py does not exist in *module_dir*.
        ImportError:       If the module has unresolvable import-time dependencies.
        SyntaxError:       If module.py contains invalid Python syntax.
    """
    module_file = Path(module_dir) / "module.py"
    if not module_file.exists():
        raise FileNotFoundError(f"module.py not found in {module_dir}")
    spec = importlib.util.spec_from_file_location(f"{module_dir.name}.module", module_file)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load spec for {module_file}")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except SyntaxError as exc:
        raise SyntaxError(
            f"{module_file}: syntax error on line {exc.lineno}: {exc.msg}"
        ) from exc
    except ImportError as exc:
        raise ImportError(
            f"{module_file}: import failed — {exc}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(
            f"{module_file}: unexpected error during import — "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    cls = getattr(mod, "Module", None)
    if cls is None:
        raise ImportError(f"{module_file}: no top-level 'Module' class found")
    return cls


def validate_options(meta: ModuleMeta, options: Optional[dict] = None) -> tuple[bool, List[dict]]:
    """Validate user options against the module's declared options schema.

    Returns (is_valid, errors).
    """
    opts = options or {}
    errors: List[dict] = []

    for opt in meta.options:
        if opt.name not in opts or opts[opt.name] is None:
            if opt.required:
                errors.append({
                    "option": opt.name,
                    "error": f"Required option '{opt.name}' is missing",
                })
            continue

        val = opts[opt.name]

        if opt.option_type == OptionType.STRING:
            if not isinstance(val, str):
                errors.append({
                    "option": opt.name,
                    "error": f"Option '{opt.name}' must be a string, got {type(val).__name__}",
                })
        elif opt.option_type == OptionType.INTEGER:
            if not isinstance(val, int) or isinstance(val, bool):
                errors.append({
                    "option": opt.name,
                    "error": f"Option '{opt.name}' must be an integer, got {type(val).__name__}",
                })
        elif opt.option_type == OptionType.BOOLEAN:
            if not isinstance(val, bool):
                errors.append({
                    "option": opt.name,
                    "error": f"Option '{opt.name}' must be a boolean, got {type(val).__name__}",
                })
        elif opt.option_type == OptionType.ENUM:
            if not isinstance(val, str):
                errors.append({
                    "option": opt.name,
                    "error": f"Option '{opt.name}' must be a string enum value, got {type(val).__name__}",
                })
            elif opt.choices and val not in opt.choices:
                errors.append({
                    "option": opt.name,
                    "error": f"Option '{opt.name}' value '{val}' is not in allowed choices: {opt.choices}",
                })
        elif opt.option_type == OptionType.FILE_PATH:
            if not isinstance(val, str):
                errors.append({
                    "option": opt.name,
                    "error": f"Option '{opt.name}' must be a file path string, got {type(val).__name__}",
                })

    return len(errors) == 0, errors

