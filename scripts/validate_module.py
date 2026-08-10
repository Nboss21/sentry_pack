"""
CLI validator script: sentrypack validate-module <path>
"""

import sys
from pathlib import Path
import argparse
from core.registry import ModuleRegistry


def validate_module(module_path: Path) -> bool:
    print(f"Validating module at: {module_path}")
    manifest = module_path / "module.toml"
    module_py = module_path / "module.py"

    registry = ModuleRegistry(module_path.parent)

    is_valid, err_msg, data = registry.validate_manifest(manifest)
    if not is_valid:
        print(f"[-] Error: {err_msg}")
        return False

    if not module_py.exists():
        print(f"[-] Error: Entry point module.py file is missing at '{module_py}'")
        return False

    module_id = data["module"]["id"]
    is_loaded, err_msg, module_cls = registry._load_module_class(module_py, module_id)
    if not is_loaded:
        print(f"[-] Error: {err_msg}")
        return False

    print("[+] Module structure and Python entry point validated successfully.")
    return True


def main():
    parser = argparse.ArgumentParser(description="SentryPack Module Validator CLI")
    parser.add_argument("path", type=str, help="Path to module directory")
    args = parser.parse_args()

    module_dir = Path(args.path)
    if not validate_module(module_dir):
        sys.exit(1)


if __name__ == "__main__":
    main()

