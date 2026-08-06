"""
CLI validator script: sentrypack validate-module <path>
"""

import sys
from pathlib import Path
import argparse

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def validate_module(module_path: Path) -> bool:
    print(f"Validating module at: {module_path}")
    manifest = module_path / "module.toml"
    module_py = module_path / "module.py"

    if not manifest.exists():
        print("[-] Error: module.toml manifest is missing.")
        return False
    if not module_py.exists():
        print("[-] Error: module.py file is missing.")
        return False

    with open(manifest, "rb") as f:
        data = tomllib.load(f)

    meta = data.get("module", {})
    required_fields = ["id", "name", "description", "author", "version", "category"]
    for field in required_fields:
        if field not in meta:
            print(f"[-] Error: missing required field '{field}' in module.toml")
            return False

    print("[+] Module structure validated successfully.")
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
