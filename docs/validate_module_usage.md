# `sentrypack validate-module` — CLI Reference

The `sentrypack-validate` command validates a SentryPack plugin module against the
full plugin contract before it is submitted for merge.  Run it locally before
opening a PR and add it to your pre-commit hooks for continuous enforcement.

---

## Installation

```bash
# From the repository root (editable install):
pip install -e .

# Or run the script directly without installing:
python scripts/validate_module.py <path>
```

---

## Usage

```
sentrypack-validate <path> [--strict] [--json] [--no-color]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `path`   | ✅ | Path to the module directory (must contain `module.toml` + `module.py`) |
| `--strict` | ❌ | Treat warnings as errors — exits `1` when any warning is present |
| `--json` | ❌ | Emit a machine-readable JSON report to stdout instead of coloured text |
| `--no-color` | ❌ | Disable ANSI colour codes (auto-disabled when stdout is not a TTY) |

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | All checks passed. Warnings are allowed unless `--strict` is set. |
| `1`  | One or more validation **errors** (or warnings under `--strict`). |
| `2`  | Usage error — bad argument or path does not exist / is not a directory. |

---

## Examples

### Basic validation

```bash
# Validate an existing module
sentrypack-validate modules/recon/nmap_scan

# Expected output:
#
# Validating: modules/recon/nmap_scan
#
#   [PASS]  module toml exists
#   [PASS]  module py exists
#   [PASS]  toml parseable
#   [PASS]  required manifest fields  id=recon.nmap_scan
#   [PASS]  id format  recon.nmap_scan
#   [PASS]  version format  0.1.0
#   [PASS]  category valid  recon
#   [PASS]  options schema  2 option(s)
#   [PASS]  py importable
#   [PASS]  module class exists
#   [PASS]  base module subclass
#   [PASS]  meta attribute  id='recon.nmap_scan'
#   [PASS]  meta id matches  recon.nmap_scan
#   [PASS]  check signature
#   [PASS]  run signature
#   [PASS]  instantiable
#   [PASS]  template guard
#
# 17/17 checks passed — module is valid.
```

### Validate a new module being developed

```bash
sentrypack-validate modules/exploit/my_new_exploit
echo "Exit code: $?"
```

### Strict mode (fail on warnings)

The template module emits a warning because its `id` is still `"template_module"`.
Under `--strict` this becomes an error:

```bash
sentrypack-validate modules/_template --strict
# Exit: 1

sentrypack-validate modules/_template
# Exit: 0  (warnings are non-fatal without --strict)
```

### Machine-readable JSON output

```bash
sentrypack-validate modules/recon/nmap_scan --json
```

```json
{
  "path": "/path/to/modules/recon/nmap_scan",
  "valid": true,
  "errors": [],
  "warnings": [],
  "checks": [
    {"name": "module_toml_exists", "status": "pass", "message": ""},
    {"name": "module_py_exists",   "status": "pass", "message": ""},
    {"name": "toml_parseable",     "status": "pass", "message": ""},
    ...
  ]
}
```

Parse it with any JSON tool:

```bash
# Get just the errors list
sentrypack-validate my_module/ --json | python -m json.tool

# Check in a CI script
result=$(sentrypack-validate my_module/ --json)
if echo "$result" | python -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d['valid'] else 1)"; then
  echo "Module is valid"
fi
```

### No-color for CI / log files

```bash
sentrypack-validate modules/recon/nmap_scan --no-color 2>&1 | tee ci_report.txt
```

---

## Validation checks

The validator runs **17 checks** in order.  Earlier failures cause later checks to
be *skipped* (since they depend on the earlier step succeeding).

| # | Check name | What is verified |
|---|-----------|-----------------|
| 1 | `module_toml_exists` | `module.toml` file is present in the module directory |
| 2 | `module_py_exists` | `module.py` file is present |
| 3 | `toml_parseable` | `module.toml` is valid TOML (no syntax errors) |
| 4 | `required_manifest_fields` | `[module]` section has all of: `id`, `name`, `description`, `author`, `version`, `category` |
| 5 | `id_format` | `id` matches `^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+$` — e.g. `recon.nmap_scan` |
| 6 | `version_format` | `version` is `MAJOR.MINOR.PATCH` — e.g. `1.0.0` |
| 7 | `category_valid` | `category` is one of `recon`, `exploit`, `c2`, `analysis`, `dev`, `utility` |
| 8 | `options_schema` | Each `[[options]]` entry has `name`, `description`, `type`; `type` is a valid `OptionType`; `enum` type has a `choices` list |
| 9 | `py_importable` | `module.py` can be imported without `SyntaxError` or `ImportError` |
| 10 | `module_class_exists` | A class named `Module` is exported from `module.py` |
| 11 | `base_module_subclass` | `Module` subclasses `core.base_module.BaseModule` |
| 12 | `meta_attribute` | `Module.meta` exists and is a `ModuleMeta` instance |
| 13 | `meta_id_matches` | `Module.meta.id` matches the `id` in `module.toml` |
| 14 | `check_signature` | `check(self, ctx)` method is present and callable |
| 15 | `run_signature` | `run(self, ctx)` method is present and callable |
| 16 | `instantiable` | `Module()` (no options) does not raise |
| W1 | `template_guard` | **Warning** — `id` is not still `"template_module"` |

---

## Common errors and fixes

### `id format` — `id 'mymod' does not match pattern`

The module `id` must be dot-separated, e.g. `recon.my_module`.  A plain name
without a category prefix fails.

```toml
# ✗ Bad
id = "my_module"

# ✓ Good
id = "recon.my_module"
```

### `meta id matches` — `Manifest id 'recon.old' ≠ Module.meta.id 'recon.new'`

The `id` in `module.toml` and the `id` in `Module.meta` must be identical.
Update both when renaming a module.

### `base module subclass` — Module class must subclass BaseModule

```python
# ✗ Bad — standalone class
class Module:
    ...

# ✓ Good
from core.base_module import BaseModule
class Module(BaseModule):
    ...
```

### `check signature` — check() must accept (self, ctx)

```python
# ✗ Bad — missing ctx parameter
def check(self) -> bool:
    return True

# ✓ Good
def check(self, ctx: Any) -> bool:
    return True
```

### `options schema` — type 'hostname' is not valid

The `type` field in `[[options]]` must be one of:
`string`, `integer`, `boolean`, `enum`, `file_path`

```toml
# ✗ Bad
[[options]]
name = "TARGET"
type = "hostname"

# ✓ Good
[[options]]
name = "TARGET"
type = "string"
```

---

## Pre-commit hook

Add this to `.pre-commit-config.yaml` to validate every module that is modified:

```yaml
repos:
  - repo: local
    hooks:
      - id: validate-modules
        name: Validate SentryPack modules
        language: system
        entry: sentrypack-validate
        pass_filenames: false
        always_run: false
        files: ^modules/.*/(module\.toml|module\.py)$
        # Runs once for each changed module directory
        args: []
```

Or as a simple git pre-commit script:

```bash
#!/bin/sh
# .git/hooks/pre-commit
changed_modules=$(git diff --cached --name-only | grep -oE 'modules/[^/]+/[^/]+' | sort -u)
for mod in $changed_modules; do
  if [ -d "$mod" ]; then
    sentrypack-validate "$mod" --strict --no-color || exit 1
  fi
done
```

---

## Programmatic API

The validator can also be used directly from Python:

```python
from pathlib import Path
from scripts.validate_module import ModuleValidator

validator = ModuleValidator(Path("modules/recon/nmap_scan"), use_color=False)
report = validator.validate()

if report.valid:
    print(f"✓ Module is valid ({len(report.checks)} checks passed)")
else:
    for error in report.errors:
        print(f"✗ {error}")

# Convert to dict for JSON serialisation
import json
print(json.dumps(report.to_dict(), indent=2))
```
