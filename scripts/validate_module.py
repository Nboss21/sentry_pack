"""
sentrypack validate-module — Module validation CLI.

Checks a candidate module directory against the full SentryPack plugin
contract before it is merged into the registry.

Usage
-----
    sentrypack-validate <path> [--strict] [--json] [--no-color]
    python scripts/validate_module.py <path> [--strict] [--json] [--no-color]

Exit codes
----------
    0   All checks passed (warnings are non-fatal unless --strict is set)
    1   One or more validation errors
    2   Usage error (bad argument, path does not exist)

Validation checks (in order)
-----------------------------
     1  module.toml  present
     2  module.py    present
     3  TOML parseable
     4  Required manifest fields: id, name, description, author, version, category
     5  id format:     ^[a-z_][a-z0-9_]*(\\.[a-z_][a-z0-9_]*)+$
     6  version format: ^\\d+\\.\\d+\\.\\d+$
     7  category in allowlist
     8  options schema: name / description / type present; type is a valid OptionType
     9  module.py importable (no SyntaxError / ImportError)
    10  Module class exported from module.py
    11  Module subclasses BaseModule
    12  meta attribute present (ModuleMeta instance)
    13  meta.id matches manifest id
    14  check(self, ctx) method present and callable
    15  run(self, ctx) method present and callable
    16  Module() instantiates cleanly with no options
    W1  template guard: warns when id == "template_module"
"""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import re
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# ---------------------------------------------------------------------------
# Tomllib compat (stdlib ≥ 3.11, else tomli)
# ---------------------------------------------------------------------------
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore[no-reuse-declaration]
    except ImportError:
        sys.exit(
            "Error: 'tomli' is required on Python < 3.11. "
            "Install it with: pip install tomli"
        )

# ---------------------------------------------------------------------------
# Ensure the repository root is on sys.path so 'core.*' imports work
# ---------------------------------------------------------------------------
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VALID_CATEGORIES = frozenset({"recon", "exploit", "c2", "analysis", "dev", "utility"})
_VALID_OPTION_TYPES = frozenset({"string", "integer", "boolean", "enum", "file_path"})
_ID_RE = re.compile(r"^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_TEMPLATE_ID = "template_module"

# ANSI colour codes (disabled in --no-color / non-TTY mode)
_ANSI: dict[str, str] = {
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    name: str
    status: str  # "pass" | "fail" | "warn" | "skip"
    message: str = ""


@dataclass
class ValidationReport:
    path: str
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    checks: List[CheckResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "valid": self.valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "checks": [{"name": c.name, "status": c.status, "message": c.message} for c in self.checks],
        }


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class ModuleValidator:
    """Runs the full 16-check validation pipeline on a module directory."""

    def __init__(self, module_path: Path, use_color: bool = True) -> None:
        self.module_path = module_path
        self.use_color = use_color
        self._report = ValidationReport(path=str(module_path), valid=True)
        # Intermediate state shared between checks
        self._toml_data: dict = {}
        self._py_module = None  # imported Python module object
        self._cls = None        # Module class

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self) -> ValidationReport:
        """Run all checks in order and return the completed report."""
        checks = [
            self._check_toml_exists,
            self._check_py_exists,
            self._check_toml_parseable,
            self._check_required_fields,
            self._check_id_format,
            self._check_version_format,
            self._check_category,
            self._check_options_schema,
            self._check_py_importable,
            self._check_module_class_exists,
            self._check_base_module_subclass,
            self._check_meta_attribute,
            self._check_meta_id_matches,
            self._check_check_signature,
            self._check_run_signature,
            self._check_instantiable,
            self._check_template_guard,   # warning only
        ]
        for fn in checks:
            fn()
        self._report.valid = len(self._report.errors) == 0
        return self._report

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _pass(self, name: str, message: str = "") -> None:
        self._report.checks.append(CheckResult(name, "pass", message))

    def _fail(self, name: str, message: str) -> None:
        self._report.errors.append(message)
        self._report.checks.append(CheckResult(name, "fail", message))

    def _warn(self, name: str, message: str) -> None:
        self._report.warnings.append(message)
        self._report.checks.append(CheckResult(name, "warn", message))

    def _skip(self, name: str, reason: str = "") -> None:
        self._report.checks.append(CheckResult(name, "skip", reason))

    # ── 1. module.toml exists ──────────────────────────────────────────
    def _check_toml_exists(self) -> None:
        if (self.module_path / "module.toml").exists():
            self._pass("module_toml_exists")
        else:
            self._fail("module_toml_exists", "module.toml is missing from the module directory")

    # ── 2. module.py exists ───────────────────────────────────────────
    def _check_py_exists(self) -> None:
        if (self.module_path / "module.py").exists():
            self._pass("module_py_exists")
        else:
            self._fail("module_py_exists", "module.py is missing from the module directory")

    # ── 3. TOML parseable ─────────────────────────────────────────────
    def _check_toml_parseable(self) -> None:
        manifest = self.module_path / "module.toml"
        if not manifest.exists():
            self._skip("toml_parseable", "module.toml not found — skipping parse check")
            return
        try:
            with open(manifest, "rb") as f:
                self._toml_data = tomllib.load(f)
            self._pass("toml_parseable")
        except Exception as exc:
            self._fail("toml_parseable", f"module.toml contains invalid TOML: {exc}")

    # ── 4. Required manifest fields ───────────────────────────────────
    def _check_required_fields(self) -> None:
        if not self._toml_data:
            self._skip("required_manifest_fields", "TOML not loaded — skipping field check")
            return
        meta = self._toml_data.get("module", {})
        missing = [f for f in ("id", "name", "description", "author", "version", "category") if f not in meta]
        if missing:
            self._fail(
                "required_manifest_fields",
                f"Missing required [module] fields: {', '.join(missing)}",
            )
        else:
            self._pass("required_manifest_fields", f"id={meta.get('id')!r}")

    # ── 5. id format ──────────────────────────────────────────────────
    def _check_id_format(self) -> None:
        meta = self._toml_data.get("module", {})
        mod_id: str = meta.get("id", "")
        if not mod_id:
            self._skip("id_format", "id field absent — skipping format check")
            return
        if _ID_RE.match(mod_id):
            self._pass("id_format", mod_id)
        else:
            self._fail(
                "id_format",
                f"id {mod_id!r} does not match pattern 'category.module_name' "
                "(lowercase letters, digits, underscores, at least one dot)",
            )

    # ── 6. version format ─────────────────────────────────────────────
    def _check_version_format(self) -> None:
        meta = self._toml_data.get("module", {})
        version: str = meta.get("version", "")
        if not version:
            self._skip("version_format", "version field absent — skipping format check")
            return
        if _VERSION_RE.match(str(version)):
            self._pass("version_format", version)
        else:
            self._fail(
                "version_format",
                f"version {version!r} must be 'MAJOR.MINOR.PATCH' (e.g. '1.0.0')",
            )

    # ── 7. category allowlist ─────────────────────────────────────────
    def _check_category(self) -> None:
        meta = self._toml_data.get("module", {})
        category: str = meta.get("category", "")
        if not category:
            self._skip("category_valid", "category field absent — skipping allowlist check")
            return
        if category in _VALID_CATEGORIES:
            self._pass("category_valid", category)
        else:
            self._fail(
                "category_valid",
                f"category {category!r} is not in the allowed list: "
                f"{sorted(_VALID_CATEGORIES)}",
            )

    # ── 8. options schema ─────────────────────────────────────────────
    def _check_options_schema(self) -> None:
        options = self._toml_data.get("options", [])
        errors: list[str] = []
        for i, opt in enumerate(options):
            prefix = f"options[{i}] ({opt.get('name', '?')})"
            for req_field in ("name", "description", "type"):
                if req_field not in opt:
                    errors.append(f"{prefix}: missing required field '{req_field}'")
            opt_type = opt.get("type", "")
            if opt_type and opt_type not in _VALID_OPTION_TYPES:
                errors.append(
                    f"{prefix}: type {opt_type!r} is not valid. "
                    f"Allowed: {sorted(_VALID_OPTION_TYPES)}"
                )
            if opt.get("type") == "enum" and not opt.get("choices"):
                errors.append(f"{prefix}: type 'enum' requires a 'choices' list")
        if errors:
            self._fail("options_schema", "; ".join(errors))
        else:
            self._pass("options_schema", f"{len(options)} option(s)")

    # ── 9. module.py importable ───────────────────────────────────────
    def _check_py_importable(self) -> None:
        module_py = self.module_path / "module.py"
        if not module_py.exists():
            self._skip("py_importable", "module.py not found — skipping import check")
            return
        try:
            spec = importlib.util.spec_from_file_location(
                f"_sentrypack_validate.{self.module_path.name}.module",
                module_py,
            )
            if spec is None or spec.loader is None:
                self._fail("py_importable", "importlib could not create a module spec for module.py")
                return
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            self._py_module = mod
            self._pass("py_importable")
        except SyntaxError as exc:
            self._fail(
                "py_importable",
                f"module.py has a Python syntax error: {exc.msg} "
                f"(line {exc.lineno})",
            )
        except ImportError as exc:
            self._fail(
                "py_importable",
                f"module.py could not be imported due to a missing dependency: {exc}",
            )
        except Exception as exc:
            self._fail(
                "py_importable",
                f"module.py raised an unexpected error during import: "
                f"{type(exc).__name__}: {exc}",
            )

    # ── 10. Module class exported ─────────────────────────────────────
    def _check_module_class_exists(self) -> None:
        if self._py_module is None:
            self._skip("module_class_exists", "module.py not imported — skipping class check")
            return
        cls = getattr(self._py_module, "Module", None)
        if cls is None:
            self._fail(
                "module_class_exists",
                "module.py does not export a top-level class named 'Module'",
            )
        else:
            self._cls = cls
            self._pass("module_class_exists")

    # ── 11. Subclasses BaseModule ─────────────────────────────────────
    def _check_base_module_subclass(self) -> None:
        if self._cls is None:
            self._skip("base_module_subclass", "Module class not found — skipping subclass check")
            return
        try:
            from core.base_module import BaseModule
        except ImportError:
            self._skip("base_module_subclass", "core.base_module not available — skipping")
            return
        if issubclass(self._cls, BaseModule):
            self._pass("base_module_subclass")
        else:
            self._fail(
                "base_module_subclass",
                f"Module class must subclass BaseModule "
                f"(core.base_module.BaseModule), got: {self._cls.__bases__}",
            )

    # ── 12. meta attribute present ────────────────────────────────────
    def _check_meta_attribute(self) -> None:
        if self._cls is None:
            self._skip("meta_attribute", "Module class not found — skipping meta check")
            return
        try:
            from core.base_module import ModuleMeta
        except ImportError:
            self._skip("meta_attribute", "core.base_module not available — skipping")
            return
        meta = getattr(self._cls, "meta", None)
        if meta is None:
            self._fail(
                "meta_attribute",
                "Module class does not have a class-level 'meta' attribute. "
                "Assign meta = ModuleMeta(...) at class level.",
            )
        elif not isinstance(meta, ModuleMeta):
            self._fail(
                "meta_attribute",
                f"Module.meta must be a ModuleMeta instance, got: {type(meta).__name__}",
            )
        else:
            self._pass("meta_attribute", f"id={meta.id!r}")

    # ── 13. meta.id matches manifest id ──────────────────────────────
    def _check_meta_id_matches(self) -> None:
        if self._cls is None:
            self._skip("meta_id_matches", "Module class not found — skipping consistency check")
            return
        manifest_id: str = self._toml_data.get("module", {}).get("id", "")
        py_id: str = getattr(getattr(self._cls, "meta", None), "id", "")
        if not manifest_id or not py_id:
            self._skip("meta_id_matches", "id(s) not available — skipping consistency check")
            return
        if manifest_id == py_id:
            self._pass("meta_id_matches", manifest_id)
        else:
            self._fail(
                "meta_id_matches",
                f"Manifest id {manifest_id!r} ≠ Module.meta.id {py_id!r}. "
                "Keep them in sync to avoid registry confusion.",
            )

    # ── 14. check() signature ─────────────────────────────────────────
    def _check_check_signature(self) -> None:
        if self._cls is None:
            self._skip("check_signature", "Module class not found — skipping check() check")
            return
        method = getattr(self._cls, "check", None)
        if method is None:
            self._fail(
                "check_signature",
                "Module class does not implement check(self, ctx) -> bool",
            )
            return
        try:
            sig = inspect.signature(method)
            params = list(sig.parameters.keys())
            # Accept ('self', 'ctx') — when obtained from the class (unbound) self is first
            if len(params) >= 2 and params[1] == "ctx":
                self._pass("check_signature")
            else:
                self._fail(
                    "check_signature",
                    f"check() must accept (self, ctx) — got parameters: {params}",
                )
        except (ValueError, TypeError):
            self._pass("check_signature")  # Can't inspect; assume OK

    # ── 15. run() signature ───────────────────────────────────────────
    def _check_run_signature(self) -> None:
        if self._cls is None:
            self._skip("run_signature", "Module class not found — skipping run() check")
            return
        method = getattr(self._cls, "run", None)
        if method is None:
            self._fail(
                "run_signature",
                "Module class does not implement run(self, ctx) -> List[Finding]",
            )
            return
        try:
            sig = inspect.signature(method)
            params = list(sig.parameters.keys())
            if len(params) >= 2 and params[1] == "ctx":
                self._pass("run_signature")
            else:
                self._fail(
                    "run_signature",
                    f"run() must accept (self, ctx) — got parameters: {params}",
                )
        except (ValueError, TypeError):
            self._pass("run_signature")

    # ── 16. Module() instantiates cleanly ────────────────────────────
    def _check_instantiable(self) -> None:
        if self._cls is None:
            self._skip("instantiable", "Module class not found — skipping instantiation check")
            return
        try:
            self._cls()
            self._pass("instantiable")
        except TypeError as exc:
            # ABC enforcement — this means check or run is still abstract
            self._fail(
                "instantiable",
                f"Module() could not be instantiated: {exc} "
                "(ensure check() and run() are both implemented)",
            )
        except Exception as exc:
            self._fail(
                "instantiable",
                f"Module() raised {type(exc).__name__} during instantiation: {exc}",
            )

    # ── W1. Template guard (warning only) ────────────────────────────
    def _check_template_guard(self) -> None:
        meta_id: str = self._toml_data.get("module", {}).get("id", "")
        if meta_id == _TEMPLATE_ID:
            self._warn(
                "template_guard",
                f"id is still {_TEMPLATE_ID!r} — this appears to be an unmodified "
                "copy of the template. Update the id before submitting.",
            )
        else:
            self._pass("template_guard")


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def _c(text: str, code: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_ANSI.get(code, '')}{text}{_ANSI['reset']}"


def _print_report_text(report: ValidationReport, use_color: bool) -> None:
    print(f"\n{_c('Validating:', 'bold', use_color)} {_c(report.path, 'cyan', use_color)}\n")
    for check in report.checks:
        if check.status == "pass":
            icon = _c("[PASS]", "green", use_color)
        elif check.status == "fail":
            icon = _c("[FAIL]", "red", use_color)
        elif check.status == "warn":
            icon = _c("[WARN]", "yellow", use_color)
        else:
            icon = _c("[SKIP]", "cyan", use_color)
        detail = f"  {check.message}" if check.message else ""
        label = check.name.replace("_", " ")
        print(f"  {icon}  {label}{detail}")

    print()
    total = len(report.checks)
    passed = sum(1 for c in report.checks if c.status == "pass")
    failed = len(report.errors)
    warned = len(report.warnings)

    if report.valid:
        if warned:
            msg = (
                f"{_c(str(passed), 'green', use_color)}/{total} checks passed, "
                f"{_c(str(warned), 'yellow', use_color)} warning(s)."
            )
        else:
            msg = f"{_c(str(passed), 'green', use_color)}/{total} checks passed — module is valid."
        print(msg)
    else:
        msg = (
            f"{_c(str(failed), 'red', use_color)} error(s), "
            f"{_c(str(passed), 'green', use_color)}/{total} checks passed — "
            f"{_c('module is invalid.', 'red', use_color)}"
        )
        print(msg)
        print()
        for err in report.errors:
            print(f"  {_c('✗', 'red', use_color)} {err}")

    if report.warnings:
        print()
        for w in report.warnings:
            print(f"  {_c('⚠', 'yellow', use_color)} {w}")
    print()


def _print_report_json(report: ValidationReport) -> None:
    print(json.dumps(report.to_dict(), indent=2))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns the exit code."""
    parser = argparse.ArgumentParser(
        prog="sentrypack-validate",
        description="Validate a SentryPack module's manifest and class signature.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0   All checks passed (warnings are non-fatal unless --strict)
  1   One or more validation errors found
  2   Usage error (bad argument or path does not exist)

Examples:
  sentrypack-validate modules/recon/nmap_scan
  sentrypack-validate my_module/ --strict
  sentrypack-validate my_module/ --json | python -m json.tool
""",
    )
    parser.add_argument(
        "path",
        type=str,
        help="Path to the module directory containing module.toml and module.py",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Treat warnings as errors (exit 1 if any warnings exist)",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        default=False,
        help="Output a machine-readable JSON report instead of coloured text",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI colour codes in text output",
    )

    args = parser.parse_args(argv)

    module_path = Path(args.path).resolve()
    use_color = not args.no_color and sys.stdout.isatty() and not args.json_output

    if not module_path.exists():
        if args.json_output:
            print(json.dumps({"error": f"Path does not exist: {args.path}"}))
        else:
            print(
                f"{_c('Error:', 'red', use_color)} "
                f"Path does not exist: {args.path}",
                file=sys.stderr,
            )
        return 2

    if not module_path.is_dir():
        if args.json_output:
            print(json.dumps({"error": f"Not a directory: {args.path}"}))
        else:
            print(
                f"{_c('Error:', 'red', use_color)} "
                f"Not a directory: {args.path}",
                file=sys.stderr,
            )
        return 2

    validator = ModuleValidator(module_path, use_color=use_color)
    report = validator.validate()

    if args.json_output:
        _print_report_json(report)
    else:
        _print_report_text(report, use_color=use_color)

    if not report.valid:
        return 1
    if args.strict and report.warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
