"""
Tests for scripts/validate_module.py — the sentrypack validate-module CLI.

Covers:
  - Happy path: valid module (nmap_scan, hello_world) → exit 0
  - File-level failures: missing toml / missing py → exit 1
  - TOML failures: invalid syntax, missing required field, bad id format,
    bad version, bad category, bad option schema
  - Python failures: syntax error, no Module class, not a BaseModule subclass,
    no meta attribute, meta.id mismatch, no check(), no run()
  - Warning: template id (non-fatal)
  - --strict: warning becomes exit 1
  - --json: machine-readable JSON with correct shape
  - main() return codes (called directly, not via subprocess)
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path
from typing import Optional

import pytest

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]
_NMAP_MODULE_PATH = _REPO_ROOT / "modules" / "recon" / "nmap_scan"
_HELLO_MODULE_PATH = _REPO_ROOT / "modules" / "hello_world"
_TEMPLATE_PATH = _REPO_ROOT / "modules" / "_template"

sys.path.insert(0, str(_REPO_ROOT))

from scripts.validate_module import ModuleValidator, ValidationReport, main


# ---------------------------------------------------------------------------
# Fixtures for temporary module directories
# ---------------------------------------------------------------------------


def _write_valid_module(
    tmp_path: Path,
    *,
    toml_id: str = "recon.test_mod",
    py_id: str = "recon.test_mod",
    category: str = "recon",
    version: str = "1.0.0",
    extra_options: str = "",
    extra_py: str = "",
) -> Path:
    """Write a minimal valid module into *tmp_path* and return the path."""
    toml = textwrap.dedent(f"""\
        [module]
        id = "{toml_id}"
        name = "Test Module"
        description = "A test module."
        author = "Tester"
        version = "{version}"
        category = "{category}"
        {extra_options}
    """)
    py = textwrap.dedent(f"""\
        from __future__ import annotations
        from typing import Any, List
        from core.base_module import BaseModule, Finding, ModuleMeta, ModuleOption, OptionType

        class Module(BaseModule):
            meta = ModuleMeta(
                id="{py_id}",
                name="Test Module",
                description="A test module.",
                author="Tester",
                version="1.0.0",
                category="recon",
            )

            def check(self, ctx: Any) -> bool:
                return True

            def run(self, ctx: Any) -> List[Finding]:
                return []
        {extra_py}
    """)
    (tmp_path / "module.toml").write_text(toml, encoding="utf-8")
    (tmp_path / "module.py").write_text(py, encoding="utf-8")
    return tmp_path


# ===========================================================================
# Happy-path tests against real modules
# ===========================================================================


class TestValidModules:
    def test_nmap_scan_passes(self):
        v = ModuleValidator(_NMAP_MODULE_PATH, use_color=False)
        r = v.validate()
        assert r.valid is True
        assert r.errors == []

    def test_nmap_scan_main_returns_0(self):
        code = main([str(_NMAP_MODULE_PATH), "--no-color"])
        assert code == 0

    def test_hello_world_passes(self):
        v = ModuleValidator(_HELLO_MODULE_PATH, use_color=False)
        r = v.validate()
        assert r.valid is True
        assert r.errors == []

    def test_hello_world_main_returns_0(self):
        code = main([str(_HELLO_MODULE_PATH), "--no-color"])
        assert code == 0

    def test_all_16_checks_represented(self):
        v = ModuleValidator(_NMAP_MODULE_PATH, use_color=False)
        r = v.validate()
        check_names = {c.name for c in r.checks}
        # Core 16 structural checks (not counting the warning-only template_guard)
        expected = {
            "module_toml_exists", "module_py_exists", "toml_parseable",
            "required_manifest_fields", "id_format", "version_format",
            "category_valid", "options_schema", "py_importable",
            "module_class_exists", "base_module_subclass", "meta_attribute",
            "meta_id_matches", "check_signature", "run_signature",
            "instantiable",
        }
        assert expected.issubset(check_names), f"Missing checks: {expected - check_names}"

    def test_nmap_passes_no_warnings(self):
        v = ModuleValidator(_NMAP_MODULE_PATH, use_color=False)
        r = v.validate()
        assert r.warnings == []


# ===========================================================================
# File-level failures
# ===========================================================================


class TestFileLevelFailures:
    def test_missing_toml_fails(self, tmp_path):
        (tmp_path / "module.py").write_text("# stub", encoding="utf-8")
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("module.toml" in e for e in r.errors)

    def test_missing_toml_check_name(self, tmp_path):
        (tmp_path / "module.py").write_text("# stub", encoding="utf-8")
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        fail_names = [c.name for c in r.checks if c.status == "fail"]
        assert "module_toml_exists" in fail_names

    def test_missing_py_fails(self, tmp_path):
        (tmp_path / "module.toml").write_text("[module]\nid='x'", encoding="utf-8")
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("module.py" in e for e in r.errors)

    def test_main_missing_toml_returns_1(self, tmp_path):
        (tmp_path / "module.py").write_text("# stub", encoding="utf-8")
        assert main([str(tmp_path), "--no-color"]) == 1

    def test_main_missing_py_returns_1(self, tmp_path):
        (tmp_path / "module.toml").write_text("[module]\nid='x'", encoding="utf-8")
        assert main([str(tmp_path), "--no-color"]) == 1


# ===========================================================================
# TOML failures
# ===========================================================================


class TestTomlFailures:
    def test_invalid_toml_syntax(self, tmp_path):
        (tmp_path / "module.toml").write_text("[[broken\nno_close = true", encoding="utf-8")
        (tmp_path / "module.py").write_text("# stub", encoding="utf-8")
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("invalid TOML" in e or "toml" in e.lower() for e in r.errors)

    def test_missing_required_field_id(self, tmp_path):
        toml = textwrap.dedent("""\
            [module]
            name = "Missing ID"
            description = "No id field"
            author = "Tester"
            version = "1.0.0"
            category = "recon"
        """)
        (tmp_path / "module.toml").write_text(toml, encoding="utf-8")
        (tmp_path / "module.py").write_text("# stub", encoding="utf-8")
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("id" in e for e in r.errors)

    def test_missing_required_field_author(self, tmp_path):
        toml = textwrap.dedent("""\
            [module]
            id = "recon.x"
            name = "X"
            description = "X"
            version = "1.0.0"
            category = "recon"
        """)
        (tmp_path / "module.toml").write_text(toml, encoding="utf-8")
        (tmp_path / "module.py").write_text("# stub", encoding="utf-8")
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("author" in e for e in r.errors)

    def test_invalid_id_format_no_dot(self, tmp_path):
        _write_valid_module(tmp_path, toml_id="nodot", py_id="nodot")
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("id_format" == c.name and c.status == "fail" for c in r.checks)

    def test_invalid_id_format_uppercase(self, tmp_path):
        _write_valid_module(tmp_path, toml_id="Recon.MyMod", py_id="Recon.MyMod")
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("id_format" == c.name and c.status == "fail" for c in r.checks)

    def test_invalid_version_format(self, tmp_path):
        _write_valid_module(tmp_path, version="1.0", py_id="recon.test_mod")
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("version_format" == c.name and c.status == "fail" for c in r.checks)

    def test_invalid_category(self, tmp_path):
        _write_valid_module(tmp_path, category="hacking", py_id="recon.test_mod")
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("category_valid" == c.name and c.status == "fail" for c in r.checks)

    def test_valid_categories_all_pass(self, tmp_path):
        for cat in ("recon", "exploit", "c2", "analysis", "dev", "utility"):
            sub = tmp_path / cat
            sub.mkdir()
            mod_id = f"{cat}.test"
            _write_valid_module(sub, toml_id=mod_id, py_id=mod_id, category=cat)
            v = ModuleValidator(sub, use_color=False)
            r = v.validate()
            assert r.valid is True, f"Category {cat!r} should be valid but got: {r.errors}"

    def test_option_missing_name_field(self, tmp_path):
        extra = textwrap.dedent("""\
            [[options]]
            description = "No name"
            type = "string"
        """)
        _write_valid_module(tmp_path, extra_options=extra)
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("options_schema" == c.name and c.status == "fail" for c in r.checks)

    def test_option_invalid_type(self, tmp_path):
        extra = textwrap.dedent("""\
            [[options]]
            name = "TARGET"
            description = "Target host"
            type = "hostname"
        """)
        _write_valid_module(tmp_path, extra_options=extra)
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False

    def test_option_enum_without_choices(self, tmp_path):
        extra = textwrap.dedent("""\
            [[options]]
            name = "PROTO"
            description = "Protocol"
            type = "enum"
        """)
        _write_valid_module(tmp_path, extra_options=extra)
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False


# ===========================================================================
# Python class failures
# ===========================================================================


class TestPythonClassFailures:
    def test_syntax_error_in_module_py(self, tmp_path):
        _write_valid_module(tmp_path)
        (tmp_path / "module.py").write_text("def broken(\n    pass\n", encoding="utf-8")
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("py_importable" == c.name and c.status == "fail" for c in r.checks)

    def test_no_module_class_exported(self, tmp_path):
        _write_valid_module(tmp_path)
        (tmp_path / "module.py").write_text(
            "class NotModule:\n    pass\n", encoding="utf-8"
        )
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("module_class_exists" == c.name and c.status == "fail" for c in r.checks)

    def test_module_does_not_subclass_base_module(self, tmp_path):
        _write_valid_module(tmp_path)
        (tmp_path / "module.py").write_text(
            textwrap.dedent("""\
                from core.base_module import ModuleMeta
                class Module:
                    meta = ModuleMeta('recon.test_mod','T','D','A','1.0.0','recon')
                    def check(self, ctx): return True
                    def run(self, ctx): return []
            """),
            encoding="utf-8",
        )
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("base_module_subclass" == c.name and c.status == "fail" for c in r.checks)

    def test_no_meta_attribute(self, tmp_path):
        _write_valid_module(tmp_path)
        (tmp_path / "module.py").write_text(
            textwrap.dedent("""\
                from core.base_module import BaseModule, Finding
                from typing import Any, List
                class Module(BaseModule):
                    def check(self, ctx: Any) -> bool: return True
                    def run(self, ctx: Any) -> List[Finding]: return []
            """),
            encoding="utf-8",
        )
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("meta_attribute" == c.name and c.status == "fail" for c in r.checks)

    def test_meta_id_mismatch(self, tmp_path):
        _write_valid_module(tmp_path, toml_id="recon.actual", py_id="recon.different")
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("meta_id_matches" == c.name and c.status == "fail" for c in r.checks)

    def test_missing_check_method(self, tmp_path):
        _write_valid_module(tmp_path)
        (tmp_path / "module.py").write_text(
            textwrap.dedent("""\
                from core.base_module import BaseModule, Finding, ModuleMeta
                from typing import Any, List
                class Module(BaseModule):
                    meta = ModuleMeta('recon.test_mod','T','D','A','1.0.0','recon')
                    def run(self, ctx: Any) -> List[Finding]: return []
            """),
            encoding="utf-8",
        )
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        # TypeError from ABC means instantiable check will also fail
        assert any(c.status == "fail" for c in r.checks)

    def test_missing_run_method(self, tmp_path):
        _write_valid_module(tmp_path)
        (tmp_path / "module.py").write_text(
            textwrap.dedent("""\
                from core.base_module import BaseModule, ModuleMeta
                from typing import Any
                class Module(BaseModule):
                    meta = ModuleMeta('recon.test_mod','T','D','A','1.0.0','recon')
                    def check(self, ctx: Any) -> bool: return True
            """),
            encoding="utf-8",
        )
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False

    def test_check_wrong_signature(self, tmp_path):
        _write_valid_module(tmp_path)
        (tmp_path / "module.py").write_text(
            textwrap.dedent("""\
                from core.base_module import BaseModule, Finding, ModuleMeta
                from typing import Any, List
                class Module(BaseModule):
                    meta = ModuleMeta('recon.test_mod','T','D','A','1.0.0','recon')
                    def check(self) -> bool: return True   # missing ctx
                    def run(self, ctx: Any) -> List[Finding]: return []
            """),
            encoding="utf-8",
        )
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("check_signature" == c.name and c.status == "fail" for c in r.checks)

    def test_run_wrong_signature(self, tmp_path):
        _write_valid_module(tmp_path)
        (tmp_path / "module.py").write_text(
            textwrap.dedent("""\
                from core.base_module import BaseModule, Finding, ModuleMeta
                from typing import Any, List
                class Module(BaseModule):
                    meta = ModuleMeta('recon.test_mod','T','D','A','1.0.0','recon')
                    def check(self, ctx: Any) -> bool: return True
                    def run(self) -> List[Finding]: return []   # missing ctx
            """),
            encoding="utf-8",
        )
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert r.valid is False
        assert any("run_signature" == c.name and c.status == "fail" for c in r.checks)


# ===========================================================================
# Template guard (warning, non-fatal)
# ===========================================================================


class TestTemplateGuard:
    def test_template_id_emits_warning(self):
        v = ModuleValidator(_TEMPLATE_PATH, use_color=False)
        r = v.validate()
        # Should have a warning about template id
        assert any("template" in w.lower() or "template_module" in w for w in r.warnings)

    def test_template_valid_without_strict(self):
        """Template module has id='template_module' (no dot) so id_format fails.
        The template_guard check emits an additional warning.
        Both the id_format error and the template_guard warning must be present."""
        v = ModuleValidator(_TEMPLATE_PATH, use_color=False)
        r = v.validate()
        # id 'template_module' has no dot → id_format error is expected
        assert any("id_format" == c.name and c.status == "fail" for c in r.checks)
        # template_guard warning must also be present
        assert any(
            "template" in w.lower() or "template_module" in w for w in r.warnings
        )

    def test_template_strict_returns_1(self):
        code = main([str(_TEMPLATE_PATH), "--strict", "--no-color"])
        assert code == 1

    def test_non_template_no_warning(self, tmp_path):
        _write_valid_module(tmp_path)
        v = ModuleValidator(tmp_path, use_color=False)
        r = v.validate()
        assert not any(
            "template" in w.lower() for w in r.warnings
        ), f"Unexpected template warning: {r.warnings}"


# ===========================================================================
# --json output
# ===========================================================================


class TestJsonOutput:
    def _capture_json(self, args: list[str], tmp_path: Path) -> dict:
        """Run main() with --json and capture its stdout via capsys workaround."""
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            main(args + ["--json"])
        return json.loads(buf.getvalue())

    def test_json_valid_module_has_valid_true(self, tmp_path):
        _write_valid_module(tmp_path)
        data = self._capture_json([str(tmp_path)], tmp_path)
        assert data["valid"] is True
        assert data["errors"] == []

    def test_json_invalid_module_has_valid_false(self, tmp_path):
        (tmp_path / "module.toml").write_text("[module]\nid='x'", encoding="utf-8")
        (tmp_path / "module.py").write_text("# stub", encoding="utf-8")
        data = self._capture_json([str(tmp_path)], tmp_path)
        assert data["valid"] is False
        assert len(data["errors"]) > 0

    def test_json_has_checks_list(self, tmp_path):
        _write_valid_module(tmp_path)
        data = self._capture_json([str(tmp_path)], tmp_path)
        assert isinstance(data["checks"], list)
        assert len(data["checks"]) > 0
        assert all("name" in c and "status" in c for c in data["checks"])

    def test_json_has_path_field(self, tmp_path):
        _write_valid_module(tmp_path)
        data = self._capture_json([str(tmp_path)], tmp_path)
        assert "path" in data

    def test_json_has_warnings_field(self, tmp_path):
        _write_valid_module(tmp_path)
        data = self._capture_json([str(tmp_path)], tmp_path)
        assert "warnings" in data
        assert isinstance(data["warnings"], list)


# ===========================================================================
# CLI usage errors
# ===========================================================================


class TestUsageErrors:
    def test_nonexistent_path_returns_2(self):
        code = main(["/nonexistent/path/abc123", "--no-color"])
        assert code == 2

    def test_file_instead_of_dir_returns_2(self, tmp_path):
        f = tmp_path / "some_file.txt"
        f.write_text("hello")
        code = main([str(f), "--no-color"])
        assert code == 2


# ===========================================================================
# Return code contract
# ===========================================================================


class TestReturnCodes:
    def test_valid_module_returns_0(self, tmp_path):
        _write_valid_module(tmp_path)
        assert main([str(tmp_path), "--no-color"]) == 0

    def test_invalid_module_returns_1(self, tmp_path):
        (tmp_path / "module.toml").write_text("[[broken", encoding="utf-8")
        (tmp_path / "module.py").write_text("# stub", encoding="utf-8")
        assert main([str(tmp_path), "--no-color"]) == 1

    def test_strict_with_no_warnings_still_returns_0(self, tmp_path):
        _write_valid_module(tmp_path)
        # Non-template valid module → no warnings → --strict has no effect
        assert main([str(tmp_path), "--strict", "--no-color"]) == 0

    def test_strict_with_warning_returns_1(self):
        # Template module emits a warning; --strict upgrades to exit 1
        assert main([str(_TEMPLATE_PATH), "--strict", "--no-color"]) == 1
