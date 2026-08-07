"""
Tests for core/base_module.py — verifies OptionType, ModuleOption, ModuleMeta,
Finding, and the BaseModule abstract interface.
"""

from __future__ import annotations

import pytest
from dataclasses import fields

from core.base_module import (
    BaseModule,
    Finding,
    ModuleMeta,
    ModuleOption,
    OptionType,
)


# ---------------------------------------------------------------------------
# OptionType
# ---------------------------------------------------------------------------


class TestOptionType:
    def test_all_members_present(self):
        names = {m.name for m in OptionType}
        assert names == {"STRING", "INTEGER", "BOOLEAN", "ENUM", "FILE_PATH"}

    def test_values_are_strings(self):
        for member in OptionType:
            assert isinstance(member.value, str)


# ---------------------------------------------------------------------------
# ModuleOption
# ---------------------------------------------------------------------------


class TestModuleOption:
    def test_required_fields(self):
        opt = ModuleOption(
            name="TARGET",
            description="Target host",
            option_type=OptionType.STRING,
        )
        assert opt.name == "TARGET"
        assert opt.option_type is OptionType.STRING
        assert opt.required is True
        assert opt.default is None
        assert opt.choices is None

    def test_optional_fields(self):
        opt = ModuleOption(
            name="PROTO",
            description="Protocol",
            option_type=OptionType.ENUM,
            required=False,
            default="tcp",
            choices=["tcp", "udp"],
        )
        assert opt.required is False
        assert opt.default == "tcp"
        assert opt.choices == ["tcp", "udp"]


# ---------------------------------------------------------------------------
# ModuleMeta
# ---------------------------------------------------------------------------


class TestModuleMeta:
    def test_defaults_empty_options_list(self):
        meta = ModuleMeta(
            id="test.mod",
            name="Test",
            description="desc",
            author="Alice",
            version="1.0.0",
            category="recon",
        )
        assert meta.options == []

    def test_options_stored(self):
        opt = ModuleOption("A", "desc", OptionType.BOOLEAN)
        meta = ModuleMeta(
            id="test.mod",
            name="Test",
            description="desc",
            author="Alice",
            version="1.0.0",
            category="recon",
            options=[opt],
        )
        assert len(meta.options) == 1
        assert meta.options[0].name == "A"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class TestFinding:
    def test_required_fields(self):
        f = Finding(title="Open Port", severity="Low", description="Port 22 is open")
        assert f.title == "Open Port"
        assert f.severity == "Low"
        assert f.cve is None
        assert f.cpe is None
        assert f.remediation is None
        assert f.evidence is None

    def test_optional_fields(self):
        f = Finding(
            title="RCE",
            severity="Critical",
            description="Remote code execution via log4j",
            cve="CVE-2021-44228",
            cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
            remediation="Upgrade to log4j 2.17.1",
            evidence={"poc": "ldap://evil.example"},
        )
        assert f.cve == "CVE-2021-44228"
        assert f.evidence == {"poc": "ldap://evil.example"}


# ---------------------------------------------------------------------------
# BaseModule — abstract interface enforcement
# ---------------------------------------------------------------------------


class TestBaseModuleABC:
    def test_cannot_instantiate_without_check_and_run(self):
        """BaseModule must not be instantiable if check or run is absent."""

        with pytest.raises(TypeError):
            BaseModule()  # type: ignore[abstract]

    def test_cannot_instantiate_missing_run(self):
        class OnlyCheck(BaseModule):
            meta = ModuleMeta("x", "x", "x", "x", "0", "recon")

            def check(self, ctx):
                return True

        with pytest.raises(TypeError):
            OnlyCheck()

    def test_cannot_instantiate_missing_check(self):
        class OnlyRun(BaseModule):
            meta = ModuleMeta("x", "x", "x", "x", "0", "recon")

            def run(self, ctx):
                return []

        with pytest.raises(TypeError):
            OnlyRun()

    def test_options_default_to_empty_dict(self):
        class Concrete(BaseModule):
            meta = ModuleMeta("x", "x", "x", "x", "0", "recon")

            def check(self, ctx):
                return True

            def run(self, ctx):
                return []

        mod = Concrete()
        assert mod.options == {}

    def test_options_passed_through(self):
        class Concrete(BaseModule):
            meta = ModuleMeta("x", "x", "x", "x", "0", "recon")

            def check(self, ctx):
                return True

            def run(self, ctx):
                return []

        mod = Concrete(options={"TARGET": "10.0.0.1"})
        assert mod.options["TARGET"] == "10.0.0.1"
