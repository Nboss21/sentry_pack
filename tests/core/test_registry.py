from pathlib import Path
import pytest
from core.registry import ModuleRegistry
from core.base_module import BaseModule, ModuleMeta


def test_registry_scan(modules_dir):
    registry = ModuleRegistry(modules_dir)
    modules = registry.scan()
    assert isinstance(modules, dict)
    assert "recon.nmap_scan" in modules
    assert registry.is_loaded("recon.nmap_scan")
    
    nmap_meta = modules["recon.nmap_scan"]
    assert len(nmap_meta.options) > 0
    option_names = [opt.name for opt in nmap_meta.options]
    assert "TARGET" in option_names

    entry = registry.get("recon.nmap_scan")
    assert entry is not None
    assert isinstance(entry["meta"], ModuleMeta)
    assert issubclass(entry["class"], BaseModule)
    assert len(registry.list_all()) >= 1



def test_valid_module_load(tmp_path):
    mod_dir = tmp_path / "valid_mod"
    mod_dir.mkdir()
    manifest = mod_dir / "module.toml"
    manifest.write_text(
        '[module]\nid = "test.valid"\nname = "Valid Module"\ndescription = "Test"\nauthor = "Tester"\nversion = "1.0.0"\ncategory = "test"\n'
    )
    module_py = mod_dir / "module.py"
    module_py.write_text(
        "from core.base_module import BaseModule\nclass Module(BaseModule):\n    def run(self, ctx):\n        return []\n"
    )

    registry = ModuleRegistry(tmp_path)
    loaded = registry.scan()

    assert "test.valid" in loaded
    assert registry.is_loaded("test.valid")
    assert registry.is_loaded("Valid Module")
    entry = registry.get("test.valid")
    assert entry["meta"].name == "Valid Module"


def test_missing_module_toml(tmp_path):
    mod_dir = tmp_path / "missing_toml_mod"
    mod_dir.mkdir()
    module_py = mod_dir / "module.py"
    module_py.write_text("class Module: pass")

    registry = ModuleRegistry(tmp_path)
    loaded = registry.scan()

    assert len(loaded) == 0


def test_malformed_toml(tmp_path):
    mod_dir = tmp_path / "bad_toml_mod"
    mod_dir.mkdir()
    manifest = mod_dir / "module.toml"
    manifest.write_text("[module\nid = invalid_toml_format")

    registry = ModuleRegistry(tmp_path)
    loaded = registry.scan()

    assert len(loaded) == 0


def test_missing_required_field(tmp_path):
    mod_dir = tmp_path / "missing_field_mod"
    mod_dir.mkdir()
    manifest = mod_dir / "module.toml"
    # Missing 'author' and 'version'
    manifest.write_text(
        '[module]\nid = "test.incomplete"\nname = "Incomplete Module"\ndescription = "Test"\ncategory = "test"\n'
    )
    module_py = mod_dir / "module.py"
    module_py.write_text("class Module: pass")

    registry = ModuleRegistry(tmp_path)
    loaded = registry.scan()

    assert "test.incomplete" not in loaded
    assert not registry.is_loaded("test.incomplete")


def test_entry_point_import_error(tmp_path):
    mod_dir = tmp_path / "import_error_mod"
    mod_dir.mkdir()
    manifest = mod_dir / "module.toml"
    manifest.write_text(
        '[module]\nid = "test.syntax_error"\nname = "Syntax Error Module"\ndescription = "Test"\nauthor = "Tester"\nversion = "1.0.0"\ncategory = "test"\n'
    )
    module_py = mod_dir / "module.py"
    # Invalid syntax in Python file
    module_py.write_text("def broken_func(: syntax error here")

    registry = ModuleRegistry(tmp_path)
    loaded = registry.scan()

    assert "test.syntax_error" not in loaded
    assert not registry.is_loaded("test.syntax_error")

