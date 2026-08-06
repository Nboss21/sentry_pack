from core.registry import ModuleRegistry

def test_registry_scan(modules_dir):
    registry = ModuleRegistry(modules_dir)
    modules = registry.scan()
    assert isinstance(modules, dict)
    assert "recon.nmap_scan" in modules
