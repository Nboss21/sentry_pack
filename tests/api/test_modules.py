from api.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_get_modules_endpoint():
    response = client.get("/api/modules/")
    assert response.status_code == 200
    data = response.json()
    assert "modules" in data
    modules = data["modules"]
    assert isinstance(modules, list)

    nmap_module = next((m for m in modules if m["id"] == "recon.nmap_scan"), None)
    assert nmap_module is not None
    assert "options" in nmap_module
    assert len(nmap_module["options"]) > 0

    option_names = [opt["name"] for opt in nmap_module["options"]]
    assert "TARGET" in option_names
    assert "PORTS" in option_names
