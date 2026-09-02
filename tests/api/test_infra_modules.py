"""
Integration tests for Infrastructure Modules API Routes (/api/infra_modules).

Verifies:
  ✓ GET /api/infra_modules/ lists registered modules
  ✓ GET /api/infra_modules/{id} returns module detail (404 on nonexistent)
  ✓ POST /api/infra_modules/{id}/enable toggles module state
  ✓ POST /api/infra_modules/{id}/disable deactivates module
  ✓ POST /api/infra_modules/{id}/configure updates configuration
  ✓ POST /api/infra_modules/{id}/associate creates project/transport associations
  ✓ GET /api/infra_modules/{id}/associations retrieves associations
  ✓ Invalid associate requests return 400 Bad Request
"""

from __future__ import annotations

from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from api.main import app
from core.infra_registry import infra_registry

client = TestClient(app)
INFRA_DIR = Path(__file__).resolve().parent.parent.parent / "modules" / "infra"


@pytest.fixture(autouse=True)
def setup_infra_registry():
    """Ensure actual infrastructure modules are scanned for API tests."""
    infra_registry.scan(INFRA_DIR)


def test_list_infra_modules():
    resp = client.get("/api/infra_modules/")
    assert resp.status_code == 200
    data = resp.json()
    assert "infra_modules" in data
    assert "count" in data
    assert isinstance(data["infra_modules"], list)
    assert data["count"] >= 1

    module_ids = [m["id"] for m in data["infra_modules"]]
    assert "infra.https_proxy" in module_ids


def test_get_infra_module_detail():
    resp = client.get("/api/infra_modules/infra.https_proxy")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "infra.https_proxy"
    assert data["name"] == "HTTP/S Proxy Infrastructure Module"
    assert data["category"] == "proxy"
    assert "connect_tunnel" in data["capabilities"]
    assert "status" in data
    assert "associations" in data


def test_get_nonexistent_infra_module_returns_404():
    resp = client.get("/api/infra_modules/infra.nonexistent")
    assert resp.status_code == 404


def test_configure_infra_module():
    resp = client.post(
        "/api/infra_modules/infra.https_proxy/configure",
        json={"config": {"proxy_host": "127.0.0.1", "proxy_port": 8080, "target_host": "127.0.0.1", "target_port": 443}},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["module_id"] == "infra.https_proxy"
    assert data["configured"] is True


def test_configure_nonexistent_returns_404():
    resp = client.post(
        "/api/infra_modules/infra.nonexistent/configure",
        json={"config": {}},
    )
    assert resp.status_code == 404


def test_enable_and_disable_infra_module():
    # Attempting enable without live proxy will fail cleanly -> status="error"
    enable_resp = client.post("/api/infra_modules/infra.https_proxy/enable")
    assert enable_resp.status_code == 200
    enable_data = enable_resp.json()
    assert enable_data["module_id"] == "infra.https_proxy"
    assert enable_data["status"] in ("enabled", "error")

    # Disable
    disable_resp = client.post("/api/infra_modules/infra.https_proxy/disable")
    assert disable_resp.status_code == 200
    disable_data = disable_resp.json()
    assert disable_data["module_id"] == "infra.https_proxy"
    assert disable_data["status"] == "disabled"


def test_enable_nonexistent_returns_404():
    resp = client.post("/api/infra_modules/infra.nonexistent/enable")
    assert resp.status_code == 404


def test_disable_nonexistent_returns_404():
    resp = client.post("/api/infra_modules/infra.nonexistent/disable")
    assert resp.status_code == 404


def test_associate_and_get_associations():
    # Associate with project
    assoc_resp = client.post(
        "/api/infra_modules/infra.https_proxy/associate",
        json={"project_id": 42, "transport_id": "https_proxy"},
    )
    assert assoc_resp.status_code == 200
    data = assoc_resp.json()
    assert data["module_id"] == "infra.https_proxy"
    assert {"project_id": 42, "transport_id": "https_proxy"} in data["associations"]

    # Query associations
    get_resp = client.get("/api/infra_modules/infra.https_proxy/associations")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["module_id"] == "infra.https_proxy"
    assert {"project_id": 42, "transport_id": "https_proxy"} in get_data["associations"]


def test_associate_empty_payload_returns_400():
    resp = client.post(
        "/api/infra_modules/infra.https_proxy/associate",
        json={"project_id": None, "transport_id": None},
    )
    assert resp.status_code == 400


def test_associate_nonexistent_returns_404():
    resp = client.post(
        "/api/infra_modules/infra.nonexistent/associate",
        json={"project_id": 1},
    )
    assert resp.status_code == 404


def test_get_associations_nonexistent_returns_404():
    resp = client.get("/api/infra_modules/infra.nonexistent/associations")
    assert resp.status_code == 404
