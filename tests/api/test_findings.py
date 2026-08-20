"""
Tests for GET /api/targets/{id}/findings endpoint.

Uses an isolated in-memory SQLite DB to avoid touching the production data file.
The FastAPI `get_db` dependency is overridden for the duration of each test.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.db.models import Base, FindingModel, Project, Target
from api.db.session import get_db
from api.main import app


# ---------------------------------------------------------------------------
# Isolated test database
# ---------------------------------------------------------------------------

# StaticPool forces every SQLAlchemy session to reuse the *same* underlying
# connection, which is the only way all sessions can share a single
# SQLite :memory: database (each new connection would otherwise get its own
# fresh, empty database).

TEST_DB_URL = "sqlite:///:memory:"

_test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_test_engine)


def _override_get_db():
    db = _TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _setup_db():
    """Create all tables before each test and drop them after."""
    Base.metadata.create_all(bind=_test_engine)
    app.dependency_overrides[get_db] = _override_get_db
    yield
    app.dependency_overrides.pop(get_db, None)
    Base.metadata.drop_all(bind=_test_engine)


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture()
def db_session():
    db = _TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def target(db_session):
    """Insert a Project + Target and return the Target row."""
    project = Project(name="Test Project", description="For findings tests")
    db_session.add(project)
    db_session.commit()
    db_session.refresh(project)

    tgt = Target(
        project_id=project.id,
        name="Test Target",
        ip_address="10.0.0.1",
        status="idle",
    )
    db_session.add(tgt)
    db_session.commit()
    db_session.refresh(tgt)
    return tgt


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestGetFindings:
    # ---- target with findings ----

    def test_returns_200(self, client, db_session, target):
        db_session.add(
            FindingModel(
                target_id=target.id,
                title="Open SSH",
                severity="Info",
                description="Port 22 open",
                evidence={"port": "22"},
            )
        )
        db_session.commit()

        resp = client.get(f"/api/targets/{target.id}/findings")
        assert resp.status_code == 200

    def test_target_id_in_response(self, client, db_session, target):
        resp = client.get(f"/api/targets/{target.id}/findings")
        data = resp.json()
        assert data["target_id"] == target.id

    def test_findings_list_present(self, client, db_session, target):
        resp = client.get(f"/api/targets/{target.id}/findings")
        data = resp.json()
        assert "findings" in data

    def test_correct_number_of_findings(self, client, db_session, target):
        for i in range(3):
            db_session.add(
                FindingModel(
                    target_id=target.id,
                    title=f"Finding {i}",
                    severity="Info",
                    description=f"Description {i}",
                )
            )
        db_session.commit()

        resp = client.get(f"/api/targets/{target.id}/findings")
        data = resp.json()
        assert len(data["findings"]) == 3

    def test_finding_fields_present(self, client, db_session, target):
        db_session.add(
            FindingModel(
                target_id=target.id,
                title="Open RDP",
                severity="High",
                description="Remote Desktop exposed",
                cve="CVE-2019-0708",
                cpe="cpe:/a:microsoft:rdp",
                remediation="Patch immediately",
                evidence={"port": "3389"},
            )
        )
        db_session.commit()

        resp = client.get(f"/api/targets/{target.id}/findings")
        f = resp.json()["findings"][0]

        assert "id" in f
        assert f["title"] == "Open RDP"
        assert f["severity"] == "High"
        assert f["description"] == "Remote Desktop exposed"
        assert f["cve"] == "CVE-2019-0708"
        assert f["cpe"] == "cpe:/a:microsoft:rdp"
        assert f["remediation"] == "Patch immediately"
        assert f["evidence"] == {"port": "3389"}
        assert "created_at" in f

    def test_findings_ordered_newest_first(self, client, db_session, target):
        """Findings must come back ordered newest first (created_at DESC)."""
        from datetime import datetime, timedelta

        base_time = datetime(2026, 1, 1, 12, 0, 0)
        for i in range(3):
            f = FindingModel(
                target_id=target.id,
                title=f"Finding {i}",
                severity="Info",
                description=f"Desc {i}",
            )
            f.created_at = base_time + timedelta(seconds=i)
            db_session.add(f)
        db_session.commit()

        resp = client.get(f"/api/targets/{target.id}/findings")
        titles = [f["title"] for f in resp.json()["findings"]]
        # Newest first means Finding 2, 1, 0
        assert titles == ["Finding 2", "Finding 1", "Finding 0"]

    # ---- target with no findings ----

    def test_no_findings_returns_empty_list(self, client, db_session, target):
        resp = client.get(f"/api/targets/{target.id}/findings")
        data = resp.json()
        assert data == {"target_id": target.id, "findings": []}

    def test_no_findings_status_200(self, client, db_session, target):
        resp = client.get(f"/api/targets/{target.id}/findings")
        assert resp.status_code == 200

    # ---- cross-target isolation ----

    def test_only_returns_findings_for_requested_target(self, client, db_session, target):
        """Findings belonging to a different target must not leak."""
        other_project = Project(name="Other Project", description="")
        db_session.add(other_project)
        db_session.commit()
        db_session.refresh(other_project)

        other_target = Target(
            project_id=other_project.id,
            name="Other Target",
            ip_address="10.0.0.99",
        )
        db_session.add(other_target)
        db_session.commit()
        db_session.refresh(other_target)

        # Finding for the other target
        db_session.add(
            FindingModel(
                target_id=other_target.id,
                title="Other Finding",
                severity="Info",
                description="Should not appear",
            )
        )
        # Finding for our target
        db_session.add(
            FindingModel(
                target_id=target.id,
                title="Our Finding",
                severity="Info",
                description="Should appear",
            )
        )
        db_session.commit()

        resp = client.get(f"/api/targets/{target.id}/findings")
        data = resp.json()
        assert len(data["findings"]) == 1
        assert data["findings"][0]["title"] == "Our Finding"
