"""
Unit tests for Reporting Engine and GET /api/projects/{project_id}/report route.
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
from api.reporting.generator import ReportGenerator

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
def seeded_project(db_session):
    """Seed project with targets and findings."""
    project = Project(
        name="Pentest Engagement Alpha",
        description="Comprehensive external and internal penetration test.",
    )
    db_session.add(project)
    db_session.commit()
    db_session.refresh(project)

    t1 = Target(project_id=project.id, name="web-front", ip_address="192.168.1.10", status="active")
    t2 = Target(project_id=project.id, name="db-backend", ip_address="192.168.1.20", status="idle")
    db_session.add_all([t1, t2])
    db_session.commit()
    db_session.refresh(t1)
    db_session.refresh(t2)

    findings = [
        FindingModel(
            target_id=t1.id,
            title="Log4Shell RCE",
            severity="Critical",
            cve="CVE-2021-44228",
            description="Remote code execution in logging framework.",
            remediation="Upgrade to 2.17.1",
            evidence={"param": "header"},
        ),
        FindingModel(
            target_id=t1.id,
            title="Reflected XSS",
            severity="High",
            description="Unfiltered query reflection.",
        ),
        FindingModel(
            target_id=t2.id,
            title="Missing SSL",
            severity="Medium",
            description="Plaintext DB socket.",
        ),
    ]
    db_session.add_all(findings)
    db_session.commit()
    return project


class TestReportEndpoints:
    def test_get_report_html_200(self, client, seeded_project):
        response = client.get(f"/api/projects/{seeded_project.id}/report?format=html")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "SentryPack Vulnerability Assessment Report" in response.text
        assert "Pentest Engagement Alpha" in response.text
        assert "Log4Shell RCE" in response.text
        assert "CVE-2021-44228" in response.text
        assert "web-front (192.168.1.10)" in response.text

    def test_get_report_default_format_is_html(self, client, seeded_project):
        response = client.get(f"/api/projects/{seeded_project.id}/report")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Pentest Engagement Alpha" in response.text

    def test_get_report_pdf_200(self, client, seeded_project):
        response = client.get(f"/api/projects/{seeded_project.id}/report?format=pdf")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert f'filename="sentrypack_report_{seeded_project.id}.pdf"' in response.headers["content-disposition"]
        assert response.content.startswith(b"%PDF")

    def test_get_report_404_nonexistent_project(self, client):
        response = client.get("/api/projects/9999/report")
        assert response.status_code == 404
        data = response.json()
        assert data.get("error") == "not_found"

    def test_get_report_400_invalid_format(self, client, seeded_project):
        response = client.get(f"/api/projects/{seeded_project.id}/report?format=xml")
        assert response.status_code == 400
        data = response.json()
        assert data.get("error") == "invalid_format"


class TestReportGeneratorLogic:
    def test_empty_findings_report(self, db_session):
        project = Project(name="Clean Project", description="Zero findings project")
        db_session.add(project)
        db_session.commit()
        db_session.refresh(project)

        target = Target(project_id=project.id, name="clean-host", ip_address="10.0.0.99")
        db_session.add(target)
        db_session.commit()

        gen = ReportGenerator()
        html = gen.render_html(project, db_session)
        assert "Clean Project" in html
        assert "No findings recorded for this target." in html

        pdf = gen.render_pdf(project, db_session)
        assert pdf.startswith(b"%PDF")
        assert len(pdf) > 1000

    def test_render_resilience_on_broken_db(self, db_session):
        gen = ReportGenerator()
        # Pass a mock or closed session / invalid project
        broken_project = Project(id=-1, name="Broken")
        html = gen.render_html(broken_project, db_session)
        assert "Broken" in html

        pdf = gen.render_pdf(broken_project, db_session)
        assert pdf.startswith(b"%PDF")
