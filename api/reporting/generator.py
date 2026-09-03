"""
Report generator exporting HTML and PDF reports using Jinja2 templates.

PDF export strategy
-------------------
Primary:  WeasyPrint — renders the same Jinja2 HTML template to PDF via CSS
          Paged Media, guaranteeing visual parity between HTML and PDF outputs.
          Requires libpango / libcairo system libraries; if they are absent the
          import will fail silently and the fallback is used instead.

Fallback: ReportLab Platypus — pure-Python programmatic PDF; works on every
          platform without system library requirements.  Layout is equivalent
          but constructed independently from the HTML template.

Both backends are imported lazily so this module always loads even when neither
library is installed — in that case `render_pdf` returns a 1-page error PDF
constructed from scratch.
"""

from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader
from sqlalchemy.orm import Session

from api.db.models import FindingModel, Project, Target

logger = logging.getLogger("sentrypack.reporting")

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
TEMPLATES_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Backend detection (lazy, cached)
# ---------------------------------------------------------------------------

_PDF_BACKEND: Optional[str] = None  # "weasyprint" | "reportlab" | None


def _get_pdf_backend() -> str:
    """
    Detect and cache which PDF backend is available.

    Returns:
        ``"weasyprint"`` if WeasyPrint + its native libs are importable,
        ``"reportlab"`` if only ReportLab is available,
        ``"none"`` if neither is installed.
    """
    global _PDF_BACKEND
    if _PDF_BACKEND is not None:
        return _PDF_BACKEND

    try:
        import weasyprint  # noqa: F401
        _PDF_BACKEND = "weasyprint"
        logger.info("PDF backend: WeasyPrint (primary)")
    except Exception:
        try:
            import reportlab  # noqa: F401
            _PDF_BACKEND = "reportlab"
            logger.warning(
                "WeasyPrint unavailable (missing system libs?); falling back to ReportLab."
            )
        except ImportError:
            _PDF_BACKEND = "none"
            logger.error(
                "No PDF backend available — install weasyprint or reportlab."
            )

    return _PDF_BACKEND


# ---------------------------------------------------------------------------
# Main generator class
# ---------------------------------------------------------------------------


class ReportGenerator:
    """
    Generates structured vulnerability assessment reports in HTML and PDF formats.

    PDF backend selection
    ---------------------
    Call order in :meth:`render_pdf`:

    1. WeasyPrint   — renders from the Jinja2 HTML template via CSS Paged Media.
    2. ReportLab    — programmatic fallback if WeasyPrint is absent.
    3. Minimal stub — last-resort 1-page error PDF if both fail.
    """

    SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

    # Severity → hex colour mapping (shared between backends)
    SEVERITY_HEX = {
        "Critical": "#dc2626",
        "High":     "#ea580c",
        "Medium":   "#ca8a04",
        "Low":      "#2563eb",
        "Info":     "#6b7280",
    }

    # Finding type → display label + CSS class
    FINDING_TYPE_LABELS = {
        "offensive": ("OFFENSIVE", "type-offensive"),
        "defensive": ("DEFENSIVE", "type-defensive"),
        "recon":     ("RECON",     "type-recon"),
    }

    def __init__(self) -> None:
        """Initialise Jinja2 environment with autoescaping enabled."""
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )

    # ------------------------------------------------------------------
    # Context builder
    # ------------------------------------------------------------------

    def _build_context(
        self, project: Project, db: Session
    ) -> Dict[str, Any]:
        """
        Query all targets and their findings for this project.
        Build and return the full template context dict.

        ``finding_type`` is read from ``evidence["finding_type"]`` if present;
        falls back to ``"offensive"`` for findings with a CVE (exploit-oriented),
        ``"defensive"`` for configuration/hardening findings without a CVE, and
        ``"recon"`` for severity ``"Info"`` findings.  This keeps the DB schema
        stable (no migration required).

        Never raises — logs and returns a minimal fallback context on failure.
        """
        try:
            now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
            severity_rank = {s: i for i, s in enumerate(self.SEVERITY_ORDER)}

            targets_data: List[Dict[str, Any]] = []
            severity_counts = {s: 0 for s in self.SEVERITY_ORDER}
            type_counts: Dict[str, int] = {"offensive": 0, "defensive": 0, "recon": 0}
            total_findings = 0

            targets = (
                db.query(Target)
                .filter(Target.project_id == project.id)
                .order_by(Target.id)
                .all()
            )

            for target in targets:
                findings = (
                    db.query(FindingModel)
                    .filter(FindingModel.target_id == target.id)
                    .all()
                )

                # Sort: severity priority (Critical first), then created_at DESC
                findings.sort(
                    key=lambda f: (
                        severity_rank.get(f.severity, 99),
                        -(f.created_at.timestamp() if f.created_at else 0),
                    )
                )

                target_findings_data: List[Dict[str, Any]] = []
                for f in findings:
                    sev = f.severity if f.severity in severity_counts else "Info"
                    severity_counts[sev] += 1
                    total_findings += 1

                    # Derive finding_type
                    evidence = f.evidence if isinstance(f.evidence, dict) else {}
                    finding_type = _derive_finding_type(f, evidence)
                    type_counts[finding_type] = type_counts.get(finding_type, 0) + 1

                    # Flatten evidence for template rendering (key/value pairs)
                    evidence_items = [
                        {"key": k, "value": _fmt_evidence_value(v)}
                        for k, v in evidence.items()
                        if k != "finding_type"
                    ]

                    target_findings_data.append({
                        "id": f.id,
                        "title": f.title,
                        "severity": sev,
                        "finding_type": finding_type,
                        "description": f.description,
                        "cve": f.cve,
                        "cpe": f.cpe,
                        "remediation": f.remediation,
                        "evidence": evidence,
                        "evidence_items": evidence_items,
                        "created_at": f.created_at.isoformat() if f.created_at else "",
                    })

                targets_data.append({
                    "id": target.id,
                    "name": target.name,
                    "ip_address": target.ip_address,
                    "status": target.status or "idle",
                    "findings": target_findings_data,
                    "finding_count": len(target_findings_data),
                })

            context = {
                "project": {
                    "id": project.id,
                    "name": project.name,
                    "description": project.description,
                    "created_at": project.created_at.isoformat() if project.created_at else "",
                    "generated_at": now_iso,
                },
                "targets": targets_data,
                "summary": {
                    "total_findings": total_findings,
                    "by_severity": severity_counts,
                    "by_type": type_counts,
                    "total_targets": len(targets_data),
                },
                "pdf_backend": _get_pdf_backend(),
            }
            return context

        except Exception as exc:
            logger.exception(
                "Error building report context for project %s: %s",
                getattr(project, "id", None), exc,
            )
            return {
                "project": {
                    "id": getattr(project, "id", 0),
                    "name": getattr(project, "name", "Unknown Project"),
                    "description": getattr(project, "description", None),
                    "created_at": "",
                    "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                },
                "targets": [],
                "summary": {
                    "total_findings": 0,
                    "by_severity": {s: 0 for s in self.SEVERITY_ORDER},
                    "by_type": {"offensive": 0, "defensive": 0, "recon": 0},
                    "total_targets": 0,
                },
                "pdf_backend": _get_pdf_backend(),
            }

    # ------------------------------------------------------------------
    # HTML rendering
    # ------------------------------------------------------------------

    def render_html(self, project: Project, db: Session) -> str:
        """
        Render the full HTML report string for the given project.

        Args:
            project: SQLAlchemy Project ORM object.
            db:      Active SQLAlchemy Session.

        Returns:
            Complete HTML report string. Never raises.
        """
        try:
            context = self._build_context(project, db)
            template = self.env.get_template("report.html")
            return template.render(**context)
        except Exception as exc:
            logger.exception(
                "Failed to render HTML report for project %s: %s",
                getattr(project, "id", None), exc,
            )
            return (
                f"<!DOCTYPE html><html><head><title>Report Generation Error</title></head>"
                f"<body style='font-family: sans-serif; padding: 40px; color: #1f2937;'>"
                f"<h1 style='color: #dc2626;'>Report Generation Error</h1>"
                f"<p>An error occurred while generating the vulnerability report for project "
                f"<strong>{getattr(project, 'name', 'Unknown')}</strong>.</p>"
                f"<pre style='background: #f3f4f6; padding: 15px; border-radius: 4px;'>{exc}</pre>"
                f"</body></html>"
            )

    # ------------------------------------------------------------------
    # PDF rendering — WeasyPrint primary, ReportLab fallback
    # ------------------------------------------------------------------

    def render_pdf(self, project: Project, db: Session) -> bytes:
        """
        Generate a PDF vulnerability report.

        Tries WeasyPrint first (CSS-rendered from the same Jinja2 HTML template),
        then falls back to a ReportLab programmatic build if WeasyPrint is
        unavailable or fails.

        Args:
            project: SQLAlchemy Project ORM object.
            db:      Active SQLAlchemy Session.

        Returns:
            bytes of the complete PDF document.  Never raises; returns a
            minimal 1-page error PDF on catastrophic failure.
        """
        backend = _get_pdf_backend()

        if backend == "weasyprint":
            try:
                return self._render_pdf_weasyprint(project, db)
            except Exception as exc:
                logger.exception(
                    "WeasyPrint PDF rendering failed for project %s; trying ReportLab fallback: %s",
                    getattr(project, "id", None), exc,
                )
                # fall through to ReportLab

        if backend in ("reportlab", "weasyprint"):  # also try RL if WP failed above
            try:
                return self._render_pdf_reportlab(project, db)
            except Exception as exc:
                logger.exception(
                    "ReportLab PDF rendering failed for project %s: %s",
                    getattr(project, "id", None), exc,
                )

        return self._render_pdf_error_stub(
            getattr(project, "name", "Unknown"),
            "No PDF backend available — install weasyprint or reportlab.",
        )

    # ------------------------------------------------------------------
    # WeasyPrint backend
    # ------------------------------------------------------------------

    def _render_pdf_weasyprint(self, project: Project, db: Session) -> bytes:
        """Render PDF via WeasyPrint from the Jinja2 HTML template."""
        import weasyprint  # lazy import

        html_string = self.render_html(project, db)
        # base_url lets WeasyPrint resolve any relative asset paths from templates/
        pdf_bytes: bytes = weasyprint.HTML(
            string=html_string,
            base_url=str(TEMPLATES_DIR),
        ).write_pdf()
        logger.info(
            "WeasyPrint generated PDF for project %s (%d bytes)",
            getattr(project, "id", None), len(pdf_bytes),
        )
        return pdf_bytes

    # ------------------------------------------------------------------
    # ReportLab fallback backend
    # ------------------------------------------------------------------

    def _render_pdf_reportlab(self, project: Project, db: Session) -> bytes:
        """Render PDF programmatically via ReportLab Platypus (fallback)."""
        from reportlab.lib import colors as rl_colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            HRFlowable,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        context = self._build_context(project, db)
        project_data = context["project"]
        targets_data = context["targets"]
        summary_data = context["summary"]

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=15 * mm,
            rightMargin=15 * mm,
            topMargin=15 * mm,
            bottomMargin=15 * mm,
        )

        styles = getSampleStyleSheet()

        # Custom styles
        title_eyebrow = ParagraphStyle(
            "Eyebrow", parent=styles["Normal"],
            fontName="Helvetica-Bold", fontSize=10, leading=12,
            textColor=rl_colors.HexColor("#4b5563"), spaceAfter=4,
        )
        title_style = ParagraphStyle(
            "CoverTitle", parent=styles["Heading1"],
            fontName="Helvetica-Bold", fontSize=22, leading=26,
            textColor=rl_colors.HexColor("#111827"), spaceAfter=8,
        )
        desc_style = ParagraphStyle(
            "CoverDesc", parent=styles["Normal"],
            fontName="Helvetica", fontSize=10, leading=14,
            textColor=rl_colors.HexColor("#4b5563"), spaceAfter=12,
        )
        meta_style = ParagraphStyle(
            "CoverMeta", parent=styles["Normal"],
            fontName="Helvetica", fontSize=8, leading=11,
            textColor=rl_colors.HexColor("#6b7280"), spaceAfter=4,
        )
        h2_style = ParagraphStyle(
            "SectionHeading", parent=styles["Heading2"],
            fontName="Helvetica-Bold", fontSize=14, leading=18,
            textColor=rl_colors.HexColor("#111827"), spaceBefore=12, spaceAfter=8,
        )
        target_heading_style = ParagraphStyle(
            "TargetHeading", parent=styles["Heading3"],
            fontName="Helvetica-Bold", fontSize=12, leading=15,
            textColor=rl_colors.HexColor("#1f2937"), spaceBefore=8, spaceAfter=6,
        )
        tbl_cell = ParagraphStyle(
            "TableCell", parent=styles["Normal"],
            fontName="Helvetica", fontSize=8, leading=10,
            textColor=rl_colors.HexColor("#1f2937"),
        )
        tbl_bold = ParagraphStyle(
            "TableCellBold", parent=tbl_cell, fontName="Helvetica-Bold",
        )
        tbl_cve = ParagraphStyle(
            "TableCellCVE", parent=tbl_cell,
            fontName="Courier", fontSize=7.5, leading=9,
        )
        sev_badge_style = ParagraphStyle(
            "SevBadge", parent=styles["Normal"],
            fontName="Helvetica-Bold", fontSize=8, leading=10,
            textColor=rl_colors.white, alignment=1,
        )
        empty_style = ParagraphStyle(
            "EmptyFindings", parent=styles["Normal"],
            fontName="Helvetica-Oblique", fontSize=9, leading=12,
            textColor=rl_colors.HexColor("#6b7280"), spaceAfter=10,
        )
        footer_style = ParagraphStyle(
            "ReportFooter", parent=styles["Normal"],
            fontName="Helvetica", fontSize=8, leading=10,
            textColor=rl_colors.HexColor("#9ca3af"), alignment=2, spaceBefore=16,
        )

        # Severity colour mapping (ReportLab Color objects)
        sev_colors_rl = {
            sev: rl_colors.HexColor(hex_val)
            for sev, hex_val in self.SEVERITY_HEX.items()
        }

        story = []

        # 1. COVER
        story.append(Paragraph("SentryPack Vulnerability Assessment Report", title_eyebrow))
        story.append(Paragraph(str(project_data.get("name", "Project Report")), title_style))
        if project_data.get("description"):
            story.append(Paragraph(str(project_data["description"]), desc_style))
        story.append(Paragraph(f"<b>Generated:</b> {project_data.get('generated_at', '—')}", meta_style))
        story.append(Paragraph(f"<b>Project created:</b> {project_data.get('created_at', '—')}", meta_style))
        story.append(Spacer(1, 4 * mm))
        story.append(HRFlowable(width="100%", thickness=1, color=rl_colors.HexColor("#e5e7eb"), spaceAfter=10))

        # 2. EXECUTIVE SUMMARY
        story.append(Paragraph("Executive Summary", h2_style))
        stats_text = (
            f"<b>Targets Assessed:</b> {summary_data['total_targets']} &nbsp;&nbsp;|&nbsp;&nbsp;"
            f"<b>Total Findings:</b> {summary_data['total_findings']}"
        )
        story.append(Paragraph(stats_text, meta_style))
        story.append(Spacer(1, 3 * mm))

        summary_rows = [[Paragraph("<b>Severity</b>", tbl_bold), Paragraph("<b>Count</b>", tbl_bold)]]
        summary_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#f9fafb")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#e5e7eb")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]

        for row_idx, sev in enumerate(self.SEVERITY_ORDER, start=1):
            count = summary_data["by_severity"].get(sev, 0)
            sev_color = sev_colors_rl.get(sev, rl_colors.HexColor("#6b7280"))
            summary_rows.append([
                Paragraph(sev.upper(), sev_badge_style),
                Paragraph(str(count), tbl_bold),
            ])
            summary_styles.append(("BACKGROUND", (0, row_idx), (0, row_idx), sev_color))
            if row_idx % 2 == 0:
                summary_styles.append(("BACKGROUND", (1, row_idx), (1, row_idx), rl_colors.HexColor("#fafafa")))

        summary_table = Table(summary_rows, colWidths=[70 * mm, 110 * mm])
        summary_table.setStyle(TableStyle(summary_styles))
        story.append(summary_table)
        story.append(Spacer(1, 6 * mm))

        # 3. TARGET SECTIONS
        story.append(Paragraph("Target Assessment Details", h2_style))

        total_target_count = len(targets_data)
        for idx, target in enumerate(targets_data):
            target_title = (
                f"{target['name']} ({target['ip_address']}) — Status: {target['status']}"
            )
            story.append(Paragraph(target_title, target_heading_style))

            findings = target.get("findings", [])
            if not findings:
                story.append(Paragraph("No findings recorded for this target.", empty_style))
            else:
                rows = [[
                    Paragraph("<b>#</b>", tbl_bold),
                    Paragraph("<b>Severity</b>", tbl_bold),
                    Paragraph("<b>Type</b>", tbl_bold),
                    Paragraph("<b>Title</b>", tbl_bold),
                    Paragraph("<b>CVE</b>", tbl_bold),
                    Paragraph("<b>Description / Remediation</b>", tbl_bold),
                ]]
                row_styles = [
                    ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#f9fafb")),
                    ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#e5e7eb")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]

                for f_idx, finding in enumerate(findings, start=1):
                    sev_name = finding.get("severity", "Info")
                    sev_color = sev_colors_rl.get(sev_name, rl_colors.HexColor("#6b7280"))
                    cve_text = finding.get("cve") or "—"
                    desc_text = finding.get("description") or "—"
                    if finding.get("remediation"):
                        desc_text += f"<br/><br/><b>Fix:</b> {finding['remediation']}"
                    ftype = (finding.get("finding_type") or "offensive").upper()

                    rows.append([
                        Paragraph(str(f_idx), tbl_cell),
                        Paragraph(sev_name, sev_badge_style),
                        Paragraph(ftype, tbl_cell),
                        Paragraph(f"<b>{finding.get('title', 'Untitled')}</b>", tbl_cell),
                        Paragraph(cve_text, tbl_cve),
                        Paragraph(desc_text, tbl_cell),
                    ])
                    row_styles.append(("BACKGROUND", (1, f_idx), (1, f_idx), sev_color))
                    if f_idx % 2 == 0:
                        for col in (0, 2, 3, 4, 5):
                            row_styles.append(("BACKGROUND", (col, f_idx), (col, f_idx), rl_colors.HexColor("#fafafa")))

                # Total 180 mm = A4 content width with 15 mm margins each side
                findings_table = Table(
                    rows,
                    colWidths=[8 * mm, 20 * mm, 18 * mm, 36 * mm, 24 * mm, 74 * mm],
                )
                findings_table.setStyle(TableStyle(row_styles))
                story.append(findings_table)
                story.append(Spacer(1, 4 * mm))

            if idx < total_target_count - 1:
                story.append(PageBreak())

        # 4. FOOTER
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph(
            f"Confidential — SentryPack automated report (ReportLab) | "
            f"Generated: {project_data.get('generated_at', '')}",
            footer_style,
        ))

        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()

        logger.info(
            "ReportLab generated PDF for project %s (%d bytes)",
            getattr(project, "id", None), len(pdf_bytes),
        )
        return pdf_bytes

    # ------------------------------------------------------------------
    # Last-resort error stub
    # ------------------------------------------------------------------

    def _render_pdf_error_stub(self, project_name: str, message: str) -> bytes:
        """Return a minimal 1-page error PDF using ReportLab (best-effort)."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import mm
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

            buf = BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=A4)
            styles = getSampleStyleSheet()
            doc.build([
                Paragraph("<b>Report Generation Failed</b>", styles["Heading1"]),
                Spacer(1, 10 * mm),
                Paragraph(f"Project: {project_name}", styles["Normal"]),
                Spacer(1, 4 * mm),
                Paragraph(message, styles["Normal"]),
            ])
            data = buf.getvalue()
            buf.close()
            return data
        except Exception:
            # Absolute last resort: return a raw minimal PDF skeleton
            return (
                b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
                b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
                b"3 0 obj<</Type/Page/MediaBox[0 0 595 842]/Parent 2 0 R>>endobj\n"
                b"xref\n0 4\n0000000000 65535 f\n"
                b"0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\n"
                b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF"
            )


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _derive_finding_type(finding: FindingModel, evidence: dict) -> str:
    """
    Infer the finding type from evidence dict, CVE presence, and severity.

    Priority:
    1. ``evidence["finding_type"]`` if explicitly set (``"offensive"`` |
       ``"defensive"`` | ``"recon"``)
    2. ``"recon"`` for ``severity == "Info"``
    3. ``"offensive"`` if a CVE is present (exploit-oriented)
    4. ``"defensive"`` as default (configuration / hardening)
    """
    explicit = evidence.get("finding_type", "").lower()
    if explicit in ("offensive", "defensive", "recon"):
        return explicit
    if (finding.severity or "").lower() == "info":
        return "recon"
    if finding.cve:
        return "offensive"
    return "defensive"


def _fmt_evidence_value(value: Any) -> str:
    """Format an evidence dict value for display in the report."""
    if isinstance(value, (list, dict)):
        import json
        return json.dumps(value, ensure_ascii=False)
    return str(value)
