"""
Report generator exporting HTML and PDF reports using Jinja2 templates and ReportLab.
"""

from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader
from reportlab.lib import colors
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
from sqlalchemy.orm import Session

from api.db.models import FindingModel, Project, Target

logger = logging.getLogger("sentrypack.reporting")

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
TEMPLATES_DIR.mkdir(exist_ok=True)


class ReportGenerator:
    """
    Generates structured vulnerability assessment reports in HTML and PDF formats.
    """

    SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

    SEVERITY_COLORS = {
        "Critical": colors.HexColor("#dc2626"),
        "High": colors.HexColor("#ea580c"),
        "Medium": colors.HexColor("#ca8a04"),
        "Low": colors.HexColor("#2563eb"),
        "Info": colors.HexColor("#6b7280"),
    }

    def __init__(self) -> None:
        """Initialize Jinja2 environment with autoescaping enabled."""
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )

    def _build_context(
        self, project: Project, db: Session
    ) -> Dict[str, Any]:
        """
        Query all targets and their findings for this project.
        Build and return the full template context dict.

        Never raises — logs and returns a minimal fallback context on failure.
        """
        try:
            now_iso = datetime.now(timezone.utc).isoformat()
            severity_rank = {s: i for i, s in enumerate(self.SEVERITY_ORDER)}

            targets_data: List[Dict[str, Any]] = []
            severity_counts = {s: 0 for s in self.SEVERITY_ORDER}
            total_findings = 0

            # 1. Load all Target rows ordered by ID
            targets = (
                db.query(Target)
                .filter(Target.project_id == project.id)
                .order_by(Target.id)
                .all()
            )

            # 2. For each target, load and sort findings
            for target in targets:
                findings = (
                    db.query(FindingModel)
                    .filter(FindingModel.target_id == target.id)
                    .all()
                )

                # Sort by severity priority (Critical first), then created_at DESC
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

                    target_findings_data.append({
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity,
                        "description": f.description,
                        "cve": f.cve,
                        "cpe": f.cpe,
                        "remediation": f.remediation,
                        "evidence": f.evidence if isinstance(f.evidence, dict) else None,
                        "created_at": f.created_at.isoformat() if f.created_at else "",
                    })

                targets_data.append({
                    "id": target.id,
                    "name": target.name,
                    "ip_address": target.ip_address,
                    "status": target.status or "idle",
                    "findings": target_findings_data,
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
                    "total_targets": len(targets_data),
                },
            }
            return context

        except Exception as exc:
            logger.exception("Error building report context for project %s: %s", getattr(project, "id", None), exc)
            return {
                "project": {
                    "id": getattr(project, "id", 0),
                    "name": getattr(project, "name", "Unknown Project"),
                    "description": getattr(project, "description", None),
                    "created_at": "",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                },
                "targets": [],
                "summary": {
                    "total_findings": 0,
                    "by_severity": {s: 0 for s in self.SEVERITY_ORDER},
                    "total_targets": 0,
                },
            }

    def render_html(self, project: Project, db: Session) -> str:
        """
        Render the full HTML report string for the given project.

        Args:
            project: SQLAlchemy Project ORM object.
            db: Active SQLAlchemy Session.

        Returns:
            Complete HTML report string. Never raises.
        """
        try:
            context = self._build_context(project, db)
            template = self.env.get_template("report.html")
            return template.render(**context)
        except Exception as exc:
            logger.exception("Failed to render HTML report for project %s: %s", getattr(project, "id", None), exc)
            return (
                f"<!DOCTYPE html><html><head><title>Report Generation Error</title></head>"
                f"<body style='font-family: sans-serif; padding: 40px; color: #1f2937;'>"
                f"<h1 style='color: #dc2626;'>Report Generation Error</h1>"
                f"<p>An error occurred while generating the vulnerability report for project "
                f"<strong>{getattr(project, 'name', 'Unknown')}</strong>.</p>"
                f"<pre style='background: #f3f4f6; padding: 15px; border-radius: 4px;'>{exc}</pre>"
                f"</body></html>"
            )

    def render_pdf(self, project: Project, db: Session) -> bytes:
        """
        Generate a PDF vulnerability report using ReportLab Platypus.

        Args:
            project: SQLAlchemy Project ORM object.
            db: Active SQLAlchemy Session.

        Returns:
            bytes of the complete PDF document. Never raises.
        """
        try:
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
                "Eyebrow",
                parent=styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=10,
                leading=12,
                textColor=colors.HexColor("#4b5563"),
                textTransform="uppercase",
                spaceAfter=4,
            )
            title_style = ParagraphStyle(
                "CoverTitle",
                parent=styles["Heading1"],
                fontName="Helvetica-Bold",
                fontSize=22,
                leading=26,
                textColor=colors.HexColor("#111827"),
                spaceAfter=8,
            )
            desc_style = ParagraphStyle(
                "CoverDesc",
                parent=styles["Normal"],
                fontName="Helvetica",
                fontSize=10,
                leading=14,
                textColor=colors.HexColor("#4b5563"),
                spaceAfter=12,
            )
            meta_style = ParagraphStyle(
                "CoverMeta",
                parent=styles["Normal"],
                fontName="Helvetica",
                fontSize=8,
                leading=11,
                textColor=colors.HexColor("#6b7280"),
                spaceAfter=4,
            )
            h2_style = ParagraphStyle(
                "SectionHeading",
                parent=styles["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=14,
                leading=18,
                textColor=colors.HexColor("#111827"),
                spaceBefore=12,
                spaceAfter=8,
            )
            target_heading_style = ParagraphStyle(
                "TargetHeading",
                parent=styles["Heading3"],
                fontName="Helvetica-Bold",
                fontSize=12,
                leading=15,
                textColor=colors.HexColor("#1f2937"),
                spaceBefore=8,
                spaceAfter=6,
            )
            table_cell_style = ParagraphStyle(
                "TableCell",
                parent=styles["Normal"],
                fontName="Helvetica",
                fontSize=8,
                leading=10,
                textColor=colors.HexColor("#1f2937"),
            )
            table_cell_bold = ParagraphStyle(
                "TableCellBold",
                parent=table_cell_style,
                fontName="Helvetica-Bold",
            )
            table_cell_cve = ParagraphStyle(
                "TableCellCVE",
                parent=table_cell_style,
                fontName="Courier",
                fontSize=7.5,
                leading=9,
            )
            sev_badge_style = ParagraphStyle(
                "SevBadge",
                parent=styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=8,
                leading=10,
                textColor=colors.white,
                alignment=1,  # Center
            )
            empty_findings_style = ParagraphStyle(
                "EmptyFindings",
                parent=styles["Normal"],
                fontName="Helvetica-Oblique",
                fontSize=9,
                leading=12,
                textColor=colors.HexColor("#6b7280"),
                spaceAfter=10,
            )
            footer_style = ParagraphStyle(
                "ReportFooter",
                parent=styles["Normal"],
                fontName="Helvetica",
                fontSize=8,
                leading=10,
                textColor=colors.HexColor("#9ca3af"),
                alignment=2,  # Right
                spaceBefore=16,
            )

            story = []

            # 1. COVER SECTION
            story.append(Paragraph("SentryPack Vulnerability Assessment Report", title_eyebrow))
            story.append(Paragraph(str(project_data.get("name", "Project Report")), title_style))
            if project_data.get("description"):
                story.append(Paragraph(str(project_data["description"]), desc_style))
            story.append(Paragraph(f"<b>Generated:</b> {project_data.get('generated_at', '—')}", meta_style))
            story.append(Paragraph(f"<b>Project created:</b> {project_data.get('created_at', '—')}", meta_style))
            story.append(Spacer(1, 4 * mm))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e5e7eb"), spaceAfter=10))

            # 2. EXECUTIVE SUMMARY TABLE
            story.append(Paragraph("Executive Summary", h2_style))
            summary_stats_text = (
                f"<b>Total Targets Assessed:</b> {summary_data['total_targets']} &nbsp;&nbsp;|&nbsp;&nbsp; "
                f"<b>Total Findings Identified:</b> {summary_data['total_findings']}"
            )
            story.append(Paragraph(summary_stats_text, meta_style))
            story.append(Spacer(1, 3 * mm))

            summary_rows = [
                [
                    Paragraph("<b>Severity</b>", table_cell_bold),
                    Paragraph("<b>Findings Count</b>", table_cell_bold),
                ]
            ]
            summary_styles = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f9fafb")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]

            row_idx = 1
            for sev in self.SEVERITY_ORDER:
                count = summary_data["by_severity"].get(sev, 0)
                sev_color = self.SEVERITY_COLORS.get(sev, colors.HexColor("#6b7280"))
                summary_rows.append([
                    Paragraph(sev.upper(), sev_badge_style),
                    Paragraph(str(count), table_cell_bold),
                ])
                summary_styles.append(("BACKGROUND", (0, row_idx), (0, row_idx), sev_color))
                if row_idx % 2 == 0:
                    summary_styles.append(("BACKGROUND", (1, row_idx), (1, row_idx), colors.HexColor("#fafafa")))
                row_idx += 1

            summary_table = Table(summary_rows, colWidths=[70 * mm, 110 * mm])
            summary_table.setStyle(TableStyle(summary_styles))
            story.append(summary_table)
            story.append(Spacer(1, 6 * mm))

            # 3. TARGET SECTIONS
            story.append(Paragraph("Target Assessment Details", h2_style))

            total_targets_count = len(targets_data)
            for idx, target in enumerate(targets_data):
                target_title = f"{target['name']} ({target['ip_address']}) — Status: {target['status']}"
                story.append(Paragraph(target_title, target_heading_style))

                findings = target.get("findings", [])
                if not findings:
                    story.append(Paragraph("No findings recorded for this target.", empty_findings_style))
                else:
                    findings_rows = [
                        [
                            Paragraph("<b>#</b>", table_cell_bold),
                            Paragraph("<b>Severity</b>", table_cell_bold),
                            Paragraph("<b>Title</b>", table_cell_bold),
                            Paragraph("<b>CVE</b>", table_cell_bold),
                            Paragraph("<b>Description</b>", table_cell_bold),
                        ]
                    ]
                    findings_styles = [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f9fafb")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]

                    for f_idx, finding in enumerate(findings, start=1):
                        sev_name = finding.get("severity", "Info")
                        sev_color = self.SEVERITY_COLORS.get(sev_name, colors.HexColor("#6b7280"))
                        cve_text = finding.get("cve") or "—"
                        desc_text = finding.get("description") or "—"
                        if finding.get("remediation"):
                            desc_text += f"<br/><br/><b>Remediation:</b> {finding['remediation']}"

                        findings_rows.append([
                            Paragraph(str(f_idx), table_cell_style),
                            Paragraph(sev_name, sev_badge_style),
                            Paragraph(f"<b>{finding.get('title', 'Untitled')}</b>", table_cell_style),
                            Paragraph(cve_text, table_cell_cve),
                            Paragraph(desc_text, table_cell_style),
                        ])
                        findings_styles.append(("BACKGROUND", (1, f_idx), (1, f_idx), sev_color))
                        if f_idx % 2 == 0:
                            findings_styles.append(("BACKGROUND", (0, f_idx), (0, f_idx), colors.HexColor("#fafafa")))
                            findings_styles.append(("BACKGROUND", (2, f_idx), (-1, f_idx), colors.HexColor("#fafafa")))

                    # Total width = 10 + 22 + 42 + 28 + 78 = 180 mm (fits A4 with 15mm margins)
                    findings_table = Table(
                        findings_rows,
                        colWidths=[10 * mm, 22 * mm, 42 * mm, 28 * mm, 78 * mm],
                    )
                    findings_table.setStyle(TableStyle(findings_styles))
                    story.append(findings_table)
                    story.append(Spacer(1, 4 * mm))

                # Add a page break after each target except the last one
                if idx < total_targets_count - 1:
                    story.append(PageBreak())

            # 4. FOOTER
            story.append(Spacer(1, 4 * mm))
            story.append(
                Paragraph(
                    f"Confidential — SentryPack automated report | Generated: {project_data.get('generated_at', '')}",
                    footer_style,
                )
            )

            doc.build(story)
            pdf_bytes = buffer.getvalue()
            buffer.close()
            return pdf_bytes

        except Exception as exc:
            logger.exception("Failed to render PDF report for project %s: %s", getattr(project, "id", None), exc)
            # Return minimal 1-page error PDF
            err_buffer = BytesIO()
            err_doc = SimpleDocTemplate(err_buffer, pagesize=A4)
            err_styles = getSampleStyleSheet()
            err_story = [
                Paragraph("<b>Report Generation Failed</b>", err_styles["Heading1"]),
                Spacer(1, 10 * mm),
                Paragraph(f"An error occurred while generating the PDF report: {exc}", err_styles["Normal"]),
            ]
            err_doc.build(err_story)
            err_bytes = err_buffer.getvalue()
            err_buffer.close()
            return err_bytes
