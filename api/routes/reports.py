"""
Reports API routes (GET /api/projects/{project_id}/report).
"""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from api.db.models import Project
from api.db.session import get_db
from api.reporting.generator import ReportGenerator

logger = logging.getLogger("sentrypack.api.reports")

router = APIRouter()


@router.get("/{project_id}/report")
def generate_report(
    project_id: int,
    format: str = "html",
    db: Session = Depends(get_db),
):
    """
    Generate and return a vulnerability assessment report.

    Query params:
      format=html  → returns HTMLResponse (text/html)
      format=pdf   → returns Response with
                      media_type="application/pdf"
                      Content-Disposition: attachment;
                        filename="sentrypack_report_{project_id}.pdf"

    Errors:
      404 if project not found
      400 if format is not "html" or "pdf"
      500 (JSON body) if generation fails unexpectedly
    """
    logger.info("Generating report for project_id=%s format=%s", project_id, format)

    # 1. Validate format param
    if format not in ("html", "pdf"):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_format",
                "message": "format must be 'html' or 'pdf'",
            },
        )

    # 2. Load project or 404
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "not_found",
                "message": f"Project {project_id} not found",
            },
        )

    # 3. Generate and return
    gen = ReportGenerator()
    if format == "html":
        html = gen.render_html(project, db)
        return HTMLResponse(content=html)
    else:
        pdf_bytes = gen.render_pdf(project, db)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="sentrypack_report_{project_id}.pdf"'
            },
        )
