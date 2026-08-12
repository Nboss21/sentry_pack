"""
Findings API routes (GET /api/targets/{id}/findings).
"""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.db.models import FindingModel
from api.db.session import get_db

logger = logging.getLogger("sentrypack.api.findings")
router = APIRouter()


@router.get("/targets/{target_id}/findings")
def get_findings(target_id: int, db: Session = Depends(get_db)):
    findings = (
        db.query(FindingModel)
        .filter(FindingModel.target_id == target_id)
        .order_by(FindingModel.created_at.desc())
        .all()
    )
    return {
        "target_id": target_id,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "cve": f.cve,
                "cpe": f.cpe,
                "remediation": f.remediation,
                "evidence": f.evidence,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in findings
        ],
    }
