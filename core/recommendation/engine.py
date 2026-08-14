"""
Recommendation engine main service module.

Queries real Exploit DB records from the database, matches them against target findings,
ranks them by precedence rules, and returns structured recommendations per target.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from api.db.models import ExploitModel, FindingModel
from core.recommendation.matcher import StringMatcher
from core.recommendation.models import ExploitRecord, MatchResult, ServiceResult
from core.recommendation.ranker import rank_recommendations


def get_exploit_records_from_db(db: Session) -> List[ExploitRecord]:
    """Query ExploitModel table and convert to ExploitRecord dataclass instances."""
    models = db.query(ExploitModel).all()
    records: List[ExploitRecord] = []
    for m in models:
        records.append(
            ExploitRecord(
                id=m.id,
                service_name=m.service_name,
                cve_id=m.cve_id,
                module_id=m.module_id,
                severity=m.severity or "Medium",
                cvss_score=m.cvss_score,
                description=m.description or "",
                has_public_exploit=m.has_public_exploit if m.has_public_exploit is not None else True,
                published_date=m.published_date,
                cpe_prefix=m.cpe_prefix,
                version_start_including=m.version_start_including,
                version_start_excluding=m.version_start_excluding,
                version_end_including=m.version_end_including,
                version_end_excluding=m.version_end_excluding,
                references=m.references or [],
            )
        )
    return records


class RecommendationEngine:
    """Service for retrieving and ranking exploit recommendations per target."""

    def __init__(self, exploit_table: Optional[List[ExploitRecord]] = None) -> None:
        self._exploit_table = exploit_table

    def get_service_results_for_target(self, target_id: int, db: Session) -> List[ServiceResult]:
        """Fetch all findings for target and convert evidence to ServiceResult objects."""
        findings = db.query(FindingModel).filter(FindingModel.target_id == target_id).all()
        results: List[ServiceResult] = []
        for f in findings:
            if f.evidence and isinstance(f.evidence, dict):
                results.append(ServiceResult.from_finding_evidence(f.evidence))
        return results

    def recommend_for_target(
        self,
        target_id: int,
        db: Session,
        exploit_table: Optional[List[ExploitRecord]] = None,
    ) -> List[Dict[str, Any]]:
        """Query Exploit DB, match against target findings/services, rank results, and format."""
        table = exploit_table or self._exploit_table
        if table is None:
            table = get_exploit_records_from_db(db)

        service_results = self.get_service_results_for_target(target_id, db)
        if not service_results:
            return []

        matcher = StringMatcher(table)
        matches: List[MatchResult] = matcher.match_many(service_results)
        ranked_matches = rank_recommendations(matches)

        formatted: List[Dict[str, Any]] = []
        for m in ranked_matches:
            formatted.append({
                "id": m.record.id,
                "service_name": m.record.service_name,
                "cve_id": m.record.cve_id,
                "title": m.record.description or f"Exploit for {m.record.service_name}",
                "description": m.record.description,
                "severity": m.record.severity,
                "cvss_score": m.record.cvss_score,
                "module_id": m.record.module_id,
                "has_public_exploit": m.record.has_public_exploit,
                "published_date": m.record.published_date,
                "match_type": m.match_type,
                "matched_field": m.matched_field,
                "is_direct_match": m.is_direct_match,
                "references": m.record.references or [],
                "target_service": {
                    "host": m.service_result.host,
                    "port": m.service_result.port,
                    "protocol": m.service_result.protocol,
                    "service": m.service_result.service,
                    "product": m.service_result.product,
                    "version": m.service_result.version,
                    "cpe": m.service_result.cpe,
                },
            })
        return formatted


recommendation_engine = RecommendationEngine()
