"""
Recommendation engine ranking module.

Implements the precedence ranking function:
Direct match > Public exploit available > CVSS score > Recency.
"""

from __future__ import annotations

from typing import List

from core.recommendation.models import MatchResult


def rank_recommendations(matches: List[MatchResult]) -> List[MatchResult]:
    """Rank a list of recommendation matches by priority precedence:

    1. Direct match (is_direct_match or module_id present)
    2. Public exploit available (has_public_exploit is True)
    3. CVSS score (higher score first)
    4. Recency (published_date, newest first)
    5. Stable tie-breaker (record ID)
    """

    def sort_key(match: MatchResult) -> tuple:
        is_direct = 1 if (match.is_direct_match or (match.record.module_id and match.record.module_id.strip())) else 0
        has_exploit = 1 if match.record.has_public_exploit else 0
        cvss = float(match.record.cvss_score) if match.record.cvss_score is not None else 0.0
        recency = match.record.published_date or ""
        rec_id = -match.record.id if getattr(match.record, "id", None) is not None else 0
        return (is_direct, has_exploit, cvss, recency, rec_id)

    return sorted(matches, key=sort_key, reverse=True)
