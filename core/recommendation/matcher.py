"""
Matching engine combining Phase-1 string matching, Phase-2 CPE/version-range matching, and direct module matching.
"""

from __future__ import annotations

from typing import List, Optional

from core.recommendation.cpe_matcher import CPEMatcher
from core.recommendation.models import ExploitRecord, MatchResult, ServiceResult


class StringMatcher:
    """Exact and prefix string matching engine for scan-result services.

    Also integrates Phase 2 CPE/version-range matching when CPE or version-range
    data is available on exploit records.
    """

    def __init__(self, exploit_table: Optional[List[ExploitRecord]] = None) -> None:
        self._table: List[ExploitRecord] = exploit_table or []
        self._cpe_matcher = CPEMatcher(self._table)

    def match(self, result: ServiceResult) -> List[MatchResult]:
        """Match a single scan result against the exploit table.

        Phase 2 CPE version-range matching is attempted first for records that specify
        CPE or version bounds. If no range bounds are present or match fails due to absence
        of version bounds, falls back to Phase 1 exact/prefix matching.
        """
        exact_matches: List[MatchResult] = []
        prefix_matches: List[MatchResult] = []
        cpe_matches: List[MatchResult] = []
        direct_matches: List[MatchResult] = []

        seen_ids: set[int] = set()

        # 1. Run CPE / Version-range matcher
        cpe_results = self._cpe_matcher.match_cpe(result, self._table)
        for m in cpe_results:
            seen_ids.add(m.record.id)
            cpe_matches.append(m)

        service_lower = result.service.strip().lower()
        product_lower = result.product.strip().lower()

        # 2. Phase 1 String matching for records not already matched by CPE/version range
        for record in self._table:
            if record.id in seen_ids:
                continue

            needle = record.service_name.strip().lower()
            if not needle:
                continue

            match_result: Optional[MatchResult] = None

            # --- Direct module match check ---
            if record.module_id and (
                (service_lower and service_lower in record.module_id.lower())
                or (product_lower and product_lower in record.module_id.lower())
            ):
                match_result = MatchResult(
                    record=record,
                    match_type="direct",
                    matched_field="module_id",
                    service_result=result,
                    is_direct_match=True,
                )

            # --- Exact matching (service field first, then product) ---
            elif service_lower and service_lower == needle:
                match_result = MatchResult(
                    record=record,
                    match_type="exact",
                    matched_field="service",
                    service_result=result,
                )
            elif product_lower and product_lower == needle:
                match_result = MatchResult(
                    record=record,
                    match_type="exact",
                    matched_field="product",
                    service_result=result,
                )

            # --- Prefix matching (service field first, then product) ---
            elif service_lower and service_lower.startswith(needle):
                match_result = MatchResult(
                    record=record,
                    match_type="prefix",
                    matched_field="service",
                    service_result=result,
                )
            elif product_lower and product_lower.startswith(needle):
                match_result = MatchResult(
                    record=record,
                    match_type="prefix",
                    matched_field="product",
                    service_result=result,
                )

            if match_result is None or record.id in seen_ids:
                continue

            seen_ids.add(record.id)
            if match_result.match_type == "direct":
                direct_matches.append(match_result)
            elif match_result.match_type == "exact":
                exact_matches.append(match_result)
            else:
                prefix_matches.append(match_result)

        return direct_matches + cpe_matches + exact_matches + prefix_matches

    def match_many(self, results: List[ServiceResult]) -> List[MatchResult]:
        """Match a list of scan results against the exploit table."""
        all_matches: List[MatchResult] = []
        for result in results:
            all_matches.extend(self.match(result))
        return all_matches


class RecommendationMatcher(StringMatcher):
    """Unified recommendation matcher wrapper."""

    pass
