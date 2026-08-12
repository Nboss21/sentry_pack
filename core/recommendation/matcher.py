"""
Phase-1 exact and prefix string matching engine.

The :class:`StringMatcher` is the primary entry point for Phase 1 of the
recommendation engine.  It takes a list of :class:`~.models.ExploitRecord`
objects (the exploit table) and matches them against
:class:`~.models.ServiceResult` objects (parsed scan output).

Matching strategy
-----------------
For each ``ExploitRecord`` in the table the matcher checks two fields of the
``ServiceResult`` — ``service`` and ``product`` — against the record's
``service_name`` using two strategies:

1. **Exact match** — case-insensitive equality
   (``result.service.lower() == record.service_name.lower()``).
2. **Prefix match** — the *scan result field* starts with the record's
   ``service_name`` (``result.service.lower().startswith(...)``).

Result ordering
---------------
* Exact matches are always returned before prefix matches.
* Within the same match type, records preserve their original insertion order
  in the exploit table.

Deduplication
-------------
An ``ExploitRecord`` can match via both fields (``service`` *and* ``product``).
In that case only the *highest-priority* hit (exact > prefix, service > product)
is included — the same record never appears twice in the output.

Phase scope note
----------------
The exploit table is expected to be **mostly empty** in Phase 1.  The point
is the matching *function*, not the data.  Phase 4 will load the real NVD /
Exploit DB records into this table.
"""

from __future__ import annotations

from typing import List, Optional

from core.recommendation.models import ExploitRecord, MatchResult, ServiceResult


class StringMatcher:
    """Exact and prefix string matching engine for scan-result services.

    Args:
        exploit_table: List of :class:`~.models.ExploitRecord` objects to
                       match against.  Pass an empty list to get a matcher
                       that always returns no results — useful for testing
                       the caller without populating data.

    Example::

        table = [
            ExploitRecord(id=1, service_name="ssh", cve_id="CVE-2023-38408"),
            ExploitRecord(id=2, service_name="apache"),
        ]
        matcher = StringMatcher(table)

        result = ServiceResult(host="10.0.0.1", port=22, protocol="tcp",
                               service="ssh", product="OpenSSH")
        matches = matcher.match(result)
        # → [MatchResult(record=<ssh exploit>, match_type="exact", matched_field="service", ...)]
    """

    def __init__(self, exploit_table: Optional[List[ExploitRecord]] = None) -> None:
        self._table: List[ExploitRecord] = exploit_table or []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def match(self, result: ServiceResult) -> List[MatchResult]:
        """Match a single scan result against the exploit table.

        Args:
            result: A :class:`~.models.ServiceResult` representing one
                    discovered service.

        Returns:
            A deduplicated list of :class:`~.models.MatchResult` objects,
            exact matches first, then prefix matches.  Returns ``[]`` when
            the exploit table is empty or no record matches.
        """
        exact_matches: List[MatchResult] = []
        prefix_matches: List[MatchResult] = []
        seen_ids: set[int] = set()

        service_lower = result.service.strip().lower()
        product_lower = result.product.strip().lower()

        for record in self._table:
            needle = record.service_name.strip().lower()
            if not needle:
                continue

            match_result: Optional[MatchResult] = None

            # --- Exact matching (service field first, then product) ---
            if service_lower and service_lower == needle:
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
            if match_result.match_type == "exact":
                exact_matches.append(match_result)
            else:
                prefix_matches.append(match_result)

        return exact_matches + prefix_matches

    def match_many(self, results: List[ServiceResult]) -> List[MatchResult]:
        """Match a list of scan results against the exploit table.

        Convenience wrapper around :meth:`match` that processes an entire
        scan's worth of services in one call.

        Args:
            results: List of :class:`~.models.ServiceResult` objects from a
                     completed scan.

        Returns:
            Flat list of all :class:`~.models.MatchResult` objects across all
            results, preserving per-result ordering (exact before prefix).
        """
        all_matches: List[MatchResult] = []
        for result in results:
            all_matches.extend(self.match(result))
        return all_matches
