"""
Phase-2 CPE-style version-range matching engine.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple, Union

from core.recommendation.models import ExploitRecord, MatchResult, ServiceResult


def parse_version(ver_str: Optional[str]) -> Tuple[Union[int, str], ...]:
    """Parse a version string into a comparable tuple.

    Handles standard semver, numbers, and letter suffixes (e.g. "8.9p1", "2.4.52").
    """
    if not ver_str:
        return ()

    cleaned = ver_str.lstrip("vV").strip()
    parts = re.findall(r"(\d+|\D+)", cleaned)
    parsed: list[Union[int, str]] = []
    for part in parts:
        token = part.strip(".-_")
        if not token:
            continue
        if token.isdigit():
            parsed.append(int(token))
        else:
            parsed.append(token.lower())
    return tuple(parsed)


def version_in_range(
    target_version: Optional[str],
    version_start_including: Optional[str] = None,
    version_start_excluding: Optional[str] = None,
    version_end_including: Optional[str] = None,
    version_end_excluding: Optional[str] = None,
) -> bool:
    """Evaluate whether target_version falls within specified version bounds.

    Returns True if target_version satisfies all present bounds.
    If no bounds are specified, returns True.
    If bounds are specified but target_version is missing/empty, returns False.
    """
    has_bounds = any(
        b is not None and b.strip() != ""
        for b in (
            version_start_including,
            version_start_excluding,
            version_end_including,
            version_end_excluding,
        )
    )
    if not has_bounds:
        return True

    if not target_version or not target_version.strip():
        return False

    v = parse_version(target_version)

    if version_start_including and version_start_including.strip():
        if v < parse_version(version_start_including):
            return False

    if version_start_excluding and version_start_excluding.strip():
        if v <= parse_version(version_start_excluding):
            return False

    if version_end_including and version_end_including.strip():
        if v > parse_version(version_end_including):
            return False

    if version_end_excluding and version_end_excluding.strip():
        if v >= parse_version(version_end_excluding):
            return False

    return True


class CPEMatcher:
    """CPE 2.3 version range matching against Exploit DB records."""

    def __init__(self, exploit_table: Optional[List[ExploitRecord]] = None) -> None:
        self._table: List[ExploitRecord] = exploit_table or []

    def match_cpe(
        self,
        service_result: ServiceResult,
        known_cve_records: Optional[List[ExploitRecord]] = None,
    ) -> List[MatchResult]:
        """Filter CVE/Exploit records matching target CPE or service version range."""
        records = known_cve_records if known_cve_records is not None else self._table
        matches: List[MatchResult] = []

        target_cpe = service_result.cpe.strip().lower()
        target_service = service_result.service.strip().lower()
        target_product = service_result.product.strip().lower()
        target_version = service_result.version.strip()

        for record in records:
            cpe_prefix = (record.cpe_prefix or "").strip().lower()
            service_name = (record.service_name or "").strip().lower()

            has_range_data = any(
                getattr(record, b, None) is not None and getattr(record, b, "").strip() != ""
                for b in (
                    "version_start_including",
                    "version_start_excluding",
                    "version_end_including",
                    "version_end_excluding",
                )
            )

            # Skip CPE matcher if record doesn't have CPE or version range info
            if not cpe_prefix and not has_range_data:
                continue

            cpe_matched = False
            matched_field = "cpe"

            if cpe_prefix and target_cpe:
                if target_cpe.startswith(cpe_prefix) or cpe_prefix.startswith(target_cpe):
                    cpe_matched = True
                    matched_field = "cpe"
            elif service_name:
                if (
                    (target_service and (target_service == service_name or target_service.startswith(service_name)))
                    or (target_product and (target_product == service_name or target_product.startswith(service_name)))
                ):
                    cpe_matched = True
                    matched_field = "service" if target_service == service_name else "product"

            if not cpe_matched:
                continue

            # Evaluate version range
            if has_range_data:
                if not target_version:
                    # Missing version in target -> cannot satisfy version-range check
                    continue
                if not version_in_range(
                    target_version,
                    version_start_including=record.version_start_including,
                    version_start_excluding=record.version_start_excluding,
                    version_end_including=record.version_end_including,
                    version_end_excluding=record.version_end_excluding,
                ):
                    continue

            matches.append(
                MatchResult(
                    record=record,
                    match_type="cpe_version",
                    matched_field=matched_field,
                    service_result=service_result,
                )
            )

        return matches
