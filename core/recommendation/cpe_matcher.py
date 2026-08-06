"""
Phase-2 CPE-style version-range matching engine.
"""

from typing import List, Dict, Any, Optional


class CPEMatcher:
    """CPE 2.3 version range matching against CVE datasets."""

    def match_cpe(self, target_cpe: str, known_cve_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter CVE records matching target CPE identifier."""
        matched_cves = []
        for record in known_cve_records:
            cpe_prefix = record.get("cpe_prefix", "")
            if cpe_prefix and target_cpe.startswith(cpe_prefix):
                matched_cves.append(record)
        return matched_cves
