"""
NVD / CVE Feed enrichment client.
"""

from typing import Dict, Any, List


class NVDSyncClient:
    """Client for fetching and synchronizing CVE details from NVD API."""

    def __init__(self, api_key: str = None):
        self.api_key = api_key

    def fetch_cve(self, cve_id: str) -> Dict[str, Any]:
        """Fetch details for a specific CVE ID."""
        return {
            "cve_id": cve_id,
            "description": "Vulnerability details",
            "cvss_score": 7.5,
        }
