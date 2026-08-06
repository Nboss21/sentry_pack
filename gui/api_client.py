"""
API Client wrapper for REST endpoints and WebSocket subscriptions.
"""

from typing import Any, Dict, Optional
import requests


class SentryPackAPIClient:
    """REST API and WebSocket client wrapper for SentryPack GUI."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url.rstrip("/")

    def get_modules(self) -> Dict[str, Any]:
        """Fetch available modules."""
        response = requests.get(f"{self.base_url}/api/modules/")
        response.raise_for_status()
        return response.json()

    def get_projects(self) -> Dict[str, Any]:
        """Fetch projects list."""
        response = requests.get(f"{self.base_url}/api/projects/")
        response.raise_for_status()
        return response.json()
