"""
Phase-1 exact and prefix string matcher for banners, service names, and technologies.
"""

from typing import List, Dict, Any


class StringMatcher:
    """Exact & prefix string matching engine for target services."""

    def __init__(self, rules: List[Dict[str, Any]] = None):
        self.rules = rules or []

    def match(self, service_banner: str) -> List[Dict[str, Any]]:
        """Match service banner against configured rule keywords."""
        matches = []
        banner_lower = service_banner.lower()
        for rule in self.rules:
            keyword = rule.get("keyword", "").lower()
            if keyword and (keyword in banner_lower or banner_lower.startswith(keyword)):
                matches.append(rule)
        return matches
