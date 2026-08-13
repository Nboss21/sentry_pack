"""
Recommendation engine — Phase 1 exact and prefix string matching.

Public API
----------
.. code-block:: python

    from core.recommendation import (
        ServiceResult,
        ExploitRecord,
        MatchResult,
        StringMatcher,
    )
"""

from core.recommendation.models import ExploitRecord, MatchResult, ServiceResult
from core.recommendation.matcher import StringMatcher

__all__ = [
    "ServiceResult",
    "ExploitRecord",
    "MatchResult",
    "StringMatcher",
]
