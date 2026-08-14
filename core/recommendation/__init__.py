"""
Recommendation package for module and exploit matching engines.

Public API
----------
- Data models: ServiceResult, ExploitRecord, MatchResult
- Matching engines: StringMatcher, CPEMatcher, RecommendationMatcher
- Utilities: parse_version, version_in_range, rank_recommendations
- Service: RecommendationEngine, recommendation_engine, get_exploit_records_from_db
"""

from core.recommendation.cpe_matcher import CPEMatcher, parse_version, version_in_range
from core.recommendation.engine import (
    RecommendationEngine,
    get_exploit_records_from_db,
    recommendation_engine,
)
from core.recommendation.matcher import RecommendationMatcher, StringMatcher
from core.recommendation.models import ExploitRecord, MatchResult, ServiceResult
from core.recommendation.ranker import rank_recommendations

__all__ = [
    "ServiceResult",
    "ExploitRecord",
    "MatchResult",
    "StringMatcher",
    "CPEMatcher",
    "RecommendationMatcher",
    "parse_version",
    "version_in_range",
    "rank_recommendations",
    "RecommendationEngine",
    "recommendation_engine",
    "get_exploit_records_from_db",
]
