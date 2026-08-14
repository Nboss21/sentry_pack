"""
Unit tests for recommendation engine precedence ranking function.

Precedence order tested:
Direct match > Public exploit available > CVSS score > Recency.
"""

from __future__ import annotations

import pytest

from core.recommendation.models import ExploitRecord, MatchResult, ServiceResult
from core.recommendation.ranker import rank_recommendations


def _dummy_svc() -> ServiceResult:
    return ServiceResult(host="10.0.0.1", port=80, protocol="tcp", service="http")


class TestRankerPrecedence:
    def test_direct_match_precedence(self):
        """Direct module match must rank above non-direct match regardless of CVSS or exploit availability."""
        r1 = ExploitRecord(
            id=1,
            service_name="http",
            module_id=None,
            has_public_exploit=True,
            cvss_score=10.0,
            published_date="2026-02-01",
        )
        r2 = ExploitRecord(
            id=2,
            service_name="http",
            module_id="exploit.http_direct",
            has_public_exploit=False,
            cvss_score=5.0,
            published_date="2020-01-01",
        )
        m1 = MatchResult(record=r1, match_type="exact", matched_field="service", service_result=_dummy_svc(), is_direct_match=False)
        m2 = MatchResult(record=r2, match_type="direct", matched_field="module_id", service_result=_dummy_svc(), is_direct_match=True)

        ranked = rank_recommendations([m1, m2])
        assert ranked[0].record.id == 2
        assert ranked[1].record.id == 1

    def test_public_exploit_precedence(self):
        """When neither is a direct match, public exploit available ranks before no public exploit."""
        r1 = ExploitRecord(id=1, service_name="http", has_public_exploit=False, cvss_score=10.0)
        r2 = ExploitRecord(id=2, service_name="http", has_public_exploit=True, cvss_score=7.0)

        m1 = MatchResult(record=r1, match_type="exact", matched_field="service", service_result=_dummy_svc())
        m2 = MatchResult(record=r2, match_type="exact", matched_field="service", service_result=_dummy_svc())

        ranked = rank_recommendations([m1, m2])
        assert ranked[0].record.id == 2
        assert ranked[1].record.id == 1

    def test_cvss_score_precedence(self):
        """When direct match & public exploit availability tie, higher CVSS score ranks first."""
        r1 = ExploitRecord(id=1, service_name="http", has_public_exploit=True, cvss_score=7.5)
        r2 = ExploitRecord(id=2, service_name="http", has_public_exploit=True, cvss_score=9.8)

        m1 = MatchResult(record=r1, match_type="exact", matched_field="service", service_result=_dummy_svc())
        m2 = MatchResult(record=r2, match_type="exact", matched_field="service", service_result=_dummy_svc())

        ranked = rank_recommendations([m1, m2])
        assert ranked[0].record.id == 2
        assert ranked[1].record.id == 1

    def test_recency_precedence(self):
        """When direct match, public exploit, and CVSS score tie, newer published_date ranks first."""
        r1 = ExploitRecord(id=1, service_name="http", has_public_exploit=True, cvss_score=9.0, published_date="2024-01-15")
        r2 = ExploitRecord(id=2, service_name="http", has_public_exploit=True, cvss_score=9.0, published_date="2026-02-10")

        m1 = MatchResult(record=r1, match_type="exact", matched_field="service", service_result=_dummy_svc())
        m2 = MatchResult(record=r2, match_type="exact", matched_field="service", service_result=_dummy_svc())

        ranked = rank_recommendations([m1, m2])
        assert ranked[0].record.id == 2
        assert ranked[1].record.id == 1

    def test_multi_level_tie_breaking(self):
        """Complete test sorting 4 items spanning all precedence criteria."""
        r1 = ExploitRecord(id=1, service_name="ssh", module_id=None, has_public_exploit=False, cvss_score=6.0, published_date="2020-01-01")
        r2 = ExploitRecord(id=2, service_name="ssh", module_id=None, has_public_exploit=True, cvss_score=8.0, published_date="2021-01-01")
        r3 = ExploitRecord(id=3, service_name="ssh", module_id=None, has_public_exploit=True, cvss_score=9.8, published_date="2022-01-01")
        r4 = ExploitRecord(id=4, service_name="ssh", module_id="exploit.ssh", has_public_exploit=True, cvss_score=5.0, published_date="2023-01-01")

        m1 = MatchResult(record=r1, match_type="exact", matched_field="service", service_result=_dummy_svc(), is_direct_match=False)
        m2 = MatchResult(record=r2, match_type="exact", matched_field="service", service_result=_dummy_svc(), is_direct_match=False)
        m3 = MatchResult(record=r3, match_type="exact", matched_field="service", service_result=_dummy_svc(), is_direct_match=False)
        m4 = MatchResult(record=r4, match_type="direct", matched_field="module_id", service_result=_dummy_svc(), is_direct_match=True)

        ranked = rank_recommendations([m1, m2, m3, m4])
        # Expected order:
        # 1. r4 (direct match)
        # 2. r3 (has public exploit, CVSS 9.8)
        # 3. r2 (has public exploit, CVSS 8.0)
        # 4. r1 (no public exploit)
        ordered_ids = [m.record.id for m in ranked]
        assert ordered_ids == [4, 3, 2, 1]
