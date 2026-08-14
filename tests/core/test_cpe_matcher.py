"""
Unit tests for CPE and version-range matching logic.
"""

from __future__ import annotations

import pytest

from core.recommendation.cpe_matcher import CPEMatcher, parse_version, version_in_range
from core.recommendation.models import ExploitRecord, ServiceResult


class TestParseVersion:
    def test_basic_version_parsing(self):
        assert parse_version("8.9.1") == (8, 9, 1)
        assert parse_version("2.4.52") == (2, 4, 52)
        assert parse_version("1.0") == (1, 0)

    def test_version_with_letter_suffixes(self):
        assert parse_version("8.9p1") == (8, 9, "p", 1)
        assert parse_version("v1.0.2g") == (1, 0, 2, "g")

    def test_empty_or_none_version(self):
        assert parse_version("") == ()
        assert parse_version(None) == ()

    def test_version_comparisons(self):
        assert parse_version("8.9p1") > parse_version("8.0")
        assert parse_version("8.9p1") < parse_version("8.9p2")
        assert parse_version("2.4.52") <= parse_version("2.4.52")


class TestVersionInRange:
    def test_no_bounds_returns_true(self):
        assert version_in_range("8.9p1") is True

    def test_missing_version_with_bounds_returns_false(self):
        assert version_in_range("", version_start_including="8.0") is False
        assert version_in_range(None, version_end_including="8.9") is False

    def test_inclusive_bounds(self):
        # 8.0 <= v <= 8.9
        assert version_in_range("8.0", version_start_including="8.0", version_end_including="8.9") is True
        assert version_in_range("8.5", version_start_including="8.0", version_end_including="8.9") is True
        assert version_in_range("8.9", version_start_including="8.0", version_end_including="8.9") is True
        assert version_in_range("7.9", version_start_including="8.0", version_end_including="8.9") is False
        assert version_in_range("9.0", version_start_including="8.0", version_end_including="8.9") is False

    def test_exclusive_bounds(self):
        # 8.0 < v < 8.9
        assert version_in_range("8.0", version_start_excluding="8.0", version_end_excluding="8.9") is False
        assert version_in_range("8.1", version_start_excluding="8.0", version_end_excluding="8.9") is True
        assert version_in_range("8.8", version_start_excluding="8.0", version_end_excluding="8.9") is True
        assert version_in_range("8.9", version_start_excluding="8.0", version_end_excluding="8.9") is False

    def test_mixed_bounds(self):
        # 8.0 <= v < 9.0
        assert version_in_range("8.0", version_start_including="8.0", version_end_excluding="9.0") is True
        assert version_in_range("8.9.9", version_start_including="8.0", version_end_excluding="9.0") is True
        assert version_in_range("9.0", version_start_including="8.0", version_end_excluding="9.0") is False


class TestCPEMatcher:
    def test_cpe_prefix_matching(self):
        record = ExploitRecord(
            id=1,
            service_name="openssh",
            cpe_prefix="cpe:/a:openbsd:openssh",
            cve_id="CVE-2023-38408",
        )
        matcher = CPEMatcher([record])
        svc = ServiceResult(
            host="10.0.0.1",
            port=22,
            protocol="tcp",
            service="ssh",
            product="OpenSSH",
            version="8.9p1",
            cpe="cpe:/a:openbsd:openssh:8.9p1",
        )
        matches = matcher.match_cpe(svc)
        assert len(matches) == 1
        assert matches[0].match_type == "cpe_version"
        assert matches[0].matched_field == "cpe"

    def test_cpe_version_in_range_matching(self):
        record = ExploitRecord(
            id=2,
            service_name="apache",
            cpe_prefix="cpe:/a:apache:http_server",
            version_start_including="2.4.0",
            version_end_including="2.4.50",
            cve_id="CVE-2021-41773",
        )
        matcher = CPEMatcher([record])

        # Version 2.4.49 (in range) -> match
        svc_vulnerable = ServiceResult(
            host="10.0.0.1",
            port=80,
            protocol="tcp",
            service="http",
            product="Apache httpd",
            version="2.4.49",
            cpe="cpe:/a:apache:http_server:2.4.49",
        )
        matches_v = matcher.match_cpe(svc_vulnerable)
        assert len(matches_v) == 1

        # Version 2.4.52 (out of range) -> no match
        svc_patched = ServiceResult(
            host="10.0.0.1",
            port=80,
            protocol="tcp",
            service="http",
            product="Apache httpd",
            version="2.4.52",
            cpe="cpe:/a:apache:http_server:2.4.52",
        )
        matches_p = matcher.match_cpe(svc_patched)
        assert len(matches_p) == 0

    def test_cpe_missing_target_version(self):
        """When exploit record defines a version range but target has no version string, skip range match."""
        record = ExploitRecord(
            id=3,
            service_name="vsftpd",
            cpe_prefix="cpe:/a:vsftpd:vsftpd",
            version_start_including="2.3.4",
            version_end_including="2.3.4",
        )
        matcher = CPEMatcher([record])

        svc_no_ver = ServiceResult(
            host="10.0.0.1",
            port=21,
            protocol="tcp",
            service="ftp",
            product="vsftpd",
            version="",
            cpe="cpe:/a:vsftpd:vsftpd",
        )
        matches = matcher.match_cpe(svc_no_ver)
        assert len(matches) == 0
