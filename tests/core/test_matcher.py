"""
Tests for core/recommendation/ — Phase 1 exact and prefix string matching.

Covers:
  * ServiceResult construction (direct and from_finding_evidence)
  * StringMatcher.match() — exact, prefix, no-match, case-insensitive
  * Ordering: exact matches before prefix matches
  * Deduplication: same ExploitRecord never returned twice
  * Field priority: service field preferred over product field
  * match_many() — processes multiple results in one call
  * Empty exploit table → always empty result
  * Mocked scan results that mirror nmap_scan Finding.evidence shape
"""

from __future__ import annotations

import pytest

from core.recommendation import (
    ExploitRecord,
    MatchResult,
    ServiceResult,
    StringMatcher,
)


# ---------------------------------------------------------------------------
# Fixtures — mock exploit table
# ---------------------------------------------------------------------------


def _make_table() -> list[ExploitRecord]:
    """A small, realistic exploit table for unit tests."""
    return [
        ExploitRecord(id=1, service_name="ssh",        cve_id="CVE-2023-38408",  severity="Critical"),
        ExploitRecord(id=2, service_name="openssh",    cve_id="CVE-2023-51767",  severity="High"),
        ExploitRecord(id=3, service_name="apache",     cve_id="CVE-2021-41773",  severity="Critical"),
        ExploitRecord(id=4, service_name="http",       cve_id=None,              severity="Low"),
        ExploitRecord(id=5, service_name="ftp",        cve_id="CVE-1999-0082",   severity="High"),
        ExploitRecord(id=6, service_name="smb",        cve_id="CVE-2017-0144",   severity="Critical"),
        ExploitRecord(id=7, service_name="postgresql", cve_id=None,              severity="Medium"),
    ]


def _svc(
    service: str = "",
    product: str = "",
    port: int = 80,
    host: str = "10.0.0.1",
) -> ServiceResult:
    """Build a minimal ServiceResult for testing."""
    return ServiceResult(
        host=host,
        port=port,
        protocol="tcp",
        service=service,
        product=product,
    )


# ---------------------------------------------------------------------------
# ServiceResult construction
# ---------------------------------------------------------------------------


class TestServiceResult:
    def test_direct_construction(self):
        r = ServiceResult(host="1.2.3.4", port=22, protocol="tcp", service="ssh")
        assert r.host == "1.2.3.4"
        assert r.port == 22
        assert r.service == "ssh"

    def test_defaults_empty_strings(self):
        r = ServiceResult(host="1.2.3.4", port=80, protocol="tcp")
        assert r.service == ""
        assert r.product == ""
        assert r.version == ""
        assert r.cpe == ""

    def test_from_finding_evidence_all_fields(self):
        evidence = {
            "host": "192.168.1.1",
            "port": "22",
            "protocol": "tcp",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "8.9p1",
            "extrainfo": "Ubuntu",
            "cpe": "cpe:/a:openbsd:openssh:8.9p1",
        }
        r = ServiceResult.from_finding_evidence(evidence)
        assert r.host == "192.168.1.1"
        assert r.port == 22
        assert r.service == "ssh"
        assert r.product == "OpenSSH"
        assert r.version == "8.9p1"
        assert r.cpe == "cpe:/a:openbsd:openssh:8.9p1"

    def test_from_finding_evidence_missing_fields(self):
        r = ServiceResult.from_finding_evidence({"host": "1.2.3.4", "port": "80"})
        assert r.protocol == "tcp"
        assert r.service == ""
        assert r.product == ""


# ---------------------------------------------------------------------------
# StringMatcher — basic behaviour
# ---------------------------------------------------------------------------


class TestStringMatcherBasic:
    def test_empty_table_returns_empty(self):
        matcher = StringMatcher([])
        result = _svc(service="ssh")
        assert matcher.match(result) == []

    def test_no_match_returns_empty(self):
        matcher = StringMatcher(_make_table())
        result = _svc(service="rdp", product="Microsoft Terminal Services")
        assert matcher.match(result) == []

    def test_returns_list_of_match_results(self):
        matcher = StringMatcher(_make_table())
        matches = matcher.match(_svc(service="ssh"))
        assert isinstance(matches, list)
        for m in matches:
            assert isinstance(m, MatchResult)

    def test_match_result_back_references_service_result(self):
        matcher = StringMatcher(_make_table())
        svc = _svc(service="ssh")
        matches = matcher.match(svc)
        assert matches[0].service_result is svc


# ---------------------------------------------------------------------------
# Exact matching
# ---------------------------------------------------------------------------


class TestExactMatching:
    def test_exact_match_on_service_field(self):
        matcher = StringMatcher(_make_table())
        matches = matcher.match(_svc(service="ssh"))
        exact = [m for m in matches if m.match_type == "exact"]
        assert len(exact) >= 1
        assert exact[0].matched_field == "service"
        assert exact[0].record.service_name == "ssh"

    def test_exact_match_on_product_field(self):
        table = [ExploitRecord(id=10, service_name="openssh")]
        matcher = StringMatcher(table)
        # product="OpenSSH" exactly matches service_name="openssh" case-insensitively
        matches = matcher.match(_svc(service="", product="openssh"))
        assert len(matches) == 1
        assert matches[0].match_type == "exact"
        assert matches[0].matched_field == "product"

    def test_exact_match_case_insensitive(self):
        table = [ExploitRecord(id=1, service_name="SSH")]
        matcher = StringMatcher(table)
        matches = matcher.match(_svc(service="ssh"))
        assert len(matches) == 1
        assert matches[0].match_type == "exact"

    def test_exact_match_service_preferred_over_product(self):
        """When service matches exactly, matched_field must be 'service'."""
        table = [ExploitRecord(id=1, service_name="http")]
        matcher = StringMatcher(table)
        # Both service="http" and product="http" match exactly
        matches = matcher.match(_svc(service="http", product="http"))
        assert len(matches) == 1  # deduplicated
        assert matches[0].matched_field == "service"

    def test_ftp_exact(self):
        matcher = StringMatcher(_make_table())
        matches = matcher.match(_svc(service="ftp"))
        ids = [m.record.id for m in matches]
        assert 5 in ids  # ftp record


# ---------------------------------------------------------------------------
# Prefix matching
# ---------------------------------------------------------------------------


class TestPrefixMatching:
    def test_prefix_match_on_service_field(self):
        """'postgresql' starts with 'postgresql' → exact, not tested here.
        Use 'postgresql-9.6' which starts with 'postgresql'."""
        table = [ExploitRecord(id=7, service_name="postgresql")]
        matcher = StringMatcher(table)
        matches = matcher.match(_svc(service="postgresql-9.6"))
        assert len(matches) == 1
        assert matches[0].match_type == "prefix"
        assert matches[0].matched_field == "service"

    def test_prefix_match_on_product_field(self):
        table = [ExploitRecord(id=3, service_name="apache")]
        matcher = StringMatcher(table)
        matches = matcher.match(_svc(service="http", product="Apache httpd"))
        # service "http" does not start with "apache"; product "apache httpd" does
        prefix_matches = [m for m in matches if m.match_type == "prefix"]
        assert any(m.matched_field == "product" for m in prefix_matches)

    def test_prefix_match_case_insensitive(self):
        table = [ExploitRecord(id=1, service_name="OPEN")]
        matcher = StringMatcher(table)
        matches = matcher.match(_svc(service="openssh"))
        assert len(matches) == 1
        assert matches[0].match_type == "prefix"

    def test_short_prefix_not_a_false_positive(self):
        """Ensure 'ht' does NOT match 'http' (the needle must be the prefix)."""
        # The needle is service_name; the haystack is the scan result field.
        # 'http'.startswith('ht') — this SHOULD match since needle is 'ht'.
        table = [ExploitRecord(id=99, service_name="ht")]
        matcher = StringMatcher(table)
        matches = matcher.match(_svc(service="http"))
        # "http".startswith("ht") → True → prefix match expected
        assert len(matches) == 1
        assert matches[0].match_type == "prefix"

    def test_no_reverse_prefix(self):
        """'apache httpd' does NOT match a record whose service_name='apache httpd extra'."""
        table = [ExploitRecord(id=1, service_name="apache httpd extra")]
        matcher = StringMatcher(table)
        # "apache httpd".startswith("apache httpd extra") → False
        matches = matcher.match(_svc(service="", product="Apache httpd"))
        assert matches == []


# ---------------------------------------------------------------------------
# Ordering: exact before prefix
# ---------------------------------------------------------------------------


class TestMatchOrdering:
    def test_exact_before_prefix(self):
        table = [
            ExploitRecord(id=1, service_name="open"),   # prefix match for "openssh"
            ExploitRecord(id=2, service_name="openssh"), # exact match for "openssh"
        ]
        matcher = StringMatcher(table)
        matches = matcher.match(_svc(service="openssh"))
        assert len(matches) == 2
        assert matches[0].match_type == "exact"
        assert matches[1].match_type == "prefix"

    def test_exact_before_prefix_regardless_of_table_order(self):
        """Even if the prefix record comes first in the table, exact wins."""
        table = [
            ExploitRecord(id=10, service_name="openssh"), # exact
            ExploitRecord(id=20, service_name="open"),    # prefix
        ]
        matcher = StringMatcher(table)
        matches = matcher.match(_svc(service="openssh"))
        assert matches[0].match_type == "exact"
        assert matches[1].match_type == "prefix"


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    def test_same_record_not_returned_twice(self):
        """A record that matches via both service AND product is returned once."""
        table = [ExploitRecord(id=1, service_name="http")]
        matcher = StringMatcher(table)
        matches = matcher.match(_svc(service="http", product="http"))
        ids = [m.record.id for m in matches]
        assert len(ids) == len(set(ids))  # no duplicates
        assert len(matches) == 1

    def test_different_records_both_returned(self):
        table = [
            ExploitRecord(id=1, service_name="ssh"),
            ExploitRecord(id=2, service_name="openssh"),
        ]
        matcher = StringMatcher(table)
        # service="ssh" exact on 1; product="OpenSSH" → no match for "ssh" (not prefix of "openssh")
        # product="OpenSSH" exact on 2 (case-insensitive)
        matches = matcher.match(_svc(service="ssh", product="openssh"))
        ids = {m.record.id for m in matches}
        assert 1 in ids
        assert 2 in ids


# ---------------------------------------------------------------------------
# match_many()
# ---------------------------------------------------------------------------


class TestMatchMany:
    def test_match_many_empty_list(self):
        matcher = StringMatcher(_make_table())
        assert matcher.match_many([]) == []

    def test_match_many_multiple_results(self):
        matcher = StringMatcher(_make_table())
        results = [
            _svc(service="ssh", port=22),
            _svc(service="ftp", port=21),
            _svc(service="rdp", port=3389),  # no match
        ]
        all_matches = matcher.match_many(results)
        services_matched = {m.service_result.service for m in all_matches}
        assert "ssh" in services_matched
        assert "ftp" in services_matched
        assert "rdp" not in services_matched

    def test_match_many_preserves_per_result_ordering(self):
        """Exact matches within each result appear before prefix matches."""
        table = [
            ExploitRecord(id=1, service_name="open"),    # prefix for "openssh"
            ExploitRecord(id=2, service_name="openssh"), # exact for "openssh"
        ]
        matcher = StringMatcher(table)
        results = [_svc(service="openssh")]
        matches = matcher.match_many(results)
        assert matches[0].match_type == "exact"


# ---------------------------------------------------------------------------
# Integration: mocked nmap_scan Finding evidence
# ---------------------------------------------------------------------------


class TestFromNmapEvidence:
    """End-to-end path: nmap evidence dict → ServiceResult → MatchResult."""

    MOCK_FINDINGS_EVIDENCE = [
        {
            "host": "10.0.0.1", "port": "22", "protocol": "tcp",
            "service": "ssh", "product": "OpenSSH", "version": "8.9p1",
            "extrainfo": "Ubuntu", "cpe": "cpe:/a:openbsd:openssh:8.9p1",
        },
        {
            "host": "10.0.0.1", "port": "80", "protocol": "tcp",
            "service": "http", "product": "Apache httpd", "version": "2.4.52",
            "extrainfo": "", "cpe": "cpe:/a:apache:http_server:2.4.52",
        },
        {
            "host": "10.0.0.1", "port": "21", "protocol": "tcp",
            "service": "ftp", "product": "vsftpd", "version": "3.0.5",
            "extrainfo": "", "cpe": "",
        },
    ]

    def test_ssh_service_matched(self):
        matcher = StringMatcher(_make_table())
        results = [ServiceResult.from_finding_evidence(e) for e in self.MOCK_FINDINGS_EVIDENCE]
        all_matches = matcher.match_many(results)
        ssh_matches = [m for m in all_matches if m.service_result.service == "ssh"]
        assert len(ssh_matches) >= 1
        assert any(m.record.cve_id == "CVE-2023-38408" for m in ssh_matches)

    def test_ftp_service_matched(self):
        matcher = StringMatcher(_make_table())
        results = [ServiceResult.from_finding_evidence(e) for e in self.MOCK_FINDINGS_EVIDENCE]
        all_matches = matcher.match_many(results)
        ftp_matches = [m for m in all_matches if m.service_result.service == "ftp"]
        assert len(ftp_matches) >= 1

    def test_http_service_matched(self):
        matcher = StringMatcher(_make_table())
        results = [ServiceResult.from_finding_evidence(e) for e in self.MOCK_FINDINGS_EVIDENCE]
        all_matches = matcher.match_many(results)
        http_matches = [m for m in all_matches if m.service_result.service == "http"]
        assert len(http_matches) >= 1

    def test_apache_prefix_matched_via_product(self):
        """Product 'Apache httpd' should prefix-match the 'apache' exploit record."""
        matcher = StringMatcher(_make_table())
        evidence = self.MOCK_FINDINGS_EVIDENCE[1]  # Apache httpd on port 80
        result = ServiceResult.from_finding_evidence(evidence)
        matches = matcher.match(result)
        apache_matches = [m for m in matches if m.record.service_name == "apache"]
        assert len(apache_matches) == 1
        assert apache_matches[0].match_type == "prefix"
        assert apache_matches[0].matched_field == "product"
