"""
Data models for the SentryPack recommendation engine.

These dataclasses form the shared vocabulary between the scan-result layer
(Nmap module output) and the matching/exploit-lookup layer.

Scan result shape
-----------------
:class:`ServiceResult` mirrors the ``evidence`` dict that
``modules/recon/nmap_scan/module.py`` populates inside each
:class:`~core.base_module.Finding`.  Any future recon module that returns
findings in the same evidence shape will automatically be compatible with the
matching engine.

Exploit table shape
-------------------
:class:`ExploitRecord` is intentionally sparse for Phase 1 — only
``service_name`` is required for prefix/exact matching.  Phase 4 will fill in
``cve_id``, ``module_id``, severity, and CVSS score once the real Exploit DB
is loaded.

Match result shape
------------------
:class:`MatchResult` is what every matcher returns: the record that matched,
which matching strategy fired, and which field of the scan result triggered
it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Scan result
# ---------------------------------------------------------------------------


@dataclass
class ServiceResult:
    """A single service discovered on a host during a recon scan.

    All string fields default to ``""`` (empty) when the scanner did not
    report them — callers should treat ``""`` as "unknown" rather than
    raising errors.

    Attributes:
        host:      IP address string of the scanned host (e.g. ``"10.0.0.1"``).
        port:      Port number (e.g. ``22``).
        protocol:  Transport protocol, typically ``"tcp"`` or ``"udp"``.
        service:   Nmap service name (e.g. ``"ssh"``, ``"http"``, ``"ftp"``).
        product:   Software product name reported by the scanner
                   (e.g. ``"OpenSSH"``, ``"Apache httpd"``).
        version:   Version string (e.g. ``"8.9p1"``, ``"2.4.52"``).
        extrainfo: Extra banner info (e.g. ``"Ubuntu Linux; protocol 2.0"``).
        cpe:       CPE 2.3 URI if Nmap reported one
                   (e.g. ``"cpe:/a:openbsd:openssh:8.9p1"``).
    """

    host: str
    port: int
    protocol: str
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: str = ""

    @classmethod
    def from_finding_evidence(cls, evidence: dict) -> "ServiceResult":
        """Construct a :class:`ServiceResult` from a Finding's evidence dict.

        This is the canonical way to convert an ``nmap_scan`` finding into a
        form the matching engine can consume::

            for finding in findings:
                if finding.evidence:
                    result = ServiceResult.from_finding_evidence(finding.evidence)
                    matches = matcher.match(result)

        Args:
            evidence: The ``evidence`` dict from a
                      :class:`~core.base_module.Finding`.

        Returns:
            A populated :class:`ServiceResult`.
        """
        return cls(
            host=evidence.get("host", ""),
            port=int(evidence.get("port", 0)),
            protocol=evidence.get("protocol", "tcp"),
            service=evidence.get("service", ""),
            product=evidence.get("product", ""),
            version=evidence.get("version", ""),
            extrainfo=evidence.get("extrainfo", ""),
            cpe=evidence.get("cpe", ""),
        )


# ---------------------------------------------------------------------------
# Exploit record
# ---------------------------------------------------------------------------


@dataclass
class ExploitRecord:
    """A single entry in the exploit / known-vulnerability table.

    Attributes:
        id:                       Internal unique identifier.
        service_name:             The canonical service/product name used for matching.
        cve_id:                   CVE identifier (e.g. ``"CVE-2023-38408"``).
        module_id:                SentryPack module that exploits this (e.g. ``"exploit.ssh_cve_2023_38408"``).
        severity:                 Qualitative severity label.
        cvss_score:               CVSS v3 base score (0.0 – 10.0).
        description:              Human-readable summary of the vulnerability.
        has_public_exploit:       Whether a public exploit script/module is available.
        published_date:           Publication date (e.g. ``"2026-01-15"``).
        cpe_prefix:               CPE prefix identifier (e.g. ``"cpe:/a:openbsd:openssh"``).
        version_start_including: Inclusive lower bound for affected versions.
        version_start_excluding: Exclusive lower bound for affected versions.
        version_end_including:   Inclusive upper bound for affected versions.
        version_end_excluding:   Exclusive upper bound for affected versions.
        references:              List of reference URLs or advisory IDs.
    """

    id: int
    service_name: str
    cve_id: Optional[str] = None
    module_id: Optional[str] = None
    severity: str = "Unknown"
    cvss_score: Optional[float] = None
    description: str = ""
    has_public_exploit: bool = True
    published_date: Optional[str] = None
    cpe_prefix: Optional[str] = None
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Match result
# ---------------------------------------------------------------------------


@dataclass
class MatchResult:
    """A single match produced by the recommendation engine.

    Attributes:
        record:          The :class:`ExploitRecord` that matched the scan result.
        match_type:      How it matched — ``"direct"``, ``"cpe_version"``, ``"exact"``, or ``"prefix"``.
        matched_field:   Which field of the :class:`ServiceResult` triggered the match.
        service_result:  The :class:`ServiceResult` that was being matched.
        is_direct_match: True if this match has a direct module available or direct match.
    """

    record: ExploitRecord
    match_type: str          # "direct" | "cpe_version" | "exact" | "prefix"
    matched_field: str       # "service" | "product" | "cpe" | "module_id"
    service_result: ServiceResult
    is_direct_match: bool = False

    def __post_init__(self) -> None:
        if self.match_type == "direct" or (self.record.module_id and self.record.module_id.strip()):
            self.is_direct_match = True

