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

    Phase 1 only needs ``service_name`` for string matching.  All other
    fields are optional stubs that Phase 4 will populate from the NVD / Exploit
    DB import.

    Attributes:
        id:           Internal unique identifier (auto-incremented int or UUID).
        service_name: The canonical service/product name used for matching
                      (e.g. ``"ssh"``, ``"openssh"``, ``"apache"``).
        cve_id:       CVE identifier, if known (e.g. ``"CVE-2023-38408"``).
        module_id:    SentryPack module that exploits this vulnerability,
                      if one exists (e.g. ``"exploit.ssh_cve_2023_38408"``).
        severity:     Qualitative severity label
                      (``"Info"``, ``"Low"``, ``"Medium"``, ``"High"``,
                      ``"Critical"``).  Defaults to ``"Unknown"`` until
                      populated.
        cvss_score:   CVSS v3 base score (0.0 – 10.0).  ``None`` until
                      populated.
        description:  Human-readable summary of the vulnerability.
    """

    id: int
    service_name: str
    cve_id: Optional[str] = None
    module_id: Optional[str] = None
    severity: str = "Unknown"
    cvss_score: Optional[float] = None
    description: str = ""


# ---------------------------------------------------------------------------
# Match result
# ---------------------------------------------------------------------------


@dataclass
class MatchResult:
    """A single match produced by the recommendation engine.

    Attributes:
        record:        The :class:`ExploitRecord` that matched the scan result.
        match_type:    How it matched — ``"exact"`` or ``"prefix"``.
        matched_field: Which field of the :class:`ServiceResult` triggered
                       the match — ``"service"`` or ``"product"``.
        service_result: The :class:`ServiceResult` that was being matched
                        (back-reference for context).
    """

    record: ExploitRecord
    match_type: str          # "exact" | "prefix"
    matched_field: str       # "service" | "product"
    service_result: ServiceResult
