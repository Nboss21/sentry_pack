"""
Tests for the recon.nmap_scan module.

Verifies:
  * Two open ports in XML → 2 Findings with correct title format and evidence fields.
  * XML with no open ports → empty list, no exception.
  * Malformed XML → empty list, no exception.
  * run_subprocess raising TimeoutExpired → empty list, no exception.
"""

from __future__ import annotations

import asyncio
import importlib.util
import subprocess
from pathlib import Path
from typing import Any, List
from unittest.mock import MagicMock, patch

import pytest

from core.base_module import Finding
from core.execution import ExecutionContext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_module():
    """Dynamically import the nmap_scan Module class."""
    spec = importlib.util.spec_from_file_location(
        "nmap_scan.module",
        Path(__file__).resolve().parents[2] / "modules" / "recon" / "nmap_scan" / "module.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.Module


def _make_ctx() -> ExecutionContext:
    """Create a test ExecutionContext backed by a fresh asyncio.Queue."""
    return ExecutionContext(
        run_id="test-nmap-001",
        target="192.168.1.1",
        queue=asyncio.Queue(),
    )


# Full-service XML: host up, 2 open ports — port 22 has full service attrs,
# port 80 has only name.
_SAMPLE_XML_TWO_PORTS = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu Linux"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# XML with a host that is up but no open ports
_SAMPLE_XML_NO_OPEN_PORTS = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# XML where the host is down
_SAMPLE_XML_HOST_DOWN = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports/>
  </host>
</nmaprun>
"""

_MALFORMED_XML = "this is not xml <<< broken"


def _make_completed_process(stdout: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["nmap"],
        returncode=0,
        stdout=stdout,
        stderr="",
    )


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestNmapScanModule:
    def setup_method(self):
        self.Module = _load_module()

    # ------------------------------------------------------------------
    # Meta contract
    # ------------------------------------------------------------------

    def test_meta_id(self):
        assert self.Module.meta.id == "recon.nmap_scan"

    def test_has_target_option(self):
        names = [o.name for o in self.Module.meta.options]
        assert "TARGET" in names

    def test_has_ports_option(self):
        names = [o.name for o in self.Module.meta.options]
        assert "PORTS" in names

    # ------------------------------------------------------------------
    # check()
    # ------------------------------------------------------------------

    def test_check_true_when_nmap_on_path(self):
        mod = self.Module(options={"TARGET": "127.0.0.1"})
        ctx = _make_ctx()
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            result = mod.check(ctx)
        assert result is True

    def test_check_false_when_nmap_not_on_path(self):
        mod = self.Module(options={"TARGET": "127.0.0.1"})
        ctx = _make_ctx()
        with patch("shutil.which", return_value=None):
            result = mod.check(ctx)
        assert result is False

    # ------------------------------------------------------------------
    # run() — two open ports (one with full service attrs, one with name only)
    # ------------------------------------------------------------------

    def test_two_open_ports_returns_two_findings(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_SAMPLE_XML_TWO_PORTS)
        )
        findings = mod.run(ctx)
        assert len(findings) == 2

    def test_findings_are_Finding_instances(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_SAMPLE_XML_TWO_PORTS)
        )
        findings = mod.run(ctx)
        for f in findings:
            assert isinstance(f, Finding)

    def test_ssh_port_title_format(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_SAMPLE_XML_TWO_PORTS)
        )
        findings = mod.run(ctx)
        titles = [f.title for f in findings]
        assert "Open port 22/tcp — ssh" in titles

    def test_http_port_title_format(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_SAMPLE_XML_TWO_PORTS)
        )
        findings = mod.run(ctx)
        titles = [f.title for f in findings]
        assert "Open port 80/tcp — http" in titles

    def test_ssh_finding_severity_info(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_SAMPLE_XML_TWO_PORTS)
        )
        findings = mod.run(ctx)
        assert all(f.severity == "Info" for f in findings)

    def test_ssh_evidence_fields_populated(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_SAMPLE_XML_TWO_PORTS)
        )
        findings = mod.run(ctx)
        ssh_finding = next(f for f in findings if "22" in f.title)
        ev = ssh_finding.evidence
        assert ev["host"] == "192.168.1.1"
        assert ev["port"] == "22"
        assert ev["protocol"] == "tcp"
        assert ev["service"] == "ssh"
        assert ev["product"] == "OpenSSH"
        assert ev["version"] == "8.9p1"
        assert ev["extrainfo"] == "Ubuntu Linux"

    def test_http_evidence_has_empty_product(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_SAMPLE_XML_TWO_PORTS)
        )
        findings = mod.run(ctx)
        http_finding = next(f for f in findings if "80" in f.title)
        ev = http_finding.evidence
        assert ev["service"] == "http"
        assert ev["product"] == ""
        assert ev["version"] == ""

    def test_findings_added_to_ctx(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_SAMPLE_XML_TWO_PORTS)
        )
        findings = mod.run(ctx)
        assert len(ctx.findings) == 2
        assert ctx.findings == findings

    def test_closed_port_not_included(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_SAMPLE_XML_TWO_PORTS)
        )
        findings = mod.run(ctx)
        # Port 443 is closed — must not appear
        titles = [f.title for f in findings]
        assert not any("443" in t for t in titles)

    # ------------------------------------------------------------------
    # run() — no open ports → empty list, no exception
    # ------------------------------------------------------------------

    def test_no_open_ports_returns_empty_list(self):
        mod = self.Module(options={"TARGET": "192.168.1.2", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_SAMPLE_XML_NO_OPEN_PORTS)
        )
        findings = mod.run(ctx)
        assert findings == []

    def test_no_open_ports_does_not_raise(self):
        mod = self.Module(options={"TARGET": "192.168.1.2", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_SAMPLE_XML_NO_OPEN_PORTS)
        )
        # Must not raise
        mod.run(ctx)

    def test_host_down_returns_empty_list(self):
        mod = self.Module(options={"TARGET": "10.0.0.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_SAMPLE_XML_HOST_DOWN)
        )
        findings = mod.run(ctx)
        assert findings == []

    # ------------------------------------------------------------------
    # run() — malformed XML → empty list, no exception
    # ------------------------------------------------------------------

    def test_malformed_xml_returns_empty_list(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_MALFORMED_XML)
        )
        findings = mod.run(ctx)
        assert findings == []

    def test_malformed_xml_does_not_raise(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_MALFORMED_XML)
        )
        mod.run(ctx)  # must not raise

    def test_malformed_xml_emits_error_event(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_MALFORMED_XML)
        )
        emitted: list = []
        original_emit = ctx.emit

        def _capture_emit(msg, event_type="log"):
            emitted.append((msg, event_type))
            original_emit(msg, event_type=event_type)

        ctx.emit = _capture_emit
        mod.run(ctx)
        error_events = [(m, t) for m, t in emitted if t == "error"]
        assert len(error_events) >= 1

    # ------------------------------------------------------------------
    # run() — TimeoutExpired → empty list, no exception
    # ------------------------------------------------------------------

    def test_timeout_expired_returns_empty_list(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            side_effect=subprocess.TimeoutExpired(cmd=["nmap"], timeout=300)
        )
        findings = mod.run(ctx)
        assert findings == []

    def test_timeout_expired_does_not_raise(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            side_effect=subprocess.TimeoutExpired(cmd=["nmap"], timeout=300)
        )
        mod.run(ctx)  # must not raise

    def test_timeout_expired_emits_error_event(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            side_effect=subprocess.TimeoutExpired(cmd=["nmap"], timeout=300)
        )
        emitted: list = []
        original_emit = ctx.emit

        def _capture_emit(msg, event_type="log"):
            emitted.append((msg, event_type))
            original_emit(msg, event_type=event_type)

        ctx.emit = _capture_emit
        mod.run(ctx)
        error_events = [(m, t) for m, t in emitted if t == "error"]
        assert len(error_events) >= 1

    # ------------------------------------------------------------------
    # run() — description cleanliness (no "None" or blank trailing text)
    # ------------------------------------------------------------------

    def test_description_no_none_strings(self):
        mod = self.Module(options={"TARGET": "192.168.1.1", "PORTS": "1-1024"})
        ctx = _make_ctx()
        ctx.run_subprocess = MagicMock(
            return_value=_make_completed_process(_SAMPLE_XML_TWO_PORTS)
        )
        findings = mod.run(ctx)
        for f in findings:
            assert "None" not in f.description
