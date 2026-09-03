"""
Nmap network scanning module.
"""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from typing import Any, List

from core.base_module import BaseModule, Finding, ModuleMeta, ModuleOption, OptionType


class Module(BaseModule):

    meta = ModuleMeta(
        id="recon.nmap_scan",
        name="Nmap Port Scanner",
        description="Network reconnaissance using Nmap scanner.",
        author="SentryPack Team",
        version="0.1.0",
        category="recon",
        options=[
            ModuleOption(
                name="TARGET",
                description="Target hostname or IP address",
                option_type=OptionType.STRING,
                required=True,
            ),
            ModuleOption(
                name="PORTS",
                description="Port range specification",
                option_type=OptionType.STRING,
                required=False,
                default="1-1024",
            ),
        ],
    )

    def check(self, ctx: Any) -> bool:
        """Return True — basic check that nmap exists on PATH."""
        import shutil
        if shutil.which("nmap") is None:
            ctx.emit("nmap binary not found on PATH — skipping scan.", event_type="warning")
            return False
        return True

    def run(self, ctx: Any) -> List[Finding]:
        target: str = self.options.get("TARGET") or ""
        ports: str = self.options.get("PORTS", "1-1024")

        if not target:
            ctx.emit(
                "TARGET option is not set or is empty — cannot run nmap scan.",
                event_type="error",
            )
            return []

        ctx.emit(f"Scanning target {target} on ports {ports} (XML output mode)")

        try:
            res = ctx.run_subprocess(["nmap", "-oX", "-", "-p", ports, target])
        except subprocess.TimeoutExpired as exc:
            ctx.emit(str(exc), event_type="error")
            return []
        except Exception as exc:
            ctx.emit(f"Unexpected error during scan: {exc}", event_type="error")
            return []

        try:
            root = ET.fromstring(res.stdout)
        except ET.ParseError as exc:
            ctx.emit(f"Failed to parse Nmap XML output: {exc}", event_type="error")
            return []
        except Exception as exc:
            ctx.emit(f"Unexpected error during scan: {exc}", event_type="error")
            return []

        findings: List[Finding] = []

        for host in root.findall("host"):
            # Only process hosts that are up
            status_elem = host.find("status")
            if status_elem is None or status_elem.get("state") != "up":
                continue

            # Resolve the host IP address
            ip = ""
            address_elem = host.find("address")
            if address_elem is not None:
                ip = address_elem.get("addr", "")

            # Iterate over open ports
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                portid: str = port_elem.get("portid", "")
                protocol: str = port_elem.get("protocol", "")

                # Service element is optional
                svc = port_elem.find("service")
                if svc is not None:
                    name: str = svc.get("name", "")
                    product: str = svc.get("product", "")
                    version: str = svc.get("version", "")
                    extrainfo: str = svc.get("extrainfo", "")
                else:
                    name = product = version = extrainfo = ""

                title = f"Open port {portid}/{protocol} — {name or 'unknown service'}"

                # Build a clean description — omit empty product/version/extrainfo
                desc_parts = [f"Host {ip} has port {portid}/{protocol} open."]
                detail_parts = []
                if product:
                    detail_parts.append(product)
                if version:
                    detail_parts.append(version)
                if extrainfo:
                    detail_parts.append(f"({extrainfo})")
                if detail_parts:
                    desc_parts.append("Service: " + " ".join(detail_parts) + ".")
                description = " ".join(desc_parts)

                evidence = {
                    "host": ip,
                    "port": portid,
                    "protocol": protocol,
                    "service": name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                }

                finding = Finding(
                    title=title,
                    severity="Info",
                    description=description,
                    evidence=evidence,
                )
                ctx.add_finding(finding)
                findings.append(finding)

        if not findings:
            ctx.emit(f"No open ports found on {target}", event_type="info")
            return []

        return findings
