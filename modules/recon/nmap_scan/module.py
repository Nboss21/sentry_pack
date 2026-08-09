"""
Nmap network scanning module.
"""

from __future__ import annotations

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
        target = self.options.get("TARGET")
        ports = self.options.get("PORTS", "1-1024")
        ctx.emit(f"Scanning target {target} on ports {ports}")

        # Run subprocess nmap or stub
        res = ctx.run_subprocess(["nmap", "-p", ports, target])
        finding = Finding(
            title="Open Ports Discovered",
            severity="Info",
            description=f"Scan result output: {res.stdout[:200]}",
        )
        ctx.add_finding(finding)
        return [finding]
