"""
Template module implementation for SentryPack module authoring reference.
"""

from typing import List
from core.base_module import BaseModule, Finding, ModuleMeta, ModuleOption, OptionType


class Module(BaseModule):

    meta = ModuleMeta(
        id="template_module",
        name="Template Module",
        description="Starting point template for developing new SentryPack modules.",
        author="SentryPack Core Team",
        version="0.1.0",
        category="recon",
        options=[
            ModuleOption(
                name="TARGET",
                description="Target host or IP address",
                option_type=OptionType.STRING,
                required=True,
                default="127.0.0.1",
            )
        ],
    )

    def run(self, ctx) -> List[Finding]:
        ctx.emit("info", {"message": "Executing template module..."})
        finding = Finding(
            title="Sample Template Finding",
            severity="Info",
            description="Template module executed successfully.",
        )
        ctx.add_finding(finding)
        return [finding]
