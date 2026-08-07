"""
Module template — copy this folder to start a new SentryPack module.

Steps
-----
1. Duplicate the ``_template/`` directory to ``modules/<category>/<module_name>/``.
2. Edit ``module.toml`` — fill in ``id``, ``name``, ``description``, etc.
3. Replace the placeholder ``meta``, ``check()``, and ``run()`` bodies below.
4. Run ``python scripts/validate_module.py modules/<category>/<module_name>``
   to verify the manifest before opening a PR.
"""

from __future__ import annotations

from typing import Any, List

from core.base_module import BaseModule, Finding, ModuleMeta, ModuleOption, OptionType


class Module(BaseModule):
    """Replace this docstring with a one-paragraph summary of your module."""

    meta: ModuleMeta = ModuleMeta(
        id="template_module",           # change to "category.module_name"
        name="Template Module",         # display name in the GUI
        description="Starting point template for developing new SentryPack modules.",
        author="Your Name",
        version="0.1.0",
        category="recon",              # recon | exploit | c2 | analysis | dev
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

    def check(self, ctx: Any) -> bool:
        """Return True if it is safe to run this module against the target.

        Typical checks: required binary exists, target responds to ping,
        options are valid.  Keep this fast — no heavy work here.
        """
        return True  # replace with real precondition logic

    def run(self, ctx: Any) -> List[Finding]:
        """Execute module logic and return findings.

        Use ``ctx.emit("message")`` for progress updates and
        ``ctx.add_finding(finding)`` (or just append to the return list)
        for results.
        """
        ctx.emit("Executing template module...")
        finding = Finding(
            title="Sample Template Finding",
            severity="Info",
            description="Template module executed successfully.",
        )
        ctx.add_finding(finding)
        return [finding]
