"""
Hello World — trivial smoke-test module.

Purpose
-------
This module exists solely to give Person B (API) and Person C (GUI)
a **real, working module** to register and invoke before any actual
feature module is written.  It performs no genuine security work.

Design constraints (from the task spec)
----------------------------------------
* One string option (``GREETING``).
* :meth:`check` always returns ``True``.
* :meth:`run` sleeps for **2 seconds**, calls ``ctx.emit("still working…")``
  exactly once during that sleep, then returns a **single** :class:`Finding`.
"""

from __future__ import annotations

import time
from typing import Any, List

from core.base_module import BaseModule, Finding, ModuleMeta, ModuleOption, OptionType


class Module(BaseModule):
    """Smoke-test module that always succeeds and produces one finding.

    Inherits from :class:`~core.base_module.BaseModule` and satisfies the
    full plugin contract without any external dependencies.
    """

    meta: ModuleMeta = ModuleMeta(
        id="dev.hello_world",
        name="Hello World",
        description=(
            "Trivial smoke-test module. Exists to give the API and GUI "
            "something real to register and call before any actual feature exists."
        ),
        author="SentryPack Core Team",
        version="0.1.0",
        category="dev",
        options=[
            ModuleOption(
                name="GREETING",
                description="A greeting string to include in the finding description.",
                option_type=OptionType.STRING,
                required=False,
                default="Hello, SentryPack!",
            )
        ],
    )

    # ------------------------------------------------------------------
    # Pre-flight check
    # ------------------------------------------------------------------

    def check(self, ctx: Any) -> bool:
        """Always returns ``True`` — no preconditions required.

        Args:
            ctx: The :class:`~core.execution.ExecutionContext` for this run.

        Returns:
            ``True`` unconditionally.
        """
        return True

    # ------------------------------------------------------------------
    # Main execution
    # ------------------------------------------------------------------

    def run(self, ctx: Any) -> List[Finding]:
        """Sleep for 2 seconds, emit one progress message, return one finding.

        Behaviour (exactly per spec):

        1. Sleep 1 second.
        2. Call ``ctx.emit("still working…")`` once.
        3. Sleep 1 more second (total = 2 s).
        4. Build and return a single :class:`~core.base_module.Finding`.

        Args:
            ctx: The :class:`~core.execution.ExecutionContext` for this run.

        Returns:
            A list containing exactly one :class:`~core.base_module.Finding`
            with ``severity="Info"``.
        """
        greeting: str = self.options.get("GREETING", "Hello, SentryPack!")

        # Half of the 2-second delay, then emit progress, then the other half.
        time.sleep(1)
        ctx.emit("still working...")
        time.sleep(1)

        finding = Finding(
            title="Hello World",
            severity="Info",
            description=greeting,
            remediation="No action required — this is a smoke-test finding.",
        )
        ctx.add_finding(finding)
        return [finding]
