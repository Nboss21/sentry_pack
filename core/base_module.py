"""
Base module abstractions, metadata models, options, and finding structures.

This module defines the complete plugin contract that every SentryPack
module must satisfy.  The three key pieces are:

* **Data models** – :class:`OptionType`, :class:`ModuleOption`,
  :class:`ModuleMeta`, :class:`Finding`
* **Abstract base** – :class:`BaseModule` (enforce ``check`` + ``run``)
* **Execution context** – consumed from :mod:`core.execution`
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Option types
# ---------------------------------------------------------------------------


class OptionType(Enum):
    """Discriminator for the kinds of values a :class:`ModuleOption` may hold.

    Used by the GUI's :class:`~gui.widgets.config_form_generator.ConfigFormGenerator`
    to render the correct input widget for each option.
    """

    STRING = "string"
    """A free-form text value (e.g. a hostname, a URL, a regex)."""

    INTEGER = "integer"
    """A whole-number value (e.g. a port, a thread count)."""

    BOOLEAN = "boolean"
    """A flag that is either ``True`` or ``False``."""

    ENUM = "enum"
    """One value selected from a fixed set of :attr:`~ModuleOption.choices`."""

    FILE_PATH = "file_path"
    """An absolute or relative path to a file on disk."""


# ---------------------------------------------------------------------------
# Module option
# ---------------------------------------------------------------------------


@dataclass
class ModuleOption:
    """A single configurable parameter exposed by a module.

    Attributes:
        name:        Machine-readable key used in the options dict at runtime.
        description: Human-readable explanation shown in the GUI / CLI.
        option_type: The :class:`OptionType` that constrains valid values.
        required:    When *True* the registry will refuse to run the module
                     unless this option has been set.
        default:     Optional default value; may be ``None`` for required opts.
        choices:     Non-empty list of allowed strings when
                     ``option_type`` is :attr:`OptionType.ENUM`, else ``None``.
    """

    name: str
    description: str
    option_type: OptionType
    required: bool = True
    default: Optional[Any] = None
    choices: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------


@dataclass
class ModuleMeta:
    """Declarative descriptor attached to every :class:`BaseModule` subclass.

    The registry reads this object to populate the module catalogue without
    instantiating the module class.

    Attributes:
        id:          Globally unique dot-separated identifier
                     (e.g. ``"recon.nmap_scan"``).
        name:        Short display name shown in the GUI module browser.
        description: One-sentence summary of what the module does.
        author:      Name / handle of the primary author.
        version:     Semantic version string (``"MAJOR.MINOR.PATCH"``).
        category:    Top-level category slug (``"recon"``, ``"exploit"``, …).
        options:     Ordered list of :class:`ModuleOption` the module accepts.
        timeout:     Maximum wall-clock seconds the runner grants to
                     :meth:`~BaseModule.run` before it is forcibly killed.
                     ``None`` means "use the runner's global default" (60 s).
    """

    id: str
    name: str
    description: str
    author: str
    version: str
    category: str
    options: List[ModuleOption] = field(default_factory=list)
    timeout: Optional[int] = None



# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single vulnerability or observation produced by a module run.

    Findings are persisted to the database and surfaced in the GUI
    findings view and the PDF / HTML report.

    Attributes:
        title:       Short one-line headline (e.g. ``"Open SSH port"``).
        severity:    One of ``"Info"``, ``"Low"``, ``"Medium"``, ``"High"``,
                     ``"Critical"``.
        description: Detailed explanation of what was found and why it matters.
        cve:         Optional CVE identifier (e.g. ``"CVE-2021-44228"``).
        cpe:         Optional CPE 2.3 URI (e.g. ``"cpe:2.3:a:vendor:product:…"``).
        remediation: Suggested fix or mitigation steps.
        evidence:    Arbitrary JSON-serialisable data attached as proof
                     (e.g. raw scanner output, packet captures).
    """

    title: str
    severity: str  # "Info" | "Low" | "Medium" | "High" | "Critical"
    description: str
    cve: Optional[str] = None
    cpe: Optional[str] = None
    remediation: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Abstract base module
# ---------------------------------------------------------------------------


class BaseModule(abc.ABC):
    """Abstract base class every SentryPack plugin module must subclass.

    Subclass contract
    -----------------
    * Declare a **class-level** :attr:`meta` attribute of type
      :class:`ModuleMeta`.
    * Implement :meth:`check` to perform a lightweight pre-flight check
      (e.g. verify the target is reachable, that a required binary exists).
    * Implement :meth:`run` to perform the actual work and return findings.

    Example skeleton::

        class Module(BaseModule):
            meta = ModuleMeta(
                id="recon.example",
                name="Example",
                description="Does nothing useful.",
                author="Alice",
                version="0.1.0",
                category="recon",
                options=[
                    ModuleOption("TARGET", "Target host", OptionType.STRING),
                ],
            )

            def check(self, ctx: ExecutionContext) -> bool:
                return True   # always safe to run

            def run(self, ctx: ExecutionContext) -> List[Finding]:
                ctx.emit("Running example module")
                return [Finding(title="OK", severity="Info", description="Nothing to report.")]
    """

    #: Every concrete subclass **must** define this at class level.
    meta: ModuleMeta

    def __init__(self, options: Optional[Dict[str, Any]] = None) -> None:
        """Initialise the module with a user-supplied options mapping.

        Args:
            options: Key/value pairs corresponding to the option names
                     declared in :attr:`meta`.options.  Missing keys fall
                     back to each option's ``default`` at runtime.
        """
        self.options: Dict[str, Any] = options or {}

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def check(self, ctx: Any) -> bool:
        """Return ``True`` when it is safe to proceed with :meth:`run`.

        Perform inexpensive pre-flight verification here: confirm a binary
        is available, ping the target, validate option values, etc.

        Args:
            ctx: The :class:`~core.execution.ExecutionContext` for this run.

        Returns:
            ``True``  — module may proceed.
            ``False`` — module should be skipped; the runner will mark the
                        run as *skipped* and will **not** call :meth:`run`.
        """

    @abc.abstractmethod
    def run(self, ctx: Any) -> List[Finding]:
        """Execute the module's main logic and return a list of findings.

        The method must be **synchronous**.  All subprocess calls should go
        through :meth:`~core.execution.ExecutionContext.run_subprocess` so
        that timeouts and logging are handled consistently.

        Args:
            ctx: The :class:`~core.execution.ExecutionContext` for this run.

        Returns:
            A (possibly empty) list of :class:`Finding` objects.
        """
