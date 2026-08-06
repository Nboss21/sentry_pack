"""
Base module abstractions, metadata models, options, and findings structures.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional


class OptionType(Enum):
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    ENUM = "enum"
    FILE_PATH = "file_path"


@dataclass
class ModuleOption:
    name: str
    description: str
    option_type: OptionType
    required: bool = True
    default: Optional[Any] = None
    choices: Optional[List[str]] = None


@dataclass
class ModuleMeta:
    id: str
    name: str
    description: str
    author: str
    version: str
    category: str
    options: List[ModuleOption] = field(default_factory=list)


@dataclass
class Finding:
    title: str
    severity: str  # Low, Medium, High, Critical, Info
    description: str
    cve: Optional[str] = None
    cpe: Optional[str] = None
    remediation: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None


class BaseModule:
    """
    Abstract base class for all SentryPack pluggable modules.
    """

    meta: ModuleMeta

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        self.options = options or {}

    def run(self, ctx: Any) -> List[Finding]:
        """
        Main execution logic for the module. Must be overridden by subclasses.
        """
        raise NotImplementedError("Subclasses must implement run()")
