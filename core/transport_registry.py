"""
Transport registry for scanning transport plugin directories, dynamically loading,
validating against ITransport, and managing active transport plugins.
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type

from core.transport_base import ITransport, TransportMeta

logger = logging.getLogger("sentrypack.transport_registry")


class TransportRegistry:
    """Scans, validates, and manages available SentryPack transport plugins."""

    def __init__(self) -> None:
        self._transports: Dict[str, Type[ITransport]] = {}

    def scan(self, transport_dir: Path) -> None:
        """Scan directory tree for transport plugins in subdirectories."""
        t_dir = Path(transport_dir)
        if not t_dir.exists() or not t_dir.is_dir():
            logger.warning("Transport directory %s does not exist or is not a directory", t_dir)
            return

        for plugin_dir in sorted(t_dir.iterdir()):
            if not plugin_dir.is_dir() or plugin_dir.name.startswith((".", "_")):
                continue
            try:
                transport_cls = self.load_transport(plugin_dir)
                if transport_cls is not None:
                    t_id = transport_cls.meta.id
                    if t_id in self._transports:
                        logger.warning(
                            "Duplicate transport ID '%s' found in %s. Keeping already registered transport.",
                            t_id,
                            plugin_dir,
                        )
                    else:
                        self._transports[t_id] = transport_cls
                        logger.info("Loaded transport plugin '%s' from %s", t_id, plugin_dir)
            except Exception as exc:
                logger.warning("Failed to load transport plugin from %s: %s", plugin_dir, exc)

    def load_transport(self, plugin_dir: Path) -> Optional[Type[ITransport]]:
        """Dynamically load and validate an ITransport subclass from a plugin directory."""
        p_dir = Path(plugin_dir)
        if not p_dir.is_dir():
            logger.warning("%s is not a directory", p_dir)
            return None

        transport_file = p_dir / "transport.py"
        if not transport_file.exists():
            logger.warning("transport.py not found in %s", p_dir)
            return None

        try:
            spec = importlib.util.spec_from_file_location(
                f"transports.{p_dir.name}.transport", transport_file
            )
            if spec is None or spec.loader is None:
                logger.warning("Could not load spec for %s", transport_file)
                return None
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        except Exception as exc:
            logger.warning("Error loading module %s: %s", transport_file, exc)
            return None

        # Inspect module for ITransport subclasses
        candidates: List[Type[ITransport]] = []
        for name in dir(mod):
            obj = getattr(mod, name)
            is_valid, _ = self._validate_transport(obj)
            if is_valid:
                candidates.append(obj)

        if not candidates:
            logger.warning("No valid ITransport subclass found in %s", transport_file)
            return None

        return candidates[0]

    def _validate_transport(self, cls: Any) -> Tuple[bool, str]:
        """Validate that cls is a concrete ITransport subclass with a valid TransportMeta."""
        if not isinstance(cls, type):
            return False, "Object is not a class"

        try:
            if not issubclass(cls, ITransport) or cls is ITransport:
                return False, "Class does not subclass ITransport"
        except TypeError:
            return False, "Object is not a valid type/class"

        if not hasattr(cls, "meta"):
            return False, "Class is missing 'meta' attribute"

        meta = getattr(cls, "meta")
        if not isinstance(meta, TransportMeta):
            return False, f"'meta' attribute is not of type TransportMeta (got {type(meta).__name__})"

        if not getattr(meta, "id", None) or not isinstance(meta.id, str):
            return False, "TransportMeta 'id' must be a non-empty string"

        if inspect.isabstract(cls) or getattr(cls, "__abstractmethods__", None):
            return False, f"Class has unimplemented abstract methods: {getattr(cls, '__abstractmethods__', set())}"

        for method_name in ("connect", "send", "receive", "disconnect"):
            if not callable(getattr(cls, method_name, None)):
                return False, f"Class is missing required method '{method_name}'"

        return True, ""

    def get_transport(self, transport_id: str) -> Optional[Type[ITransport]]:
        """Retrieve loaded transport class by its meta.id."""
        return self._transports.get(transport_id)

    def list_transports(self) -> List[TransportMeta]:
        """Return metadata for all loaded transport plugins."""
        return [cls.meta for cls in self._transports.values()]


transport_registry = TransportRegistry()
