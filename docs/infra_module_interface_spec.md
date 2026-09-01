# Infrastructure Module Interface Spec (Phase 6)

## Overview

The `IInfrastructureModule` interface establishes the foundational architectural contract for pluggable, persistent, and controllable infrastructure components within SentryPack (e.g., HTTP/S forward/reverse proxies, TLS tunnels, DNS redirectors, CDN domain-fronters).

Unlike ephemeral reconnaissance or exploit modules that execute sequentially to produce findings, infrastructure modules operate as controllable long-running services. They support penetration testing and C2 campaigns by routing traffic, maintaining tunnels, and managing egress/ingress channels.

This contract provides:
1. **Lifecycle Management**: Explicit states and transitions (`enable`, `disable`, `status`, `health_check`, `configure`).
2. **Unified Configuration Schema**: Reuses `ModuleOption` and `OptionType` from `core.base_module`, enabling the desktop GUI (`ConfigFormGenerator`) to dynamically render configuration forms with zero custom widget code.
3. **Resilience & Isolation**: Failure in an infrastructure service is contained and surfaced cleanly without crashing the registry or the parent application.

---

## File layout

Every infrastructure module plugin must reside in its own subdirectory under `modules/infra/`:

```text
modules/infra/
└── <module_name>/
    ├── infra_module.py       # Required: Python implementation subclassing IInfrastructureModule
    └── infra_module.toml     # Optional: Declarative metadata manifest for registry scanning
```

### Naming Conventions
- Directory name: lowercase snake_case (e.g., `https_proxy`, `dns_tunnel`, `cdn_fronter`).
- Module ID: dot-slug prefixed with `infra.` (e.g., `infra.https_proxy`, `infra.dns_tunnel`).
- Implementation file: MUST be named `infra_module.py`.

---

## Interface contract (IInfrastructureModule)

Located in `core/infra_module_base.py`. Pure Python standard library with zero third-party GUI or framework dependencies.

### Class Definition

```python
class IInfrastructureModule(abc.ABC):
    meta: InfraModuleMeta  # Class-level declaration (required)
```

### Method Signatures and Behavioral Guarantees

#### 1. `enable(self) -> bool` [Abstract]
- **Purpose**: Activates the infrastructure service (binds sockets, launches worker threads, establishes upstream connections).
- **Return Type**: `bool` (`True` on successful startup, `False` on failure).
- **Behavior Guarantee**: **Idempotent**. If the module is already in `InfraModuleStatus.ENABLED`, calling `enable()` is a no-op and must return `True`.
- **Failure Behavior**: If an error occurs during startup, the module must transition its status to `InfraModuleStatus.ERROR`, log the error, release any partially bound resources, and return `False`.

#### 2. `disable(self) -> None` [Abstract]
- **Purpose**: Deactivates the infrastructure service cleanly.
- **Return Type**: `None`.
- **Behavior Guarantee**: **Must never raise**. Closes network sockets, terminates threads/subprocesses, and transitions status to `InfraModuleStatus.DISABLED`.
- **Failure Behavior**: All exceptions encountered during teardown must be caught, logged, and swallowed.

#### 3. `status(self) -> InfraModuleStatus` [Abstract]
- **Purpose**: Queries the current lifecycle state of the module.
- **Return Type**: `InfraModuleStatus` enum (`ENABLED`, `DISABLED`, `ERROR`, `STARTING`, `STOPPING`).
- **Behavior Guarantee**: Fast, non-blocking state inspection.

#### 4. `configure(self, config: Dict[str, Any]) -> bool` [Abstract]
- **Purpose**: Ingests, validates, and stores runtime configuration parameters.
- **Return Type**: `bool` (`True` if valid and applied, `False` if validation fails).
- **Behavior Guarantee**: Must be callable **before** `enable()` to pre-load settings, as well as while running if the module supports dynamic reconfiguration.
- **Failure Behavior**: If required keys are missing or invalid, configuration is rejected and returns `False` without corrupting existing configuration.

#### 5. `health_check(self) -> bool` [Default Provided]
- **Purpose**: Liveness and readiness probe executed periodically by the module manager.
- **Return Type**: `bool` (`True` if responsive and healthy, `False` if degraded).
- **Behavior Guarantee**: Safe to call at any time in any lifecycle state. Default returns `True`.

#### 6. `get_schema(self) -> List[ModuleOption]` [Default Provided]
- **Purpose**: Exposes the configurable option schema to the GUI and API.
- **Return Type**: `List[ModuleOption]`.
- **Behavior Guarantee**: Returns `self.meta.options` in declaration order.

#### 7. `describe(self) -> Dict[str, Any]` [Default Provided]
- **Purpose**: Returns complete serializable metadata dictionary merged with the active lifecycle status.
- **Return Type**: `Dict[str, Any]`.
- **Behavior Guarantee**: JSON-serializable dictionary containing all metadata, serialized option definitions, and `"status"`.

---

## Configuration schema (InfraModuleMeta.options)

`InfraModuleMeta.options` accepts a list of `ModuleOption` instances (imported directly from `core.base_module`). This design maintains a single configuration contract across the entire SentryPack ecosystem.

```python
from core.base_module import ModuleOption, OptionType
```

### OptionType to PyQt6 Widget Mapping

When rendering an infrastructure configuration panel, `gui.widgets.config_form_generator.ConfigFormGenerator` maps each `OptionType` directly to PyQt6 widgets:

| `OptionType` | PyQt6 Widget | Behavior / Constraints |
| :--- | :--- | :--- |
| `OptionType.STRING` | `QLineEdit` | Text entry with default text pre-filled. Tooltip displays `description`. |
| `OptionType.FILE_PATH` | `QLineEdit` | Path string entry for certificates, keys, or log destinations. |
| `OptionType.INTEGER` | `QSpinBox` | Numeric spinbox bounded between `0` and `65535` (ideal for ports). |
| `OptionType.BOOLEAN` | `QCheckBox` | Binary toggle checked/unchecked based on `default`. |
| `OptionType.ENUM` | `QComboBox` | Dropdown populated with choices from `option.choices`. |

---

## Lifecycle state machine

Infrastructure modules progress through deterministic lifecycle states managed by `IInfrastructureModule` and orchestrated by `InfrastructureModuleRegistry`:

```text
+-------------------------------------------------------------------------+
|                    INFRASTRUCTURE MODULE STATE MACHINE                  |
+-------------------------------------------------------------------------+

                           +-----------------------+
                           |                       |
                           |       DISABLED        |<---------------------+
                           |                       |                      |
                           +-----------+-----------+                      |
                                       |                                  |
                              enable() |                                  |
                                       v                                  |
                           +-----------------------+                      |
                           |       STARTING        |                      |
                           |     (transient)       |                      |
                           +-----------+-----------+                      |
                                       |                                  |
                           +-----------+-----------+                      |
                           |                       |                      |
                           v                       v                      |
                   +---------------+       +---------------+              |
                   |    ENABLED    |       |     ERROR     |              |
                   |  (operational)|       |  (failure)    |              |
                   +-------+-------+       +-------+-------+              |
                           |                       |                      |
                           | health_check fails    | disable()            |
                           | or runtime exception  |                      |
                           |       +---------------+                      |
                           |       |                                      |
                           v       v                                      |
                   +---------------+                                      |
                   |    STOPPING   |                                      |
                   |  (transient)  |--------------------------------------+
                   +---------------+               disable()
```

### State Transitions:
1. **Normal Startup**: `DISABLED` → `(enable())` → `STARTING` → `ENABLED`
2. **Clean Shutdown**: `ENABLED` → `(disable())` → `STOPPING` → `DISABLED`
3. **Runtime Fault**: `ENABLED` → `(exception / health_check failure)` → `ERROR`
4. **Recovery Path**: `ERROR` → `(disable() + enable())` → `ENABLED`

---

## Minimal implementation skeleton

Below is the reference stub implementation from `modules/infra/_stub/infra_module.py`:

```python
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from core.base_module import ModuleOption, OptionType
from core.infra_module_base import (
    IInfrastructureModule,
    InfraModuleMeta,
    InfraModuleStatus,
)

logger = logging.getLogger("sentrypack.infra.stub")


class StubInfraModule(IInfrastructureModule):
    """
    Minimal reference stub infrastructure module.

    Demonstrates option schema declaration, configuration handling,
    and lifecycle management according to the IInfrastructureModule contract.
    """

    # 1. Class-level metadata declaration
    meta = InfraModuleMeta(
        id="infra.stub",
        name="Stub Infrastructure Module",
        version="0.1.0",
        description="Minimal reference stub — validates the IInfrastructureModule interface.",
        author="Burka Zelalem",
        category="proxy",
        capabilities=["stub"],
        options=[
            ModuleOption(
                name="HOST",
                description="Target hostname or IP",
                option_type=OptionType.STRING,
                required=True,
                default="127.0.0.1",
            ),
            ModuleOption(
                name="PORT",
                description="Target port",
                option_type=OptionType.INTEGER,
                required=True,
                default=8080,
            ),
            ModuleOption(
                name="USE_TLS",
                description="Wrap connection in TLS",
                option_type=OptionType.BOOLEAN,
                required=False,
                default=False,
            ),
            ModuleOption(
                name="MODE",
                description="Proxy operation mode",
                option_type=OptionType.ENUM,
                required=False,
                default="forward",
                choices=["forward", "reverse", "transparent"],
            ),
        ],
    )

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialize internal state and call parent constructor."""
        super().__init__(config)
        self._status: InfraModuleStatus = InfraModuleStatus.DISABLED

    def enable(self) -> bool:
        """Activate the infrastructure service (idempotent)."""
        if self._status == InfraModuleStatus.ENABLED:
            return True  # Idempotency guarantee
        
        # [Startup logic: bind sockets, spawn threads, etc.]
        self._status = InfraModuleStatus.ENABLED
        return True

    def disable(self) -> None:
        """Deactivate service cleanly. Must never raise."""
        # [Teardown logic: close sockets, stop threads, etc.]
        self._status = InfraModuleStatus.DISABLED

    def status(self) -> InfraModuleStatus:
        """Return current lifecycle status."""
        return self._status

    def configure(self, config: Dict[str, Any]) -> bool:
        """Validate and apply runtime configuration."""
        required = {"HOST", "PORT"}
        if not required.issubset(config.keys()):
            return False
        self.config.update(config)
        return True
```

---

## Rules every implementer must follow (numbered list)

1. **Class-Level Metadata**: Every subclass **MUST** declare `meta` at the class level as an instance of `InfraModuleMeta`. The registry introspects `cls.meta` without instantiating the class.
2. **Idempotent `enable()`**: Calling `enable()` on a module that is already `ENABLED` must be a no-op and return `True`. Do not create duplicate sockets or threads.
3. **Exception-Safe `disable()`**: `disable()` must never raise exceptions under any circumstances. All socket teardown errors or thread timeouts must be caught and logged internally.
4. **Pre-Execution `configure()`**: `configure()` must be callable before `enable()` to pre-load settings into `self.config` before the service activates.
5. **Safe `health_check()`**: `health_check()` must be safe to call at any time, at high frequency, and regardless of whether the module is `ENABLED`, `DISABLED`, or in `ERROR`.
6. **Explicit Error Transition**: A module that crashes during `enable()` or while running in the background must set its own status to `InfraModuleStatus.ERROR` before returning `False` or logging.
7. **Declaration-Order Schemas**: `get_schema()` returns options in the exact order declared in `meta.options`. The GUI renders form fields sequentially based on this declaration order.

---

## How the GUI uses your schema

The desktop application uses the existing `ConfigFormGenerator` to dynamically construct configuration panels without requiring custom Qt UI code for individual modules:

```python
from PyQt6.QtWidgets import QWidget, QVBoxLayout
from gui.widgets.config_form_generator import ConfigFormGenerator
from modules.infra._stub.infra_module import StubInfraModule

# 1. Instantiate the module
module = StubInfraModule()

# 2. Pass schema options directly to the generator
form = ConfigFormGenerator(module.meta.options)

# 3. Read form values keyed by option name
values = form.get_values()
# Output: {'HOST': '127.0.0.1', 'PORT': 8080, 'USE_TLS': False, 'MODE': 'forward'}

# 4. Apply directly to module
module.configure(values)
```

---

## Validation

Verify that your infrastructure module compiles, satisfies all abstract methods, and exposes a valid schema using this validation command:

```bash
python -c "
import importlib.util, sys
spec = importlib.util.spec_from_file_location('infra_module', 'modules/infra/<your_module>/infra_module.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print('OK — module loaded')
"
```

To validate the reference stub:

```bash
python modules/infra/_stub/infra_module.py
```
Expected output:
```text
{'id': 'infra.stub', 'name': 'Stub Infrastructure Module', ... 'status': 'enabled'}
Schema OK — ConfigFormGenerator can render 4 fields
```
