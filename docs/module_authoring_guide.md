# Module Authoring Guide (Extension SDK Walkthrough)

Every module in SentryPack lives in its own subfolder inside `modules/<category>/<module_name>/`.

## Required Files

1. `module.toml`: Declarative manifest file defining module metadata and user options.
2. `module.py`: Python code defining the module execution logic inheriting from `BaseModule`.

## Example `module.toml`

```toml
[module]
id = "recon.custom_scanner"
name = "Custom Scanner"
description = "Scans host for custom service ports."
author = "Your Name"
version = "1.0.0"
category = "recon"

[[options]]
name = "TARGET"
description = "Target host"
type = "string"
required = true
```

## Example `module.py`

```python
from core.base_module import BaseModule, Finding

class Module(BaseModule):
    def run(self, ctx):
        ctx.emit("info", {"message": "Scanning host..."})
        return [
            Finding(title="Service Found", severity="Low", description="Custom service running.")
        ]
```

## Validating Your Module

Run the SentryPack validation CLI before submitting:

```bash
python scripts/validate_module.py modules/recon/custom_scanner
```
