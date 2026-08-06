# Contributing to SentryPack

Thank you for your interest in contributing to SentryPack!

## Directory & Component Ownership

- `core/`: Person A — Plugin engine & runner.
- `api/`: Person B — FastAPI REST & WebSockets, DB schemas.
- `gui/`: Person C — PyQt GUI Desktop Shell.
- `modules/`: Community and open-source capability modules.

## Pull Request Checklist

1. Run `python scripts/validate_module.py <path>` for any added module.
2. Run unit tests (`pytest`).
3. Follow PEP 8 style standards (`ruff check .`).
