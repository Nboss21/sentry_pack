# SentryPack

SentryPack is a modular penetration testing and vulnerability assessment platform built with a 3-layer architecture (Core Engine, FastAPI Backend, PyQt Desktop GUI) and an extensible module plugin system.

## Project Architecture

- **`core/`**: Plugin engine, module runner, subprocess execution context, and recommendation system (Person A).
- **`api/`**: FastAPI REST API and WebSocket server, database models, connectors (Metasploit RPC, NVD sync), report generator (Person B).
- **`gui/`**: PyQt frontend application shell, visual target graph, console stream, module runner forms (Person C).
- **`modules/`**: Open-source pluggable capability modules (`recon`, `exploit_db`, `c2`, `analysis`, `community`).
- **`data/`**: Seed data fixtures and local SQLite database storage.
- **`docs/`**: Technical documentation, API specs, schema definitions, and authoring guides.
- **`scripts/`**: CLI validation tools and import scripts.
- **`packaging/`**: PyInstaller spec files for desktop app distribution.

## Getting Started

### Prerequisites

- Python 3.10+
- Virtualenv

### Installation

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .[dev]
```

### Running the API Backend

```bash
uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```

### Running the GUI Frontend

```bash
python -m gui.main_window
```

## Module Validation

Validate any custom module against SentryPack specifications:

```bash
python scripts/validate_module.py modules/_template
```

## License

GNU General Public License v3.0 (GPLv3) - see [LICENSE](LICENSE) for details.
