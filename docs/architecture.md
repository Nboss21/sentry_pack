# Architecture Specification

## Overview

SentryPack is structured into three primary architectural layers:
1. **Core Engine (`core/`)**: Module runtime execution engine, sandboxed subprocess runner, recommendation engines.
2. **Backend API (`api/`)**: FastAPI REST service binding loopback (`127.0.0.1`), WebSocket stream handlers, database models, C2 session queue, report generation.
3. **Desktop GUI (`gui/`)**: PyQt application shell, project workspaces, visual host topology graph, module browser, live console streaming view.

## System Boundaries & Layer Isolation

- `gui/` interacts exclusively with `api/` via HTTP REST and WebSocket connections.
- `api/` interacts with `core/` to register and invoke modules.
- `modules/` are isolated plugins extending capability without touching core application logic.
