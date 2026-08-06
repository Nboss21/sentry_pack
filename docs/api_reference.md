# API Reference Specification

## Endpoints

### Modules
- `GET /api/modules` — List all registered modules and metadata.

### Projects
- `GET /api/projects` — List project workspaces.
- `POST /api/projects` — Create new project workspace.

### Targets
- `GET /api/targets` — List targets within projects.
- `POST /api/targets` — Register target IP or hostname.

### Module Execution & Runs
- `POST /api/targets/{id}/run` — Launch module execution against target.
- `GET /api/targets/{id}/findings` — Retrieve findings generated for target.

### C2 Sessions & Reporting
- `GET /api/sessions` — List active C2 agent sessions.
- `POST /api/sessions/{session_id}/tasks` — Enqueue command task for session.
- `GET /api/projects/{id}/report` — Export project security findings report.

## WebSockets
- `WS /ws/runs/{run_id}` — Stream live output logs from active module runs.
- `WS /ws/sessions/{session_id}` — Interactive C2 session terminal stream.
