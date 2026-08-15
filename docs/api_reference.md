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

### Exploit DB
- `GET /api/exploits/search` — Full-text and filtered search over the Exploit DB.
  FTS5-ranked when a query string (`q`) is provided; falls back to CVSS/date ordering
  for filter-only browsing. Supports combining free-text with structured filters.

  **Query parameters** (all optional):
  | Param | Type | Description |
  |---|---|---|
  | `q` | string | Free-text FTS5 query; tokens prefix-matched, AND-ed |
  | `service_name` | string | Partial, case-insensitive match on service name |
  | `cve_id` | string | Partial, case-insensitive match on CVE ID |
  | `severity` | string | Exact, case-insensitive match (e.g. `Critical`) |
  | `min_cvss` | float 0–10 | Lower bound on CVSS score |
  | `has_public_exploit` | bool | Filter by public exploit availability |
  | `platform` | string | Partial match on platform |
  | `exploit_type` | string | Partial match on exploit type |
  | `limit` | int 1–100 | Results per page (default 25) |
  | `offset` | int ≥0 | Pagination offset (default 0) |
