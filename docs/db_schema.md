# Database Schema Documentation

## Entities

### `projects`
- `id` (INTEGER, PK)
- `name` (VARCHAR)
- `description` (TEXT)
- `created_at` (DATETIME)

### `targets`
- `id` (INTEGER, PK)
- `project_id` (INTEGER, FK -> projects.id)
- `name` (VARCHAR)
- `ip_address` (VARCHAR)
- `status` (VARCHAR)
- `created_at` (DATETIME)

### `module_runs`
- `id` (INTEGER, PK)
- `target_id` (INTEGER, FK -> targets.id)
- `module_id` (VARCHAR)
- `status` (VARCHAR)
- `started_at` (DATETIME)
- `completed_at` (DATETIME)
- `logs` (TEXT)

### `findings`
- `id` (INTEGER, PK)
- `target_id` (INTEGER, FK -> targets.id)
- `title` (VARCHAR)
- `severity` (VARCHAR)
- `description` (TEXT)
- `cve` (VARCHAR)
- `cpe` (VARCHAR)
- `remediation` (TEXT)
- `evidence` (JSON)
- `created_at` (DATETIME)
