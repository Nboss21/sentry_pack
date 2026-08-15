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

### `exploits`
- `id` (INTEGER, PK)
- `service_name` (VARCHAR, NOT NULL, indexed)
- `cve_id` (VARCHAR, nullable, indexed)
- `title` (VARCHAR, nullable)
- `description` (TEXT, nullable)
- `author` (VARCHAR, nullable)
- `exploit_type` (VARCHAR, nullable)
- `platform` (VARCHAR, nullable)
- `port` (INTEGER, nullable)
- `cpe_prefix` (VARCHAR, nullable, indexed)
- `version_start_including` (VARCHAR, nullable)
- `version_start_excluding` (VARCHAR, nullable)
- `version_end_including` (VARCHAR, nullable)
- `version_end_excluding` (VARCHAR, nullable)
- `has_public_exploit` (BOOLEAN, default=True)
- `module_id` (VARCHAR, nullable)
- `cvss_score` (FLOAT, nullable)
- `severity` (VARCHAR, default='Medium')
- `published_date` (VARCHAR, nullable)
- `references` (JSON, nullable)
- `created_at` (DATETIME)

### `exploits_fts` (FTS5 virtual table)

An [external-content FTS5](https://www.sqlite.org/fts5.html#external_content_tables)
virtual table that mirrors the following columns from `exploits` for full-text search:
`title`, `description`, `service_name`, `cve_id`, `platform`, `author`.

- Created automatically by `ensure_exploits_fts(engine)` in `api/db/session.py`,
  called from `init_db()`.
- Kept in sync with `exploits` by three triggers:
  - `exploits_fts_ai` — AFTER INSERT
  - `exploits_fts_bu` / `exploits_fts_au` — BEFORE/AFTER UPDATE
  - `exploits_fts_bd` — BEFORE DELETE
- On startup, an `INSERT INTO exploits_fts(exploits_fts) VALUES('rebuild')` backfills
  the index from any pre-existing rows (e.g. from `scripts/import_exploitdb.py`).
- Queried via `GET /api/exploits/search?q=...` using `bm25()` ranking.

### `exploitdb_entries`
- `id` (INTEGER, PK, from CSV)
- `file` (VARCHAR)
- `description` (TEXT)
- `date_published` (VARCHAR)
- `author` (VARCHAR)
- `type` (VARCHAR)
- `platform` (VARCHAR)
- `port` (INTEGER)
- `imported_at` (DATETIME)

