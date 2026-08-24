# ClickHouse Archive Provider

Copies Keep alerts (raw event log), incidents, and alert↔incident links to an
external ClickHouse warehouse for long-term storage. Intended to be used as a
single **action** in a scheduled (interval) workflow.

## Summary

The provider is **self-contained**: a single workflow action fetches the data
from Keep's own database and pushes it to ClickHouse, creating the destination
tables if they don't exist. Sync is **incremental** — each run queries
ClickHouse for the `MAX` watermark already stored per tenant and copies only
newer records, making the operation idempotent and restart-safe.

This mirrors the existing `ElasticClient` export pattern and reuses the
connection/protocol logic shape from the query-only `clickhouse_provider`.
HA/dedup of the schedule itself is already handled by the workflow scheduler
(Redis lock + Postgres advisory lock + unique constraint), so this provider
adds **no** locking of its own.

## Key design points

- **Self-contained fetch model** — the provider itself queries Keep's DB
  (`query_alerts`, `get_last_incidents`, and an inline `LastAlertToIncident`
  query via `Session(engine)`) and pushes to ClickHouse. No existing code is
  modified; all logic lives in this provider module.
- **Incremental & idempotent** — per-tenant watermarks
  (`MAX(timestamp)` for alerts/links, `MAX(last_seen_time)` for incidents)
  are read from ClickHouse at the start of each run. Only newer rows are
  copied. Re-runs re-insert at most a single boundary row.
- **Auto-creates schema** — `CREATE DATABASE/TABLE IF NOT EXISTS` is run on
  first use (gated by an in-memory `_tables_ensured` flag; `IF NOT EXISTS`
  keeps it safe even if the flag is lost on restart):
  - `keep_alerts` — `MergeTree`, ordered by `(tenant_id, timestamp)`,
    partitioned monthly. Append-only raw event log.
  - `keep_incidents` — `ReplacingMergeTree(version)` ordered by `(tenant_id, id)`,
    partitioned by `toYYYYMM(creation_time)`. `version = last_seen_time`.
  - `keep_alert_incident_links` — `ReplacingMergeTree(version)` ordered by
    `(tenant_id, incident_id, fingerprint)`. `version = timestamp`.
- **Tables archived** — raw alerts + incidents + alert↔incident links.
  `event` and `enrichments` are stored as JSON strings, so alert-schema
  changes are captured without DDL migrations.
- **Connection management** — supports both native (`clickhouse://` /
  `clickhouses://`) and HTTP (`http`/`https`) protocols via `clickhouse_driver`.
  Lazy client creation; closed in `dispose()`.
- **Chunked inserts** — `chunk_size` config (default 1000) controls ClickHouse
  memory usage per `INSERT` batch.
- **Tenant isolation** — only `self.context_manager.tenant_id` is ever copied;
  all ClickHouse watermark queries include `WHERE tenant_id = %(tid)s`.
- **No locking** — the workflow scheduler already deduplicates interval
  executions across HA instances, so the provider does not add its own.

### Configuration

Auth fields (with `config_main_group="authentication"` metadata for the UI):

| Field | Required | Default | Description |
|---|---|---|---|
| `host` | yes | — | ClickHouse hostname |
| `port` | yes | — | ClickHouse port (9000 native, 8123 HTTP) |
| `username` | yes | — | ClickHouse username |
| `password` | yes (sensitive) | — | ClickHouse password |
| `database` | no | `keep_archive` | Target archive database (created if missing) |
| `protocol` | yes | `clickhouse` | `clickhouse` / `clickhouses` (SSL) / `http` / `https` |
| `verify` | no | `true` | Enable SSL verification |
| `chunk_size` | no | `1000` | Rows per INSERT batch |

### Known limitation

The `Incident` model has no `updated_at` column, so the incident watermark is
`last_seen_time`. Status/assignee-only mutations that do not bump
`last_seen_time` may not propagate as the newest `ReplacingMergeTree` row.
Consumers should run `OPTIMIZE TABLE keep_incidents FINAL` periodically; the
proper fix is an upstream `Incident.updated_at` column.

## Example workflow

```yaml
workflow:
  id: archive-to-clickhouse
  name: Archive Keep alerts and incidents to ClickHouse
  triggers:
    - type: manual
    - type: interval
      value: 300   # every 5 minutes
  actions:
    - name: archive-to-clickhouse
      provider:
        type: clickhouse_archive
        config: " {{ providers.clickhouse-warehouse }} "
        with: {}
```

Install the provider in Keep (named `clickhouse-warehouse`) via the UI,
`KEEP_PROVIDERS` env, or `providers.yaml`, then upload the workflow above
(also at `examples/workflows/archive_to_clickhouse.yml`).

The action returns a summary dict:

```json
{
  "tenant_id": "...",
  "alerts_copied": 12,
  "incidents_copied": 3,
  "links_copied": 7,
  "alert_watermark": "2026-07-22T10:00:00.123",
  "incident_watermark": "2026-07-22T09:55:00",
  "link_watermark": "2026-07-22T09:58:00",
  "started_at": "2026-07-22T10:00:01.000"
}
```

## Verification (end-to-end)

1. Start a local ClickHouse:
   ```bash
   docker run -d --name ch -p 9000:9000 -p 8123:8123 clickhouse/clickhouse-server:latest
   ```
2. Install the provider in Keep named `clickhouse-warehouse` with
   `host=localhost`, `port=9000`, `protocol=clickhouse`,
   `database=keep_archive`, `username=default`, `password=""`.
3. Upload `archive_to_clickhouse.yml` and run it via the **manual** trigger.
4. Verify counts in ClickHouse match Keep's DB:
   ```sql
   SELECT count() FROM keep_archive.keep_alerts;
   SELECT count() FROM keep_archive.keep_incidents;
   SELECT count() FROM keep_archive.keep_alert_incident_links;
   ```
5. Run the workflow again → `alerts_copied` ≈ 0 (or 1 boundary row),
   confirming the incremental watermark works.
6. Push a new alert into Keep, run the workflow, confirm the new row appears.
7. Switch to HTTP protocol (`protocol=http`, `port=8123`) and re-run to
   validate the HTTP insert path.
8. Enable the interval trigger and let it run; (optional) start two Keep
   instances and confirm only one insert batch per interval (HA dedup).
9. Misconfigure `host` and run `validate_scopes` (UI) → expect the error
   string returned for the `connect_to_server` scope.