-- ============================================================================
-- One-time performance indexes for the Keep "alerts" feature on PostgreSQL.
--
-- Targets: keep/api/core/alerts.py feed query path and facets.
--
-- Background:
--   The alerts feed always scans `lastalert` by (tenant_id, timestamp) and
--   joins `alert` (PK) + `alertenrichment` (UNIQUE on alert_fingerprint).
--   CEL filters are compiled by keep/api/core/cel_to_sql/sql_providers/postgresql.py
--   into expressions of the form:
--       COALESCE(alertenrichment.enrichments ->> '<field>', alert.event ->> '<field>')
--   Most-used fields: severity, status, lastReceived, firingCounter,
--   unresolvedCounter (and arbitrary `*` wildcards). Source/providerType maps
--   to alert.provider_type. Array fields use `event::jsonb @> '[...]'`.
--
--   B-tree indexes on the JSON column itself do nothing — the planner can only
--   use them if the expression in the WHERE clause matches the indexed
--   expression exactly. Hence the functional indexes below.
--
-- IMPORTANT:
--   * Run outside Alembic; do not commit / check in results.
--   * Run with psql -f (which is non-transactional by default). DO NOT wrap
--     the body in BEGIN/COMMIT; CREATE INDEX CONCURRENTLY requires no txn.
--   * PG 14+ does NOT support CREATE INDEX CONCURRENTLY on a partitioned
--     parent for ANY index type. For a partitioned `alert` we:
--       1) create the parent index WITHOUT CONCURRENTLY (metadata-only;
--          the work is in the children)
--       2) build the child index CONCURRENTLY at the top level
--       3) ALTER INDEX parent_idx ATTACH PARTITION child_idx
--   * CREATE INDEX CONCURRENTLY is rejected inside a function/DO block
--     (transactional context). The per-partition statements here are
--     generated via \gexec from a temp table so they execute at top level.
--   * Tested on PG >= 12.
-- ============================================================================

\set ON_ERROR_STOP on

-- Set the default schema for unqualified table names in this script.
-- Override by setting the PGSEARCHPATH env var or editing this line.
\set pgsearchpath `echo "${PGSEARCHPATH:-keep,public}"`
SET search_path TO :pgsearchpath;

-- Bound how long the parent-index CREATE INDEX may block on locks. The
-- parent index is metadata-only (no data scanned), so the actual lock
-- hold time is microseconds — but if some other session is holding a
-- conflicting lock, we want to fail fast rather than stall the script.
-- Override with PG_LOCK_TIMEOUT_MS env var (integer milliseconds).
\set lock_timeout_ms `echo "${PG_LOCK_TIMEOUT_MS:-5000}"`
SET lock_timeout = :'lock_timeout_ms';

\echo
\echo '=== Phase 1: extension (idempotent) ==='
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ---------------------------------------------------------------------------
-- Phase 2: detect whether `alert` is partitioned in this database.
-- Use \gset so the value is available as a psql variable.
-- ---------------------------------------------------------------------------
\echo
\echo '=== Phase 2: detect alert partitioning ==='
SELECT
    (c.relkind = 'p') AS is_partitioned,
    n.nspname          AS alert_schema
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relname = 'alert'
   AND n.nspname = current_schema()
\gset alert_

\echo alert partition info: is_partitioned=:alert_is_partitioned, schema=:alert_schema

-- Defensive: if the table wasn't found, the psql vars are empty; default them
-- so the rest of the script degrades to "non-partitioned" path. (A missing
-- `alert` table is the only way the vars would be empty.)
SELECT COALESCE(NULLIF(:'alert_is_partitioned', ''), 'f') AS alert_is_partitioned
\gset alert_
SELECT COALESCE(NULLIF(:'alert_schema', ''), current_schema()) AS alert_schema
\gset alert_

\echo final: alert_is_partitioned=:alert_is_partitioned, alert_schema=:alert_schema

-- ---------------------------------------------------------------------------
-- Phase 3a (PARTITIONED path): for each B-tree expression index
--   1) create the parent index (no CONCURRENTLY — metadata only)
--   2) for every partition, create the child index CONCURRENTLY at top level
--      (driven via \gexec on a temp table) and ATTACH it to the parent.
-- The temp table stores (schemaname, partitionname) and is passed to format()
-- as two %I args, so the script works regardless of the actual schema.
--
-- Idempotency: re-runs must succeed. If a previous run created a child
-- index but failed to attach it (or attached a different parent), the
-- child index is left behind and CREATE INDEX would error. We therefore:
--   * DROP INDEX IF EXISTS before each per-partition CREATE INDEX
--   * only ATTACH if not already attached (driven by a separate
--     SELECT against pg_inherits + pg_index).
-- ---------------------------------------------------------------------------
\echo
\echo '=== Phase 3a: B-tree expression indexes (partitioned) ==='
\if :alert_is_partitioned
    CREATE TEMP TABLE _alert_partitions (schemaname text, partitionname text);
    INSERT INTO _alert_partitions (schemaname, partitionname)
    SELECT n.nspname, c.relname
      FROM pg_inherits i
      JOIN pg_class c     ON c.oid = i.inhrelid
      JOIN pg_class p     ON p.oid = i.inhparent
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE p.relname = 'alert'
       AND n.nspname = current_schema();

    -- (tenant_id, ((event ->> 'status')))
    CREATE INDEX IF NOT EXISTS ix_alert_event_status
        ON :"alert_schema".alert (tenant_id, ((event ->> 'status')));
    -- Drop a stale (unattached or attached-to-wrong-parent) child index from
    -- a prior failed run. Skip drops for indexes that are already attached
    -- to the correct parent, so re-runs are cheap.
    SELECT format(
        'DROP INDEX IF EXISTS %I.%I',
        p.schemaname, 'ix_alert_' || p.partitionname || '_event_status') AS sql_stmt
      FROM _alert_partitions p
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE c.relname = 'ix_alert_' || p.partitionname || '_event_status'
           AND p.relname = 'ix_alert_event_status'
     )
    \gexec
    -- Create the child index CONCURRENTLY.
    SELECT format(
        'CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_alert_%s_event_status '
        'ON %I.%I (tenant_id, ((event ->> %L)))',
        p.partitionname, p.schemaname, p.partitionname, 'status') AS sql_stmt
      FROM _alert_partitions p
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE c.relname = 'ix_alert_' || p.partitionname || '_event_status'
           AND p.relname = 'ix_alert_event_status'
     )
    \gexec
    -- Attach only if not already attached.
    SELECT format(
        'ALTER INDEX %I.%I ATTACH PARTITION %I.%I',
        p.schemaname, 'ix_alert_event_status',
        p.schemaname, 'ix_alert_' || p.partitionname || '_event_status') AS sql_stmt
      FROM _alert_partitions p
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE c.relname = 'ix_alert_' || p.partitionname || '_event_status'
           AND p.relname = 'ix_alert_event_status'
     )
    \gexec

    -- (tenant_id, ((event ->> 'severity')))
    CREATE INDEX IF NOT EXISTS ix_alert_event_severity
        ON :"alert_schema".alert (tenant_id, ((event ->> 'severity')));
    SELECT format(
        'DROP INDEX IF EXISTS %I.%I',
        p.schemaname, 'ix_alert_' || p.partitionname || '_event_severity') AS sql_stmt
      FROM _alert_partitions p
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE c.relname = 'ix_alert_' || p.partitionname || '_event_severity'
           AND p.relname = 'ix_alert_event_severity'
     )
    \gexec
    SELECT format(
        'CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_alert_%s_event_severity '
        'ON %I.%I (tenant_id, ((event ->> %L)))',
        p.partitionname, p.schemaname, p.partitionname, 'severity') AS sql_stmt
      FROM _alert_partitions p
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE c.relname = 'ix_alert_' || p.partitionname || '_event_severity'
           AND p.relname = 'ix_alert_event_severity'
     )
    \gexec
    SELECT format(
        'ALTER INDEX %I.%I ATTACH PARTITION %I.%I',
        p.schemaname, 'ix_alert_event_severity',
        p.schemaname, 'ix_alert_' || p.partitionname || '_event_severity') AS sql_stmt
      FROM _alert_partitions p
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE c.relname = 'ix_alert_' || p.partitionname || '_event_severity'
           AND p.relname = 'ix_alert_event_severity'
     )
    \gexec

    -- (tenant_id, ((event ->> 'lastReceived')))
    CREATE INDEX IF NOT EXISTS ix_alert_event_lastrecv
        ON :"alert_schema".alert (tenant_id, ((event ->> 'lastReceived')));
    SELECT format(
        'DROP INDEX IF EXISTS %I.%I',
        p.schemaname, 'ix_alert_' || p.partitionname || '_event_lastrecv') AS sql_stmt
      FROM _alert_partitions p
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE c.relname = 'ix_alert_' || p.partitionname || '_event_lastrecv'
           AND p.relname = 'ix_alert_event_lastrecv'
     )
    \gexec
    SELECT format(
        'CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_alert_%s_event_lastrecv '
        'ON %I.%I (tenant_id, ((event ->> %L)))',
        p.partitionname, p.schemaname, p.partitionname, 'lastReceived') AS sql_stmt
      FROM _alert_partitions p
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE c.relname = 'ix_alert_' || p.partitionname || '_event_lastrecv'
           AND p.relname = 'ix_alert_event_lastrecv'
     )
    \gexec
    SELECT format(
        'ALTER INDEX %I.%I ATTACH PARTITION %I.%I',
        p.schemaname, 'ix_alert_event_lastrecv',
        p.schemaname, 'ix_alert_' || p.partitionname || '_event_lastrecv') AS sql_stmt
      FROM _alert_partitions p
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE c.relname = 'ix_alert_' || p.partitionname || '_event_lastrecv'
           AND p.relname = 'ix_alert_event_lastrecv'
     )
    \gexec

    -- (tenant_id, provider_type)
    CREATE INDEX IF NOT EXISTS ix_alert_tenant_provider_type
        ON :"alert_schema".alert (tenant_id, provider_type);
    SELECT format(
        'DROP INDEX IF EXISTS %I.%I',
        p.schemaname, 'ix_alert_' || p.partitionname || '_provider_type') AS sql_stmt
      FROM _alert_partitions p
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE c.relname = 'ix_alert_' || p.partitionname || '_provider_type'
           AND p.relname = 'ix_alert_tenant_provider_type'
     )
    \gexec
    SELECT format(
        'CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_alert_%s_provider_type '
        'ON %I.%I (tenant_id, provider_type)',
        p.partitionname, p.schemaname, p.partitionname) AS sql_stmt
      FROM _alert_partitions p
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE c.relname = 'ix_alert_' || p.partitionname || '_provider_type'
           AND p.relname = 'ix_alert_tenant_provider_type'
     )
    \gexec
    SELECT format(
        'ALTER INDEX %I.%I ATTACH PARTITION %I.%I',
        p.schemaname, 'ix_alert_tenant_provider_type',
        p.schemaname, 'ix_alert_' || p.partitionname || '_provider_type') AS sql_stmt
      FROM _alert_partitions p
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE c.relname = 'ix_alert_' || p.partitionname || '_provider_type'
           AND p.relname = 'ix_alert_tenant_provider_type'
     )
    \gexec

    DROP TABLE _alert_partitions;
\else
    \echo '   alert is NOT partitioned — skipped (handled in Phase 3b)'
\endif

-- ---------------------------------------------------------------------------
-- Phase 3b (NON-PARTITIONED path): plain CONCURRENTLY on the table itself.
-- ---------------------------------------------------------------------------
\echo
\echo '=== Phase 3b: B-tree expression indexes (non-partitioned) ==='
\if :alert_is_partitioned
    \echo '   skipped — alert is partitioned'
\else
    CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_alert_event_status
        ON alert (tenant_id, ((event ->> 'status')));
    CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_alert_event_severity
        ON alert (tenant_id, ((event ->> 'severity')));
    CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_alert_event_lastrecv
        ON alert (tenant_id, ((event ->> 'lastReceived')));
    CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_alert_tenant_provider_type
        ON alert (tenant_id, provider_type);
\endif

-- ---------------------------------------------------------------------------
-- Phase 4: expression indexes on alertenrichment.enrichments
-- (Filters are COALESCE(enrichments, event) — both sides must be indexable
--  for a BitmapOr plan to be chosen. alertenrichment is not partitioned.)
-- ---------------------------------------------------------------------------
\echo
\echo '=== Phase 4: expression indexes on alertenrichment.enrichments ==='
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_alert_enr_status
    ON alertenrichment (tenant_id, ((enrichments ->> 'status')));

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_alert_enr_severity
    ON alertenrichment (tenant_id, ((enrichments ->> 'severity')));

-- ---------------------------------------------------------------------------
-- Phase 5: GIN indexes for containment / array / path checks.
-- Same CONCURRENTLY limitation on a partitioned parent — per-partition
-- build + ATTACH. alertenrichment is not partitioned, so plain CONCURRENTLY.
-- ---------------------------------------------------------------------------
\echo
\echo '=== Phase 5: GIN indexes (containment/array/path) ==='
\if :alert_is_partitioned
    CREATE TEMP TABLE _alert_partitions (schemaname text, partitionname text);
    INSERT INTO _alert_partitions (schemaname, partitionname)
    SELECT n.nspname, c.relname
      FROM pg_inherits i
      JOIN pg_class c     ON c.oid = i.inhrelid
      JOIN pg_class p     ON p.oid = i.inhparent
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE p.relname = 'alert'
       AND n.nspname = current_schema();

    -- parent GIN (metadata only)
    CREATE INDEX IF NOT EXISTS ix_alert_event_gin
        ON :"alert_schema".alert USING gin (event jsonb_path_ops);

    -- per-partition CONCURRENTLY GIN + ATTACH (idempotent: drop stale, skip-if-attached)
    SELECT format(
        'DROP INDEX IF EXISTS %I.%I',
        p.schemaname, 'ix_alert_' || p.partitionname || '_event_gin') AS sql_stmt
      FROM _alert_partitions p
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE c.relname = 'ix_alert_' || p.partitionname || '_event_gin'
           AND p.relname = 'ix_alert_event_gin'
     )
    \gexec
    SELECT format(
        'CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_alert_%s_event_gin '
        'ON %I.%I USING gin (event jsonb_path_ops)',
        p.partitionname, p.schemaname, p.partitionname) AS sql_stmt
      FROM _alert_partitions p
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE c.relname = 'ix_alert_' || p.partitionname || '_event_gin'
           AND p.relname = 'ix_alert_event_gin'
     )
    \gexec
    SELECT format(
        'ALTER INDEX %I.%I ATTACH PARTITION %I.%I',
        p.schemaname, 'ix_alert_event_gin',
        p.schemaname, 'ix_alert_' || p.partitionname || '_event_gin') AS sql_stmt
      FROM _alert_partitions p
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE c.relname = 'ix_alert_' || p.partitionname || '_event_gin'
           AND p.relname = 'ix_alert_event_gin'
     )
    \gexec

    DROP TABLE _alert_partitions;
\else
    CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_alert_event_gin
        ON alert USING gin (event jsonb_path_ops);
\endif

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_alert_enr_gin
    ON alertenrichment USING gin (enrichments jsonb_path_ops);

-- ---------------------------------------------------------------------------
-- Phase 6: trigram index for ILIKE / .contains()  (optional, commented)
-- ---------------------------------------------------------------------------
\echo
\echo '=== Phase 6: trigram index (commented out — uncomment if needed) ==='
-- CEL .contains() compiles to `ILIKE '%...%'`, which B-tree / path_ops GIN
-- cannot serve. trigram ops do. For a partitioned parent, build per-partition
-- and ATTACH as in Phase 3a / 5. Example:
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_alert_event_trgm
--     ON alert USING gin (((event)::text) gin_trgm_ops);

-- ---------------------------------------------------------------------------
-- Phase 7: incident index for the FIRING subquery in __build_query_for_filtering
-- ---------------------------------------------------------------------------
\echo
\echo '=== Phase 7: incident (tenant_id, status) ==='
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_incident_tenant_status
    ON incident (tenant_id, status);

-- ---------------------------------------------------------------------------
-- Phase 8: ANALYZE
-- ---------------------------------------------------------------------------
\echo
\echo '=== Phase 8: ANALYZE ==='
ANALYZE alert;
ANALYZE alertenrichment;
ANALYZE incident;

\echo
\echo '=== Done. Verify with: ==='
\echo "  SELECT schemaname, tablename, indexname, indexdef"
\echo "    FROM pg_indexes"
\echo "   WHERE schemaname = current_schema()"
\echo "     AND tablename IN ('alert', 'alertenrichment', 'incident')"
\echo '   ORDER BY tablename, indexname;'
\echo
\echo '=== Confirm planner uses them: ==='
\echo "  EXPLAIN (ANALYZE, BUFFERS)"
\echo "  SELECT * FROM alert"
\echo "   WHERE tenant_id = '<your-tenant>'"
\echo "     AND (event ->> 'status') = 'firing';"



