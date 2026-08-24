"""
ClickHouse Archive provider.

Copies Keep alerts (raw event log), incidents, and alert↔incident links to an
external ClickHouse warehouse for long-term storage. Intended to be used as a
single **action** in a scheduled (interval) workflow — the provider is
self-contained: it fetches the data from Keep's own DB and pushes it to
ClickHouse, creating the destination tables if they don't exist.

Sync is **incremental**: each run queries ClickHouse for the MAX watermark
already stored per tenant and copies only newer records. This makes the
operation idempotent and restart-safe. HA/dedup of the schedule itself is
already handled by the workflow scheduler (Redis lock + PG advisory lock +
unique constraint), so this provider does not add any locking of its own.

Known limitation: the ``Incident`` model has no ``updated_at`` column, so the
incident watermark is ``last_seen_time`` — status/assignee-only mutations that
do not bump ``last_seen_time`` may not propagate as the newest row. Consumers
should run ``OPTIMIZE TABLE keep_incidents FINAL`` periodically; the proper
fix is an upstream ``Incident.updated_at`` column.
"""

import dataclasses
import datetime
import json
import typing

import pydantic
import requests
from clickhouse_driver import connect
from dateutil.parser import parse as parse_dt

from keep.api.core.db import engine, get_last_incidents, query_alerts
from keep.api.models.db.alert import Alert, LastAlertToIncident
from keep.api.models.db.helpers import NULL_FOR_DELETED_AT
from keep.api.models.db.incident import Incident
from keep.api.models.incident import IncidentSorting
from keep.contextmanager.contextmanager import ContextManager
from keep.exceptions.provider_exception import ProviderException
from keep.providers.base.base_provider import BaseProvider, ProviderHealthMixin
from keep.providers.models.provider_config import ProviderConfig, ProviderScope
from keep.providers.models.provider_method import ProviderMethod
from keep.validation.fields import NoSchemeUrl, UrlPort

try:
    from sqlmodel import Session
except ImportError:  # pragma: no cover - sqlmodel is a core keep dependency
    from sqlalchemy.orm import Session


DEFAULT_TIMEOUT_SECONDS = 120


@pydantic.dataclasses.dataclass
class ClickhouseArchiveProviderAuthConfig:
    username: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Clickhouse username",
            "config_main_group": "authentication",
        },
    )
    password: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Clickhouse password",
            "sensitive": True,
            "config_main_group": "authentication",
        }
    )
    host: NoSchemeUrl = dataclasses.field(
        metadata={
            "required": True,
            "description": "Clickhouse hostname",
            "validation": "no_scheme_url",
            "config_main_group": "authentication",
        }
    )
    port: UrlPort = dataclasses.field(
        metadata={
            "required": True,
            "description": "Clickhouse port",
            "validation": "port",
            "config_main_group": "authentication",
        }
    )
    database: str | None = dataclasses.field(
        default="keep_archive",
        metadata={
            "required": False,
            "description": "Target ClickHouse database for archive tables (created if missing)",
            "config_main_group": "authentication",
        },
    )
    protocol: typing.Literal["clickhouse", "clickhouses", "http", "https"] = (
        dataclasses.field(
            default="clickhouse",
            metadata={
                "required": True,
                "description": "Protocol ('clickhouses' for SSL, 'clickhouse' for no SSL, 'http' or 'https')",
                "type": "select",
                "options": ["clickhouse", "clickhouses", "http", "https"],
                "config_main_group": "authentication",
            },
        )
    )
    verify: bool = dataclasses.field(
        default=True,
        metadata={
            "description": "Enable SSL verification",
            "hint": "SSL verification is enabled by default",
            "type": "switch",
            "config_main_group": "authentication",
        },
    )
    chunk_size: int = dataclasses.field(
        default=1000,
        metadata={
            "required": False,
            "description": "Number of rows per INSERT batch (controls ClickHouse memory usage)",
            "config_main_group": "authentication",
        },
    )


_ALERT_COLUMNS = [
    "id", "tenant_id", "timestamp", "provider_type", "provider_id",
    "fingerprint", "alert_hash", "event",
]

_INCIDENT_COLUMNS = [
    "id", "tenant_id", "running_number", "user_generated_name", "ai_generated_name",
    "user_summary", "generated_summary", "assignee", "severity", "forced_severity",
    "status", "creation_time", "start_time", "end_time", "last_seen_time",
    "is_predicted", "is_candidate", "is_visible", "alerts_count",
    "affected_services", "sources", "rule_id", "rule_fingerprint", "fingerprint",
    "incident_type", "incident_application", "resolve_on",
    "merged_into_incident_id", "merged_at", "merged_by", "enrichments", "version",
]

_LINK_COLUMNS = [
    "tenant_id", "fingerprint", "incident_id", "timestamp",
    "is_created_by_ai", "deleted_at", "version",
]


class ClickhouseArchiveProvider(BaseProvider, ProviderHealthMixin):
    """Archive Keep alerts, incidents and alert↔incident links to ClickHouse."""

    PROVIDER_DISPLAY_NAME = "ClickHouse Archive"
    PROVIDER_CATEGORY = ["Database"]
    PROVIDER_TAGS = ["data"]

    PROVIDER_SCOPES = [
        ProviderScope(
            name="connect_to_server",
            description="The user can connect to the server",
            mandatory=True,
            alias="Connect to the server",
        )
    ]

    PROVIDER_METHODS = [
        ProviderMethod(
            name="archive",
            func_name="_notify",
            description="Incrementally archive Keep alerts, incidents, and alert↔incident links to ClickHouse",
            type="action",
        ),
        ProviderMethod(
            name="last_sync_summary",
            func_name="_query",
            description="Return a summary of the last archival run (watermarks, row counts)",
            type="view",
        ),
    ]

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)
        self.client = None
        self._tables_ensured = False
        self._last_sync_summary = None

    # ------------------------------------------------------------------ #
    # Config / scopes
    # ------------------------------------------------------------------ #
    def validate_config(self):
        self.authentication_config = ClickhouseArchiveProviderAuthConfig(
            **self.config.authentication
        )

    def validate_scopes(self):
        try:
            self._ensure_schema()
            scopes = {"connect_to_server": True}
        except Exception as e:
            self.logger.exception("Error validating scopes")
            scopes = {"connect_to_server": str(e)}
        return scopes

    # ------------------------------------------------------------------ #
    # Connection management (mirrors keep/providers/clickhouse_provider)
    # ------------------------------------------------------------------ #
    def _is_http_protocol(self) -> bool:
        return self.authentication_config.protocol in ["http", "https"]

    def _get_native_connection(self):
        ac = self.authentication_config
        dsn = f"{ac.protocol}://{ac.username}:{ac.password}@{ac.host}:{ac.port}"
        if ac.database:
            dsn += f"/{ac.database}"
        if ac.verify is False:
            dsn += "?verify=false"
        return connect(
            dsn,
            connect_timeout=DEFAULT_TIMEOUT_SECONDS,
            send_receive_timeout=DEFAULT_TIMEOUT_SECONDS,
            sync_request_timeout=DEFAULT_TIMEOUT_SECONDS,
            verify=ac.verify,
        )

    def _ensure_client(self):
        if self._is_http_protocol():
            return None
        if self.client is None:
            self.client = self._get_native_connection()
        return self.client

    def dispose(self):
        if not self._is_http_protocol() and self.client is not None:
            try:
                self.client.close()
            except Exception:
                self.logger.exception("Error closing Clickhouse connection")
            self.client = None

    # ------------------------------------------------------------------ #
    # Low-level query helpers
    # ------------------------------------------------------------------ #
    def _execute(self, query: str, params: dict | None = None):
        """Execute a statement that has no result set (DDL/INSERT)."""
        if self._is_http_protocol():
            self._execute_http(query, params, expect_rows=False)
            return
        conn = self._ensure_client()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params or {})
        finally:
            cursor.close()

    @staticmethod
    def _http_substitute(query: str, params: dict | None) -> str:
        """
        The native clickhouse_driver binds ``%(name)s`` params itself (with proper
        quoting). The HTTP endpoint has no parameter binding, so we replicate it by
        applying Python ``%`` formatting after quoting each value as a ClickHouse
        literal. Only used for our simple watermark queries (params are trusted
        tenant_id strings / scalars).
        """
        if not params:
            return query
        quoted = {
            k: ("'" + str(v).replace("'", "''") + "'") if v is not None else "NULL"
            for k, v in params.items()
        }
        return query % quoted

    def _execute_http(
        self, query: str, params: dict | None = None, expect_rows: bool = True
    ) -> list:
        ac = self.authentication_config
        url = f"{ac.protocol}://{ac.host}:{ac.port}/"
        query = self._http_substitute(query, params)
        request_params = {"query": query, "default_format": "JSONEachRow"}
        if ac.database:
            request_params["database"] = ac.database
        response = requests.post(
            url,
            params=request_params,
            auth=(ac.username, ac.password),
            verify=ac.verify,
            timeout=DEFAULT_TIMEOUT_SECONDS,
        )
        if not response.ok:
            raise ProviderException(f"HTTP query failed: {response.text}")
        if not expect_rows or not response.text.strip():
            return []
        results = []
        for line in response.text.strip().split("\n"):
            if line:
                results.append(json.loads(line))
        return results

    def _scalar(self, query: str, params: dict | None = None):
        """Return a single scalar value or None."""
        if self._is_http_protocol():
            rows = self._execute_http(query, params)
            if not rows:
                return None
            return next(iter(rows[0].values()))
        conn = self._ensure_client()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params or {})
            row = cursor.fetchone()
            return row[0] if row else None
        finally:
            cursor.close()

    @staticmethod
    def _to_utc(dt):
        if dt is None:
            return None
        if isinstance(dt, str):
            dt = parse_dt(dt)
        if dt.tzinfo is None:
            return dt  # Keep stores naive UTC; leave as-is
        return dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)

    # ------------------------------------------------------------------ #
    # Schema
    # ------------------------------------------------------------------ #
    def _ensure_schema(self):
        if self._tables_ensured:
            return
        db = self.authentication_config.database or "default"
        ddls = [
            f"CREATE DATABASE IF NOT EXISTS {db}",
            f"""CREATE TABLE IF NOT EXISTS {db}.keep_alerts
            (
                id            String,
                tenant_id     String,
                timestamp     DateTime64(3),
                provider_type String,
                provider_id   String,
                fingerprint   String,
                alert_hash    String,
                event         String
            )
            ENGINE = MergeTree
            PARTITION BY toYYYYMM(timestamp)
            ORDER BY (tenant_id, timestamp)""",
            f"""CREATE TABLE IF NOT EXISTS {db}.keep_incidents
            (
                id                       String,
                tenant_id                String,
                running_number           Nullable(Int32),
                user_generated_name      Nullable(String),
                ai_generated_name        Nullable(String),
                user_summary             Nullable(String),
                generated_summary        Nullable(String),
                assignee                 Nullable(String),
                severity                 Int32,
                forced_severity          UInt8,
                status                   String,
                creation_time            DateTime64(3),
                start_time               Nullable(DateTime64(3)),
                end_time                 Nullable(DateTime64(3)),
                last_seen_time           Nullable(DateTime64(3)),
                is_predicted             UInt8,
                is_candidate             UInt8,
                is_visible               UInt8,
                alerts_count             Int32,
                affected_services        Array(String),
                sources                  Array(String),
                rule_id                  Nullable(String),
                rule_fingerprint         String,
                fingerprint              Nullable(String),
                incident_type            String,
                incident_application     Nullable(String),
                resolve_on               String,
                merged_into_incident_id  Nullable(String),
                merged_at                Nullable(DateTime64(3)),
                merged_by                Nullable(String),
                enrichments              String,
                version                  DateTime64(3)
            )
            ENGINE = ReplacingMergeTree(version)
            PARTITION BY toYYYYMM(creation_time)
            ORDER BY (tenant_id, id)""",
            f"""CREATE TABLE IF NOT EXISTS {db}.keep_alert_incident_links
            (
                tenant_id        String,
                fingerprint      String,
                incident_id      String,
                timestamp        DateTime64(3),
                is_created_by_ai UInt8,
                deleted_at       Nullable(DateTime64(3)),
                version          DateTime64(3)
            )
            ENGINE = ReplacingMergeTree(version)
            ORDER BY (tenant_id, incident_id, fingerprint)""",
        ]
        for ddl in ddls:
            self._execute(ddl)
        self._tables_ensured = True

    # ------------------------------------------------------------------ #
    # Entry points
    # ------------------------------------------------------------------ #
    def _notify(self, **kwargs) -> dict:
        """Archive run. Returns a summary dict (also exposed via expose())."""
        tenant_id = self.context_manager.tenant_id
        self._ensure_schema()
        summary = {
            "tenant_id": tenant_id,
            "alerts_copied": 0,
            "incidents_copied": 0,
            "links_copied": 0,
            "alert_watermark": None,
            "incident_watermark": None,
            "link_watermark": None,
            "started_at": datetime.datetime.utcnow().isoformat(),
        }
        summary["alerts_copied"] = self._sync_alerts(tenant_id, summary)
        summary["incidents_copied"] = self._sync_incidents(tenant_id, summary)
        summary["links_copied"] = self._sync_links(tenant_id, summary)
        self._last_sync_summary = summary
        self.logger.info("ClickHouse archive complete", extra=summary)
        return summary

    def _query(self, **kwargs) -> dict:
        return getattr(self, "_last_sync_summary", None) or {
            "message": "No archive run yet"
        }

    def expose(self):
        return {"last_sync_summary": getattr(self, "_last_sync_summary", {})}

    # ------------------------------------------------------------------ #
    # Sync: alerts
    # ------------------------------------------------------------------ #
    def _sync_alerts(self, tenant_id, summary):
        db = self.authentication_config.database or "default"
        last_ts = self._scalar(
            f"SELECT MAX(timestamp) FROM {db}.keep_alerts WHERE tenant_id = %(tid)s",
            {"tid": tenant_id},
        )
        lower = self._to_utc(last_ts)
        # query_alerts uses an inclusive `>=` on lower_timestamp, so the single
        # boundary row at the watermark is re-inserted each run (append-only,
        # tiny overlap). This is acceptable and keeps the operation idempotent.
        alerts = query_alerts(
            tenant_id=tenant_id,
            lower_timestamp=lower,
            limit=None,
            sort_ascending=True,
        )
        rows = [self._alert_to_row(a) for a in alerts]
        self._insert_rows(f"{db}.keep_alerts", _ALERT_COLUMNS, rows)
        if rows:
            max_ts = max(a.timestamp for a in alerts if a.timestamp is not None)
            summary["alert_watermark"] = max_ts.isoformat() if max_ts else None
        return len(rows)

    @staticmethod
    def _alert_to_row(a: Alert):
        return (
            str(a.id),
            a.tenant_id,
            a.timestamp,
            a.provider_type,
            a.provider_id or "",
            a.fingerprint,
            a.alert_hash or "",
            json.dumps(a.event, default=str),
        )

    # ------------------------------------------------------------------ #
    # Sync: incidents
    # ------------------------------------------------------------------ #
    def _sync_incidents(self, tenant_id, summary):
        db = self.authentication_config.database or "default"
        last_ts = self._scalar(
            f"SELECT MAX(last_seen_time) FROM {db}.keep_incidents WHERE tenant_id = %(tid)s",
            {"tid": tenant_id},
        )
        lower = self._to_utc(last_ts)
        incidents, _ = get_last_incidents(
            tenant_id=tenant_id,
            limit=10000,
            lower_timestamp=lower,
            sorting=IncidentSorting.last_seen_time,
        )
        rows = [self._incident_to_row(i) for i in incidents]
        self._insert_rows(f"{db}.keep_incidents", _INCIDENT_COLUMNS, rows)
        if rows:
            seen = [i.last_seen_time for i in incidents if i.last_seen_time]
            if seen:
                summary["incident_watermark"] = max(seen).isoformat()
        return len(rows)

    @staticmethod
    def _incident_to_row(inc: Incident):
        version = inc.last_seen_time or inc.creation_time
        return (
            str(inc.id),
            inc.tenant_id,
            inc.running_number,
            inc.user_generated_name,
            inc.ai_generated_name,
            inc.user_summary,
            inc.generated_summary,
            inc.assignee,
            int(inc.severity) if inc.severity is not None else 0,
            int(bool(inc.forced_severity)),
            inc.status,
            inc.creation_time,
            inc.start_time,
            inc.end_time,
            inc.last_seen_time,
            int(bool(inc.is_predicted)),
            int(bool(inc.is_candidate)),
            int(bool(inc.is_visible)),
            int(inc.alerts_count) if inc.alerts_count is not None else 0,
            list(inc.affected_services or []),
            list(inc.sources or []),
            str(inc.rule_id) if inc.rule_id else None,
            inc.rule_fingerprint or "",
            inc.fingerprint,
            inc.incident_type,
            str(inc.incident_application) if inc.incident_application else None,
            inc.resolve_on,
            str(inc.merged_into_incident_id) if inc.merged_into_incident_id else None,
            inc.merged_at,
            inc.merged_by,
            json.dumps(getattr(inc, "_enrichments", {}) or {}, default=str),
            version,
        )

    # ------------------------------------------------------------------ #
    # Sync: alert↔incident links
    # ------------------------------------------------------------------ #
    @staticmethod
    def _query_last_alert_to_incident_links(
        tenant_id: str, lower_timestamp: datetime.datetime = None, limit: int = None
    ) -> list[LastAlertToIncident]:
        """
        Fetch LastAlertToIncident link rows for a tenant ordered by link timestamp
        ascending, optionally bounded by ``lower_timestamp`` (inclusive). Kept
        inside the provider so no existing code (e.g. ``db.py``) needs to change.
        """
        with Session(engine) as session:
            query = session.query(LastAlertToIncident).filter(
                LastAlertToIncident.tenant_id == tenant_id
            )
            if lower_timestamp is not None:
                query = query.filter(LastAlertToIncident.timestamp >= lower_timestamp)
            query = query.order_by(LastAlertToIncident.timestamp.asc())
            if limit:
                query = query.limit(limit)
            return query.all()

    def _sync_links(self, tenant_id, summary):
        db = self.authentication_config.database or "default"
        last_ts = self._scalar(
            f"SELECT MAX(timestamp) FROM {db}.keep_alert_incident_links WHERE tenant_id = %(tid)s",
            {"tid": tenant_id},
        )
        lower = self._to_utc(last_ts)
        links = self._query_last_alert_to_incident_links(
            tenant_id=tenant_id, lower_timestamp=lower
        )
        rows = [self._link_to_row(l) for l in links]
        self._insert_rows(f"{db}.keep_alert_incident_links", _LINK_COLUMNS, rows)
        if rows:
            max_ts = max(l.timestamp for l in links if l.timestamp is not None)
            summary["link_watermark"] = max_ts.isoformat() if max_ts else None
        return len(rows)

    @staticmethod
    def _link_to_row(link: LastAlertToIncident):
        deleted_at = link.deleted_at
        # NULL_FOR_DELETED_AT sentinel (datetime(1000,1,1)) means "not deleted"
        if deleted_at == NULL_FOR_DELETED_AT:
            deleted_at = None
        return (
            link.tenant_id,
            link.fingerprint,
            str(link.incident_id),
            link.timestamp,
            int(bool(link.is_created_by_ai)),
            deleted_at,
            link.timestamp,  # version
        )

    # ------------------------------------------------------------------ #
    # Insert (native + HTTP), chunked
    # ------------------------------------------------------------------ #
    def _insert_rows(self, table: str, columns: list[str], rows: list[tuple]):
        if not rows:
            return
        chunk = self.authentication_config.chunk_size or 1000
        for i in range(0, len(rows), chunk):
            batch = rows[i : i + chunk]
            if self._is_http_protocol():
                self._insert_rows_http(table, columns, batch)
            else:
                self._insert_rows_native(table, columns, batch)

    def _insert_rows_native(self, table, columns, rows):
        conn = self._ensure_client()
        cursor = conn.cursor()
        col_list = ",".join(columns)
        placeholders = ",".join(["%s"] * len(columns))
        try:
            cursor.executemany(
                f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})", rows
            )
        finally:
            cursor.close()

    def _insert_rows_http(self, table, columns, rows):
        ac = self.authentication_config
        url = f"{ac.protocol}://{ac.host}:{ac.port}/"
        col_list = ",".join(columns)
        request_params = {
            "query": f"INSERT INTO {table} ({col_list}) FORMAT JSONEachRow",
        }
        if ac.database:
            request_params["database"] = ac.database
        body = "\n".join(
            json.dumps(self._row_to_jsondict(columns, r), default=str) for r in rows
        )
        response = requests.post(
            url,
            params=request_params,
            data=body.encode("utf-8"),
            auth=(ac.username, ac.password),
            verify=ac.verify,
            timeout=DEFAULT_TIMEOUT_SECONDS,
        )
        if not response.ok:
            raise ProviderException(f"HTTP insert failed: {response.text}")

    @staticmethod
    def _row_to_jsondict(columns, row):
        d = {}
        for col, val in zip(columns, row):
            if isinstance(val, datetime.datetime):
                # Explicit UTC so ClickHouse parses into DateTime64 unambiguously
                d[col] = val.isoformat() + "+00:00"
            else:
                d[col] = val
        return d


if __name__ == "__main__":
    import os

    config = ProviderConfig(
        authentication={
            "username": os.environ.get("CLICKHOUSE_USER", "default"),
            "password": os.environ.get("CLICKHOUSE_PASSWORD", ""),
            "host": os.environ.get("CLICKHOUSE_HOST", "localhost"),
            "database": os.environ.get("CLICKHOUSE_DATABASE", "keep_archive"),
            "port": os.environ.get("CLICKHOUSE_PORT", "9000"),
            "protocol": os.environ.get("CLICKHOUSE_PROTOCOL", "clickhouse"),
        }
    )
    context_manager = ContextManager(tenant_id="singletenant", workflow_id="test")
    provider = ClickhouseArchiveProvider(context_manager, "clickhouse-warehouse", config)
    print(json.dumps(provider.notify(), indent=2, default=str))