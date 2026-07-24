"""Relay Ledger: authenticated, idempotent event ingestion over SQLite.

An event is authenticated (HMAC-SHA256 over the raw request bytes) before any
database mutation, appended to an immutable event log, and materialized into a
deterministic per-entity projection.

Projections are computed by one pure fold (``project_events``) shared by live
ingest and ``reconcile`` replay, so the two cannot drift: the projected state
of an entity is a function of its logged events only, never of arrival order.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone

__all__ = [
    "Ledger",
    "LedgerError",
    "AuthenticationError",
    "ValidationError",
    "IdempotencyConflict",
    "project_events",
]

MAX_SKEW_SECONDS = 300
DEFAULT_BUSY_TIMEOUT_MS = 5000

_TIMESTAMP_RE = re.compile(rb"^-?[0-9]+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_REQUIRED_FIELDS = {
    "tenant_id",
    "source",
    "event_id",
    "entity_id",
    "event_type",
    "occurred_at",
    "data",
}
_ALLOWED_FIELDS = _REQUIRED_FIELDS | {"source_version"}

_STATE_FIELDS = ("event_id", "event_type", "occurred_at", "source_version", "data_json")


class LedgerError(Exception):
    """Base class for ledger errors."""


class AuthenticationError(LedgerError):
    """The request could not be authenticated. Nothing was written."""


class ValidationError(LedgerError):
    """The authenticated payload failed validation. Nothing was written."""


class IdempotencyConflict(LedgerError):
    """The event identity was reused with different semantic content."""


def _reject_constant(name):
    raise ValidationError(f"non-finite number not allowed: {name}")


def canonical_json(value) -> str:
    """Canonical serialization: sorted keys, no extra whitespace, Unicode
    preserved, non-finite numbers rejected."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def fingerprint_event(event: dict) -> str:
    return hashlib.sha256(canonical_json(event).encode("utf-8")).hexdigest()


def _parse_occurred_at(text):
    if not isinstance(text, str) or not text:
        raise ValidationError("occurred_at must be an RFC3339 string")
    normalized = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        raise ValidationError(f"occurred_at is not valid RFC3339: {text!r}") from None
    if dt.tzinfo is None:
        raise ValidationError("occurred_at must include a UTC offset")
    # Fixed-width UTC form so lexicographic order in SQLite equals instant order.
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def project_events(events):
    """Fold an entity's events into its projected state.

    The single projector for live ingest and replay. Events are folded in
    (occurred_at, event_id) order regardless of arrival order, so the result
    is a pure function of the log.

    Tombstones are sticky: once the folded state is a delete, a later upsert
    resurrects the entity only when both the tombstone's and the upsert's
    source_version are non-null and the upsert's is strictly greater. The
    version gate replaces timestamp ordering for resurrection only; every
    other transition follows (occurred_at, event_id) order.

    Returns a dict of _STATE_FIELDS, or None for an empty event list.
    """
    state = None
    for event in sorted(events, key=lambda e: (e["occurred_at"], e["event_id"])):
        if (
            state is not None
            and state["event_type"] == "delete"
            and event["event_type"] == "upsert"
        ):
            tombstone_version = state["source_version"]
            upsert_version = event["source_version"]
            if (
                tombstone_version is None
                or upsert_version is None
                or upsert_version <= tombstone_version
            ):
                continue
        state = {field: event[field] for field in _STATE_FIELDS}
    return state


class Ledger:
    """Event ledger with authenticated ingest and materialized projections.

    ``secrets`` maps tenant_id to that tenant's shared HMAC secret, or is a
    callable ``tenant_id -> secret | None``. Secrets are never persisted.
    ``now_fn`` returns current Unix seconds (injectable for tests).
    ``busy_timeout_ms`` bounds how long SQLite waits on a locked database;
    lock timeouts surface as sqlite3.OperationalError, never as a duplicate.
    """

    def __init__(
        self,
        db_path,
        secrets,
        now_fn=time.time,
        busy_timeout_ms=DEFAULT_BUSY_TIMEOUT_MS,
    ):
        self._db_path = str(db_path)
        self._secrets = secrets
        self._now_fn = now_fn
        self._busy_timeout_ms = int(busy_timeout_ms)

    # -- connection ---------------------------------------------------------

    def _connect(self):
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        # WAL where supported; SQLite silently keeps the prior mode otherwise.
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def initialize(self):
        """Create schema if absent. Repeatable; never touches existing data."""
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                        tenant_id      TEXT NOT NULL,
                        source         TEXT NOT NULL,
                        event_id       TEXT NOT NULL,
                        entity_id      TEXT NOT NULL,
                        event_type     TEXT NOT NULL,
                        occurred_at    TEXT NOT NULL,
                        source_version INTEGER,
                        data_json      TEXT NOT NULL,
                        fingerprint    TEXT NOT NULL,
                        received_at    TEXT NOT NULL,
                        PRIMARY KEY (tenant_id, source, event_id)
                    ) WITHOUT ROWID
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS projections (
                        tenant_id      TEXT NOT NULL,
                        source         TEXT NOT NULL,
                        entity_id      TEXT NOT NULL,
                        event_id       TEXT NOT NULL,
                        event_type     TEXT NOT NULL,
                        occurred_at    TEXT NOT NULL,
                        source_version INTEGER,
                        data_json      TEXT NOT NULL,
                        PRIMARY KEY (tenant_id, source, entity_id)
                    ) WITHOUT ROWID
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_events_entity
                    ON events (tenant_id, source, entity_id, occurred_at, event_id)
                    """
                )
        finally:
            conn.close()

    # -- authentication -----------------------------------------------------

    def _secret_for(self, tenant_id):
        secret = self._secrets(tenant_id) if callable(self._secrets) else self._secrets.get(tenant_id)
        if secret is None:
            return None
        return secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)

    def _authenticate(self, raw_body, headers):
        if isinstance(raw_body, str):
            raw_body = raw_body.encode("utf-8")
        lowered = {}
        for name, value in headers.items():
            lowered[name.lower()] = value

        ts_text = lowered.get("x-relay-timestamp")
        sig_text = lowered.get("x-relay-signature")
        if ts_text is None:
            raise AuthenticationError("missing X-Relay-Timestamp header")
        if sig_text is None:
            raise AuthenticationError("missing X-Relay-Signature header")

        ts_bytes = ts_text.encode("ascii", "replace") if isinstance(ts_text, str) else bytes(ts_text)
        if not _TIMESTAMP_RE.fullmatch(ts_bytes):
            raise AuthenticationError("X-Relay-Timestamp must be integer seconds")
        timestamp = int(ts_bytes)

        now = int(self._now_fn())
        if abs(now - timestamp) > MAX_SKEW_SECONDS:
            raise AuthenticationError("timestamp outside allowed skew")

        if not isinstance(sig_text, str) or not sig_text.startswith("v1="):
            raise AuthenticationError("signature must use the v1 scheme")
        presented = sig_text[3:]
        if not _HEX_RE.fullmatch(presented):
            raise AuthenticationError("signature is not hex")

        # Resolve tenant_id — the only field read before the signature check.
        try:
            parsed = json.loads(raw_body, parse_constant=_reject_constant)
        except ValidationError:
            raise
        except (ValueError, UnicodeDecodeError):
            raise AuthenticationError("body is not valid JSON") from None
        if not isinstance(parsed, dict) or not isinstance(parsed.get("tenant_id"), str):
            raise AuthenticationError("cannot resolve tenant_id")

        secret = self._secret_for(parsed["tenant_id"])
        if secret is None:
            raise AuthenticationError("unknown tenant")

        expected = hmac.new(secret, ts_bytes + b"." + raw_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, presented.lower()):
            raise AuthenticationError("signature mismatch")
        return parsed

    # -- validation ---------------------------------------------------------

    @staticmethod
    def _validate(parsed):
        extra = set(parsed) - _ALLOWED_FIELDS
        if extra:
            raise ValidationError(f"unknown fields: {sorted(extra)}")
        missing = _REQUIRED_FIELDS - set(parsed)
        if missing:
            raise ValidationError(f"missing fields: {sorted(missing)}")

        for field in ("tenant_id", "source", "event_id", "entity_id"):
            value = parsed[field]
            if not isinstance(value, str) or not value:
                raise ValidationError(f"{field} must be a non-empty string")

        if parsed["event_type"] not in ("upsert", "delete"):
            raise ValidationError("event_type must be 'upsert' or 'delete'")

        version = parsed.get("source_version")
        if version is not None:
            if isinstance(version, bool) or not isinstance(version, int) or version < 0:
                raise ValidationError("source_version must be a non-negative integer")

        if not isinstance(parsed["data"], dict):
            raise ValidationError("data must be an object")

        return {
            "tenant_id": parsed["tenant_id"],
            "source": parsed["source"],
            "event_id": parsed["event_id"],
            "entity_id": parsed["entity_id"],
            "event_type": parsed["event_type"],
            "occurred_at": _parse_occurred_at(parsed["occurred_at"]),
            "source_version": version,
            "data_json": canonical_json(parsed["data"]),
        }

    # -- ingest -------------------------------------------------------------

    def ingest(self, raw_body, headers):
        """Authenticate, validate, and store one event.

        Returns {"status": "ingested" | "duplicate", "projected": bool}.
        The append and the projection update happen in one IMMEDIATE
        transaction. A uniqueness race re-reads the winning row and is
        classified duplicate vs conflict; no other SQLite error is ever
        treated as a duplicate.
        """
        parsed = self._authenticate(raw_body, headers)
        event = self._validate(parsed)
        event_fp = fingerprint_event(parsed)

        conn = self._connect()
        try:
            with conn:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT fingerprint FROM events"
                    " WHERE tenant_id = ? AND source = ? AND event_id = ?",
                    (event["tenant_id"], event["source"], event["event_id"]),
                ).fetchone()
                if row is None:
                    received_at = datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%S.%f+00:00"
                    )
                    try:
                        conn.execute(
                            "INSERT INTO events (tenant_id, source, event_id,"
                            " entity_id, event_type, occurred_at, source_version,"
                            " data_json, fingerprint, received_at)"
                            " VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (
                                event["tenant_id"],
                                event["source"],
                                event["event_id"],
                                event["entity_id"],
                                event["event_type"],
                                event["occurred_at"],
                                event["source_version"],
                                event["data_json"],
                                event_fp,
                                received_at,
                            ),
                        )
                    except sqlite3.IntegrityError:
                        # Uniqueness race: another writer inserted this
                        # identity between our read and write. Re-read the
                        # winner and classify. Any other SQLite error
                        # (locked, busy, disk) propagates unchanged.
                        row = conn.execute(
                            "SELECT fingerprint FROM events"
                            " WHERE tenant_id = ? AND source = ? AND event_id = ?",
                            (event["tenant_id"], event["source"], event["event_id"]),
                        ).fetchone()
                        if row is None:
                            raise
                if row is not None:
                    if row[0] == event_fp:
                        return {"status": "duplicate", "projected": False}
                    raise IdempotencyConflict(
                        "event identity reused with different content"
                    )
                projected = self._reproject_entity(
                    conn, event["tenant_id"], event["source"], event["entity_id"]
                ) == event["event_id"]
        finally:
            conn.close()
        return {"status": "ingested", "projected": projected}

    # -- projection ---------------------------------------------------------

    @staticmethod
    def _entity_events(conn, tenant_id, source, entity_id):
        rows = conn.execute(
            "SELECT event_id, event_type, occurred_at, source_version, data_json"
            " FROM events WHERE tenant_id = ? AND source = ? AND entity_id = ?",
            (tenant_id, source, entity_id),
        ).fetchall()
        return [dict(zip(_STATE_FIELDS, row)) for row in rows]

    @classmethod
    def _reproject_entity(cls, conn, tenant_id, source, entity_id):
        """Recompute one entity's projection from its logged events using the
        shared projector. Returns the winning event_id, or None."""
        state = project_events(cls._entity_events(conn, tenant_id, source, entity_id))
        if state is None:
            conn.execute(
                "DELETE FROM projections"
                " WHERE tenant_id = ? AND source = ? AND entity_id = ?",
                (tenant_id, source, entity_id),
            )
            return None
        cls._write_projection(conn, tenant_id, source, entity_id, state)
        return state["event_id"]

    @staticmethod
    def _write_projection(conn, tenant_id, source, entity_id, state):
        conn.execute(
            "INSERT INTO projections (tenant_id, source, entity_id, event_id,"
            " event_type, occurred_at, source_version, data_json)"
            " VALUES (?,?,?,?,?,?,?,?)"
            " ON CONFLICT (tenant_id, source, entity_id) DO UPDATE SET"
            " event_id = excluded.event_id, event_type = excluded.event_type,"
            " occurred_at = excluded.occurred_at,"
            " source_version = excluded.source_version,"
            " data_json = excluded.data_json",
            (
                tenant_id,
                source,
                entity_id,
                state["event_id"],
                state["event_type"],
                state["occurred_at"],
                state["source_version"],
                state["data_json"],
            ),
        )

    # -- reconciliation -----------------------------------------------------

    def reconcile(self, tenant_id=None, repair=False):
        """Deterministically replay the log and report projection drift.

        Returns one item per drifted, missing, or orphaned projection, sorted
        by (tenant_id, source, entity_id). Each item carries the identity,
        ``stored``, ``expected``, and ``reason``. With ``repair=True`` the
        reported projections — and only those — are fixed in one transaction;
        a following dry run returns an empty list.
        """
        scope_sql = " WHERE tenant_id = ?" if tenant_id is not None else ""
        scope_params = (tenant_id,) if tenant_id is not None else ()

        conn = self._connect()
        try:
            entities = set(
                conn.execute(
                    "SELECT DISTINCT tenant_id, source, entity_id FROM events" + scope_sql,
                    scope_params,
                ).fetchall()
            )
            entities.update(
                conn.execute(
                    "SELECT tenant_id, source, entity_id FROM projections" + scope_sql,
                    scope_params,
                ).fetchall()
            )

            report = []
            fixes = []
            for tenant, source, entity in sorted(entities):
                expected = project_events(
                    self._entity_events(conn, tenant, source, entity)
                )
                row = conn.execute(
                    "SELECT event_id, event_type, occurred_at, source_version,"
                    " data_json FROM projections"
                    " WHERE tenant_id = ? AND source = ? AND entity_id = ?",
                    (tenant, source, entity),
                ).fetchone()
                stored = dict(zip(_STATE_FIELDS, row)) if row is not None else None
                if stored == expected:
                    continue
                if stored is None:
                    reason = "missing"
                elif expected is None:
                    reason = "orphaned"
                else:
                    reason = "drifted"
                report.append(
                    {
                        "tenant_id": tenant,
                        "source": source,
                        "entity_id": entity,
                        "stored": _public_state(stored),
                        "expected": _public_state(expected),
                        "reason": reason,
                    }
                )
                fixes.append((tenant, source, entity, expected))

            if repair and fixes:
                with conn:
                    conn.execute("BEGIN IMMEDIATE")
                    for tenant, source, entity, expected in fixes:
                        if expected is None:
                            conn.execute(
                                "DELETE FROM projections WHERE tenant_id = ?"
                                " AND source = ? AND entity_id = ?",
                                (tenant, source, entity),
                            )
                        else:
                            self._write_projection(conn, tenant, source, entity, expected)
            return report
        finally:
            conn.close()

    # -- reads --------------------------------------------------------------

    def get_projection(self, tenant_id, source, entity_id):
        """Current projected state for an entity, or None.

        A projected delete is reported as None (tombstone rows stay in the
        table to keep ordering and resurrection-gate information).
        """
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT event_id, event_type, occurred_at, source_version,"
                " data_json FROM projections"
                " WHERE tenant_id = ? AND source = ? AND entity_id = ?",
                (tenant_id, source, entity_id),
            ).fetchone()
        finally:
            conn.close()
        if row is None or row[1] == "delete":
            return None
        return {
            "tenant_id": tenant_id,
            "source": source,
            "entity_id": entity_id,
            "event_id": row[0],
            "event_type": row[1],
            "occurred_at": row[2],
            "source_version": row[3],
            "data": json.loads(row[4]),
        }

    def get_events(self, tenant_id, source=None):
        """Immutable log entries for a tenant, in received order."""
        query = (
            "SELECT tenant_id, source, event_id, entity_id, event_type,"
            " occurred_at, source_version, data_json, fingerprint, received_at"
            " FROM events WHERE tenant_id = ?"
        )
        params = [tenant_id]
        if source is not None:
            query += " AND source = ?"
            params.append(source)
        query += " ORDER BY received_at, event_id"
        conn = self._connect()
        try:
            rows = conn.execute(query, params).fetchall()
        finally:
            conn.close()
        return [
            {
                "tenant_id": r[0],
                "source": r[1],
                "event_id": r[2],
                "entity_id": r[3],
                "event_type": r[4],
                "occurred_at": r[5],
                "source_version": r[6],
                "data": json.loads(r[7]),
                "fingerprint": r[8],
                "received_at": r[9],
            }
            for r in rows
        ]


def _public_state(state):
    if state is None:
        return None
    return {
        "event_id": state["event_id"],
        "event_type": state["event_type"],
        "occurred_at": state["occurred_at"],
        "source_version": state["source_version"],
        "data": json.loads(state["data_json"]),
    }


# -- CLI ---------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(prog="relay-ledger")
    subparsers = parser.add_subparsers(dest="command", required=True)
    rec = subparsers.add_parser(
        "reconcile", help="Replay the log and report projection drift as JSON Lines."
    )
    rec.add_argument("db", help="Path to the ledger SQLite database")
    rec.add_argument("--tenant", default=None, help="Limit to one tenant")
    rec.add_argument("--repair", action="store_true", help="Fix reported drift")
    args = parser.parse_args(argv)

    ledger = Ledger(args.db, {})
    report = ledger.reconcile(tenant_id=args.tenant, repair=args.repair)
    for item in report:
        print(json.dumps(item, sort_keys=True, ensure_ascii=False))
    if not report:
        return 0
    if not args.repair:
        return 2
    # Confirm the repair actually converged before reporting success.
    return 0 if not ledger.reconcile(tenant_id=args.tenant) else 1


if __name__ == "__main__":
    sys.exit(main())
