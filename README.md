# Relay Ledger

Authenticated, idempotent event ingestion over SQLite (Python stdlib only).

## Usage

```python
from relay_ledger import Ledger

ledger = Ledger("relay.sqlite", {"tenant-a": "shared-secret"})
ledger.initialize()  # repeatable; never touches existing data
result = ledger.ingest(raw_body_bytes, headers)
```

`ingest(raw_body, headers)`:

- Verifies `X-Relay-Timestamp` (integer Unix seconds, ±300s inclusive skew)
  and `X-Relay-Signature` (`v1=<hex>` HMAC-SHA256 over
  `ascii(timestamp) + b"." + raw_body`) before any database mutation.
  Header names are case-insensitive; signature hex may be upper or lower case.
- Appends the event to an immutable log keyed by
  `(tenant_id, source, event_id)`.
- Replays of the same semantic payload (any byte representation) are
  idempotent duplicates; identity reuse with different content raises
  `IdempotencyConflict` and writes nothing.
- Maintains a materialized projection per `(tenant_id, source, entity_id)`;
  the winner is the event with the latest `occurred_at` (compared as an
  instant), ties broken by lexicographically larger `event_id`. Deletes
  become tombstones; late events stay in the log without regressing the
  projection.

## Projection semantics

Projections are computed by a single pure fold (`project_events`) over an
entity's logged events in `(occurred_at, event_id)` order — the same
projector serves live ingest and replay, so the projected state is a
function of the log alone, independent of arrival order.

Tombstones are sticky: once the folded state is a delete, a subsequent
upsert resurrects the entity only when both the tombstone's and the
upsert's `source_version` are non-null and the upsert's is strictly
greater. Equal, lower, or missing versions cannot resurrect, and a
versionless tombstone is permanent. The version gate applies only to
resurrection; all other transitions follow normal ordering.

Ingest performs the log append and projection update in one `IMMEDIATE`
transaction with a bounded busy timeout and WAL journaling where
supported. A uniqueness race re-reads the winning row and is classified
duplicate vs conflict; no other SQLite error is ever reported as a
duplicate.

## Reconciliation

```python
report = ledger.reconcile(tenant_id=None, repair=False)
```

Replays the log with the shared projector and returns one item per
drifted, missing, or orphaned projection, sorted by
`(tenant_id, source, entity_id)`, each with `stored`, `expected`, and
`reason`. `repair=True` fixes exactly the reported projections in one
transaction; a second dry run returns `[]`.

CLI (JSON Lines output):

```
python3 relay_ledger.py reconcile <db> [--tenant TENANT] [--repair]
```

Exit codes: `0` no drift, `2` drift found without `--repair`, `0` after a
successful repair.

## Tests

```
python3 -m unittest test_relay_ledger
```
