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

## Tests

```
python3 -m unittest test_relay_ledger
```
