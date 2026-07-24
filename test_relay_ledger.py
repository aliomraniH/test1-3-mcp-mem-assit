import hashlib
import hmac
import json
import os
import tempfile
import unittest

from relay_ledger import (
    AuthenticationError,
    IdempotencyConflict,
    Ledger,
    ValidationError,
)

SECRET = "test-secret"
NOW = 1_800_000_000


def sign(raw_body, timestamp=NOW, secret=SECRET, upper=False):
    if isinstance(raw_body, str):
        raw_body = raw_body.encode("utf-8")
    ts = str(timestamp)
    digest = hmac.new(
        secret.encode(), ts.encode("ascii") + b"." + raw_body, hashlib.sha256
    ).hexdigest()
    if upper:
        digest = digest.upper()
    return {"X-Relay-Timestamp": ts, "X-Relay-Signature": "v1=" + digest}


def event_body(**overrides):
    event = {
        "tenant_id": "t1",
        "source": "crm",
        "event_id": "evt-1",
        "entity_id": "acct-1",
        "event_type": "upsert",
        "occurred_at": "2027-01-01T10:00:00+00:00",
        "data": {"name": "Acme"},
    }
    event.update(overrides)
    return json.dumps(event).encode()


class LedgerTestCase(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        self.addCleanup(os.unlink, self.db_path)
        self.ledger = Ledger(
            self.db_path, {"t1": SECRET, "t2": "other-secret"}, now_fn=lambda: NOW
        )
        self.ledger.initialize()


class AuthenticationTests(LedgerTestCase):
    def test_valid_signature_ingests(self):
        body = event_body()
        result = self.ledger.ingest(body, sign(body))
        self.assertEqual(result["status"], "ingested")

    def test_headers_are_case_insensitive(self):
        body = event_body()
        headers = {k.upper(): v for k, v in sign(body).items()}
        self.assertEqual(self.ledger.ingest(body, headers)["status"], "ingested")

    def test_uppercase_hex_signature_accepted(self):
        body = event_body()
        result = self.ledger.ingest(body, sign(body, upper=True))
        self.assertEqual(result["status"], "ingested")

    def test_bad_signature_rejected_before_any_write(self):
        body = event_body()
        headers = sign(body)
        headers["X-Relay-Signature"] = "v1=" + "0" * 64
        with self.assertRaises(AuthenticationError):
            self.ledger.ingest(body, headers)
        self.assertEqual(self.ledger.get_events("t1"), [])

    def test_signature_covers_raw_bytes_not_reserialized_json(self):
        body = b'{"tenant_id":"t1","source":"crm","event_id":"e","entity_id":"a","event_type":"upsert","occurred_at":"2027-01-01T00:00:00Z","data":{}}'
        reserialized = json.dumps(json.loads(body)).encode()
        self.assertNotEqual(body, reserialized)
        with self.assertRaises(AuthenticationError):
            self.ledger.ingest(body, sign(reserialized))
        self.assertEqual(self.ledger.ingest(body, sign(body))["status"], "ingested")

    def test_missing_headers_rejected(self):
        body = event_body()
        for drop in ("X-Relay-Timestamp", "X-Relay-Signature"):
            headers = sign(body)
            del headers[drop]
            with self.assertRaises(AuthenticationError):
                self.ledger.ingest(body, headers)

    def test_skew_boundary_is_inclusive_and_symmetric(self):
        for offset in (-300, 300):
            body = event_body(event_id=f"skew-{offset}")
            result = self.ledger.ingest(body, sign(body, timestamp=NOW + offset))
            self.assertEqual(result["status"], "ingested")
        for offset in (-301, 301):
            body = event_body(event_id=f"skew-{offset}")
            with self.assertRaises(AuthenticationError):
                self.ledger.ingest(body, sign(body, timestamp=NOW + offset))

    def test_non_integer_timestamp_rejected(self):
        body = event_body()
        for bad in ("1.5", "abc", "", " 100", "+100"):
            headers = sign(body)
            headers["X-Relay-Timestamp"] = bad
            with self.assertRaises(AuthenticationError):
                self.ledger.ingest(body, headers)

    def test_unknown_tenant_rejected(self):
        body = event_body(tenant_id="nobody")
        with self.assertRaises(AuthenticationError):
            self.ledger.ingest(body, sign(body))

    def test_wrong_tenant_secret_rejected(self):
        body = event_body(tenant_id="t2")
        with self.assertRaises(AuthenticationError):
            self.ledger.ingest(body, sign(body, secret=SECRET))

    def test_unsigned_scheme_rejected(self):
        body = event_body()
        headers = sign(body)
        headers["X-Relay-Signature"] = headers["X-Relay-Signature"].replace("v1=", "v2=")
        with self.assertRaises(AuthenticationError):
            self.ledger.ingest(body, headers)


class ValidationTests(LedgerTestCase):
    def ingest(self, body):
        return self.ledger.ingest(body, sign(body))

    def test_event_type_restricted(self):
        with self.assertRaises(ValidationError):
            self.ingest(event_body(event_type="update"))

    def test_missing_field_rejected(self):
        event = json.loads(event_body())
        del event["entity_id"]
        with self.assertRaises(ValidationError):
            self.ingest(json.dumps(event).encode())

    def test_unknown_field_rejected(self):
        with self.assertRaises(ValidationError):
            self.ingest(event_body(surprise=1))

    def test_source_version_must_be_non_negative_int(self):
        for bad in (-1, "3", 1.5, True):
            with self.assertRaises(ValidationError):
                self.ingest(event_body(source_version=bad))
        self.assertEqual(self.ingest(event_body(source_version=0))["status"], "ingested")

    def test_occurred_at_requires_offset(self):
        with self.assertRaises(ValidationError):
            self.ingest(event_body(occurred_at="2027-01-01T10:00:00"))

    def test_non_finite_numbers_rejected(self):
        raw = event_body().replace(b'{"name": "Acme"}', b'{"n": NaN}')
        with self.assertRaises(ValidationError):
            self.ledger.ingest(raw, sign(raw))

    def test_data_must_be_object(self):
        with self.assertRaises(ValidationError):
            self.ingest(event_body(data=[1, 2]))

    def test_validation_failure_writes_nothing(self):
        try:
            self.ingest(event_body(event_type="bogus"))
        except ValidationError:
            pass
        self.assertEqual(self.ledger.get_events("t1"), [])


class IdempotencyTests(LedgerTestCase):
    def ingest(self, body):
        return self.ledger.ingest(body, sign(body))

    def test_byte_identical_replay_is_duplicate(self):
        body = event_body()
        self.ingest(body)
        result = self.ingest(body)
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(len(self.ledger.get_events("t1")), 1)

    def test_byte_different_same_semantics_is_duplicate(self):
        body = event_body()
        self.ingest(body)
        # Same object, different key order and whitespace.
        reordered = json.dumps(
            json.loads(body), sort_keys=True, indent=2
        ).encode()
        self.assertNotEqual(body, reordered)
        result = self.ledger.ingest(reordered, sign(reordered))
        self.assertEqual(result["status"], "duplicate")
        self.assertEqual(len(self.ledger.get_events("t1")), 1)

    def test_identity_reuse_with_new_content_conflicts(self):
        self.ingest(event_body())
        altered = event_body(data={"name": "Evil Corp"})
        with self.assertRaises(IdempotencyConflict):
            self.ledger.ingest(altered, sign(altered))
        events = self.ledger.get_events("t1")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["data"], {"name": "Acme"})
        projection = self.ledger.get_projection("t1", "crm", "acct-1")
        self.assertEqual(projection["data"], {"name": "Acme"})

    def test_unicode_preserved_in_fingerprint_and_data(self):
        body = event_body(data={"name": "Ünïcode ✓"})
        self.ingest(body)
        escaped = json.dumps(json.loads(body)).encode()  # \uXXXX escapes
        result = self.ledger.ingest(escaped, sign(escaped))
        self.assertEqual(result["status"], "duplicate")
        projection = self.ledger.get_projection("t1", "crm", "acct-1")
        self.assertEqual(projection["data"], {"name": "Ünïcode ✓"})


class ProjectionTests(LedgerTestCase):
    def ingest(self, body):
        return self.ledger.ingest(body, sign(body))

    def test_later_occurred_at_wins(self):
        self.ingest(event_body(event_id="e1", occurred_at="2027-01-01T10:00:00Z", data={"v": 1}))
        self.ingest(event_body(event_id="e2", occurred_at="2027-01-01T11:00:00Z", data={"v": 2}))
        self.assertEqual(self.ledger.get_projection("t1", "crm", "acct-1")["data"], {"v": 2})

    def test_late_event_kept_in_log_but_projection_not_regressed(self):
        self.ingest(event_body(event_id="e2", occurred_at="2027-01-01T11:00:00Z", data={"v": 2}))
        result = self.ingest(
            event_body(event_id="e1", occurred_at="2027-01-01T10:00:00Z", data={"v": 1})
        )
        self.assertEqual(result, {"status": "ingested", "projected": False})
        self.assertEqual(len(self.ledger.get_events("t1")), 2)
        self.assertEqual(self.ledger.get_projection("t1", "crm", "acct-1")["data"], {"v": 2})

    def test_tie_broken_by_larger_event_id(self):
        at = "2027-01-01T10:00:00Z"
        self.ingest(event_body(event_id="b", occurred_at=at, data={"v": "b"}))
        self.ingest(event_body(event_id="a", occurred_at=at, data={"v": "a"}))
        self.assertEqual(self.ledger.get_projection("t1", "crm", "acct-1")["data"], {"v": "b"})
        self.ingest(event_body(event_id="c", occurred_at=at, data={"v": "c"}))
        self.assertEqual(self.ledger.get_projection("t1", "crm", "acct-1")["data"], {"v": "c"})

    def test_offset_timestamps_compared_as_instants(self):
        self.ingest(
            event_body(event_id="e1", occurred_at="2027-01-01T12:00:00+02:00", data={"v": 1})
        )
        # Same instant as e1 (10:00Z); larger event_id wins the tie.
        self.ingest(
            event_body(event_id="e2", occurred_at="2027-01-01T10:00:00Z", data={"v": 2})
        )
        self.assertEqual(self.ledger.get_projection("t1", "crm", "acct-1")["data"], {"v": 2})

    def test_delete_produces_tombstone(self):
        self.ingest(event_body(event_id="e1", occurred_at="2027-01-01T10:00:00Z"))
        self.ingest(
            event_body(
                event_id="e2",
                event_type="delete",
                occurred_at="2027-01-01T11:00:00Z",
                data={},
            )
        )
        self.assertIsNone(self.ledger.get_projection("t1", "crm", "acct-1"))
        # A late upsert does not resurrect the entity.
        self.ingest(
            event_body(event_id="e0", occurred_at="2027-01-01T09:00:00Z", data={"v": 0})
        )
        self.assertIsNone(self.ledger.get_projection("t1", "crm", "acct-1"))

    def test_tenant_and_source_isolation(self):
        self.ingest(event_body(data={"who": "t1-crm"}))
        other_source = event_body(source="billing", data={"who": "t1-billing"})
        self.ingest(other_source)
        t2 = event_body(tenant_id="t2", data={"who": "t2"})
        self.ledger.ingest(t2, sign(t2, secret="other-secret"))
        self.assertEqual(
            self.ledger.get_projection("t1", "crm", "acct-1")["data"], {"who": "t1-crm"}
        )
        self.assertEqual(
            self.ledger.get_projection("t1", "billing", "acct-1")["data"],
            {"who": "t1-billing"},
        )
        self.assertEqual(
            self.ledger.get_projection("t2", "crm", "acct-1")["data"], {"who": "t2"}
        )


class InitializeTests(LedgerTestCase):
    def test_initialize_is_repeatable_and_preserves_data(self):
        body = event_body()
        self.ledger.ingest(body, sign(body))
        self.ledger.initialize()
        self.assertEqual(len(self.ledger.get_events("t1")), 1)
        self.assertIsNotNone(self.ledger.get_projection("t1", "crm", "acct-1"))


if __name__ == "__main__":
    unittest.main()
