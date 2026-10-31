"""Tests for epoch publication (part 1).

Keys are generated on the fly in each test and never written to
disk: the pilot private key is created by the operator on their own
machine, never here. Fake batch/epoch stamps below are test
fixtures only — they are not TSA tokens (the TSA client is a later
step, after the NUCA root fingerprint check and the legal question).

Run from the friday/ staging root:
    python3 -m unittest tests.test_publication -v
"""

import base64
import hashlib
import unittest
import uuid
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from friday.anchor import HmacSigner, _signed_payload
from friday.publication import (
    EPOCH_DOMAIN,
    FORMAT_VERSION,
    ChainVerification,
    KeyHistory,
    PublicationError,
    RecordVerification,
    build_epoch_publication,
    canonical_client_bytes,
    canonical_record_bytes,
    epoch_root,
    utc_today_epoch,
    verify_client_copy,
    verify_epoch_chain,
    verify_public_record,
)

# Fixture only: not a TSA token. Part 1 has no TSA client.
_FAKE_STAMP = base64.b64encode(b"fake-tsa-token").decode()


class _Signer:
    """Ephemeral Ed25519 signer, generated on the fly."""

    def __init__(self, key_id):
        self._priv = Ed25519PrivateKey.generate()
        self._kid = key_id

    def key_id(self):
        return self._kid

    def public_key_bytes(self):
        return self._priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, payload):
        return self._priv.sign(payload)


def _batch(batch_id, label, leaves, stamp=None):
    return {"batch_id": batch_id,
            "root": hashlib.sha256(label.encode()).hexdigest(),
            "leaf_count": leaves, "stamp": stamp}


def _batches():
    return [_batch("b1", "batch-1", 5, _FAKE_STAMP),
            _batch("b2", "batch-2", 3, None)]


def _pub(signer=None, epoch="2026-10-31", prev=None, batches=None,
         stamp=None, journal=None):
    signer = signer or _Signer("anchor-2026-01")
    journal = journal or str(uuid.uuid4())
    batches = batches if batches is not None else _batches()
    return build_epoch_publication(journal, epoch, batches, prev,
                                   signer, epoch_stamp=stamp)


def _history(signer, **kwargs):
    history = KeyHistory()
    kwargs.setdefault("first_epoch", "2026-01-01")
    history.add(signer.key_id(), signer.public_key_bytes().hex(),
                **kwargs)
    return history


def _verifies(pub_hex, payload, sig_hex):
    try:
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(pub_hex)).verify(bytes.fromhex(sig_hex),
                                           payload)
        return True
    except InvalidSignature:
        return False


def _flip(hexstr):
    return ("0" if hexstr[0] != "0" else "1") + hexstr[1:]


class TestFormat(unittest.TestCase):
    def test_public_record_has_no_volume(self):
        public, client = _pub()
        self.assertNotIn("leaf_count", public)
        self.assertNotIn("batch_count", public)
        self.assertNotIn("batches", public)
        self.assertEqual(client["leaf_count"], 8)
        self.assertEqual(client["batch_count"], 2)
        self.assertEqual(len(client["batches"]), 2)

    def test_smuggled_volume_rejected(self):
        public, _client = _pub()
        public["leaf_count"] = 8
        signer = _Signer("anchor-2026-01")
        with self.assertRaises(PublicationError):
            verify_public_record(public, _history(signer))

    def test_missing_signature_rejected(self):
        public, _client = _pub()
        del public["signature"]
        signer = _Signer("anchor-2026-01")
        with self.assertRaises(PublicationError):
            verify_public_record(public, _history(signer))

    def test_canonical_serialization(self):
        self.assertEqual(
            canonical_record_bytes({"b": 1, "a": 2}),
            EPOCH_DOMAIN + b'{"a":2,"b":1}')
        first = canonical_record_bytes({"x": "v", "y": [1, 2]})
        second = canonical_record_bytes({"y": [1, 2], "x": "v"})
        self.assertEqual(first, second)

    def test_signature_deterministic(self):
        signer = _Signer("anchor-2026-01")
        payload = canonical_record_bytes({"a": 1})
        self.assertEqual(signer.sign(payload), signer.sign(payload))

    def test_epoch_validation(self):
        for bad in ("2026-13-01", "2026-1-1", "2026-02-30", "",
                    20261031, None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    _pub(epoch=bad)

    def test_utc_today_epoch(self):
        self.assertEqual(
            utc_today_epoch(),
            datetime.now(timezone.utc).strftime("%Y-%m-%d"))

    def test_hmac_signer_refused(self):
        with self.assertRaises(ValueError):
            _pub(signer=HmacSigner(b"secret"))

    def test_empty_batches_refused(self):
        with self.assertRaises(ValueError):
            _pub(batches=[])


class TestEpochRoot(unittest.TestCase):
    def test_single_batch_root_is_batch_root(self):
        batches = [_batch("b1", "batch-1", 5)]
        self.assertEqual(epoch_root(batches), batches[0]["root"])

    def test_two_batches(self):
        left = bytes.fromhex(_batch("b1", "batch-1", 5)["root"])
        right = bytes.fromhex(_batch("b2", "batch-2", 3)["root"])
        expect = hashlib.sha256(left + right).hexdigest()
        self.assertEqual(
            epoch_root([_batch("b1", "batch-1", 5),
                        _batch("b2", "batch-2", 3)]), expect)

    def test_three_batches_duplicate_last(self):
        b1 = bytes.fromhex(_batch("b1", "batch-1", 5)["root"])
        b2 = bytes.fromhex(_batch("b2", "batch-2", 3)["root"])
        b3 = bytes.fromhex(_batch("b3", "batch-3", 7)["root"])
        level = hashlib.sha256(b1 + b2).digest()
        level3 = hashlib.sha256(b3 + b3).digest()
        expect = hashlib.sha256(level + level3).hexdigest()
        self.assertEqual(
            epoch_root([_batch("b1", "batch-1", 5),
                        _batch("b2", "batch-2", 3),
                        _batch("b3", "batch-3", 7)]), expect)

    def test_empty_root_refused(self):
        with self.assertRaises(ValueError):
            epoch_root([])


class TestSignature(unittest.TestCase):
    def test_domain_separation(self):
        signer = _Signer("anchor-2026-01")
        public, _client = _pub(signer=signer)
        pub_hex = signer.public_key_bytes().hex()
        epoch_fields = {k: public[k] for k in
                        ("journal_id", "epoch", "root", "prev_epoch_root",
                         "key_id", "public_key", "format_version",
                         "epoch_stamp_digest")}
        epoch_payload = canonical_record_bytes(epoch_fields)
        # Epoch signature must not verify as a batch anchor.
        self.assertFalse(_verifies(
            pub_hex,
            _signed_payload(bytes.fromhex(public["root"]), 8),
            public["signature"]))
        # Batch signature must not verify as an epoch record.
        batch_sig = signer.sign(
            _signed_payload(bytes.fromhex(public["root"]), 8)).hex()
        self.assertFalse(_verifies(pub_hex, epoch_payload, batch_sig))
        # And the epoch signature does verify against its own payload.
        self.assertTrue(_verifies(pub_hex, epoch_payload,
                                  public["signature"]))

    def test_any_field_edit_breaks_signature(self):
        signer = _Signer("anchor-2026-01")
        other = _Signer("anchor-2026-02")
        public, _client = _pub(signer=signer, stamp=_FAKE_STAMP)
        history = _history(signer)
        edits = {
            "journal_id": str(uuid.uuid4()),
            "epoch": "2026-11-01",
            "root": _flip(public["root"]),
            "prev_epoch_root": "00" * 32,
            "key_id": "anchor-2026-99",
            "public_key": other.public_key_bytes().hex(),
            "format_version": 2,
            "epoch_stamp_digest": _flip(public["epoch_stamp_digest"]),
        }
        for field, value in edits.items():
            with self.subTest(field=field):
                tampered = dict(public)
                tampered[field] = value
                with self.assertRaises(PublicationError):
                    verify_public_record(tampered, history)

    def test_stamp_digest_invariant(self):
        signer = _Signer("anchor-2026-01")
        public, _client = _pub(signer=signer, stamp=_FAKE_STAMP)
        self.assertEqual(
            public["epoch_stamp_digest"],
            hashlib.sha256(base64.b64decode(_FAKE_STAMP)).hexdigest())
        plain, _client = _pub(signer=signer)
        self.assertIsNone(plain["epoch_stamp"])
        self.assertIsNone(plain["epoch_stamp_digest"])
        history = _history(signer)
        result = verify_public_record(public, history)
        self.assertTrue(result.signature_ok)
        self.assertEqual(result.stamp, "present_unverified")
        tampered = dict(public)
        tampered["epoch_stamp"] = base64.b64encode(b"other").decode()
        with self.assertRaises(PublicationError):
            verify_public_record(tampered, history)


    def test_stamp_status_not_proof(self):
        """Probe 5: a garbage stamp with a matching digest must not
        'verify' as a proven date. The verifier returns a structure:
        signature ok, stamp present_unverified — never a bare True,
        never 'verified'."""
        signer = _Signer("anchor-2026-01")
        garbage = base64.b64encode(b"garbage-not-a-tsa-token").decode()
        public, _client = _pub(signer=signer, stamp=garbage)
        result = verify_public_record(public, _history(signer))
        self.assertIsInstance(result, RecordVerification)
        self.assertTrue(result.signature_ok)
        self.assertEqual(result.stamp, "present_unverified")
        self.assertNotEqual(result.stamp, "verified")
        plain, _client = _pub(signer=signer)
        self.assertEqual(
            verify_public_record(plain, _history(signer)).stamp,
            "absent")
class TestClientCopy(unittest.TestCase):
    def test_stamp_pending_honest(self):
        signer = _Signer("anchor-2026-01")
        _public, client = _pub(signer=signer)
        self.assertEqual(client["batches"][0]["status"], "stamped")
        self.assertEqual(client["batches"][0]["stamp"], _FAKE_STAMP)
        self.assertEqual(client["batches"][1]["status"], "stamp_pending")
        self.assertIsNone(client["batches"][1]["stamp"])
        result = verify_client_copy(client, _history(signer))
        self.assertTrue(result.signature_ok)
        self.assertEqual(result.stamp, "absent")

    def test_client_signature_binds_volume(self):
        """Probe 1: edit a batch leaf_count and recompute the sum —
        the old verifier passed this. The copy signature must catch
        it, because the public signature never bound the counts."""
        signer = _Signer("anchor-2026-01")
        _public, client = _pub(signer=signer)
        history = _history(signer)
        self.assertTrue(
            verify_client_copy(client, history).signature_ok)
        tampered = dict(client)
        tampered["batches"] = [dict(entry)
                               for entry in client["batches"]]
        tampered["batches"][0]["leaf_count"] = 5000
        tampered["leaf_count"] = sum(
            entry["leaf_count"] for entry in tampered["batches"])
        with self.assertRaisesRegex(
                PublicationError, "client copy signature"):
            verify_client_copy(tampered, history)

    def test_client_signature_transplant_rejected(self):
        signer = _Signer("anchor-2026-01")
        _public, client = _pub(signer=signer)
        _public2, client2 = _pub(signer=signer)
        history = _history(signer)
        transplant = dict(client)
        transplant["client_signature"] = client2["client_signature"]
        with self.assertRaisesRegex(
                PublicationError, "client copy signature"):
            verify_client_copy(transplant, history)
        tampered = dict(client)
        tampered["client_signature"] = _flip(client["client_signature"])
        with self.assertRaisesRegex(
                PublicationError, "client copy signature"):
            verify_client_copy(tampered, history)

    def test_false_stamp_claims_rejected(self):
        signer = _Signer("anchor-2026-01")
        _public, client = _pub(signer=signer)
        history = _history(signer)
        stamped_no_bytes = dict(client)
        stamped_no_bytes["batches"] = [dict(entry)
                                       for entry in client["batches"]]
        stamped_no_bytes["batches"][0]["stamp"] = None
        with self.assertRaises(PublicationError):
            verify_client_copy(stamped_no_bytes, history)
        pending_with_bytes = dict(client)
        pending_with_bytes["batches"] = [dict(entry)
                                         for entry in client["batches"]]
        pending_with_bytes["batches"][1]["stamp"] = _FAKE_STAMP
        with self.assertRaises(PublicationError):
            verify_client_copy(pending_with_bytes, history)
        missing_status = dict(client)
        missing_status["batches"] = [dict(entry)
                                     for entry in client["batches"]]
        del missing_status["batches"][0]["status"]
        with self.assertRaises(PublicationError):
            verify_client_copy(missing_status, history)

    def test_counts_and_root_recomputed(self):
        signer = _Signer("anchor-2026-01")
        _public, client = _pub(signer=signer)
        history = _history(signer)
        for field, value in (("leaf_count", 9), ("batch_count", 3)):
            with self.subTest(field=field):
                tampered = dict(client)
                tampered[field] = value
                with self.assertRaises(PublicationError):
                    verify_client_copy(tampered, history)
        tampered = dict(client)
        tampered["batches"] = [dict(entry)
                               for entry in client["batches"]]
        tampered["batches"][0]["leaf_count"] = 6
        with self.assertRaises(PublicationError):
            verify_client_copy(tampered, history)
        tampered = dict(client)
        tampered["batches"] = [dict(entry)
                               for entry in client["batches"]]
        tampered["batches"][0]["root"] = _flip(client["batches"][0]["root"])
        with self.assertRaises(PublicationError):
            verify_client_copy(tampered, history)


    def test_duplicate_batch_roots_rejected(self):
        """Probe 2: [a,b,c] and [a,b,c,c] share a root under DIC
        duplication. A repeated batch root must fail in build and
        in the verifier — even for a copy signed over the forgery."""
        with self.assertRaisesRegex(ValueError, "duplicate batch root"):
            _pub(batches=[_batch("b1", "batch-1", 5),
                          _batch("b2", "batch-2", 3),
                          _batch("b3", "batch-1", 5)])
        with self.assertRaisesRegex(ValueError, "duplicate batch root"):
            epoch_root([_batch("b1", "batch-1", 5),
                        _batch("b2", "batch-1", 5)])
        signer = _Signer("anchor-2026-01")
        _public, client = _pub(signer=signer)
        forged = dict(client)
        forged["batches"] = [dict(entry)
                             for entry in client["batches"]]
        forged["batches"].append(dict(client["batches"][0]))
        forged["batch_count"] = len(forged["batches"])
        forged["leaf_count"] = sum(
            entry["leaf_count"] for entry in forged["batches"])
        # Re-sign the forgery so only the duplicate rule can catch it.
        forged["client_signature"] = signer.sign(
            canonical_client_bytes({
                "public_signature": forged["signature"],
                "leaf_count": forged["leaf_count"],
                "batch_count": forged["batch_count"],
                "batches": forged["batches"],
            })).hex()
        with self.assertRaisesRegex(PublicationError, "duplicate"):
            verify_client_copy(forged, _history(signer))
class TestKeyHistory(unittest.TestCase):
    def test_substituted_public_key_rejected(self):
        signer = _Signer("anchor-2026-01")
        attacker = _Signer("anchor-2026-01")  # same key_id, own key
        history = _history(signer)
        forged, _client = _pub(signer=attacker)
        # Negative control: the forgery verifies against the
        # attacker's own key — only the history catches it.
        forged_fields = {k: forged[k] for k in
                         ("journal_id", "epoch", "root",
                          "prev_epoch_root", "key_id", "public_key",
                          "format_version", "epoch_stamp_digest")}
        self.assertTrue(_verifies(
            attacker.public_key_bytes().hex(),
            canonical_record_bytes(forged_fields), forged["signature"]))
        with self.assertRaises(PublicationError):
            verify_public_record(forged, history)

    def test_unknown_key_id_rejected(self):
        signer = _Signer("anchor-2026-01")
        public, _client = _pub(signer=signer)
        history = KeyHistory()
        with self.assertRaises(PublicationError):
            verify_public_record(public, history)

    def test_compromised_key_window(self):
        signer = _Signer("anchor-2026-01")
        history = KeyHistory()
        history.add(signer.key_id(), signer.public_key_bytes().hex(),
                    status="compromised", first_epoch="2026-01-01",
                    compromise_epoch="2026-10-15")
        before, _client = _pub(signer=signer, epoch="2026-10-10")
        self.assertTrue(
            verify_public_record(before, history).signature_ok)
        after, _client = _pub(signer=signer, epoch="2026-10-20")
        with self.assertRaises(PublicationError):
            verify_public_record(after, history)

    def test_key_history_windows_required(self):
        """Probe 3: a compromised key without compromise_epoch, or a
        retired key without last_epoch, used to accept every epoch.
        add() must refuse such entries, and check() must fail closed
        even if one slips through."""
        signer = _Signer("anchor-2026-01")
        with self.assertRaisesRegex(ValueError, "compromise_epoch"):
            KeyHistory().add(signer.key_id(),
                             signer.public_key_bytes().hex(),
                             status="compromised",
                             first_epoch="2026-01-01")
        with self.assertRaisesRegex(ValueError, "last_epoch"):
            KeyHistory().add(signer.key_id(),
                             signer.public_key_bytes().hex(),
                             status="retired",
                             first_epoch="2026-01-01")
        for status in ("compromised", "retired"):
            with self.subTest(status=status):
                history = KeyHistory()
                # Bypass add() to prove check() itself is fail-closed.
                history._entries[signer.key_id()] = {
                    "public_key": signer.public_key_bytes().hex(),
                    "status": status,
                    "first_epoch": "2026-01-01",
                    "last_epoch": None,
                    "compromise_epoch": None,
                    "successor": None,
                }
                public, _client = _pub(signer=signer)
                with self.assertRaises(PublicationError):
                    verify_public_record(public, history)


class TestChain(unittest.TestCase):
    def _chain(self):
        signer = _Signer("anchor-2026-01")
        journal = str(uuid.uuid4())
        genesis, _c = _pub(signer=signer, epoch="2026-10-30",
                           journal=journal,
                           batches=[_batch("b1", "batch-1", 5)])
        second, _c = _pub(signer=signer, epoch="2026-10-31",
                          prev=genesis["root"], journal=journal,
                          batches=[_batch("b2", "batch-2", 3)])
        return signer, genesis, second

    def test_chain_verifies(self):
        signer, genesis, second = self._chain()
        result = verify_epoch_chain([genesis, second], _history(signer))
        self.assertTrue(result.chain_ok)
        self.assertEqual(len(result.records), 2)
        self.assertEqual(result.records[0].stamp, "absent")
        self.assertTrue(result.records[1].signature_ok)

    def test_chain_break_detected(self):
        signer, genesis, _second = self._chain()
        # A second record validly signed with the WRONG prev: its own
        # signature verifies, so only the linkage check catches it.
        broken, _c = _pub(signer=signer, epoch="2026-10-31",
                          prev="00" * 32, journal=genesis["journal_id"],
                          batches=[_batch("b2", "batch-2", 3)])
        history = _history(signer)
        result = verify_public_record(broken, history)
        self.assertTrue(result.signature_ok)
        with self.assertRaises(PublicationError):
            verify_epoch_chain([genesis, broken], history)

    def test_chain_epochs_strictly_increasing(self):
        """Probe 4: two records for one day, and epochs out of
        order, used to pass when linkage was intact."""
        signer, genesis, _second = self._chain()
        history = _history(signer)
        same_day, _c = _pub(signer=signer, epoch="2026-10-30",
                            prev=genesis["root"],
                            journal=genesis["journal_id"],
                            batches=[_batch("b2", "batch-2", 3)])
        with self.assertRaisesRegex(PublicationError, "strictly"):
            verify_epoch_chain([genesis, same_day], history)
        later, _c = _pub(signer=signer, epoch="2026-10-31",
                         journal=genesis["journal_id"],
                         batches=[_batch("b1", "batch-1", 5)])
        earlier, _c = _pub(signer=signer, epoch="2026-10-30",
                           prev=later["root"],
                           journal=genesis["journal_id"],
                           batches=[_batch("b2", "batch-2", 3)])
        with self.assertRaisesRegex(PublicationError, "strictly"):
            verify_epoch_chain([later, earlier], history)

    def test_non_genesis_first_rejected(self):
        signer, genesis, second = self._chain()
        history = _history(signer)
        with self.assertRaises(PublicationError):
            verify_epoch_chain([second], history, expect_genesis=True)
        result = verify_epoch_chain([second], history,
                                    expect_genesis=False)
        self.assertTrue(result.chain_ok)

    def test_mixed_journal_rejected(self):
        signer, genesis, second = self._chain()
        other, _c = _pub(signer=signer, epoch="2026-10-31",
                         prev=genesis["root"],
                         batches=[_batch("b2", "batch-2", 3)])
        with self.assertRaises(PublicationError):
            verify_epoch_chain([genesis, other], _history(signer))


if __name__ == "__main__":
    unittest.main()
