"""Step 2: durable journal file, pilot-mode Ed25519, key custody.

After the text fixes: journal + Ed25519 before any
pilot. The RAM journal becomes a file a pilot can show after the
process dies; pilot mode signs with Ed25519 only (the demo HMAC keys
are public in this repo and prove nothing to a third party).
"""

import json
import os
import stat
import tempfile
import unittest

from friday import (AnchorService, Ed25519Signer, HmacSigner, NullTsa)
from friday.persistence import (CorruptJournalError, JournalStore,
                                PersistentJournal)


def _pj(tmp):
    store = JournalStore(os.path.join(tmp, "journal.jsonl"))
    return store, PersistentJournal(store)


class TestPersistenceRoundTrip(unittest.TestCase):
    def test_round_trip_and_idempotency(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, pj = _pj(tmp)
            pj.append("decision", {"task": "a"}, idempotency_key="k1")
            pj.append("decision", {"task": "b"})
            pj.append("decision", {"task": "a"}, idempotency_key="k1")
            self.assertEqual(len(pj), 2)
            pj2, anchors = PersistentJournal.open(store)
            self.assertEqual(anchors, {})
            ok, bad = pj2.verify()
            self.assertTrue(ok)
            self.assertIsNone(bad)
            self.assertEqual([e["payload"] for e in pj2.entries()],
                             [{"task": "a"}, {"task": "b"}])
            # Idempotency survives reload: replay writes no new line.
            with open(store.path, encoding="utf-8") as fh:
                before = fh.read()
            pj2.append("decision", {"task": "a"}, idempotency_key="k1")
            self.assertEqual(len(pj2), 2)
            with open(store.path, encoding="utf-8") as fh:
                self.assertEqual(before, fh.read())

    def test_continues_chain_after_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, pj = _pj(tmp)
            pj.append("decision", {"task": "a"})
            pj2, _ = PersistentJournal.open(store)
            pj2.append("decision", {"task": "b"})
            ok, bad = pj2.verify()
            self.assertTrue(ok)
            self.assertEqual([e["index"] for e in pj2.entries()], [0, 1])

    def test_batch_marks_are_separate_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, pj = _pj(tmp)
            pj.append("decision", {"task": "a"})
            pj.append("decision", {"task": "b"})
            pj.mark_batched([e["event_id"] for e in pj.entries()],
                            "batch-1")
            lines = open(store.path, encoding="utf-8").read().splitlines()
            kinds = [json.loads(line).get("type") for line in lines[1:]]
            self.assertEqual(kinds, ["entry", "entry",
                                     "batch_mark", "batch_mark"])
            # Entry lines still carry batch_id None: marks never
            # rewrite them, or the file would stop being append-only.
            entry_lines = [json.loads(line) for line in lines[1:]
                           if json.loads(line).get("type") == "entry"]
            self.assertTrue(all(e["entry"]["batch_id"] is None
                                for e in entry_lines))
            pj2, _ = PersistentJournal.open(store)
            self.assertTrue(all(e["batch_id"] == "batch-1"
                                for e in pj2.entries()))
            self.assertEqual(pj2.unbatched(), [])

    def test_new_journal_file_is_owner_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "journal.jsonl")
            JournalStore(path)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            # An existing file with loose mode is tightened on open:
            # the file holds raw tasks and answers.
            os.chmod(path, 0o644)
            JournalStore(path)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_broken_chain_on_load_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, pj = _pj(tmp)
            pj.append("decision", {"task": "a"})
            pj.append("decision", {"task": "b"})
            text = open(store.path, encoding="utf-8").read()
            forged = text.replace('"task":"b"', '"task":"FORGED"')
            self.assertNotEqual(text, forged)
            open(store.path, "w", encoding="utf-8").write(forged)
            with self.assertRaises(CorruptJournalError):
                PersistentJournal.open(JournalStore(store.path))

    def test_bad_header_version_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "journal.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('{"format": "friday-journal", "version": 99}\n')
            with self.assertRaises(CorruptJournalError):
                JournalStore(path)

    def test_corrupt_line_and_unknown_type_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, pj = _pj(tmp)
            pj.append("decision", {"task": "a"})
            with open(store.path, "a", encoding="utf-8") as fh:
                fh.write("{not json\n")
            with self.assertRaises(CorruptJournalError):
                store.load()
            store2 = JournalStore(os.path.join(tmp, "j2.jsonl"))
            pj2 = PersistentJournal(store2)
            pj2.append("decision", {"task": "a"})
            with open(store2.path, "a", encoding="utf-8") as fh:
                fh.write('{"type": "mystery"}\n')
            with self.assertRaises(CorruptJournalError):
                store2.load()

    def test_batch_mark_for_unknown_event_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, pj = _pj(tmp)
            pj.append("decision", {"task": "a"})
            with open(store.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"type": "batch_mark",
                                     "event_id": "nope",
                                     "batch_id": "b1"}) + "\n")
            with self.assertRaises(CorruptJournalError):
                store.load()


class TestPilotMode(unittest.TestCase):
    def test_demo_hmac_rejected_in_pilot_mode(self):
        for secret in ("friday-demo", "demo-secret"):
            with self.assertRaises(ValueError):
                AnchorService(HmacSigner(secret), NullTsa(),
                              pilot_mode=True)

    def test_pilot_mode_anchor_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, pj = _pj(tmp)
            pj.append("decision", {"task": "a"})
            pj.append("decision", {"task": "b"})
            signer = Ed25519Signer()
            service = AnchorService(signer, NullTsa(), pilot_mode=True,
                                    on_anchor=store.append_anchor)
            record = service.anchor_pending(pj, force=True)
            self.assertIsNotNone(record)
            self.assertEqual(record.leaf_count, 2)
            pj2, anchors = PersistentJournal.open(store)
            self.assertEqual(set(anchors), {record.batch_id})
            reloaded = anchors[record.batch_id]
            self.assertEqual(reloaded.root, record.root)
            self.assertEqual(reloaded.key_id, signer.key_id())
            # Proof rows are recomputed from the journal, not restored.
            self.assertEqual(reloaded.proofs, {})
            # Verify with a public-key-only signer (the verifier's shape).
            verifier = Ed25519Signer.from_public_bytes(
                signer.public_key_bytes(), key_id=signer.key_id())
            with self.assertRaises(RuntimeError):
                verifier.sign(b"x")
            checking = AnchorService(verifier, NullTsa())
            self.assertTrue(checking.verify_anchor_signature(reloaded))
            # A tampered leaf count fails even with the same root
            # (the DIC duplication collision binding).
            reloaded.leaf_count = 99
            self.assertFalse(checking.verify_anchor_signature(reloaded))

    def test_failed_anchor_callback_leaves_batch_retryable(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, pj = _pj(tmp)
            pj.append("decision", {"task": "a"})

            def failing(record):
                raise IOError("disk full (simulated)")

            service = AnchorService(Ed25519Signer(), NullTsa(),
                                    on_anchor=failing)
            with self.assertRaises(IOError):
                service.anchor_pending(pj, force=True)
            self.assertEqual(len(pj.unbatched()), 1)  # not marked
            retry = AnchorService(Ed25519Signer(), NullTsa(),
                                  on_anchor=store.append_anchor)
            record = retry.anchor_pending(pj, force=True)
            self.assertIsNotNone(record)
            self.assertEqual(pj.unbatched(), [])

    def test_key_save_load_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            signer = Ed25519Signer()
            priv = os.path.join(tmp, "pilot.pem")
            pub = os.path.join(tmp, "pilot.pub")
            signer.save_private_key(priv)
            signer.save_public_key(pub)
            self.assertEqual(stat.S_IMODE(os.stat(priv).st_mode), 0o600)
            restored = Ed25519Signer.from_private_key_file(priv)
            self.assertEqual(restored.public_key_bytes(),
                             signer.public_key_bytes())
            sig = restored.sign(b"evidence")
            self.assertTrue(signer.verify(b"evidence", sig,
                                          signer.public_key_bytes()))
            with open(pub, encoding="utf-8") as fh:
                pub_lines = fh.read().splitlines()
            self.assertEqual(pub_lines[0], signer.key_id())
            self.assertEqual(pub_lines[1],
                             signer.public_key_bytes().hex())


if __name__ == "__main__":
    unittest.main()
