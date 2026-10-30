"""Tests for the F.R.I.D.A.Y. engine. Standard library only.

Run from the friday/ staging root:
    python3 -m unittest tests.test_friday -v
"""

import unittest

from friday import (EscalationGate, Journal, Memory, Router, Skill,
                    SkillRegistry, compress, fidelity_check)
from friday.router import cache_key
from friday.anchor import AnchorService, HmacSigner, NullTsa
from friday.dic_merkle import (MerkleBatch, compute_leaf_hash,
                               verify_inclusion_proof)
from friday.events import FrEvent
from friday.skill_trace import collect_traces
from friday.compress import compress as compress_fn
from friday.memory import SHAREABLE, SENSITIVE, classify_fragment
from friday.skills import builtin_skills


def _always_ok(task):
    return "done", 0.9


def _always_unsure(task):
    return "guess", 0.1


class TestJournal(unittest.TestCase):
    def test_chain_verifies(self):
        journal = Journal()
        journal.append("a", {"x": 1})
        journal.append("b", {"x": 2})
        ok, bad = journal.verify()
        self.assertTrue(ok)
        self.assertIsNone(bad)

    def test_tamper_detected(self):
        journal = Journal()
        journal.append("a", {"x": 1})
        journal.append("b", {"x": 2})
        exported = journal.entries()
        exported[0]["payload"] = {"x": 99}
        ok, bad = journal.verify_external(exported)
        self.assertFalse(ok)
        self.assertEqual(bad, 0)

    def test_head_changes(self):
        journal = Journal()
        self.assertIsNone(journal.head())
        journal.append("a", {})
        head1 = journal.head()
        journal.append("b", {})
        self.assertNotEqual(head1, journal.head())


class TestEscalationGate(unittest.TestCase):
    def test_threshold_routing(self):
        gate = EscalationGate(threshold=0.8)
        self.assertEqual(gate.decide(0.9), "local")
        self.assertEqual(gate.decide(0.1), "escalate")
        self.assertEqual(gate.decide(0.8), "local")

    def test_two_sided_errors(self):
        gate = EscalationGate(threshold=0.8)
        gate.decide(0.9)
        gate.decide(0.1)
        # was_correct describes the LOCAL answer (Grok audit): a local
        # miss answered locally, a wasted call (local right, went up),
        # and a justified call (local wrong, went up).
        gate.record_outcome(was_escalated=False, was_correct=False)
        gate.record_outcome(was_escalated=True, was_correct=True)
        gate.record_outcome(was_escalated=True, was_correct=False)
        report = gate.report()
        self.assertEqual(report["missed_escalations"], 1)
        self.assertEqual(report["false_escalations"], 1)
        self.assertEqual(report["justified_escalations"], 1)


class TestGates(unittest.TestCase):
    def test_passing_skill(self):
        skill = Skill("s", "1", _always_ok, [("t", lambda: True)])
        registry = SkillRegistry()
        registry.register(skill)
        found, report = registry.get_gated("s")
        self.assertIsNotNone(found)
        self.assertTrue(report["passed"])

    def test_failing_skill_blocks(self):
        skill = Skill("s", "1", _always_ok, [("t", lambda: False)])
        registry = SkillRegistry()
        registry.register(skill)
        found, report = registry.get_gated("s")
        self.assertIsNone(found)
        self.assertFalse(report["passed"])

    def test_missing_skill_blocks(self):
        registry = SkillRegistry()
        found, report = registry.get_gated("nope")
        self.assertIsNone(found)


class TestMemory(unittest.TestCase):
    def test_expiry(self):
        now = [1000.0]
        mem = Memory(clock=lambda: now[0])
        mem.put("k", "v", "s", "1", ttl_s=10)
        self.assertEqual(mem.get("k"), "v")
        now[0] = 1011.0
        self.assertIsNone(mem.get("k"))

    def test_classify(self):
        self.assertEqual(classify_fragment("call boss@example.com"), SENSITIVE)
        self.assertEqual(classify_fragment("the sky is blue"), SHAREABLE)


class TestCompress(unittest.TestCase):
    def test_keeps_numbers_and_constraints(self):
        out = compress("budget is 42 coins\nmust never exceed it\njust chat")
        self.assertIn("42", out)
        self.assertIn("must never exceed it", out)
        self.assertNotIn("just chat", out)

    def test_fidelity(self):
        def decide(context, case):
            return "42" in context
        cases = [("budget is 42 coins", None), ("no numbers here", None)]
        rate, bad = fidelity_check(decide, cases, compress_fn)
        self.assertEqual(rate, 1.0)
        self.assertEqual(bad, [])


class TestRouter(unittest.TestCase):
    def _router(self, threshold=0.8):
        memory = Memory()
        journal = Journal()
        registry = SkillRegistry()
        for skill in builtin_skills(memory, registry):
            registry.register(skill)
        gate = EscalationGate(threshold=threshold)
        return Router(registry, memory, journal, gate), memory, journal

    def test_reuse(self):
        router, memory, _ = self._router()
        # Merge: the cache key is skill:version:sha256(content), not
        # the raw task text; seeding by raw text no longer hits.
        memory.put(cache_key("retrieve", "0.1.0", "capital of France"),
                   "Paris", "retrieve", "0.1.0", 3600)
        kind, payload = router.handle("capital of France", "retrieve")
        self.assertEqual((kind, payload), ("reuse", "Paris"))

    def test_local_answer(self):
        router, _, _ = self._router()
        kind, payload = router.handle("summarise::limit 7 days, chatter",
                                      "summarise")
        self.assertEqual(kind, "local")
        self.assertIn("7", payload)

    def test_escalation_redacts(self):
        router, memory, journal = self._router()
        memory.put("admin contact", "boss@example.com", "retrieve",
                   "0.1.0", 3600)
        kind, payload = router.handle("find admin contact", "retrieve")
        self.assertEqual(kind, "escalate")
        self.assertEqual(payload.redacted_count, 1)
        self.assertNotIn("boss@example.com", payload.compressed_context)
        ok, _ = journal.verify()
        self.assertTrue(ok)

    def test_gate_failure_escalates(self):
        memory = Memory()
        journal = Journal()
        registry = SkillRegistry()
        broken = Skill("broken", "1", _always_ok, [("t", lambda: False)])
        registry.register(broken)
        router = Router(registry, memory, journal, EscalationGate())
        kind, _ = router.handle("anything", "broken")
        self.assertEqual(kind, "escalate")


class TestJournalIdempotency(unittest.TestCase):
    def test_same_key_appends_once(self):
        journal = Journal()
        first = journal.append("a", {"x": 1}, idempotency_key="k1")
        second = journal.append("a", {"x": 1}, idempotency_key="k1")
        self.assertEqual(len(journal), 1)
        self.assertEqual(first["event_id"], second["event_id"])

    def test_mark_batched_keeps_verification(self):
        journal = Journal()
        entry = journal.append("a", {"x": 1})
        journal.mark_batched([entry["event_id"]], "batch-1")
        ok, _ = journal.verify()
        self.assertTrue(ok)
        self.assertEqual(journal.entries()[0]["batch_id"], "batch-1")


class TestDicMerkle(unittest.TestCase):
    def test_close_proof_roundtrip(self):
        leaves = [bytes([i]) * 32 for i in range(5)]
        batch = MerkleBatch(leaves=leaves)
        root = batch.close()
        for idx, leaf in enumerate(leaves):
            proof = batch.proof_for(idx)
            self.assertTrue(verify_inclusion_proof(leaf, proof, root))

    def test_tampered_leaf_fails_proof(self):
        leaves = [bytes([i]) * 32 for i in range(4)]
        batch = MerkleBatch(leaves=leaves)
        root = batch.close()
        proof = batch.proof_for(0)
        self.assertFalse(verify_inclusion_proof(bytes([9]) * 32, proof, root))

    def test_decision_leaf_formula_is_stable(self):
        h1 = compute_leaf_hash(decision_id="d1", metric_name="m",
                               value=42, timestamp_iso="2026-01-01T00:00:00Z",
                               evidence_refs=["e2", "e1", "e1"],
                               idempotency_key="k")
        h2 = compute_leaf_hash(decision_id="d1", metric_name="m",
                               value=42, timestamp_iso="2026-01-01T00:00:00Z",
                               evidence_refs=["e1", "e2"],
                               idempotency_key="k")
        self.assertEqual(h1, h2)


class TestEvents(unittest.TestCase):
    def test_envelope_roundtrip(self):
        event = FrEvent("local_answer", {"task": "t"},
                        runtime_context={"model": "local"})
        restored = FrEvent.from_dict(event.to_dict())
        self.assertEqual(restored.event_type, "local_answer")
        self.assertEqual(restored.runtime_context, {"model": "local"})
        self.assertEqual(restored.event_id, event.event_id)


class TestAnchor(unittest.TestCase):
    def _journal_with(self, n):
        journal = Journal()
        for i in range(n):
            journal.append("local_answer", {"task": "t%d" % i})
        return journal

    def test_force_close_signs_and_proves(self):
        journal = self._journal_with(3)
        anchor = AnchorService(HmacSigner("secret"), NullTsa(),
                               max_leaves=100, max_seconds=3600.0)
        record = anchor.anchor_pending(journal, force=True)
        self.assertIsNotNone(record)
        self.assertEqual(record.leaf_count, 3)
        self.assertTrue(anchor.verify_anchor_signature(record))
        first = journal.entries()[0]["hash"]
        self.assertTrue(anchor.verify_proof(
            first, record.proofs[first], record.root_hex))
        self.assertEqual(len(journal.unbatched()), 0)

    def test_no_pending_no_anchor(self):
        journal = Journal()
        anchor = AnchorService(HmacSigner("secret"), NullTsa())
        self.assertIsNone(anchor.anchor_pending(journal, force=True))

    def test_null_tsa_is_not_rfc3161(self):
        tsa = NullTsa()
        self.assertEqual(tsa.authority_id, "local")
        self.assertTrue(tsa.verify(b"root", tsa.timestamp(b"root")))


class TestTraceExport(unittest.TestCase):
    def test_only_local_answers_exported(self):
        journal = Journal()
        journal.append("local_answer", {"task": "t", "skill": "s",
                                        "confidence": 0.9, "answer": "a"})
        journal.append("escalate", {"task": "u"})
        traces = collect_traces(journal.entries())
        self.assertEqual(len(traces), 1)
        self.assertEqual(traces[0]["prompt"], "t")
        self.assertEqual(traces[0]["answer"], "a")


if __name__ == "__main__":
    unittest.main()
