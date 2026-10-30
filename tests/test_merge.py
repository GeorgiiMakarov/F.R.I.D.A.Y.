"""Step 4 (merge): the agent shares the router's plumbing.

The note's variant, accepted with three review conditions:
reports cached SENSITIVE (test 7), submitter/notes never passed to
the builder (test 2), and the demo golden defined precisely
(test 1: stdout minus the batch/root line, journal count 24,
event-type sequence, agent payloads). Routing decisions still live
in both places by design (see TestMergeRoutingContract): only the
call sites are duplicated, the gate object is shared.
"""

import contextlib
import io
import unittest

from friday import (EscalationGate, Journal, Memory, Router, Skill,
                    SkillRegistry)
from friday.anchor import AnchorService, Ed25519Signer, NullTsa
from friday.local_model import StubLocalModel
from friday.memory import SENSITIVE, SHAREABLE, classify_fragment
from friday.router import cache_key
from friday.skills import builtin_skills
from examples.compliance_agent.agent import ComplianceAgent
from examples.compliance_agent.demo import STUB_ANSWERS, main as demo_main
from examples.compliance_agent.rules import RULES_VERSION
from examples.compliance_agent.samples import (
    DOC_MISMATCH,
    DOC_OK,
    DOC_SENSITIVE,
)

# Demo golden, condition 3: the batch id and root vary run to run
# (uuid4), so they are masked from stdout; the journal count, the
# agent's event-type sequence and the agent payloads do not vary.
EXPECTED_TYPES = (
    ["rule_check"] * 6 + ["verdict"]
    + ["rule_check"] * 6 + ["verdict"]
    + ["rule_check", "rule_check", "model_review", "escalate"]
    + ["rule_check"] * 4 + ["verdict", "reuse"]
)


def _demo_sequence():
    agent = ComplianceAgent(local_model=StubLocalModel(STUB_ANSWERS))
    for doc in (DOC_OK, DOC_MISMATCH, DOC_SENSITIVE):
        agent.review(doc)
    agent.review(DOC_OK)
    return agent


def _router_with_builtins():
    memory, registry = Memory(), SkillRegistry()
    for skill in builtin_skills(memory, registry):
        registry.register(skill)
    router = Router(registry, memory, Journal(),
                    EscalationGate(threshold=0.8))
    return router, memory


class TestMergeGolden(unittest.TestCase):
    def test_demo_golden(self):
        outs = []
        for _ in range(2):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                demo_main()
            outs.append([line for line in buf.getvalue().splitlines()
                         if not line.startswith("batch ")])
        self.assertEqual(outs[0], outs[1])
        agents = [_demo_sequence() for _ in range(2)]
        for agent in agents:
            entries = agent.journal.entries()
            self.assertEqual(len(entries), 24)
            self.assertEqual([e["event"] for e in entries],
                             EXPECTED_TYPES)
        payloads = [[(e["event"], e["payload"])
                     for e in a.journal.entries()] for a in agents]
        self.assertEqual(payloads[0], payloads[1])


class TestMergeBuilder(unittest.TestCase):
    def test_builder_excludes_submitter_and_notes(self):
        doc = {"doc_id": "T-NAME", "period": "2026-P1",
               "total_minor": 100,
               "lines": [{"amount_minor": None, "evidence_ref": "E-1"}],
               "submitter": "Иванов Иван Иванович",
               "notes": "позвонить завтра обсудить детали"}
        # Probe: the denylist does NOT catch names, so
        # exclusion — not classification — is what protects them.
        self.assertEqual(classify_fragment("Иванов Иван Иванович"),
                         SHAREABLE)
        report = ComplianceAgent().review(doc)
        self.assertEqual(len(report["escalated"]), 1)
        context = report["escalated"][0]["context"]
        # The two excluded lines count as withheld (merge fix): the
        # reviewer sees the context is incomplete, not clean.
        self.assertEqual(report["escalated"][0]["redacted"], 2)
        self.assertNotIn("Иванов", context)
        self.assertNotIn("позвонить", context)
        self.assertNotIn("submitter", context)
        self.assertNotIn("notes", context)
        # One builder: the agent context equals the router builder's
        # output for the same doc-field lines.
        lines = ["doc_id: T-NAME", "period: 2026-P1",
                 "total_minor: 100",
                 "line 0: amount_minor=None evidence_ref=E-1"]
        self.assertEqual(Router.build_escalation_context(lines)[0],
                         context)


class TestMergeCache(unittest.TestCase):
    def test_cached_fragment_survives_escalation(self):
        # Merge regression (found in zip review): the hashed
        # cache key contains a 64-char token the classifier reads as
        # a key-like secret, so gluing "key: value" redacted every
        # cached fragment and left Router context empty. Lines carry
        # values only now, so the fragment survives.
        router, _ = _router_with_builtins()
        kind, _ = router.handle(
            "summarise::limit is 1000000 minor units", "summarise")
        self.assertEqual(kind, "local")
        kind, esc = router.handle("what is the approval limit",
                                  "no_such_skill")
        self.assertEqual(kind, "escalate")
        self.assertIn("limit is 1000000 minor units",
                      esc.compressed_context)
        self.assertEqual(esc.redacted_count, 0)

    def test_old_raw_text_key_unreachable(self):
        router, memory = _router_with_builtins()
        memory.put("capital of France", "Paris", "retrieve", "0.1.0",
                   3600)
        # The router's reuse path hashes now: the raw-text seed is
        # not a reuse hit (the skill's own find path may still see
        # the fragment — that path is unchanged by design).
        kind, _ = router.handle("capital of France", "retrieve")
        self.assertNotEqual(kind, "reuse")
        self.assertIsNone(memory.lookup(
            cache_key("retrieve", "0.1.0", "capital of France")))
        # The new key works: local once, reuse after.
        kind, _ = router.handle("summarise::budget is 42 coins",
                                "summarise")
        self.assertEqual(kind, "local")
        kind, payload = router.handle("summarise::budget is 42 coins",
                                      "summarise")
        self.assertEqual(kind, "reuse")
        self.assertIn("42", payload)


class TestMergeRoutingContract(unittest.TestCase):
    """One routing contract for both contours (merge, partial by
    design): the call sites are duplicated (get_gated, gate.decide,
    escalation assembly), but the gate object is shared by reference,
    so the same confidence and threshold must route the same way in
    the router and in the agent, and a gate failure must escalate in
    both. A full unification through Router.handle was deliberately
    rejected (document vs. string task, journal event vocabulary,
    accepted golden) — this contract is what guards the duplication
    instead.
    """

    def test_gate_shared_by_reference(self):
        gate = EscalationGate(threshold=0.8)
        router = Router(SkillRegistry(), Memory(), Journal(), gate)
        agent = ComplianceAgent(router=router)
        self.assertIs(agent.gate, gate)
        self.assertIs(agent.gate, router.gate)

    def test_same_confidence_same_route(self):
        router, _ = _router_with_builtins()
        for confidence, expected in ((0.95, "local"), (0.3, "escalate"),
                                     (0.8, "local")):
            probe = Skill("probe", "1.0",
                          lambda task, c=confidence: ("ok", c), [])
            router.registry.register(probe)
            # Fresh task per case: the cache key is skill:version:
            # sha256(task), so reusing one task would hit the first
            # case's cached answer instead of running the probe.
            kind, _ = router.handle("probe-%s" % confidence, "probe")
            self.assertEqual(kind, expected)
        # Agent side, real rules at the default threshold 0.8: R1
        # passes at 0.95 (stays local), R2 is unsure at 0.30
        # (escalates). No rule yields exactly 0.8, so the boundary
        # case is router-only.
        doc = {"doc_id": "T-R", "period": "2026-P1", "total_minor": 100,
               "lines": [{"amount_minor": None, "evidence_ref": "E-1"}]}
        report = ComplianceAgent().review(doc)
        escalated = {item["rule_id"] for item in report["escalated"]}
        self.assertNotIn("R1", escalated)
        self.assertIn("R2", escalated)

    def test_gate_failure_escalates_both(self):
        router, _ = _router_with_builtins()
        kind, esc = router.handle("anything", "no_such_skill")
        self.assertEqual(kind, "escalate")
        self.assertEqual(esc.reasons, ["gate_failed"])
        agent = ComplianceAgent()
        orig = agent.registry.get_gated

        def failing(name):
            return None, {"failures": ["forced gate failure"]}

        agent.registry.get_gated = failing
        try:
            report = agent.review(DOC_OK)
        finally:
            agent.registry.get_gated = orig
        self.assertTrue(report["gates_failed"])
        self.assertTrue(all(item["reason"] == "gate_failed"
                            for item in report["escalated"]))
        self.assertEqual(report["verdict"], "REVIEW_REQUIRED")


class TestMergeBackCompat(unittest.TestCase):
    def test_old_construction_still_works(self):
        memory, journal = Memory(), Journal()
        agent = ComplianceAgent(memory=memory, journal=journal)
        self.assertIs(agent.memory, memory)
        self.assertIs(agent.journal, journal)
        self.assertIsNotNone(agent.router)
        report = agent.review(DOC_OK)
        self.assertEqual(report["verdict"], "PASS")
        self.assertTrue(agent.review(DOC_OK)["reuse_hit"])


class TestMergeAnchor(unittest.TestCase):
    def test_anchor_uses_router_service(self):
        router, _ = _router_with_builtins()
        signer = Ed25519Signer()
        service = AnchorService(signer, NullTsa(), pilot_mode=True)
        agent = ComplianceAgent(router=router, anchor_service=service)
        self.assertIs(agent.anchor_service, service)
        self.assertIs(router.anchor_service, service)
        agent.review(DOC_OK)
        agent.review(DOC_MISMATCH)
        record = agent.finalize_anchor()
        self.assertIsNotNone(record)
        verifier = Ed25519Signer.from_public_bytes(
            signer.public_key_bytes(), key_id=signer.key_id())
        checking = AnchorService(verifier, NullTsa())
        self.assertTrue(checking.verify_anchor_signature(record))


class TestMergeRegistry(unittest.TestCase):
    def test_single_registry(self):
        router, _ = _router_with_builtins()
        agent = ComplianceAgent(router=router)
        extra = Skill("extra", "1.0", lambda task: ("done", 0.9), [])
        router.registry.register(extra)
        names = router.registry.names()
        self.assertIn("rule_R1", names)
        self.assertIn("extra", names)
        self.assertEqual(agent.review(DOC_OK)["verdict"], "PASS")
        self.assertEqual(router.handle("anything", "extra"),
                         ("local", "done"))


class TestMergeSensitiveReports(unittest.TestCase):
    def test_sensitive_reports_not_mixed(self):
        router, memory = _router_with_builtins()
        agent = ComplianceAgent(router=router)
        doc_a = {"doc_id": "DOC-FALCON", "period": "2026-P1",
                 "total_minor": 100,
                 "lines": [{"amount_minor": 100,
                            "evidence_ref": "FALCON-1"}],
                 "submitter": "Falconer"}
        agent.review(doc_a)
        # Condition 1: the report is cached SENSITIVE.
        key = cache_key("compliance_agent", RULES_VERSION, doc_a)
        entry = memory.lookup(key)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["sensitivity"], SENSITIVE)
        # Reuse still works: direct key access ignores sensitivity.
        self.assertTrue(agent.review(doc_a)["reuse_hit"])
        # Control: a shareable fragment IS found by the router path.
        memory.put("falcon notes", "falcon budget notes", "s", "1",
                   3600)
        kind, esc = router.handle("falcon review", "no_such_skill")
        self.assertEqual(kind, "escalate")
        self.assertIn("falcon budget notes", esc.compressed_context)
        # But nothing from doc A's report leaks into it.
        self.assertNotIn("DOC-FALCON", esc.compressed_context)
        self.assertNotIn("FALCON-1", esc.compressed_context)


if __name__ == "__main__":
    unittest.main()
