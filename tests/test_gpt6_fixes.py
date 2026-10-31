"""Regression tests for the GPT-6 audit fixes (F-01..F-10, extra-1/2/3).

Each test reproduces the audited defect and fails on the pre-fix code.
"""

import json
import math
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from friday import EscalationGate, Journal, Memory, SkillRegistry
from friday.anchor import AnchorService, HmacSigner, NullTsa
from friday.dic_merkle import MerkleBatch, ProofStep, verify_inclusion_proof
from friday.local_model import OpenAICompatibleLocalModel
from friday.memory import SENSITIVE, SHAREABLE, redact_text
from friday.router import TASK_WITHHELD, Router, cache_key
from friday.skill_trace import collect_traces
from examples.compliance_agent.agent import ComplianceAgent
from examples.compliance_agent.rules import RULES_VERSION


def _doc(doc_id, total, amount=None):
    return {"doc_id": doc_id, "period": "2026-P1", "total_minor": total,
            "lines": [{"amount_minor": total if amount is None else amount,
                       "evidence_ref": "E-1"}],
            "submitter": "Tester"}


def _serve(payload):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class TestGpt6Fixes(unittest.TestCase):
    def test_f01_no_duplicate_leaves(self):
        journal = Journal()
        journal.append("evt", {"x": 1})
        svc = AnchorService(HmacSigner("demo"), NullTsa(),
                            max_leaves=100, max_seconds=3600.0)
        for _ in range(3):
            self.assertIsNone(svc.anchor_pending(journal, force=False))
        self.assertEqual(len(svc._builder._pending), 1)
        record = svc.anchor_pending(journal, force=True)
        self.assertEqual(record.leaf_count, 1)

    def test_f02_all_gates_fail_is_review_required(self):
        agent = ComplianceAgent()
        for skill in agent.registry._skills.values():
            skill.tests = [("forced-fail", lambda: False)]
        report = agent.review(_doc("D-1", 100))
        self.assertEqual(report["verdict"], "REVIEW_REQUIRED")
        self.assertEqual(len(report["findings"]), 0)
        self.assertEqual(len(report["escalated"]), 6)

    def test_f02_partial_gate_failure_is_review_required(self):
        agent = ComplianceAgent()
        for name, skill in agent.registry._skills.items():
            if name != "rule_R1":
                skill.tests = [("forced-fail", lambda: False)]
        report = agent.review(_doc("D-1", 100))
        self.assertEqual(report["verdict"], "REVIEW_REQUIRED")

    def test_f03_changed_document_is_rechecked(self):
        agent = ComplianceAgent()
        agent.review(_doc("D-2", 100))
        second = agent.review(_doc("D-2", 200))
        self.assertFalse(second["reuse_hit"])
        details = [f["detail"] for f in second["findings"]]
        self.assertIn("lines sum 200 == total 200", details)

    def test_extra2_cache_key_covers_content_and_version(self):
        doc = _doc("D-9", 100)
        key = cache_key("compliance_agent", RULES_VERSION, doc)
        self.assertEqual(
            key, cache_key("compliance_agent", RULES_VERSION, doc))
        self.assertNotEqual(
            key, cache_key("compliance_agent", RULES_VERSION,
                           _doc("D-9", 200)))
        self.assertNotEqual(
            key, cache_key("compliance_agent", "9.9.9", doc))
        # Merge format: skill:version:sha256(content); the old
        # "review:doc_id:digest:version" format is retired.
        self.assertTrue(
            key.startswith("compliance_agent:" + RULES_VERSION + ":"))

    def test_f04_mutation_does_not_corrupt_journal(self):
        payload = {"x": [1]}
        journal = Journal()
        journal.append("evt", payload)
        payload["x"].append(2)
        self.assertEqual(journal.verify(), (True, None))

        journal = Journal()
        journal.append("evt", {"x": [1]})
        journal.entries()[0]["payload"]["x"].append(2)
        self.assertEqual(journal.verify(), (True, None))

        journal = Journal()
        returned = journal.append("evt", {"x": [1]})
        returned["payload"]["x"].append(2)
        self.assertEqual(journal.verify(), (True, None))

    def test_f05_escalation_task_is_withheld(self):
        # Step 3, option A supersedes F-05 redaction: the task is
        # withheld, not redacted — nothing of it goes up at all.
        router = Router(SkillRegistry(), Memory(), Journal(),
                        EscalationGate())
        _, esc = router.handle(
            "contact alice@example.com, my password is hunter2",
            "no_such_skill")
        self.assertNotIn("alice@example.com", esc.task)
        self.assertNotIn("hunter2", esc.task)
        _, esc2 = router.handle("summarise the quarterly report",
                                "no_such_skill")
        self.assertEqual(esc2.task, TASK_WITHHELD)

    def test_f05_redact_text_patterns(self):
        self.assertEqual(redact_text("write to bob@x.com now"),
                         "write to [redacted] now")
        self.assertEqual(redact_text("api_key=abc123 inside"),
                         "[redacted] inside")
        self.assertEqual(redact_text("plain quarterly report"),
                         "plain quarterly report")

    def test_f06_sensitive_label_wins(self):
        memory = Memory()
        memory.put("k1", "project falcon budget notes", "s", "1",
                   ttl_s=3600, sensitivity=SENSITIVE)
        self.assertEqual(memory.find("falcon budget"), [])
        self.assertEqual(
            memory.export_shareable(
                [("k1", "project falcon budget notes", SENSITIVE)]), [])
        self.assertEqual(
            memory.export_shareable(
                [("k2", "plain note", SHAREABLE)]),
            [("k2", "plain note")])

    def test_f07_invalid_confidence_becomes_zero(self):
        for bad in (5.0, float("nan"), "not-a-number"):
            server = _serve({"choices": [{"message": {"content": "ans"},
                                        "finish_reason": "stop"}],
                             "confidence": bad})
            try:
                model = OpenAICompatibleLocalModel(
                    "http://127.0.0.1:%d" % server.server_address[1],
                    "stub")
                _, confidence, source = model.generate("q", budget=8)
            finally:
                server.shutdown()
                server.server_close()
            self.assertEqual(confidence, 0.0)
            self.assertEqual(source, "none")
        server = _serve({"choices": [{"message": {"content": "ans"},
                                    "finish_reason": "stop"}],
                         "confidence": 0.9})
        try:
            model = OpenAICompatibleLocalModel(
                "http://127.0.0.1:%d" % server.server_address[1], "stub")
            _, confidence, source = model.generate("q", budget=8)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(confidence, 0.9)
        self.assertEqual(source, "explicit")

    def test_f08_traces_carry_pending_approval(self):
        journal = Journal()
        journal.append("local_answer", {"task": "2+2", "skill": "arith",
                                        "confidence": 0.97, "answer": "5"})
        traces = collect_traces(journal.entries())
        self.assertEqual(len(traces), 1)
        self.assertEqual(traces[0]["approval"], "pending")

    def test_f10_local_stamp_is_labelled(self):
        token = NullTsa().timestamp(b"digest")
        self.assertEqual(token["trust"], "local_untrusted")
        self.assertTrue(NullTsa().verify(b"digest", token))

    def test_extra1_negative_amounts_flagged(self):
        report = ComplianceAgent().review(_doc("NEG", -500))
        self.assertEqual(report["verdict"], "FLAGGED")
        r2 = [f for f in report["findings"] if f["rule_id"] == "R2"][0]
        self.assertEqual(r2["status"], "flag")

    def test_extra3_malformed_proof_position_rejected(self):
        batch = MerkleBatch(
            leaves=[b"a" * 32, b"b" * 32, b"c" * 32, b"d" * 32])
        root = batch.close()
        leaves = [b"a" * 32, b"b" * 32, b"c" * 32, b"d" * 32]
        for idx in range(4):
            proof = batch.proof_for(idx)
            self.assertTrue(verify_inclusion_proof(leaves[idx], proof,
                                                   root))
            bad = [ProofStep(s.sibling_hash,
                             "BOGUS" if i == 0 else s.position)
                   for i, s in enumerate(proof)]
            self.assertFalse(verify_inclusion_proof(leaves[idx], bad,
                                                    root))


# Pass 2 (pre-release remarks): labelled leak tests + the upward
# payload contract. Every value below that must never leave the device
# is asserted absent from every field that does leave it.
_SECRETS = [
    "alice@example.com",
    "bob@example.com",
    "4111 1111 1111 1111",
    # Step 3: over-cap token (64 chars). A 40-char letter-first id
    # passes the evidence_ref format by design now, so the contract
    # test pins over-cap tokens instead; see test_schema_redaction.
    "A" * 64,
    "hunter2",
]

_LABELED_SENSITIVE = [
    "contact alice@example.com now",
    "api_key=abc123def456",
    "token: xyz789",
    "card 4111 1111 1111 1111",
    "A" * 40,
    "my password is hunter2",
]

_LABELED_BENIGN = [
    "summarise the quarterly report",
    "token economics overview",
    "the secret garden summary",
]


class TestEscalationContract(unittest.TestCase):
    def test_redact_text_labelled_set(self):
        from friday.memory import classify_fragment, redact_text
        for text in _LABELED_SENSITIVE:
            self.assertEqual(classify_fragment(text), SENSITIVE)
            cleaned = redact_text(text)
            for secret in ("alice@example.com", "abc123def456", "xyz789",
                           "4111", "A" * 40, "hunter2"):
                self.assertNotIn(secret, cleaned)
        for text in _LABELED_BENIGN:
            self.assertEqual(classify_fragment(text), SHAREABLE)
            self.assertEqual(redact_text(text), text)

    def test_router_escalation_contract(self):
        memory = Memory()
        memory.put("frag-mail", "contact alice@example.com", "s", "1",
                   ttl_s=3600)
        memory.put("frag-label", "project falcon budget notes", "s", "1",
                   ttl_s=3600, sensitivity=SENSITIVE)
        router = Router(SkillRegistry(), memory, Journal(),
                        EscalationGate())
        kind, esc = router.handle(
            "summarise falcon budget, contact alice@example.com",
            "no_such_skill")
        self.assertEqual(kind, "escalate")
        for secret in _SECRETS:
            self.assertNotIn(secret, esc.task)
            self.assertNotIn(secret, esc.compressed_context)
        # Reasons are fixed strings, redacted_count an int: no payload.
        self.assertEqual(esc.reasons, ["gate_failed"])
        self.assertIsInstance(esc.redacted_count, int)

    def test_agent_escalation_contract(self):
        doc = {"doc_id": "S-1", "period": "2026-P1",
               "total_minor": 100,
               "lines": [{"evidence_ref": "A" * 64}],
               "submitter": "alice@example.com",
               "notes": "call bob@example.com, card 4111 1111 1111 1111"}
        report = ComplianceAgent().review(doc)
        self.assertTrue(report["escalated"])
        self.assertGreater(
            sum(item["redacted"] for item in report["escalated"]), 0)
        for item in report["escalated"]:
            for field in ("context", "detail"):
                for secret in _SECRETS:
                    self.assertNotIn(secret, item[field])
            self.assertNotIn("big_model_review", item)

    def test_agent_detail_is_redacted_even_when_leaky(self):
        import examples.compliance_agent.agent as agent_module

        def leaky_rule(doc):
            if doc.get("trigger"):
                return {"rule_id": "R6", "status": "unsure",
                        "detail": "cannot decide, see alice@example.com",
                        "confidence": 0.3}
            return {"rule_id": "R6", "status": "note",
                    "detail": "noted", "confidence": 0.95}

        original = agent_module.RULES
        agent_module.RULES = [("R6", "custom", leaky_rule)]
        try:
            agent = ComplianceAgent()
            report = agent.review({"doc_id": "L-1", "trigger": True,
                                   "period": "2026-P1",
                                   "total_minor": 100,
                                   "lines": [{"amount_minor": 100,
                                              "evidence_ref": "E-1"}],
                                   "submitter": "Tester"})
        finally:
            agent_module.RULES = original
        self.assertEqual(len(report["escalated"]), 1)
        detail = report["escalated"][0]["detail"]
        self.assertNotIn("alice@example.com", detail)
        self.assertIn("[redacted]", detail)


if __name__ == "__main__":
    unittest.main()
