"""Tests for the compliance demo agent. Standard library only.

Run from the friday/ staging root:
    python3 -m unittest tests.test_demo_agent -v
"""

import unittest

from examples.compliance_agent.agent import ComplianceAgent
from examples.compliance_agent.rules import (
    APPROVAL_LIMIT,
    check_document,
)
from examples.compliance_agent.samples import (
    DOC_MISMATCH,
    DOC_OK,
    DOC_SENSITIVE,
)


def _statuses(report):
    return {f["rule_id"]: f["status"] for f in report["findings"]}


class TestRules(unittest.TestCase):
    def test_clean_doc_passes(self):
        statuses = {f["rule_id"]: f["status"]
                    for f in check_document(DOC_OK)}
        self.assertTrue(all(s in ("pass", "note")
                            for s in statuses.values()))

    def test_mismatch_flags_totals_and_evidence(self):
        statuses = _statuses({"findings": check_document(DOC_MISMATCH)})
        self.assertEqual(statuses["R2"], "flag")
        self.assertEqual(statuses["R5"], "flag")

    def test_approval_boundary(self):
        base = {"doc_id": "B", "period": "2026-P1",
                "lines": [{"amount_minor": APPROVAL_LIMIT,
                           "evidence_ref": "E"}],
                "submitter": "T"}
        at_limit = dict(base, total_minor=APPROVAL_LIMIT)
        over = dict(base, total_minor=APPROVAL_LIMIT + 1)
        self.assertEqual(
            [f for f in check_document(at_limit)
             if f["rule_id"] == "R4"][0]["status"], "pass")
        self.assertEqual(
            [f for f in check_document(over)
             if f["rule_id"] == "R4"][0]["status"], "flag")

    def test_sensitive_note_and_unsure(self):
        statuses = _statuses({"findings": check_document(DOC_SENSITIVE)})
        self.assertEqual(statuses["R4"], "flag")
        self.assertEqual(statuses["R2"], "unsure")
        self.assertEqual(statuses["R6"], "note")


class TestAgent(unittest.TestCase):
    def test_clean_doc_pass_no_escalation(self):
        agent = ComplianceAgent()
        report = agent.review(DOC_OK)
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["escalated"], [])
        self.assertFalse(report["reuse_hit"])

    def test_mismatch_flagged(self):
        agent = ComplianceAgent()
        report = agent.review(DOC_MISMATCH)
        self.assertEqual(report["verdict"], "FLAGGED")

    def test_reuse_second_review(self):
        agent = ComplianceAgent()
        agent.review(DOC_OK)
        report = agent.review(DOC_OK)
        self.assertTrue(report["reuse_hit"])
        self.assertEqual(report["verdict"], "PASS")

    def test_escalation_redacts_email(self):
        agent = ComplianceAgent()
        report = agent.review(DOC_SENSITIVE)
        self.assertEqual(report["verdict"], "FLAGGED")
        self.assertEqual(len(report["escalated"]), 1)
        item = report["escalated"][0]
        self.assertEqual(item["rule_id"], "R2")
        self.assertGreaterEqual(item["redacted"], 1)
        self.assertNotIn("boss@example.com", item["context"])
        self.assertNotIn("big_model_review", item)

    def test_anchor_and_proof(self):
        agent = ComplianceAgent()
        agent.review(DOC_OK)
        agent.review(DOC_MISMATCH)
        record = agent.finalize_anchor()
        self.assertIsNotNone(record)
        first = agent.journal.entries()[0]["hash"]
        self.assertTrue(agent.anchor_service.verify_proof(
            first, record.proofs[first], record.root_hex))
        ok, _ = agent.journal.verify()
        self.assertTrue(ok)

    def test_summary_counts(self):
        agent = ComplianceAgent()
        agent.review(DOC_OK)
        agent.review(DOC_SENSITIVE)
        summary = agent.summary()
        self.assertEqual(summary["reviews"], 2)
        self.assertEqual(summary["escalated_total"], 1)
        self.assertGreater(summary["estimated_tokens_saved"], 0)


if __name__ == "__main__":
    unittest.main()
