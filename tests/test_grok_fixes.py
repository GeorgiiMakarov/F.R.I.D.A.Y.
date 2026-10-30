"""Tests for the Grok 4.7 audit fixes (v0.2.1 -> post-Grok tree).

Each test pins one confirmed finding.
"""

import unittest

from friday import (EscalationGate, Journal, Memory, Skill, SkillRegistry)
from friday.anchor import (AnchorService, HmacSigner, NullTsa,
                           _signed_payload)
from friday.compress import compress
from friday.router import Router
from examples.compliance_agent.agent import ComplianceAgent
from examples.compliance_agent.rules import (r4_approval, r6_sensitive)
from examples.compliance_agent.samples import DOC_OK


def _skill(name, answer, version="1.0"):
    return Skill(name, version, lambda t: (answer, 0.95),
                 [("ok", lambda: True)])


class TestRouterSkillKey(unittest.TestCase):
    def test_other_skill_does_not_reuse(self):
        reg = SkillRegistry()
        reg.register(_skill("alpha", "FROM_ALPHA"))
        reg.register(_skill("beta", "FROM_BETA"))
        router = Router(reg, Memory(), Journal(),
                        EscalationGate(threshold=0.8))
        self.assertEqual(router.handle("same-task", "alpha"),
                         ("local", "FROM_ALPHA"))
        # Grok 1: beta used to get FROM_ALPHA; now it runs itself.
        self.assertEqual(router.handle("same-task", "beta"),
                         ("local", "FROM_BETA"))

    def test_version_bump_invalidates_reuse(self):
        reg = SkillRegistry()
        reg.register(_skill("alpha", "V1", version="1.0"))
        router = Router(reg, Memory(), Journal(),
                        EscalationGate(threshold=0.8))
        self.assertEqual(router.handle("t", "alpha"), ("local", "V1"))
        reg.register(_skill("alpha", "V2", version="2.0"))
        self.assertEqual(router.handle("t", "alpha"), ("local", "V2"))

    def test_reuse_journal_names_true_producer(self):
        mem, jrn = Memory(), Journal()
        reg = SkillRegistry()
        reg.register(_skill("alpha", "FROM_ALPHA"))
        router = Router(reg, mem, jrn, EscalationGate(threshold=0.8))
        router.handle("t", "alpha")
        router.handle("t", "alpha")
        reuse = [e for e in jrn.entries() if e["event"] == "reuse"]
        self.assertEqual(len(reuse), 1)
        self.assertEqual(reuse[0]["payload"]["skill"], "alpha")


class TestMemoryDeepCopy(unittest.TestCase):
    def test_get_mutation_does_not_corrupt(self):
        mem = Memory()
        mem.put("k", {"verdict": "PASS"}, "s", "1", ttl_s=3600)
        mem.get("k")["verdict"] = "HACKED"
        self.assertEqual(mem.get("k"), {"verdict": "PASS"})

    def test_put_mutation_does_not_corrupt(self):
        mem = Memory()
        value = {"verdict": "PASS"}
        mem.put("k", value, "s", "1", ttl_s=3600)
        value["verdict"] = "HACKED"
        self.assertEqual(mem.get("k"), {"verdict": "PASS"})

    def test_find_mutation_does_not_corrupt(self):
        mem = Memory()
        mem.put("doc", {"x": 1}, "s", "1", ttl_s=3600)
        found = mem.find("doc")
        found[0][1]["x"] = 99
        self.assertEqual(mem.get("doc"), {"x": 1})

    def test_agent_reuse_mutation_does_not_corrupt(self):
        agent = ComplianceAgent()
        report = agent.review(dict(DOC_OK))
        report["verdict"] = "HACKED"
        again = agent.review(dict(DOC_OK))
        self.assertTrue(again["reuse_hit"])
        self.assertEqual(again["verdict"], "PASS")


class TestVerdictVsGate(unittest.TestCase):
    def test_fully_escalated_clean_doc_is_not_pass(self):
        agent = ComplianceAgent(threshold=0.99)
        report = agent.review(dict(DOC_OK))
        self.assertEqual(len(report["escalated"]), 6)
        self.assertEqual(report["verdict"], "REVIEW_REQUIRED")

    def test_clean_doc_still_passes_at_default_threshold(self):
        agent = ComplianceAgent()
        report = agent.review(dict(DOC_OK))
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["escalated"], [])


class TestCompressNames(unittest.TestCase):
    def test_names_survive(self):
        out = compress("doc_id: ABC\nsubmitter: Georgii Makarov\n"
                       "period: 2026-P1")
        self.assertIn("doc_id: ABC", out)
        self.assertIn("submitter: Georgii Makarov", out)
        self.assertIn("period: 2026-P1", out)

    def test_sensitive_lines_dropped_even_when_labeled(self):
        out = compress("doc_id: ABC\nnotes: password is hunter2")
        self.assertIn("doc_id: ABC", out)
        self.assertNotIn("hunter2", out)


class TestFalseEscalations(unittest.TestCase):
    def test_documented_definition(self):
        gate = EscalationGate(threshold=0.8)
        # Local was right, went up anyway: the wasted call.
        gate.record_outcome(was_escalated=True, was_correct=True)
        # Local was wrong, went up: justified, not false.
        gate.record_outcome(was_escalated=True, was_correct=False)
        report = gate.report()
        self.assertEqual(report["false_escalations"], 1)
        self.assertEqual(report["justified_escalations"], 1)


class TestSingleRuleContracts(unittest.TestCase):
    def test_r6_password(self):
        finding = r6_sensitive({"notes": "password is hunter2"})
        self.assertEqual(finding["status"], "note")
        self.assertIn("sensitive data present", finding["detail"])

    def test_r4_unsure_cases(self):
        for doc in ({}, {"total_minor": -500},
                    {"total_minor": 5_000_000.0}):
            self.assertEqual(r4_approval(doc)["status"], "unsure")

    def test_r4_regressions(self):
        self.assertEqual(r4_approval({"total_minor": 100})["status"],
                         "pass")
        self.assertEqual(r4_approval({"total_minor": 9_999_999})["status"],
                         "flag")
        self.assertEqual(r4_approval({"total_minor": 9_999_999,
                                      "approver": "boss"})["status"],
                         "pass")


class TestJournalRuntimeContext(unittest.TestCase):
    def test_runtime_context_tamper_breaks_chain(self):
        journal = Journal()
        journal.append("evt", {"x": 1}, runtime_context={"user": "alice"})
        exported = journal.entries()
        exported[0]["runtime_context"]["user"] = "mallory"
        ok, bad = journal.verify_external(exported)
        self.assertFalse(ok)
        self.assertEqual(bad, 0)


class TestProofRowLeafCount(unittest.TestCase):
    def test_row_carries_leaf_count_and_verifies(self):
        signer = HmacSigner("demo-secret")
        service = AnchorService(signer, NullTsa())
        journal = Journal()
        journal.append("evt", {"x": 1})
        record = service.anchor_pending(journal, force=True)
        row = list(service.proof_store.values())[0]
        self.assertEqual(row["leaf_count"], record.leaf_count)
        payload = _signed_payload(bytes.fromhex(row["root"]),
                                  row["leaf_count"])
        self.assertTrue(signer.verify(
            payload, bytes.fromhex(row["anchor_signature"]), None))


class TestReportCoverage(unittest.TestCase):
    def test_mixed_gate_failure_visible_in_report(self):
        agent = ComplianceAgent()
        orig = agent.registry.get_gated

        def gated(name):
            if name == "rule_R1":
                return None, {"skill": name, "passed": False,
                              "failures": [("battery", "forced")]}
            return orig(name)

        agent.registry.get_gated = gated
        report = agent.review({"doc_id": "T", "period": "2026-P1",
                               "total_minor": 100,
                               "lines": [{"amount_minor": 90,
                                          "evidence_ref": "E"}],
                               "submitter": "X"})
        self.assertEqual(report["verdict"], "FLAGGED")
        self.assertEqual(report["gates_failed"], ["R1"])


if __name__ == "__main__":
    unittest.main()
