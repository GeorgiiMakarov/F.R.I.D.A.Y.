"""Step 3: schema redaction (allowlist) for the compliance agent path,
Router task withholding (option A), and SENSITIVE-by-default router
caching with explicit shareable declaration.

Probe values are synthetic: zero patterns, invalid checksums and
canonical placeholders, never real personal data.
"""

import unittest

from friday import EscalationGate, Journal, Memory, Router, Skill, SkillRegistry
from friday.memory import SENSITIVE, redact_text
from friday.router import TASK_WITHHELD, cache_key
from friday.schema import PackSchema, evidence_ref_ok
from examples.compliance_agent.agent import ComplianceAgent


def _escalating_doc(**overrides):
    doc = {"doc_id": "T-1", "period": "2026-P1", "total_minor": 100,
           "lines": [{"amount_minor": None, "evidence_ref": "E-1"}]}
    doc.update(overrides)
    return doc


def _escalated_item(doc, **agent_kwargs):
    report = ComplianceAgent(**agent_kwargs).review(doc)
    assert len(report["escalated"]) == 1, report["escalated"]
    return report["escalated"][0]


PROBES = [
    ("phone RU", "+7 900 000-00-01"),
    ("phone KZ", "+7 700 000-00-02"),
    ("address", "г. Выдумка, ул. Несуществующая, д. 999"),
    ("INN", "123456789012"),
    ("passport", "00 00 000000"),
    ("IIN", "000000000000"),
    ("name RU", "Иван Иванович Иванов"),
    ("name EN", "John Doe"),
    ("IBAN KZ", "KZ00 0000 0000 0000 0000"),
]


class TestNeverFields(unittest.TestCase):
    def test_probes_in_submitter_and_notes_never_go_up(self):
        # Never-fields never reach the schema at all, so these probes
        # prove the allowlist, not the regex.
        for name, value in PROBES:
            item = _escalated_item(_escalating_doc(submitter=value,
                                                   notes=value))
            self.assertNotIn(value, item["context"], name)
            self.assertNotIn(value, item["detail"], name)
            self.assertEqual(item["redacted"], 2, name)
            self.assertEqual(item["excluded"], ["submitter", "notes"],
                             name)


class TestKnownResiduals(unittest.TestCase):
    def test_phone_in_doc_id_documents_the_limitation(self):
        # KNOWN LIMITATION, pinned not hidden: the denylist second
        # line has no phone pattern, so a phone inside an allowed id
        # field passes. Pack authors must not put PII in id fields;
        # this test fails loudly if the behaviour ever changes.
        phone = "+7 900 000-00-01"
        item = _escalated_item(_escalating_doc(doc_id=phone))
        self.assertIn(phone, item["context"])
        self.assertEqual(item["redacted"], 0)

    def test_phone_in_period_documents_the_limitation(self):
        phone = "+7 900 000-00-01"
        item = _escalated_item(_escalating_doc(period=phone))
        self.assertIn(phone, item["context"])
        self.assertEqual(item["redacted"], 0)

    def test_email_in_period_is_dropped_by_second_line(self):
        item = _escalated_item(_escalating_doc(period="boss@example.com"))
        self.assertNotIn("boss@example.com", item["context"])
        self.assertEqual(item["excluded"], ["period"])
        self.assertEqual(item["redacted"], 1)

    def test_detail_phone_is_known_limitation_email_is_redacted(self):
        # Detail is redact_text-only (no schema for free strings):
        # email is removed, phone passes. Both pinned.
        self.assertNotIn("boss@example.com",
                         redact_text("contact boss@example.com now"))
        self.assertIn("+7 900 000-00-01",
                      redact_text("call +7 900 000-00-01"))

    def test_agent_detail_is_redacted_text_of_finding(self):
        # The upward item detail equals redact_text of the rule's raw
        # detail (which stays in the SENSITIVE-cached report, local).
        report = ComplianceAgent().review(_escalating_doc())
        item = report["escalated"][0]
        raw = [f for f in report["findings"]
               if f["status"] == "unsure"][0]["detail"]
        self.assertEqual(item["detail"], redact_text(raw))


class TestEvidenceRef(unittest.TestCase):
    UUID = "123e4567-e89b-12d3-a456-426614174000"

    def test_uuid_passes(self):
        self.assertTrue(evidence_ref_ok(self.UUID))
        item = _escalated_item(_escalating_doc(lines=[
            {"amount_minor": None, "evidence_ref": "E-1"},
            {"amount_minor": 100, "evidence_ref": self.UUID}]))
        self.assertIn(self.UUID, item["context"])

    def test_digit_only_ref_dropped(self):
        item = _escalated_item(_escalating_doc(lines=[
            {"amount_minor": None, "evidence_ref": "E-1"},
            {"amount_minor": 100, "evidence_ref": "123456789"}]))
        self.assertNotIn("123456789", item["context"])
        self.assertEqual(item["excluded"], ["lines[1].evidence_ref"])
        self.assertEqual(item["redacted"], 1)

    def test_cap_40_boundary(self):
        ref40 = "A" + "b" * 39  # 40 chars, letter-first: passes
        ref41 = "A" + "b" * 40  # 41 chars: dropped
        self.assertTrue(evidence_ref_ok(ref40))
        self.assertFalse(evidence_ref_ok(ref41))
        self.assertFalse(evidence_ref_ok("a" * 64))  # sha256-hex shape
        item = _escalated_item(_escalating_doc(lines=[
            {"amount_minor": None, "evidence_ref": "E-1"},
            {"amount_minor": 100, "evidence_ref": ref40}]))
        self.assertIn(ref40, item["context"])


class TestMissing(unittest.TestCase):
    def test_missing_amount_is_marker_not_redaction(self):
        item = _escalated_item(_escalating_doc(submitter="Tester",
                                               notes="note"))
        self.assertIn("amount_minor=missing", item["context"])
        self.assertEqual(item["redacted"], 2)  # submitter + notes only

    def test_empty_evidence_ref_is_missing(self):
        item = _escalated_item(_escalating_doc(lines=[
            {"amount_minor": None, "evidence_ref": ""}]))
        self.assertIn("evidence_ref=missing", item["context"])
        self.assertEqual(item["redacted"], 0)


class TestPackConfig(unittest.TestCase):
    def test_config_allow_appears_and_is_journaled(self):
        agent = ComplianceAgent(schema_config={
            "pack": "test-pack", "version": "1.0",
            "allow": [{"field": "department", "kind": "str"}]})
        doc = _escalating_doc(department="ledger")
        item = agent.review(doc)["escalated"][0]
        self.assertIn("department: ledger", item["context"])
        self.assertEqual(item["schema"], "1.0")
        entries = agent.journal.entries()
        self.assertEqual(entries[0]["event"], "schema")
        record = entries[0]["payload"]
        self.assertEqual(record["version"], "1.0")
        self.assertEqual(record["allow"],
                         [{"field": "department", "kind": "str"}])
        self.assertEqual(record["evidence_ref_max_len"], 40)

    def test_config_cannot_open_never_fields(self):
        with self.assertRaises(ValueError):
            PackSchema.from_config({"version": "1.0",
                                    "allow": ["submitter"]})
        with self.assertRaises(ValueError):
            PackSchema.from_config({"version": "1.0",
                                    "allow": ["approver"]})
        with self.assertRaises(ValueError):
            PackSchema.from_config({"version": "1.0",
                                    "allow": ["notes"]})

    def test_config_can_raise_evidence_ref_cap(self):
        ref64 = "a" * 64
        agent = ComplianceAgent(schema_config={
            "pack": "hex-pack", "version": "2.0",
            "evidence_ref_max_len": 64})
        doc = _escalating_doc(lines=[
            {"amount_minor": None, "evidence_ref": "E-1"},
            {"amount_minor": 100, "evidence_ref": ref64}])
        item = agent.review(doc)["escalated"][0]
        self.assertIn(ref64, item["context"])
        record = agent.journal.entries()[0]["payload"]
        self.assertEqual(record["evidence_ref_max_len"], 64)

    def test_default_schema_adds_no_journal_event(self):
        agent = ComplianceAgent()
        agent.review(_escalating_doc())
        events = [e["event"] for e in agent.journal.entries()]
        self.assertNotIn("schema", events)


class TestRouterWithholding(unittest.TestCase):
    def test_task_withheld_and_journal_keeps_raw(self):
        router = Router(SkillRegistry(), Memory(), Journal(),
                        EscalationGate())
        task = "call +7 900 000-00-01 about the report"
        kind, esc = router.handle(task, "no_such_skill")
        self.assertEqual(kind, "escalate")
        self.assertEqual(esc.task, TASK_WITHHELD)
        self.assertNotIn("+7 900 000-00-01", esc.task)
        entry = router.journal.entries()[-1]
        self.assertEqual(entry["event"], "escalate")
        self.assertTrue(entry["payload"]["task_withheld"])
        self.assertEqual(entry["payload"]["task"], task)  # local audit

    def test_router_answers_cached_sensitive_by_default(self):
        router = Router(SkillRegistry(), Memory(), Journal(),
                        EscalationGate())
        skill = Skill("echo", "1.0", lambda task: ("some answer", 0.9), [])
        router.registry.register(skill)
        kind, _ = router.handle("echo task", "echo")
        self.assertEqual(kind, "local")
        entry = router.memory.lookup(cache_key("echo", "1.0", "echo task"))
        self.assertEqual(entry["sensitivity"], SENSITIVE)

    def test_shareable_skill_answer_feeds_context(self):
        router = Router(SkillRegistry(), Memory(), Journal(),
                        EscalationGate())
        skill = Skill("shareable", "1.0",
                      lambda task: ("limit is 1000000 minor units", 0.9),
                      [], output_shareable=True)
        router.registry.register(skill)
        kind, _ = router.handle("shareable task", "shareable")
        self.assertEqual(kind, "local")
        kind, esc = router.handle("what is the approval limit",
                                  "no_such_skill")
        self.assertEqual(kind, "escalate")
        self.assertIn("limit is 1000000 minor units",
                      esc.compressed_context)


class TestUnknownKeys(unittest.TestCase):
    def test_unknown_key_names_never_leak_into_excluded_or_journal(self):
        # Leak fix: unknown keys come from the document, so naming
        # them would leak user data (a name, a phone) into the item
        # and the journal. Only the fixed label goes up.
        key_name = "Иван Иванович Иванов"
        key_phone = "тел +7 700 000-00-02"
        agent = ComplianceAgent()
        doc = _escalating_doc(**{key_name: "x", key_phone: "y"})
        item = agent.review(doc)["escalated"][0]
        self.assertEqual(item["excluded"],
                         ["unknown_field", "unknown_field"])
        self.assertEqual(item["redacted"], 2)
        self.assertNotIn(key_name, item["context"])
        self.assertNotIn(key_phone, item["context"])
        self.assertNotIn(key_name, item["excluded"])
        self.assertNotIn(key_phone, item["excluded"])
        payload = [e["payload"] for e in agent.journal.entries()
                   if e["event"] == "escalate"][0]
        self.assertEqual(payload["excluded"],
                         ["unknown_field", "unknown_field"])
        self.assertNotIn(key_name, str(payload))
        self.assertNotIn(key_phone, str(payload))

    def test_unknown_line_key_is_unknown_field(self):
        item = _escalated_item(_escalating_doc(lines=[
            {"amount_minor": None, "evidence_ref": "E-1",
             "comment": "call +7 700 000-00-02"}]))
        self.assertEqual(item["excluded"], ["unknown_field"])
        self.assertEqual(item["redacted"], 1)
        self.assertNotIn("+7 700 000-00-02", item["context"])
        self.assertNotIn("comment", item["context"])


class TestEvidenceRefSecondLine(unittest.TestCase):
    def test_digit_run_and_iban_rejected_legit_ids_pass(self):
        self.assertFalse(evidence_ref_ok("INV-79000000001"))
        self.assertFalse(evidence_ref_ok("KZ86125KZT5004100100"))
        self.assertTrue(evidence_ref_ok("INV-2026-000045"))
        self.assertTrue(evidence_ref_ok("E-1"))

    def test_digit_run_boundary(self):
        self.assertFalse(evidence_ref_ok("A123456789"))  # 9 digits
        self.assertTrue(evidence_ref_ok("A12345678"))  # 8 digits

    def test_iban_shape_boundary(self):
        self.assertFalse(evidence_ref_ok("AB12" + "C" * 11))  # 15 total
        self.assertTrue(evidence_ref_ok("AB12" + "C" * 10))  # 14 total

    def test_trailing_newline_rejected(self):
        self.assertFalse(evidence_ref_ok("E-1\n"))
        self.assertFalse(
            evidence_ref_ok("123e4567-e89b-12d3-a456-426614174000\n"))

    def test_rejected_ref_absent_and_counted_in_agent(self):
        item = _escalated_item(_escalating_doc(lines=[
            {"amount_minor": None, "evidence_ref": "E-1"},
            {"amount_minor": 100, "evidence_ref": "INV-79000000001"}]))
        self.assertNotIn("79000000001", item["context"])
        self.assertEqual(item["excluded"], ["lines[1].evidence_ref"])
        self.assertEqual(item["redacted"], 1)
        item = _escalated_item(_escalating_doc(lines=[
            {"amount_minor": None, "evidence_ref": "E-1"},
            {"amount_minor": 100, "evidence_ref": "INV-2026-000045"}]))
        self.assertIn("INV-2026-000045", item["context"])


if __name__ == "__main__":
    unittest.main()
