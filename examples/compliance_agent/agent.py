"""ComplianceAgent: deterministic rules wired through F.R.I.D.A.Y.

Merge (Step 4): the agent shares the router's plumbing — registry,
memory, journal, gate object, cache key, escalation-context builder
and anchor service — but it still drives its own rules and gate
decisions (it calls fn(doc) and gate.decide itself and writes its own
journal events). Routing remains in two places, not one; calling the
agent a thin layer over the router would overstate the merge.

- a verdict is PASS only when every rule ran AND none escalated on
  low confidence: a rule that never ran (gate failure) yields
  REVIEW_REQUIRED, never PASS (F-02), and so does a document whose
  findings all passed but were all escalated (Grok audit — a PASS
  stamp on a document the system itself refused to accept locally
  is a contradiction);
- the report carries "gates_failed": rule ids that never ran, so
  partial coverage is visible at report level, not only inside the
  escalated list (Grok audit, mixed-gate case);
- upward payloads carry nothing sensitive: escalation items hold a
  redacted detail, a schema-filtered context, fixed reasons, a
  redacted count, the schema version and the names of withheld fields
  (pass-2 contract; enforced by TestEscalationContract);
- every rule check is journaled; the verdict is journaled;
- findings below the escalation threshold escalate with a context
  built by the pack schema (Step 3) from document fields: only listed
  fields go up, submitter/notes/approver never do, and the redacted
  count includes the withheld fields, so the reviewer sees the
  context is incomplete, not clean;
- a second review of the same doc is a reuse hit, not a re-check;
  reports are cached with sensitivity=SENSITIVE, so the router's
  find() never mixes one document's report into another document's
  escalation context (merge condition 1);
- finalize_anchor() folds the journal into a Merkle batch, signs the
  root and stores inclusion proofs (see friday.anchor), through the
  pair's one anchor service.

The escalated-review hook (big_model_review) is intentionally left
unconnected in the demo: when set to a callable, it receives the
escalation dict and its text is attached as "big_model_review". In
the demo it stays None, and escalated findings are reported as
pending review — the demo proves the pipeline, not model intelligence.
"""

from friday import EscalationGate, Journal, Memory, Skill, SkillRegistry
from friday.anchor import AnchorService, HmacSigner, NullTsa
from friday.memory import SENSITIVE, redact_text
from friday.router import Router, cache_key
from friday.schema import DEFAULT_SCHEMA, PackSchema, apply_schema
from examples.compliance_agent.rules import RULES, RULES_VERSION

__all__ = ["ComplianceAgent"]


def _battery(rule_id, fn, good_doc, bad_doc, good_status="pass"):
    """Self-contained battery: good doc -> good_status, bad doc -> flag."""
    return [
        ("good doc -> " + good_status,
         lambda fn=fn, doc=good_doc: fn(doc)["status"] == good_status),
        ("bad doc -> flag",
         lambda fn=fn, doc=bad_doc: fn(doc)["status"] == "flag"),
    ]


_GOOD_DOC = {
    "doc_id": "T-1", "period": "2026-P1", "total_minor": 100,
    "lines": [{"amount_minor": 100, "evidence_ref": "E-1"}],
    "submitter": "Tester",
}
_BAD_DOCS = {
    "R1": {"period": "2026-P1"},
    "R2": {"doc_id": "T-1", "period": "2026-P1", "total_minor": 100,
           "lines": [{"amount_minor": 90, "evidence_ref": "E-1"}],
           "submitter": "Tester"},
    "R3": {"doc_id": "T-1", "period": "soon", "total_minor": 100,
           "lines": [{"amount_minor": 100, "evidence_ref": "E-1"}],
           "submitter": "Tester"},
    "R4": {"doc_id": "T-1", "period": "2026-P1", "total_minor": 9_999_999,
           "lines": [{"amount_minor": 9_999_999, "evidence_ref": "E-1"}],
           "submitter": "Tester"},
    "R5": {"doc_id": "T-1", "period": "2026-P1", "total_minor": 100,
           "lines": [{"amount_minor": 100, "evidence_ref": ""}],
           "submitter": "Tester"},
    "R6": {"doc_id": "T-1", "period": "2026-P1", "total_minor": 100,
           "lines": [{"amount_minor": 100, "evidence_ref": "E-1"}],
           "submitter": "a@b.com"},
}


def _rule_skill(rule_id, description, fn):
    def run(task_doc):
        finding = fn(task_doc)
        return finding["detail"], finding["confidence"]

    if rule_id == "R6":
        battery = [
            ("sensitive mail is noted",
             lambda: fn(_BAD_DOCS["R6"])["status"] == "note"),
            ("clean doc is noted clean",
             lambda: fn(_GOOD_DOC)["status"] == "note"),
        ]
    else:
        battery = _battery(rule_id, fn, _GOOD_DOC, _BAD_DOCS[rule_id])
    return Skill("rule_" + rule_id, RULES_VERSION, run, battery,
                 description=description)


class ComplianceAgent:
    """Review documents against the rule battery, on-device first.

    Shares a Router's plumbing (merge): the agent's attributes memory,
    journal, registry, gate and anchor_service are the router's
    objects, shared by reference. But the agent still drives its own
    rules and gate decisions — it calls fn(doc) and gate.decide itself
    and writes its own journal events — so routing remains in two
    places, not one. Constructing with memory=/journal= still works
    (back-compat): an internal router is built around them. Passing
    router= uses that router's plumbing; threshold then applies only
    to the internal router (a given router keeps its own gate).
    Passing anchor_service= shares one anchor service with the
    router; otherwise the demo HMAC service is built once and stored
    on the router, so finalize_anchor() always uses the pair's one
    service.
    """

    def __init__(self, memory=None, journal=None, threshold=0.8,
                 local_model=None, router=None, anchor_service=None,
                 schema_config=None):
        if router is None:
            registry = SkillRegistry()
            router = Router(registry,
                            memory if memory is not None else Memory(),
                            journal if journal is not None else Journal(),
                            EscalationGate(threshold=threshold))
        self.router = router
        self.memory = router.memory
        self.journal = router.journal
        self.registry = router.registry
        self.gate = router.gate
        # Step 3: the pack schema is the allowlist for upward payloads.
        # A non-default config is journaled at load, before any
        # review, so a widening is in the append-only journal first;
        # the default schema adds no event (demo journal stays 24).
        if schema_config is not None:
            self.schema = PackSchema.from_config(schema_config)
            self.journal.append("schema", self.schema.journal_record())
        else:
            self.schema = DEFAULT_SCHEMA
        for rule_id, description, fn in RULES:
            self.registry.register(_rule_skill(rule_id, description, fn))
        service = (anchor_service or router.anchor_service
                   or AnchorService(HmacSigner("friday-demo"), NullTsa(),
                                    max_leaves=100, max_seconds=3600.0))
        router.anchor_service = service
        self.anchor_service = service
        self.local_model = local_model
        self.big_model_review = None  # hook, see module docstring
        self.reviews = 0
        self.reuse_hits = 0
        self.findings_total = 0
        self.escalated_total = 0
        self.full_chars = 0
        self.up_chars = 0

    def review(self, doc):
        """Review one document. Returns a report dict.

        Terminal-event invariant (A4): every call ends with exactly
        one terminal journal event — "verdict" (completed), "reuse"
        (cached) or "error" (raised). On error the event is written
        and the exception re-raised, never swallowed; a failure to
        write the event must not mask the original error. The error
        event carries doc_id and the exception type only — never the
        message verbatim (it may carry document fragments). Which
        rule failed is inferable from the preceding rule_check events.
        """
        doc_id = doc.get("doc_id", "?") if isinstance(doc, dict) else "?"
        try:
            return self._review_inner(doc, doc_id)
        except Exception as exc:
            try:
                self.journal.append("error", {
                    "doc_id": doc_id, "error": type(exc).__name__})
            except Exception:
                pass  # journal failure must not mask the original error
            raise

    def _review_inner(self, doc, doc_id):
        key = cache_key("compliance_agent", RULES_VERSION, doc)
        cached = self.memory.get(key)
        if cached is not None:
            self.reuse_hits += 1
            self.journal.append("reuse", {"doc_id": doc_id})
            report = dict(cached)
            report["reuse_hit"] = True
            return report

        self.reviews += 1
        findings = []
        escalated = []
        gates_failed = []
        for rule_id, _description, fn in RULES:
            skill, gate_report = self.registry.get_gated("rule_" + rule_id)
            if skill is None:
                gates_failed.append(rule_id)
                escalated.append({
                    "rule_id": rule_id, "reason": "gate_failed",
                    "context": "", "redacted": 0,
                    "detail": gate_report["failures"],
                })
                self.journal.append("rule_gate_failed", {
                    "doc_id": doc_id, "rule_id": rule_id})
                continue
            finding = fn(doc)
            findings.append(finding)
            self.journal.append("rule_check", {
                "doc_id": doc_id, "rule_id": rule_id,
                "status": finding["status"],
                "confidence": finding["confidence"],
            })
            if self.gate.decide(finding["confidence"]) == "escalate":
                # Step 3 (schema redaction): the agent no longer builds
                # string lines for the router builder. Fields pass
                # through the pack schema; only listed fields reach
                # the context, never-fields and unknown fields are
                # withheld and counted, and the withheld NAMES (schema
                # labels, never values) ride along so the reviewer
                # sees exactly what is missing.
                context, redacted, excluded = apply_schema(doc,
                                                           self.schema)
                # Detail is part of the upward payload: redact it the
                # same way as the task, so a present or future rule
                # embedding raw document values cannot leak through it.
                detail = redact_text(finding["detail"])
                item = {"rule_id": rule_id, "reason": "low_confidence",
                        "context": context, "redacted": redacted,
                        "detail": detail, "schema": self.schema.version,
                        "excluded": excluded}
                if self.local_model is not None:
                    prompt = (
                        "Compliance finding %s: %s\n"
                        "Shareable context only:\n%s\n"
                        "Give a short judgment: what should the "
                        "reviewer do next?"
                        % (rule_id, detail, context))
                    result = self.local_model.generate(prompt, budget=512)
                    parts = tuple(result)
                    if len(parts) == 3:
                        text, confidence, source = parts
                    elif len(parts) == 2:
                        # Old models return no source (A6): accept
                        # them as "unattributed", never crash.
                        text, confidence = parts
                        source = "unattributed"
                    else:
                        raise ValueError(
                            "local model must return (text, confidence) "
                            "or (text, confidence, source)")
                    item["model_review"] = {
                        "text": text, "confidence": confidence,
                        "source": source,
                        "gate": self.gate.decide(confidence)}
                    self.journal.append("model_review", {
                        "doc_id": doc_id, "rule_id": rule_id,
                        "confidence": confidence, "source": source})
                if self.big_model_review is not None:
                    item["big_model_review"] = self.big_model_review(item)
                escalated.append(item)
                self.journal.append("escalate", {
                    "doc_id": doc_id, "rule_id": rule_id,
                    "redacted": redacted, "schema": self.schema.version,
                    "excluded": excluded})

        verdict = "PASS"
        if any(f["status"] in ("flag", "unsure") for f in findings):
            verdict = "FLAGGED"
        elif (gates_failed or len(findings) != len(RULES)
              or any(item["reason"] == "low_confidence"
                     for item in escalated)):
            # A rule that never ran must not yield PASS (F-02), and
            # neither must a document whose findings all passed but
            # were escalated on low confidence (Grok audit): the
            # system refused its own local answers, so the document
            # is REVIEW_REQUIRED, not clean.
            verdict = "REVIEW_REQUIRED"
        report = {
            "doc_id": doc_id,
            "verdict": verdict,
            "findings": findings,
            "escalated": escalated,
            "gates_failed": gates_failed,
            "reuse_hit": False,
        }
        self.findings_total += len(findings)
        self.escalated_total += len(escalated)
        self.full_chars += len(str(doc))
        self.up_chars += sum(len(item["context"]) for item in escalated)
        # Reports are cached SENSITIVE (merge condition 1): the
        # router's find() never returns them, so one document's
        # report cannot leak into another's escalation context.
        # Direct key access via get() still reuses them.
        self.memory.put(key, report, "compliance_agent",
                        RULES_VERSION, ttl_s=3600, sensitivity=SENSITIVE)
        self.journal.append("verdict", {"doc_id": doc_id,
                                        "verdict": verdict})
        return report

    def finalize_anchor(self, force=True):
        """Anchor the journal. Returns an AnchorRecord or None."""
        return self.anchor_service.anchor_pending(self.journal,
                                                  force=force)

    def summary(self):
        """Measured metrics across reviews (token figure is an estimate:
        characters / 4, labelled as such wherever it is shown)."""
        saved_chars = self.full_chars - self.up_chars
        return {
            "reviews": self.reviews,
            "reuse_hits": self.reuse_hits,
            "findings_total": self.findings_total,
            "escalated_total": self.escalated_total,
            "escalation_rate": (self.escalated_total / self.findings_total
                                if self.findings_total else 0.0),
            "estimated_tokens_saved": saved_chars / 4,
            "journal_entries": len(self.journal),
        }
