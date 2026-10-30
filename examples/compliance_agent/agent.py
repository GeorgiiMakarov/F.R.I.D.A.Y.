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
  redacted detail, a shareable-only context, fixed reasons and a
  redacted count (pass-2 contract; enforced by TestEscalationContract);
- every rule check is journaled; the verdict is journaled;
- findings below the escalation threshold escalate with a context
  built by the router's single builder from document-field lines
  WITHOUT submitter/notes (excluded until Step 3: the rules going up
  do not need them, and the denylist does not catch names). The
  redacted count includes the excluded lines, so the reviewer sees
  the context is incomplete, not clean;
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
                 local_model=None, router=None, anchor_service=None):
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
        """Review one document. Returns a report dict."""
        doc_id = doc.get("doc_id", "?")
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
                # Single builder (merge): document-field lines WITHOUT
                # submitter/notes — the rules going up do not need
                # them, and the denylist does not catch names, so
                # passing them would leak names until Step 3.
                lines = ["doc_id: %s" % (doc.get("doc_id"),),
                         "period: %s" % (doc.get("period"),),
                         "total_minor: %s" % (doc.get("total_minor"),)]
                for idx, line in enumerate(doc.get("lines") or []):
                    if isinstance(line, dict):
                        lines.append(
                            "line %d: amount_minor=%s evidence_ref=%s"
                            % (idx, line.get("amount_minor"),
                               line.get("evidence_ref")))
                context, redacted = Router.build_escalation_context(lines)
                # Excluded fields count as withheld (merge fix): the
                # reviewer must see that the context is incomplete.
                # submitter/notes never reach the builder (until
                # Step 3), so without this the count would read 0
                # on DOC-003 even though two lines were withheld.
                redacted += sum(1 for k in ("submitter", "notes")
                                if doc.get(k) is not None)
                # Detail is part of the upward payload: redact it the
                # same way as the task, so a present or future rule
                # embedding raw document values cannot leak through it.
                detail = redact_text(finding["detail"])
                item = {"rule_id": rule_id, "reason": "low_confidence",
                        "context": context, "redacted": redacted,
                        "detail": detail}
                if self.local_model is not None:
                    prompt = (
                        "Compliance finding %s: %s\n"
                        "Shareable context only:\n%s\n"
                        "Give a short judgment: what should the "
                        "reviewer do next?"
                        % (rule_id, detail, context))
                    text, confidence = self.local_model.generate(
                        prompt, budget=512)
                    item["model_review"] = {
                        "text": text, "confidence": confidence,
                        "gate": self.gate.decide(confidence)}
                    self.journal.append("model_review", {
                        "doc_id": doc_id, "rule_id": rule_id,
                        "confidence": confidence})
                if self.big_model_review is not None:
                    item["big_model_review"] = self.big_model_review(item)
                escalated.append(item)
                self.journal.append("escalate", {
                    "doc_id": doc_id, "rule_id": rule_id,
                    "redacted": redacted})

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
