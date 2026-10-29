"""ComplianceAgent: deterministic rules wired through F.R.I.D.A.Y.

The agent composes FRIDAY primitives directly (one rule = one gated
skill; the router is for single-skill tasks, the agent runs a battery):

- each rule is registered as a Skill with a self-contained battery;
  a failed gate escalates the rule instead of running it;
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
  built from shareable fragments only (sensitive lines redacted and
  counted — they never leave the device);
- a second review of the same doc_id is a reuse hit, not a re-check;
- finalize_anchor() folds the journal into a Merkle batch, signs the
  root and stores inclusion proofs (see friday.anchor).

The escalated-review hook (big_model_review) is intentionally left
unconnected in the demo: when set to a callable, it receives the
escalation dict and its text is attached as "big_model_review". In
the demo it stays None, and escalated findings are reported as
pending review — the demo proves the pipeline, not model intelligence.
"""

from friday import EscalationGate, Journal, Memory, Skill, SkillRegistry
from friday.anchor import AnchorService, HmacSigner, NullTsa
from friday.compress import compress
from friday.memory import SHAREABLE, classify_fragment, redact_text
from examples.compliance_agent.rules import RULES, RULES_VERSION

import hashlib
import json

__all__ = ["ComplianceAgent"]


def _cache_key(doc_id, doc):
    """Cache key: doc id + content hash + rule version.

    A changed document or a changed rule set must not hit an old
    report (F-03, extra-2). RULES_VERSION covers the rule set and the
    report schema: bump it when either changes.
    """
    blob = json.dumps(doc, sort_keys=True, ensure_ascii=False,
                      default=str)
    digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
    return "review:%s:%s:%s" % (doc_id, digest, RULES_VERSION)


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
    """Review documents against the rule battery, on-device first."""

    def __init__(self, memory=None, journal=None, threshold=0.8,
                 local_model=None):
        self.memory = memory or Memory()
        self.journal = journal or Journal()
        self.registry = SkillRegistry()
        for rule_id, description, fn in RULES:
            self.registry.register(_rule_skill(rule_id, description, fn))
        self.gate = EscalationGate(threshold=threshold)
        self.local_model = local_model
        self.anchor_service = AnchorService(
            HmacSigner("friday-demo"), NullTsa(),
            max_leaves=100, max_seconds=3600.0)
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
        cache_key = _cache_key(doc_id, doc)
        cached = self.memory.get(cache_key)
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
                context, redacted = self._shareable_context(doc)
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
        self.memory.put(cache_key, report, "compliance_agent",
                        RULES_VERSION, ttl_s=3600)
        self.journal.append("verdict", {"doc_id": doc_id,
                                        "verdict": verdict})
        return report

    def _shareable_context(self, doc):
        """Compressed doc text with sensitive lines removed."""
        lines = ["doc_id: %s" % (doc.get("doc_id"),),
                 "period: %s" % (doc.get("period"),),
                 "total_minor: %s" % (doc.get("total_minor"),)]
        for idx, line in enumerate(doc.get("lines") or []):
            if isinstance(line, dict):
                lines.append("line %d: amount_minor=%s evidence_ref=%s"
                             % (idx, line.get("amount_minor"),
                                line.get("evidence_ref")))
        for key in ("submitter", "notes"):
            if doc.get(key) is not None:
                lines.append("%s: %s" % (key, doc.get(key)))
        shareable = []
        redacted = 0
        for line in lines:
            if classify_fragment(line) == SHAREABLE:
                shareable.append(line)
            else:
                redacted += 1
        return compress("\n".join(shareable)), redacted

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
