"""Deterministic compliance rules. Amounts are integer minor units
(cents/tiyn) — never floats, so totals reconcile exactly — and must
be non-negative: a negative total or line amount is flagged (extra-1).

Each rule returns a finding dict:
  {rule_id, status, detail, confidence}
status: "pass" | "flag" | "unsure" | "note".
- "flag" means the document violates the rule (verdict FLAGGED).
- "unsure" means the rule cannot be decided from the data (verdict
  FLAGGED for review, and the finding escalates).
- "note" is a handling note, not a violation (e.g. sensitive data
  present -> redaction required). Notes never flag a document.

Confidences are fixed by construction, not estimated: deterministic
rules on complete data are 0.9-0.98; undecidable rules are 0.3 so the
escalation gate routes them up. A rule that cannot estimate its
confidence must return 0.0 (escalate), never a guessed number.
"""

import re

from friday.memory import SENSITIVE, classify_fragment

__all__ = ["RULES", "RULES_VERSION", "APPROVAL_LIMIT", "check_document"]

# Bumped whenever the rule set or the report schema changes. The agent
# includes this version in its cache key, so a rule change invalidates
# old cached reports (extra-2). 0.3.0: R4 unsure on missing/negative/
# non-integer totals, R6 on the engine's sensitivity patterns (Grok).
RULES_VERSION = "0.3.0"

APPROVAL_LIMIT = 1_000_000
_PERIOD_RE = re.compile(r"^\d{4}-P[1-4]$")


def _finding(rule_id, status, detail, confidence):
    return {"rule_id": rule_id, "status": status,
            "detail": detail, "confidence": confidence}


def r1_required_fields(doc):
    missing = [f for f in ("doc_id", "period", "total_minor", "lines",
                           "submitter") if f not in doc]
    if missing:
        return _finding("R1", "flag", "missing fields: " + ",".join(missing),
                        0.95)
    if not isinstance(doc["lines"], list):
        return _finding("R1", "flag", "lines is not a list", 0.95)
    return _finding("R1", "pass", "all required fields present", 0.95)


def r2_totals(doc):
    lines = doc.get("lines")
    if not isinstance(lines, list):
        return _finding("R2", "unsure", "no lines to reconcile", 0.3)
    amounts = []
    for line in lines:
        amount = line.get("amount_minor") if isinstance(line, dict) else None
        if not isinstance(amount, int) or isinstance(amount, bool):
            return _finding("R2", "unsure",
                            "line amount missing or not an integer", 0.3)
        amounts.append(amount)
    total = doc.get("total_minor")
    if not isinstance(total, int) or isinstance(total, bool):
        return _finding("R2", "unsure", "total missing or not an integer",
                        0.3)
    if total < 0 or any(a < 0 for a in amounts):
        return _finding("R2", "flag", "negative amounts not allowed",
                        0.98)
    if sum(amounts) == total:
        return _finding("R2", "pass",
                        "lines sum %d == total %d" % (sum(amounts), total),
                        0.98)
    return _finding("R2", "flag",
                    "lines sum %d != total %d" % (sum(amounts), total),
                    0.98)


def r3_period(doc):
    period = doc.get("period", "")
    if _PERIOD_RE.match(str(period)):
        return _finding("R3", "pass", "period format ok", 0.95)
    return _finding("R3", "flag", "bad period format: %r" % (period,),
                    0.95)


def r4_approval(doc):
    total = doc.get("total_minor")
    if not isinstance(total, int) or isinstance(total, bool):
        # No total to judge approval against: unsure, not pass (Grok).
        # The old code passed here with "under limit or approver
        # present" — a lie when there is no total at all, and a lie
        # for floats, which are not valid minor units.
        return _finding("R4", "unsure",
                        "total missing or not an integer", 0.3)
    if total < 0:
        return _finding("R4", "unsure", "negative total", 0.3)
    if total > APPROVAL_LIMIT:
        if doc.get("approver"):
            return _finding("R4", "pass", "over-limit approval present",
                            0.95)
        return _finding("R4", "flag",
                        "total %d over limit %d without approver"
                        % (total, APPROVAL_LIMIT), 0.95)
    return _finding("R4", "pass", "under limit", 0.95)


def r5_evidence(doc):
    lines = doc.get("lines")
    if not isinstance(lines, list):
        return _finding("R5", "unsure", "no lines to check evidence for",
                        0.3)
    missing = [i for i, line in enumerate(lines)
               if not (isinstance(line, dict) and line.get("evidence_ref"))]
    if missing:
        return _finding("R5", "flag",
                        "lines without evidence_ref: %s" % (missing,), 0.9)
    return _finding("R5", "pass", "all lines have evidence_ref", 0.9)


def r6_sensitive(doc):
    texts = []

    def walk(value):
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(doc)
    # Same definition of sensitive as the engine classifier (Grok):
    # the old email-only check reported "no sensitive patterns found"
    # for "password is hunter2", while the engine flagged it.
    if any(classify_fragment(text) == SENSITIVE for text in texts):
        return _finding("R6", "note",
                        "sensitive data present -> redact on "
                        "escalation", 0.95)
    return _finding("R6", "note", "no sensitive patterns found", 0.95)


RULES = [
    ("R1", "required fields", r1_required_fields),
    ("R2", "totals reconcile", r2_totals),
    ("R3", "period format", r3_period),
    ("R4", "over-limit approval", r4_approval),
    ("R5", "evidence refs", r5_evidence),
    ("R6", "sensitive scan", r6_sensitive),
]


def check_document(doc):
    """Run all rules; returns a list of findings in rule order."""
    return [fn(doc) for _, _, fn in RULES]
