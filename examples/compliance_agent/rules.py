"""Deterministic compliance rules. Amounts are integer minor units
(cents/tiyn) — never floats, so totals reconcile exactly.

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

__all__ = ["RULES", "APPROVAL_LIMIT", "check_document"]

APPROVAL_LIMIT = 1_000_000
_PERIOD_RE = re.compile(r"^\d{4}-P[1-4]$")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


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
    if isinstance(total, int) and total > APPROVAL_LIMIT:
        if doc.get("approver"):
            return _finding("R4", "pass", "over-limit approval present",
                            0.95)
        return _finding("R4", "flag",
                        "total %d over limit %d without approver"
                        % (total, APPROVAL_LIMIT), 0.95)
    return _finding("R4", "pass", "under limit or approver present", 0.95)


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
    if any(_EMAIL_RE.search(text) for text in texts):
        return _finding("R6", "note",
                        "sensitive data present (email) -> redact on "
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
