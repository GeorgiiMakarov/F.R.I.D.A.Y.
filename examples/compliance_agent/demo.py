"""Demo: compliance agent on F.R.I.D.A.Y. (no model, no network).

Three documents, three stories:
1. DOC_OK — clean: PASS, everything local.
2. DOC_MISMATCH — totals and evidence fail: FLAGGED, everything local.
3. DOC_SENSITIVE — over limit without approver, one undecidable line,
   and an email address: FLAGGED, one finding escalated, the email
   redacted from the escalation context (it never leaves the device).

Then: a reuse hit on DOC_OK, a Merkle-anchored journal batch with an
offline inclusion proof, and measured metrics. This script is the
reference walkthrough: three documents end to end.
"""

from examples.compliance_agent.agent import ComplianceAgent
from examples.compliance_agent.samples import (
    DOC_MISMATCH,
    DOC_OK,
    DOC_SENSITIVE,
)
from friday.local_model import StubLocalModel

STUB_ANSWERS = {
    "line amount missing": (
        "Cannot verify totals: one line has no integer amount. Ask "
        "the submitter for a corrected document with all amounts "
        "present; do not approve on partial sums.", 0.85),
}


def _show(report):
    print("doc %s -> verdict %s (reuse_hit=%s)"
          % (report["doc_id"], report["verdict"], report["reuse_hit"]))
    for finding in report["findings"]:
        print("  %s %-7s conf %.2f  %s"
              % (finding["rule_id"], finding["status"],
                 finding["confidence"], finding["detail"]))
    for item in report["escalated"]:
        print("  ESCALATED %s reason=%s redacted=%d"
              % (item["rule_id"], item["reason"], item["redacted"]))
        print("    context: %r" % (item["context"],))
        if "model_review" in item:
            review = item["model_review"]
            print("    local model review (conf %.2f, gate %s): %s"
                  % (review["confidence"], review["gate"],
                     review["text"]))
        if "big_model_review" not in item:
            print("    big-model review: PENDING (hook not connected "
                  "in this demo — no model call is faked)")


def main():
    agent = ComplianceAgent(
        local_model=StubLocalModel(STUB_ANSWERS))
    print("== F.R.I.D.A.Y. compliance demo ==")
    for doc in (DOC_OK, DOC_MISMATCH, DOC_SENSITIVE):
        _show(agent.review(doc))
        print()

    print("== reuse ==")
    _show(agent.review(DOC_OK))
    print()

    print("== anchor ==")
    record = agent.finalize_anchor()
    print("batch %s leaves %d root %s"
          % (record.batch_id[:12], record.leaf_count, record.root_hex))
    first = agent.journal.entries()[0]["hash"]
    print("first entry inclusion proof verifies:",
          agent.anchor_service.verify_proof(
              first, record.proofs[first], record.root_hex))
    ok, bad = agent.journal.verify()
    print("journal verifies:", ok, "bad index:", bad)

    print()
    print("== measured metrics ==")
    for key, value in agent.summary().items():
        print(" ", key, "=", value)
    print("note: estimated_tokens_saved uses chars/4 and is an "
          "estimate, not a benchmark")


if __name__ == "__main__":
    main()
