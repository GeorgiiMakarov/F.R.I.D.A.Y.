"""Compliance pre-check built on F.R.I.D.A.Y.

The reference rule pack: reviews regulated-company documents (payout
reports, expense claims) against deterministic rules, on-device, with
every step gated, journaled and anchored.

What this proves (and what it honestly does NOT):
- proves: rule checks with acceptance gates, reuse, escalation with
  redaction of sensitive fragments, hash-chained journal, Merkle
  batch anchoring with offline inclusion proofs, and measured metrics
  (escalation rate, token estimate);
- does NOT prove: model intelligence. The rules are deterministic;
  the "big-model review" of escalated findings is a clearly marked
  SIMULATED hook in the demo. The product claim is verifiability,
  cost and data locality — not that a small model out-reasons a big one.
"""

from examples.compliance_agent.agent import ComplianceAgent
from examples.compliance_agent.samples import (
    DOC_MISMATCH,
    DOC_OK,
    DOC_SENSITIVE,
)

__all__ = ["ComplianceAgent", "DOC_OK", "DOC_MISMATCH", "DOC_SENSITIVE"]
