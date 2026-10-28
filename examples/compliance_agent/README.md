# Compliance demo agent (Business category)

An agent that reviews regulated-company documents against deterministic
rules, on-device, on F.R.I.D.A.Y. Built as the entry prototype for the
Dubai Create AI Agents Championship, Best Business AI Agent category.

## The problem it solves

Regulated companies pay humans (or expensive big-model calls) to check
routine documents: payout reports, expense claims, vendor statements.
Most checks are mechanical — fields present, totals reconcile, limits
respected, evidence attached — but failures are expensive, and sending
every document to a cloud model leaks sensitive data and costs tokens
on every page.

This agent does the mechanical checks locally, escalates only what it
cannot decide, redacts sensitive fragments before anything leaves the
device, and journals every step into a Merkle-anchored batch with
offline inclusion proofs.

## Rules (amounts are integer minor units, never floats)

| Rule | Check | On failure |
|---|---|---|
| R1 | Required fields present | FLAGGED |
| R2 | Line amounts sum to the total | FLAGGED (or ESCALATED if undecidable) |
| R3 | Period format `YYYY-P[1-4]` | FLAGGED |
| R4 | Total over the limit needs an approver | FLAGGED |
| R5 | Every line has an evidence ref | FLAGGED |
| R6 | Sensitive patterns present | NOTE (redaction required, never a violation) |

Verdict is PASS only when every finding is pass or note. Anything
flagged or undecidable is FLAGGED.

## What the demo shows (and what it does not)

Shows: gated rules, reuse, escalation with redaction, hash-chained
journal, Merkle anchoring with offline proof verification, and measured
metrics (escalation rate, token estimate).

Does NOT show: model intelligence. The rules are deterministic and the
big-model review hook is intentionally unconnected in the demo —
escalated findings report as PENDING, and no model call is faked.
The claim is verifiability, cost and data locality.

## Run it

```bash
python3 -m unittest tests.test_demo_agent -v
python3 -m examples.compliance_agent.demo
```

## How it maps to the championship criteria

- Real problem: routine compliance checks for regulated companies.
- Measurable impact: escalation rate, estimated tokens saved
  (chars/4, labelled as an estimate), journal completeness — all
  printed by the demo, not asserted.
- Scalable business: the agent is one product on the F.R.I.D.A.Y.
  engine; new document types are new rule batteries, not new systems.
- Data locality: sensitive fragments are classified and redacted
  before escalation; the demo proves the email never appears in the
  escalation context.

## Plugging in a real local model

Set `agent.big_model_review` to a callable taking an escalation dict
and returning review text. The natural next step is a small model
behind `friday.local_model` answering only escalated findings — the
routine 95% stays deterministic and free.
