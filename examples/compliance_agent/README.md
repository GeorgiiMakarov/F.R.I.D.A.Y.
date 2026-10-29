# Compliance pre-check: reference rule pack

A compliance pre-check engine for regulated-company documents,
on-device, on F.R.I.D.A.Y.: the reference implementation of the
product's first rule pack. Deterministic rules decide; a local model
advises; nothing sensitive leaves the device.

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

## What the reference implementation shows (and what it does not)

Shows: gated rules, reuse, escalation with redaction, hash-chained
journal, Merkle anchoring with offline proof verification, and measured
metrics (escalation rate, token estimate).

Does NOT show: model intelligence. The rules are deterministic and the
big-model review hook is intentionally unconnected in the demo —
escalated findings report as PENDING, and no model call is faked.
The claim is verifiability, cost and data locality.

## Model in the loop

Deterministic rules decide the verdict; a local model judges only
what the rules cannot decide. Pass a `LocalModel` to `ComplianceAgent`
and every escalated finding gets a `model_review` (text, confidence,
gate decision), journaled like everything else. The model never
overrides a flag: an undecidable document stays FLAGGED even when the
model is confident — verification blocks, the model advises.

The bundled demo uses `StubLocalModel` (canned answers, labelled).
For a real small model, point the agent at a local server:

```bash
python3 -m examples.compliance_agent.run_with_model \
    --base-url http://localhost:11434/v1 --model qwen2.5:3b
```

Save that script's output as the recorded run: model, device,
elapsed time and metrics. A recorded real-model run is still pending
hardware — the stub demo proves the loop, not model quality.

## Run it

```bash
python3 -m unittest tests.test_demo_agent -v
python3 -m examples.compliance_agent.demo
```

## What this proves for a buyer

- Real problem: routine compliance checks for regulated companies.
- Measurable impact: escalation rate, estimated tokens saved
  (chars/4, labelled as an estimate), journal completeness — all
  printed by the demo, not asserted.
- Scalable product: this is one rule pack on the F.R.I.D.A.Y.
  engine; new document types are new rule packs, not new systems.
- Data locality: sensitive fragments are classified and redacted
  before escalation; the demo proves the email never appears in the
  escalation context.

## Plugging in a real local model

Set `agent.big_model_review` to a callable taking an escalation dict
and returning review text. The natural next step is a small model
behind `friday.local_model` answering only escalated findings — the
routine 95% stays deterministic and free.
