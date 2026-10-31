# Regression seed (compliance pack)

Synthetic documents with fixed expected verdicts. This is a
regression seed, not a calibration corpus: it guards the rules
against regressions, it does not calibrate the threshold — the
distribution of synthetic documents is not the clients' distribution.

## Files

- `dev.jsonl` (16 docs): iteration set. Rules and prompts may be
  tuned against dev.
- `test.jsonl` (8 docs): held out. The model run on test happens
  once per version; tuning to test is not allowed — otherwise the
  test number means nothing. (The deterministic rules test in
  `tests/test_seed.py` runs on every suite run — it checks rules,
  not prompts, so it carries no fitting risk.)

## Line format (JSONL, one document per line)

```json
{"id": "DEV-001",
 "doc": {"doc_id": "...", "period": "2026-P1", "total_minor": 500000,
         "lines": [{"amount_minor": 300000, "evidence_ref": "INV-1"}],
         "submitter": "Ivanov"},
 "expected": {"report_doc_id": "DEV-001", "verdict": "PASS",
              "findings": {"R1": "pass", "R2": "pass", "R3": "pass",
                           "R4": "pass", "R5": "pass", "R6": "note"},
              "escalated": [],
              "r6_sensitive": false}}
```

- `verdict`: PASS / FLAGGED (REVIEW_REQUIRED needs a gate failure,
  which documents alone cannot trigger).
- `findings`: per-rule status from `rules.py`.
- `escalated`: rule ids with a low_confidence escalation item
  (exactly the `unsure` rules: confidence 0.3 < threshold 0.8).
- `r6_sensitive`: whether R6's note reports sensitive data present.
  R6 is a note in all cases — it never flags a document.
- `report_doc_id`: the report's doc_id; `"?"` when the document
  has no `doc_id` (the agent's fallback).

## How to check

Committed deterministic test: `tests/test_seed.py` (fresh agent
per document, no model). It compares verdict, per-rule statuses,
escalated rule ids, report doc_id and the R6 sensitive flag
against `expected`.
A mismatch is investigated, not papered over:

- document does not express its intent (typo, wrong field) →
  fix the document;
- expectation misreads the rule spec → fix the expectation;
- rule implementation diverges from its spec → record as a
  known failure below, never adjust the expectation to match
  the bug.

## Known failures

None at seed v1 (24/24 match, verified 2026-10-31; enforced by
`tests/test_seed.py` on every suite run).

## Honest limits

The dev/test split guards against prompt fitting, but not
against the synthetic author's blind spots.

The seed contains only 10 escalated decisions (6 in dev, 4 in
test): this is a pipeline smoke test, not calibration.

## Run gate

The model run on this seed (3B–4B, Georgiy's hardware, procedure
ollama + run_with_model) is allowed only after Block A items
A1, A3, A4, A5, A6. The run record fixes model, quantization, prompt
and temperature, plus date and seed version.
