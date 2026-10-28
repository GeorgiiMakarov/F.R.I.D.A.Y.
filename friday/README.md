# F.R.I.D.A.Y.

**F**ederated **R**easoning **I**nterface for **D**elegation, **A**udit and **Y**ield.
(Name expansion proposed; the engine stands on its own.)

A local-first delegation engine for small on-device models (4 GB class,
top smartphones and laptops). The local layer owns context, memory and
compute; the large model is consulted only on escalation. Delegation
happens **under verification**: nothing is reused, compressed or sent up
without a check that can fail.

## The eight skills (learned from frontier-model work)

1. **Calibrated escalation.** Routing by measured confidence, with the
   threshold set from a calibration set on the actual delegation tasks.
   Both error directions are counted: false escalations (wasted cost)
   and missed escalations (quality loss).
2. **Effect-gated skills.** Every skill ships with its own acceptance
   battery. A failed gate blocks reuse and forces escalation.
3. **Hash-chained journal.** Every action is appended to a
   tamper-evident chain. The head hash can be anchored externally
   (this repo's Merkle/TSA anchoring fits here).
4. **Local memory and cache.** Indexed, fresh-only reuse of verified
   results. Expired or unverified entries are invisible.
5. **Loss-aware compression.** Extractive only: numbers, constraints,
   names and quoted text survive verbatim; summaries link to sources.
6. **Result reuse.** Same task, fresh verified result — no re-reasoning.
7. **Fragment classification.** Shareable vs. sensitive, checked before
   anything leaves the device. Relevance filtering alone is NOT data
   protection; the built-in classifier is a rule-based stub to be
   replaced by a measured local classifier.
8. **Skill back-transfer (offline).** Verified journaled traces become
   training pairs for adapters; an adapter ships as a new skill version
   behind the same gate. The runtime never trains on live traffic.

## What is deliberately NOT here

- **KV-cache sharing between models.** A small local model cannot pick
  up a large model's KV cache: it depends on architecture, weights and
  data layout. The shared layer is external memory (documents, indexes,
  summaries, tool results), not internal attention state.
- **Prompt-cache sharing between models.** Prefix caches are per-model
  and per-provider. Local reuse works for repeated local calls.
- **Paraphrase compression.** Paraphrase is where critical details
  silently change, so compression here is extractive only.

## Layout

```
friday/
  __init__.py      exports
  escalation.py    confidence gate + two-sided error accounting
  gates.py         skill batteries + registry with gate enforcement
  journal.py       hash-chained append-only journal (DIC I6/I7)
  events.py        event envelope, opaque runtime_context (DIC)
  dic_merkle.py    Merkle tree, proofs, batch builder (from DIC)
  anchor.py        close -> sign root -> timestamp -> proof rows
  memory.py        fresh-only store + fragment classification
  compress.py      extractive compression + fidelity battery
  router.py        reuse -> local skill -> escalation
  local_model.py   model adapter interface + HTTP adapter + stub
  skills.py        built-in skills: retrieve, summarise, verify
  skill_trace.py   offline back-transfer export (JSONL)
  demo.py          end-to-end demo, no model, no network
tests/
  test_friday.py   stdlib unittest suite
```

## Built on decision-intelligence-core

See the root README for the provenance table. In short: the Merkle
machinery, the anchor flow, the Signer/TSA protocol shapes, the
append-only audit-trail shape and the event envelope come from DIC,
adapted to stdlib-only dataclasses for on-device use. FastAPI, gRPC,
Kafka, Redis, Postgres and pydantic were deliberately left behind.

## Run it

```bash
python3 -m unittest tests.test_friday -v
python3 -m friday.demo
```

Standard library only. No weights included and no vendor lock-in: any
local model that can serve `generate(prompt, budget)` works — llama.cpp
server, Ollama, MLX server, or any OpenAI-compatible endpoint (see
`local_model.OpenAICompatibleLocalModel`).

## Running on a 4 GB model

- Weights: a 4-bit quantised 4B model (~4 GB) leaves room for context on
  devices with 8 GB+ RAM.
- Working budget: keep it small (2k tokens is a sane default) and let
  the router escalate anything bigger or less confident.
- Outputs: prefer short, structured outputs (JSON, lists). Small models
  stay faithful on short outputs and drift on long ones.
- Cache first: identical prompts must hit memory before they hit the
  model — that is the cheapest token saving in the whole design.

## Measuring it (the evidence this design owes)

- Tokens, money and latency saved against a full-context baseline.
- Fidelity: agreement rate between decisions on full vs. compressed
  context (`compress.fidelity_check`), measured, not promised.
- Escalation: rate, false-escalation rate, missed-escalation rate,
  and escalation accuracy (`EscalationGate.report`).
- Detail loss: critical details (numbers, constraints, names) present
  in the full context but missing after compression — must be zero
  for kept-line classes, measured by the fidelity battery.
