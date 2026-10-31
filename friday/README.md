# F.R.I.D.A.Y.

**F**ail-closed **R**easoning **I**nterface for **D**elegation, **A**udit and **Y**ield.
(Name expansion proposed; the engine stands on its own.)

A local-first delegation engine for small on-device models (4 GB class,
top smartphones and laptops). The local layer owns context, memory and
compute; the large model is consulted only on escalation. Delegation
happens **under verification**: nothing is reused, compressed or sent up
without a check that can fail.

Two contours, one plumbing: the agent runs a battery of rules, the
router routes single-skill tasks; they share memory, journal, cache
key, and anchor service — only the call sites
(get_gated, gate.decide, escalation assembly) are duplicated,
deliberately. Redaction split in Step 3: the agent path filters
document fields through the pack schema (allowlist), the router path
still filters fragment strings through the denylist builder.

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
4. **Local memory and cache.** Indexed, fresh-only reuse of gate-passed
   results. Expired entries are invisible.
5. **Loss-aware compression.** Extractive only: numbers, constraints,
   names and quoted text survive verbatim; summaries link to sources.
6. **Result reuse.** Same task, fresh gate-passed result — no re-reasoning.
7. **Fragment classification.** Shareable vs. sensitive, checked before
   anything leaves the device. Relevance filtering alone is NOT data
   protection; the built-in classifier is a rule-based stub to be
   replaced by a measured local classifier.
8. **Skill back-transfer (offline).** Reviewed journaled traces become
   training pairs for adapters; an adapter ships as a new skill version
   behind the same gate. The runtime never trains on live traffic.

Step 3 (schema redaction): the agent path sends up only fields listed
in the pack schema (doc_id, period, total_minor, line amounts and
evidence_refs by default); submitter, notes and approver never go up,
and no pack config can open them. `evidence_ref` is allowed by format
(UUID or a letter-first id up to 40 chars), minus 9+ digit runs and
IBAN-shaped strings, not by sensitivity regex. Withheld fields are
reported by known schema labels plus a fixed `unknown_field` label —
unknown document keys are never named, because the key text itself
may be user data. Honest residual: a spaceless name (JohnDoe) in
`evidence_ref` passes the format — that is a pack-author error, not
protection. Same for a dash-split phone (INV-7900-000-00-01): no
9-digit run accumulates, and a total digit limit would reject honest
date-bearing refs — again a pack-author error. The router path withholds the task text entirely
(option A) and caches skill answers SENSITIVE unless the skill
declares its output shareable.

Regression seed (examples/compliance_agent/corpus/): synthetic
documents with fixed expected verdicts, split into dev (iteration)
and test (held out). The seed guards the rules against regressions;
it does not calibrate the threshold. The dev/test split guards
against prompt fitting, but not against the synthetic author's
blind spots. The journal records withheld field
names and the schema version — counts, never values.

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
  persistence.py   durable journal file (format v1) + pilot-mode wiring
  events.py        event envelope, opaque runtime_context (DIC)
  dic_merkle.py    Merkle tree, proofs, batch builder (from DIC)
  anchor.py        close -> sign root -> timestamp -> proof rows
  memory.py        fresh-only store + fragment classification
  compress.py      extractive compression + fidelity battery
  router.py        reuse -> local skill -> escalation
  schema.py        pack schema: allowlist for upward payloads (Step 3)
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

- Tokens: estimated_tokens_saved is an estimate, not a measurement
  — it has no real baseline scenario (it compares a full document
  against the escalated context, chars/4). The first measured
  quantity is the miss rate (missed escalations on judged decisions).
- Fidelity: agreement rate between decisions on full vs. compressed
  context (`compress.fidelity_check`), measured, not promised.
- Escalation: rate, false-escalation rate, missed-escalation rate,
  and escalation accuracy (`EscalationGate.report`).
- Detail loss: critical details (numbers, constraints, names) present
  in the full context but missing after compression — must be zero
  for kept-line classes, measured by the fidelity battery.

## Pilot mode (durable journal + Ed25519)

Step 2: the journal survives the process. `friday/persistence.py`
stores one journal as an append-only JSON Lines file, format
`friday-journal` version 1: a header line, entry lines, batch_mark
lines (batching never rewrites an entry line), and anchor lines
(root, signature, key_id, leaf count, TSA token). Proof rows are
recomputed from the batch's entries, not stored.

```python
from friday import Ed25519Signer, AnchorService, NullTsa
from friday.persistence import JournalStore, PersistentJournal

store = JournalStore("pilot-journal.jsonl")
journal, _anchors = PersistentJournal.open(store)  # or fresh
signer = Ed25519Signer.from_private_key_file("pilot.pem")
service = AnchorService(signer, NullTsa(), pilot_mode=True,
                        on_anchor=store.append_anchor)
```

Pilot mode accepts only Ed25519Signer: HMAC proves integrity under a
shared secret, not authorship, and the demo HMAC keys
(`friday-demo`, `demo-secret`) are public in this repo, so they are
rejected in pilot mode. Pilot mode requires the `cryptography`
package (`pip install -e .[ed25519]`); the core stays stdlib-only.

Load is strict: a corrupt line, a bad header, or a broken chain
raises `CorruptJournalError` — a broken chain never degrades to a
fresh journal.

Honest limits: the root's DATE is still not proven — NullTsa stamps
carry `trust="local_untrusted"` and are not RFC 3161 tokens. A real
TSA client (for a KZ pilot, the state tsp.pki.gov.kz is the
candidate — live-checked 2026-10-30: it granted an RFC 3161 stamp
for a test query) is future work. Key custody here is pilot-grade (a
PEM file, mode 0600); production needs a key manager or HSM. Three
more limits, all by design, all open: (1) torn tail — after a power
failure the last line may be half-written and load fails on it;
there is no auto-repair, repair is explicit (truncate the torn final
line and reload; the surviving chain still verifies, the torn
entries are lost); (2) no file locking — one writer at a time, two
processes appending to the same file will interleave and corrupt it;
(3) root unpublished — nothing outside the file proves the tail, so
truncating the journal's tail is undetectable until a publication
destination is chosen (open decision).

The journal file contains raw tasks and answers, including any
personal data in them: protect it like source data. Owner-only mode
(0600) is enforced on the file, but that is only the file's own
mode — do not copy it to shared storage, do not send it anywhere
unencrypted, and do not commit it.
