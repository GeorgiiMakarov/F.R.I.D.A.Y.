# F.R.I.D.A.Y.

**F**ederated **R**easoning **I**nterface for **D**elegation, **A**udit and **Y**ield.
(Name expansion proposed; the engine stands on its own.)

A local-first delegation engine for small on-device models (4 GB class,
top smartphones and laptops). The local layer owns context, memory and
compute; the large model is consulted only on escalation — and every
delegation step happens under verification. See `friday/README.md` for
the full design, the eight skills, and the evidence this design owes.

Product direction: F.R.I.D.A.Y. is a local-first compliance pre-check
engine for regulated companies — a reference implementation of a
compliance pre-check. It is an engine, not an AI agent: verification first — rules
decide, a local model advises, nothing sensitive leaves the device.

## Quick start

```bash
python3 -m unittest tests.test_friday -v
python3 -m friday.demo
```

## Reference implementation: compliance pre-check

`examples/compliance_agent/` — the product's first rule pack: a
compliance pre-check engine for regulated documents on this engine —
deterministic rules with gates, reuse, escalation with redaction,
anchored journal, measured metrics. See its README.

```bash
python3 -m unittest tests.test_demo_agent -v
python3 -m examples.compliance_agent.demo
```

Standard library only. No weights included, no vendor lock-in: any local
model that can serve `generate(prompt, budget)` works — llama.cpp
server, Ollama, MLX server, or any OpenAI-compatible endpoint.

## Taken from decision-intelligence-core

FRIDAY is built on DIC's proven core (Apache-2.0, same author), adapted
for on-device use:

| Taken | From DIC | Adaptation |
|---|---|---|
| Merkle tree, proofs, offline verification, N/T batch triggers | `application/merkle.py` | Verbatim logic in `friday/dic_merkle.py`; leaves are journal entry hashes |
| Decision-leaf hash formula | `application/merkle.py` | Kept verbatim for compatibility; not used for journal leaves |
| Anchor flow: close → sign root → timestamp → proof rows | `application/merkle_anchor_service.py` | Synchronous, in-memory proof store, no ProjectionStore |
| Signer / TSA protocols, key_id rotation | `interfaces/signer.py`, `interfaces/tsa.py` | Same shapes; HMAC signer added for stdlib-only use |
| Append-only audit trail, idempotency inside append (I6, I7) | `interfaces/audit_trail.py` | Journal interface shape: no update/delete, dedup in append |
| Event envelope, opaque runtime_context | `domain/events.py` | stdlib dataclasses instead of pydantic |

Deliberately left behind (server-side, not on-device): FastAPI, gRPC,
Kafka, Redis, Postgres, and pydantic. A phone does not run that stack,
and the engine must not require it.

Two conventions to never mix: DIC's Merkle tree duplicates the last
node on odd levels; the Defense-Dossier live demo uses RFC 6962
(promote the odd node unchanged). Proofs from the two systems are not
interchangeable.

## License

Apache-2.0 (see LICENSE).
