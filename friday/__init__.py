"""F.R.I.D.A.Y. — Federated Reasoning Interface for Delegation, Audit and Yield.

Proposed expansion of the name; the engine itself is model-agnostic.

A local-first delegation engine for small (4 GB class) on-device models:
the local layer owns context, memory and compute; the large model is
consulted only on escalation. Every local decision passes through three
checks learned from frontier-model work:

1. Calibrated escalation (friday.escalation): route by measured confidence,
   not by guess. Thresholds are set from a calibration set, and both error
   directions are counted: false escalations and missed escalations.
2. Effect-gated skills (friday.gates): a skill ships with its own acceptance
   battery. A failed gate blocks reuse and forces escalation.
3. Hash-chained journal (friday.journal): every action is appended to a
   tamper-evident chain. The chain head can be anchored externally
   (for example by decision-intelligence-core's Merkle/TSA anchoring).

Supporting pieces: local memory with freshness and fragment classification
(friday.memory), loss-aware context compression (friday.compress), a
local-first router (friday.router), a model adapter interface
(friday.local_model), DIC-based event envelopes (friday.events),
Merkle batching and anchoring (friday.dic_merkle, friday.anchor), and
offline back-transfer export (friday.skill_trace).

Standard library only. No weights, no vendor lock-in: any local model that
can serve a generate() call (llama.cpp server, Ollama, MLX, or any
OpenAI-compatible endpoint) can back the engine.
"""

__version__ = "0.3.1"

from friday.escalation import EscalationGate
from friday.gates import Skill, SkillGate, SkillRegistry
from friday.journal import Journal
from friday.memory import Memory
from friday.compress import compress, fidelity_check
from friday.router import Escalation, Router, cache_key
from friday.events import FrEvent, new_event
from friday.dic_merkle import (MerkleBatch, verify_inclusion_proof)
from friday.anchor import (AnchorService, AnchorRecord, HmacSigner,
                           Ed25519Signer, NullTsa)
from friday.persistence import (CorruptJournalError, JournalStore,
                                PersistentJournal)
from friday.skill_trace import collect_traces, export_jsonl

__all__ = [
    "EscalationGate",
    "Skill",
    "SkillGate",
    "SkillRegistry",
    "Journal",
    "Memory",
    "compress",
    "fidelity_check",
    "Escalation",
    "Router",
    "cache_key",
    "FrEvent",
    "new_event",
    "MerkleBatch",
    "verify_inclusion_proof",
    "AnchorService",
    "AnchorRecord",
    "HmacSigner",
    "Ed25519Signer",
    "NullTsa",
    "CorruptJournalError",
    "JournalStore",
    "PersistentJournal",
    "collect_traces",
    "export_jsonl",
    "__version__",
]
