"""F.R.I.D.A.Y. end-to-end demo (no model, no network).

Runs the local-first loop with a stub memory and the built-in skills:
reuse hit, local answer, low-confidence escalation with redaction,
and journal verification including a tamper demo on a copy.
"""

from friday import EscalationGate, Journal, Memory, Router, SkillRegistry
from friday.router import cache_key
from friday.skills import builtin_skills


def main():
    memory = Memory()
    journal = Journal()
    registry = SkillRegistry()
    for skill in builtin_skills(memory, registry):
        registry.register(skill)
    # The "verify" skill's battery checks the registry for "retrieve",
    # which is registered above, so its gate passes.
    gate = EscalationGate(threshold=0.8)
    router = Router(registry, memory, journal, gate)

    memory.put(cache_key("retrieve", "0.1.0", "capital of France"),
               "Paris", "retrieve", "0.1.0", 3600)
    memory.put("capital of Japan", "Tokyo", "retrieve", "0.1.0", 3600)

    kind, payload = router.handle("capital of France", "retrieve")
    print("1. reuse/local:", kind, "->", payload)

    kind, payload = router.handle("summarise::budget is 42 coins, see notes",
                                  "summarise")
    print("2. local:", kind, "->", payload)

    kind, payload = router.handle("quantum entanglement", "retrieve")
    print("3. low-confidence:", kind, "->", payload)

    memory.put(cache_key("retrieve", "0.1.0", "admin contact"),
               "boss@example.com", "retrieve", "0.1.0", 3600)
    # Step 5's redaction demo needs a findable fragment: cache entries
    # use hashed keys (exact lookup only) and are invisible to find(),
    # so the fragment below is a separate, raw-keyed entry.
    memory.put("admin contact", "boss@example.com", "retrieve",
               "0.1.0", 3600)
    kind, payload = router.handle("admin contact", "retrieve")
    print("4. reuse of stored fragment:", kind, "->", payload)
    kind, payload = router.handle("find admin contact", "retrieve")
    print("5. escalation redacts sensitive fragments:",
          kind, "redacted =", payload.redacted_count,
          "context =", repr(payload.compressed_context))

    ok, bad = journal.verify()
    print("6. journal verify:", ok, "bad index:", bad, "head:", journal.head())

    exported = journal.entries()
    exported[1]["payload"] = {"task": "forged"}
    ok, bad = journal.verify_external(exported)
    print("7. tampered copy verifies:", ok, "first bad index:", bad)

    print("8. gate report:", gate.report())

    # 9-11. DIC-based anchoring: batch the journal, sign the root,
    # verify an inclusion proof offline.
    from friday.anchor import AnchorService, HmacSigner, NullTsa
    from friday.skill_trace import collect_traces
    anchor = AnchorService(HmacSigner("demo-secret"), NullTsa(),
                           max_leaves=100, max_seconds=3600.0)
    record = anchor.anchor_pending(journal, force=True)
    print("9. anchored batch:", record.batch_id[:12],
          "leaves:", record.leaf_count, "root:", record.root_hex[:16] + "...")
    first_leaf = journal.entries()[0]["hash"]
    proof = record.proofs[first_leaf]
    print("10. inclusion proof verifies:",
          anchor.verify_proof(first_leaf, proof, record.root_hex))
    traces = collect_traces(journal.entries())
    print("11. back-transfer traces collected:", len(traces),
          "skills:", sorted({t["skill"] for t in traces}))


if __name__ == "__main__":
    main()
