"""Tests for count-bound anchor signatures (Merkle fix).

The DIC tree duplicates the last node on odd levels, so [A,B,C] and
[A,B,C,C] share a root. The anchor signature must therefore bind the
leaf count together with the root: a batch presented with a forged
count fails signature verification even when the root collides.

Run from the friday/ staging root:
    python3 -m unittest tests.test_anchor_count -v
"""

import copy
import unittest

from friday.anchor import AnchorService, HmacSigner, NullTsa
from friday.journal import Journal


def _anchored_journal(n=3):
    journal = Journal()
    for i in range(n):
        journal.append("test", {"i": i})
    service = AnchorService(HmacSigner("test-secret"), NullTsa())
    record = service.anchor_pending(journal, force=True)
    return service, journal, record


class TestCountBoundSignature(unittest.TestCase):
    def test_signature_verifies_for_record(self):
        service, _journal, record = _anchored_journal(3)
        self.assertTrue(service.verify_anchor_signature(record))

    def test_forged_leaf_count_fails(self):
        service, _journal, record = _anchored_journal(3)
        forged = copy.copy(record)
        forged.leaf_count = 4
        self.assertFalse(service.verify_anchor_signature(forged))

    def test_wrong_root_fails(self):
        service, _journal, record = _anchored_journal(3)
        forged = copy.copy(record)
        forged.root = bytes([record.root[0] ^ 0x01]) + record.root[1:]
        self.assertFalse(service.verify_anchor_signature(forged))

    def test_inclusion_proofs_still_verify(self):
        service, journal, record = _anchored_journal(3)
        first = journal.entries()[0]["hash"]
        self.assertTrue(service.verify_proof(
            first, record.proofs[first], record.root_hex))


if __name__ == "__main__":
    unittest.main()
