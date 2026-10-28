"""Sample documents shared by the demo and the tests.

Amounts are integer minor units. DOC_OK passes every rule. DOC_MISMATCH
fails totals and evidence. DOC_SENSITIVE is over the approval limit
without an approver, has an undecidable totals line (escalation case),
and carries an email address that must never leave the device.
"""

DOC_OK = {
    "doc_id": "DOC-001",
    "period": "2026-P3",
    "total_minor": 500_000,
    "lines": [
        {"amount_minor": 300_000, "evidence_ref": "INV-1"},
        {"amount_minor": 200_000, "evidence_ref": "INV-2"},
    ],
    "submitter": "Ivanov",
}

DOC_MISMATCH = {
    "doc_id": "DOC-002",
    "period": "2026-P3",
    "total_minor": 500_000,
    "lines": [
        {"amount_minor": 300_000, "evidence_ref": "INV-1"},
        {"amount_minor": 150_000, "evidence_ref": ""},
    ],
    "submitter": "Petrov",
}

DOC_SENSITIVE = {
    "doc_id": "DOC-003",
    "period": "2026-P3",
    "total_minor": 2_000_000,
    "lines": [
        {"amount_minor": 1_200_000, "evidence_ref": "INV-9"},
        {"amount_minor": None, "evidence_ref": "INV-10"},
    ],
    "submitter": "Sidorov",
    "notes": "contact boss@example.com for questions",
}
