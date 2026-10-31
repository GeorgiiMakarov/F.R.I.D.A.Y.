"""Deterministic seed test: seed documents through the rules, no model.

Run from the friday/ staging root:
    python3 -m unittest tests.test_seed -v
"""

import json
import unittest
from pathlib import Path

from examples.compliance_agent.agent import ComplianceAgent

CORPUS = (Path(__file__).resolve().parent.parent / "examples"
          / "compliance_agent" / "corpus")


def _check(testcase, row):
    # Fresh agent per document: reuse would mask re-checks.
    agent = ComplianceAgent()
    rep = agent.review(row["doc"])
    exp = row["expected"]
    testcase.assertEqual(rep["doc_id"], exp["report_doc_id"])
    testcase.assertEqual(rep["verdict"], exp["verdict"])
    testcase.assertEqual(
        {f["rule_id"]: f["status"] for f in rep["findings"]},
        exp["findings"])
    testcase.assertEqual(
        [e["rule_id"] for e in rep["escalated"]
         if e["reason"] == "low_confidence"],
        exp["escalated"])
    r6 = [f for f in rep["findings"] if f["rule_id"] == "R6"][0]
    testcase.assertEqual("sensitive data present" in r6["detail"],
                         exp["r6_sensitive"])


class TestSeed(unittest.TestCase):
    def test_dev(self):
        for line in open(CORPUS / "dev.jsonl", encoding="utf-8"):
            row = json.loads(line)
            with self.subTest(row["id"]):
                _check(self, row)

    def test_test(self):
        for line in open(CORPUS / "test.jsonl", encoding="utf-8"):
            row = json.loads(line)
            with self.subTest(row["id"]):
                _check(self, row)


if __name__ == "__main__":
    unittest.main()
