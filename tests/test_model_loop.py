"""Tests for the model-in-the-loop path and the adapter confidence fix.

The adapter used to read a "confidence" field that stock llama.cpp /
Ollama servers never return, so confidence was always 0.0 and every
call escalated. Now: explicit "confidence" field wins, else logprob
mean (exponentiated) when the server returns logprobs, else 0.0.
Servers that reject the logprobs parameter get one retry without it.

Run from the friday/ staging root:
    python3 -m unittest tests.test_model_loop -v
"""

import http.server
import json
import math
import threading
import unittest

from examples.compliance_agent.agent import ComplianceAgent
from examples.compliance_agent.samples import DOC_SENSITIVE
from friday.local_model import (
    OpenAICompatibleLocalModel,
    StubLocalModel,
)


class _Handler(http.server.BaseHTTPRequestHandler):
    mode = "plain"
    bodies = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        _Handler.bodies.append(body)
        if _Handler.mode == "strict" and body.get("logprobs"):
            self.send_response(400)
            self.end_headers()
            return
        if _Handler.mode == "logprobs":
            payload = {
                "choices": [{
                    "message": {"content": "judged"},
                    "logprobs": {"content": [
                        {"logprob": -0.1},
                        {"logprob": -0.2},
                        {"logprob": -0.3},
                    ]},
                }],
            }
        elif _Handler.mode == "confidence":
            payload = {
                "choices": [{"message": {"content": "judged"}}],
                "confidence": 0.7,
            }
        else:
            payload = {"choices": [{"message": {"content": "judged"}}]}
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class TestAdapterConfidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _model(self):
        return OpenAICompatibleLocalModel(
            "http://127.0.0.1:%d/v1" % self.port, "test-model")

    def test_logprob_mean_confidence(self):
        _Handler.mode = "logprobs"
        text, conf = self._model().generate("hello", budget=64)
        self.assertEqual(text, "judged")
        self.assertAlmostEqual(conf, math.exp(-0.2), places=6)

    def test_explicit_confidence_field_wins(self):
        _Handler.mode = "confidence"
        _text, conf = self._model().generate("hello", budget=64)
        self.assertEqual(conf, 0.7)

    def test_no_signal_means_escalate(self):
        _Handler.mode = "plain"
        _text, conf = self._model().generate("hello", budget=64)
        self.assertEqual(conf, 0.0)

    def test_strict_server_retries_without_logprobs(self):
        _Handler.mode = "strict"
        _Handler.bodies = []
        text, conf = self._model().generate("hello", budget=64)
        self.assertEqual(text, "judged")
        self.assertEqual(conf, 0.0)
        self.assertEqual(len(_Handler.bodies), 2)
        self.assertTrue(_Handler.bodies[0].get("logprobs"))
        self.assertNotIn("logprobs", _Handler.bodies[1])


class TestAgentModelLoop(unittest.TestCase):
    def test_model_review_attached_and_journaled(self):
        stub = StubLocalModel({
            "line amount missing": ("Ask for a corrected document.",
                                    0.85),
        })
        agent = ComplianceAgent(local_model=stub)
        report = agent.review(DOC_SENSITIVE)
        self.assertEqual(report["verdict"], "FLAGGED")
        self.assertEqual(len(report["escalated"]), 1)
        review = report["escalated"][0]["model_review"]
        self.assertEqual(review["text"], "Ask for a corrected document.")
        self.assertEqual(review["confidence"], 0.85)
        self.assertEqual(review["gate"], "local")
        events = [e["event"] for e in agent.journal.entries()]
        self.assertIn("model_review", events)

    def test_no_model_means_no_review(self):
        agent = ComplianceAgent()
        report = agent.review(DOC_SENSITIVE)
        self.assertNotIn("model_review", report["escalated"][0])


if __name__ == "__main__":
    unittest.main()
