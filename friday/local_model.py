"""Local model adapter interface.

A local model is anything that implements generate(prompt, budget) and
returns (text, confidence). Confidence is the model's own calibrated
estimate that the text is correct; a model that cannot estimate it
must return 0.0 so the router escalates.

Two adapters ship here:

- StubLocalModel: deterministic, for tests and the demo. It never
  pretends to be a real model.
- OpenAICompatibleLocalModel: talks to a local server over HTTP with
  the standard library only (llama.cpp server, Ollama, MLX server, or
  any other OpenAI-compatible endpoint). It expects the server to
  return a "confidence" field in the response JSON when one is
  available; otherwise confidence is 0.0 (escalate).

Serving notes for the 4 GB class (top smartphones and laptops):
- weights: a 4-bit quantised 4B model (~4 GB) leaves room for context
  on devices with 8 GB+ RAM; keep the working budget small (2k tokens
  is a sane default) and let the router escalate anything bigger;
- prefer short, structured outputs (JSON, lists) over free prose:
  small models stay faithful on short outputs and drift on long ones;
- batch and cache: identical prompts must hit memory before they hit
  the model (see Router reuse).
"""

import json
import urllib.request

__all__ = ["LocalModel", "StubLocalModel", "OpenAICompatibleLocalModel"]


class LocalModel:
    """Interface: generate(prompt, budget) -> (text, confidence)."""

    def generate(self, prompt, budget=2048):
        raise NotImplementedError


class StubLocalModel(LocalModel):
    """Deterministic stub for tests/demo. Not a model."""

    def __init__(self, answers=None):
        self._answers = answers or {}

    def generate(self, prompt, budget=2048):
        for key, (text, confidence) in self._answers.items():
            if key in prompt:
                return text, confidence
        return "no stub answer for this prompt", 0.0


class OpenAICompatibleLocalModel(LocalModel):
    """HTTP adapter for a local OpenAI-compatible server."""

    def __init__(self, base_url, model, timeout_s=60):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_s = timeout_s

    def generate(self, prompt, budget=2048):
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": budget,
            "temperature": 0.0,
        }).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + "/v1/chat/completions", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        choice = payload["choices"][0]["message"]["content"]
        confidence = float(payload.get("confidence", 0.0))
        return choice, confidence
