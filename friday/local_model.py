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
  any other OpenAI-compatible endpoint). Confidence comes from, in
  order: an explicit "confidence" field in the response JSON when the
  server provides one; logprobs when the server returns them (mean
  token logprob, exponentiated); otherwise 0.0 (escalate). Servers
  that reject the logprobs parameter get one retry without it.

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
import math
import urllib.error
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

    def __init__(self, base_url, model, timeout_s=60,
                 want_logprobs=True):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_s = timeout_s
        self.want_logprobs = want_logprobs

    def _post(self, body):
        req = urllib.request.Request(
            self.base_url + "/v1/chat/completions", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def generate(self, prompt, budget=2048):
        body = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": budget,
            "temperature": 0.0,
        }
        if self.want_logprobs:
            body["logprobs"] = True
        try:
            payload = self._post(json.dumps(body).encode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code != 400 or not self.want_logprobs:
                raise
            body.pop("logprobs", None)
            payload = self._post(json.dumps(body).encode("utf-8"))
        choice = payload["choices"][0]
        text = choice["message"]["content"]
        if payload.get("confidence") is not None:
            # Validate at the adapter boundary (F-07): an out-of-range
            # or non-finite confidence is treated as absent (0.0,
            # escalate), never passed on. Without this, a bad value
            # crashes the gate downstream with ValueError.
            try:
                conf = float(payload["confidence"])
            except (TypeError, ValueError):
                return text, 0.0
            if not math.isfinite(conf) or not 0.0 <= conf <= 1.0:
                return text, 0.0
            return text, conf
        logprobs = (choice.get("logprobs") or {}).get("content") or []
        vals = [item["logprob"] for item in logprobs
                if isinstance(item, dict) and "logprob" in item]
        if vals:
            conf = math.exp(sum(vals) / len(vals))
            return text, min(1.0, max(0.0, conf))
        return text, 0.0
