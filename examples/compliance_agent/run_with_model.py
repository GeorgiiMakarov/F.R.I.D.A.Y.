"""Run the compliance demo against a real local model server.

The demo (demo.py) uses a deterministic stub so it runs anywhere.
This script swaps in OpenAICompatibleLocalModel pointed at a local
OpenAI-compatible endpoint — llama.cpp server, Ollama, MLX server —
so the escalated finding is judged by a real small model, under the
same gates and journal.

Start a server first, for example:
    ollama serve
    ollama pull qwen2.5:3b
    python3 -m examples.compliance_agent.run_with_model \
        --base-url http://localhost:11434 --model qwen2.5:3b

Or with llama.cpp server:
    llama-server -m <model.gguf> --port 8080
    python3 -m examples.compliance_agent.run_with_model \
        --base-url http://localhost:8080 --model local

base-url may be given with or without a trailing "/v1" — the
adapter strips it (it appends "/v1/chat/completions" itself).

The output of this script IS the recorded run: model, device, tokens,
latency, escalation share. Save it as evidence; do not hand-edit the
numbers.
"""

import argparse
import time

from examples.compliance_agent.agent import ComplianceAgent
from examples.compliance_agent.demo import _show
from examples.compliance_agent.samples import (
    DOC_MISMATCH,
    DOC_OK,
    DOC_SENSITIVE,
)
from friday.local_model import OpenAICompatibleLocalModel


def main():
    parser = argparse.ArgumentParser(
        description="Compliance demo against a real local model.")
    parser.add_argument("--base-url", default="http://localhost:11434")
    parser.add_argument("--model", default="qwen2.5:3b")
    args = parser.parse_args()

    agent = ComplianceAgent(
        local_model=OpenAICompatibleLocalModel(args.base_url,
                                               args.model))
    print("== F.R.I.D.A.Y. compliance demo, model %s at %s =="
          % (args.model, args.base_url))
    started = time.time()
    for doc in (DOC_OK, DOC_MISMATCH, DOC_SENSITIVE):
        _show(agent.review(doc))
        print()
    record = agent.finalize_anchor()
    print("anchor: batch %s leaves %d root %s"
          % (record.batch_id[:12], record.leaf_count, record.root_hex))
    print("elapsed_s: %.1f" % (time.time() - started))
    print("== measured metrics ==")
    for key, value in agent.summary().items():
        print(" ", key, "=", value)


if __name__ == "__main__":
    main()
