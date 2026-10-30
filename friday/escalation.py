"""Calibrated escalation gate: local answer vs. ask the large model.

The gate routes by a confidence number in [0, 1]. The threshold is a
configuration value that must be SET FROM A CALIBRATION SET (measured
accuracy per confidence bucket on the actual delegation tasks), not
guessed. The v2 calibration rounds showed confidence *can* rank
correctness, but thresholds measured on arithmetic do
not transfer to retrieval, summarisation or skill selection: measure
them on the tasks the gate will actually route.

Both error directions are counted, because they cost differently:
- false escalation: routed up although the local answer was right
  (wasted tokens, money, latency);
- missed escalation: answered locally although the answer was wrong
  (quality loss, the dangerous direction).

was_correct in record_outcome() always describes the LOCAL answer,
never the large model's answer (Grok audit): the old code counted
"escalated and final answer wrong" as a false escalation, which is
a big-model error, not a wasted call — and counted "escalated and
local answer right" as correct_up, which is exactly the documented
false escalation. An escalated decision with a wrong local answer
was a justified escalation; whether the large model then got it
right is a separate measurement this API does not take.

Feedback arrives later than the routing decision, so outcomes are
recorded separately through record_outcome().
"""

__all__ = ["EscalationGate"]


class EscalationGate:
    """Threshold gate with two-sided error accounting."""

    def __init__(self, threshold=0.8):
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be in [0, 1]")
        self.threshold = threshold
        self.routed_local = 0
        self.routed_up = 0
        self.false_escalations = 0
        self.missed_escalations = 0
        self.correct_local = 0
        self.justified_escalations = 0

    def decide(self, confidence):
        """Return 'local' or 'escalate' for a confidence in [0, 1]."""
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be in [0, 1]")
        if confidence >= self.threshold:
            self.routed_local += 1
            return "local"
        self.routed_up += 1
        return "escalate"

    def record_outcome(self, was_escalated, was_correct):
        """Record ground truth for a routed decision, when it is known.

        was_correct describes the LOCAL answer: True when the local
        answer was right. So an escalated decision with a right local
        answer is a false escalation (wasted cost), and an escalated
        decision with a wrong local answer was justified.
        """
        if was_escalated:
            if was_correct:
                self.false_escalations += 1
            else:
                self.justified_escalations += 1
        else:
            if was_correct:
                self.correct_local += 1
            else:
                self.missed_escalations += 1

    def report(self):
        """Rates that decide whether the threshold needs moving."""
        decided = self.routed_local + self.routed_up
        judged = (self.correct_local + self.missed_escalations
                  + self.justified_escalations + self.false_escalations)
        return {
            "threshold": self.threshold,
            "routed_local": self.routed_local,
            "routed_up": self.routed_up,
            "false_escalations": self.false_escalations,
            "missed_escalations": self.missed_escalations,
            "justified_escalations": self.justified_escalations,
            "escalation_rate": (self.routed_up / decided) if decided else 0.0,
            "miss_rate_on_judged": (
                self.missed_escalations / judged) if judged else 0.0,
        }
