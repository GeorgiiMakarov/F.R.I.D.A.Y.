"""Effect-gated skills: a skill is reusable only if its tests pass.

Pattern learned from the AuditLog work: a behaviour is not described by
a percentage, it is described by an effect matrix — a battery of named
checks, each with an expected outcome. A skill ships with its battery;
the gate runs it before the skill may serve a request. Any failure
blocks reuse and forces escalation. The battery is part of the skill,
not an afterthought: a skill without tests is not shippable.

A "test" here is a zero-argument callable returning True (pass) or
raising/returning False (fail). Tests must be deterministic and fast:
the gate runs on the request path.

Scope note (F-09): the battery gates a skill VERSION — it proves the
skill still behaves on fixed regression cases. It does NOT validate
runtime inputs: input validation is the skill's own job on each
request. A skill that passes its battery can still fail on an input
the battery never covered.
"""

__all__ = ["Skill", "SkillGate", "SkillRegistry"]


class Skill:
    """A named local capability with its acceptance battery."""

    def __init__(self, name, version, run, tests, description="",
                 output_shareable=False):
        self.name = name
        self.version = version
        self.run = run  # callable(task) -> (answer, confidence)
        self.tests = list(tests)  # list of (test_name, callable)
        self.description = description
        # Step 3: the router caches a skill's answer SENSITIVE unless
        # the skill explicitly declares its output shareable, so free
        # text cannot flow up through memory fragments by default.
        self.output_shareable = output_shareable

    def check(self):
        """Run the battery. Returns (passed, failures)."""
        failures = []
        for test_name, fn in self.tests:
            try:
                ok = bool(fn())
            except Exception as exc:  # a raising test is a failed test
                ok = False
                failures.append((test_name, "raised %r" % (exc,)))
                continue
            if not ok:
                failures.append((test_name, "returned false"))
        return not failures, failures


class SkillGate:
    """Runs a skill's battery and reports pass/fail."""

    @staticmethod
    def evaluate(skill):
        passed, failures = skill.check()
        return {
            "skill": skill.name,
            "version": skill.version,
            "passed": passed,
            "failures": failures,
        }


class SkillRegistry:
    """Name -> Skill, with gate enforcement on lookup."""

    def __init__(self):
        self._skills = {}

    def register(self, skill):
        self._skills[skill.name] = skill

    def names(self):
        return sorted(self._skills)

    def get_gated(self, name):
        """Return (skill, gate_report); skill is None if the gate fails."""
        skill = self._skills.get(name)
        if skill is None:
            return None, {"skill": name, "passed": False,
                          "failures": [("missing", "no such skill")]}
        report = SkillGate.evaluate(skill)
        return (skill if report["passed"] else None), report
