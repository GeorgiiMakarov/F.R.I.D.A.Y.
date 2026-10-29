"""Package version consistency: pyproject.toml must agree with __version__.

Regression test for the v0.2.0/v0.2.2 drift (package said 0.2.0 while
releases were already at v0.2.2): a future bump that touches only one
of the two files must fail here instead of drifting silently.

Parsed with a regex on purpose: the package supports Python >= 3.9
and tomllib exists only from 3.11.
"""

import re
import unittest
from pathlib import Path

import friday

VERSION_RE = re.compile(r"^version\s*=\s*[\"']([^\"']+)[\"']\s*$", re.MULTILINE)
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def pyproject_version() -> str:
    text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    match = VERSION_RE.search(text)
    assert match is not None, "pyproject.toml has no version = ... line"
    return match.group(1)


class TestVersionConsistency(unittest.TestCase):
    def test_pyproject_matches_dunder_version(self):
        self.assertEqual(pyproject_version(), friday.__version__)

    def test_version_is_semver(self):
        self.assertRegex(friday.__version__, SEMVER_RE)
        self.assertRegex(pyproject_version(), SEMVER_RE)


if __name__ == "__main__":
    unittest.main()
