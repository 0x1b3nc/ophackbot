"""Policy import -> SCOPE YAML tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hackbot.policy_guard import ScopePolicy
from hackbot.policy_import import import_policy_to_target, parse_policy_text

POLICY = """
# In Scope
- example.com
- *.api.demo.test

# Out of Scope
- admin.example.com

# Explicitly Allowed
- Passive recon
- Automated scanning with nuclei at low rate

# Explicitly Prohibited
- DoS
- Brute force
"""


class PolicyImportTests(unittest.TestCase):
    def test_parse(self) -> None:
        meta = parse_policy_text(POLICY)
        self.assertIn("example.com", meta["in_scope"])
        self.assertIn("admin.example.com", meta["out_of_scope"])
        self.assertTrue(any("Passive" in a for a in meta["allowed"]))

    def test_write_and_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "acme"
            meta, rendered, path = import_policy_to_target(
                str(target), POLICY, write=True
            )
            self.assertTrue(path.exists())
            self.assertTrue(rendered.startswith("---"))
            policy = ScopePolicy.load(target)
            self.assertTrue(policy.structured)
            self.assertTrue(policy.contains_host("example.com"))
            self.assertTrue(policy.is_explicitly_out_of_scope("admin.example.com"))


if __name__ == "__main__":
    unittest.main()
