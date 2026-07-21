"""Tests for scope host matching and aggression classification."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hackbot.policy_guard import (
    ScopePolicy,
    host_from_target,
    policy_quote_for,
)


SCOPE = """# Scope

## In Scope

- `example.com`
- `*.api.demo.test`

## Out of Scope

- `*.example.net`
- `admin.example.com`

## Explicitly Allowed

- Passive recon
- Automated scanning with nuclei at low rate

## Explicitly Prohibited

- DoS
- Brute force
- Credential stuffing
"""


LEVEL3_ALLOWED = """# Scope

## In Scope
- lab.local

## Explicitly Allowed
- Controlled brute force against own test accounts
- Rate-limit testing

## Explicitly Prohibited
- Destructive data deletion
"""


class PolicyGuardTests(unittest.TestCase):
    def _policy(self, text: str = SCOPE) -> ScopePolicy:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(text, encoding="utf-8")
        return ScopePolicy.load(root)

    def test_host_from_url(self) -> None:
        self.assertEqual(host_from_target("https://Example.com/path"), "example.com")
        self.assertEqual(host_from_target("example.com"), "example.com")

    def test_contains_exact_host(self) -> None:
        policy = self._policy()
        self.assertTrue(policy.contains_host("example.com"))
        # Parent domain listed does not auto-include arbitrary subdomains.
        self.assertFalse(policy.contains_host("www.example.com"))
        self.assertFalse(policy.contains_host("other.com"))

    def test_wildcard_match(self) -> None:
        policy = self._policy()
        self.assertTrue(policy.contains_host("v1.api.demo.test"))
        self.assertFalse(policy.contains_host("api.demo.test"))

    def test_out_of_scope_section(self) -> None:
        policy = self._policy()
        self.assertTrue(policy.is_explicitly_out_of_scope("foo.example.net"))
        self.assertTrue(policy.is_explicitly_out_of_scope("admin.example.com"))

    def test_assert_host_allowed(self) -> None:
        policy = self._policy()
        policy.assert_host_allowed("example.com")
        with self.assertRaises(PermissionError):
            policy.assert_host_allowed("evil.com")
        with self.assertRaises(PermissionError):
            policy.assert_host_allowed("admin.example.com")

    def test_aggression_levels(self) -> None:
        policy = self._policy()
        self.assertEqual(policy.classify_aggression("crt.sh osint"), 0)
        self.assertEqual(policy.classify_aggression("httpx fingerprint"), 1)
        self.assertEqual(policy.classify_aggression("nuclei templates"), 2)
        self.assertEqual(policy.classify_aggression("ffuf fuzz"), 2)
        self.assertEqual(policy.classify_aggression("dos stress"), 3)

    def test_mentions_active_testing(self) -> None:
        policy = self._policy()
        self.assertTrue(policy.mentions_active_testing())

    def test_level3_not_allowed_when_only_prohibited(self) -> None:
        policy = self._policy()
        self.assertFalse(policy.allows_level3())

    def test_level3_allowed_when_in_allowed_section(self) -> None:
        policy = self._policy(LEVEL3_ALLOWED)
        self.assertTrue(policy.allows_level3())

    def test_policy_quote(self) -> None:
        policy = self._policy()
        quote = policy_quote_for(policy, 1)
        self.assertTrue(len(quote) > 0)


if __name__ == "__main__":
    unittest.main()
