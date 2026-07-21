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

    def test_assert_action_allowed_level3(self) -> None:
        policy = self._policy(LEVEL3_ALLOWED)
        gate = policy.assert_action_allowed("lab.local", "rate-limit testing", force=False)
        self.assertEqual(gate["aggression"], 3)
        self.assertFalse(gate["force_override"])

    def test_policy_quote(self) -> None:
        policy = self._policy()
        quote = policy_quote_for(policy, 1)
        self.assertTrue(len(quote) > 0)

    def test_yaml_front_matter_is_source_of_truth(self) -> None:
        yaml_scope = """---
in_scope:
  - example.com
  - "*.api.demo.test"
out_of_scope:
  - "*.example.net"
  - admin.example.com
allowed:
  - Passive recon
prohibited:
  - DoS
---

# Notes

Prose mentioning evil.com here must not put it in scope.
"""
        policy = self._policy(yaml_scope)
        self.assertTrue(policy.structured)
        self.assertTrue(policy.contains_host("example.com"))
        self.assertTrue(policy.contains_host("v1.api.demo.test"))
        self.assertFalse(policy.contains_host("evil.com"))
        self.assertTrue(policy.is_explicitly_out_of_scope("foo.example.net"))
        self.assertTrue(policy.is_explicitly_out_of_scope("admin.example.com"))
        with self.assertRaises(PermissionError):
            policy.assert_host_allowed("evil.com")

    def test_markdown_fallback_still_works(self) -> None:
        policy = self._policy(SCOPE)
        self.assertFalse(policy.structured)
        self.assertTrue(policy.contains_host("example.com"))

    def test_url_port_and_path_constraints(self) -> None:
        yaml_scope = """---
in_scope:
  - https://api.example.com:8443/v1/*
out_of_scope:
  - admin.example.com
allowed:
  - Active testing
prohibited: []
---
"""
        policy = self._policy(yaml_scope)
        self.assertTrue(
            policy.target_in_scope("https://api.example.com:8443/v1/users")
        )
        self.assertFalse(
            policy.target_in_scope("https://api.example.com:8443/admin/delete")
        )
        self.assertFalse(policy.target_in_scope("http://api.example.com:80/v1/x"))
        self.assertFalse(policy.target_in_scope("https://api.example.com:9999/v1/x"))
        policy.assert_action_allowed(
            "https://api.example.com:8443/v1/users",
            "httpx fingerprint",
            force=False,
        )
        with self.assertRaises(PermissionError):
            policy.assert_action_allowed(
                "https://api.example.com:9999/v1/x",
                "httpx fingerprint",
                force=False,
            )

    def test_tool_id_aggression_and_prohibited(self) -> None:
        yaml_scope = """---
in_scope:
  - api.example.com
allowed:
  - Passive recon only
prohibited:
  - Automated scanning
  - Mutating requests
  - Brute force
---
"""
        policy = self._policy(yaml_scope)
        self.assertEqual(
            policy.classify_aggression("method override probe", tool="method_override_probe"),
            3,
        )
        self.assertEqual(
            policy.classify_aggression("mass assignment probe", tool="mass_assignment_probe"),
            2,
        )
        self.assertEqual(
            policy.classify_aggression("graphql introspection probe", tool="graphql_probe"),
            2,
        )
        self.assertEqual(
            policy.classify_aggression("race condition probe", tool="race_probe"),
            3,
        )
        for action, tool in (
            ("method override probe", "method_override_probe"),
            ("mass assignment probe", "mass_assignment_probe"),
            ("graphql introspection probe", "graphql_probe"),
            ("nuclei templates", "nuclei"),
        ):
            with self.assertRaises(PermissionError):
                policy.assert_action_allowed(
                    "api.example.com",
                    action,
                    force=False,
                    tool=tool,
                )
        # Operator force still overrides soft prohibited / aggression gates.
        gate = policy.assert_action_allowed(
            "api.example.com",
            "method override probe",
            force=True,
            tool="method_override_probe",
        )
        self.assertTrue(gate["force_override"])

    def test_structured_l2_hard_without_active_allow(self) -> None:
        yaml_scope = """---
in_scope:
  - lab.local
allowed:
  - Passive recon only
---
"""
        policy = self._policy(yaml_scope)
        with self.assertRaises(PermissionError):
            policy.assert_action_allowed(
                "lab.local",
                "idor bola authz probe",
                force=False,
                tool="idor_probe",
            )

    def test_cidr_in_scope(self) -> None:
        yaml_scope = """---
in_scope:
  - 10.0.0.0/8
  - 2001:db8::/32
out_of_scope:
  - 10.9.9.9
allowed:
  - Active testing
---
"""
        policy = self._policy(yaml_scope)
        self.assertTrue(policy.contains_host("10.1.2.3"))
        self.assertTrue(policy.target_in_scope("http://10.1.2.3:8080/x"))
        self.assertFalse(policy.contains_host("11.0.0.1"))
        self.assertTrue(policy.is_explicitly_out_of_scope("10.9.9.9"))
        with self.assertRaises(PermissionError):
            policy.assert_action_allowed("http://10.9.9.9/", "httpx fingerprint", force=False)
        self.assertTrue(policy.contains_host("2001:db8::1"))


if __name__ == "__main__":
    unittest.main()
