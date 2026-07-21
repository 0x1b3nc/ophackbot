"""Tests for study-note routing."""

from __future__ import annotations

import unittest

from hackbot.knowledge import classify, notes_for_classes, required_bundle


class KnowledgeTests(unittest.TestCase):
    def test_classify_idor(self) -> None:
        self.assertIn("idor", classify("test BOLA/IDOR on object id"))

    def test_classify_ssrf(self) -> None:
        self.assertIn("ssrf", classify("webhook SSRF to metadata"))

    def test_notes_exist_for_idor(self) -> None:
        paths = notes_for_classes(["idor"])
        self.assertTrue(paths)
        self.assertTrue(all(p.name.endswith(".md") for p in paths))

    def test_bundle_always_includes_rules(self) -> None:
        bundle = required_bundle("graphql mutation authz")
        self.assertIn("graphql", bundle.class_name)
        names = [p.name for p in bundle.always]
        self.assertIn("OPERATING_RULES.md", names)
        self.assertIn("INDEX.md", names)


if __name__ == "__main__":
    unittest.main()
