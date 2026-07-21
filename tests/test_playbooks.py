"""Playbook routing tests."""

from __future__ import annotations

import unittest

from hackbot.playbooks import list_playbooks, playbook_for, playbook_markdown


class PlaybookTests(unittest.TestCase):
    def test_idor_playbook(self) -> None:
        pb = playbook_for("idor on /api/orders/1")
        self.assertEqual(pb.class_name, "idor")
        self.assertGreaterEqual(len(pb.steps), 2)
        md = playbook_markdown(pb, endpoint="https://example.com/api/orders/1")
        self.assertIn("Hypothesis", md)
        self.assertIn("Aggression", md)

    def test_list_includes_core(self) -> None:
        names = list_playbooks()
        for key in ("idor", "ssrf", "xss", "recon"):
            self.assertIn(key, names)


if __name__ == "__main__":
    unittest.main()
