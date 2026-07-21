"""Active target session tests."""

from __future__ import annotations

import unittest

from hackbot.session import clear_active, get_active, load_session, set_active, status_line


class SessionTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_active()

    def test_load_demo(self) -> None:
        session = load_session("targets/demo")
        self.assertEqual(session.name, "demo")
        self.assertTrue(session.scope_excerpt or session.resume_excerpt)
        self.assertIn("example.com", session.in_scope_hosts)

    def test_set_active(self) -> None:
        set_active("demo")
        self.assertIsNotNone(get_active())
        self.assertIn("demo", status_line())


if __name__ == "__main__":
    unittest.main()
