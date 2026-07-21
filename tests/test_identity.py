"""Identity / sessions store tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hackbot.identity import load_identity, save_session


class IdentityTests(unittest.TestCase):
    def test_save_and_mask(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(
            "---\nin_scope:\n  - example.com\nheaders:\n  X-Bug-Bounty: hunter@test.com\n---\n# Scope\n",
            encoding="utf-8",
        )
        save_session(root, "A", authorization="Bearer secrettoken123456")
        save_session(root, "B", cookie="session=abc; other=1")
        ident = load_identity(root)
        self.assertIn("A", ident.ready_sessions())
        self.assertIn("B", ident.ready_sessions())
        masked = ident.masked_summary()
        self.assertNotIn("secrettoken123456", str(masked))
        self.assertIn("X-Bug-Bounty", ident.program_headers)
        merged = ident.merge_headers("A")
        self.assertTrue(merged["Authorization"].startswith("Bearer "))
        self.assertEqual(merged["X-Bug-Bounty"], "hunter@test.com")


if __name__ == "__main__":
    unittest.main()
