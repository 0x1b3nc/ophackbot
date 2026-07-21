"""Playwright SCOPE route guard rejects OOS request URLs."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from hackbot.scoped_http import attach_playwright_scope_guard


class _FakeRequest:
    def __init__(self, url: str) -> None:
        self.url = url


class _FakeRoute:
    def __init__(self, url: str) -> None:
        self.request = _FakeRequest(url)
        self.continued = False
        self.aborted = False
        self.abort_reason = ""

    def continue_(self) -> None:
        self.continued = True

    def abort(self, reason: str = "") -> None:
        self.aborted = True
        self.abort_reason = reason


class _FakeTarget:
    def __init__(self) -> None:
        self.handler = None

    def route(self, pattern: str, handler) -> None:  # noqa: ANN001
        self.handler = handler


class PlaywrightScopeGuardTests(unittest.TestCase):
    def test_aborts_oos_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(
                "---\nin_scope:\n  - 127.0.0.1\nout_of_scope:\n  - localhost\n"
                "allowed:\n  - Active testing\n---\n",
                encoding="utf-8",
            )
            target = _FakeTarget()
            blocked: list[dict[str, str]] = []
            attach_playwright_scope_guard(
                target,
                root,
                action="browser navigate playwright",
                force=False,
                blocked=blocked,
            )
            self.assertIsNotNone(target.handler)
            ok = _FakeRoute("http://127.0.0.1:9/")
            target.handler(ok)
            self.assertTrue(ok.continued)
            self.assertFalse(ok.aborted)

            bad = _FakeRoute("http://localhost:9/landing")
            target.handler(bad)
            self.assertTrue(bad.aborted)
            self.assertTrue(blocked)
            self.assertIn("localhost", blocked[0]["url"])


if __name__ == "__main__":
    unittest.main()
