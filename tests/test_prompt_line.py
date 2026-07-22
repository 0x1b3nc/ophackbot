"""Operator prompt uses prompt_toolkit when available (paste-safe)."""

from __future__ import annotations

import unittest
from unittest import mock

from hackbot.prompt_line import ask_operator_line


class PromptLineTests(unittest.TestCase):
    def test_uses_prompt_toolkit_session_when_present(self) -> None:
        try:
            import prompt_toolkit  # noqa: F401
        except ImportError:
            self.skipTest("prompt_toolkit not installed")
        session = mock.Mock()
        session.prompt.return_value = "  hello  "
        with mock.patch("hackbot.prompt_line._SESSION", session):
            out = ask_operator_line("codex · auto · aylo")
        self.assertEqual(out, "hello")
        session.prompt.assert_called_once()

    def test_fallback_when_import_fails(self) -> None:
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name.startswith("prompt_toolkit"):
                raise ImportError("nope")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=fake_import):
            out = ask_operator_line("x", fallback=lambda _m: " pasted ")
        self.assertEqual(out, "pasted")


if __name__ == "__main__":
    unittest.main()
