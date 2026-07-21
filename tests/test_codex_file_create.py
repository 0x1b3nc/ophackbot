"""Codex path: clear create-file NL must not invent kit-only write limits."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.codex_backend import _build_prompt, _try_direct_file_create, run_codex_turn


class CodexFileCreateTests(unittest.TestCase):
    def test_resume_prompt_restates_fileop_rules(self) -> None:
        prompt = _build_prompt(
            "criar um .md chamado scopetest na pasta de downloads",
            [("user", "Olá"), ("hackbot", "Oi")],
            chat_mode=False,
            resume=True,
        )
        self.assertIn("hackbot-fileop", prompt)
        self.assertIn("Downloads", prompt)
        self.assertIn("NEVER say you can only write inside the repo", prompt)
        self.assertIn("scopetest.md", prompt.replace("\\", "/"))

    def test_direct_create_skips_codex(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "scopetest.md"
            with mock.patch(
                "hackbot.local_agent._parse_create_file_path",
                return_value=str(target),
            ):
                with mock.patch(
                    "hackbot.codex_backend._try_direct_file_create",
                    wraps=_try_direct_file_create,
                ):
                    msg = run_codex_turn(
                        "criar um .md chamado scopetest na pasta de downloads",
                        history=[("user", "Olá"), ("hackbot", "Oi")],
                        approve_fn=lambda _d: True,
                        allow_file_ops=True,
                    )
            self.assertTrue(target.exists())
            self.assertIn("scopetest.md", msg)
            self.assertIn("# scopetest", target.read_text(encoding="utf-8"))

    def test_try_direct_denied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "x.md"
            with mock.patch(
                "hackbot.local_agent._parse_create_file_path",
                return_value=str(target),
            ):
                msg = _try_direct_file_create(
                    "criar um .md chamado x na pasta de downloads",
                    approve_fn=lambda _d: False,
                )
            self.assertIsNotNone(msg)
            self.assertFalse(target.exists())
            self.assertIn("approve", msg.lower())


if __name__ == "__main__":
    unittest.main()
