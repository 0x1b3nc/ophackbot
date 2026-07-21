"""Codex path: clear create-file NL must not invent kit-only write limits."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.codex_backend import (
    _build_prompt,
    _fileop_continue_prompt,
    _try_direct_file_create,
    codex_sandbox_mode,
    run_codex_turn,
)


class CodexFileCreateTests(unittest.TestCase):
    def test_sandbox_default_allows_network_writes(self) -> None:
        with mock.patch.dict(os.environ, {"HACKBOT_CODEX_SANDBOX": ""}, clear=False):
            os.environ.pop("HACKBOT_CODEX_SANDBOX", None)
            with mock.patch("hackbot.yolo.is_yolo", return_value=False):
                self.assertEqual(codex_sandbox_mode(), "workspace-write")
            with mock.patch("hackbot.yolo.is_yolo", return_value=True):
                self.assertEqual(codex_sandbox_mode(), "danger-full-access")
        with mock.patch.dict(
            os.environ, {"HACKBOT_CODEX_SANDBOX": "read-only"}, clear=False
        ):
            self.assertEqual(codex_sandbox_mode(), "read-only")

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

    def test_fileop_continue_prompt_keeps_original_task(self) -> None:
        text = _fileop_continue_prompt(
            "inicie o hunting no aylo",
            [{"tool": "write_file", "path": "targets/aylo/SCOPE.md", "ok": True}],
        )
        self.assertIn("write_file", text)
        self.assertIn("SCOPE.md", text)
        self.assertIn("inicie o hunting no aylo", text)
        self.assertIn("Do NOT re-emit", text)

    def test_fileop_auto_continues_after_approve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "SCOPE.md"
            first = (
                "Vou criar o SCOPE.\n\n```hackbot-fileop\n"
                + json.dumps(
                    {
                        "op": "write_file",
                        "path": str(target),
                        "content": "---\nin_scope: []\n",
                    },
                    ensure_ascii=False,
                )
                + "\n```\n"
            )
            second = "SCOPE ok. Proximo passo: dry-run httpx."
            answers = [first, second]
            calls: list[str] = []

            def _fake_run(cmd: list[str], prompt: str, timeout: int) -> tuple[str, str]:
                del timeout
                calls.append(prompt)
                out = Path(cmd[cmd.index("-o") + 1])
                out.write_text(answers.pop(0) if answers else second, encoding="utf-8")
                return ("", "")

            with mock.patch.dict(
                os.environ,
                {
                    "HACKBOT_STREAM": "0",
                    "HACKBOT_FILEOP_CONTINUE": "1",
                    "HACKBOT_CODEX_RESUME": "0",
                    "HACKBOT_MODEL": "",
                },
                clear=False,
            ):
                with mock.patch("hackbot.codex_backend._run_quiet", side_effect=_fake_run):
                    msg = run_codex_turn(
                        "inicie o hunting",
                        history=[("user", "oi"), ("hackbot", "fala")],
                        approve_fn=lambda _d: True,
                        allow_file_ops=True,
                    )
            self.assertTrue(target.exists())
            self.assertGreaterEqual(len(calls), 2)
            self.assertIn("file-op", calls[1].lower())
            self.assertIn("dry-run httpx", msg)


if __name__ == "__main__":
    unittest.main()
