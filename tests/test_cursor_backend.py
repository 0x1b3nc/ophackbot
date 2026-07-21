"""Cursor SDK brain: availability, turns, fileops — no live network."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from hackbot import cursor_backend
from hackbot.cursor_backend import (
    close_cursor_agent,
    cursor_available,
    run_cursor_turn,
)
from hackbot.providers import PROVIDERS, resolve_config


class _FakeResult:
    def __init__(self, status: str = "finished", text: str = "", run_id: str = "run-1"):
        self.status = status
        self.text = text
        self.result = text
        self.id = run_id


class _FakeRun:
    def __init__(self, text: str, status: str = "finished"):
        self._text = text
        self._status = status
        self.id = "run-1"

    def messages(self):
        return iter(())

    def stream(self):
        return self.messages()

    def wait(self):
        return _FakeResult(status=self._status, text=self._text)

    def text(self):
        return self._text

    def supports(self, _op: str) -> bool:
        return False


class _FakeAgent:
    def __init__(self):
        self.agent_id = "agent-test-1"
        self.closed = False
        self.prompts: list[str] = []
        self.next_text = "Olá do cursor."
        self.next_status = "finished"

    def send(self, prompt: str, **_kwargs):
        self.prompts.append(prompt)
        return _FakeRun(self.next_text, status=self.next_status)

    def close(self):
        self.closed = True


def _install_fake_sdk(agent: _FakeAgent) -> types.ModuleType:
    """Inject a minimal cursor_sdk module into sys.modules."""

    class _LocalAgentOptions:
        def __init__(self, cwd: str = "."):
            self.cwd = cwd

    class _AgentOptions:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class _SendOptions:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class _AgentAPI:
        @staticmethod
        def create(*args, **kwargs):
            return agent

    mod = types.ModuleType("cursor_sdk")
    mod.Agent = _AgentAPI
    mod.LocalAgentOptions = _LocalAgentOptions
    mod.AgentOptions = _AgentOptions
    mod.SendOptions = _SendOptions
    sys.modules["cursor_sdk"] = mod
    return mod


class CursorProviderRegistryTests(unittest.TestCase):
    def test_cursor_provider_registered(self) -> None:
        p = PROVIDERS["cursor"]
        self.assertEqual(p.wire, "cursor")
        self.assertIn("CURSOR_API_KEY", p.key_envs)
        self.assertEqual(p.default_model, "composer-2.5")

    def test_resolve_config_needs_key(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"HACKBOT_PROVIDER": "cursor", "CURSOR_API_KEY": ""},
            clear=False,
        ):
            os.environ.pop("CURSOR_API_KEY", None)
            with mock.patch("hackbot.providers._user_env_windows", return_value=None):
                with self.assertRaises(Exception):
                    resolve_config()

    def test_resolve_config_with_key(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"HACKBOT_PROVIDER": "cursor", "CURSOR_API_KEY": "cursor_test_key"},
            clear=False,
        ):
            cfg = resolve_config()
            self.assertEqual(cfg.provider, "cursor")
            self.assertEqual(cfg.wire, "cursor")
            self.assertEqual(cfg.api_key, "cursor_test_key")


class CursorAvailableTests(unittest.TestCase):
    def tearDown(self) -> None:
        close_cursor_agent()
        sys.modules.pop("cursor_sdk", None)

    def test_false_without_key(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CURSOR_API_KEY", None)
            with mock.patch("hackbot.providers._user_env_windows", return_value=None):
                self.assertFalse(cursor_available())

    def test_false_without_sdk(self) -> None:
        with mock.patch.dict(os.environ, {"CURSOR_API_KEY": "k"}, clear=False):
            sys.modules.pop("cursor_sdk", None)
            with mock.patch.dict(sys.modules, {"cursor_sdk": None}):
                # Force import failure
                real_import = __import__

                def fake_import(name, *a, **k):
                    if name == "cursor_sdk":
                        raise ImportError("missing")
                    return real_import(name, *a, **k)

                with mock.patch("builtins.__import__", side_effect=fake_import):
                    self.assertFalse(cursor_available())

    def test_true_with_key_and_sdk(self) -> None:
        agent = _FakeAgent()
        _install_fake_sdk(agent)
        with mock.patch.dict(os.environ, {"CURSOR_API_KEY": "k"}, clear=False):
            self.assertTrue(cursor_available())


class CursorTurnTests(unittest.TestCase):
    def setUp(self) -> None:
        close_cursor_agent()
        self.agent = _FakeAgent()
        _install_fake_sdk(self.agent)

    def tearDown(self) -> None:
        close_cursor_agent()
        sys.modules.pop("cursor_sdk", None)

    def test_turn_returns_assistant_text(self) -> None:
        self.agent.next_text = "Pronto para caçar."
        with mock.patch.dict(
            os.environ,
            {
                "CURSOR_API_KEY": "cursor_test",
                "HACKBOT_STREAM": "0",
                "HACKBOT_CURSOR_MODE": "plan",
            },
            clear=False,
        ):
            answer = run_cursor_turn("Olá", approve_fn=lambda _d: False)
        self.assertIn("Pronto", answer)
        self.assertEqual(len(self.agent.prompts), 1)
        self.assertIn("Hackbot", self.agent.prompts[0])

    def test_fileop_requires_approve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "from-cursor.md"
            block = (
                "Vou criar o arquivo.\n\n"
                "```hackbot-fileop\n"
                + json.dumps(
                    {"op": "write_file", "path": str(target), "content": "# hi\n"},
                    ensure_ascii=False,
                )
                + "\n```\n"
            )
            self.agent.next_text = block
            with mock.patch.dict(
                os.environ,
                {"CURSOR_API_KEY": "cursor_test", "HACKBOT_STREAM": "0"},
                clear=False,
            ):
                answer = run_cursor_turn(
                    "faz um arquivo de teste no tmp",
                    approve_fn=lambda _d: False,
                    allow_file_ops=True,
                )
            self.assertFalse(target.exists())
            self.assertNotIn("Criei", answer)

    def test_fileop_writes_when_approved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "ok.md"
            block = (
                "ok\n\n```hackbot-fileop\n"
                + json.dumps(
                    {"op": "write_file", "path": str(target), "content": "# ok\n"},
                    ensure_ascii=False,
                )
                + "\n```\n"
            )
            self.agent.next_text = block
            with mock.patch.dict(
                os.environ,
                {"CURSOR_API_KEY": "cursor_test", "HACKBOT_STREAM": "0"},
                clear=False,
            ):
                run_cursor_turn(
                    "write notes please",
                    approve_fn=lambda _d: True,
                    allow_file_ops=True,
                )
            self.assertTrue(target.exists())
            self.assertIn("# ok", target.read_text(encoding="utf-8"))

    def test_direct_create_skips_sdk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "scopetest.md"
            with mock.patch(
                "hackbot.local_agent._parse_create_file_path",
                return_value=str(target),
            ):
                with mock.patch.dict(
                    os.environ, {"CURSOR_API_KEY": "cursor_test"}, clear=False
                ):
                    msg = run_cursor_turn(
                        "criar um .md chamado scopetest na pasta de downloads",
                        approve_fn=lambda _d: True,
                    )
            self.assertTrue(target.exists())
            self.assertIn("scopetest", msg)
            self.assertEqual(self.agent.prompts, [])

    def test_close_disposes_agent(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"CURSOR_API_KEY": "cursor_test", "HACKBOT_STREAM": "0"},
            clear=False,
        ):
            run_cursor_turn("oi", approve_fn=lambda _d: False)
        self.assertIsNotNone(cursor_backend._AGENT)
        close_cursor_agent()
        self.assertIsNone(cursor_backend._AGENT)
        self.assertTrue(self.agent.closed)

    def test_run_error_status(self) -> None:
        self.agent.next_text = ""
        self.agent.next_status = "error"
        with mock.patch.dict(
            os.environ,
            {"CURSOR_API_KEY": "cursor_test", "HACKBOT_STREAM": "0"},
            clear=False,
        ):
            answer = run_cursor_turn("explora example.com", approve_fn=lambda _d: False)
        self.assertIn("cursor", answer.lower())
        self.assertIn("error", answer.lower())


if __name__ == "__main__":
    unittest.main()
