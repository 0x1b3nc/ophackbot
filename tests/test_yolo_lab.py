"""YOLO mode + lab_exec / stack_prepare / burp_ensure (no live Burp/sudo)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot import yolo as yolo_mod
from hackbot.runners import lab_stack
from hackbot.tools import _normalize_tool_args, _require_approval, execute_tool
from hackbot.yolo import disable_yolo, enable_yolo, is_yolo


class YoloTests(unittest.TestCase):
    def tearDown(self) -> None:
        yolo_mod._YOLO_ACTIVE = False
        yolo_mod._YOLO_ENABLED_FORCE = False
        os.environ.pop("HACKBOT_YOLO", None)

    def test_yolo_skips_approve_prompt(self) -> None:
        enable_yolo(quiet=True)
        self.assertTrue(is_yolo())
        refusal = _require_approval(lambda _d: False, "should auto-allow under yolo")
        self.assertIsNone(refusal)

    def test_yolo_coerces_approve_on_run_tool(self) -> None:
        enable_yolo(quiet=True)
        out = _normalize_tool_args(
            "run_tool",
            {"target_dir": "targets/demo", "tool": "httpx", "host": "example.com"},
        )
        self.assertTrue(out.get("approve"))

    def test_disable_yolo(self) -> None:
        enable_yolo(quiet=True)
        disable_yolo()
        self.assertFalse(is_yolo())


class LabStackTests(unittest.TestCase):
    def test_sudo_password_from_file_not_leaked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pass_file = root / "sudo_pass"
            pass_file.write_text("s3cret-lab\n", encoding="utf-8")
            with mock.patch.object(lab_stack, "SUDO_PASS_FILE", pass_file):
                with mock.patch.dict(os.environ, {"HACKBOT_SUDO_PASS": ""}, clear=False):
                    os.environ.pop("HACKBOT_SUDO_PASS", None)
                    self.assertEqual(lab_stack.sudo_password(), "s3cret-lab")
                    with mock.patch("hackbot.runners.lab_stack.subprocess.run") as run:
                        run.return_value = mock.Mock(
                            returncode=0, stdout="ok\n", stderr="s3cret-lab leaked?\n"
                        )
                        result = lab_stack.lab_exec("echo hi", sudo=True, timeout_sec=5)
            self.assertTrue(result.get("ok"))
            self.assertNotIn("s3cret-lab", json.dumps(result))
            self.assertIn("***", result.get("stderr") or "")

    def test_stack_prepare_adds_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            go_bin = home / "go" / "bin"
            go_bin.mkdir(parents=True)
            (go_bin / "gau").write_text("x", encoding="utf-8")
            old_path = os.environ.get("PATH", "")
            try:
                # Ensure go_bin is not already on PATH so it gets added.
                os.environ["PATH"] = "/usr/bin"
                with mock.patch("hackbot.runners.lab_stack.Path.home", return_value=home):
                    with mock.patch(
                        "hackbot.runners.lab_stack.shutil.which",
                        side_effect=lambda n: str(go_bin / "gau") if n == "gau" else None,
                    ):
                        with mock.patch("hackbot.runners.lab_stack.subprocess.run") as run:
                            run.return_value = mock.Mock(
                                returncode=0, stdout="usage", stderr=""
                            )
                            result = lab_stack.stack_prepare()
                self.assertTrue(result.get("ok"))
                self.assertIn(str(go_bin), result.get("path_added") or [])
                self.assertIn("gau", result.get("found") or {})
            finally:
                os.environ["PATH"] = old_path

    def test_burp_ensure_missing_binary(self) -> None:
        with mock.patch("hackbot.runners.lab_stack._burp_already_up", return_value=None):
            with mock.patch("hackbot.runners.lab_stack._find_burpsuite", return_value=None):
                result = lab_stack.burp_ensure(wait_sec=1, download_ext=False)
        self.assertFalse(result.get("ok"))
        self.assertEqual(result.get("kind"), "needs_setup")

    def test_burp_ensure_already_up_sets_env(self) -> None:
        health = {
            "ok": True,
            "up": True,
            "base": "http://127.0.0.1:1337",
            "path": "/",
        }
        with mock.patch("hackbot.runners.lab_stack._burp_already_up", return_value=health):
            result = lab_stack.burp_ensure(wait_sec=1, download_ext=False)
        self.assertTrue(result.get("ok"))
        self.assertFalse(result.get("started"))
        self.assertEqual(os.environ.get("HACKBOT_BURP_BASE"), "http://127.0.0.1:1337")

    def test_lab_exec_tool_denied_without_approve(self) -> None:
        yolo_mod._YOLO_ACTIVE = False
        os.environ.pop("HACKBOT_YOLO", None)
        raw = execute_tool(
            "lab_exec",
            {"command": "echo hi"},
            approve_fn=lambda _d: False,
        )
        data = json.loads(raw)
        self.assertFalse(data.get("ok"))
        self.assertEqual(data.get("kind"), "denied")


if __name__ == "__main__":
    unittest.main()
