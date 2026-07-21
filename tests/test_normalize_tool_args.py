"""Active-session target_dir injection for Cursor-omitted args."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.session import TargetSession, clear_active
from hackbot.tools import _normalize_tool_args, execute_tool


class NormalizeToolArgsTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_active()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.target = self.root / "targets" / "bmwgroup"
        self.target.mkdir(parents=True)
        (self.target / "SCOPE.md").write_text(
            "---\nin_scope: [www.bmw.de]\n---\n", encoding="utf-8"
        )
        self.session = TargetSession(target_dir=self.target, name="bmwgroup")

    def tearDown(self) -> None:
        clear_active()

    def test_injects_target_dir_from_active(self) -> None:
        with mock.patch("hackbot.tools.get_active", return_value=self.session):
            out = _normalize_tool_args("http_request", {"url": "https://www.bmw.de/"})
        self.assertEqual(out["target_dir"], "targets/bmwgroup")

    def test_target_alias_to_target_dir(self) -> None:
        with mock.patch("hackbot.tools.ROOT", self.root):
            with mock.patch("hackbot.tools.get_active", return_value=None):
                out = _normalize_tool_args("show_identity", {"target": "bmwgroup"})
        self.assertEqual(out["target_dir"], "targets/bmwgroup")

    def test_missing_key_soft_error_not_tool_bug(self) -> None:
        empty = self.root / "empty_targets"
        empty.mkdir(exist_ok=True)
        with mock.patch("hackbot.tools.TARGETS", empty):
            with mock.patch("hackbot.tools.get_active", return_value=None):
                with mock.patch("hackbot.tools._guess_target_name", return_value=""):
                    out = execute_tool("set_target", {})
        data = json.loads(out)
        self.assertFalse(data.get("ok", True))
        self.assertEqual(data.get("kind"), "bad_args")

    def test_set_target_blank_uses_bmwgroup(self) -> None:
        with mock.patch("hackbot.tools.ROOT", self.root):
            with mock.patch("hackbot.tools.TARGETS", self.root / "targets"):
                with mock.patch("hackbot.tools.get_active", return_value=None):
                    out = _normalize_tool_args("set_target", {"target": ""})
        self.assertEqual(out.get("target"), "bmwgroup")


if __name__ == "__main__":
    unittest.main()
