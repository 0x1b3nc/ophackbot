"""Approval gate and path blocklist for mutating tools."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hackbot.tools import execute_tool


class WriteFileApprovalTests(unittest.TestCase):
    def test_write_file_denied_when_operator_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "x.txt"
            result = execute_tool(
                "write_file",
                {"path": str(target), "content": "x"},
                approve_fn=lambda _d: False,
            )
            data = json.loads(result)
            self.assertFalse(data["ok"])
            self.assertEqual(data.get("kind"), "denied")
            self.assertFalse(target.exists())

    def test_write_file_allowed_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "ok.txt"
            result = execute_tool(
                "write_file",
                {"path": str(target), "content": "hello"},
                approve_fn=lambda _d: True,
            )
            data = json.loads(result)
            self.assertTrue(data["ok"])
            self.assertEqual(target.read_text(encoding="utf-8"), "hello")

    def test_delete_path_denied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "keep.txt"
            target.write_text("stay", encoding="utf-8")
            result = execute_tool(
                "delete_path",
                {"path": str(target)},
                approve_fn=lambda _d: False,
            )
            data = json.loads(result)
            self.assertFalse(data["ok"])
            self.assertTrue(target.exists())


class PathBlocklistTests(unittest.TestCase):
    def test_ssh_path_blocked_without_asking(self) -> None:
        called: list[str] = []

        def approve(desc: str) -> bool:
            called.append(desc)
            return True

        ssh = Path.home() / ".ssh" / "id_rsa"
        result = execute_tool(
            "write_file",
            {"path": str(ssh), "content": "nope"},
            approve_fn=approve,
        )
        data = json.loads(result)
        self.assertFalse(data["ok"])
        self.assertEqual(data.get("kind"), "path_blocked")
        self.assertEqual(called, [])


class ScopeDeniedKindTests(unittest.TestCase):
    def test_run_tool_out_of_scope_is_scope_denied(self) -> None:
        # demo SCOPE has example.com; evil.com must raise PermissionError -> scope_denied
        result = execute_tool(
            "run_tool",
            {
                "target_dir": "targets/demo",
                "tool": "httpx",
                "host": "evil.com",
                "approve": False,
            },
            approve_fn=lambda _d: False,
        )
        data = json.loads(result)
        self.assertFalse(data["ok"])
        self.assertEqual(data.get("kind"), "scope_denied")


if __name__ == "__main__":
    unittest.main()
