"""Cursor CustomTool bridge — in-process execute_tool + approve."""

from __future__ import annotations

import json
import os
import sys
import types
import unittest
from unittest import mock

from hackbot.cursor_tools import (
    build_cursor_custom_tools,
    cursor_tools_enabled,
    set_cursor_approve_fn,
)


class CursorToolsTests(unittest.TestCase):
    def setUp(self) -> None:
        # Minimal CustomTool type for import
        types_mod = types.ModuleType("cursor_sdk.types")

        class _CustomTool:
            def __init__(self, execute=None, description=None, input_schema=None):
                self.execute = execute
                self.description = description
                self.input_schema = input_schema

        types_mod.CustomTool = _CustomTool
        sdk = types.ModuleType("cursor_sdk")
        sdk.types = types_mod
        sys.modules["cursor_sdk"] = sdk
        sys.modules["cursor_sdk.types"] = types_mod

    def tearDown(self) -> None:
        set_cursor_approve_fn(None)

    def test_disabled_returns_empty(self) -> None:
        with mock.patch.dict(os.environ, {"HACKBOT_CURSOR_TOOLS": "0"}, clear=False):
            self.assertFalse(cursor_tools_enabled())
            self.assertEqual(build_cursor_custom_tools("hunt example.com"), {})

    def test_builds_filtered_tools(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"HACKBOT_CURSOR_TOOLS": "1", "HACKBOT_TOOL_PACK": "core"},
            clear=False,
        ):
            tools = build_cursor_custom_tools("status")
        self.assertIn("list_targets", tools)
        self.assertIn("session_status", tools)
        self.assertNotIn("http_request", tools)  # inject pack

    def test_execute_respects_approve_holder(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"HACKBOT_CURSOR_TOOLS": "1", "HACKBOT_TOOL_PACK": "core"},
            clear=False,
        ):
            tools = build_cursor_custom_tools("")
        calls: list[str] = []

        def approve(detail: str) -> bool:
            calls.append(detail)
            return False

        set_cursor_approve_fn(approve)
        with mock.patch(
            "hackbot.cursor_tools.execute_tool",
            return_value=json.dumps({"ok": True}),
        ) as ex:
            out = tools["list_targets"].execute({}, None)
        self.assertIn("ok", out)
        ex.assert_called_once()
        self.assertIs(ex.call_args.kwargs.get("approve_fn"), approve)

    def test_execute_is_serialized(self) -> None:
        import threading
        import time

        with mock.patch.dict(
            os.environ,
            {"HACKBOT_CURSOR_TOOLS": "1", "HACKBOT_TOOL_PACK": "core"},
            clear=False,
        ):
            tools = build_cursor_custom_tools("")
        order: list[str] = []

        def slow_execute(name, args, approve_fn=None):
            order.append("start")
            time.sleep(0.08)
            order.append("end")
            return json.dumps({"ok": True})

        with mock.patch("hackbot.cursor_tools.execute_tool", side_effect=slow_execute):
            t1 = threading.Thread(target=lambda: tools["list_targets"].execute({}, None))
            t1.start()
            time.sleep(0.02)
            t2 = threading.Thread(target=lambda: tools["session_status"].execute({}, None))
            t2.start()
            t1.join(timeout=2)
            t2.join(timeout=2)
        self.assertEqual(order, ["start", "end", "start", "end"])


if __name__ == "__main__":
    unittest.main()
