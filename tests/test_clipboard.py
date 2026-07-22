"""Clipboard helper tests (OS backends mocked)."""

from __future__ import annotations

import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

from hackbot.clipboard import copy_text, normalize_copied_text


class NormalizeTests(unittest.TestCase):
    def test_strips_trailing_cell_padding(self) -> None:
        raw = "› /yolo on" + (" " * 80) + "\n" + "yolo **on**" + (" " * 120)
        out = normalize_copied_text(raw)
        self.assertEqual(out, "› /yolo on\nyolo **on**")

    def test_keeps_leading_indent(self) -> None:
        raw = "    def foo():\n        return 1" + (" " * 40)
        out = normalize_copied_text(raw)
        self.assertEqual(out, "    def foo():\n        return 1")

    def test_collapses_huge_mid_line_gap(self) -> None:
        raw = "hello" + (" " * 60) + "world"
        out = normalize_copied_text(raw)
        self.assertEqual(out, "hello world")


class ClipboardTests(unittest.TestCase):
    def test_empty_rejected(self) -> None:
        ok, method = copy_text("   ")
        self.assertFalse(ok)
        self.assertEqual(method, "empty")

    def test_normalize_on_copy(self) -> None:
        seen: list[str] = []

        def _osc(data: str) -> None:
            seen.append(data)

        padded = "hi" + (" " * 50)
        with mock.patch("hackbot.clipboard.sys.platform", "linux"):
            with mock.patch("hackbot.clipboard.shutil.which", return_value=None):
                import builtins

                real_import = builtins.__import__

                def _no_pyperclip(name, *a, **k):  # noqa: ANN001
                    if name == "pyperclip":
                        raise ImportError("nope")
                    return real_import(name, *a, **k)

                with mock.patch("builtins.__import__", side_effect=_no_pyperclip):
                    ok, method = copy_text(padded, osc52_write=_osc)
        self.assertTrue(ok)
        self.assertEqual(method, "osc52")
        self.assertEqual(seen, ["hi"])

    def test_file_fallback_when_everything_missing(self) -> None:
        with mock.patch("hackbot.clipboard.sys.platform", "linux"):
            with mock.patch("hackbot.clipboard.shutil.which", return_value=None):
                import builtins

                real_import = builtins.__import__

                def _no_pyperclip(name, *a, **k):  # noqa: ANN001
                    if name == "pyperclip":
                        raise ImportError("nope")
                    return real_import(name, *a, **k)

                with mock.patch("builtins.__import__", side_effect=_no_pyperclip):
                    ok, method = copy_text("hello fallback")
        self.assertTrue(ok)
        self.assertTrue(method.startswith("file:"))
        path = Path(method.split(":", 1)[1])
        self.assertTrue(path.exists())
        self.assertIn("hello fallback", path.read_text(encoding="utf-8"))
        path.unlink(missing_ok=True)

    @unittest.skipUnless(sys.platform == "win32", "Windows clipboard")
    def test_windows_roundtrip(self) -> None:
        marker = f"hb-clip-test-{uuid.uuid4().hex[:8]}"
        ok, method = copy_text(marker)
        self.assertTrue(ok)
        self.assertIn(method, {"powershell", "clip"})


if __name__ == "__main__":
    unittest.main()
