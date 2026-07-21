"""Windows bridge patch for cursor-sdk discovery."""

from __future__ import annotations

import os
import unittest
from unittest import mock


class CursorBridgeWinTests(unittest.TestCase):
    def test_patch_applies_on_windows_only(self) -> None:
        from hackbot import cursor_bridge_win

        cursor_bridge_win._PATCHED = False
        with mock.patch.object(os, "name", "nt"):
            # Even without cursor_sdk, should not crash
            try:
                import cursor_sdk  # noqa: F401

                has_sdk = True
            except ImportError:
                has_sdk = False
            ok = cursor_bridge_win.apply_windows_bridge_patch()
            if has_sdk:
                self.assertTrue(ok)
                self.assertTrue(cursor_bridge_win._PATCHED)
                # Idempotent
                self.assertTrue(cursor_bridge_win.apply_windows_bridge_patch())

    def test_patch_noop_on_posix(self) -> None:
        from hackbot import cursor_bridge_win

        cursor_bridge_win._PATCHED = False
        with mock.patch.object(os, "name", "posix"):
            self.assertFalse(cursor_bridge_win.apply_windows_bridge_patch())
            self.assertFalse(cursor_bridge_win._PATCHED)


if __name__ == "__main__":
    unittest.main()
