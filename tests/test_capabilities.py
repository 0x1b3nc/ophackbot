"""Stack / capabilities visibility."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from hackbot.capabilities import collect_capabilities, compact_line
from hackbot.tools import execute_tool


class CapabilitiesTests(unittest.TestCase):
    def test_collect_has_bins_and_packs(self) -> None:
        caps = collect_capabilities(prompt="hunt bmw", probe_network=False)
        self.assertTrue(caps.get("ok"))
        self.assertIn("binaries", caps)
        self.assertIn("packs", caps)
        self.assertIn("recon", caps["packs"]["packs"])
        line = compact_line(caps)
        self.assertIn("packs=", line)

    def test_tool_returns_json(self) -> None:
        with mock.patch(
            "hackbot.capabilities._hexstrike",
            return_value={"name": "hexstrike", "ok": False, "detail": "test"},
        ):
            with mock.patch(
                "hackbot.capabilities._burp",
                return_value={"name": "burp_rest", "ok": False, "detail": "test"},
            ):
                out = json.loads(
                    execute_tool("capabilities", {"probe_network": False})
                )
        self.assertTrue(out.get("ok"))
        self.assertIn("how", out)


if __name__ == "__main__":
    unittest.main()
