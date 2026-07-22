"""extract_page: public program JSON + no-login defaults."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.runners.extract_page import (
    _detect_spa,
    _program_summary_from_embeds,
    extract_page,
)


class ExtractPagePublicTests(unittest.TestCase):
    def test_program_json_preferred_no_login_hint(self) -> None:
        html = (
            "<html><head><title>Acme BB</title>"
            '<script id="__NEXT_DATA__" type="application/json">'
            + json.dumps(
                {
                    "props": {
                        "pageProps": {
                            "program": {
                                "name": "Acme",
                                "inScope": ["*.acme.com", "api.acme.com"],
                                "outOfScope": ["blog.acme.com"],
                                "maxBounty": 5000,
                            }
                        }
                    }
                }
            )
            + "</script></head><body><div id='root'></div>"
            "<p>Sign in Get started Pricing Careers</p></body></html>"
        )

        class FakeResp:
            status = 200
            body = html.encode()
            url = "https://app.intigriti.com/programs/acme"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(
                "# Scope\n\n## In scope\n- app.intigriti.com\n", encoding="utf-8"
            )
            with mock.patch(
                "hackbot.scoped_http.scoped_fetch_bytes", return_value=FakeResp()
            ):
                # render would fire without program json; with json it must NOT require login
                result = extract_page(
                    root,
                    "https://app.intigriti.com/programs/acme",
                    approve=True,
                    force=True,
                    save=True,
                    render=False,
                )
            data = json.loads(result.stdout)
            self.assertTrue(data["ok"])
            self.assertTrue(data["has_program_json"])
            self.assertFalse(data["login_required"])
            self.assertIn("inScope", data["text"])
            self.assertIn("*.acme.com", data["text"])
            self.assertTrue(data.get("saved_json") or data.get("saved_text"))
            self.assertNotIn("needs_session", data)

    def test_summary_walker(self) -> None:
        embeds = [
            (
                "__NEXT_DATA__",
                json.dumps({"program": {"inScope": ["a.com"], "bounty": 1}}),
            )
        ]
        prog = _program_summary_from_embeds(embeds)
        self.assertTrue(prog["has_program_json"])
        self.assertGreater(prog["program_keys_found"], 0)

    def test_spa_detect(self) -> None:
        spa = _detect_spa('<div id="root"></div>' + ("<script></script>" * 9), "")
        self.assertTrue(spa["likely_spa"])


if __name__ == "__main__":
    unittest.main()
