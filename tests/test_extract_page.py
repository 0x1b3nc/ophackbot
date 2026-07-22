"""extract_page SPA detection + artifact persistence."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.runners.base import RunnerResult
from hackbot.runners.extract_page import _detect_spa, _parse_html, extract_page


class ExtractPageUpgradeTests(unittest.TestCase):
    def test_spa_detection(self) -> None:
        html = '<div id="root"></div><script></script>' * 10
        spa = _detect_spa(html, "Sign in Get started Pricing")
        self.assertTrue(spa["likely_spa"])

    def test_parse_and_save_artifacts(self) -> None:
        html = (
            "<html><head><title>Prog</title>"
            '<script id="__NEXT_DATA__" type="application/json">'
            '{"props":[{"asset":"*.example.com"}]}</script></head>'
            "<body><div id='root'></div><p>Public marketing shell Sign in</p>"
            '<a href="/program">prog</a></body></html>'
        )

        class FakeResp:
            status = 200
            body = html.encode()
            url = "https://app.intigriti.com/programs/x"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(
                "# Scope\n\n## In scope\n- app.intigriti.com\n", encoding="utf-8"
            )
            with mock.patch(
                "hackbot.scoped_http.scoped_fetch_bytes", return_value=FakeResp()
            ):
                result = extract_page(
                    root,
                    "https://app.intigriti.com/programs/x",
                    approve=True,
                    force=True,
                    save=True,
                )
            data = json.loads(result.stdout)
            self.assertTrue(data.get("ok"))
            self.assertTrue(data.get("saved_text"))
            self.assertTrue(Path(data["saved_text"]).is_file())
            self.assertTrue(data.get("saved_html"))
            self.assertTrue(data.get("needs_browser") or data.get("likely_spa"))
            self.assertIn("next_tools", data)
            self.assertGreater(data.get("embedded_json_chars") or 0, 0)


if __name__ == "__main__":
    unittest.main()
