"""Offline NL: create a file in Downloads without listing the whole folder."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from hackbot.local_agent import build_plan, interpret, _parse_create_file_path
from hackbot.prompt_router import model_usable_for_route, offline_confidence, route_prompt


class CreateFileNlTests(unittest.TestCase):
    def test_parse_pt_downloads_chamado(self) -> None:
        path = _parse_create_file_path(
            "crie um arquivo na pasta downloads chamado scope.md"
        )
        self.assertEqual(path, str(Path.home() / "Downloads" / "scope.md"))

    def test_parse_pt_md_chamado_pasta_de_downloads(self) -> None:
        path = _parse_create_file_path(
            "criar um .md chamado scopetest na pasta de downloads"
        )
        self.assertEqual(path, str(Path.home() / "Downloads" / "scopetest.md"))

    def test_interpret_write_file_not_list_dir(self) -> None:
        interp = interpret("crie um arquivo na pasta downloads chamado scope.md")
        self.assertIn("write_file", interp.intents)
        self.assertNotIn("list_dir", interp.intents)
        self.assertNotIn("scope", interp.intents)

    def test_plan_is_single_write_file(self) -> None:
        text = "crie um arquivo na pasta downloads chamado scope.md"
        interp = interpret(text)
        plan = build_plan(text, interp)
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0].tool, "write_file")
        self.assertEqual(plan[0].args["path"], str(Path.home() / "Downloads" / "scope.md"))
        self.assertIn("Scope", plan[0].args["content"])

    def test_confidence_high_enough_offline(self) -> None:
        conf = offline_confidence(
            "crie um arquivo na pasta downloads chamado scope.md",
            host=None,
            intents=["write_file"],
            classes=["recon"],
        )
        self.assertGreaterEqual(conf, 0.68)

    def test_route_skips_llm_without_explicit_provider(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"HACKBOT_PROVIDER": "", "HACKBOT_BACKEND": "", "HACKBOT_LOCAL": ""},
            clear=False,
        ):
            os.environ.pop("HACKBOT_PROVIDER", None)
            os.environ.pop("HACKBOT_BACKEND", None)
            self.assertFalse(model_usable_for_route())
            with mock.patch("hackbot.prompt_router.llm_interpret") as llm:
                d = route_prompt(
                    "crie um arquivo na pasta downloads chamado scope.md",
                    host=None,
                    intents=["write_file"],
                    classes=["recon"],
                )
                llm.assert_not_called()
                self.assertEqual(d.source, "offline")


if __name__ == "__main__":
    unittest.main()
