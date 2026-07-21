"""NL session import + image read — no slash commands required."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hackbot.local_agent import build_plan, interpret
from hackbot.session_import import extract_path_mentions, parse_sessions_text
from hackbot.tools import execute_tool


class SessionImportParseTests(unittest.TestCase):
    def test_yaml_sessions(self) -> None:
        text = """
sessions:
  A:
    authorization: Bearer aaa.bbb.ccc
  B:
    cookie: session=victim
"""
        parsed = parse_sessions_text(text)
        self.assertIn("A", parsed)
        self.assertIn("B", parsed)
        self.assertTrue(parsed["A"]["authorization"].startswith("Bearer"))
        self.assertEqual(parsed["B"]["cookie"], "session=victim")

    def test_prose_two_bearers(self) -> None:
        text = "Session A bearer tokAAAA1111\nSession B bearer tokBBBB2222"
        parsed = parse_sessions_text(text)
        self.assertIn("A", parsed)
        self.assertIn("B", parsed)

    def test_path_mentions_pt(self) -> None:
        text = "as credenciais estão no arquivo tokens.yaml na pasta Downloads"
        paths = extract_path_mentions(text)
        self.assertTrue(any("tokens.yaml" in p for p in paths))
        self.assertTrue(any("Downloads" in p for p in paths))


class NlSessionPlanTests(unittest.TestCase):
    def test_credentials_file_plans_load(self) -> None:
        text = (
            "as credenciais estão no arquivo tokens.yaml na pasta Downloads; "
            "depois explora o que der em example.com targets/demo"
        )
        interp = interpret(text)
        self.assertIn("set_session", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "load_sessions_from_file" for a in plan))
        self.assertTrue(any(a.tool == "run_hunt" for a in plan))

    def test_image_plans_read_image(self) -> None:
        text = "leia a imagem Desktop/scope.png e resume o scope"
        interp = interpret(text)
        self.assertIn("read_image", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "read_image" for a in plan))


class LoadSessionsToolTests(unittest.TestCase):
    def test_load_and_write(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text("# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8")
        creds = root / "tokens.yaml"
        creds.write_text(
            "sessions:\n  A:\n    bearer: tokAAAA11112222\n  B:\n    bearer: tokBBBB33334444\n",
            encoding="utf-8",
        )
        out = execute_tool(
            "load_sessions_from_file",
            {"target_dir": str(root), "path": str(creds), "write": True},
            approve_fn=lambda _d: True,
        )
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertTrue(data["written"])
        self.assertIn("A", data["saved"])
        self.assertTrue((root / "secrets" / "sessions.yaml").exists())


class ReadImageToolTests(unittest.TestCase):
    def test_missing_image(self) -> None:
        out = execute_tool("read_image", {"path": "targets/demo/nope.png"})
        data = json.loads(out)
        self.assertFalse(data["ok"])

    def test_png_metadata(self) -> None:
        # Minimal 1x1 PNG
        png = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
            b"\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "tiny.png"
        path.write_bytes(png)
        out = execute_tool("read_image", {"path": str(path)})
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertEqual(data["suffix"], ".png")


if __name__ == "__main__":
    unittest.main()
