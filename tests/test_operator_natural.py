"""Wave 1 operator natural: set_account, FS content, extract_page, disambiguation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from hackbot.accounts import load_accounts, save_account
from hackbot.local_agent import (
    _hosts_from_text,
    _parse_edit_replace,
    _parse_file_content,
    _parse_set_account,
    build_plan,
    interpret,
)
from hackbot.runners.extract_page import _parse_html, extract_page
from hackbot.tools import execute_tool


SCOPE = """# Scope

## In Scope
- example.com

## Explicitly Allowed
- Automated scanning
- Active testing
"""


class SetAccountTests(unittest.TestCase):
    def test_parse_account_slots(self) -> None:
        slots = _parse_set_account(
            "conta A email user@x.com senha Secret123 em targets/demo"
        )
        self.assertIsNotNone(slots)
        assert slots is not None
        self.assertEqual(slots["name"], "A")
        self.assertEqual(slots["username"], "user@x.com")
        self.assertEqual(slots["password"], "Secret123")

    def test_accounts_yaml_not_named_s(self) -> None:
        slots = _parse_set_account(
            "altere o accounts.yaml e coloque email a@x.com senha p"
        )
        self.assertIsNotNone(slots)
        assert slots is not None
        self.assertEqual(slots["name"], "A")

    def test_interpret_set_account_not_bootstrap(self) -> None:
        text = (
            "altere o accounts.yaml e coloque na conta A "
            "o email user@x.com e senha Secret123 targets/demo"
        )
        interp = interpret(text)
        self.assertIn("set_account", interp.intents)
        self.assertNotIn("session_bootstrap", interp.intents)
        self.assertNotIn("set_session", interp.intents)
        plan = build_plan(text, interp)
        tools = [a.tool for a in plan]
        self.assertIn("set_account", tools)
        self.assertNotIn("run_campaign", tools)
        self.assertNotIn("run_hunt", tools)
        acct = next(a for a in plan if a.tool == "set_account")
        self.assertEqual(acct.args["name"], "A")
        self.assertEqual(acct.args["username"], "user@x.com")
        self.assertEqual(acct.args["password"], "Secret123")

    def test_save_account_merge(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        save_account(root, "A", username="a@x.com", password="pa")
        save_account(root, "B", username="b@x.com", password="pb")
        save_account(root, "A", password="pa2")
        data = load_accounts(root)
        self.assertEqual(data.get("A").username, "a@x.com")  # type: ignore[union-attr]
        self.assertEqual(data.get("A").password, "pa2")  # type: ignore[union-attr]
        self.assertEqual(data.get("B").username, "b@x.com")  # type: ignore[union-attr]
        self.assertIn("login", (root / "secrets" / "accounts.yaml").read_text(encoding="utf-8"))

    def test_set_account_tool_approve(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        out = json.loads(
            execute_tool(
                "set_account",
                {
                    "target_dir": str(root),
                    "name": "A",
                    "username": "op@x.com",
                    "password": "secret",
                },
                approve_fn=lambda _d: True,
            )
        )
        self.assertTrue(out["ok"])
        self.assertEqual(out["account"]["password"], "***")
        self.assertEqual(load_accounts(root).get("A").username, "op@x.com")  # type: ignore[union-attr]


class FsContentTests(unittest.TestCase):
    def test_parse_file_content(self) -> None:
        self.assertEqual(
            _parse_file_content("cria arquivo x.md na pasta Downloads com o texto: hello"),
            "hello",
        )
        self.assertEqual(
            _parse_file_content('create file notes.txt content: "line one"'),
            "line one",
        )

    def test_write_file_plan_uses_content(self) -> None:
        text = "crie um arquivo na pasta Downloads chamado lab.md com o texto: hello bounty"
        interp = interpret(text)
        self.assertIn("write_file", interp.intents)
        plan = build_plan(text, interp)
        wf = next(a for a in plan if a.tool == "write_file")
        self.assertIn("hello bounty", wf.args["content"])

    def test_edit_replace_parse_and_plan(self) -> None:
        self.assertEqual(
            _parse_edit_replace('troca "foo" por "bar"'),
            ("foo", "bar"),
        )
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "notes.md"
        path.write_text("foo\n", encoding="utf-8")
        text = f'edita o arquivo {path} troca "foo" por "bar"'
        interp = interpret(text)
        self.assertIn("edit_file", interp.intents)
        plan = build_plan(text, interp)
        ed = next(a for a in plan if a.tool == "edit_file")
        self.assertEqual(ed.args["old_string"], "foo")
        self.assertEqual(ed.args["new_string"], "bar")


class ExtractPageTests(unittest.TestCase):
    def test_parse_html(self) -> None:
        html = (
            "<html><head><title>Hello</title></head>"
            "<body><script>x()</script><p>Body text</p>"
            '<a href="/a">A</a></body></html>'
        )
        parsed = _parse_html(html, "https://example.com/")
        self.assertEqual(parsed["title"], "Hello")
        self.assertIn("Body text", parsed["text"])
        self.assertIn("https://example.com/a", parsed["links"])

    def test_nl_extract_page_plan(self) -> None:
        text = "extrai o conteudo de https://example.com/login targets/demo"
        interp = interpret(text)
        self.assertIn("extract_page", interp.intents)
        plan = build_plan(text, interp)
        tools = [a.tool for a in plan]
        self.assertIn("extract_page", tools)
        ep = next(a for a in plan if a.tool == "extract_page")
        self.assertIn("example.com", ep.args["url"])

    def test_extract_page_dry_run(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        result = extract_page(root, "https://example.com/", approve=False, force=True)
        data = json.loads(result.stdout)
        self.assertTrue(data.get("dry_run"))

    def test_extract_page_tool_executed_mock(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = b"<html><head><title>T</title></head><body>Hi there page</body></html>"
        mock_resp.url = "https://example.com/"
        mock_resp.headers = {}
        with patch("hackbot.scoped_http.scoped_fetch_bytes", return_value=mock_resp):
            out = json.loads(
                execute_tool(
                    "extract_page",
                    {
                        "target_dir": str(root),
                        "url": "https://example.com/",
                        "approve": True,
                        "force": True,
                    },
                    approve_fn=lambda _d: True,
                )
            )
        self.assertTrue(out.get("ok"))
        self.assertTrue(out.get("executed"))
        self.assertEqual(out.get("title"), "T")
        self.assertIn("Hi there", out.get("text") or "")


class ImageHostHelperTests(unittest.TestCase):
    def test_hosts_from_text(self) -> None:
        hosts = _hosts_from_text("In scope: api.foo-bar.io and app.foo-bar.io")
        self.assertIn("api.foo-bar.io", hosts)
        self.assertIn("app.foo-bar.io", hosts)


if __name__ == "__main__":
    unittest.main()
