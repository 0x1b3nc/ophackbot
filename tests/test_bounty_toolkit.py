"""New bounty toolkit: JWT, HAR, JS, GraphQL, CORS, params, crt/wayback."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from hackbot.local_agent import build_plan, interpret
from hackbot.runners.jwt_analyze import analyze_jwt
from hackbot.runners.har_import import import_har
from hackbot.tools import execute_tool


def _jwt(header: dict, payload: dict) -> str:
    def enc(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{enc(header)}.{enc(payload)}.sig"


class JwtTests(unittest.TestCase):
    def test_alg_none(self) -> None:
        token = _jwt({"alg": "none", "typ": "JWT"}, {"sub": "1", "role": "admin"})
        out = analyze_jwt(token)
        self.assertTrue(out["ok"])
        self.assertGreaterEqual(out["issue_count"], 1)
        self.assertTrue(any("none" in i.lower() for i in out["issues"]))


class HarImportTests(unittest.TestCase):
    def test_import_seeds_surface(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        har = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://example.com/api/users?id=1",
                            "headers": [{"name": "Authorization", "value": "Bearer x"}],
                        },
                        "response": {"status": 200},
                    }
                ]
            }
        }
        path = root / "traffic.har"
        path.write_text(json.dumps(har), encoding="utf-8")
        (root / "SCOPE.md").write_text("# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8")
        result = import_har(path, root)
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(result["endpoints_seeded"], 1)
        self.assertTrue((root / "hunt" / "surface.yaml").exists())


class NlNewToolsPlanTests(unittest.TestCase):
    def test_har_prompt(self) -> None:
        text = "importa o arquivo traffic.har em Downloads para targets/demo"
        interp = interpret(text)
        self.assertIn("import_har", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "import_har" for a in plan))

    def test_jwt_prompt(self) -> None:
        token = _jwt({"alg": "HS256"}, {"sub": "u1"})
        text = f"analisa este jwt {token}"
        interp = interpret(text)
        self.assertIn("analyze_jwt", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "analyze_jwt" for a in plan))

    def test_graphql_prompt(self) -> None:
        text = "testa graphql introspection em example.com targets/demo"
        interp = interpret(text)
        self.assertIn("graphql", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "graphql_probe" for a in plan))


class ToolDryRunTests(unittest.TestCase):
    def test_cors_dry(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text("# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8")
        out = execute_tool(
            "cors_probe",
            {"target_dir": str(root), "url": "https://example.com/", "approve": False, "force": True},
        )
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertFalse(data["executed"])

    def test_list_dir(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "a.txt").write_text("x", encoding="utf-8")
        out = execute_tool("list_dir", {"path": str(root)})
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertGreaterEqual(data["count"], 1)


if __name__ == "__main__":
    unittest.main()
