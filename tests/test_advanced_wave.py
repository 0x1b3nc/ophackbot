"""Advanced injection, OAuth/JWT active, chain builder."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from hackbot.chain_builder import build_chains
from hackbot.local_agent import build_plan, interpret
from hackbot.runners.jwt_analyze import analyze_jwt
from hackbot.tools import execute_tool


def _jwt(header: dict, payload: dict, sig: str = "sig") -> str:
    def enc(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{enc(header)}.{enc(payload)}.{sig}"


class ChainBuilderTests(unittest.TestCase):
    def test_chains_from_findings(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "FINDINGS.md").write_text(
            "# Findings\n\n## C-001 Secrets leak\n\n- Class: secrets\n- Endpoint: https://x/.env\n",
            encoding="utf-8",
        )
        (root / "RESUME.md").write_text("# Resume\n\n## Safe Next Step\n\n- TBD\n", encoding="utf-8")
        out = build_chains(root)
        self.assertTrue(out["ok"])
        self.assertGreaterEqual(out["count"], 1)
        self.assertTrue((root / "hunt" / "chains.md").exists())
        tos = {c["to"] for c in out["chains"]}
        self.assertTrue({"auth-bypass", "idor"} & tos)


class NlAdvancedPlanTests(unittest.TestCase):
    def test_lfi_ssti_xxe(self) -> None:
        for word, tool in (
            ("testa lfi em example.com/file targets/demo", "lfi_probe"),
            ("ssti template injection em example.com targets/demo", "ssti_probe"),
            ("xxe no endpoint example.com/xml targets/demo", "xxe_probe"),
        ):
            interp = interpret(word)
            plan = build_plan(word, interp)
            self.assertTrue(any(a.tool == tool for a in plan), msg=word)

    def test_chain_prompt(self) -> None:
        text = "monta a cadeia de exploits / build chains targets/demo"
        interp = interpret(text)
        self.assertIn("build_chains", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "build_chains" for a in plan))

    def test_oauth_prompt(self) -> None:
        text = (
            "oauth_probe authorize "
            "https://example.com/oauth/authorize?client_id=1&redirect_uri=https://app.com/cb "
            "targets/demo"
        )
        # softer: just "testa oauth"
        text = "testa oauth em https://example.com/oauth/authorize?client_id=1 targets/demo"
        interp = interpret(text)
        self.assertIn("oauth", interp.intents)


class ProbeDryRunTests(unittest.TestCase):
    def test_lfi_ssti_xxe_dry(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text("# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8")
        for tool, extra in (
            ("lfi_probe", {"param": "file"}),
            ("ssti_probe", {"param": "q"}),
            ("xxe_probe", {}),
        ):
            args = {
                "target_dir": str(root),
                "url": "https://example.com/x",
                "approve": False,
                "force": True,
                **extra,
            }
            data = json.loads(execute_tool(tool, args))
            self.assertTrue(data["ok"], msg=tool)
            self.assertFalse(data["executed"], msg=tool)

    def test_jwt_active_dry(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text("# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8")
        token = _jwt({"alg": "HS256"}, {"sub": "1"})
        data = json.loads(
            execute_tool(
                "jwt_active_probe",
                {
                    "target_dir": str(root),
                    "url": "https://example.com/api/me",
                    "token": token,
                    "approve": False,
                    "force": True,
                },
            )
        )
        self.assertTrue(data["ok"])
        self.assertFalse(data["executed"])
        self.assertIn("analysis", data)

    def test_stubs(self) -> None:
        browser = json.loads(execute_tool("browser_hint", {"task": "xss"}))
        self.assertTrue(browser["ok"])
        self.assertIn("message", browser)
        mobile = json.loads(execute_tool("mobile_hint", {"task": "apk"}))
        self.assertTrue(mobile["ok"])
        self.assertFalse(mobile.get("frida_hooking"))
        self.assertIn("checklist", mobile)


if __name__ == "__main__":
    unittest.main()
