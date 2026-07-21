"""Multi-attack campaign: scoring + default pack for vague prompts."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hackbot.campaign import (
    detect_campaign_modules,
    has_attack_intent,
    is_campaign_prompt,
    resolve_modules,
)
from hackbot.local_agent import build_plan, interpret
from hackbot.tools import execute_tool

SCOPE = """# Scope

## In Scope
- example.com

## Explicitly Allowed
- Passive recon
- Automated scanning
"""


class CampaignTests(unittest.TestCase):
    def test_detect_pt_prompt(self) -> None:
        text = (
            "de acordo com o scopo, faça ataques DDoS, Bruteforce, bypass de senha, "
            "achar tokens privados, leak de credenciais"
        )
        self.assertTrue(is_campaign_prompt(text))
        ids = [m.id for m in detect_campaign_modules(text)]
        self.assertIn("dos", ids)
        self.assertIn("brute", ids)
        self.assertIn("auth-bypass", ids)
        self.assertIn("secrets", ids)

    def test_paraphrase_still_hits(self) -> None:
        text = "tenta derrubar o site e pegar chave api em example.com"
        ids = [m.id for m in detect_campaign_modules(text)]
        self.assertIn("dos", ids)
        self.assertIn("secrets", ids)

    def test_vague_attack_uses_default_pack(self) -> None:
        text = "explora vulnerabilidades nesse alvo e me entrega o resultado"
        self.assertTrue(has_attack_intent(text))
        mods, used_default = resolve_modules(text)
        self.assertTrue(used_default)
        ids = [m.id for m in mods]
        self.assertIn("secrets", ids)
        self.assertIn("recon", ids)

    def test_offline_plans_campaign(self) -> None:
        text = (
            "de acordo com o scope, faça DDoS, bruteforce e leak de credenciais "
            "em example.com para targets/demo"
        )
        interp = interpret(text)
        self.assertIn("campaign", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "run_campaign" for a in plan))

    def test_vague_offline_still_campaigns(self) -> None:
        text = "quebra o que puder em example.com dentro do scope targets/demo"
        interp = interpret(text)
        self.assertIn("campaign", interp.intents)
        plan = build_plan(text, interp)
        # Open-ended prompts now prefer autonomous run_hunt
        self.assertTrue(any(a.tool in {"run_hunt", "run_campaign"} for a in plan))
        self.assertTrue(any(a.tool == "run_hunt" for a in plan))

    def test_run_campaign_dry_run(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        (root / "evidence" / "safe").mkdir(parents=True)
        out = execute_tool(
            "run_campaign",
            {
                "target_dir": str(root),
                "host": "example.com",
                "prompt": "DDoS, bruteforce, bypass de senha, tokens privados",
                "approve": False,
                "force": False,
            },
        )
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertFalse(data["executed"])
        statuses = {m["id"]: m["status"] for m in data["modules"]}
        self.assertEqual(statuses.get("dos"), "BLOCKED")
        self.assertEqual(statuses.get("brute"), "BLOCKED")
        self.assertIn(statuses.get("secrets"), {"DRY_RUN", "NOT_FOUND"})
        self.assertIn("report_md", data)

    def test_vague_campaign_never_empty(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        (root / "evidence" / "safe").mkdir(parents=True)
        out = execute_tool(
            "run_campaign",
            {
                "target_dir": str(root),
                "host": "example.com",
                "prompt": "faz o possível nesse host autorizado",
                "approve": False,
                "force": True,
            },
        )
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertTrue(data.get("used_default_pack"))
        self.assertGreaterEqual(len(data["modules"]), 3)


if __name__ == "__main__":
    unittest.main()
