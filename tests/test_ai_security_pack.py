"""AI security pack: corpus, dry-run, classify, playbooks, redaction, coverage."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from hackbot.ai_payloads import (
    ALL_PAYLOADS,
    classify_ai_output,
    corpus_is_canary_safe,
    redact_ai_evidence,
)
from hackbot.coverage_map import load_coverage, mark_coverage_url
from hackbot.knowledge import classify
from hackbot.playbooks import playbook_for
from hackbot.runners import ai_probes, api_probes
from hackbot.tools import TOOL_SPECS, execute_tool


class AiSecurityPackTests(unittest.TestCase):
    def test_corpus_canaries_only(self) -> None:
        ok, problems = corpus_is_canary_safe(ALL_PAYLOADS)
        self.assertTrue(ok, problems)
        for p in ALL_PAYLOADS:
            self.assertTrue(
                "HB_" in p.canary or p.canary in {"TOOL_BLOCKED", "hb-canary", "DENIED"},
                p.canary,
            )

    def test_classify_routes(self) -> None:
        self.assertIn("prompt-injection", classify("prompt injection on chatbot"))
        self.assertIn("rag", classify("rag retrieval cross tenant"))
        self.assertIn("mcp", classify("mcp tools/list exposure"))
        self.assertIn("agentic", classify("agentic confused deputy tool calling"))

    def test_playbook_steps(self) -> None:
        for name in (
            "prompt-injection",
            "indirect-prompt",
            "rag",
            "agentic",
            "mcp",
            "system-boundary",
        ):
            pb = playbook_for(name)
            self.assertGreaterEqual(len(pb.steps), 1)
            step = pb.steps[0]
            self.assertTrue(step.hypothesis)
            self.assertIn(step.aggression, {0, 1, 2, 3})
            self.assertTrue(step.stop)

    def test_canary_parser(self) -> None:
        hit = classify_ai_output("ok HB_CANARY_PROMPT_INJECTION", canary="HB_CANARY_PROMPT_INJECTION")
        self.assertEqual(hit["outcome"], "canary_returned")
        tenant = classify_ai_output("src=9 HB_CANARY_TENANT_LEAK", canary="HB_CANARY_TENANT_LEAK")
        self.assertEqual(tenant["outcome"], "cross_tenant_signal")
        other = classify_ai_output("got HB_OTHER_OBJECT_CANARY", canary="HB_OTHER_OBJECT_CANARY")
        self.assertEqual(other["outcome"], "cross_tenant_signal")
        tool_ok = classify_ai_output("TOOL_BLOCKED", canary="TOOL_BLOCKED")
        self.assertEqual(tool_ok["outcome"], "blocked")
        tool_bad = classify_ai_output("draft HB_CANARY_TOOL_BOUNDARY", canary="HB_CANARY_TOOL_BOUNDARY")
        self.assertEqual(tool_bad["outcome"], "tool_attempted")
        blocked = classify_ai_output("I cannot help with that", canary="HB_CANARY_X")
        self.assertEqual(blocked["outcome"], "blocked")

    def test_redaction_prompts(self) -> None:
        raw = 'Authorization: Bearer sk_live_abc123SECRET\n{"email":"a@b.com"}'
        out = redact_ai_evidence(raw)
        self.assertNotIn("sk_live_abc123SECRET", out)

    def test_dry_run_default_ai_and_api(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(
                "# Scope\n\n## In scope\n- chat.example.com\n- api.example.com\n",
                encoding="utf-8",
            )
            r = ai_probes.llm_prompt_probe(
                root, "https://chat.example.com/v1/chat", approve=False
            )
            self.assertEqual(r.message, "dry-run")
            self.assertFalse(r.executed)
            r2 = api_probes.api_mass_assignment_probe(
                root, "https://api.example.com/users/1", approve=False
            )
            self.assertEqual(r2.message, "dry-run")

    def test_scope_guard_blocks_oos(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(
                "# Scope\n\n## In scope\n- in.example.com\n\n## Out of scope\n- evil.com\n",
                encoding="utf-8",
            )
            with self.assertRaises(Exception):
                ai_probes.llm_prompt_probe(
                    root, "https://evil.com/chat", approve=False, force=False
                )

    def test_tool_specs_registered(self) -> None:
        names = {s["name"] for s in TOOL_SPECS}
        for n in (
            "import_openapi",
            "import_postman",
            "api_authz_matrix",
            "llm_prompt_probe",
            "mcp_agent_probe",
            "ai_eval_run",
        ):
            self.assertIn(n, names)

    def test_coverage_ai_cell(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mark_coverage_url(
                root,
                cls="prompt-injection",
                url="https://chat.example.com/v1/chat",
                method="POST",
                authz="session_a",
                status="untested",
                note="ai",
            )
            entries = load_coverage(root)["entries"]
            self.assertTrue(any("prompt-injection" in k for k in entries))

    def test_execute_dry_run_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(
                "# Scope\n\n## In scope\n- chat.example.com\n", encoding="utf-8"
            )
            raw = execute_tool(
                "llm_prompt_probe",
                {
                    "target_dir": str(root),
                    "url": "https://chat.example.com/v1/chat",
                    "approve": False,
                },
            )
            data = json.loads(raw)
            self.assertTrue(data.get("ok"))
            self.assertFalse(data.get("executed"))


if __name__ == "__main__":
    unittest.main()
