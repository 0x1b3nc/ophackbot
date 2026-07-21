"""Sprint: phase budgets, validator replay, VRT reports, learning payloads."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.findings import report_fields_from_finding
from hackbot.hunt_memory import Candidate, HuntMemory, HuntState
from hackbot.hunt_phases import (
    allocate_phase_budgets,
    phase_for_module,
    pivot_modules,
    prefer_phase,
)
from hackbot.learning import (
    record_technique,
    suggest_for_host,
    suggest_payload_hints,
)
from hackbot.severity import vrt_for_class
from hackbot.validator import _replay_winning_act, validate_and_log


class PhaseBudgetTests(unittest.TestCase):
    def test_allocate_sums_to_total(self) -> None:
        b = allocate_phase_budgets(28)
        self.assertEqual(sum(b.values()), 28)
        self.assertGreater(b["recon"], 0)
        self.assertGreater(b["authz"], 0)

    def test_phase_for_module(self) -> None:
        self.assertEqual(phase_for_module("secrets"), "recon")
        self.assertEqual(phase_for_module("idor"), "authz")
        self.assertEqual(phase_for_module("ssrf"), "inject")

    def test_prefer_phase_orders(self) -> None:
        class H:
            def __init__(self, module: str, priority: int = 50):
                self.module = module
                self.priority = priority

        q = [H("ssrf"), H("secrets"), H("idor")]
        ordered = prefer_phase(q, "authz")
        self.assertEqual(ordered[0].module, "idor")

    def test_pivot_map(self) -> None:
        self.assertIn("ssrf", pivot_modules("xxe"))


class ValidatorReplayTests(unittest.TestCase):
    def test_idor_replay_calls_idor_probe(self) -> None:
        calls: list[tuple[str, dict]] = []

        def fake_tool(name: str, args: dict, **_k):
            calls.append((name, args))
            if name == "http_request":
                return json.dumps({"ok": True, "status": 401})
            return json.dumps(
                {"ok": True, "signal": True, "verdict": "likely", "methods": ["GET", "PATCH"]}
            )

        cand = Candidate(
            id="C-1",
            module="idor",
            title="test",
            url="https://example.com/api/orders/1",
            params={"methods": "GET,PATCH", "matrix": "both", "param": "id"},
        )
        with tempfile.TemporaryDirectory() as tmp:
            info = _replay_winning_act(fake_tool, Path(tmp), cand, force=True)
        self.assertIn("negative", info)
        self.assertIn("winning_replay", info)
        self.assertEqual(calls[1][0], "idor_probe")
        self.assertEqual(calls[1][1].get("matrix"), "both")

    def test_validate_uses_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text("# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8")
            (root / "FINDINGS.md").write_text("# Findings\n", encoding="utf-8")
            mem = HuntMemory(root)
            cand = Candidate(
                id="C-001",
                module="idor",
                title="IDOR",
                url="https://example.com/api/x",
                detail="distinct body ownership leak",
                params={"methods": "GET", "matrix": "bola"},
                status="pending",
            )
            mem.upsert_candidate(cand)

            def fake_tool(name: str, args: dict, **_k):
                if name == "http_request":
                    return json.dumps({"ok": True, "status": 401})
                return json.dumps(
                    {
                        "ok": True,
                        "signal": True,
                        "verdict": "likely",
                        "reason": "distinct body",
                        "methods": ["GET"],
                    }
                )

            vr = validate_and_log(
                root,
                cand,
                observed="distinct body ownership proof",
                verdict="likely",
                rehit=True,
                execute_tool=fake_tool,
                approve=True,
                force=True,
            )
            self.assertTrue(vr.ok)
            self.assertTrue(vr.finding_id)


class VrtReportTests(unittest.TestCase):
    def test_vrt_idor(self) -> None:
        self.assertIn("IDOR", vrt_for_class("idor"))

    def test_report_fields_include_vrt_and_poc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ev = Path(tmp) / "ev.json"
            ev.write_text(
                json.dumps(
                    {
                        "params": {"methods": "GET,PATCH", "matrix": "both", "param": "id"},
                        "rehit": {
                            "negative": {"status": 401},
                            "winning_replay": {
                                "verdict": "likely",
                                "signal": True,
                                "reason": "distinct body",
                                "methods": ["GET", "PATCH"],
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            fields = report_fields_from_finding(
                {
                    "finding_id": "C-001",
                    "title": "IDOR orders",
                    "class": "idor",
                    "endpoint": "https://example.com/api/orders/1",
                    "verdict": "likely",
                    "evidence": str(ev),
                    "observed": "B saw A's order",
                }
            )
        self.assertIn("IDOR", fields["vrt"])
        self.assertIn("Minimal PoC", fields["steps"])
        self.assertIn("PATCH", fields["steps"])
        self.assertIn("VRT hint", fields["impact"])


class LearningPayloadTests(unittest.TestCase):
    def test_record_and_suggest_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            learn_dir = Path(tmp)
            with mock.patch("hackbot.learning.LEARN_DIR", learn_dir):
                with mock.patch("hackbot.learning.TECHNIQUES", learn_dir / "techniques.jsonl"):
                    with mock.patch("hackbot.learning.PATTERNS_FILE", learn_dir / "patterns.jsonl"):
                        with mock.patch("hackbot.learning.STATS_FILE", learn_dir / "stats.json"):
                            record_technique(
                                program="demo",
                                module="ssrf",
                                summary="hit metadata",
                                host="example.com",
                                outcome="validated",
                                param="url",
                                payload="http://169.254.169.254/",
                                url="https://example.com/fetch",
                            )
                            hints = suggest_payload_hints("example.com")
                            sug = suggest_for_host("example.com")
        self.assertTrue(hints)
        self.assertEqual(hints[0]["module"], "ssrf")
        self.assertEqual(hints[0]["param"], "url")
        self.assertTrue(sug["suggestions"])


class HuntStatePhasePersistTests(unittest.TestCase):
    def test_state_roundtrip_phase_budgets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mem = HuntMemory(Path(tmp))
            st = HuntState(
                phase="act",
                hunt_phase="authz",
                phase_budget_recon=2,
                phase_budget_authz=5,
                phase_budget_inject=7,
                budget_total=14,
                budget_remaining=10,
            )
            mem.save_state(st)
            loaded = mem.load_state()
            self.assertEqual(loaded.hunt_phase, "authz")
            self.assertEqual(loaded.phase_budget_authz, 5)
            status = mem.status_summary()
            self.assertEqual(status["phase_budgets"]["inject"], 7)


if __name__ == "__main__":
    unittest.main()
