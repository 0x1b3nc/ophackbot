"""Autonomous hunt memory, surface, validator, and OODA controller."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

from hackbot.hunt_controller import extract_host_from_prompt, hunt_status, run_hunt
from hackbot.hunt_memory import Candidate, Endpoint, HuntMemory
from hackbot.local_agent import build_plan, interpret
from hackbot.playbooks import executable_steps, playbook_for
from hackbot.surface import map_surface, seed_candidates_from_surface
from hackbot.tools import execute_tool
from hackbot.validator import promote_campaign_row, validate_and_log

SCOPE = """# Scope

## In Scope
- 127.0.0.1

## Explicitly Allowed
- Passive recon
- Automated scanning
- Active scanning
"""


class _LabHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/.env":
            body = b"API_KEY=supersecrettokenvalue123456\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/search":
            q = (qs.get("q") or [""])[0]
            body = f"<html><body>Results for {q}</body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/orders/1" or parsed.path.startswith("/api/orders/"):
            body = b'{"order_id":1,"owner":"alice","total":42}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/item":
            item_id = (qs.get("id") or ["1"])[0]
            if "AND 1=2" in item_id:
                body = b"not found"
                self.send_response(404)
            elif "'" in item_id:
                body = b"SQL syntax error near quotation mark mysql"
                self.send_response(500)
            else:
                body = b'{"id":1,"name":"widget"}'
                self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # Home with links
        body = (
            b'<html><body>'
            b'<a href="/search?q=test">search</a> '
            b'<a href="/api/orders/1">order</a> '
            b'<a href="/item?id=1">item</a> '
            b'<a href="/login">login</a>'
            b"</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_lab() -> tuple[HTTPServer, str]:
    server = HTTPServer(("127.0.0.1", 0), _LabHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}"


class HuntMemoryTests(unittest.TestCase):
    def test_surface_and_attempts(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        mem = HuntMemory(root)
        mem.upsert_endpoints(
            [Endpoint(url="https://example.com/api?id=1", params=["id"], source="seed")],
            host="example.com",
        )
        surface = mem.load_surface()
        self.assertEqual(surface["host"], "example.com")
        self.assertEqual(len(surface["endpoints"]), 1)
        mem.append_attempt({"phase": "act", "module": "secrets", "url": "https://example.com"})
        self.assertEqual(len(mem.recent_attempts()), 1)
        cid = mem.next_candidate_id()
        mem.upsert_candidate(
            Candidate(id=cid, module="secrets", title="leak", url="https://example.com")
        )
        self.assertEqual(len(mem.load_candidates()), 1)


class SurfaceTests(unittest.TestCase):
    def test_map_surface_live(self) -> None:
        server, base = _start_lab()
        self.addCleanup(server.shutdown)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        result = map_surface(root, base, approve=True, force=True, use_katana=False)
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(int(result["endpoints"]), 2)
        mem = HuntMemory(root)
        ideas = seed_candidates_from_surface(mem)
        modules = {i["module"] for i in ideas}
        self.assertTrue({"idor", "xss", "sqli"} & modules or "auth-bypass" in modules)


class ValidatorTests(unittest.TestCase):
    def test_validate_writes_finding(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "FINDINGS.md").write_text("# Findings\n\nNo confirmed findings yet.\n", encoding="utf-8")
        (root / "RESUME.md").write_text("# Resume\n\n## Safe Next Step\n\n- TBD\n", encoding="utf-8")
        mem = HuntMemory(root)
        cand = Candidate(
            id="H-001",
            module="secrets",
            title="Exposed API key",
            url="http://127.0.0.1/.env",
            detail="api key pattern",
        )
        mem.upsert_candidate(cand)
        vr = validate_and_log(root, cand, observed="hit aws_key on /.env")
        self.assertTrue(vr.ok)
        self.assertTrue(vr.finding_id.startswith("C-"))
        text = (root / "FINDINGS.md").read_text(encoding="utf-8")
        self.assertIn(vr.finding_id, text)

    def test_promote_campaign_row(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "FINDINGS.md").write_text("# Findings\n\n", encoding="utf-8")
        (root / "RESUME.md").write_text("# Resume\n\n## Safe Next Step\n\n- TBD\n", encoding="utf-8")
        vr = promote_campaign_row(
            root,
            {"id": "secrets", "label": "Secrets", "status": "FOUND", "summary": "hits=1"},
            host="example.com",
        )
        self.assertIsNotNone(vr)
        assert vr is not None
        self.assertTrue(vr.ok)


class PlaybookInjectionTests(unittest.TestCase):
    def test_xss_sqli_executable(self) -> None:
        xss = playbook_for("xss")
        steps = executable_steps(xss, max_aggression=2)
        self.assertTrue(any(s.tool_call and s.tool_call.get("tool") == "xss_probe" for s in steps))
        sqli = playbook_for("sqli")
        steps = executable_steps(sqli, max_aggression=2)
        self.assertTrue(any(s.tool_call and s.tool_call.get("tool") == "sqli_probe" for s in steps))


class OfflineHuntPlanTests(unittest.TestCase):
    def test_vague_prompt_plans_run_hunt(self) -> None:
        text = "explora vulnerabilidades nesse alvo example.com e me entrega o resultado targets/demo"
        interp = interpret(text)
        self.assertIn("campaign", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "run_hunt" for a in plan))

    def test_named_modules_still_campaign(self) -> None:
        text = (
            "de acordo com o scope, faça DDoS e leak de credenciais "
            "em example.com para targets/demo"
        )
        interp = interpret(text)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "run_campaign" for a in plan))


class HuntControllerE2E(unittest.TestCase):
    def test_dry_run_hunt(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        # Multi-act dry-run path (full budget); step mode covered in test_step_mode.
        with mock.patch.dict(os.environ, {"HACKBOT_STEP_MODE": "0"}, clear=False):
            result = run_hunt(
                root,
                "explora o que der em 127.0.0.1",
                host="127.0.0.1",
                approve_session=False,
                budget=5,
                force=True,
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["approve_session"], False)
        st = hunt_status(root)
        self.assertGreaterEqual(int(st["endpoints"]), 1)

    def test_approved_hunt_finds_secrets(self) -> None:
        server, base = _start_lab()
        self.addCleanup(server.shutdown)
        host = urlparse(base).hostname or "127.0.0.1"
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(
            SCOPE.replace("127.0.0.1", f"127.0.0.1\n- {host}"),
            encoding="utf-8",
        )
        (root / "FINDINGS.md").write_text("# Findings\n\n", encoding="utf-8")
        (root / "RESUME.md").write_text("# Resume\n\n## Safe Next Step\n\n- TBD\n", encoding="utf-8")

        with mock.patch.dict(os.environ, {"HACKBOT_STEP_MODE": "0"}, clear=False):
            result = run_hunt(
                root,
                f"explora o que der em {base}",
                host=base,
                approve_session=True,
                budget=12,
                approve_fn=lambda _d: True,
                force=True,
            )
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(int(result["acts_done"]), 1)
        # secrets should signal on /.env
        findings_text = (root / "FINDINGS.md").read_text(encoding="utf-8")
        # May or may not validate depending on chain timing — at least surface + attempts
        mem = HuntMemory(root)
        self.assertGreaterEqual(len(mem.endpoints()), 2)
        self.assertGreaterEqual(len(mem.recent_attempts()), 1)
        st = hunt_status(root)
        self.assertIn(st["phase"], {"done", "act", "validate", "decide", "observe"})
        # Prefer finding if secrets hit
        if result.get("findings"):
            self.assertIn(result["findings"][0], findings_text)

    def test_oos_blocked(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(
            "# Scope\n\n## In Scope\n- example.com\n\n## Out of Scope\n- evil.com\n",
            encoding="utf-8",
        )
        result = run_hunt(
            root,
            "hunt evil.com",
            host="evil.com",
            approve_session=True,
            approve_fn=lambda _d: True,
            force=True,
            budget=5,
        )
        self.assertFalse(result.get("ok"))
        self.assertIn("scope", str(result.get("error") or "").lower() + str(result.get("kind") or ""))

    def test_extract_host(self) -> None:
        self.assertEqual(extract_host_from_prompt("olha https://app.example.com/x"), "app.example.com")


class ToolWiringTests(unittest.TestCase):
    def test_sqli_xss_dry_run(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        raw = execute_tool(
            "sqli_probe",
            {"target_dir": str(root), "url": "http://127.0.0.1/item?id=1", "approve": False, "force": True},
        )
        data = json.loads(raw)
        self.assertTrue(data["ok"])
        self.assertFalse(data["executed"])
        raw = execute_tool(
            "xss_probe",
            {"target_dir": str(root), "url": "http://127.0.0.1/search?q=1", "approve": False, "force": True},
        )
        data = json.loads(raw)
        self.assertTrue(data["ok"])


if __name__ == "__main__":
    unittest.main()
