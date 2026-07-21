"""Playwright soft-fail, Burp XML seed, cross-program learning."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.learning import record_technique, suggest_for_host, ingest_from_hunt
from hackbot.local_agent import build_plan, interpret
from hackbot.runners import browser as browser_runner
from hackbot.runners import burp
from hackbot.tools import execute_tool


class BrowserTests(unittest.TestCase):
    def test_navigate_missing_dep_or_dry(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(
            "# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8"
        )
        out = json.loads(
            execute_tool(
                "browser_navigate",
                {
                    "target_dir": str(root),
                    "url": "https://example.com/",
                    "approve": False,
                },
            )
        )
        # dry-run when playwright present; missing_dep payload otherwise
        self.assertTrue(out.get("dry_run") or out.get("error") == "playwright_missing")

    def test_nl_browser_screenshot(self) -> None:
        text = "tire um print de https://example.com targets/demo"
        interp = interpret(text)
        self.assertIn("browser", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "browser_screenshot" for a in plan))

    def test_playwright_available_bool(self) -> None:
        self.assertIsInstance(browser_runner.playwright_available(), bool)

    def test_cookies_storage_network_dry(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(
            "# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8"
        )
        for tool in ("browser_cookies", "browser_storage", "browser_network"):
            out = json.loads(
                execute_tool(
                    tool,
                    {
                        "target_dir": str(root),
                        "url": "https://example.com/",
                        "approve": False,
                    },
                )
            )
            self.assertTrue(
                out.get("dry_run") or out.get("error") == "playwright_missing",
                msg=tool,
            )

    def test_nl_cookies_and_network(self) -> None:
        text = "lista cookies em https://example.com targets/demo"
        interp = interpret(text)
        self.assertIn("browser_cookies", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "browser_cookies" for a in plan))

        text2 = "captura de rede no browser em https://example.com targets/demo"
        interp2 = interpret(text2)
        self.assertIn("browser_network", interp2.intents)
        plan2 = build_plan(text2, interp2)
        self.assertTrue(any(a.tool == "browser_network" for a in plan2))


class MobileTests(unittest.TestCase):
    def test_mobile_status(self) -> None:
        out = json.loads(execute_tool("mobile_status", {"task": "apk"}))
        self.assertTrue(out["ok"])
        self.assertFalse(out.get("frida_hooking"))
        self.assertIn("checklist", out)

    def test_nl_apk_and_adb(self) -> None:
        text = "checa frida / mobile toolchain"
        interp = interpret(text)
        self.assertIn("mobile", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "mobile_status" for a in plan))

        text2 = "lista adb devices"
        interp2 = interpret(text2)
        plan2 = build_plan(text2, interp2)
        self.assertTrue(any(a.tool == "adb_devices" for a in plan2))

    def test_inspect_apk_zip(self) -> None:
        import zipfile

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(
            "# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8"
        )
        apk = root / "demo.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"\x00\x01fake")
            zf.writestr("assets/network_security_config.xml", "<network-security-config/>")
            zf.writestr("classes.dex", b"dex\n")
        out = json.loads(
            execute_tool(
                "inspect_apk",
                {"target_dir": str(root), "path": str(apk)},
            )
        )
        self.assertTrue(out["ok"])
        self.assertTrue(any("network_security" in x for x in out.get("interesting") or []))

    def test_browser_with_session_dry_or_missing(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(
            "# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8"
        )
        secrets = root / "secrets"
        secrets.mkdir(parents=True)
        (secrets / "sessions.yaml").write_text(
            "sessions:\n  A:\n    authorization: Bearer test-token-abc\n",
            encoding="utf-8",
        )
        out = json.loads(
            execute_tool(
                "browser_with_session",
                {
                    "target_dir": str(root),
                    "url": "https://example.com/",
                    "session": "A",
                    "approve": False,
                },
            )
        )
        self.assertTrue(out.get("dry_run") or out.get("error") == "playwright_missing")

    def test_browser_with_session_no_creds(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(
            "# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8"
        )
        # Force past dry-run by mocking playwright available + approve path via runner directly
        from hackbot.runners import browser as br

        with mock.patch.object(br, "playwright_available", return_value=True):
            result = br.browser_with_session(
                root, "https://example.com/", session="A", approve=True
            )
        payload = json.loads(result.stdout)
        self.assertEqual(payload.get("error"), "session_missing")

    def test_nl_browser_session(self) -> None:
        text = "abre autenticado com sessão A em https://example.com targets/demo"
        interp = interpret(text)
        self.assertIn("browser_session", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "browser_with_session" for a in plan))

    def test_mobile_bridge_har(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(
            "# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8"
        )
        har = root / "traffic.har"
        har.write_text(
            json.dumps(
                {
                    "log": {
                        "entries": [
                            {
                                "request": {
                                    "method": "GET",
                                    "url": "https://example.com/api/me",
                                    "headers": [{"name": "Authorization", "value": "Bearer x"}],
                                },
                                "response": {"status": 200},
                            }
                        ]
                    }
                }
            ),
            encoding="utf-8",
        )
        apk = root / "app.apk"
        import zipfile

        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"x")
        out = json.loads(
            execute_tool(
                "mobile_bridge",
                {
                    "target_dir": str(root),
                    "apk_path": str(apk),
                    "har_path": str(har),
                    "start_hunt": False,
                },
            )
        )
        self.assertTrue(out["ok"])
        self.assertIn("example.com", out.get("hosts") or [])
        self.assertTrue((root / "hunt" / "mobile_bridge.md").exists())

    def test_nl_mobile_bridge(self) -> None:
        text = (
            "mobile bridge com Downloads/app.apk e Downloads/traffic.har "
            "targets/demo hunt approve"
        )
        interp = interpret(text)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "mobile_bridge" for a in plan))


class BurpXmlTests(unittest.TestCase):
    def test_seed_surface_from_xml(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(
            "# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8"
        )
        xml = root / "export.xml"
        xml.write_text(
            """<?xml version="1.0"?>
<items>
  <item>
    <method>GET</method>
    <url>https://example.com/api/users?id=1</url>
    <path>/api/users</path>
    <status>200</status>
  </item>
  <item>
    <method>POST</method>
    <url>https://example.com/login</url>
    <path>/login</path>
    <status>302</status>
  </item>
</items>
""",
            encoding="utf-8",
        )
        result = burp.seed_surface_from_xml(root, xml)
        self.assertTrue(result["ok"])
        self.assertEqual(result["endpoints_seeded"], 2)
        self.assertTrue((root / "hunt" / "surface.yaml").exists())

    def test_import_burp_xml_tool(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(
            "# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8"
        )
        xml = root / "burp.xml"
        xml.write_text(
            '<?xml version="1.0"?><items><item>'
            "<method>GET</method><url>https://example.com/</url>"
            "<path>/</path><status>200</status></item></items>",
            encoding="utf-8",
        )
        out = json.loads(
            execute_tool(
                "import_burp_xml",
                {"target_dir": str(root), "path": str(xml)},
            )
        )
        self.assertTrue(out["ok"])
        self.assertGreaterEqual(out["endpoints_seeded"], 1)

    def test_burp_rest_health_offline(self) -> None:
        with mock.patch("urllib.request.urlopen", side_effect=OSError("down")):
            out = burp.burp_rest_health(base_url="http://127.0.0.1:1", timeout=0.1)
        self.assertTrue(out["ok"])
        self.assertFalse(out["up"])


class LearningTests(unittest.TestCase):
    def test_record_and_suggest(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        learn_dir = Path(tmp.name)
        techniques = learn_dir / "techniques.jsonl"
        with mock.patch("hackbot.learning.LEARN_DIR", learn_dir), mock.patch(
            "hackbot.learning.TECHNIQUES", techniques
        ):
            record_technique(
                program="demo",
                module="cors",
                summary="ACA-O reflected",
                host="example.com",
                outcome="validated",
            )
            sug = suggest_for_host("example.com")
            self.assertTrue(sug["ok"])
            mods = {s["module"] for s in sug["suggestions"]}
            self.assertIn("cors", mods)

    def test_nl_learn_suggest(self) -> None:
        text = "o que funcionou em hunts anteriores em example.com"
        interp = interpret(text)
        self.assertIn("learn_suggest", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "learn_suggest" for a in plan))

    def test_ingest_from_hunt(self) -> None:
        from hackbot.hunt_memory import Candidate, HuntMemory

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        learn_dir = root / "learning"
        techniques = learn_dir / "techniques.jsonl"
        mem = HuntMemory(root)
        mem.save_surface({"host": "example.com", "endpoints": []})
        mem.upsert_candidate(
            Candidate(
                id="c1",
                module="secrets",
                title="env leak",
                url="https://example.com/.env",
                status="validated",
                detail="found .env",
            )
        )
        with mock.patch("hackbot.learning.LEARN_DIR", learn_dir), mock.patch(
            "hackbot.learning.TECHNIQUES", techniques
        ):
            out = ingest_from_hunt(root, program="demo")
            self.assertTrue(out["ok"])
            self.assertGreaterEqual(out["recorded"], 1)
            self.assertTrue(techniques.exists())


if __name__ == "__main__":
    unittest.main()
