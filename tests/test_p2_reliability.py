"""HB-005..HB-008: HuntMemory locks, subprocess timeout, analyze_js contract, config."""

from __future__ import annotations

import json
import multiprocessing
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from hackbot.config import get_config, load_config, reset_config_cache
from hackbot.hunt_memory import Endpoint, HuntMemory
from hackbot.observe import observe_v2
from hackbot.runners.base import run_command


def _worker_upsert(root: str, idx: int, barrier: object) -> None:
    barrier.wait()  # type: ignore[attr-defined]
    mem = HuntMemory(Path(root))
    mem.upsert_endpoints(
        [Endpoint(url=f"https://example.com/e{idx}", source="race")],
        host="example.com",
    )


class HuntMemoryLockTests(unittest.TestCase):
    def test_concurrent_upsert_keeps_all_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text("# Scope\n", encoding="utf-8")
            n = 16
            ctx = multiprocessing.get_context("spawn")
            barrier = ctx.Barrier(n)
            procs = [
                ctx.Process(target=_worker_upsert, args=(str(root), i, barrier))
                for i in range(n)
            ]
            for p in procs:
                p.start()
            for p in procs:
                p.join(timeout=60)
                self.assertEqual(p.exitcode, 0, msg=f"worker exit {p.exitcode}")
            mem = HuntMemory(root)
            urls = {e.url for e in mem.endpoints()}
            self.assertEqual(len(urls), n, msg=sorted(urls))

    def test_new_candidate_unique_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mem = HuntMemory(root)
            a = mem.new_candidate(module="idor", title="a", url="https://x/1")
            b = mem.new_candidate(module="idor", title="b", url="https://x/2")
            self.assertNotEqual(a.id, b.id)
            self.assertEqual(len(mem.load_candidates()), 2)


class SubprocessTimeoutTests(unittest.TestCase):
    def test_timeout_kills_sleep(self) -> None:
        if sys.platform == "win32":
            cmd = [sys.executable, "-c", "import time; time.sleep(30)"]
        else:
            cmd = [sys.executable, "-c", "import time; time.sleep(30)"]
        started = time.monotonic()
        result = run_command(cmd, approve=True, timeout=2.0)
        elapsed = time.monotonic() - started
        self.assertEqual(result.message, "timeout")
        self.assertLess(elapsed, 15.0)
        self.assertTrue(result.executed)


class AnalyzeJsContractTests(unittest.TestCase):
    def test_observe_passes_source_and_surfaces_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(
                "---\nin_scope:\n  - example.com\nallowed:\n  - Active testing\n---\n",
                encoding="utf-8",
            )
            mem = HuntMemory(root)
            mem.upsert_endpoints(
                [Endpoint(url="https://example.com/app.js", source="html")],
                host="example.com",
            )
            calls: list[dict] = []

            def fake_tool(name: str, args: dict) -> str:
                calls.append({"name": name, "args": args})
                if name == "analyze_js":
                    self.assertIn("source", args)
                    self.assertNotIn("url", args)
                    return json.dumps({"ok": False, "error": "boom", "kind": "internal_error"})
                return json.dumps({"ok": True})

            with mock.patch("hackbot.observe.map_surface", return_value={"ok": True, "links": []}):
                out = observe_v2(
                    root,
                    "https://example.com/",
                    approve=True,
                    force=False,
                    execute_tool=fake_tool,
                )
            self.assertTrue(out.get("ok"))
            err_steps = [
                s
                for s in out.get("steps") or []
                if s.get("step") == "analyze_js" and s.get("error")
            ]
            self.assertTrue(err_steps)
            self.assertTrue(any(c["name"] == "analyze_js" for c in calls))


class ConfigLoadTests(unittest.TestCase):
    def test_example_yaml_loads_and_env_overrides_rps(self) -> None:
        reset_config_cache()
        cfg = load_config()
        self.assertGreaterEqual(cfg.safety.default_max_rps, 1)
        self.assertGreaterEqual(cfg.safety.subprocess_timeout_sec, 5.0)
        self.assertTrue(cfg.source_path)
        reset_config_cache()
        cfg2 = load_config(environ={**os.environ, "HACKBOT_MAX_RPS": "2"})
        self.assertEqual(cfg2.safety.default_max_rps, 2)
        reset_config_cache()
        # Cannot disable OOS via file
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.yaml"
            path.write_text(
                "safety:\n  block_out_of_scope: false\n  default_max_rps: 4\n",
                encoding="utf-8",
            )
            cfg3 = load_config(path)
            self.assertTrue(cfg3.safety.block_out_of_scope)
            self.assertEqual(cfg3.safety.default_max_rps, 4)
            self.assertTrue(any("ignored" in n for n in cfg3.notes))
        reset_config_cache()
        _ = get_config(reload=True)


if __name__ == "__main__":
    unittest.main()
