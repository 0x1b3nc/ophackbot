"""Wave 0: Hypothesis metadata + aggression audit rails."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.hunt_controller import Hypothesis, MODULE_AGGRESSION, log_aggression, unauth_only


class Wave0RailsTests(unittest.TestCase):
    def test_hypothesis_dedupe_key(self) -> None:
        h = Hypothesis(
            module="idor",
            url="https://example.com/x",
            title="t",
            method="PATCH",
            params={"param": "id"},
            aggression=2,
            scope_quote="Active testing",
            signal_tags=("authz",),
        )
        self.assertEqual(h.dedupe_key(), "idor|PATCH|https://example.com/x|id")
        self.assertIn("idor", MODULE_AGGRESSION)

    def test_log_aggression_writes_audit(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        with mock.patch("hackbot.hunt_controller.log_decision") as logged:
            log_aggression(
                root,
                module="idor",
                level=2,
                quote="Active testing allowed",
                host="example.com",
                url="https://example.com/api/1",
            )
            logged.assert_called_once()
            args, kwargs = logged.call_args
            self.assertEqual(args[0], "ALLOW")
            self.assertEqual(kwargs.get("kind"), "aggression")
            self.assertEqual(kwargs.get("extra", {}).get("aggression"), 2)

    def test_unauth_env(self) -> None:
        with mock.patch.dict("os.environ", {"HACKBOT_HUNT_UNAUTH": "1"}):
            self.assertTrue(unauth_only())
        with mock.patch.dict("os.environ", {"HACKBOT_HUNT_UNAUTH": "0"}):
            self.assertFalse(unauth_only())

    def test_fixture_scope_exists(self) -> None:
        root = Path(__file__).resolve().parent / "fixtures" / "autonomy"
        self.assertTrue((root / "SCOPE.md").exists())
        self.assertTrue((root / "surface_sample.json").exists())
        self.assertTrue((root / "accounts.example.yaml").exists())


if __name__ == "__main__":
    unittest.main()
