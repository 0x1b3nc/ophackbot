"""Offline NL: more intents + soft clarify on low confidence."""

from __future__ import annotations

import unittest
from unittest import mock

from hackbot.local_agent import build_plan, interpret
from hackbot.prompt_router import needs_soft_clarify, offline_confidence


class OfflineNlHardenTests(unittest.TestCase):
    def test_set_target_intent(self) -> None:
        interp = interpret("usa o target demo")
        self.assertIn("set_target", interp.intents)
        plan = build_plan("usa o target demo", interp)
        self.assertTrue(any(a.tool == "set_target" for a in plan))

    def test_map_surface_intent(self) -> None:
        interp = interpret("mapeia a surface de example.com targets/demo")
        self.assertIn("map_surface", interp.intents)
        plan = build_plan("mapeia a surface de example.com targets/demo", interp)
        self.assertTrue(any(a.tool == "map_surface" for a in plan))
        args = next(a.args for a in plan if a.tool == "map_surface")
        self.assertIn("seed", args)

    def test_http_request_intent(self) -> None:
        interp = interpret("faz um get em https://example.com/api for targets/demo")
        self.assertIn("http_request", interp.intents)

    def test_high_signal_boosts_confidence(self) -> None:
        low = offline_confidence("faz algo", host=None, intents=["campaign"], classes=["recon"])
        high = offline_confidence(
            "leia a imagem Desktop/scope.png",
            host=None,
            intents=["read_image"],
            classes=["recon"],
        )
        self.assertGreater(high, low)

    def test_soft_clarify_on_vague_default_pack(self) -> None:
        self.assertTrue(
            needs_soft_clarify(
                confidence=0.3,
                intents=["campaign"],
                used_default_pack=True,
                source="offline",
            )
        )
        self.assertFalse(
            needs_soft_clarify(
                confidence=0.3,
                intents=["write_file"],
                used_default_pack=False,
                source="offline",
            )
        )

    def test_run_local_clarifies_instead_of_default_hunt(self) -> None:
        from hackbot.local_agent import run_local_agent

        with mock.patch("hackbot.local_agent.ui") as ui:
            with mock.patch("hackbot.local_agent.execute_tool") as ex:
                run_local_agent(
                    "preciso que voce resolva aquela coisa do programa depois",
                    approve_fn=lambda _d: False,
                )
        # Should not execute campaign tools when clarifying
        for call in ex.call_args_list:
            self.assertNotIn(call.args[0], {"run_campaign", "run_hunt"})
        # Panel or warn with clarify message
        self.assertTrue(ui.markdown_panel.called or ui.warn.called)


if __name__ == "__main__":
    unittest.main()
