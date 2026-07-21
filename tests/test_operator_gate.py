"""Operator approve gate — serialize tools + mute stream during Confirm."""

from __future__ import annotations

import threading
import time
import unittest

from hackbot.operator_gate import (
    operator_prompt_active,
    serialized_tool_call,
    stream_output_allowed,
)


class OperatorGateTests(unittest.TestCase):
    def test_stream_muted_during_prompt(self) -> None:
        from hackbot.operator_gate import console_output_allowed

        self.assertTrue(stream_output_allowed())
        self.assertTrue(console_output_allowed())
        with operator_prompt_active():
            self.assertFalse(stream_output_allowed())
            # Permission UI may print; Cursor stream must stay muted.
            self.assertTrue(console_output_allowed())
        self.assertTrue(stream_output_allowed())

    def test_nested_prompt_stays_muted(self) -> None:
        with operator_prompt_active():
            with operator_prompt_active():
                self.assertFalse(stream_output_allowed())
            self.assertFalse(stream_output_allowed())
        self.assertTrue(stream_output_allowed())

    def test_serialized_tool_call_waits_for_prior(self) -> None:
        order: list[str] = []

        def worker(name: str, hold: float) -> None:
            with serialized_tool_call():
                order.append(f"{name}:start")
                time.sleep(hold)
                order.append(f"{name}:end")

        t1 = threading.Thread(target=worker, args=("a", 0.12))
        t1.start()
        time.sleep(0.04)  # ensure a holds the lock
        t2 = threading.Thread(target=worker, args=("b", 0.01))
        t2.start()
        t1.join(timeout=2)
        t2.join(timeout=2)
        self.assertEqual(order, ["a:start", "a:end", "b:start", "b:end"])

    def test_approve_then_next_tool_order(self) -> None:
        """Mirrors permission → y/n → next permission."""
        events: list[str] = []

        def tool(name: str) -> None:
            with serialized_tool_call():
                events.append(f"{name}:ask")
                with operator_prompt_active():
                    events.append(f"{name}:prompt")
                    time.sleep(0.05)
                events.append(f"{name}:done")

        t1 = threading.Thread(target=tool, args=("mkdir",))
        t1.start()
        time.sleep(0.02)
        t2 = threading.Thread(target=tool, args=("scope",))
        t2.start()
        t1.join(timeout=2)
        t2.join(timeout=2)
        self.assertEqual(
            events,
            [
                "mkdir:ask",
                "mkdir:prompt",
                "mkdir:done",
                "scope:ask",
                "scope:prompt",
                "scope:done",
            ],
        )
        self.assertTrue(stream_output_allowed())


if __name__ == "__main__":
    unittest.main()
