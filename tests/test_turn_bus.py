"""Background turn bus: queue + interrupt semantics."""

from __future__ import annotations

import threading
import time
import unittest

from hackbot.turn_bus import TurnBus, set_bus, turn_cancel_requested


class TurnBusTests(unittest.TestCase):
    def tearDown(self) -> None:
        set_bus(None)
        # Ensure process-global cancel does not leak across tests.
        bus = TurnBus(sync=True)
        bus.clear_cancel()

    def test_sync_runs_inline(self) -> None:
        seen: list[str] = []
        bus = TurnBus(sync=True)
        bus.start(seen.append)
        bus.submit("hello")
        self.assertEqual(seen, ["hello"])
        self.assertFalse(bus.is_busy())

    def test_async_queue_and_interrupt(self) -> None:
        started = threading.Event()
        release = threading.Event()
        ran: list[str] = []

        def turn(text: str) -> None:
            ran.append(text)
            started.set()
            # Simulate a long turn; exit early if cancelled.
            for _ in range(50):
                if turn_cancel_requested():
                    return
                if release.wait(0.05):
                    return

        bus = TurnBus(sync=False)
        set_bus(bus)
        bus.start(turn)
        bus.submit("first")
        self.assertTrue(started.wait(2.0), "turn did not start")
        self.assertTrue(bus.is_busy())
        bus.submit("second")  # interrupt + queue
        # Unblock whatever is left; second should run after first exits.
        release.set()
        deadline = time.time() + 3.0
        while time.time() < deadline and "second" not in ran:
            time.sleep(0.05)
        bus.shutdown(wait=True, timeout=2.0)
        self.assertIn("first", ran)
        self.assertIn("second", ran)

    def test_cancel_flag_wired(self) -> None:
        bus = TurnBus(sync=True)
        set_bus(bus)
        self.assertFalse(turn_cancel_requested())
        bus.request_interrupt()
        self.assertTrue(turn_cancel_requested())
        # Survives clearing the bus pointer (shutdown race).
        set_bus(None)
        self.assertTrue(turn_cancel_requested())
        bus.clear_cancel()
        self.assertFalse(turn_cancel_requested())


if __name__ == "__main__":
    unittest.main()
