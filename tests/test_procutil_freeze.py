"""Process-tree cancel + chat prune guards against VM freezes."""

from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from hackbot.procutil import kill_process_tree, popen_new_group_kwargs


class ProcutilTests(unittest.TestCase):
    def test_popen_kwargs_platform(self) -> None:
        kw = popen_new_group_kwargs()
        self.assertTrue("start_new_session" in kw or "creationflags" in kw)

    def test_kill_noop_when_finished(self) -> None:
        proc = mock.Mock(spec=subprocess.Popen)
        proc.poll.return_value = 0
        kill_process_tree(proc)
        proc.kill.assert_not_called()

    def test_kill_none_safe(self) -> None:
        kill_process_tree(None)


class ChatPruneTests(unittest.TestCase):
    def test_prune_constant(self) -> None:
        from hackbot.tui import app as tui_app

        self.assertGreaterEqual(tui_app._MAX_CHAT_WIDGETS, 40)
        self.assertLessEqual(tui_app._MAX_CHAT_WIDGETS, 200)


if __name__ == "__main__":
    unittest.main()
