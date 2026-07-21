"""Env key resolution — including Windows setx User-env footgun."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from hackbot.providers import _first_env, _user_env_windows


class FirstEnvTests(unittest.TestCase):
    def test_process_env_wins(self) -> None:
        with mock.patch.dict(os.environ, {"CURSOR_API_KEY": "from-process"}, clear=False):
            self.assertEqual(_first_env(("CURSOR_API_KEY",)), "from-process")

    def test_windows_user_env_fallback(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows only")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CURSOR_API_KEY", None)
            with mock.patch(
                "hackbot.providers._user_env_windows",
                return_value="from-setx",
            ):
                self.assertEqual(_first_env(("CURSOR_API_KEY",)), "from-setx")
                # Hydrated into process env for later reads
                self.assertEqual(os.environ.get("CURSOR_API_KEY"), "from-setx")

    def test_user_env_helper_missing(self) -> None:
        self.assertIsNone(_user_env_windows("__HACKBOT_NO_SUCH_VAR__"))


if __name__ == "__main__":
    unittest.main()
