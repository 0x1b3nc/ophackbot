"""Tool pack resolution — avoid false recon-only on PT hunt prompts."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from hackbot.tool_packs import resolve_packs


class ToolPacksTests(unittest.TestCase):
    def test_pt_vuln_prompt_gets_inject(self) -> None:
        with mock.patch.dict(os.environ, {"HACKBOT_TOOL_PACK": "auto"}, clear=False):
            packs = resolve_packs(
                "Faça o próximo passo lógico. Vamos tentar achar vulnerabilidade "
                "sem eu precisar criar contas."
            )
        self.assertIn("recon", packs)
        self.assertIn("inject", packs)
        self.assertIn("report", packs)

    def test_achar_does_not_recon_only_via_har(self) -> None:
        """Regression: substring 'har' inside 'achar' used to select recon only."""
        with mock.patch.dict(os.environ, {"HACKBOT_TOOL_PACK": "auto"}, clear=False):
            packs = resolve_packs("vamos achar algo interessante no bmw")
        # Either full hunt surface or core-only expansion — never recon without inject
        # when it is a vague hunt ask.
        if "recon" in packs:
            self.assertIn("inject", packs)


if __name__ == "__main__":
    unittest.main()
