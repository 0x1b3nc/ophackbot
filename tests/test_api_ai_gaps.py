"""Gaps closed: A/B authz fixtures, AI surfaces, OpenAPI file $ref, curl tool."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.ai_target import list_ai_surfaces, upsert_ai_surface
from hackbot.openapi_parse import ingest_openapi_file, parse_openapi_dict
from hackbot.runners import api_probes, curl_request
from hackbot.runners.base import RunnerResult
from hackbot.tools import TOOL_SPECS, execute_tool


class AuthzMatrixFixtureTests(unittest.TestCase):
    def test_missing_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(
                "# Scope\n\n## In scope\n- api.example.com\n", encoding="utf-8"
            )
            r = api_probes.api_authz_matrix(
                root, "https://api.example.com/users/1", approve=True
            )
            data = json.loads(r.stdout)
            self.assertEqual(data.get("error"), "sessions_missing")
            self.assertFalse(r.executed)

    def test_active_matrix_with_fixtures_and_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(
                "# Scope\n\n## In scope\n- api.example.com\n", encoding="utf-8"
            )
            secrets = root / "secrets"
            secrets.mkdir()
            (secrets / "sessions.yaml").write_text(
                "sessions:\n"
                "  A:\n    authorization: Bearer token-a\n"
                "  B:\n    authorization: Bearer token-b\n",
                encoding="utf-8",
            )

            def fake_http(target_dir, url, **kwargs):
                sess = kwargs.get("session") or "anon"
                label = kwargs.get("label") or sess
                # A owns object → 200 private; B same URL → 200 leak
                status = 200 if sess in {"A", "B"} else 401
                body = f'{{"owner":"A","sess":"{sess}"}}' if status == 200 else "denied"
                payload = {
                    "status": status,
                    "body": body,
                    "body_preview": body,
                    "sha256": "x",
                    "label": label,
                }
                return RunnerResult(
                    ["http"], True, 0, json.dumps(payload), "", "executed"
                )

            with mock.patch.object(api_probes.http_mod, "http_request", side_effect=fake_http):
                r = api_probes.api_authz_matrix(
                    root,
                    "https://api.example.com/users/1",
                    approve=True,
                    include_anon=True,
                )
            data = json.loads(r.stdout)
            self.assertTrue(data.get("ok"))
            self.assertIn(data.get("verdict"), {"confirmed", "likely", "negative", "inconclusive"})
            self.assertEqual(len(data.get("rows") or []), 3)
            # cache seeded for assert_diff
            from hackbot.tools import _RESPONSE_CACHE, _cache_key

            self.assertIn(_cache_key(root, "authz_A"), _RESPONSE_CACHE)


class AiSurfaceTests(unittest.TestCase):
    def test_persist_and_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            r = upsert_ai_surface(
                root,
                chat_url="https://chat.example.com/v1/chat",
                prompt_field="messages",
                mcp_urls=["https://chat.example.com/mcp"],
                tags=["llm", "rag"],
                tenant="t-a",
            )
            self.assertTrue(r["ok"])
            surfaces = list_ai_surfaces(root)
            self.assertEqual(len(surfaces), 1)
            self.assertEqual(surfaces[0].prompt_field, "messages")
            self.assertIn("https://chat.example.com/mcp", surfaces[0].mcp_urls)
            path = root / "hunt" / "ai_surfaces.yaml"
            self.assertTrue(path.is_file())


class OpenApiExternalRefTests(unittest.TestCase):
    def test_file_ref_and_allof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "schemas.yaml").write_text(
                "components:\n"
                "  schemas:\n"
                "    User:\n"
                "      type: object\n"
                "      properties:\n"
                "        id:\n"
                "          type: string\n"
                "          example: u1\n"
                "        role:\n"
                "          type: string\n"
                "          enum: [user, admin]\n"
                "  parameters:\n"
                "    Id:\n"
                "      name: id\n"
                "      in: path\n"
                "      required: true\n"
                "      schema:\n"
                "        type: string\n",
                encoding="utf-8",
            )
            (root / "openapi.yaml").write_text(
                "openapi: 3.0.0\n"
                "info:\n"
                "  title: t\n"
                "  version: '1'\n"
                "servers:\n"
                "  - url: https://api.example.com\n"
                "paths:\n"
                "  /users/{id}:\n"
                "    get:\n"
                "      operationId: getUser\n"
                "      parameters:\n"
                "        - $ref: './schemas.yaml#/components/parameters/Id'\n"
                "      responses:\n"
                "        '200':\n"
                "          description: ok\n"
                "    post:\n"
                "      operationId: createUser\n"
                "      requestBody:\n"
                "        content:\n"
                "          application/json:\n"
                "            schema:\n"
                "              allOf:\n"
                "                - $ref: './schemas.yaml#/components/schemas/User'\n"
                "                - type: object\n"
                "                  properties:\n"
                "                    email:\n"
                "                      type: string\n"
                "                      example: hb@example.com\n"
                "      responses:\n"
                "        '200':\n"
                "          description: ok\n",
                encoding="utf-8",
            )
            r = ingest_openapi_file(root, root / "openapi.yaml", host="api.example.com")
            self.assertTrue(r["ok"], r)
            self.assertGreaterEqual(r["seeded"], 1)
            from hackbot.hunt_memory import HuntMemory

            eps = HuntMemory(root).endpoints()
            get = next(e for e in eps if e.method == "GET")
            self.assertIn("id", get.params)
            post = next(e for e in eps if e.method == "POST")
            self.assertTrue(post.body_template)
            self.assertIn("email", post.body_template)


class CurlToolTests(unittest.TestCase):
    def test_spec_and_dry_run(self) -> None:
        names = {s["name"] for s in TOOL_SPECS}
        self.assertIn("curl_request", names)
        self.assertIn("ai_surface_upsert", names)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(
                "# Scope\n\n## In scope\n- api.example.com\n", encoding="utf-8"
            )
            r = curl_request.curl_request(
                root, "https://api.example.com/x", approve=False
            )
            self.assertEqual(r.message, "dry-run")
            raw = execute_tool(
                "curl_request",
                {
                    "target_dir": str(root),
                    "url": "https://api.example.com/x",
                    "approve": False,
                },
            )
            self.assertFalse(json.loads(raw).get("executed"))


if __name__ == "__main__":
    unittest.main()
