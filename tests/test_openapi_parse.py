"""OpenAPI JSON/YAML parsing, body templates, ranking, coverage seed."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hackbot.api_rank import endpoint_risk_score, rank_endpoints
from hackbot.coverage_map import load_coverage
from hackbot.hunt_memory import Endpoint, HuntMemory
from hackbot.openapi_parse import ingest_openapi_text, parse_openapi_dict


OAS3 = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1"},
    "servers": [{"url": "https://api.example.com"}],
    "components": {
        "securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer"},
        }
    },
    "security": [{"bearer": []}],
    "paths": {
        "/users/{id}": {
            "parameters": [
                {
                    "name": "id",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "example": "u1"},
                }
            ],
            "get": {
                "operationId": "getUser",
                "tags": ["users"],
                "summary": "Get user",
                "parameters": [
                    {"name": "X-Request-Id", "in": "header", "schema": {"type": "string"}}
                ],
                "responses": {"200": {"description": "ok"}},
            },
        },
        "/static/app.js": {
            "get": {
                "operationId": "staticJs",
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/billing/invoices": {
            "post": {
                "operationId": "createInvoice",
                "tags": ["billing"],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "amount": {"type": "integer", "example": 10},
                                    "plan": {"type": "string", "enum": ["free", "pro"]},
                                },
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
}

SWAGGER2_YAML = """
swagger: "2.0"
host: legacy.example.com
basePath: /api
schemes: [https]
paths:
  /orders/{orderId}:
    get:
      operationId: getOrder
      parameters:
        - name: orderId
          in: path
          type: string
          required: true
      responses:
        200:
          description: ok
"""


class OpenApiParseTests(unittest.TestCase):
    def test_json_extracts_params_body_auth(self) -> None:
        eps = parse_openapi_dict(OAS3)
        by_url = {e.url: e for e in eps}
        user = by_url["https://api.example.com/users/{id}"]
        self.assertEqual(user.method, "GET")
        self.assertIn("id", user.params)
        self.assertTrue(user.auth_required)
        self.assertIn("getUser", user.notes)
        bill = next(e for e in eps if e.method == "POST")
        self.assertTrue(bill.body_template)
        self.assertIn("amount", bill.body_template)

    def test_yaml_swagger2(self) -> None:
        from hackbot.openapi_parse import _load_spec

        spec = _load_spec(SWAGGER2_YAML)
        assert spec is not None
        eps = parse_openapi_dict(spec)
        self.assertTrue(eps)
        self.assertTrue(eps[0].url.startswith("https://legacy.example.com/api/orders"))

    def test_ranking_sensitive_above_static(self) -> None:
        eps = parse_openapi_dict(OAS3)
        ranked = rank_endpoints(eps)
        self.assertGreater(endpoint_risk_score(ranked[0]), endpoint_risk_score(ranked[-1]))
        self.assertNotIn("/static/", ranked[0].url)

    def test_ingest_seeds_memory_and_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(
                "# Scope\n\n## In scope\n- api.example.com\n", encoding="utf-8"
            )
            r = ingest_openapi_text(root, json.dumps(OAS3), host="api.example.com")
            self.assertTrue(r["ok"])
            self.assertGreater(r["seeded"], 0)
            mem = HuntMemory(root)
            self.assertTrue(mem.endpoints())
            cov = load_coverage(root)
            self.assertTrue(cov.get("entries"))


if __name__ == "__main__":
    unittest.main()
