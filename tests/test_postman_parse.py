"""Postman collection ingestion → HuntMemory."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hackbot.hunt_memory import HuntMemory
from hackbot.postman_parse import ingest_postman_text, parse_postman_dict

COLLECTION = {
    "info": {
        "name": "Demo API",
        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    "variable": [{"key": "baseUrl", "value": "https://api.example.com"}],
    "item": [
        {
            "name": "Get account",
            "request": {
                "method": "GET",
                "header": [{"key": "Authorization", "value": "Bearer {{token}}"}],
                "url": "{{baseUrl}}/accounts/{{accountId}}",
                "auth": {"type": "bearer"},
            },
            "response": [{"name": "ok", "status": "OK"}],
        },
        {
            "name": "Folder",
            "item": [
                {
                    "name": "Create invite",
                    "request": {
                        "method": "POST",
                        "header": [{"key": "Content-Type", "value": "application/json"}],
                        "body": {
                            "mode": "raw",
                            "raw": '{"email":"hb_canary@example.com","role":"hb_canary_role"}',
                        },
                        "url": {
                            "raw": "{{baseUrl}}/invites",
                            "host": ["{{baseUrl}}"],
                            "path": ["invites"],
                        },
                    },
                }
            ],
        },
    ],
}


class PostmanParseTests(unittest.TestCase):
    def test_parse_methods_and_auth(self) -> None:
        eps = parse_postman_dict(COLLECTION)
        self.assertGreaterEqual(len(eps), 2)
        get_ep = next(e for e in eps if e.method == "GET")
        self.assertIn("accounts", get_ep.url)
        self.assertTrue(get_ep.auth_required)
        post = next(e for e in eps if e.method == "POST")
        self.assertIn("role", post.body_template)

    def test_ingest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            r = ingest_postman_text(root, json.dumps(COLLECTION), host="api.example.com")
            self.assertTrue(r["ok"])
            self.assertGreater(r["seeded"], 0)
            self.assertTrue(HuntMemory(root).endpoints())


if __name__ == "__main__":
    unittest.main()
