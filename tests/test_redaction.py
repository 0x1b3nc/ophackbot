"""Tests for secret / PII redaction."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hackbot.evidence import EvidenceStore
from hackbot.redaction import (
    StrictRedactError,
    looks_sensitive,
    redact_text,
    strict_check,
    unknown_sensitive_headers,
)


class RedactionTests(unittest.TestCase):
    def test_authorization_header(self) -> None:
        raw = "Authorization: Bearer supersecrettoken123\nAccept: application/json\n"
        out = redact_text(raw)
        self.assertIn("[REDACTED]", out)
        self.assertNotIn("supersecrettoken123", out)

    def test_cookie_header(self) -> None:
        raw = "Cookie: session=abc123; other=1\n"
        out = redact_text(raw)
        self.assertNotIn("abc123", out)

    def test_email(self) -> None:
        out = redact_text("contact me at hunter@example.com please")
        self.assertIn("[REDACTED_EMAIL]", out)
        self.assertNotIn("hunter@example.com", out)

    def test_jwt(self) -> None:
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "signaturepart"
        )
        out = redact_text(f"token={jwt}")
        self.assertIn("[REDACTED_JWT]", out)

    def test_looks_sensitive(self) -> None:
        self.assertTrue(looks_sensitive("Authorization: Bearer stillhere123456"))
        self.assertFalse(looks_sensitive("Authorization: [REDACTED]\nOK"))

    def test_unknown_headers_for_strict(self) -> None:
        text = "Content-Type: application/json\nX-Internal-Session: abcd1234\n"
        self.assertIn("x-internal-session", unknown_sensitive_headers(text))
        reasons = strict_check(text)
        self.assertTrue(any("x-internal-session" in r for r in reasons))

    def test_strict_evidence_refuses_unknown_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(Path(tmp))
            with self.assertRaises(StrictRedactError):
                store.save(
                    "leak.txt",
                    "X-Internal-Session: abcd1234\n",
                    strict=True,
                )
            self.assertEqual(list(store.safe.glob("*")), [])


if __name__ == "__main__":
    unittest.main()
