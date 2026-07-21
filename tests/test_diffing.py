"""IDOR assert_diff heuristics."""

from __future__ import annotations

import unittest

from hackbot.diffing import assert_idor_diff


class DiffingTests(unittest.TestCase):
    def test_negative_denied(self) -> None:
        a = {"status": 200, "body": '{"id":1,"email":"a@x.com"}', "sha256": "aaa"}
        b = {"status": 403, "body": "forbidden", "sha256": "bbb"}
        d = assert_idor_diff(a, b)
        self.assertEqual(d.verdict, "negative")

    def test_confirmed_leak(self) -> None:
        a = {"status": 200, "body": '{"id":42,"secret":"alice"}', "sha256": "hashA"}
        b = {"status": 200, "body": '{"id":42,"secret":"alice"}', "sha256": "hashB"}
        # different hash, same id hint
        b["sha256"] = "hashB"
        d = assert_idor_diff(a, b, object_hint="alice")
        self.assertIn(d.verdict, {"confirmed", "likely"})

    def test_inconclusive_both_fail(self) -> None:
        a = {"status": 401, "body": "", "sha256": "x"}
        b = {"status": 401, "body": "", "sha256": "y"}
        d = assert_idor_diff(a, b)
        self.assertEqual(d.verdict, "inconclusive")


if __name__ == "__main__":
    unittest.main()
