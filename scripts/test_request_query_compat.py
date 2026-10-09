#!/usr/bin/env python3
"""Pure shared query vectors; no provider, routing, canonical digest or dispatch.

These tests do not prove signed mode selection, legacy parity, canonical v3
consumer fences, approval handling, final URL preservation, or SDK operation.
Those require the separate Python/Rust integration and transport controls.
"""
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import request_query_compat as query


FIXTURES = ROOT / "scripts/fixtures/ordered_form_query_v1.json"


class OrderedFormQueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))
        cls.cases = {case["id"]: case for case in cls.fixtures["cases"]}

    def error(self, code, function, *args, **kwargs):
        with self.assertRaises(query.QueryCompatibilityError) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(str(raised.exception), code)

    def test_fixture_identity_and_fixed_bounds(self):
        self.assertEqual(self.fixtures["schema"], "serverware.orderedFormQueryVectors/v1")
        self.assertEqual(self.fixtures["mode"], query.MODE)
        self.assertEqual(self.fixtures["adapter"], query.ADAPTER)
        self.assertEqual(self.fixtures["limits"], {
            "raw_bytes": query.MAX_RAW_QUERY_BYTES, "segments": query.MAX_SEGMENTS,
            "pairs": query.MAX_PAIRS, "repeated_values": query.MAX_REPEATED_VALUES})
        self.assertEqual(len(self.cases), len(self.fixtures["cases"]))
        self.assertGreaterEqual(len(self.cases), 50)

    def test_shared_golden_vectors(self):
        for case in self.fixtures["cases"]:
            with self.subTest(case=case["id"]):
                operation = case["operation"]
                function = query.parse_query if operation is None else query.parse_gmail_query
                kwargs = {} if operation is None else {"operation": operation}
                if "error" in case:
                    self.error(case["error"], function, case["raw_query"], **kwargs)
                else:
                    parsed = function(case["raw_query"], **kwargs)
                    self.assertEqual(parsed.raw_query, case["raw_query"])
                    self.assertEqual(parsed.pairs, tuple(tuple(pair) for pair in case["pairs"]))

    def test_decoded_equivalence_does_not_erase_raw_identity(self):
        for group in self.fixtures["same_pairs_distinct_wire"]:
            with self.subTest(group=group):
                parsed = [query.parse_query(self.cases[name]["raw_query"]) for name in group]
                self.assertEqual(len({item.raw_query for item in parsed}), len(parsed))
                for item in parsed[1:]:
                    self.assertEqual(item.pairs, parsed[0].pairs)
                    self.assertNotEqual(item, parsed[0])

    def test_repeat_order_and_literal_plus_are_not_collapsed(self):
        forward = query.parse_query(self.cases["repeat-labels"]["raw_query"])
        reverse = query.parse_query(self.cases["reverse-labels"]["raw_query"])
        self.assertNotEqual(forward.pairs, reverse.pairs)
        self.assertNotEqual(query.parse_query("q=a+b").pairs, query.parse_query("q=a%2Bb").pairs)
        self.assertEqual(query.parse_query("q=%252B").pairs, (("q", "%2B"),))

    def test_raw_byte_bound(self):
        at_limit = "q=" + "a" * (query.MAX_RAW_QUERY_BYTES - 2)
        self.assertEqual(query.parse_query(at_limit).raw_query, at_limit)
        self.error("query_too_large", query.parse_query, at_limit + "a")

    def test_pair_and_skipped_segment_bounds(self):
        at_limit = "&".join(f"key{index}=v" for index in range(query.MAX_PAIRS))
        self.assertEqual(len(query.parse_query(at_limit).pairs), query.MAX_PAIRS)
        self.error("query_segment_limit", query.parse_query, at_limit + "&extra=v")
        self.assertEqual(query.parse_query("&" * (query.MAX_SEGMENTS - 1)).pairs, ())
        self.error("query_segment_limit", query.parse_query, "&" * query.MAX_SEGMENTS)
        self.assertEqual(query.parse_query("&" * (query.MAX_SEGMENTS - 1) + "q").pairs, (("q", ""),))

    def test_operation_specific_repeat_bounds_and_encoded_aliases(self):
        for operation, key, escaped in (
            (query.LIST_OPERATION, "labelIds", "%6cabelIds"),
            (query.GET_OPERATION, "metadataHeaders", "%6detadataHeaders"),
        ):
            with self.subTest(operation=operation):
                wire = "&".join([f"{key}=same"] * query.MAX_REPEATED_VALUES)
                parsed = query.parse_gmail_query(wire, operation=operation)
                self.assertEqual(len(parsed.pairs), query.MAX_REPEATED_VALUES)
                self.error("query_repeat_limit", query.parse_gmail_query,
                    wire + f"&{escaped}=same", operation=operation)

    def test_constructed_record_must_match_wire(self):
        parsed = query.parse_gmail_query("labelIds=INBOX&labelIds=STARRED", operation=query.LIST_OPERATION)
        self.error("query_binding_mismatch", query.validate_gmail_query,
            replace(parsed, pairs=tuple(reversed(parsed.pairs))), operation=query.LIST_OPERATION)
        self.error("query_binding_mismatch", query.validate_gmail_query,
            query.OrderedFormQuery("q=a%2Bb", (("q", "a b"),)), operation=query.LIST_OPERATION)
        self.error("query_binding_mismatch", query.validate_gmail_query,
            query.OrderedFormQuery(None, (("q", "x"),)), operation=query.LIST_OPERATION)
        with self.assertRaises(FrozenInstanceError):
            parsed.raw_query = "q=changed"

    def test_syntax_is_not_provider_value_validation(self):
        # Separate adapter checks must still refuse these invalid provider values.
        query.parse_gmail_query("maxResults=0&q", operation=query.LIST_OPERATION)
        query.parse_gmail_query("metadataHeaders=", operation=query.GET_OPERATION)
        query.parse_gmail_query("includeSpamTrash=true", operation=query.LIST_OPERATION)

    def test_syntax_is_not_operation_authorization(self):
        parsed = query.parse_query("unknown=a&unknown=b")
        self.error("query_name_denied", query.validate_gmail_query, parsed, operation=query.LIST_OPERATION)
        self.error("query_operation_unsupported", query.parse_gmail_query, None, operation="gmail.message.send")

    def test_bad_python_input_types_fail_closed(self):
        for value in (b"q=hello", 1, True, [], {}):
            with self.subTest(value_type=type(value).__name__):
                self.error("query_invalid_type", query.parse_query, value)
        self.error("query_binding_mismatch", query.validate_gmail_query,
            {"raw_query": "q=a", "pairs": (("q", "a"),)}, operation=query.LIST_OPERATION)

    def test_all_c0_del_c1_and_backslash_refused_after_decoding(self):
        for point in (*range(0x20), *range(0x7F, 0xA0), 0x5C):
            with self.subTest(codepoint=point):
                escaped = "".join(f"%{byte:02X}" for byte in chr(point).encode("utf-8"))
                self.error("query_forbidden_character", query.parse_query, "q=" + escaped)


if __name__ == "__main__":
    unittest.main(failfast=True)
