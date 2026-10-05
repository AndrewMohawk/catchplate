#!/usr/bin/env python3
"""Complete relative history replay using independent primary/index fixtures.

These controls do not establish SQL snapshot custody, signed parent admission,
live recovery, a real hardware ceremony or maximal-population performance.
"""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_recovery_history as history
from serverware import authority_index_projection as projection
from serverware.authority_index_contract import IndexLeaf, KeyInterval
from serverware.authority_index_heads import CapturedIndexHead
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_index_join import expected_profile, expected_leaf, expected_interval
from test_authority_index_range import IndependentIndex
from test_authority_index_range_count import count_frontier
from test_authority_radix_mutation import IndependentTree


def encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def credential(identity, user="target", *, revoked=None):
    return dict(id=identity, credential_id="wire-" + identity, user_id=user, label="hardware",
        public_key_cose="synthetic-cose", sign_count=1, aaguid=None,
        authenticator_class="yubikey", attestation_fmt=None, attestation_trusted=1,
        attestation_trust_path="[]", attestation_leaf_sha256=None, attestation_root_sha256=None,
        attestation_trust_bundle_digest=None, attestation_trust_bundle_sequence=None,
        attestation_verified_at=None, transports='["usb"]', dev_private_key_pem=None,
        created_at="2026-01-01T00:00:00+00:00", updated_at="2026-01-01T00:00:00+00:00",
        last_used_at=None, revoked_at=revoked, revoked_by=None, revocation_reason=None,
        revocation_source=None)


def legacy_projection(row):
    # Literal independent legacy mapping; no production projector/serializer.
    result = {name: row[name] for name in ("sign_count", "aaguid", "authenticator_class",
        "attestation_fmt", "attestation_leaf_sha256", "attestation_root_sha256",
        "attestation_trust_bundle_digest", "attestation_trust_bundle_sequence",
        "attestation_verified_at", "created_at", "updated_at", "last_used_at", "revoked_at",
        "revoked_by", "revocation_reason", "revocation_source")}
    result.update(record_id=row["id"], credential_id_digest=digest(row["credential_id"].encode()),
        public_key_cose_digest=digest(row["public_key_cose"].encode("ascii")),
        attestation_trusted=bool(row["attestation_trusted"]),
        attestation_trust_path=json.loads(row["attestation_trust_path"] or "[]"),
        transports=json.loads(row["transports"] or "[]"),
        development_material_digest=(None if row["dev_private_key_pem"] is None
                                     else digest(row["dev_private_key_pem"].encode())))
    return result


def frontier_wire(frontier):
    return [({"kind": "leaf", "key": item.key, "primaryKeyDigest": item.primary_key_digest,
              "primaryRowDigest": item.primary_row_digest} if type(item) is IndexLeaf else
             {"kind": "opaque", "prefix": item.prefix, "digest": item.digest, "count": item.count})
            for item in frontier]


class Fixture:
    def __init__(self, rows=None, *, maximum_count=1000, maximum_bytes=4 * 1024 * 1024):
        self.rows = rows if rows is not None else [credential("a"), credential("b", revoked="revoked"),
                                                  credential("elsewhere", user="other")]
        self.primary = IndependentTree(self.rows, table="webauthn_credentials")
        profile = expected_profile("webauthn_credential_user_history")
        self.selected = [self.primary.selected({"id": row["id"]}) for row in self.rows]
        leaves = [expected_leaf(profile, item["row"], item, self.primary.proof(item)) for item in self.selected]
        index = IndependentIndex(leaves, profile=profile)
        self.head = CapturedIndexHead(profile.index_id, profile.table, projection.COUNTED_PROFILE,
            profile.projection_digest, projection.projection_manifest_digest(), 7, index.root)
        whole = expected_interval(profile, {"user_id": "target"})
        self.count_body = encoded({"schema": history.COUNT_SCHEMA,
                                  "frontier": frontier_wire(count_frontier(index, whole))})
        selected_by_key = {item["keyDigest"]: item for item in self.selected}
        selected_leaves = index.matches(whole)
        self.pages, lower = [], whole.lower
        for ordinal, leaf in enumerate(selected_leaves):
            upper = whole.upper if ordinal == len(selected_leaves) - 1 else f"{int(leaf.key, 16) + 1:0160x}"
            selected = selected_by_key[leaf.primary_key_digest]
            self.pages.append(encoded({"schema": history.PAGE_SCHEMA, "ordinal": ordinal,
                "lower": lower, "upper": upper, "selectedRows": [selected],
                "beforeProofs": [self.primary.proof(selected)],
                "frontier": frontier_wire(index.frontier(KeyInterval(lower, upper)))}))
            lower = upper
        self.context = {"operation": "webauthn.recovery.create", "userId": "target", "cutoffUs": 1,
            "maximumCount": maximum_count, "maximumBytes": maximum_bytes,
            "primaryRoot": self.primary.root.json_projection(), "indexHead": history.head_wire(self.head)}

    def manifest(self):
        descriptor = lambda raw: {"byteCount": len(raw), "digest": digest(raw)}
        count = descriptor(self.count_body)
        pages = [descriptor(raw) for raw in self.pages]
        chain = digest(encoded({"schema": history.CHAIN_SCHEMA, "context": self.context, "countBody": count}))
        for ordinal, page in enumerate(pages):
            chain = digest(encoded({"schema": history.CHAIN_SCHEMA, "previous": chain,
                                    "ordinal": ordinal, **page}))
        return {"schema": history.SCHEMA, **self.context, "countBody": count,
                "pages": pages, "chainDigest": chain}

    def verify(self, **changes):
        arguments = dict(manifest=self.manifest(), count_body=self.count_body, read_page=self.pages.__getitem__,
            operation=self.context["operation"], user_id="target", cutoff_us=1,
            maximum_count=self.context["maximumCount"], maximum_bytes=self.context["maximumBytes"],
            primary_root=self.primary.root.json_projection(), index_head=self.head)
        arguments.update(changes)
        return history.verify_history(**arguments)


class RecoveryHistoryTests(unittest.TestCase):
    def test_real_count_full_rows_ranges_and_legacy_digest(self):
        fixture = Fixture()
        calls = []
        def read(ordinal):
            calls.append(ordinal)
            return fixture.pages[ordinal]
        result = fixture.verify(read_page=read)
        rows = sorted((row for row in fixture.rows if row["user_id"] == "target"),
                      key=lambda row: (row["created_at"], row["id"]))
        expected = encoded([legacy_projection(row) for row in rows])
        self.assertEqual(result.digest, digest(expected))
        self.assertEqual((result.count, result.active_count, calls), (2, 1, [0, 1]))
        self.assertEqual(len(result.metrics.phases), 4)
        self.assertEqual(result.metrics.projection_bytes, len(expected))
        self.assertEqual(result.metrics.total.input_bytes,
                         sum(item.input_bytes for item in result.metrics.phases))
        self.assertTrue(all(item.input_bytes <= 64 * 1024 * 1024 for item in result.metrics.phases))

    def test_missing_page_refused_by_actual_count_before_callback(self):
        fixture = Fixture()
        fixture.pages.pop()
        def forbidden(_):
            self.fail("page callback ran after count mismatch")
        with self.assertRaises(history.RecoveryHistoryError):
            fixture.verify(read_page=forbidden)

    def test_resealed_wrong_row_gap_ordinal_and_hidden_leaf_are_rejected(self):
        def changed_row(page):
            page["selectedRows"][0]["row"]["sign_count"] += 1
        def gap(page):
            page["lower"] = f"{int(page['lower'], 16) + 1:0160x}"
        def ordinal(page):
            page["ordinal"] = 1
        def hidden_leaf(page):
            page["frontier"] = [item for item in page["frontier"] if item["kind"] != "leaf"]
        for mutation in (changed_row, gap, ordinal, hidden_leaf):
            with self.subTest(mutation=mutation.__name__):
                fixture = Fixture()
                page = json.loads(fixture.pages[0])
                mutation(page)
                fixture.pages[0] = encoded(page)  # Manifest/chain also re-sealed; proofs must catch it.
                with self.assertRaises(ValueError):
                    fixture.verify()

    def test_independent_anchor_config_and_raw_canonicality_remain_required(self):
        for change in ({"user_id": "another"}, {"cutoff_us": 2}, {"maximum_count": 999},
                       {"maximum_bytes": 65_536}):
            with self.subTest(change=change), self.assertRaises(history.RecoveryHistoryError):
                Fixture().verify(**change)
        fixture = Fixture()
        fixture.pages[0] = fixture.pages[0] + b"\n"
        with self.assertRaises(history.RecoveryHistoryError):
            fixture.verify()

    def test_empty_history_preserves_configured_maximum_without_an_empty_page(self):
        fixture = Fixture([], maximum_count=10_000, maximum_bytes=16 * 1024 * 1024)
        result = fixture.verify(read_page=lambda _: self.fail("empty history read a page"))
        self.assertEqual((result.digest, result.count, result.active_count), (digest(b"[]"), 0, 0))
        self.assertEqual(len(result.metrics.phases), 2)

    def test_single_projection_matches_legacy_fallback_and_unicode_hashes(self):
        row = credential("unicode")
        row.update(credential_id="credential-\u00e9", transports="", attestation_trust_path="",
                   dev_private_key_pem="synthetic-development-material", attestation_trusted=-1)
        work = _ValidationWork(QueryReadValidationLimits())
        self.assertEqual(history.project_history_row(row, work=work), encoded(legacy_projection(row)))
        self.assertGreater(work.hash_work, 0)

    def test_historical_json_text_keeps_legacy_parser_domain(self):
        for text in ('["\u00e9"]', '["\\u00e9"]', '[1.25,1e15,NaN,Infinity]',
                     '{"duplicate":1,"duplicate":2}', '["\\u0000","\\ud800"]'):
            with self.subTest(text=text):
                row = credential("historical")
                row["transports"] = text
                work = _ValidationWork(QueryReadValidationLimits())
                self.assertEqual(history.project_history_row(row, work=work), encoded(legacy_projection(row)))


if __name__ == "__main__":
    unittest.main()
