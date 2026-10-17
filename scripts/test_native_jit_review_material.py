#!/usr/bin/env python3
"""Real private-JIT AEAD components with public synthetic keys only.

Inputs come through the actual installed facade (stopped before transport),
service extraction and public request codec. Independent AESGCM readback checks
the exact AAD/wrapper wire contract. No native owner, attestation, configured
trust, database, approval, review authorization or plaintext erasure is claimed.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def no_network(event, _args):
    if event.startswith("socket."):
        raise AssertionError("JIT material tests forbid sockets and DNS")


if __name__ == "__main__":
    sys.addaudithook(no_network)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scripts import test_authority_jit_private_request as ingress
from scripts import test_authority_jit_request as original
from scripts import test_authority_release_private_request as release_fixture
from catchplate import authority_contract as contract
from catchplate import authority_jit_private_request as private
from catchplate import authority_planner as planner
from catchplate import authority_release_private_request as release_private
from catchplate import native_jit_review_material as material


NOW = 1_800_000_000_000_000_000
SECOND = 1_000_000_000
KEY = bytes(range(32))  # Public synthetic fixture, never provisioned or deployed.
KEY_ID = "attested-memory-kek:" + hashlib.sha256(KEY).hexdigest()[:24]
KINDS = ("approval-secret-json/v1", "approval-review-json/v1")
PURPOSES = ("jit-canonical-request", "jit-redacted-display")
ITEM_FIELDS = {"opaqueId", "valueKind", "plaintextSha256", "plaintextBytes",
    "wrappedKeyNonce", "wrappedKey", "ciphertextNonce", "ciphertext"}
_UNSET = object()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")


def encoded(value):
    return base64.urlsafe_b64encode(value).decode("ascii")


def decoded(value):
    return base64.b64decode(value, altchars=b"-_", validate=True)


def fixture(raw=None):
    envelope = ingress.captured() if raw is None else private.prepare(raw)
    public, explicit, documents = ingress.extracted(envelope)
    if explicit is not None:
        raise AssertionError("unexpected assertion channel")
    request = ingress.typed_request(public)
    scope = {"schema": "catchplate.nativeJitReviewScope/v1", "publicRequest": request,
        "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
        "controlPlaneConfigurationDigest": original.sha(b"synthetic JIT configuration"),
        "ownerScopeDigest": original.sha(b"synthetic JIT owner scope"),
        "issuedAtEpochNs": NOW, "sealExpiresAtEpochNs": NOW + 30 * SECOND,
        "documentExpiresAtEpochNs": NOW + public["pending_ttl_seconds"] * SECOND}
    return scope, documents


def aad(scope, item, purpose, key_id=KEY_ID):
    # Independent literal protocol oracle, not material._aad or _identity.
    return canonical({"schema": "catchplate.nativeJitReviewAad/v1", "purpose": purpose,
        "scope": scope, "keyId": key_id,
        "approvalRequestId": original.identity(scope["publicRequest"]["requestDigest"], "jit-approval-request"),
        **{name: item[name] for name in ("opaqueId", "valueKind", "plaintextSha256", "plaintextBytes")}})


class Cancelled(BaseException):
    pass


def release_fixture_values(raw=None):
    """Actual original codec, independently framed parent/child expectations."""
    raw = release_fixture.native_raw_arguments() if raw is None else raw
    envelope = release_private.prepare(raw)
    expected = release_fixture.expected_envelope(raw)
    if canonical(envelope) != canonical(expected):
        raise AssertionError("release fixture original projection changed")
    parent = release_fixture.native_request_oracle("release.reserve", expected["arguments"])
    child = release_fixture.native_request_oracle("jit.request", expected["arguments"]["jit_approval_request"])
    scope = {"schema": "catchplate.nativeJitReviewScope/v2", "publicRequest": child,
        "parentRequestSha256": original.sha(canonical(parent)),
        "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
        "controlPlaneConfigurationDigest": original.sha(b"synthetic JIT configuration"),
        "ownerScopeDigest": original.sha(b"synthetic JIT owner scope"),
        "issuedAtEpochNs": NOW, "sealExpiresAtEpochNs": NOW + 30 * SECOND,
        "documentExpiresAtEpochNs": NOW + raw["jit_approval_request"]["pending_ttl_seconds"] * SECOND}
    return scope, envelope["privateDocuments"], parent


def release_aad(scope, item, purpose, key_id=KEY_ID):
    # Independent literal v2 domain. A parent commitment is AAD, not evidence
    # that the material leaf independently authenticated a release request.
    return canonical({"schema": "catchplate.nativeJitReviewAad/v2", "purpose": purpose,
        "scope": scope, "keyId": key_id,
        "approvalRequestId": original.identity(scope["publicRequest"]["requestDigest"], "jit-approval-request"),
        **{name: item[name] for name in ("opaqueId", "valueKind", "plaintextSha256", "plaintextBytes")}})


class NativeJitReviewMaterialTests(unittest.TestCase):
    def setUp(self):
        self.scope, self.documents = fixture()
        self.kek = AESGCM(KEY)

    def seal(self, scope=_UNSET, documents=_UNSET, **changes):
        return material.seal_pair(self.scope if scope is _UNSET else scope,
            self.documents if documents is _UNSET else documents,
            **{"key_id": KEY_ID, "kek": self.kek, "now_epoch_ns": NOW, **changes})

    def open(self, pair, **changes):
        return material.open_pair(pair, **{"expected_scope": self.scope,
            "key_id": KEY_ID, "kek": self.kek, "now_epoch_ns": NOW, **changes})

    def refused(self, call):
        with self.assertRaisesRegex(material.MaterialError,
                "^native JIT review material is invalid$") as caught:
            call()
        self.assertIsNone(caught.exception.__cause__)
        for canary in ingress.CANARIES:
            self.assertNotIn(canary, str(caught.exception))

    def forge_plaintext(self, pair, index, plaintext):
        """Authenticated synthetic malformed plaintext, not owner admission."""
        value = copy.deepcopy(pair)
        item = value["items"][index]
        item.update(plaintextSha256=original.sha(plaintext), plaintextBytes=len(plaintext))
        # Fixed test key/nonces only for these independent corruption controls.
        dek, wrap_nonce, nonce = b"d" * 32, b"w" * 12, b"n" * 12
        item.update(wrappedKeyNonce=encoded(wrap_nonce), ciphertextNonce=encoded(nonce),
            wrappedKey=encoded(self.kek.encrypt(wrap_nonce, dek, aad(self.scope, item, "wrap-dek"))),
            ciphertext=encoded(AESGCM(dek).encrypt(nonce, plaintext, aad(self.scope, item, "encrypt-document"))))
        return value

    def test_real_facade_public_request_and_exact_original_roundtrip(self):
        before_scope, before_docs = copy.deepcopy(self.scope), copy.deepcopy(self.documents)
        request = self.scope["publicRequest"]
        self.assertEqual(planner.typed_request_digest(request), request["requestDigest"])
        pair = self.seal()
        self.assertEqual(set(pair), {"schema", "scope", "keyId", "items"})
        self.assertEqual(pair["schema"], "catchplate.nativeJitReviewPair/v1")
        self.assertEqual(pair["scope"], self.scope)
        self.assertEqual(pair["keyId"], KEY_ID)
        self.assertEqual(len(pair["items"]), 2)
        self.assertEqual(self.open(pair), self.documents)
        self.assertEqual(self.scope, before_scope)
        self.assertEqual(self.documents, before_docs)
        opened = self.open(pair)
        opened["canonical_request"]["literal"]["base64Url"] = "not retained"
        self.assertEqual(self.open(pair), before_docs)
        self.assertIsNot(pair["scope"], self.scope)

    def test_independent_aesgcm_aad_and_plaintext_wrapper_digest_oracle(self):
        pair = self.seal()
        plaintexts = (canonical({"schema": "catchplate.jitCanonicalReviewPayload/v1",
            "url": self.documents["url"], "canonical_request": self.documents["canonical_request"]}),
            canonical(self.documents["redacted_display"]))
        for index, (item, plaintext) in enumerate(zip(pair["items"], plaintexts)):
            self.assertEqual(set(item), ITEM_FIELDS)
            self.assertEqual(item["opaqueId"], original.identity(self.scope["publicRequest"]["requestDigest"], PURPOSES[index]))
            self.assertEqual(item["valueKind"], KINDS[index])
            self.assertEqual(item["plaintextBytes"], len(plaintext))
            self.assertEqual(item["plaintextSha256"], original.sha(plaintext))
            dek = self.kek.decrypt(decoded(item["wrappedKeyNonce"]), decoded(item["wrappedKey"]),
                aad(self.scope, item, "wrap-dek"))
            self.assertEqual(len(dek), 32)
            self.assertEqual(AESGCM(dek).decrypt(decoded(item["ciphertextNonce"]), decoded(item["ciphertext"]),
                aad(self.scope, item, "encrypt-document")), plaintext)
        # The encrypted first payload includes URL + schema; its digest is NOT
        # the existing canonical_request document-only commitment.
        self.assertNotEqual(pair["items"][0]["plaintextSha256"],
            self.scope["publicRequest"]["arguments"]["canonical_request_digest"])

    def test_randomized_sealing_and_no_plaintext_in_public_persistable_bytes(self):
        first, second = self.seal(), self.seal()
        for index in range(2):
            for name in ("wrappedKeyNonce", "wrappedKey", "ciphertextNonce", "ciphertext"):
                self.assertNotEqual(first["items"][index][name], second["items"][index][name])
        self.assertNotEqual(first["items"][0]["ciphertextNonce"], first["items"][1]["ciphertextNonce"])
        for value in (first, second, self.scope["publicRequest"]):
            wire = canonical(value)
            for canary in ingress.CANARIES:
                self.assertNotIn(canary.encode(), wire)
        # JSON storage/reload retains only actual ciphertext; no custody or SQL
        # admission is inferred from this serialization round trip.
        self.assertEqual(self.open(json.loads(canonical(first))), self.documents)

    def test_original_seal_window_and_longer_pending_document_expiry_are_distinct(self):
        pair = self.seal()
        seal_end, document_end = self.scope["sealExpiresAtEpochNs"], self.scope["documentExpiresAtEpochNs"]
        self.assertGreater(document_end, seal_end)
        self.seal(now_epoch_ns=seal_end - 1)
        self.refused(lambda: self.seal(now_epoch_ns=seal_end))
        self.assertEqual(self.open(pair, now_epoch_ns=seal_end), self.documents)
        self.assertEqual(self.open(pair, now_epoch_ns=document_end - 1), self.documents)
        self.refused(lambda: self.open(pair, now_epoch_ns=document_end))
        self.refused(lambda: self.open(pair, now_epoch_ns=NOW - 1))
        extended = {**self.scope, "documentExpiresAtEpochNs": document_end + 1}
        self.refused(lambda: self.open(pair, expected_scope=extended))
        shorter = {**self.scope, "sealExpiresAtEpochNs": NOW + SECOND, "documentExpiresAtEpochNs": NOW + 2 * SECOND}
        short_pair = self.seal(scope=shorter)
        self.assertEqual(self.open(short_pair, expected_scope=shorter, now_epoch_ns=NOW + SECOND), self.documents)
        self.refused(lambda: self.open(short_pair, expected_scope=shorter, now_epoch_ns=NOW + 2 * SECOND))

    def test_scope_identity_request_domain_purpose_key_and_lifetime_refusals(self):
        pair = self.seal()
        changes = []
        for name in self.scope:
            value = copy.deepcopy(self.scope)
            value.pop(name)
            changes.append(value)
        changes += [{**self.scope, "extra": None}, {**self.scope, "schema": "other"},
            {**self.scope, "sourceContractDigest": original.sha(b"other contract")},
            {**self.scope, "issuedAtEpochNs": True},
            {**self.scope, "sealExpiresAtEpochNs": NOW},
            {**self.scope, "sealExpiresAtEpochNs": NOW + 30 * SECOND + 1},
            {**self.scope, "documentExpiresAtEpochNs": NOW + 301 * SECOND}]
        for field in ("operation", "handler", "requestDigest", "operationId", "operationManifestDigest"):
            value = copy.deepcopy(self.scope)
            value["publicRequest"][field] = "wrong" if field in {"operation", "handler"} else original.sha(b"wrong")
            changes.append(value)
        for index, value in enumerate(changes):
            with self.subTest(control=index):
                self.refused(lambda: self.seal(scope=value))
        for field in ("controlPlaneConfigurationDigest", "ownerScopeDigest"):
            changed = {**self.scope, field: original.sha(b"different valid pin")}
            self.refused(lambda: self.open(pair, expected_scope=changed))
            altered = {**pair, "scope": changed}
            self.refused(lambda: self.open(altered, expected_scope=changed))
        self.refused(lambda: self.open(pair, key_id="attested-memory-kek:" + "f" * 24))
        self.refused(lambda: self.open(pair, kek=AESGCM(bytes(reversed(KEY)))))
        for key in (None, KEY, object()):
            self.refused(lambda: self.seal(kek=key))
        for label in (None, "", "attested-memory-kek:" + "F" * 24, KEY_ID + "x"):
            self.refused(lambda: self.seal(key_id=label))
        for now in (None, True, float(NOW), 0, 2**63):
            self.refused(lambda: self.seal(now_epoch_ns=now))

    def test_all_private_commitments_and_document_types_are_checked(self):
        for name in self.documents:
            changed = copy.deepcopy(self.documents)
            changed[name] = "changed" if name == "url" else {"changed": True}
            with self.subTest(changed=name):
                self.refused(lambda: self.seal(documents=changed))
        for field in ("url_commitment", "canonical_request_digest", "redacted_display_digest", "original_arguments_digest"):
            # Recompute a coherent public request so refusal is from the
            # private-original join, not merely the outer request hash.
            public, _, _ = ingress.extracted()
            public[field] = original.sha(b"another commitment")
            changed = {**self.scope, "publicRequest": ingress.typed_request(public)}
            self.refused(lambda: self.seal(scope=changed))
        changes = [None, [], {**self.documents, "extra": None}]
        for name in self.documents:
            changes.append({key: value for key, value in self.documents.items() if key != name})
        for name, bad in (("url", b"bytes"), ("url", ""), ("url", "\ud800"),
                ("canonical_request", []), ("redacted_display", None),
                ("redacted_display", {"nan": float("nan")}), ("redacted_display", {"bad": object()})):
            changes.append({**self.documents, name: bad})
        for index, documents in enumerate(changes):
            with self.subTest(control=index):
                self.refused(lambda: self.seal(documents=documents))

    def test_private_size_depth_bounds_and_nonascii_originals(self):
        self.assertEqual(material.MAX_PRIVATE_BYTES, 65536)

        def malformed_leaf_scope(documents):
            # Deliberately NOT an admitted facade input: prepare() correctly
            # refuses these originals first. Make every hash coherent so the
            # independent material size/depth check is the refusal under test.
            raw = {**ingress.raw_arguments(), **documents}
            public = {name: value for name, value in raw.items() if name not in ingress.PRIVATE_FIELDS}
            public.update(schema="catchplate.jitRequestCommitments/v2",
                url_commitment=original.sha(documents["url"].encode("utf-8")),
                canonical_request_digest=original.sha(canonical(documents["canonical_request"])),
                redacted_display_digest=original.sha(canonical(documents["redacted_display"])),
                original_arguments_digest=original.sha(canonical(raw)))
            scope = {**self.scope, "publicRequest": ingress.typed_request(public)}
            self.assertEqual(material.validate_scope(scope), scope)
            return scope

        changed = copy.deepcopy(self.documents)
        changed["canonical_request"] = {"padding": "x" * (33 * 1024)}
        changed["redacted_display"] = {"padding": "y" * (33 * 1024)}
        oversized_scope = malformed_leaf_scope(changed)
        self.refused(lambda: self.seal(scope=oversized_scope, documents=changed))
        deep = {"leaf": "value"}
        for _ in range(18):
            deep = {"nested": deep}
        deep_documents = {**self.documents, "canonical_request": deep}
        deep_scope = malformed_leaf_scope(deep_documents)
        self.refused(lambda: self.seal(scope=deep_scope, documents=deep_documents))
        raw = ingress.raw_arguments()
        raw.update(url="https://synthetic.invalid/\u96ea?value=\U0001f512",
            canonical_request={"empty": {}, "number": 1.25, "flag": True},
            redacted_display={"label": "caf\u00e9\u96ea", "padding": "x" * (30 * 1024)})
        scope, documents = fixture(raw)
        pair = self.seal(scope=scope, documents=documents)
        self.assertEqual(self.open(pair, expected_scope=scope), documents)
        # Preflight bounds without allocating a five-megabyte pair.
        with patch.object(material, "MAX_PAIR_BYTES", len(canonical(pair)) - 1):
            self.refused(lambda: self.open(pair, expected_scope=scope))

    def test_closed_pair_items_and_canonical_padded_encodings(self):
        pair = self.seal()
        changes = [None, [], {**pair, "extra": None}, {**pair, "schema": "other"},
            {**pair, "items": pair["items"][:1]}, {**pair, "items": tuple(pair["items"])},
            {**pair, "items": list(reversed(pair["items"]))},
            {**pair, "items": [pair["items"][0], pair["items"][0]]}]
        for name in pair:
            changes.append({key: value for key, value in pair.items() if key != name})
        for name in ITEM_FIELDS:
            value = copy.deepcopy(pair)
            del value["items"][0][name]
            changes.append(value)
        for name, invalid in (("extra", None), ("opaqueId", "caller-selected"),
                ("valueKind", "approval-review-json/v1"), ("plaintextBytes", True),
                ("plaintextBytes", 0), ("plaintextBytes", material.MAX_PLAINTEXT_BYTES + 1),
                ("plaintextSha256", "sha256:" + "A" * 64)):
            value = copy.deepcopy(pair)
            value["items"][0][name] = invalid
            changes.append(value)
        for field in ("wrappedKeyNonce", "wrappedKey", "ciphertextNonce", "ciphertext"):
            for invalid in (None, "", pair["items"][0][field] + "=", " " + pair["items"][0][field], "+/=="):
                value = copy.deepcopy(pair)
                value["items"][0][field] = invalid
                changes.append(value)
        for index, value in enumerate(changes):
            with self.subTest(control=index):
                self.refused(lambda: self.open(value))
        for item in pair["items"]:
            for field in ("wrappedKeyNonce", "wrappedKey", "ciphertextNonce", "ciphertext"):
                self.assertEqual(encoded(decoded(item[field])), item[field])

    def test_every_aead_component_bitflip_and_cross_document_substitution_refuses(self):
        pair = self.seal()
        for index in range(2):
            for field in ("wrappedKeyNonce", "wrappedKey", "ciphertextNonce", "ciphertext"):
                value = copy.deepcopy(pair)
                data = decoded(value["items"][index][field])
                value["items"][index][field] = encoded(bytes([data[0] ^ 1]) + data[1:])
                with self.subTest(index=index, field=field):
                    self.refused(lambda: self.open(value))
        value = copy.deepcopy(pair)
        value["items"][1]["wrappedKey"] = pair["items"][0]["wrappedKey"]
        self.refused(lambda: self.open(value))
        raw = ingress.raw_arguments()
        raw["redacted_display"] = {"different": "real private original"}
        scope, documents = fixture(raw)
        other = self.seal(scope=scope, documents=documents)
        value = copy.deepcopy(pair)
        value["items"][1] = other["items"][1]
        self.refused(lambda: self.open(value))

    def test_authenticated_but_noncanonical_or_wrong_plaintext_is_not_accepted(self):
        pair = self.seal()
        controls = (b'{"label":"one","label":"two"}', b'{"number":NaN}',
            b'{"number":Infinity}', b'{ "valid":"JSON but noncanonical" }',
            b'[]', b'null', b'{"unexpected":"changed document"}', b'\xff')
        for index, raw in enumerate(controls):
            with self.subTest(control=index):
                self.refused(lambda: self.open(self.forge_plaintext(pair, 1, raw)))
        first = canonical({"schema": "wrong-purpose", "url": self.documents["url"],
            "canonical_request": self.documents["canonical_request"]})
        self.refused(lambda: self.open(self.forge_plaintext(pair, 0, first)))

    def test_ordinary_failures_redact_and_baseexception_cancellation_propagates(self):
        failure = OSError("synthetic " + ingress.CANARIES[0])
        before = copy.deepcopy(self.documents)
        with patch.object(material.os, "urandom", side_effect=failure):
            self.refused(self.seal)
        cancellation = Cancelled("bounded synthetic cancellation")
        with patch.object(material.os, "urandom", side_effect=cancellation):
            with self.assertRaises(Cancelled) as caught:
                self.seal()
            self.assertIs(caught.exception, cancellation)
        self.assertEqual(self.documents, before)


class NativeReleaseJitReviewMaterialTests(unittest.TestCase):
    refused = NativeJitReviewMaterialTests.refused

    def setUp(self):
        self.scope, self.documents, self.parent = release_fixture_values()
        self.kek = AESGCM(KEY)

    def seal(self, scope=_UNSET, documents=_UNSET, **changes):
        return material.seal_release_pair(self.scope if scope is _UNSET else scope,
            self.documents if documents is _UNSET else documents,
            **{"key_id": KEY_ID, "kek": self.kek, "now_epoch_ns": NOW, **changes})

    def open(self, pair, **changes):
        return material.open_release_pair(pair, **{"expected_scope": self.scope,
            "key_id": KEY_ID, "kek": self.kek, "now_epoch_ns": NOW, **changes})

    def test_release_actual_originals_independent_v2_aad_and_owned_roundtrip(self):
        before = canonical([self.scope, self.documents, self.parent])
        pair = self.seal()
        self.assertEqual(pair["schema"], "catchplate.nativeJitReviewPair/v2")
        self.assertEqual(set(pair), {"schema", "scope", "keyId", "items"})
        self.assertEqual(material.validate_release_scope(self.scope), self.scope)
        self.assertEqual(self.scope["parentRequestSha256"], original.sha(canonical(self.parent)))
        self.assertEqual(self.open(pair), self.documents)
        plaintexts = (canonical({"schema": "catchplate.jitCanonicalReviewPayload/v1",
            "url": self.documents["url"], "canonical_request": self.documents["canonical_request"]}),
            canonical(self.documents["redacted_display"]))
        for index, (item, plaintext) in enumerate(zip(pair["items"], plaintexts)):
            self.assertEqual(set(item), ITEM_FIELDS)
            self.assertEqual(item["valueKind"], KINDS[index])
            self.assertEqual(item["opaqueId"], original.identity(self.scope["publicRequest"]["requestDigest"], PURPOSES[index]))
            self.assertEqual((item["plaintextSha256"], item["plaintextBytes"]), (original.sha(plaintext), len(plaintext)))
            dek = self.kek.decrypt(decoded(item["wrappedKeyNonce"]), decoded(item["wrappedKey"]),
                release_aad(self.scope, item, "wrap-dek"))
            self.assertEqual(AESGCM(dek).decrypt(decoded(item["ciphertextNonce"]), decoded(item["ciphertext"]),
                release_aad(self.scope, item, "encrypt-document")), plaintext)
        for canary in release_fixture.CANARIES:
            self.assertNotIn(canary.encode(), canonical(pair))
        opened = self.open(pair)
        opened["canonical_request"]["literal"]["base64Url"] = "mutated returned graph"
        self.assertEqual(self.open(pair), self.documents)
        self.assertEqual(canonical([self.scope, self.documents, self.parent]), before)
        self.assertIsNot(pair["scope"], self.scope)

    def test_v1_and_v2_are_explicit_and_relabeling_never_reencrypts(self):
        v1_scope = {key: value for key, value in self.scope.items() if key != "parentRequestSha256"}
        v1_scope["schema"] = "catchplate.nativeJitReviewScope/v1"
        kwargs = {"key_id": KEY_ID, "kek": self.kek, "now_epoch_ns": NOW}
        v1 = material.seal_pair(v1_scope, self.documents, **kwargs)
        v2 = self.seal()
        self.refused(lambda: material.validate_scope(self.scope))
        self.refused(lambda: material.validate_release_scope(v1_scope))
        self.refused(lambda: material.seal_pair(self.scope, self.documents, **kwargs))
        self.refused(lambda: self.seal(scope=v1_scope))
        self.refused(lambda: material.open_pair(v2, expected_scope=self.scope, **kwargs))
        self.refused(lambda: self.open(v1, expected_scope=v1_scope))
        self.refused(lambda: self.open({**v1, "schema": "catchplate.nativeJitReviewPair/v2", "scope": self.scope}))
        self.refused(lambda: material.open_pair({**v2, "schema": "catchplate.nativeJitReviewPair/v1", "scope": v1_scope},
            expected_scope=v1_scope, **kwargs))
        for index in range(2):
            self.assertEqual(v1["items"][index]["opaqueId"], v2["items"][index]["opaqueId"])
        self.assertEqual(material.open_pair(v1, expected_scope=v1_scope, **kwargs), self.documents)

    def test_parent_hash_and_every_scope_pin_are_aead_bound_not_only_compared(self):
        pair = self.seal()
        changed_raw = release_fixture.native_raw_arguments()
        changed_raw["actor_id"] = "oidc:other-real-parent"
        other_scope, _, _ = release_fixture_values(changed_raw)
        self.assertEqual(other_scope["publicRequest"], self.scope["publicRequest"])
        self.assertNotEqual(other_scope["parentRequestSha256"], self.scope["parentRequestSha256"])
        self.refused(lambda: self.open(pair, expected_scope=other_scope))
        # Both external and embedded scope agree. Only authenticated AAD can
        # distinguish these otherwise valid same-child release parents.
        for field, value in (("parentRequestSha256", other_scope["parentRequestSha256"]),
                ("ownerScopeDigest", original.sha(b"other owner")),
                ("controlPlaneConfigurationDigest", original.sha(b"other config")),
                ("documentExpiresAtEpochNs", self.scope["documentExpiresAtEpochNs"] - SECOND)):
            with self.subTest(field=field):
                scope = {**self.scope, field: value}
                material.validate_release_scope(scope)
                self.refused(lambda: self.open({**pair, "scope": scope}, expected_scope=scope))
        for value in (None, True, "sha256:" + "A" * 64, "f" * 64, original.sha(b"x") + "x"):
            self.refused(lambda: self.seal(scope={**self.scope, "parentRequestSha256": value}))

    def test_release_scope_pair_items_are_closed_and_private_commitments_retained(self):
        pair = self.seal()
        for field in self.scope:
            with self.subTest(scope_missing=field):
                self.refused(lambda: self.seal(scope={k: v for k, v in self.scope.items() if k != field}))
        self.refused(lambda: self.seal(scope={**self.scope, "parentRequest": self.parent}))
        for field in pair:
            with self.subTest(pair_missing=field):
                self.refused(lambda: self.open({k: v for k, v in pair.items() if k != field}))
        self.refused(lambda: self.open({**pair, "extra": None}))
        for field in ITEM_FIELDS:
            value = copy.deepcopy(pair); del value["items"][0][field]
            with self.subTest(item_missing=field): self.refused(lambda: self.open(value))
        for index in range(2):
            for field in ("wrappedKeyNonce", "wrappedKey", "ciphertextNonce", "ciphertext"):
                value = copy.deepcopy(pair); raw = decoded(value["items"][index][field])
                value["items"][index][field] = encoded(bytes([raw[0] ^ 1]) + raw[1:])
                with self.subTest(item=index, corrupted=field): self.refused(lambda: self.open(value))
        self.refused(lambda: self.open({**pair, "items": list(reversed(pair["items"]))}))
        for field in self.documents:
            documents = {**self.documents, field: "changed" if field == "url" else {"changed": True}}
            self.refused(lambda: self.seal(documents=documents))

    def test_release_original_windows_bounds_and_authenticated_wrong_domain(self):
        pair = self.seal()
        seal_end, end = self.scope["sealExpiresAtEpochNs"], self.scope["documentExpiresAtEpochNs"]
        self.seal(now_epoch_ns=seal_end - 1)
        self.refused(lambda: self.seal(now_epoch_ns=seal_end))
        self.assertEqual(self.open(pair, now_epoch_ns=end - 1), self.documents)
        self.refused(lambda: self.open(pair, now_epoch_ns=end))
        for now in (True, float(NOW), 0, NOW - 1, 2**63):
            self.refused(lambda: self.open(pair, now_epoch_ns=now))
        with patch.object(material, "MAX_PAIR_BYTES", len(canonical(pair)) - 1):
            self.refused(lambda: self.open(pair))
        for domain in ("catchplate.nativeJitReviewAad/v1", "catchplate.nativeJitReviewAad/v3"):
            value = copy.deepcopy(pair); item = value["items"][0]
            wrong_aad = json.loads(release_aad(self.scope, item, "wrap-dek")); wrong_aad["schema"] = domain
            item["wrappedKey"] = encoded(self.kek.encrypt(decoded(item["wrappedKeyNonce"]), b"d" * 32, canonical(wrong_aad)))
            self.refused(lambda: self.open(value))


if __name__ == "__main__":
    unittest.main(verbosity=2)
