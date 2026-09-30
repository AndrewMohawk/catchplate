#!/usr/bin/env python3
"""Synthetic wire-shape controls; publication is not signature authentication.

The envelope signatures use deterministic in-memory TEST keys and the existing
signature preimages. Nested runtime/history/grant objects are labelled shape
fixtures, not authorities, resources or provenance. These tests call only pure
shape/original helpers: no issuer, owner, protected file or service is invoked.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))
from serverware import native_pilot_generation_install_authority as generation
from serverware import native_pilot_native_service_authority as native
from serverware import native_pilot_publication_profiles as publication
from test_native_pilot_closure_set import canonical, sha, synthetic
from test_native_pilot_generation_scope import encoded, key_fixture, signed_message

ROLES = ("durable-recovery-store", "cleanup-authorization-consumer", "recovery-target-provider",
    "current-signature-authority", "bounded-cleanup-helper")
# Independent literal wire table: operation, API stem, first version, purpose.
PROFILES = (
    ("commitRequest", "nativeShadowCommitRequestServiceAssignment", 1, "native-shadow-ledger-commit-request"),
    ("ingress", "nativeShadowIngressServiceAssignment", 1, "native-first-ingress"),
    ("ledger", "nativeShadowLedgerSpoolServiceAssignment", 2, "native-ledger-spool-and-sampling-with-unavailability"),
    ("terminal", "nativeShadowTerminalSpoolServiceAssignment", 1, "native-terminal-slot-append"),
    ("dispatchBarrier", "nativeShadowDispatchBarrierServiceAssignment", 1, "native-dispatch-barrier"),
    ("activeEffectBarrier", "nativeShadowActiveEffectBarrierServiceAssignment", 1, "native-active-effect-barrier"),
    ("activeEffectCommit", "nativeShadowActiveEffectCommitServiceAssignment", 1, "native-active-effect-commit"),
)
COMMON_FIELDS = ("apiVersion", "purpose", "guest", "assignmentPayloadSha256", "keyAuthorizationSha256",
    "trustCheckpointId", "revocationGeneration", "revocationRootSha256", "issuedAtUnixNanos", "expiresAtUnixNanos",
    "signingKeyId", "signingKeySpkiSha256")
NATIVE_ROW = ("generationGrantOriginal", "runtimeOriginal", "historyOriginal", "rootKeyId", "rootKeySpkiSha256")
GENERATION_ROW = ("grantOriginal", "historyOriginal", "rootKeyId", "rootKeySpkiSha256")
LEGACY_MAX = 65536
SUCCESSOR_MAX = 4 * 1024 * 1024


def original(role, kind):
    value = {"syntheticShapeOnly": True, "role": role, "kind": kind}
    if kind == "runtime":
        value["runtime"] = {"authorityHistoryRootKeyId": synthetic(role + "/root-id"),
            "authorityHistoryRootKeySpkiSha256": synthetic(role + "/root-spki")}
    return canonical(value).decode("ascii")


def common():
    public = key_fixture("history-grant-shape-only")[1]
    guest = {"configurationSha256": synthetic("cold"), "deliverySha256": synthetic("C9"),
        "runtimeConfigurationSha256": synthetic("marker"), "serviceRole": "production-bridge",
        "uid": 62001, "gid": 62001, "bootIdBase64url": encoded(b"0123456789abcdef"),
        "timeNamespaceDevice": 4, "timeNamespaceInode": 5, "issuedAtBoottimeNs": "1000",
        "startupDeadlineBoottimeNs": "2000", "lifetimeDeadlineBoottimeNs": "3000", "invocationId": "1" * 32}
    return {"guest": guest, "assignmentPayloadSha256": synthetic("assignment"),
        "keyAuthorizationSha256": synthetic("role-key"), "trustCheckpointId": synthetic("trust"),
        "revocationGeneration": 1, "revocationRootSha256": synthetic("revocation"),
        "issuedAtUnixNanos": 1000, "expiresAtUnixNanos": 2000,
        "signingKeyId": public["keyId"], "signingKeySpkiSha256": public["keySpkiSha256"]}


def native_payload(operation, *, successor):
    _, stem, old, purpose = next(row for row in PROFILES if row[0] == operation)
    version = old + int(successor)
    value = common() | {"apiVersion": "serverware." + stem + "/v" + str(version),
        "purpose": purpose, "scope": {"syntheticShapeOnly": True}, "expectedPeer": {"syntheticShapeOnly": True}}
    if operation != "commitRequest":
        value.update(proofScopeOriginal=original(operation, "proof"),
            originVerifier={"syntheticShapeOnly": True}, commitRequest=None)
    if successor:
        value["ordinaryServices"] = {role: {
            "generationGrantOriginal": original(role, "generation"), "runtimeOriginal": original(role, "runtime"),
            "historyOriginal": original(role, "history"), "rootKeyId": synthetic(role + "/root-id"),
            "rootKeySpkiSha256": synthetic(role + "/root-spki")} for role in ROLES}
    return value, "serverware." + stem + ".signature/v" + str(version)


def generation_payload(*, successor):
    version = 2 if successor else 1
    rows = {role: {"grantOriginal": original(role, "generation"), "historyOriginal": original(role, "history"),
        "rootKeyId": synthetic(role + "/root-id"), "rootKeySpkiSha256": synthetic(role + "/root-spki")}
        for role in ROLES}
    if successor:
        for role, row in rows.items():
            row["runtimeOriginal"] = original(role, "runtime")
    value = common() | {"apiVersion": "serverware.nativeGenerationCoordinatorAssignment/v" + str(version),
        "purpose": "native-generation-installation", "services": rows,
        "keyHistory": {"currentKeyEpoch": 1, "predecessors": []},
        "journal": {"genesisSha256": synthetic("genesis"), "sequence": 0, "headSha256": synthetic("genesis")},
        "expectedPeer": {"syntheticShapeOnly": True}}
    return value, "serverware.nativeGenerationCoordinatorAssignment.signature/v" + str(version)


def signed(value, domain):
    key = key_fixture("history-grant-shape-only")[0]
    signature = key.sign(signed_message(domain, value))
    return canonical({"payload": value, "signature": encoded(signature)})


def padded(value, domain, size):
    """Exact byte boundary fixture; no authority data or live scope is implied."""
    value = copy.deepcopy(value)
    # Both families have this existing field; its semantics are deliberately
    # outside the shape-only verifier exercised here.
    value["expectedPeer"] = {"syntheticShapePadding": ""}
    gap = size - len(signed(value, domain))
    if gap < 0:
        raise AssertionError("fixture size is below its original")
    value["expectedPeer"]["syntheticShapePadding"] = "x" * gap
    raw = signed(value, domain)
    if len(raw) != size:
        raise AssertionError("fixture did not reach exact byte boundary")
    return raw


class HistoryGrantShapeTests(unittest.TestCase):
    def accepted(self, operation, raw):
        if operation == "generationInstall":
            value = generation.grant_original(raw)
            publication.shape("native-generation-install-grant", raw)
        else:
            value = native.grant_original(operation, raw)
            publication.shape("native-service-" + operation, raw)
        self.assertEqual(canonical(value), raw)
        return value

    def refused(self, operation, raw):
        methods = ((lambda: generation.grant_original(raw)),
            (lambda: publication.shape("native-generation-install-grant", raw))) if operation == "generationInstall" else (
            (lambda: native.grant_original(operation, raw)),
            (lambda: publication.shape("native-service-" + operation, raw)))
        for method in methods:
            with self.assertRaises(ValueError):
                method()

    def test_all_seven_native_versions_have_exact_domains_and_fields(self):
        self.assertEqual(tuple(native.HISTORY_OPERATIONS), tuple(row[0] for row in PROFILES))
        for operation, _, _, _ in PROFILES:
            for successor in (False, True):
                with self.subTest(operation=operation, successor=successor):
                    payload, domain = native_payload(operation, successor=successor)
                    fields = COMMON_FIELDS + ("scope", "expectedPeer")
                    if operation != "commitRequest":
                        fields += ("proofScopeOriginal", "originVerifier", "commitRequest")
                    if successor:
                        fields += ("ordinaryServices",)
                        self.assertEqual(set(payload["ordinaryServices"]), set(ROLES))
                        self.assertTrue(all(set(row) == set(NATIVE_ROW) for row in payload["ordinaryServices"].values()))
                    self.assertEqual(set(payload), set(fields))
                    self.assertEqual(native.grant_shape(operation, payload), domain)
                    parsed = self.accepted(operation, signed(payload, domain))
                    key_fixture("history-grant-shape-only")[0].public_key().verify(
                        native.p.decoded(parsed["signature"], size=64), signed_message(domain, parsed["payload"]))

    def test_generation_install_versions_preserve_distinct_four_and_five_field_rows(self):
        for successor in (False, True):
            payload, domain = generation_payload(successor=successor)
            self.assertEqual(generation.grant_shape(payload), domain)
            self.assertEqual(set(payload["services"]), set(ROLES))
            fields = GENERATION_ROW + (("runtimeOriginal",) if successor else ())
            self.assertTrue(all(set(row) == set(fields) for row in payload["services"].values()))
            self.accepted("generationInstall", signed(payload, domain))

    def test_native_null_missing_mixed_and_unknown_successors_refused(self):
        for operation, _, _, _ in PROFILES:
            modern, domain = native_payload(operation, successor=True)
            legacy, old_domain = native_payload(operation, successor=False)
            cases = []
            for api in (None, legacy["apiVersion"], modern["apiVersion"].rsplit("/v", 1)[0] + "/v99"):
                cases.append(modern | {"apiVersion": api})
            cases.extend((modern | {"ordinaryServices": None}, modern | {"purpose": "unapproved-purpose"},
                legacy | {"ordinaryServices": None}, legacy | {"ordinaryServices": modern["ordinaryServices"]}))
            missing = copy.deepcopy(modern); del missing["ordinaryServices"]; cases.append(missing)
            for payload in cases:
                self.refused(operation, signed(payload, domain))
            self.assertNotEqual(domain, old_domain)

    def test_generation_install_missing_runtime_and_cross_version_rows_refused(self):
        modern, domain = generation_payload(successor=True)
        legacy, _ = generation_payload(successor=False)
        for role in ROLES:
            for value in (None, "not-json"):
                payload = copy.deepcopy(modern); payload["services"][role]["runtimeOriginal"] = value
                self.refused("generationInstall", signed(payload, domain))
            payload = copy.deepcopy(modern); del payload["services"][role]["runtimeOriginal"]
            self.refused("generationInstall", signed(payload, domain))
        for payload in (modern | {"apiVersion": legacy["apiVersion"]}, legacy | {"apiVersion": modern["apiVersion"]},
                modern | {"apiVersion": None}, modern | {"apiVersion": "serverware.nativeGenerationCoordinatorAssignment/v3"}):
            self.refused("generationInstall", signed(payload, domain))

    def test_complete_role_maps_and_exact_rows_are_required(self):
        for operation in tuple(row[0] for row in PROFILES) + ("generationInstall",):
            payload, domain = generation_payload(successor=True) if operation == "generationInstall" else native_payload(operation, successor=True)
            field = "services" if operation == "generationInstall" else "ordinaryServices"
            for role in ROLES:
                changed = copy.deepcopy(payload); del changed[field][role]
                self.refused(operation, signed(changed, domain))
            for name, value in (("unknown-service", {}),):
                changed = copy.deepcopy(payload); changed[field][name] = value
                self.refused(operation, signed(changed, domain))
            for name, value in (("extra", None), ("rootKeyId", "sha256:" + "0" * 64), ("historyOriginal", "{}\n")):
                changed = copy.deepcopy(payload); changed[field][ROLES[0]][name] = value
                self.refused(operation, signed(changed, domain))

    def test_legacy_native_64k_limit_is_not_silently_expanded(self):
        for operation, _, _, _ in PROFILES:
            legacy, domain = native_payload(operation, successor=False)
            self.accepted(operation, padded(legacy, domain, LEGACY_MAX))
            self.refused(operation, padded(legacy, domain, LEGACY_MAX + 1))
            modern, domain = native_payload(operation, successor=True)
            self.accepted(operation, padded(modern, domain, LEGACY_MAX + 1))

    def test_generation_legacy64k_and_both_successor4m_limits(self):
        legacy, domain = generation_payload(successor=False)
        self.accepted("generationInstall", padded(legacy, domain, LEGACY_MAX))
        self.refused("generationInstall", padded(legacy, domain, LEGACY_MAX + 1))
        for operation in ("commitRequest", "generationInstall"):
            payload, domain = generation_payload(successor=True) if operation == "generationInstall" else native_payload(operation, successor=True)
            self.accepted(operation, padded(payload, domain, SUCCESSOR_MAX))
            self.refused(operation, padded(payload, domain, SUCCESSOR_MAX + 1))

    def test_nested_public_original_limits_and_canonicality(self):
        for operation in ("commitRequest", "generationInstall"):
            payload, domain = generation_payload(successor=True) if operation == "generationInstall" else native_payload(operation, successor=True)
            field = "services" if operation == "generationInstall" else "ordinaryServices"
            grant_name = "grantOriginal" if operation == "generationInstall" else "generationGrantOriginal"
            for name, limit in ((grant_name, LEGACY_MAX), ("historyOriginal", 1024 * 1024)):
                changed = copy.deepcopy(payload)
                skeleton = canonical({"syntheticShapePadding": ""})
                changed[field][ROLES[0]][name] = canonical({"syntheticShapePadding": "x" * (limit - len(skeleton))}).decode("ascii")
                self.accepted(operation, signed(changed, domain))
                changed[field][ROLES[0]][name] = canonical({"syntheticShapePadding": "x" * (limit + 1 - len(skeleton))}).decode("ascii")
                self.refused(operation, signed(changed, domain))

    def test_literal_canonical_bytes_and_signature_shape_not_authority(self):
        for operation in ("commitRequest", "generationInstall"):
            payload, domain = generation_payload(successor=True) if operation == "generationInstall" else native_payload(operation, successor=True)
            raw = signed(payload, domain)
            for broken in (raw + b"\n", b" " + raw, raw[:-1] + b',"signature":"duplicate"}'):
                self.refused(operation, broken)
            envelope = json.loads(raw)
            for bad in (None, "AA", "not+base64"):
                self.refused(operation, canonical(envelope | {"signature": bad}))
            altered = canonical(envelope | {"signature": encoded(bytes(64))})
            self.accepted(operation, altered)  # Explicitly a shape check, not authority.
            self.assertNotEqual(sha(raw), sha(altered))
            with self.assertRaises(InvalidSignature):
                key_fixture("history-grant-shape-only")[0].public_key().verify(bytes(64), signed_message(domain, payload))

    def test_native_member_join_retains_exact_runtime_history_and_grant_bytes(self):
        for operation, _, _, _ in PROFILES:
            payload, _ = native_payload(operation, successor=True)
            for role in ROLES:
                row = payload["ordinaryServices"][role]
                values = {"runtime_raw": row["runtimeOriginal"].encode("ascii"),
                    "history_raw": row["historyOriginal"].encode("ascii"),
                    "generation_raw": row["generationGrantOriginal"].encode("ascii")}
                native.require_ordinary_member(payload, role, **values)
                for name in values:
                    changed = values | {name: canonical({"syntheticDifferentOriginal": True})}
                    with self.assertRaises(ValueError):
                        native.require_ordinary_member(payload, role, **changed)
                changed = copy.deepcopy(payload)
                changed["ordinaryServices"][role]["rootKeyId"] = synthetic("different-root")
                with self.assertRaises(ValueError):
                    native.require_ordinary_member(changed, role, **values)


if __name__ == "__main__":
    unittest.main()
