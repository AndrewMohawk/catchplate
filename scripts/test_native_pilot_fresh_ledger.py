#!/usr/bin/env python3
"""Bounded synthetic wire controls, not receipts, approval, or runtime evidence.

No keys or signatures are generated, no signer is called, and no protected
file, service, database, or application is opened. Labelled object bytes test
only the existing immutable-object grammar; they do not describe a real event.
The empty v2 manifest authorizes nothing by itself. Native grant, genesis,
actual empty-directory, and live-owner admission remain separate requirements.
"""
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_policy_canary_native_opening as opening
from catchplate import native_pilot_assignment as assignment
from catchplate import native_pilot_native_service_authority as service
from catchplate import native_shadow_retrieval_artifacts as retrieval
from catchplate import policy_shadow_assignment_fields as fields

LEGACY_FIELDS = (
    "assignmentId", "canaryId", "assignmentRevision", "generationEpoch",
    "minimumGenerationTombstoneEpoch", "policyIdentity", "expectedLoadedSnapshots",
    "responseValidationObligations", "responseValidationObligationsRootSha256",
    "fleet", "observationWindow", "readinessThresholds", "issuedAtUnixNanos", "expiresAtUnixNanos",
)
SCOPE_VALUES = (
    "assignment_id", "assignment_payload_sha256", "assignment_revision", "authority_id",
    "storage_realm_sha256", "retrieval_namespace_sha256", "authority_key_independence_sha256",
    "production_configuration_binding_sha256", "asserted_custody_key_set_root_sha256",
    "execution_closure_manifest_sha256", "structurally_verified_seccomp_policy_sha256",
)
SET_VALUES = ("execution_closure_set_root_sha256", "structurally_verified_seccomp_set_root_sha256")
V1 = "catchplate.nativeShadowRetrievalStoreManifest/v1"
V2 = "catchplate.nativeShadowRetrievalStoreManifest/v2"
INPUT_FIELDS = ("apiVersion", "operation", "configurationOriginal", "configurationSha256",
    "assignmentPayloadOriginal", "cohortConfigurationOriginal", "precreationOriginal", "observationOriginal",
    "coldConfigurationOriginal", "deliveryOriginal", "runtimeOriginal", "peerOriginal", "peerSha256",
    "issuedAtUnixNanos", "expiresAtUnixNanos", "spoolScopeOriginal", "proofScopeOriginal",
    "endpointDeliveryResultOriginal", "nativeGrantOriginals")
GRANT_FIELDS = ("apiVersion", "purpose", "guest", "assignmentPayloadSha256", "keyAuthorizationSha256",
    "trustCheckpointId", "revocationGeneration", "revocationRootSha256", "issuedAtUnixNanos",
    "expiresAtUnixNanos", "signingKeyId", "signingKeySpkiSha256", "proofScopeOriginalBase64url",
    "expectedPeer", "spoolScope", "ingress", "ledger", "store", "terminal", "effects")


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def labelled(name):
    return sha(("SYNTHETIC WIRE CONTROL ONLY / " + name).encode("ascii"))


def encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def scope_original(version):
    value = {name: labelled(name) for name in SCOPE_VALUES}
    value["assignment_revision"] = 1
    domain = "catchplate.policyShadowProductionCustodyProofScope/v" + str(version)
    selected = SCOPE_VALUES
    if version == 2:
        value["api_version"] = domain
        value.update({name: labelled(name) for name in SET_VALUES})
        selected += SET_VALUES
    for name, role in (("store_response_authority", "custody-store-response"),
                       ("retrieval_response_authority", "custody-retrieval-response")):
        value[name] = {"role": role, **{field: labelled(role + "/" + field)
            for field in ("key_id", "key_spki_sha256", "key_material_sha256")}}
    body = canonical([value[name] for name in selected])
    value["binding_sha256"] = sha(domain.encode("ascii") + b"\0" + len(body).to_bytes(8, "big") + body)
    return canonical(value)


def synthetic_object(scope_raw):
    scope = json.loads(scope_raw)
    # This deliberately is not an operational custody event or a signed receipt.
    receipt = canonical({"syntheticWireControlOnly": True})
    domain = "catchplate.policyShadowAssignmentBoundCustodyReceipt/v"
    successor = "api_version" in scope
    authority = [domain + ("2" if successor else "1"), scope["binding_sha256"],
        scope["execution_closure_manifest_sha256"], scope["structurally_verified_seccomp_policy_sha256"]]
    if successor:
        authority.extend(scope[name] for name in SET_VALUES)
    authority.extend(("ingress-admission", sha(receipt)))
    return retrieval.object_original(scope_raw, "ingress-admission", receipt, canonical(authority))


class FreshLedgerManifestTests(unittest.TestCase):
    def setUp(self):
        self.scope = scope_original(2)
        self.fresh = retrieval.fresh_ledger_manifest_original(self.scope)

    def assert_rejected(self, value):
        raw = canonical(value)
        for helper in (retrieval.manifest_objects, retrieval.manifest_initialization):
            with self.subTest(helper=helper.__name__), self.assertRaises(ValueError):
                helper(raw, sha(raw))

    def test_legacy_manifest_still_requires_nonempty_objects(self):
        for version in (1, 2):
            with self.subTest(scope_version=version):
                scope = scope_original(version)
                obj = synthetic_object(scope)
                raw = retrieval.manifest_original(scope, [obj])
                self.assertEqual(json.loads(raw)["apiVersion"], V1)
                self.assertIsNone(retrieval.manifest_initialization(raw, sha(raw)))
                self.assertEqual([item[1] for item in retrieval.manifest_objects(raw, sha(raw))], [obj])
                with self.assertRaises(ValueError):
                    retrieval.manifest_original(scope, [])
                empty = json.loads(raw)
                empty["objectOriginalsBase64url"] = []
                self.assert_rejected(empty)

    def test_fresh_v2_exact_empty_shape_and_explicit_mode(self):
        self.assertEqual(self.fresh, canonical({"apiVersion": V2,
            "proofScopeOriginalBase64url": encoded(self.scope),
            "initialization": "fresh-ledger", "objectOriginalsBase64url": []}))
        self.assertEqual(retrieval.manifest_objects(self.fresh, sha(self.fresh)), [])
        self.assertEqual(retrieval.manifest_initialization(self.fresh, sha(self.fresh)), "fresh-ledger")

    def test_initialization_missing_null_unknown_or_wrong_type_rejected(self):
        original = json.loads(self.fresh)
        missing = copy.deepcopy(original)
        del missing["initialization"]
        self.assert_rejected(missing)
        for mode in (None, "", "existing-ledger", "fresh-ledger ", True, 0, []):
            with self.subTest(initialization=mode):
                value = copy.deepcopy(original)
                value["initialization"] = mode
                self.assert_rejected(value)

    def test_mixed_versions_and_legacy_scope_rejected(self):
        with self.assertRaises(ValueError):
            retrieval.fresh_ledger_manifest_original(scope_original(1))
        original = json.loads(self.fresh)
        for api in (V1, "catchplate.nativeShadowRetrievalStoreManifest/v3", None):
            with self.subTest(api=api):
                value = copy.deepcopy(original)
                value["apiVersion"] = api
                self.assert_rejected(value)
        value = copy.deepcopy(original)
        value["proofScopeOriginalBase64url"] = encoded(scope_original(1))
        self.assert_rejected(value)
        legacy = json.loads(retrieval.manifest_original(self.scope, [synthetic_object(self.scope)]))
        for mode in (None, "fresh-ledger"):
            with self.subTest(legacy_initialization=mode):
                value = copy.deepcopy(legacy)
                value["initialization"] = mode
                self.assert_rejected(value)

    def test_fresh_manifest_forbids_objects_null_and_nonlist_inventory(self):
        for objects in ([encoded(synthetic_object(self.scope))], None, {}, "", False):
            with self.subTest(objects=objects):
                value = json.loads(self.fresh)
                value["objectOriginalsBase64url"] = objects
                self.assert_rejected(value)

    def test_literal_pin_canonicality_duplicates_and_extra_fields_rejected(self):
        for helper in (retrieval.manifest_objects, retrieval.manifest_initialization):
            with self.subTest(helper=helper.__name__), self.assertRaises(ValueError):
                helper(self.fresh, labelled("incorrect-manifest-pin"))
            duplicate = self.fresh[:-1] + b',"initialization":"fresh-ledger"}'
            for raw in (self.fresh + b"\n", b" " + self.fresh, duplicate):
                with self.subTest(helper=helper.__name__, wire=raw[-48:]), self.assertRaises(ValueError):
                    helper(raw, sha(raw))
        extra = json.loads(self.fresh)
        extra["serviceReady"] = True
        self.assert_rejected(extra)


class FreshLedgerGrantSelectionTests(unittest.TestCase):
    def input_fixture(self, version):
        # Unrelated fields are intentionally not complete authorities: these
        # controls call only the issuer's pure shape/profile gate, never sign().
        value = dict.fromkeys(INPUT_FIELDS, "SYNTHETIC SHAPE ONLY")
        value.update(apiVersion="catchplate.nativePilotNativeServiceAuthorityInput/v" + str(version),
            operation="retrieval", proofScopeOriginal=scope_original(2).decode("ascii"))
        if version == 2:
            value["retrievalManifestOriginal"] = retrieval.fresh_ledger_manifest_original(
                scope_original(2)).decode("ascii")
        return value

    def grant_fixture(self, version):
        # No signature or independently approved guest/key is manufactured.
        value = dict.fromkeys(GRANT_FIELDS, "SYNTHETIC SHAPE ONLY")
        value.update(apiVersion="catchplate.nativeLedgerSpoolRetrievalGrant/v" + str(version),
            purpose="native-ledger-spool-retrieval", proofScopeOriginalBase64url=encoded(scope_original(2)),
            store={"genesisSha256": labelled("genesis-pin-only"), "sequence": 0,
                "headSha256": labelled("genesis-pin-only")}, terminal={},
            effects={name: {} for name in ("dispatchBarrier", "activeEffectBarrier", "activeEffectCommit")})
        if version == 4:
            value["initialization"] = "fresh-ledger"
        return value

    def test_exact_legacy_and_fresh_input_selection(self):
        for version in (1, 2):
            value = self.input_fixture(version)
            admitted, fresh = service.input_shape("retrieval", canonical(value))
            self.assertEqual(admitted, value)
            self.assertIs(fresh, version == 2)
            self.assertEqual(len(admitted), 19 if version == 1 else 20)

    def test_input_mixed_versions_manifest_scope_and_operation_rejected(self):
        base = self.input_fixture(2)
        mutations = []
        for api in ("catchplate.nativePilotNativeServiceAuthorityInput/v1",
                    "catchplate.nativePilotNativeServiceAuthorityInput/v3", None):
            mutations.append({**base, "apiVersion": api})
        for key in ("apiVersion", "retrievalManifestOriginal"):
            value = copy.deepcopy(base)
            del value[key]
            mutations.append(value)
        mutations.extend(({**base, "retrievalManifestOriginal": None},
            {**base, "operation": "persistence"},
            {**base, "proofScopeOriginal": scope_original(1).decode("ascii")},
            {**base, "retrievalManifestOriginal": retrieval.manifest_original(
                scope_original(2), [synthetic_object(scope_original(2))]).decode("ascii")}))
        different = json.loads(scope_original(2))
        different["retrieval_namespace_sha256"] = labelled("different-namespace")
        body = canonical([different[name] for name in SCOPE_VALUES + SET_VALUES])
        different["binding_sha256"] = sha(different["api_version"].encode("ascii")
            + b"\0" + len(body).to_bytes(8, "big") + body)
        mutations.append({**base, "retrievalManifestOriginal":
            retrieval.fresh_ledger_manifest_original(canonical(different)).decode("ascii")})
        for index, value in enumerate(mutations):
            with self.subTest(case=index), self.assertRaises(ValueError):
                service.input_shape("retrieval", canonical(value))
        for operation in ("persistence", "trustedTime", "ingress"):
            with self.subTest(nonretrieval=operation), self.assertRaises(ValueError):
                service.input_shape(operation, canonical({**base, "operation": operation}))

    def test_exact_v3_v4_grant_domains_and_cardinality(self):
        for version in (3, 4):
            value = self.grant_fixture(version)
            self.assertEqual(len(value), 20 if version == 3 else 21)
            self.assertEqual(service.grant_shape("retrieval", value),
                "catchplate.nativeLedgerSpoolRetrievalGrant.signature/v" + str(version))
        self.assertNotEqual(service.grant_shape("retrieval", self.grant_fixture(3)),
            service.grant_shape("retrieval", self.grant_fixture(4)))

    def test_grant_explicit_version_initialization_and_role_reject_mixing(self):
        base = self.grant_fixture(4)
        mutations = []
        for mode in (None, "", "existing-ledger", True, 0):
            mutations.append({**base, "initialization": mode})
        for key in ("initialization", "apiVersion"):
            value = copy.deepcopy(base)
            del value[key]
            mutations.append(value)
        for api in ("catchplate.nativeLedgerSpoolRetrievalGrant/v3",
                    "catchplate.nativeLedgerSpoolRetrievalGrant/v5", None):
            mutations.append({**base, "apiVersion": api})
        mutations.append({**base, "purpose": "native-shadow-receipt-persistence"})
        for mode in (None, "fresh-ledger"):
            mutations.append({**self.grant_fixture(3), "initialization": mode})
        for index, value in enumerate(mutations):
            with self.subTest(case=index), self.assertRaises(ValueError):
                service.grant_shape("retrieval", value)
        for operation in ("persistence", "trustedTime", "ingress"):
            with self.subTest(nonretrieval=operation), self.assertRaises(ValueError):
                service.grant_shape(operation, base)

    def test_fresh_grant_requires_v2_zero_head_and_all_effect_slots(self):
        base = self.grant_fixture(4)
        mutations = [{**base, "proofScopeOriginalBase64url": encoded(scope_original(1))},
            {**base, "terminal": None}, {**base, "terminal": []}, {**base, "effects": None}]
        for sequence in (1, -1, False, True, "0", None):
            mutations.append({**base, "store": {**base["store"], "sequence": sequence}})
        for key in ("genesisSha256", "sequence", "headSha256"):
            store = dict(base["store"])
            del store[key]
            mutations.append({**base, "store": store})
        mutations.extend(({**base, "store": {**base["store"], "headSha256": labelled("different-head")}},
            {**base, "store": {**base["store"], "genesisSha256": "sha256:" + "0" * 64}},
            {**base, "store": {**base["store"], "extra": 0}}))
        for name in ("dispatchBarrier", "activeEffectBarrier", "activeEffectCommit"):
            effects = dict(base["effects"])
            del effects[name]
            mutations.append({**base, "effects": effects})
        for index, value in enumerate(mutations):
            with self.subTest(case=index), self.assertRaises(ValueError):
                service.grant_shape("retrieval", value)


class AssignmentFieldIsolationTests(unittest.TestCase):
    def assert_no_database_or_application(self):
        self.assertNotIn("catchplate.db", sys.modules)
        self.assertNotIn("catchplate.app", sys.modules)
        self.assertFalse(any(name == "catchplate.authority_store" or name.startswith("catchplate.authority_store.")
            for name in sys.modules))

    def test_exact_shared_legacy_and_native_fields_are_pure(self):
        self.assertEqual(fields.LEGACY_FIELDS, LEGACY_FIELDS)
        expected = LEGACY_FIELDS[:10] + ("custodyAuthority", "authorityKeyIndependence") + LEGACY_FIELDS[10:]
        self.assertEqual(fields.NATIVE_FIELDS, expected)
        self.assertIs(assignment.NATIVE_FIELDS, fields.NATIVE_FIELDS)
        self.assertEqual((len(set(fields.LEGACY_FIELDS)), len(set(fields.NATIVE_FIELDS))), (14, 16))
        tree = ast.parse((ROOT / "catchplate/policy_shadow_assignment_fields.py").read_text(encoding="utf-8"))
        self.assertFalse(any(isinstance(node, (ast.Import, ast.ImportFrom, ast.Call)) for node in ast.walk(tree)))
        self.assert_no_database_or_application()

    def test_actual_assignment_shape_helpers_do_not_load_database(self):
        self.assert_no_database_or_application()
        legacy = dict.fromkeys(LEGACY_FIELDS, "synthetic shape-only value")
        native = {**legacy, "custodyAuthority": {}, "authorityKeyIndependence": {}}
        successor = {**native, "nativeClosureSet": {"setRootSha256": labelled("closure-set"),
            "seccompSetRootSha256": labelled("seccomp-set")}}
        for version, payload in ((1, legacy), (1, native), (2, successor)):
            self.assertEqual(opening.assignment_fields(payload, version=version), frozenset(payload))
        for version, payload in ((1, successor), (2, legacy), (2, native),
                                 (2, {**native, "nativeClosureSet": None})):
            with self.subTest(version=version, fields=tuple(payload)), self.assertRaises(ValueError):
                opening.assignment_fields(payload, version=version)
        for version, payload in ((1, native), (2, successor)):
            domain = "catchplate.policyShadowAssignment/v" + str(version)
            envelope = {"apiVersion": domain, "kind": "PolicyShadowAssignment",
                "canonicalProfile": "catchplate.canonicalJson/ascii-integer-v1", "signatureDomain": domain,
                "payload": payload, "payloadSha256": sha(canonical(payload)), "signatureAlgorithm": "Ed25519",
                "signingKeyId": labelled("invalid-test-key-id"), "signingKeySpkiSha256": labelled("invalid-test-spki"),
                "signature": "A" * 86}  # Invalid zero sentinel: never signed or signature-verified.
            self.assertIs(assignment.shape(envelope), envelope)
        self.assert_no_database_or_application()

    def test_db_legacy_mapping_reuses_shared_constant_without_importing_db(self):
        tree = ast.parse((ROOT / "catchplate/db.py").read_text(encoding="utf-8"))
        shared = [node for node in tree.body if isinstance(node, ast.ImportFrom)
            and node.module == "catchplate.policy_shadow_assignment_fields"]
        aliases = [alias.asname or alias.name for node in shared for alias in node.names if alias.name == "LEGACY_FIELDS"]
        self.assertEqual(len(aliases), 1)
        mappings = [node.value for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "_POLICY_SHADOW_DIRECT_PAYLOAD_FIELDS"
                for target in node.targets)]
        self.assertEqual(len(mappings), 1)
        self.assertIsInstance(mappings[0], ast.Dict)
        values = [value for key, value in zip(mappings[0].keys, mappings[0].values)
            if isinstance(key, ast.Constant) and key.value == "canary_assignment"]
        self.assertEqual(len(values), 1)
        self.assertEqual(ast.dump(values[0], include_attributes=False), ast.dump(ast.Call(
            func=ast.Name(id="frozenset", ctx=ast.Load()),
            args=[ast.Name(id=aliases[0], ctx=ast.Load())], keywords=[]), include_attributes=False))
        self.assert_no_database_or_application()


if __name__ == "__main__":
    unittest.main(verbosity=2)
