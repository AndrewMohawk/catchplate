#!/usr/bin/env python3
"""Opening wire/reviewer/effects components, not admitted-root or commit proof.

Real signatures, request construction and pending projection run locally.
Reviewer and mutation tests explicitly supply synthetic selected rows to private
computations; they do not replace the public entrypoint's native/current-root
verification with a successful mock. No SQL, hardware, disclosure or provider.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_violations = []


def no_external_effects(event, _arguments):
    if event.startswith(("socket.", "sqlite3.")) or event in {
            "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
        _violations.append(event)
        raise AssertionError("opening components forbid external effects")


if __name__ == "__main__":
    os.environ["CATCHPLATE_PROCESS_MODE"] = "metadata-bootstrap"
    os.environ["CATCHPLATE_RELEASE_CHANNEL"] = "dev"
    sys.addaudithook(no_external_effects)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import test_authority_audit_capacity as counters
from scripts import test_authority_native_jit_pending as pending_fixture
from scripts import test_authority_native_jit_retained_history as old_fixture
from scripts import test_authority_native_jit_review_custody as crypto
from catchplate import authority_contract as authority
from catchplate import authority_audit_capacity as capacity
from catchplate import authority_native_jit_retained_history as history
from catchplate import authority_native_jit_review_open_contract as wire
from catchplate import authority_release_private_request as private
from catchplate import authority_successor_programs as programs
from catchplate import authority_transition_core as core
from catchplate import authority_transition_native_jit_review_open as kernel
from catchplate import authority_transition_quota as quota
from catchplate import authority_transition_registry as registry
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

NOW = 1_800_000_000_000_000_000
SECOND = 1_000_000_000
STAMP = datetime.fromtimestamp(NOW // SECOND, timezone.utc)
TOKEN = b"a" * 64
DIGEST = "sha256:" + "1" * 64
OTHER = "sha256:" + "2" * 64
canonical, sha, encoded = crypto.canonical, crypto.sha256, crypto.encoded


def work():
    return _ValidationWork(QueryReadValidationLimits())


def iso(offset=0):
    return (STAMP + timedelta(seconds=offset)).isoformat()


def scope():
    value = {name: DIGEST for name in wire.SCOPE_FIELDS}
    value.update(reviewId="review-one", approvalRequestId="approval-one", reviewerId="oidc:reviewer",
        sessionId="session-one", credentialRecordId="credential-one", recipientPublicKey=encoded(b"r" * 32))
    for name in wire.SCOPE_FIELDS:
        if name.endswith("EpochNs"):
            value[name] = NOW + 120 * SECOND
    return value


def authorization():
    return {"schema": wire.AUTHORIZATION_SCHEMA, "operation": wire.AUTHORIZE,
        "requestDigest": DIGEST, "scope": scope(), "currentRootVectorDigest": DIGEST,
        "currentRootHeadDigest": OTHER, "currentRootSequence": 7,
        "issuedAtEpochNs": NOW, "expiresAtEpochNs": NOW + 20 * SECOND}


def acknowledgment():
    return {"schema": wire.ACKNOWLEDGMENT_SCHEMA, "operation": wire.RECEIPT,
        "requestDigest": DIGEST, "authorizationSha256": DIGEST, "preparationSha256": OTHER,
        "scope": scope(), "reviewDigest": DIGEST, "receiptId": "receipt-one",
        "receiptExpiresAtEpochNs": NOW + 20 * SECOND, "commitMarkerSha256": DIGEST,
        "completionReceiptSha256": OTHER, "afterRootVectorDigest": DIGEST,
        "committedAtEpochNs": NOW, "expiresAtEpochNs": NOW + 10 * SECOND}


def signed(value, key, *, domain=None):
    signature = key.sign((domain or value["schema"]).encode() + b"\0" + canonical(value))
    return canonical({"schema": value["schema"].replace("catchplate.native", "catchplate.signedNative", 1),
        "payload": value, "signatureBase64Url": encoded(signature)}).decode()


class ReviewerFixture:
    def __init__(self):
        self.session = {"id": "session-one", "token_digest": sha(TOKEN), "oidc_token_digest": OTHER,
            "user_id": "oidc:reviewer", "roles_json": '["approver"]', "status": "active",
            "provider_expires_at": iso(300), "expires_at": iso(120), "pending_expires_at": None,
            "created_at": iso(-20), "updated_at": iso(-10), "activated_at": iso(-10),
            "revoked_at": None, "bound_webauthn_credential_id": "credential-one",
            "activation_trust_bundle_digest": DIGEST, "activation_trust_bundle_sequence": 7,
            "activation_authenticator_class": "hardware", "revocation_reason": None}
        self.credential = {"id": "credential-one", "credential_id": encoded(b"c" * 32),
            "user_id": "oidc:reviewer", "label": "Synthetic hardware", "public_key_cose": encoded(b"key"),
            "sign_count": 3, "aaguid": "fixture-guid", "authenticator_class": "hardware",
            "attestation_fmt": "packed", "attestation_trusted": 1, "attestation_trust_path": '[]',
            "attestation_leaf_sha256": OTHER, "attestation_root_sha256": OTHER,
            "attestation_trust_bundle_digest": DIGEST, "attestation_trust_bundle_sequence": 7,
            "attestation_verified_at": iso(-30), "transports": '["usb"]', "dev_private_key_pem": None,
            "created_at": iso(-30), "updated_at": iso(-10), "last_used_at": iso(-10),
            "revoked_at": None, "revoked_by": None, "revocation_reason": None, "revocation_source": None}
        self.rbac = {"authority_id": 1, "generation": 4, "state_digest": DIGEST,
            "binding_table_revision": 4, "verified_binding_table_revision": 4, "updated_at": iso(-5)}
        self.binding = {"subject_id": "oidc:reviewer", "roles_json": '["approver"]', "status": "active",
            "generation": 4, "binding_digest": DIGEST, "updated_at": iso(-5), "updated_by": "oidc:admin",
            "reason": None, "deprovisioned_at": None, "deprovisioned_by": None}
        self.rebind_roles()
        self.high = {"authority_scope": "webauthn-metadata", "rollback_epoch": 0,
            "publication_sequence": 7, "publication_digest": DIGEST, "metadata_blob_digest": OTHER,
            "revocation_set_digest": DIGEST, "witness_receipt_digest": OTHER, "witness_sequence": 9,
            "updated_at_epoch_ns": NOW - SECOND}
        self.publication = {"id": "publication-one", "scope": "global", "previous_bundle_digest": OTHER,
            "bundle_digest": DIGEST, "sequence": 7, "rollback_epoch": 0, "signing_key_id": DIGEST,
            "bundle_json": '{}', "payload_digest": OTHER, "actor_id": "oidc:admin",
            "withdrawn_credential_ids_json": '[]', "audit_event_json": '{}', "status": "published",
            "attempts": 1, "last_error": None, "created_at": iso(-10), "published_at": iso(-5)}
        self.authn = {"userVerification": "required", "allowedAuthenticatorClasses": ["hardware"],
            "requireHardwareAttestation": True}
        self.trust = {"roots": [{"id": "root-one", "certificate_sha256": OTHER,
            "authenticator_class": "hardware", "aaguids": ["fixture-guid"],
            "bundle_digest": DIGEST, "bundle_sequence": 7}], "currentBundleDigest": DIGEST,
            "currentBundleSequence": 7}

    def rebind_roles(self):
        material = {"subject_id": self.binding["subject_id"], "roles": json.loads(self.binding["roles_json"]),
            "status": self.binding["status"], "generation": self.binding["generation"],
            "updated_at": self.binding["updated_at"], "updated_by": self.binding["updated_by"],
            "reason": self.binding["reason"]}
        self.binding["binding_digest"] = sha(canonical(material))

    def context(self):
        rows = [("oidc_browser_sessions", {"id": self.session["id"]}, self.session),
            ("webauthn_credentials", {"id": self.credential["id"]}, self.credential),
            ("rbac_authority_state", {"authority_id": 1}, self.rbac),
            ("rbac_role_bindings", {"subject_id": self.binding["subject_id"]}, self.binding),
            ("webauthn_trust_publication_high_water", {"authority_scope": "webauthn-metadata"}, self.high),
            ("webauthn_trust_publications", {"id": self.publication["id"]}, self.publication)]
        return core.KernelContext(wire.AUTHORIZE, {"session_id": "session-one"},
            tuple(counters.selection(table, key, present=True, row=row) for table, key, row in rows), STAMP, DIGEST)

    def check(self, token=TOKEN):
        return kernel._current_reviewer(self.context(), token_original=token,
            authn_policy=self.authn, trust_policy=self.trust, work=work())


class OpeningContractTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.from_private_bytes(b"s" * 32)

    def tearDown(self):
        self.assertEqual(_violations, [])

    def test_actual_purpose_signatures_are_distinct(self):
        for payload, verify in ((authorization(), wire.verify_authorization_original),
                (acknowledgment(), wire.verify_commit_acknowledgment_original)):
            self.assertEqual(verify(signed(payload, self.key), public_key=self.key.public_key(),
                now_epoch_ns=NOW + SECOND)["payload"], payload)
            with self.assertRaises(Exception):
                verify(signed(payload, self.key, domain="catchplate.genericVerifierResponse/v1"),
                    public_key=self.key.public_key(), now_epoch_ns=NOW + SECOND)

    def test_grant_never_parses_as_commit_ack(self):
        with self.assertRaises(Exception):
            wire.verify_commit_acknowledgment_original(signed(authorization(), self.key),
                public_key=self.key.public_key(), now_epoch_ns=NOW + SECOND)

    def test_wrong_key_modified_signature_and_expiry_refuse(self):
        original = signed(authorization(), self.key)
        with self.assertRaises(Exception):
            wire.verify_authorization_original(original,
                public_key=Ed25519PrivateKey.from_private_bytes(b"t" * 32).public_key(), now_epoch_ns=NOW)
        for at in (NOW - 1, NOW + 20 * SECOND):
            with self.assertRaises(Exception):
                wire.verify_authorization_original(original, public_key=self.key.public_key(), now_epoch_ns=at)

    def test_closed_scope_and_absolute_limits(self):
        for change in ({"callerVerified": True}, {"sessionExpiresAtEpochNs": NOW},
                {"recipientPublicKey": encoded(bytes(32))}):
            payload = authorization(); payload["scope"].update(change)
            with self.assertRaises(Exception):
                wire.validate_authorization_original(signed(payload, self.key))

    def test_exact_original_canonical_duplicate_and_extra_keys_refuse(self):
        original = signed(authorization(), self.key)
        for changed in (original + " ", original.replace('"payload":', '"payload":{},"payload":', 1)):
            with self.assertRaises(Exception):
                wire.validate_authorization_original(changed)

    def test_http_bound_covers_second_json_escaping(self):
        values = {"challengeOriginal": "\\" * wire.MAX_NATIVE_ORIGINAL,
            "authorizationOriginal": '"' * wire.MAX_AUTHORITY_ORIGINAL,
            "preparationOriginal": "\\" * wire.MAX_NATIVE_ORIGINAL}
        self.assertLessEqual(len(canonical(values)), wire.MAX_HTTP_REQUEST)

    def test_operation_registry_has_actual_reader_and_replaying_kernel(self):
        for operation in wire.OPERATIONS:
            program = programs.PROGRAMS[operation]
            self.assertEqual(program.planning_mode, "typed-successor-planning")
            self.assertEqual(program.result_kind, "read-replay-components")
            self.assertIsNone(program.plan_factory)
            self.assertIn(operation, registry.COMPONENT_ONLY_SUCCESSOR_OPERATIONS)
            self.assertNotIn(operation, registry.PLANNABLE_OPERATIONS)
            self.assertNotIn(operation, registry.LEGACY_PLANNABLE_OPERATIONS)
            with self.assertRaises(ValueError):
                registry.successor_program(operation)
            self.assertEqual(program.kernel_factory().operation, operation)
            with self.assertRaises(FrozenInstanceError):
                program.kernel_factory().operation = "jit.decide"
        self.assertNotIn(wire.AUTHORIZE, authority.CURRENT_ROOT_COMMIT_MARKER_CONTRACT["operations"])
        self.assertIn(wire.RECEIPT, authority.CURRENT_ROOT_COMMIT_MARKER_CONTRACT["operations"])

    def test_exact_operation_effect_bounds(self):
        self.assertEqual(authority.operation_spec(wire.AUTHORIZE)["businessWrites"], ())
        receipt = authority.operation_spec(wire.RECEIPT)
        self.assertEqual((receipt["maximumQueryRows"], receipt["maximumMutations"]), (13, 4))
        self.assertEqual(set(receipt["businessWrites"]),
            {"approval_review_receipts", "metadata_audit_outbox", capacity.AGGREGATE_TABLE})


class CurrentReviewerTests(unittest.TestCase):
    def test_actual_structural_and_trust_checks_derive_reviewer(self):
        f = ReviewerFixture()
        session, credential, roles, expires = f.check()
        self.assertEqual((session["user_id"], credential["id"], roles, expires),
            ("oidc:reviewer", "credential-one", ["approver"], NOW + 120 * SECOND))

    def test_digest_alone_and_wrong_token_are_not_possession(self):
        digest = sha(TOKEN)
        for token in (digest, digest.encode(), TOKEN.decode("ascii"), b"b" * 64, TOKEN + b"a", b"\xff" * 64):
            with self.assertRaises(Exception):
                ReviewerFixture().check(token)

    def test_session_revocation_and_absolute_expiry_refuse(self):
        for field, value in (("status", "revoked"), ("revoked_at", iso(-1)),
                ("expires_at", iso()), ("pending_expires_at", iso(10))):
            f = ReviewerFixture(); f.session[field] = value
            with self.assertRaises(Exception):
                f.check()

    def test_credential_revocation_development_and_wrong_user_refuse(self):
        for field, value in (("revoked_at", iso(-1)), ("revocation_source", "admin"),
                ("dev_private_key_pem", "private-test-key"), ("user_id", "oidc:another"),
                ("attestation_verified_at", iso(1))):
            f = ReviewerFixture(); f.credential[field] = value
            with self.assertRaises(Exception):
                f.check()

    def test_old_activation_generation_is_not_delivery_tolerance(self):
        for field, value in (("activation_trust_bundle_sequence", 6),
                ("activation_trust_bundle_digest", OTHER), ("activation_authenticator_class", "yubikey")):
            f = ReviewerFixture(); f.session[field] = value
            with self.assertRaises(Exception):
                f.check()

    def test_rbac_current_generation_and_canonical_binding_required(self):
        for field, value in (("binding_table_revision", 5), ("verified_binding_table_revision", 3),
                ("generation", 3)):
            f = ReviewerFixture(); f.rbac[field] = value
            with self.assertRaises(Exception):
                f.check()
        f = ReviewerFixture(); f.binding["binding_digest"] = OTHER
        with self.assertRaises(Exception):
            f.check()

    def test_admin_role_alias_but_not_arbitrary_current_role(self):
        for role, allowed in (("admin", True), ("auditor", False)):
            f = ReviewerFixture(); f.session["roles_json"] = f.binding["roles_json"] = canonical([role]).decode()
            f.rebind_roles()
            if allowed:
                self.assertEqual(f.check()[2], [role])
            else:
                with self.assertRaises(Exception):
                    f.check()

    def test_current_publication_and_trust_root_joins_refuse(self):
        f = ReviewerFixture(); f.publication["bundle_digest"] = OTHER
        with self.assertRaises(Exception):
            f.check()
        f = ReviewerFixture(); f.trust["roots"][0]["certificate_sha256"] = DIGEST
        with self.assertRaises(Exception):
            f.check()

    def test_full_size_opaque_publication_is_not_repeatedly_copied(self):
        f = ReviewerFixture()
        for name in ("bundle_json", "audit_event_json", "withdrawn_credential_ids_json"):
            f.publication[name] = "\\" * (2 * 1024 * 1024)
        self.assertEqual(f.check()[0]["user_id"], "oidc:reviewer")


class ReceiptEffectsTests(unittest.TestCase):
    def make_context(self):
        identity = core.deterministic_uuid(operation=wire.RECEIPT, request_digest=DIGEST, purpose=kernel.RECEIPT_PURPOSE)
        rows = [counters.selection("approval_review_receipts", {"id": identity}),
            counters.selection("metadata_audit_outbox", {"id": quota._audit_identity(wire.RECEIPT, DIGEST)})]
        for kind, partition in (("jit-review-receipts", quota._aggregate_key("jit-review-receipts", "global")[1]),
                (capacity.AGGREGATE_KIND, capacity.PARTITION_DIGEST)):
            row = counters.aggregate_row(kind=kind, partition=partition)
            rows.append(counters.selection(capacity.AGGREGATE_TABLE,
                {"aggregate_id": row["aggregate_id"]}, present=True, row=row))
        return core.KernelContext(wire.RECEIPT, {}, tuple(rows), STAMP, DIGEST)

    def derive(self, context=None, *, expires=NOW + 10 * SECOND + 123):
        return kernel._receipt_effects(context or self.make_context(), scope=scope(),
            authorization_original='{"synthetic":"authorization"}', preparation_original='{"synthetic":"prepared"}',
            review_digest=OTHER, expires=expires, work=work())

    def test_four_real_effects_and_no_disclosure_or_decision(self):
        result = self.derive()
        self.assertEqual(len(result.mutations), 4)
        self.assertEqual(sorted((item["table"], item["operation"]) for item in result.mutations),
            [("approval_review_receipts", "INSERT"), ("metadata_audit_outbox", "INSERT"),
             (capacity.AGGREGATE_TABLE, "UPDATE"), (capacity.AGGREGATE_TABLE, "UPDATE")])
        self.assertIs(result.result["canDecide"], False)
        self.assertNotIn("acknowledgmentOriginal", result.result)
        self.assertEqual(result.result["receiptExpiresAtEpochNs"], NOW + 10 * SECOND)

    def test_existing_receipt_never_reissues_or_renews(self):
        result = self.derive(); context = self.make_context()
        for item in result.mutations:
            for selected in context.selected_rows:
                if (selected["table"], selected["key"]) == (item["table"], item["key"]):
                    selected["present"], selected["row"] = True, copy.deepcopy(item["row"])
        with self.assertRaises(Exception):
            self.derive(context)

    def test_expired_interval_cannot_start_new_ttl(self):
        with self.assertRaises(Exception):
            self.derive(expires=NOW)

    def test_missing_capacity_refuses_no_bootstrap(self):
        context = self.make_context(); context.selected_rows[-1].update(present=False, row=None)
        with self.assertRaises(Exception):
            self.derive(context)


class HistoricalProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = crypto.SyntheticNitro()

    def test_literal_349_and_expired_seal_still_parse_without_resealing(self):
        fixture = old_fixture.Fixture(self.pki)
        parsed = history.historical_retained_documents(retained_row=fixture.row,
            approval_row=fixture.approval, now_epoch_ns=NOW + 90 * SECOND)
        self.assertEqual(parsed[0]["operationManifestDigest"], old_fixture.MANIFEST)
        self.assertNotEqual(old_fixture.MANIFEST, authority.OPERATION_MANIFEST_DIGEST)

    def test_literal_350_profile_remains_supported_after_current_source_changes(self):
        manifest = "sha256:ed6d471a03516c96aa4968b89e4d220f9d5aaa0dfc4c1f848acfcc58343de4f0"
        revision = "catchplate.policyCandidateAuthoritySource/2026-07-30.350"
        fixture = old_fixture.Fixture(self.pki, manifest=manifest)
        fixture.row["source_revision"] = revision
        parsed = history.historical_retained_documents(retained_row=fixture.row,
            approval_row=fixture.approval, now_epoch_ns=NOW + 90 * SECOND)
        self.assertEqual(parsed[0]["operationManifestDigest"], manifest)
        self.assertIn((manifest, revision), history.SEALED_PROFILES)
        self.assertNotEqual(manifest, authority.OPERATION_MANIFEST_DIGEST)

    def test_fresh_351_sealing_and_pending_originals_have_explicit_historical_compatibility(self):
        fixture = pending_fixture.Fixture(self.pki)
        self.assertIsNone(fixture.verify())
        derived = private.derive_native_requests(fixture.crypto.runtime)
        self.assertEqual(derived.parent_request, fixture.parent)
        self.assertEqual(derived.child_request, fixture.child)
        transition = fixture.transition()
        rows = {item["table"]: item["row"] for item in transition.mutations}
        retained = rows["policy_authority_native_jit_review_pairs"]
        self.assertEqual(retained["source_revision"],
            "catchplate.policyCandidateAuthoritySource/2026-07-30.351")
        self.assertEqual(retained["source_contract_digest"],
            "sha256:bb0f9a53066e10042f83a1576d2c44b1dcf497eee457bb8d3146d86f4d526256")
        self.assertEqual(retained["source_contract_digest"], authority.OPERATION_MANIFEST_DIGEST)
        self.assertIn((retained["source_contract_digest"], retained["source_revision"]),
            history.SEALED_PROFILES)
        before = copy.deepcopy((retained, rows["approval_requests"]))
        parsed = history.historical_retained_documents(retained_row=retained,
            approval_row=rows["approval_requests"], now_epoch_ns=NOW + 90 * SECOND)
        self.assertEqual(parsed[:2], (fixture.parent, fixture.child))
        for column, document in zip(("parent_request_original", "child_request_original",
                "pair_original", "proof_original"), parsed, strict=True):
            self.assertEqual(canonical(document).decode("ascii"), retained[column])
        self.assertEqual(history.retained_original_documents(
            parent_original=retained["parent_request_original"],
            child_original=retained["child_request_original"],
            pair_original=retained["pair_original"],
            evidence_original=retained["proof_original"]), parsed)
        self.assertEqual((retained, rows["approval_requests"]), before)

    def test_unknown_future_profile_and_revision_mismatch_fail_closed(self):
        for manifest, revision in ((OTHER, old_fixture.REVISION),
                (old_fixture.MANIFEST, history.FRESH_SEALED_SOURCE_REVISION),
                (history.FRESH_SEALED_MANIFEST, history.SEALED_351_SOURCE_REVISION),
                (history.SEALED_351_MANIFEST, history.FRESH_SEALED_SOURCE_REVISION),
                (history.SEALED_351_MANIFEST, "catchplate.policyCandidateAuthoritySource/2026-07-30.352"),
                (OTHER, "catchplate.policyCandidateAuthoritySource/2026-07-30.352")):
            with self.subTest(manifest=manifest, revision=revision):
                fixture = old_fixture.Fixture(self.pki, manifest=manifest)
                fixture.row["source_revision"] = revision
                with self.assertRaises(history.RetainedHistoryError):
                    history.historical_retained_documents(retained_row=fixture.row,
                        approval_row=fixture.approval, now_epoch_ns=NOW + 90 * SECOND)


if __name__ == "__main__":
    unittest.main()
