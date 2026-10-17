#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from jsonschema import Draft202012Validator

import launch_authorization as protocol


ROOT = Path(__file__).resolve().parents[1]
NOW = 1_800_000_000
WITNESS_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x55]) * 32)
AUTHORITY_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def digest(character: str) -> str:
    return "sha256:" + character * 64


def named_digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def global_role_registry() -> dict[str, Any]:
    return protocol.build_launch_global_role_registry(
        {
            "launchAuthority": protocol.spki_key_id(
                public_spki(AUTHORITY_PRIVATE_KEY)
            ),
            "launchAuthorityWitness": protocol.spki_key_id(
                public_spki(WITNESS_PRIVATE_KEY)
            ),
            "launchAuthorityWitnessStoreAssurance": named_digest(
                "witness-store-assurance"
            ),
            "launchAuthorityWitnessTls": named_digest("witness-tls"),
            "nonceAuthorityAssuranceEvidence": named_digest(
                "nonce-authority-assurance-evidence"
            ),
            "nonceAuthorityVerifierState": named_digest(
                "nonce-authority-verifier-state"
            ),
            "nonceAuthorityVerifierStateStoreAttestation": named_digest(
                "nonce-authority-verifier-state-store-attestation"
            ),
            "policyActivation": named_digest("policy-activation"),
            "policyIdentity": named_digest("policy-identity"),
            "reproducibleBuild": named_digest("reproducible-build"),
        }
    )


def request_fixture() -> dict[str, Any]:
    witness_key_id = protocol.spki_key_id(public_spki(WITNESS_PRIVATE_KEY))
    role_registry = global_role_registry()
    role_registry_sha256 = protocol.launch_global_role_registry_sha256(
        role_registry
    )
    request = {
        "launcherNonce": "0" * 64,
        "bootIdSha256": digest("1"),
        "manifestSha256": digest("3"),
        "globalRoleRegistrySha256": role_registry_sha256,
        "launchAuthorityWitnessChallenge": "b" * 64,
    }
    return {
        "apiVersion": protocol.REQUEST_API_VERSION,
        "kind": protocol.REQUEST_KIND,
        **request,
        "launcherSha256": digest("2"),
        "globalRoleRegistry": role_registry,
        "globalRoleRegistryPinsSha256": named_digest(
            "global-role-registry-pins"
        ),
        "nonceRollbackAssuranceContractSha256": digest("4"),
        "nonceRollbackAssurancePinsSha256": digest("5"),
        "releaseProvenanceSha256": digest("6"),
        "provenanceDigest": digest("7"),
        "reproducibleBuildVerificationSha256": digest("8"),
        "sourceTreeDigest": digest("9"),
        "deploymentAudience": "prod:us-east-1.host_01",
        "deploymentIdentitySha256": digest("a"),
        "releaseSequence": 41,
        "rollbackEpoch": 0,
        "authorizationScope": protocol.AUTHORIZATION_SCOPE,
        "freshnessAuthority": protocol.FRESHNESS_AUTHORITY,
        "launchAuthorityWitnessKeyId": witness_key_id,
        "launchAuthorityWitnessIdentitySha256": digest("c"),
        "launchAuthorityWitnessAdministrativeDomainSha256": digest("d"),
        "launchAuthorityWitnessStoreAssuranceSha256": digest("e"),
        "launchAttemptJournalDomain": protocol.LAUNCH_ATTEMPT_JOURNAL_DOMAIN,
        "launchAttemptRecoveryIdentitySha256": (
            protocol.launch_attempt_recovery_identity_sha256(request)
        ),
    }


def public_spki(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def schema(name: str) -> dict[str, Any]:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def metadata_fixture(
    *,
    link_count: int = 1,
    mode: int = 0o400,
    size: int = 3,
) -> dict[str, int]:
    return {
        "device": 1,
        "inode": 2,
        "mode": mode,
        "ownerUid": 0,
        "ownerGid": 0,
        "linkCount": link_count,
        "size": size,
        "modifiedUnixNanos": NOW * 1_000_000_000,
        "changedUnixNanos": NOW * 1_000_000_000 + 1,
    }


def file_fixture(
    label: str,
    *,
    mode: int = 0o400,
    sha256: str | None = None,
    size: int = 3,
) -> dict[str, Any]:
    return {
        "path": f"/opt/catchplate/release/{label}",
        "sha256": (
            sha256
            if sha256 is not None
            else "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()
        ),
        "metadata": metadata_fixture(mode=mode, size=size),
    }


def bootstrap_receipt_fixture(
    authorization: dict[str, Any],
) -> dict[str, Any]:
    input_names = (
        "productionImagesBuild",
        "productionImagesEnv",
        "productionImagesPublished",
        "releaseProvenanceSummary",
        "releaseProvenance",
        "imageSignaturesSummary",
        "imageSignatures",
        "bench",
        "kmsMaterials",
        "policyBundle",
        "policyTrustedPublicKey",
        "policyIdentityVerification",
        "policyActivationVerification",
        "policyActivationSignature",
        "policyActivationTrustedPublicKey",
        "reproducibleBuildVerification",
        "reproducibleBuildSignature",
        "reproducibleBuildTrustedPublicKey",
    )
    request = request_fixture()
    inputs = {
        name: file_fixture(f"input-{index}")
        for index, name in enumerate(input_names)
    }
    inputs["releaseProvenance"]["sha256"] = request["releaseProvenanceSha256"]
    inputs["reproducibleBuildVerification"]["sha256"] = request[
        "reproducibleBuildVerificationSha256"
    ]
    return {
        "apiVersion": "catchplate.bootstrapReceipt/v3",
        "kind": "ProductionBootstrapReceipt",
        "launchId": request["launcherNonce"],
        "bootIdSha256": request["bootIdSha256"],
        "launcher": {
            **file_fixture(
                "launcher",
                mode=0o500,
                sha256=request["launcherSha256"],
            ),
            "path": "/opt/catchplate/launchers/sha256-launcher/catchplate-production-launcher",
        },
        "manifest": {
            **file_fixture(
                "manifest",
                sha256=request["manifestSha256"],
            ),
            "path": "/etc/catchplate/production-release-launch.json",
        },
        "sourceTreeDigest": request["sourceTreeDigest"],
        "launchAuthorization": {
            "request": request,
            "requestSha256": protocol.launch_authorization_request_sha256(request),
            "envelope": authorization,
            "authorizationSha256": "sha256:"
            + hashlib.sha256(protocol.canonical_json_bytes(authorization)).hexdigest(),
            "witnessPublicKeySpkiDerBase64url": protocol.canonical_base64url(
                public_spki(WITNESS_PRIVATE_KEY)
            ),
            "verifiedAtUnixSeconds": NOW,
        },
        "nonceRollbackAssurance": {
            "apiVersion": "catchplate.productionNonceRollbackAssuranceBinding/v1",
            "contractSha256": request["nonceRollbackAssuranceContractSha256"],
            "pinsFile": {
                **file_fixture(
                    "nonce-rollback-assurance-pins",
                    sha256=request["nonceRollbackAssurancePinsSha256"],
                ),
                "path": "/etc/catchplate/nonce-rollback-assurance-pins.json",
            },
            "retainedSnapshotFd": 199,
            "retainedSnapshotSha256": request[
                "nonceRollbackAssurancePinsSha256"
            ],
            "verifierStateService": {
                "signingPublicKeySpkiDerBase64url": "MCowBQYDK2VwAyEA"
                + "A" * 43,
                "storeAdministrativeDomainSha256": digest("5"),
                "storeAssuranceEvidenceSha256": digest("6"),
                "storeAttestationPublicKeySpkiDerBase64url": "MCowBQYDK2VwAyEA"
                + "E" * 43,
                "storeIdentitySha256": digest("7"),
            },
        },
        "productionEnv": {
            **file_fixture("production.env"),
            "path": "/etc/catchplate/production.env",
        },
        "python": {
            **file_fixture("python", mode=0o500),
            "path": "/opt/catchplate/release/runtime/python/bin/python3",
            "importRoots": [
                {
                    "path": "/opt/catchplate/release",
                    "sha256": digest("7"),
                    "metadata": metadata_fixture(link_count=2, mode=0o500),
                },
                {
                    "path": "/opt/catchplate/release/runtime/python/lib/python3.12",
                    "sha256": digest("8"),
                    "metadata": metadata_fixture(link_count=2, mode=0o500),
                },
                {
                    "path": "/opt/catchplate/release/runtime/python/lib/python3.12/lib-dynload",
                    "sha256": digest("9"),
                    "metadata": metadata_fixture(link_count=2, mode=0o500),
                },
                {
                    "path": "/opt/catchplate/release/vendor",
                    "sha256": digest("a"),
                    "metadata": metadata_fixture(link_count=2, mode=0o500),
                }
            ],
        },
        "scripts": {
            "preflight": file_fixture("8"),
            "runner": file_fixture("9"),
        },
        "composeFile": file_fixture("a"),
        "inputs": inputs,
        "argv": {
            "preflightSha256": digest("b"),
            "readinessSha256": digest("c"),
        },
        "environment": {
            "names": [
                "LANG",
                "LC_ALL",
                "PATH",
                "CATCHPLATE_BOOTSTRAP_RECEIPT_API_VERSION",
                "CATCHPLATE_BOOTSTRAP_RECEIPT_FD",
                "CATCHPLATE_BOOTSTRAP_RECEIPT_SHA256",
                "TZ",
            ],
            "sha256": digest("d"),
        },
    }


class LaunchAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = AUTHORITY_PRIVATE_KEY
        cls.other_private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        cls.spki = public_spki(cls.private_key)
        cls.other_spki = public_spki(cls.other_private_key)
        cls.key_id = protocol.spki_key_id(cls.spki)

    def authorization(
        self,
        *,
        request: dict[str, Any] | None = None,
        private_key: Ed25519PrivateKey | None = None,
        issued_at: int = NOW,
        expires_at: int = NOW + 30,
    ) -> dict[str, Any]:
        selected_request = request or request_fixture()
        selected_private_key = private_key or self.private_key
        authorization_id = "a" * 64
        return protocol.sign_launch_authorization(
            selected_request,
            private_key=selected_private_key,
            authorization_id=authorization_id,
            issued_at_unix_seconds=issued_at,
            expires_at_unix_seconds=expires_at,
            monotonic_witness=self.witness(
                selected_request,
                authorization_id=authorization_id,
                authority_key_id=protocol.spki_key_id(
                    public_spki(selected_private_key)
                ),
                issued_at=issued_at,
                expires_at=expires_at,
            ),
        )

    def witness(
        self,
        request: dict[str, Any],
        *,
        authorization_id: str,
        authority_key_id: str,
        checkpoint_sequence: int = 9,
        predecessor_state_sha256: str = digest("1"),
        successor_state_sha256: str = digest("2"),
        issued_at: int = NOW,
        expires_at: int = NOW + 30,
    ) -> dict[str, Any]:
        statement = {
            "operation": protocol.WITNESS_OPERATION,
            "operationId": request["launcherNonce"],
            "authorizationId": authorization_id,
            "requestSha256": protocol.launch_authorization_request_sha256(request),
            "challenge": request["launchAuthorityWitnessChallenge"],
            "issuedAtUnixSeconds": issued_at,
            "expiresAtUnixSeconds": expires_at,
            "authorityKeyId": authority_key_id,
            "witnessKeyId": request["launchAuthorityWitnessKeyId"],
            "witnessIdentitySha256": request[
                "launchAuthorityWitnessIdentitySha256"
            ],
            "witnessAdministrativeDomainSha256": request[
                "launchAuthorityWitnessAdministrativeDomainSha256"
            ],
            "storeAssuranceSha256": request[
                "launchAuthorityWitnessStoreAssuranceSha256"
            ],
            "registryGeneration": 4,
            "registrySha256": digest("3"),
            "predecessorStateSha256": predecessor_state_sha256,
            "successorStateSha256": successor_state_sha256,
            "deploymentAudience": request["deploymentAudience"],
            "deploymentIdentitySha256": request["deploymentIdentitySha256"],
            "releaseSequence": request["releaseSequence"],
            "rollbackEpoch": request["rollbackEpoch"],
            "authorizationScope": protocol.AUTHORIZATION_SCOPE,
            "stateTransitionCommitted": True,
            "checkpointSequence": checkpoint_sequence,
        }
        return {
            "apiVersion": protocol.WITNESS_API_VERSION,
            "kind": protocol.WITNESS_KIND,
            "statement": statement,
            "signature": protocol.canonical_base64url(
                WITNESS_PRIVATE_KEY.sign(
                    protocol.launch_authority_witness_signing_bytes(statement)
                )
            ),
        }

    def resign(
        self,
        document: dict[str, Any],
        *,
        private_key: Ed25519PrivateKey | None = None,
        domain: bytes = protocol.AUTHORIZATION_DOMAIN,
    ) -> dict[str, Any]:
        copied = deepcopy(document)
        unsigned = {
            "apiVersion": copied["apiVersion"],
            "kind": copied["kind"],
            "statement": copied["statement"],
        }
        copied["signature"] = protocol.canonical_base64url(
            (private_key or self.private_key).sign(
                domain + protocol.canonical_json_bytes(unsigned)
            )
        )
        return copied

    def verify(
        self,
        document: dict[str, Any],
        *,
        spki: bytes | None = None,
        expected_request_sha256: str | None = None,
        expected_authority_key_id: str | None = None,
        now: int = NOW,
    ) -> protocol.VerifiedLaunchAuthorization:
        return protocol.verify_launch_authorization(
            protocol.canonical_json_bytes(document),
            authority_public_key_spki_der=spki or self.spki,
            expected_request_sha256=(
                expected_request_sha256
                if expected_request_sha256 is not None
                else protocol.launch_authorization_request_sha256(request_fixture())
            ),
            expected_authority_key_id=(
                expected_authority_key_id
                if expected_authority_key_id is not None
                else protocol.spki_key_id(spki or self.spki)
            ),
            now_unix_seconds=now,
            expected_global_role_registry_sha256=request_fixture()[
                "globalRoleRegistrySha256"
            ],
        )

    def test_valid_request_signing_and_verification(self) -> None:
        request = request_fixture()
        expected_request_digest = "sha256:" + hashlib.sha256(
            protocol.REQUEST_API_VERSION.encode("ascii")
            + b"\0"
            + protocol.canonical_json_bytes(request)
        ).hexdigest()
        self.assertEqual(
            protocol.launch_authorization_request_sha256(request),
            expected_request_digest,
        )
        document = self.authorization(request=request)
        verified = self.verify(
            document,
            expected_request_sha256=expected_request_digest,
        )
        self.assertEqual(verified.authorization_id, "a" * 64)
        self.assertEqual(verified.authority_key_id, self.key_id)
        self.assertEqual(verified.request_sha256, expected_request_digest)
        self.assertEqual(verified.issued_at_unix_seconds, NOW)
        self.assertEqual(verified.expires_at_unix_seconds, NOW + 30)
        self.assertEqual(verified.authorization_scope, protocol.AUTHORIZATION_SCOPE)
        self.assertEqual(verified.freshness_authority, protocol.FRESHNESS_AUTHORITY)
        self.assertEqual(
            verified.capability_semantics,
            protocol.CAPABILITY_SEMANTICS,
        )
        self.assertEqual(
            verified.global_role_registry_sha256,
            request["globalRoleRegistrySha256"],
        )
        verified_witness = protocol.verify_launch_authority_witness(
            verified.monotonic_witness,
            witness_public_key_spki_der=public_spki(WITNESS_PRIVATE_KEY),
            expected_witness_key_id=request["launchAuthorityWitnessKeyId"],
            expected_request=request,
            expected_authorization_id=verified.authorization_id,
            expected_authority_key_id=verified.authority_key_id,
            expected_registry_generation=4,
            expected_registry_sha256=digest("3"),
            expected_predecessor_state_sha256=digest("1"),
            expected_successor_state_sha256=digest("2"),
            expected_issued_at_unix_seconds=NOW,
            expected_expires_at_unix_seconds=NOW + 30,
        )
        self.assertEqual(
            verified_witness["statement"]["checkpointSequence"],
            9,
        )
        integrated = protocol.verify_launch_authorization_with_witness(
            protocol.canonical_json_bytes(document),
            authority_public_key_spki_der=self.spki,
            expected_request=request,
            expected_authority_key_id=self.key_id,
            witness_public_key_spki_der=public_spki(WITNESS_PRIVATE_KEY),
            expected_witness_key_id=request["launchAuthorityWitnessKeyId"],
            now_unix_seconds=NOW,
            expected_registry_generation=4,
            expected_registry_sha256=digest("3"),
            expected_predecessor_state_sha256=digest("1"),
            expected_successor_state_sha256=digest("2"),
        )
        self.assertEqual(integrated.authorization_id, verified.authorization_id)

        signature = base64.urlsafe_b64decode(document["signature"] + "==")
        self.private_key.public_key().verify(
            signature,
            protocol.AUTHORIZATION_API_VERSION.encode("ascii")
            + b"\0"
            + protocol.canonical_json_bytes(
                {
                    "apiVersion": document["apiVersion"],
                    "kind": document["kind"],
                    "statement": document["statement"],
                }
            ),
        )

    def test_global_role_registry_is_closed_distinct_and_digest_bound(self) -> None:
        request = request_fixture()
        registry = request["globalRoleRegistry"]
        self.assertEqual(
            protocol.validate_launch_global_role_registry(registry),
            registry,
        )
        self.assertEqual(
            set(registry["roles"]),
            protocol.GLOBAL_ROLE_REGISTRY_REQUIRED_ROLES,
        )
        self.assertEqual(len(registry["roles"]), 10)
        self.assertEqual(
            tuple(registry["rolesOutsideClaim"]),
            protocol.GLOBAL_ROLE_REGISTRY_ROLES_OUTSIDE_CLAIM,
        )
        self.assertEqual(len(registry["rolesOutsideClaim"]), 10)

        missing = deepcopy(registry)
        missing["roles"].pop("reproducibleBuild")
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError, "missing required fields"
        ):
            protocol.validate_launch_global_role_registry(missing)

        extra = deepcopy(registry)
        extra["roles"]["credentialCustody"] = named_digest(
            "credential-custody"
        )
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "unknown"):
            protocol.validate_launch_global_role_registry(extra)

        unsupported_claim = deepcopy(registry)
        unsupported_claim["roles"]["finalVerifier"] = named_digest(
            "unsupported-final-verifier"
        )
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "unknown"):
            protocol.validate_launch_global_role_registry(unsupported_claim)

        collision = deepcopy(registry)
        collision["roles"]["reproducibleBuild"] = collision["roles"][
            "policyIdentity"
        ]
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "reuses"):
            protocol.validate_launch_global_role_registry(collision)

        outside_claim_substitution = deepcopy(registry)
        outside_claim_substitution["rolesOutsideClaim"].pop()
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError, "closed list"
        ):
            protocol.validate_launch_global_role_registry(
                outside_claim_substitution
            )

        digest_substitution = deepcopy(request)
        digest_substitution["globalRoleRegistrySha256"] = named_digest(
            "substituted-registry"
        )
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError, "digest binding mismatch"
        ):
            protocol.validate_launch_authorization_request(digest_substitution)

        authorization = self.authorization(request=request)
        authorization["statement"]["globalRoleRegistrySha256"] = named_digest(
            "cross-wired-registry"
        )
        authorization = self.resign(authorization)
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError,
            "global role registry digest binding mismatch",
        ):
            self.verify(authorization)

        journal_domain_substitution = deepcopy(request)
        journal_domain_substitution["launchAttemptJournalDomain"] = (
            "catchplate.launchAuthorizationAttemptJournal/v2"
        )
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError,
            "launchAttemptJournalDomain",
        ):
            protocol.validate_launch_authorization_request(
                journal_domain_substitution
            )

        recovery_identity_substitution = deepcopy(request)
        recovery_identity_substitution[
            "launchAttemptRecoveryIdentitySha256"
        ] = named_digest("substituted-recovery-identity")
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError,
            "recovery identity binding mismatch",
        ):
            protocol.validate_launch_authorization_request(
                recovery_identity_substitution
            )

    def test_global_registry_exactly_binds_the_witness_request_signer_and_verifier(
        self,
    ) -> None:
        request_mismatch = request_fixture()
        other_witness_key_id = protocol.spki_key_id(self.other_spki)
        request_mismatch["globalRoleRegistry"]["roles"][
            "launchAuthorityWitness"
        ] = other_witness_key_id
        request_mismatch["globalRoleRegistrySha256"] = (
            protocol.launch_global_role_registry_sha256(
                request_mismatch["globalRoleRegistry"]
            )
        )
        request_mismatch["launchAttemptRecoveryIdentitySha256"] = (
            protocol.launch_attempt_recovery_identity_sha256(request_mismatch)
        )
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError,
            "request witness key differs from global role registry",
        ):
            protocol.validate_launch_authorization_request(request_mismatch)

        request = request_fixture()
        mismatched_witness = self.witness(
            request,
            authorization_id="a" * 64,
            authority_key_id=self.key_id,
        )
        mismatched_witness["statement"][
            "witnessKeyId"
        ] = other_witness_key_id
        mismatched_witness["signature"] = protocol.canonical_base64url(
            self.other_private_key.sign(
                protocol.launch_authority_witness_signing_bytes(
                    mismatched_witness["statement"]
                )
            )
        )
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError,
            "authorization signer witness key differs from global role registry",
        ):
            protocol.sign_launch_authorization(
                request,
                private_key=self.private_key,
                authorization_id="a" * 64,
                issued_at_unix_seconds=NOW,
                expires_at_unix_seconds=NOW + 30,
                monotonic_witness=mismatched_witness,
            )

        authorization = self.authorization(request=request)
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError,
            "verifier witness key differs from global role registry",
        ):
            protocol.verify_launch_authorization_with_witness(
                protocol.canonical_json_bytes(authorization),
                authority_public_key_spki_der=self.spki,
                expected_request=request,
                expected_authority_key_id=self.key_id,
                witness_public_key_spki_der=public_spki(WITNESS_PRIVATE_KEY),
                expected_witness_key_id=other_witness_key_id,
                now_unix_seconds=NOW,
                expected_registry_generation=4,
                expected_registry_sha256=digest("3"),
                expected_predecessor_state_sha256=digest("1"),
                expected_successor_state_sha256=digest("2"),
            )

    def test_expired_authorization_can_be_authenticated_only_for_recovery(self) -> None:
        request = request_fixture()
        expired = self.authorization(
            request=request,
            issued_at=NOW - 30,
            expires_at=NOW,
        )
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "expired"):
            self.verify(expired)
        recovered = protocol.verify_launch_authorization_for_recovery(
            protocol.canonical_json_bytes(expired),
            authority_public_key_spki_der=self.spki,
            expected_request_sha256=protocol.launch_authorization_request_sha256(
                request
            ),
            expected_authority_key_id=self.key_id,
            expected_global_role_registry_sha256=request[
                "globalRoleRegistrySha256"
            ],
        )
        self.assertEqual(recovered.expires_at_unix_seconds, NOW)
        recovered_with_witness = (
            protocol.verify_launch_authorization_with_witness_for_recovery(
                protocol.canonical_json_bytes(expired),
                authority_public_key_spki_der=self.spki,
                expected_request=request,
                expected_authority_key_id=self.key_id,
                witness_public_key_spki_der=public_spki(
                    WITNESS_PRIVATE_KEY
                ),
                expected_witness_key_id=request[
                    "launchAuthorityWitnessKeyId"
                ],
                expected_registry_generation=4,
                expected_registry_sha256=digest("3"),
                expected_predecessor_state_sha256=digest("1"),
                expected_successor_state_sha256=digest("2"),
            )
        )
        self.assertEqual(
            recovered_with_witness.authorization_id,
            recovered.authorization_id,
        )

        tampered_witness = deepcopy(expired)
        tampered_witness["statement"]["monotonicWitness"]["statement"][
            "checkpointSequence"
        ] += 1
        tampered_witness = self.resign(tampered_witness)
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError, "witness signature"
        ):
            protocol.verify_launch_authorization_with_witness_for_recovery(
                protocol.canonical_json_bytes(tampered_witness),
                authority_public_key_spki_der=self.spki,
                expected_request=request,
                expected_authority_key_id=self.key_id,
                witness_public_key_spki_der=public_spki(
                    WITNESS_PRIVATE_KEY
                ),
                expected_witness_key_id=request[
                    "launchAuthorityWitnessKeyId"
                ],
            )

    def test_schemas_are_valid_closed_and_accept_valid_documents(self) -> None:
        fixtures = (
            ("launch-authorization-request.v2.schema.json", request_fixture()),
            ("launch-authorization.v2.schema.json", self.authorization()),
        )
        for name, document in fixtures:
            loaded = schema(name)
            Draft202012Validator.check_schema(loaded)
            validator = Draft202012Validator(loaded)
            validator.validate(document)

            hostile = deepcopy(document)
            hostile["unknown"] = True
            with self.subTest(schema=name, boundary="top-level"), self.assertRaises(Exception):
                validator.validate(hostile)

            object_schemas: list[dict[str, Any]] = []

            def collect(value: Any) -> None:
                if isinstance(value, dict):
                    if value.get("type") == "object":
                        object_schemas.append(value)
                    for item in value.values():
                        collect(item)
                elif isinstance(value, list):
                    for item in value:
                        collect(item)

            collect(loaded)
            self.assertTrue(object_schemas, name)
            self.assertTrue(
                all(item.get("additionalProperties") is False for item in object_schemas),
                name,
            )

        envelope_validator = Draft202012Validator(
            schema("launch-authorization.v2.schema.json")
        )
        nested = self.authorization()
        nested["statement"]["unknown"] = True
        with self.assertRaises(Exception):
            envelope_validator.validate(nested)

    def test_completion_proof_v6_embedded_authorization_matches_runtime(self) -> None:
        loaded = schema("completion-proof.v6.schema.json")
        Draft202012Validator.check_schema(loaded)
        request_schema = loaded["$defs"]["authorizationRequestV2"]
        statement_schema = loaded["$defs"]["authorizationStatementV2"]
        self.assertEqual(
            set(request_schema["required"]),
            protocol._REQUEST_FIELDS,
        )
        self.assertEqual(
            set(request_schema["properties"]),
            protocol._REQUEST_FIELDS,
        )
        self.assertEqual(
            set(statement_schema["required"]),
            protocol._STATEMENT_FIELDS,
        )
        self.assertEqual(
            set(statement_schema["properties"]),
            protocol._STATEMENT_FIELDS,
        )

        request_validator = Draft202012Validator(
            {
                "$schema": loaded["$schema"],
                "$ref": "#/$defs/authorizationRequestV2",
                "$defs": loaded["$defs"],
            }
        )
        statement_validator = Draft202012Validator(
            {
                "$schema": loaded["$schema"],
                "$ref": "#/$defs/authorizationStatementV2",
                "$defs": loaded["$defs"],
            }
        )
        witness_statement_validator = Draft202012Validator(
            {
                "$schema": loaded["$schema"],
                "$ref": "#/$defs/monotonicWitnessStatement",
                "$defs": loaded["$defs"],
            }
        )
        request = request_fixture()
        statement = self.authorization(request=request)["statement"]
        request_validator.validate(request)
        statement_validator.validate(statement)
        witness_statement_validator.validate(
            statement["monotonicWitness"]["statement"]
        )
        self.assertEqual(
            statement["globalRoleRegistrySha256"],
            request["globalRoleRegistrySha256"],
        )

        for field in (
            "globalRoleRegistry",
            "globalRoleRegistrySha256",
            "globalRoleRegistryPinsSha256",
            "launchAttemptJournalDomain",
            "launchAttemptRecoveryIdentitySha256",
        ):
            hostile = deepcopy(request)
            hostile.pop(field)
            with self.subTest(missing_request_field=field), self.assertRaises(
                Exception
            ):
                request_validator.validate(hostile)

        missing_statement_digest = deepcopy(statement)
        missing_statement_digest.pop("globalRoleRegistrySha256")
        with self.assertRaises(Exception):
            statement_validator.validate(missing_statement_digest)

        invalid_authorization_interval = deepcopy(statement)
        invalid_authorization_interval["expiresAtUnixSeconds"] = NOW + 31
        statement_validator.validate(invalid_authorization_interval)
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError,
            "validity must not exceed 30 seconds",
        ):
            protocol.validate_launch_authorization_statement(
                invalid_authorization_interval
            )

        witness_statement = statement["monotonicWitness"]["statement"]
        invalid_witness_interval = deepcopy(witness_statement)
        invalid_witness_interval["expiresAtUnixSeconds"] = NOW + 31
        witness_statement_validator.validate(invalid_witness_interval)
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError,
            "validity interval is invalid",
        ):
            protocol.validate_launch_authority_witness_statement(
                invalid_witness_interval
            )

        identity_transition = deepcopy(witness_statement)
        identity_transition["successorStateSha256"] = identity_transition[
            "predecessorStateSha256"
        ]
        witness_statement_validator.validate(identity_transition)
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError,
            "non-identity state transition",
        ):
            protocol.validate_launch_authority_witness_statement(
                identity_transition
            )

        for definition in (
            "authorizationStatementV2",
            "monotonicWitnessStatement",
            "launchAuthorizationV2",
        ):
            boundary = loaded["$defs"][definition]["$comment"]
            self.assertIn("non-verifying", boundary)
            self.assertIn("Native launch_authorization.py", boundary)

    def test_bootstrap_receipt_v3_schema_matches_native_nested_contract(self) -> None:
        loaded = schema("bootstrap-receipt.v3.schema.json")
        Draft202012Validator.check_schema(loaded)
        validator = Draft202012Validator(loaded)
        receipt = bootstrap_receipt_fixture(self.authorization())
        validator.validate(receipt)

        hostile_documents: list[dict[str, Any]] = []
        v2 = deepcopy(receipt)
        v2["apiVersion"] = "catchplate.bootstrapReceipt/v2"
        hostile_documents.append(v2)
        old_request = deepcopy(receipt)
        old_request["launchAuthorization"]["request"][
            "apiVersion"
        ] = "catchplate.launchAuthorizationRequest/v1"
        hostile_documents.append(old_request)
        old_envelope = deepcopy(receipt)
        old_envelope["launchAuthorization"]["envelope"][
            "apiVersion"
        ] = "catchplate.launchAuthorization/v1"
        hostile_documents.append(old_envelope)
        missing_assurance = deepcopy(receipt)
        missing_assurance["nonceRollbackAssurance"].pop("contractSha256")
        hostile_documents.append(missing_assurance)
        nested_extra = deepcopy(receipt)
        nested_extra["nonceRollbackAssurance"]["verifierStateService"]["unknown"] = True
        hostile_documents.append(nested_extra)
        unsafe_integer = deepcopy(receipt)
        unsafe_integer["launcher"]["metadata"]["inode"] = 1 << 64
        hostile_documents.append(unsafe_integer)
        wrong_spki = deepcopy(receipt)
        wrong_spki["nonceRollbackAssurance"]["verifierStateService"][
            "signingPublicKeySpkiDerBase64url"
        ] = "A" * 59
        hostile_documents.append(wrong_spki)
        missing_root = deepcopy(receipt)
        missing_root["python"]["importRoots"].pop()
        hostile_documents.append(missing_root)
        reordered_roots = deepcopy(receipt)
        reordered_roots["python"]["importRoots"][1], reordered_roots["python"][
            "importRoots"
        ][2] = (
            reordered_roots["python"]["importRoots"][2],
            reordered_roots["python"]["importRoots"][1],
        )
        hostile_documents.append(reordered_roots)
        standard_fd = deepcopy(receipt)
        standard_fd["nonceRollbackAssurance"]["retainedSnapshotFd"] = 2
        hostile_documents.append(standard_fd)
        receipt_fd_collision = deepcopy(receipt)
        receipt_fd_collision["nonceRollbackAssurance"]["retainedSnapshotFd"] = 198
        hostile_documents.append(receipt_fd_collision)
        missing_witness_key = deepcopy(receipt)
        missing_witness_key["launchAuthorization"].pop(
            "witnessPublicKeySpkiDerBase64url"
        )
        hostile_documents.append(missing_witness_key)
        wrong_witness_key = deepcopy(receipt)
        wrong_witness_key["launchAuthorization"][
            "witnessPublicKeySpkiDerBase64url"
        ] = protocol.canonical_base64url(self.other_spki)
        hostile_documents.append(wrong_witness_key)

        for document in hostile_documents:
            with self.subTest(document=document), self.assertRaises(Exception):
                validator.validate(document)

    def test_strict_parser_rejects_malformed_duplicate_and_non_integer_json(self) -> None:
        invalid = (
            b"",
            b"[]",
            b"{} trailing",
            b"\xef\xbb\xbf{}",
            b'{"x":"\xff"}',
            b'{"x":1.0}',
            b'{"x":1e3}',
            b'{"x":NaN}',
            b'{"x":9007199254740992}',
            b'{"x":1,"x":2}',
            b'{"statement":{"x":1,"x":2}}',
        )
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(protocol.LaunchAuthorizationError):
                protocol.parse_strict_json_object(raw)
        with self.assertRaises(protocol.LaunchAuthorizationError):
            protocol.parse_strict_json_object(bytearray(b"{}"))  # type: ignore[arg-type]
        with self.assertRaises(protocol.LaunchAuthorizationError):
            protocol.canonical_json_bytes({"x": 1.0})
        with self.assertRaises(protocol.LaunchAuthorizationError):
            protocol.canonical_json_bytes({"x": protocol.MAX_SAFE_INTEGER + 1})

    def test_canonical_byte_helper_and_verifier_reject_noncanonical_bytes(self) -> None:
        document = self.authorization()
        canonical = protocol.canonical_json_bytes(document)
        self.assertEqual(protocol.require_canonical_json_bytes(canonical), document)

        variants = (
            json.dumps(document, indent=2, sort_keys=True).encode("ascii"),
            canonical + b"\n",
            json.dumps(document, separators=(",", ":"), sort_keys=False).encode("ascii"),
        )
        for raw in variants:
            with self.subTest(raw=raw[:40]), self.assertRaises(
                protocol.LaunchAuthorizationError
            ):
                protocol.require_canonical_json_bytes(raw)
            with self.assertRaises(protocol.LaunchAuthorizationError):
                protocol.verify_launch_authorization(
                    raw,
                    authority_public_key_spki_der=self.spki,
                    expected_request_sha256=protocol.launch_authorization_request_sha256(
                        request_fixture()
                    ),
                    expected_authority_key_id=self.key_id,
                    now_unix_seconds=NOW,
                )

    def test_request_contract_rejects_malformed_unknown_and_unsafe_values(self) -> None:
        cases: list[dict[str, Any]] = []

        def changed(field: str, value: Any) -> dict[str, Any]:
            candidate = request_fixture()
            candidate[field] = value
            return candidate

        unknown = request_fixture()
        unknown["unknown"] = True
        cases.append(unknown)
        non_string_key = request_fixture()
        non_string_key[1] = True  # type: ignore[index]
        cases.append(non_string_key)
        missing = request_fixture()
        missing.pop("manifestSha256")
        cases.append(missing)
        cases.extend(
            (
                changed("apiVersion", protocol.REQUEST_API_VERSION + "x"),
                changed("kind", protocol.REQUEST_KIND + "x"),
                changed("launcherNonce", "A" * 64),
                changed("launcherNonce", "0" * 63),
                changed("bootIdSha256", "1" * 64),
                changed("launcherSha256", "sha256:" + "A" * 64),
                changed("nonceRollbackAssuranceContractSha256", digest("g")),
                changed("nonceRollbackAssurancePinsSha256", "sha256:" + "A" * 64),
                changed("deploymentAudience", ""),
                changed("deploymentAudience", "Prod"),
                changed("deploymentAudience", "prod/us"),
                changed("deploymentAudience", "prod-\N{SNOWMAN}"),
                changed("deploymentAudience", "a" * 129),
                changed("releaseSequence", 0),
                changed("releaseSequence", True),
                changed("releaseSequence", protocol.MAX_SAFE_INTEGER + 1),
                changed("rollbackEpoch", -1),
                changed("rollbackEpoch", False),
                changed("authorizationScope", "final-release-completion"),
                changed("freshnessAuthority", "secure-tee-time"),
                changed("launchAuthorityWitnessChallenge", "B" * 64),
                changed("launchAuthorityWitnessKeyId", "sha256:" + "A" * 64),
                changed("launchAuthorityWitnessIdentitySha256", digest("g")),
                changed(
                    "launchAuthorityWitnessAdministrativeDomainSha256",
                    "sha256:" + "A" * 64,
                ),
                changed(
                    "launchAuthorityWitnessStoreAssuranceSha256",
                    "sha256:" + "f" * 63,
                ),
            )
        )
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(
                protocol.LaunchAuthorizationError
            ):
                protocol.validate_launch_authorization_request(candidate)

    def test_every_request_field_is_covered_by_the_request_digest(self) -> None:
        original = request_fixture()
        expected = protocol.launch_authorization_request_sha256(original)
        mutations: dict[str, Any] = {
            "launcherNonce": "f" * 64,
            "bootIdSha256": digest("9"),
            "launcherSha256": digest("a"),
            "manifestSha256": digest("b"),
            "nonceRollbackAssuranceContractSha256": digest("c"),
            "nonceRollbackAssurancePinsSha256": digest("d"),
            "releaseProvenanceSha256": digest("e"),
            "provenanceDigest": digest("f"),
            "reproducibleBuildVerificationSha256": digest("0"),
            "sourceTreeDigest": digest("1"),
            "deploymentAudience": "prod:us-west-2.host_02",
            "deploymentIdentitySha256": digest("0"),
            "releaseSequence": 42,
            "rollbackEpoch": 1,
            "authorizationScope": "trusted-host-readiness-v2",
            "freshnessAuthority": "trusted-host-monotonic-clock",
            "launchAuthorityWitnessChallenge": "c" * 64,
            "launchAuthorityWitnessKeyId": digest("0"),
            "launchAuthorityWitnessIdentitySha256": digest("1"),
            "launchAuthorityWitnessAdministrativeDomainSha256": digest("2"),
            "launchAuthorityWitnessStoreAssuranceSha256": digest("3"),
        }
        for field, value in mutations.items():
            candidate = deepcopy(original)
            candidate[field] = value
            with self.subTest(field=field):
                self.assertNotEqual(
                    protocol.launch_authorization_request_sha256(candidate), expected
                )

    def test_v1_downgrade_omission_substitution_and_cross_field_swap_fail(self) -> None:
        original = request_fixture()
        original_digest = protocol.launch_authorization_request_sha256(original)

        v1 = deepcopy(original)
        v1["apiVersion"] = "catchplate.launchAuthorizationRequest/v1"
        with self.assertRaises(protocol.LaunchAuthorizationError):
            protocol.validate_launch_authorization_request(v1)

        for field in (
            "nonceRollbackAssuranceContractSha256",
            "nonceRollbackAssurancePinsSha256",
            "authorizationScope",
            "freshnessAuthority",
            "launchAuthorityWitnessChallenge",
            "launchAuthorityWitnessKeyId",
            "launchAuthorityWitnessIdentitySha256",
            "launchAuthorityWitnessAdministrativeDomainSha256",
            "launchAuthorityWitnessStoreAssuranceSha256",
        ):
            omitted = deepcopy(original)
            omitted.pop(field)
            with self.subTest(omitted=field), self.assertRaises(
                protocol.LaunchAuthorizationError
            ):
                protocol.validate_launch_authorization_request(omitted)

        substituted = deepcopy(original)
        substituted["nonceRollbackAssuranceContractSha256"] = digest("f")
        self.assertNotEqual(
            protocol.launch_authorization_request_sha256(substituted),
            original_digest,
        )

        swapped = deepcopy(original)
        swapped["nonceRollbackAssuranceContractSha256"], swapped[
            "nonceRollbackAssurancePinsSha256"
        ] = (
            swapped["nonceRollbackAssurancePinsSha256"],
            swapped["nonceRollbackAssuranceContractSha256"],
        )
        self.assertNotEqual(
            protocol.launch_authorization_request_sha256(swapped),
            original_digest,
        )
        authorization = self.authorization(request=original)
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "request digest"):
            self.verify(
                authorization,
                expected_request_sha256=protocol.launch_authorization_request_sha256(
                    swapped
                ),
            )

        v1_authorization = deepcopy(authorization)
        v1_authorization["apiVersion"] = "catchplate.launchAuthorization/v1"
        with self.assertRaises(protocol.LaunchAuthorizationError):
            protocol.validate_launch_authorization(v1_authorization)

    def test_envelope_and_statement_contracts_are_exact(self) -> None:
        valid = self.authorization()
        cases: list[dict[str, Any]] = []

        unknown = deepcopy(valid)
        unknown["unknown"] = True
        cases.append(unknown)
        nested_unknown = deepcopy(valid)
        nested_unknown["statement"]["unknown"] = True
        cases.append(nested_unknown)
        missing = deepcopy(valid)
        missing["statement"].pop("requestSha256")
        cases.append(missing)

        def changed(path: str, value: Any) -> dict[str, Any]:
            candidate = deepcopy(valid)
            if path in {"apiVersion", "kind", "signature"}:
                candidate[path] = value
            else:
                candidate["statement"][path] = value
            return candidate

        cases.extend(
            (
                changed("apiVersion", protocol.AUTHORIZATION_API_VERSION + "x"),
                changed("kind", protocol.AUTHORIZATION_KIND + "x"),
                changed("authorizationId", "A" * 64),
                changed("authorityKeyId", "f" * 64),
                changed("requestSha256", "sha256:" + "F" * 64),
                changed("issuedAtUnixSeconds", 0),
                changed("issuedAtUnixSeconds", True),
                changed("expiresAtUnixSeconds", protocol.MAX_SAFE_INTEGER + 1),
                changed("authorizationScope", "final-release-completion"),
                changed("freshnessAuthority", "secure-tee-time"),
                changed("capabilitySemantics", "one-use"),
                changed("monotonicWitness", {}),
            )
        )
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(
                protocol.LaunchAuthorizationError
            ):
                protocol.validate_launch_authorization(candidate)

    def test_signature_must_be_canonical_unpadded_base64url_for_64_bytes(self) -> None:
        valid = self.authorization()
        signatures = (
            valid["signature"] + "=",
            "ed25519:" + valid["signature"],
            "A" * 85,
            "A" * 85 + "B",
            "!" + valid["signature"][1:],
        )
        for signature in signatures:
            candidate = deepcopy(valid)
            candidate["signature"] = signature
            with self.subTest(signature=signature), self.assertRaises(
                protocol.LaunchAuthorizationError
            ):
                protocol.validate_launch_authorization(candidate)

    def test_wrong_signature_key_and_domain_are_rejected(self) -> None:
        valid = self.authorization()
        corrupted = deepcopy(valid)
        signature = base64.urlsafe_b64decode(corrupted["signature"] + "==")
        corrupted["signature"] = protocol.canonical_base64url(
            bytes([signature[0] ^ 1]) + signature[1:]
        )
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "signature"):
            self.verify(corrupted)

        for domain in (b"", b"catchplate.wrongLaunchAuthorization/v1\0"):
            wrong_domain = self.resign(valid, domain=domain)
            with self.subTest(domain=domain), self.assertRaisesRegex(
                protocol.LaunchAuthorizationError, "signature"
            ):
                self.verify(wrong_domain)

        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "signature"):
            self.verify(
                valid,
                spki=self.other_spki,
                expected_authority_key_id=protocol.spki_key_id(self.other_spki),
            )

    def test_validity_future_skew_and_expiry_boundaries(self) -> None:
        self.verify(self.authorization(issued_at=NOW + 5, expires_at=NOW + 30))
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "future skew"):
            self.verify(self.authorization(issued_at=NOW + 6, expires_at=NOW + 30))
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "expired"):
            self.verify(self.authorization(issued_at=NOW - 30, expires_at=NOW))
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "30 seconds"):
            self.authorization(issued_at=NOW, expires_at=NOW + 31)
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "after issuance"):
            self.authorization(issued_at=NOW, expires_at=NOW)

    def test_false_one_use_claim_is_rejected_even_when_resigned(self) -> None:
        candidate = self.authorization()
        candidate["statement"]["useLimit"] = 2
        candidate = self.resign(candidate)
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "unknown"):
            self.verify(candidate)

    def test_witness_cross_wiring_downgrade_replay_and_rollback_fail(self) -> None:
        request = request_fixture()
        authorization = self.authorization(request=request)
        witness = authorization["statement"]["monotonicWitness"]
        common = {
            "witness_public_key_spki_der": public_spki(WITNESS_PRIVATE_KEY),
            "expected_witness_key_id": request["launchAuthorityWitnessKeyId"],
            "expected_request": request,
            "expected_authorization_id": authorization["statement"][
                "authorizationId"
            ],
            "expected_authority_key_id": self.key_id,
            "expected_registry_generation": 4,
            "expected_registry_sha256": digest("3"),
            "expected_predecessor_state_sha256": digest("1"),
            "expected_successor_state_sha256": digest("2"),
            "expected_issued_at_unix_seconds": NOW,
            "expected_expires_at_unix_seconds": NOW + 30,
        }
        protocol.verify_launch_authority_witness(witness, **common)

        other_request = request_fixture()
        other_request["launchAuthorityWitnessChallenge"] = "c" * 64
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError, "challenge binding mismatch"
        ):
            protocol.verify_launch_authority_witness(
                witness,
                **{**common, "expected_request": other_request},
            )

        for field, value, message in (
            ("operation", "authorize-final-release", "operation"),
            ("authorizationScope", "final-release-completion", "authorizationScope"),
            ("checkpointSequence", 0, "checkpointSequence"),
            ("stateTransitionCommitted", False, "stateTransitionCommitted"),
            ("successorStateSha256", digest("1"), "non-identity"),
        ):
            hostile = deepcopy(witness)
            hostile["statement"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                protocol.LaunchAuthorizationError,
                message,
            ):
                protocol.validate_launch_authority_witness(hostile)

        wrong_predecessor = {**common, "expected_predecessor_state_sha256": digest("f")}
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError,
            "predecessorStateSha256 binding mismatch",
        ):
            protocol.verify_launch_authority_witness(witness, **wrong_predecessor)

        wrong_key = Ed25519PrivateKey.from_private_bytes(bytes([0x56]) * 32)
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError,
            "trusted witness key",
        ):
            protocol.verify_launch_authority_witness(
                witness,
                **{
                    **common,
                    "witness_public_key_spki_der": public_spki(wrong_key),
                },
            )

        crossed_witness = deepcopy(authorization)
        crossed_witness["statement"]["monotonicWitness"] = self.witness(
            request,
            authorization_id=authorization["statement"]["authorizationId"],
            authority_key_id=self.key_id,
            predecessor_state_sha256=digest("f"),
        )
        crossed_witness = self.resign(crossed_witness)
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError,
            "predecessorStateSha256 binding mismatch",
        ):
            protocol.verify_launch_authorization_with_witness(
                protocol.canonical_json_bytes(crossed_witness),
                authority_public_key_spki_der=self.spki,
                expected_request=request,
                expected_authority_key_id=self.key_id,
                witness_public_key_spki_der=public_spki(WITNESS_PRIVATE_KEY),
                expected_witness_key_id=request[
                    "launchAuthorityWitnessKeyId"
                ],
                now_unix_seconds=NOW,
                expected_predecessor_state_sha256=digest("1"),
            )

    def test_expected_request_and_authority_bindings_are_required(self) -> None:
        valid = self.authorization()
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "request digest"):
            self.verify(valid, expected_request_sha256=digest("f"))
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "trusted authority"):
            self.verify(valid, expected_authority_key_id=digest("f"))

        wrong_request = deepcopy(valid)
        wrong_request["statement"]["requestSha256"] = digest("f")
        wrong_request = self.resign(wrong_request)
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "request digest"):
            self.verify(wrong_request)

        wrong_authority = deepcopy(valid)
        wrong_authority["statement"]["authorityKeyId"] = digest("f")
        wrong_authority = self.resign(wrong_authority)
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "authority key ID"):
            self.verify(wrong_authority)

    def test_spki_key_id_uses_canonical_der_and_requires_ed25519(self) -> None:
        self.assertEqual(
            self.key_id,
            "sha256:" + hashlib.sha256(self.spki).hexdigest(),
        )
        pem = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        x25519_der = X25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        for value in (pem, x25519_der, bytearray(self.spki)):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(
                protocol.LaunchAuthorizationError
            ):
                protocol.spki_key_id(value)  # type: ignore[arg-type]

    def test_authorization_for_a_different_valid_request_cannot_be_rebound(self) -> None:
        original = request_fixture()
        changed = request_fixture()
        changed["manifestSha256"] = digest("f")
        authorization = self.authorization(request=changed)
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "request digest"):
            self.verify(
                authorization,
                expected_request_sha256=protocol.launch_authorization_request_sha256(
                    original
                ),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
