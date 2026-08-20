#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def candidate_bundle(
    policy_bundle: Any,
    sequence: int,
    credential_id: str,
) -> dict[str, Any]:
    bundle = policy_bundle.demo_policy_bundle(credential_id)
    bundle["metadata"]["sequence"] = sequence
    bundle["credentials"] = [
        item for item in bundle["credentials"] if item["id"] == credential_id
    ]
    bundle["routes"] = [
        route
        for route in bundle["routes"]
        if route.get("credentialRef") in {None, credential_id}
    ]
    return bundle


def dry_run_case(app_module: Any) -> Any:
    return app_module.PolicyDryRunCase(
        principalId="agent:demo",
        scheme="https",
        host="demo-upstream",
        port=8443,
        method="GET",
        path="/echo",
        expect="allow",
    )


def expect_http_error(
    label: str,
    action: Callable[[], Any],
    expected_status: int,
    expected_error: str,
) -> dict[str, Any]:
    from fastapi import HTTPException

    try:
        action()
    except HTTPException as exc:
        detail = exc.detail
        rendered = (
            json.dumps(detail, sort_keys=True)
            if isinstance(detail, dict)
            else str(detail)
        )
        if (
            exc.status_code != expected_status
            or expected_error not in rendered
            or not isinstance(detail, dict)
        ):
            raise AssertionError(
                f"{label} failed with the wrong error: "
                f"{exc.status_code} {rendered}"
            ) from exc
        return detail
    raise AssertionError(f"{label} unexpectedly succeeded")


def registered_methods(app_module: Any) -> dict[str, frozenset[str]]:
    routes: dict[str, frozenset[str]] = {}
    for route in app_module._fastapi_app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if isinstance(path, str) and methods:
            routes[path] = frozenset(methods)
    return routes


def require_route(
    routes: dict[str, frozenset[str]],
    path: str,
    method: str,
) -> None:
    if method not in routes.get(path, frozenset()):
        raise AssertionError(f"missing {method} candidate-authority route {path}")


def exercise_candidate_handoff_credential_recheck(
    app_module: Any,
    policy_bundle: Any,
    identity: Any,
) -> None:
    digest = lambda character: "sha256:" + character * 64
    credential_id = "credential:handoff-recheck"
    credential_policy = policy_bundle.CredentialPolicy(
        id=credential_id,
        kind="static",
        provider="generic",
        provider_subject="account:handoff",
        injection={"type": "bearer"},
    )
    route = type(
        "HandoffRoute",
        (),
        {
            "id": "route:handoff-recheck",
            "credential_ref": credential_id,
            "adapter_type": "generic.rest",
            "adapter_config": {
                "credentialBinding": {
                    "credentialType": "static",
                    "provider": "generic",
                    "subjects": ["account:handoff"],
                    "secretClass": "bearerToken",
                }
            },
        },
    )()
    candidate = type(
        "HandoffCandidate",
        (),
        {
            "hash": digest("c"),
            "credentials": {credential_id: credential_policy},
            "routes": [route],
        },
    )()
    active = type(
        "HandoffActive",
        (),
        {
            "hash": digest("a"),
            "raw": {
                "metadata": {
                    "id": "active-policy",
                    "sequence": 7,
                    "rollbackEpoch": 3,
                }
            },
        },
    )()
    runtime_attestation = {
        field: None
        for field in app_module._POLICY_SHADOW_RUNTIME_ATTESTATION_HANDOFF_FIELDS
    }
    runtime_attestation["apiVersion"] = (
        "serverware.policyShadowRuntimeAttestationHandoff/v2"
    )
    candidate_bundle_digest = digest("b")
    context = {
        "artifact": {
            "policy_hash": candidate.hash,
            "policy_bundle_digest": candidate_bundle_digest,
            "predecessor_policy_sequence": 7,
            "predecessor_rollback_epoch": 3,
        },
        "assignment": {
            "policy_bundle_digest": candidate_bundle_digest,
            "assignment_envelope_json": "{}",
            "assignment_envelope_digest": digest("d"),
        },
        "load_receipt": {
            "load_receipt_envelope_json": "{}",
            "load_receipt_envelope_digest": digest("e"),
        },
        "generation_trust": {
            "runtime_attestation_json": json.dumps(
                runtime_attestation,
                separators=(",", ":"),
                sort_keys=True,
            ),
            "runtime_attestation_chain_digest": digest("f"),
        },
        "high_water": {
            "policy_id": "active-policy",
            "policy_hash": active.hash,
            "sequence": 7,
            "rollback_epoch": 3,
        },
        "active": active,
    }
    valid_credential = {
        "kind": "bearer",
        "metadata": {
            "provider": "generic",
            "provider_subject": "account:handoff",
            "secret_class": "bearerToken",
        },
    }
    changed_credential = {
        **valid_credential,
        "metadata": {
            **valid_credential["metadata"],
            "provider_subject": "account:changed",
        },
    }
    originals = {
        "context": app_module._exact_policy_candidate_handoff_context,
        "compile": app_module.compile_policy_bundle,
        "bundle_digest": app_module._policy_canary_bundle_digest,
        "get_credential": app_module.db.get_credential,
        "derive": app_module.db.derive_policy_shadow_generation_request_identities,
        "claim": app_module.db.claim_policy_shadow_generation_request,
    }
    credential_reads = 0
    claim_calls = 0

    def get_credential(_credential_id: str) -> dict[str, Any]:
        nonlocal credential_reads
        credential_reads += 1
        return valid_credential if credential_reads == 1 else changed_credential

    def claim_request(**_kwargs: Any) -> dict[str, Any]:
        nonlocal claim_calls
        claim_calls += 1
        return {"audit_event_hash": digest("9")}

    try:
        app_module._exact_policy_candidate_handoff_context = lambda _handoff: context
        app_module.compile_policy_bundle = lambda *_args, **_kwargs: candidate
        app_module._policy_canary_bundle_digest = (
            lambda _bundle: candidate_bundle_digest
        )
        app_module.db.get_credential = get_credential
        app_module.db.derive_policy_shadow_generation_request_identities = (
            lambda **_kwargs: {
                "management_handoff_id": digest("1"),
                "replay_id": digest("2"),
            }
        )
        app_module.db.claim_policy_shadow_generation_request = claim_request
        payload = app_module.PolicyAuthorityCandidateHandoffRequest(
            apiVersion="serverware.policyAuthorityCandidateHandoff/v1",
            requestId="00000000-0000-4000-8000-000000000099",
            candidateId="candidate:handoff-recheck",
            artifactEnvelopeDigest=digest("3"),
            canaryId="canary:handoff-recheck",
            assignmentEnvelopeDigest=digest("4"),
            loadReceiptEnvelopeDigest=digest("5"),
            instanceId="instance:handoff-recheck",
            bootId=digest("6"),
            runtimeAttestationHandoffDigest=digest("7"),
            predecessorPolicyHash=active.hash,
            candidatePolicyBundle={},
        )
        request = type(
            "HandoffRequest",
            (),
            {
                "scope": {"query_string": b""},
                "headers": {
                    "content-type": "application/json",
                    "content-length": "2",
                },
            },
        )()
        try:
            asyncio.run(
                app_module.policy_authority_candidate_handoff(
                    request,
                    payload,
                    identity,
                )
            )
        except app_module.HTTPException as exc:
            if exc.status_code != 409 or "credential" not in str(exc.detail):
                raise AssertionError(
                    f"handoff credential recheck failed incorrectly: {exc}"
                ) from exc
        else:
            raise AssertionError(
                "candidate handoff accepted a credential changed between checks"
            )
        if credential_reads != 2 or claim_calls != 0:
            raise AssertionError(
                "candidate handoff did not reject credential drift before replay claim"
            )
    finally:
        app_module._exact_policy_candidate_handoff_context = originals["context"]
        app_module.compile_policy_bundle = originals["compile"]
        app_module._policy_canary_bundle_digest = originals["bundle_digest"]
        app_module.db.get_credential = originals["get_credential"]
        app_module.db.derive_policy_shadow_generation_request_identities = originals[
            "derive"
        ]
        app_module.db.claim_policy_shadow_generation_request = originals["claim"]


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
        os.environ["SERVERWARE_DEV_AUTHENTICATOR"] = "1"

        from serverware import app as app_module
        from serverware import db, policy_bundle
        from serverware.auth import AdminIdentity

        db.init_db()
        identity = AdminIdentity(
            "user:publisher",
            frozenset({"policy_publisher", "policy_author", "auditor"}),
            "admin-token-header",
        )
        credential = db.create_credential(
            "Canary demo",
            "bearer",
            "demo-token-from-vault",
            {
                "provider": "demo",
                "provider_subject": "demo-service-account",
                "secret_class": "bearerToken",
            },
        )
        credential_id = credential["id"]
        initial = policy_bundle.write_policy_bundle(
            candidate_bundle(policy_bundle, 1, credential_id)
        )
        policy_bundle.enforce_policy_high_water(initial)

        candidate_payload = app_module.PolicyCandidateRequest(
            bundle=candidate_bundle(policy_bundle, 2, credential_id),
            dryRun=[dry_run_case(app_module)],
        )
        candidate = app_module.policy_candidate(candidate_payload, _=identity)
        if (
            candidate["current"]["policyHash"] != initial.hash
            or candidate["candidate"]["policyHash"] == initial.hash
            or candidate["dryRun"]["passed"] is not True
        ):
            raise AssertionError(
                "advisory candidate preview did not preserve its source-only boundary"
            )

        wrong_injection = db.create_credential(
            "Wrong injection",
            "header",
            "demo-token-from-vault",
            {
                "provider": "demo",
                "provider_subject": "demo-service-account",
                "secret_class": "bearerToken",
                "injection_name": "x-api-key",
            },
        )
        expect_http_error(
            "candidate with incompatible stored injection",
            lambda: app_module.policy_candidate(
                app_module.PolicyCandidateRequest(
                    bundle=candidate_bundle(
                        policy_bundle,
                        2,
                        wrong_injection["id"],
                    ),
                    dryRun=[dry_run_case(app_module)],
                ),
                _=identity,
            ),
            409,
            "injection type",
        )

        publish_error = expect_http_error(
            "legacy direct policy publish",
            lambda: app_module.policy_publish(
                app_module.PolicyPublishRequest(
                    bundle=candidate_payload.bundle,
                    dryRun=candidate_payload.dry_run,
                ),
                identity=identity,
            ),
            409,
            "legacy_policy_publish_disabled",
        )
        if publish_error != {
            "error": "legacy_policy_publish_disabled",
            "authorityEndpoint": "/api/authority/control-plane/execute",
            "artifactEvidenceEndpoint":
                "/api/data-plane/policy-candidate/artifact",
            "canaryEvidenceEndpoint":
                "/api/data-plane/policy-canary/evidence",
            "packageImportEndpoint":
                "/api/policy/authority/candidates/package",
            "handoffEndpoint":
                "/api/policy/authority/candidates/handoff",
            "challengeEndpoint": "/api/authority/webauthn/challenges",
        }:
            raise AssertionError(
                "legacy publish did not direct callers to the durable authority path"
            )

        activation_error = expect_http_error(
            "legacy policy-canary activation",
            lambda: app_module.policy_canary_activate(
                app_module.PolicyCanaryActivationRequest(
                    canaryId="legacy-canary"
                ),
                identity=identity,
            ),
            409,
            "legacy_policy_canary_activate_disabled",
        )
        if activation_error != {
            "error": "legacy_policy_canary_activate_disabled",
            "authorityEndpoint": "/api/authority/control-plane/execute",
            "challengeEndpoint": "/api/authority/webauthn/challenges",
            "prepareOperation": "policy.activation.prepare",
            "finalizeOperation": "policy.activation.finalize",
        }:
            raise AssertionError(
                "legacy activation did not identify the controlled finalization path"
            )

        cancellation_error = expect_http_error(
            "legacy policy-canary cancellation",
            lambda: app_module.policy_canary_cancel(
                app_module.PolicyCanaryCancelRequest(
                    canaryId="legacy-canary",
                    note="obsolete compatibility request",
                ),
                identity=identity,
            ),
            409,
            "legacy_policy_canary_cancel_disabled",
        )
        if cancellation_error != {
            "error": "legacy_policy_canary_cancel_disabled",
            "authorityEndpoint": "/api/authority/control-plane/execute",
            "abortOperation": "policy.activation.abort",
            "challengeEndpoint": "/api/authority/webauthn/challenges",
        }:
            raise AssertionError(
                "legacy cancellation did not identify the controlled abort path"
            )

        routes = registered_methods(app_module)
        for path, method in (
            ("/api/data-plane/policy-candidate/artifact", "POST"),
            ("/api/data-plane/policy-canary/evidence", "POST"),
            ("/api/policy/authority/candidates/package", "POST"),
            ("/api/policy/authority/candidates/handoff", "POST"),
            (
                "/api/policy/authority/candidates/decision-gate-activate",
                "POST",
            ),
            ("/api/authority/control-plane/execute", "POST"),
            ("/api/authority/webauthn/challenges", "POST"),
            ("/api/policy/canary/status", "GET"),
            ("/api/policy/canary/activate", "POST"),
        ):
            require_route(routes, path, method)

        exercise_candidate_handoff_credential_recheck(
            app_module,
            policy_bundle,
            identity,
        )

        request_id = "00000000-0000-4000-8000-000000000001"
        for purpose in (
            "handoff",
            "decision-gate-activation",
            "authority-finalization",
            "abort",
        ):
            request = app_module.PolicyAuthorityPortalPackageImportRequest(
                apiVersion=
                    "serverware.policyAuthorityPortalPackageImportRequest/v1",
                requestId=request_id,
                purpose=purpose,
                package={},
            )
            if request.purpose != purpose:
                raise AssertionError(
                    f"candidate-authority package purpose changed: {purpose}"
                )

        activation_request = (
            app_module.PolicyAuthorityDecisionGateActivationRequest(
                apiVersion=
                    "serverware.policyAuthorityDecisionGateActivationRequest/v1",
                canaryId="durable-canary",
                generationId="sha256:" + "1" * 64,
                generationPublicationEnvelopeDigest="sha256:" + "2" * 64,
            )
        )
        if activation_request.generation_id != "sha256:" + "1" * 64:
            raise AssertionError(
                "decision-gate activation no longer binds the durable generation"
            )

    print("policy canary authority workflow source contract passed")


if __name__ == "__main__":
    main()
