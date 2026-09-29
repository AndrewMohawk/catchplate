"""Actual request commitments without importing planner registration.

These are the planner's shared computation bodies, not a second authorization
recipe. A digest never admits a request: the public planner retains its closed
registry gate, and semantic consumers still need their independent authority
inputs and genuine proof/receipt/kernel checks. Measured callers must already
own their graph and supply the real cumulative work meter.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from serverware import authority_contract
from serverware.authority_query_read_work import _ValidationWork, QueryReadWorkError


BUSINESS_INTENT_SCHEMA = authority_contract.BUSINESS_INTENT_SCHEMA


class AuthorityPlannerError(RuntimeError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def framed_digest(domain: str, *frames: bytes) -> str:
    digest = hashlib.sha256()
    encoded_domain = domain.encode("ascii")
    digest.update(encoded_domain)
    digest.update(b"\x00")
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def operation_id(operation: str, request_digest: str) -> str:
    return framed_digest(
        "serverware.policyAuthorityOperation/v2",
        operation.encode("utf-8"),
        request_digest.encode("utf-8"),
    )


def _authorization_arguments(
    arguments: Mapping[str, Any],
    *, work: _ValidationWork | None = None,
) -> dict[str, Any]:
    excluded = {
        "authn",
        "authn_evidence",
        "webauthn_authorization",
        "challenge_id",
    }
    if work is not None:
        # Full source units cover the actual sorted item list and filtered dict.
        work.prepare_copy(arguments)
        work.prepare_copy(arguments)
    return {
        key: value
        for key, value in sorted(arguments.items())
        if key not in excluded
    }


def _request_different(left: Any, right: Any, *, work: _ValidationWork | None) -> bool:
    if work is not None:
        work.prepare_comparison(left, right)
    return left != right


def publication_request_digest(operation: str, arguments: Mapping[str, Any]) -> str:
    from serverware import authority_publication_approval as publication
    publication = publication.operation_profile(operation)
    values = publication.arguments(operation, arguments)
    typed = {**values, "businessIntent": authority_contract.synthesize_business_intent(operation, values)}
    return framed_digest("serverware.policyAuthorityV9Request/v1", canonical_bytes({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "arguments": _authorization_arguments(typed)}))


def credential_currentness_request_digest(operation: str, arguments: Mapping[str, Any]) -> str:
    from serverware import authority_credential_currentness as currentness
    values = currentness.arguments(operation, arguments)
    typed = {**values, "businessIntent": authority_contract.synthesize_business_intent(operation, values)}
    return framed_digest("serverware.policyAuthorityV9Request/v1", canonical_bytes({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "arguments": _authorization_arguments(typed)}))


def oauth_activation_request_digest(operation: str, arguments: Mapping[str, Any]) -> str:
    from serverware import authority_oauth_activation as oauth
    values = oauth.arguments(operation, arguments)
    typed = {**values, "businessIntent": authority_contract.synthesize_business_intent(operation, values)}
    return framed_digest("serverware.policyAuthorityV9Request/v1", canonical_bytes({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "arguments": _authorization_arguments(typed)}))


def oauth_exchange_request_digest(operation: str, arguments: Mapping[str, Any]) -> str:
    from serverware import authority_oauth_exchange as oauth
    values = oauth.arguments(operation, arguments)
    typed = {**values, "businessIntent": authority_contract.synthesize_business_intent(operation, values)}
    return framed_digest("serverware.policyAuthorityV9Request/v1", canonical_bytes({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "arguments": _authorization_arguments(typed)}))


def oauth_measured_exchange_request_digest(operation: str, arguments: Mapping[str, Any]) -> str:
    from serverware import authority_oauth_measured_exchange as oauth
    values = oauth.arguments(operation, arguments, typed="businessIntent" in arguments)
    typed = {**values, "businessIntent": authority_contract.synthesize_business_intent(operation, values)}
    return framed_digest("serverware.policyAuthorityV9Request/v1", canonical_bytes({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "arguments": _authorization_arguments(typed)}))


def oauth_measured_setup_request_digest(operation: str, arguments: Mapping[str, Any]) -> str:
    from serverware import authority_oauth_measured_setup as oauth
    values = oauth.arguments(operation, arguments, typed="businessIntent" in arguments)
    typed = {**values, "businessIntent": authority_contract.synthesize_business_intent(operation, values)}
    return framed_digest("serverware.policyAuthorityV9Request/v1", canonical_bytes({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "arguments": _authorization_arguments(typed)}))


def oauth_setup_request_digest(operation: str, arguments: Mapping[str, Any]) -> str:
    from serverware import authority_oauth_setup as oauth
    values = oauth.arguments(operation, arguments, typed="businessIntent" in arguments)
    typed = {**values, "businessIntent": authority_contract.synthesize_business_intent(operation, values)}
    return framed_digest("serverware.policyAuthorityV9Request/v1", canonical_bytes({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "arguments": _authorization_arguments(typed)}))


def oauth_revocation_request_digest(operation: str, arguments: Mapping[str, Any]) -> str:
    from serverware import authority_oauth_revocation as oauth
    values = oauth.arguments(operation, arguments)
    typed = {**values, "businessIntent": authority_contract.synthesize_business_intent(operation, values)}
    return framed_digest("serverware.policyAuthorityV9Request/v1", canonical_bytes({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "arguments": _authorization_arguments(typed)}))


def oauth_refresh_cleanup_request_digest(operation: str, arguments: Mapping[str, Any]) -> str:
    from serverware import authority_oauth_refresh_cleanup as oauth
    values = oauth.arguments(operation, arguments)
    typed = {**values, "businessIntent": authority_contract.synthesize_business_intent(operation, values)}
    return framed_digest("serverware.policyAuthorityV9Request/v1", canonical_bytes({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "arguments": _authorization_arguments(typed)}))


def oauth_refresh_request_digest(operation: str, arguments: Mapping[str, Any]) -> str:
    from serverware import authority_oauth_refresh as oauth
    values = oauth.arguments(operation, arguments)
    typed = {**values, "businessIntent": authority_contract.synthesize_business_intent(operation, values)}
    return framed_digest("serverware.policyAuthorityV9Request/v1", canonical_bytes({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "arguments": _authorization_arguments(typed)}))


def oauth_measured_pending_retirement_request_digest(operation: str, arguments: Mapping[str, Any]) -> str:
    from serverware import authority_oauth_measured_pending_retirement as oauth
    values = oauth.arguments(operation, arguments, typed="businessIntent" in arguments)
    typed = {**values, "businessIntent": authority_contract.synthesize_business_intent(operation, values)}
    return framed_digest("serverware.policyAuthorityV9Request/v1", canonical_bytes({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "arguments": _authorization_arguments(typed)}))


def oauth_measured_capture_retirement_request_digest(operation: str, arguments: Mapping[str, Any]) -> str:
    from serverware import authority_oauth_measured_capture_retirement as oauth
    values = oauth.arguments(operation, dict(arguments), typed="businessIntent" in arguments)
    typed = {**values, "businessIntent": authority_contract.synthesize_business_intent(operation, values)}
    return framed_digest("serverware.policyAuthorityV9Request/v1", canonical_bytes({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "arguments": _authorization_arguments(typed)}))


def oauth_measured_cleanup_request_digest(operation: str, arguments: Mapping[str, Any]) -> str:
    from serverware import authority_oauth_measured_cleanup as oauth
    values = oauth.arguments(operation, arguments, typed="businessIntent" in arguments)
    typed = {**values, "businessIntent": authority_contract.synthesize_business_intent(operation, values)}
    return framed_digest("serverware.policyAuthorityV9Request/v1", canonical_bytes({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "arguments": _authorization_arguments(typed)}))


def oauth_measured_refresh_request_digest(operation: str, arguments: Mapping[str, Any]) -> str:
    from serverware import authority_oauth_measured_refresh as oauth
    values = oauth.arguments(operation, arguments, typed="businessIntent" in arguments)
    typed = {**values, "businessIntent": authority_contract.synthesize_business_intent(operation, values)}
    return framed_digest("serverware.policyAuthorityV9Request/v1", canonical_bytes({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "arguments": _authorization_arguments(typed)}))


def _typed_request_digest(
    request: Mapping[str, Any], *, work: _ValidationWork | None,
) -> str:
    """The genuine request commitment, not planner or capability admission.

    A private measured caller must already own its graph. Source-declared but
    unregistered operations may be committed here without changing the public
    planning gate. No caller-supplied manifest, serializer or success is used.
    """
    required = {
        "schema",
        "operation",
        "operationId",
        "requestDigest",
        "handler",
        "operationManifestDigest",
        "arguments",
    }
    if work is not None:
        if type(work) is not _ValidationWork:
            raise QueryReadWorkError("typed request requires the real shared work meter")
        if (type(request) is not dict or len(request) != len(required)
                or any(type(key) is not str or len(key) > 128 for key in request)):
            raise AuthorityPlannerError("typed planner request is not closed")
        work.prepare_copy(request)
    operation = request.get("operation")
    if work is not None and (type(operation) is not str or not 1 <= len(operation) <= 128):
        raise AuthorityPlannerError("typed planner request is not closed")
    try:
        spec = authority_contract.operation_spec(str(operation))
    except ValueError as exc:
        raise AuthorityPlannerError("typed planner request is not closed") from exc
    if (
        set(request) != required
        or _request_different(request.get("schema"), "serverware.policyAuthorityV9Request/v1", work=work)
        or _request_different(request.get("handler"), spec["handler"], work=work)
        or _request_different(request.get("operationManifestDigest"), authority_contract.OPERATION_MANIFEST_DIGEST, work=work)
        or not isinstance(request.get("arguments"), Mapping)
    ):
        raise AuthorityPlannerError(
            "typed planner request is not closed"
        )
    if work is None:
        _business_intent(request, operation=str(operation))
        arguments = _authorization_arguments(request["arguments"])
    else:
        _business_intent(request, operation=str(operation), work=work)
        arguments = _authorization_arguments(request["arguments"], work=work)
    document = {
        "schema": "serverware.policyAuthorityV9Authorization/v1",
        "operation": operation,
        "handler": request["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "arguments": arguments,
    }
    if work is not None:
        size, _ = work.prepare_encoding(document)
        if size > authority_contract.MAX_REQUEST_BYTES:
            raise AuthorityPlannerError("typed request commitment exceeds its source bound")
        work.charge(hashes=1)
    return framed_digest("serverware.policyAuthorityV9Request/v1", canonical_bytes(document))


def _business_intent(
    request: Mapping[str, Any],
    *,
    operation: str,
    work: _ValidationWork | None = None,
) -> Mapping[str, Any]:
    arguments = request.get("arguments")
    intent = (
        arguments.get("businessIntent")
        if isinstance(arguments, Mapping)
        else None
    )
    if work is not None:
        if type(arguments) is not dict or type(intent) is not dict or len(intent) != 4:
            raise AuthorityPlannerError("typed operation business intent is not closed")
        # Prepare the real sorted list and filtered caller-argument dictionary.
        work.prepare_copy(arguments)
        work.prepare_copy(arguments)
    caller_arguments = (
        {
            key: value
            for key, value in sorted(arguments.items())
            if key != "businessIntent"
        }
        if isinstance(arguments, Mapping)
        else None
    )
    spec = authority_contract.operation_spec(operation)
    if work is not None:
        work.prepare_copy(intent)
    if (
        not isinstance(intent, Mapping)
        or set(intent)
            != {
                "schema",
                "operation",
                "planningAdapterId",
                "arguments",
            }
        or _request_different(intent.get("schema"), BUSINESS_INTENT_SCHEMA, work=work)
        or _request_different(intent.get("operation"), operation, work=work)
        or _request_different(intent.get("planningAdapterId"), spec["planningAdapterId"], work=work)
        or not isinstance(intent.get("arguments"), Mapping)
        or caller_arguments is None
    ):
        raise AuthorityPlannerError(
            "typed operation business intent is not closed"
        )
    try:
        expected = (authority_contract.synthesize_business_intent(operation, caller_arguments)
                    if work is None else authority_contract._synthesize_business_intent(
                        operation, caller_arguments, work=work))
    except QueryReadWorkError:
        raise
    except ValueError as exc:
        raise AuthorityPlannerError(
            "typed operation business intent cannot be synthesized"
        ) from exc
    if work is not None:
        work.prepare_copy(intent)
    if _request_different(dict(intent), expected, work=work):
        raise AuthorityPlannerError(
            "typed operation business intent differs from the registry"
        )
    if work is not None:
        work.prepare_copy(intent["arguments"])
    if _request_different(dict(intent["arguments"]), expected["arguments"], work=work):
        raise AuthorityPlannerError(
            "typed operation business intent differs from the registry"
        )
    return intent
