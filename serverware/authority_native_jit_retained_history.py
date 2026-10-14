"""Historical retained-pair consistency, never read or opening authority.

The caller must independently authenticate BOTH selected rows against current
roots and authorize the current reviewer. This parser verifies no signature,
attestation, database provenance or current authority. Original sealing was
admitted before retention; its expired seal window must not be renewed or
reverified as fresh opening evidence. Fresh disclosure has a separate purpose.

The only supported historical source is the explicit v349 profile below. Its
requests keep their original manifest, handlers, intents and literal bytes.
There is no installed-manifest comparison, configurable compatibility list,
private runtime input, key loading, decryption, resealing or persistence here.
The returned four parsed documents are owned data, not an admission token;
future signatures must still hash the four ORIGINAL strings in the row.

Shared dependencies are fixed-v2 material/evidence grammar, scalar commitment
primitives, JIT policy normalization and the pure pending-row projection. Their
compatibility remains covered by the independently framed historical fixture;
no live authority request constructor or business-intent synthesizer is used.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from serverware import authority_jit_request as jit
from serverware import authority_native_jit_retention_contract as storage
from serverware import authority_native_jit_review_assignment as grammar
from serverware import authority_native_jit_review_custody as custody
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as quota
from serverware import native_jit_review_material as material


SEALED_MANIFEST = "sha256:b708d9f97ca989abf0411054bbc23d02262fb5a67bcab345246650a925e776e0"
SEALED_SOURCE_REVISION = "serverware.policyCandidateAuthoritySource/2026-07-30.349"
ERROR = "Native JIT retained history is unavailable"
_REQUEST_FIELDS = frozenset({"schema", "operation", "operationId", "requestDigest",
    "handler", "operationManifestDigest", "arguments"})
_INHERITED = frozenset({"route_id", "principal_id", "credential_id", "credential_version",
    "policy_hash", "request_digest", "operation_digest", "required_approver_roles",
    "allowed_approver_ids", "require_approver_webauthn", "approval_threshold", "approver_credential_policy"})
_COMMITMENTS = frozenset({"url_commitment", "canonical_request_digest",
    "redacted_display_digest", "original_arguments_digest"})
_CHILD_FIELDS = _INHERITED | _COMMITMENTS | {"schema", "method", "pending_ttl_seconds",
    "grant_ttl_seconds", "grant_max_uses"}
_PARENT_FIELDS = _INHERITED | {"schema", "original_arguments_digest", "attempt_id", "flow_id",
    "operation_context", "shared_quotas", "require_jit_grant", "reservation_ttl_seconds",
    "durable_policy_binding", "jit_approval_request", "now_epoch_ms", "actor_id",
    "authority_policy_hash", "authority_route_id", "native_profile", "policy_aware_profile",
    "expected_approver_policy_sha256"}
_CREDENTIAL_FIELDS = frozenset({"allowedCredentialRecordIds", "allowedAuthenticatorClasses",
    "allowedAaguids", "requireAttestationTrusted", "requiredTrustBundleDigest",
    "minimumTrustBundleSequence", "counterPolicy", "maxAssertionAgeSeconds", "rpId", "origins",
    "requireUserPresence", "requireUserVerification"})
_KINDS = ("approval-secret-json/v1", "approval-review-json/v1")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class RetainedHistoryError(ValueError):
    def __init__(self):
        super().__init__(ERROR)


def _require(value):
    if not value:
        raise RetainedHistoryError()


def _same(left, right):
    _require(core.canonical_bytes(left) == core.canonical_bytes(right))


def _request(value, operation, handler, fields):
    _require(type(value) is dict and set(value) == _REQUEST_FIELDS
        and value["schema"] == "serverware.policyAuthorityV9Request/v1"
        and value["operation"] == operation and value["handler"] == handler
        and value["operationManifestDigest"] == SEALED_MANIFEST)
    arguments = value["arguments"]
    _require(type(arguments) is dict and set(arguments) == fields | {"businessIntent"})
    public = {name: arguments[name] for name in fields}
    _same(arguments["businessIntent"], {"schema": "serverware.policyAuthorityBusinessIntent/v2",
        "operation": operation, "planningAdapterId": "serverware.policyAuthorityPlanningAdapter/" + handler + "/v1",
        "arguments": public})
    authorization = {"schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": handler, "operationManifestDigest": SEALED_MANIFEST, "arguments": arguments}
    digest = core.framed_digest("serverware.policyAuthorityV9Request/v1", core.canonical_bytes(authorization))
    _require(value["requestDigest"] == digest and value["operationId"] == core.framed_digest(
        "serverware.policyAuthorityOperation/v2", operation.encode("ascii"), digest.encode("ascii")))
    return public


def _requests(parent, child):
    public = _request(parent, "release.reserve", "reserve_release_authorization_v2", _PARENT_FIELDS)
    nested = _request(child, "jit.request", "ensure_jit_approval_request", _CHILD_FIELDS)
    _require(public["schema"] == "serverware.releaseReserveCommitments/v1"
        and nested["schema"] == "serverware.jitRequestCommitments/v2"
        and public["native_profile"] is True and public["policy_aware_profile"] is False
        and public["require_jit_grant"] is True and public["now_epoch_ms"] is None)
    _same(public["jit_approval_request"], nested)
    for name in _INHERITED:
        _same(public[name], nested[name])
    for name in _COMMITMENTS | {"policy_hash", "request_digest"}:
        grammar.digest(nested[name])
    if nested["operation_digest"] is not None:
        grammar.digest(nested["operation_digest"])
    for name in ("attempt_id", "flow_id", "original_arguments_digest"):
        grammar.digest(public[name])
    _require(public["attempt_id"] == public["flow_id"])
    grammar.integer(public["reservation_ttl_seconds"], maximum=300)
    core.require_text(public["actor_id"], "historical actor", maximum_bytes=256)
    for name in ("route_id", "credential_id", "principal_id", "method"):
        core.require_text(nested[name], "historical child identity", maximum_bytes=
            32 if name == "method" else 512 if name == "principal_id" else 256,
            allow_empty=name == "credential_id")
    _require(nested["method"] == nested["method"].upper())
    grammar.integer(nested["credential_version"], minimum=0)
    for name in ("pending_ttl_seconds", "grant_ttl_seconds", "grant_max_uses"):
        grammar.integer(nested[name], maximum=1_000_000 if name == "grant_max_uses" else 3600)
    credential = nested["approver_credential_policy"]
    _require(type(credential) is dict and {"rpId", "origins"} <= set(credential) <= _CREDENTIAL_FIELDS)
    policy = jit._policy(nested)  # Policy grammar only, never current policy admission.
    policy_raw = core.canonical_bytes(policy)
    _require(public["expected_approver_policy_sha256"] == grammar.sha256(policy_raw))
    _require((public["authority_policy_hash"], public["authority_route_id"]) in (
        (None, None), (public["policy_hash"], public["route_id"])))
    _require(type(public["operation_context"]) is dict
        and len(core.canonical_bytes(public["operation_context"])) <= 65536
        and type(public["shared_quotas"]) is list and len(public["shared_quotas"]) <= 12
        and all(type(item) is dict for item in public["shared_quotas"])
        and type(public["durable_policy_binding"]) is dict
        and public["durable_policy_binding"].get("actorId") == public["actor_id"])
    return {**nested, "approver_policy": policy,
        "approver_policy_digest": core.framed_digest("serverware.jitApproverPolicy/v1", policy_raw)}


def _pair_bindings(row, parent, child, pair, proof):
    _require(type(pair) is dict and set(pair) == material.PAIR_FIELDS
        and pair["schema"] == "serverware.nativeJitReviewPair/v2")
    scope = material.validate_release_scope(pair["scope"])
    statement = proof["statement"]
    _same(scope["publicRequest"], child)
    expected = {"sourceContractDigest": SEALED_MANIFEST,
        "parentRequestSha256": grammar.sha256(row["parent_request_original"].encode("ascii")),
        "parentRequestDigest": parent["requestDigest"], "parentOperationId": parent["operationId"],
        "requestDigest": child["requestDigest"], "operationId": child["operationId"],
        "publicRequestSha256": grammar.sha256(row["child_request_original"].encode("ascii")),
        "pairSha256": row["pair_sha256"], "secretKekId": pair["keyId"],
        "controlPlaneConfigurationDigest": row["control_plane_configuration_digest"],
        "ownerScopeDigest": row["owner_scope_digest"], "issuedAtEpochNs": row["issued_at_epoch_ns"],
        "expiresAtEpochNs": row["seal_expires_at_epoch_ns"],
        "documentExpiresAtEpochNs": row["document_expires_at_epoch_ns"]}
    for name, value in expected.items():
        _same(statement[name], value)
    for name in ("sourceContractDigest", "parentRequestSha256", "controlPlaneConfigurationDigest",
            "ownerScopeDigest", "issuedAtEpochNs", "documentExpiresAtEpochNs"):
        _same(scope[name], expected[name])
    _same(scope["sealExpiresAtEpochNs"], expected["expiresAtEpochNs"])
    assignment = grammar.original(proof["assignmentOriginal"])["payload"]
    for name in ("sourceContractDigest", "controlPlaneConfigurationDigest", "deploymentId"):
        _same(assignment[name], statement[name])
    for name in custody.IDENTITY_FIELDS | {"instanceId", "secretKekId"}:
        _same(assignment["assignment"][name], statement[name])
    _require(assignment["issuedAtEpochNs"] <= statement["issuedAtEpochNs"]
        < statement["expiresAtEpochNs"] <= assignment["expiresAtEpochNs"]
        and statement["instanceId"] == parent["arguments"]["actor_id"]
        and statement["policyHash"] == parent["arguments"]["policy_hash"])
    _require(type(pair["items"]) is list and len(pair["items"]) == 2)
    for item, kind, purpose in zip(pair["items"], _KINDS,
            ("jit-canonical-request", "jit-redacted-display"), strict=True):
        _require(type(item) is dict and set(item) == material.ITEM_FIELDS
            and item["valueKind"] == kind
            and item["opaqueId"] == material._identity(child["requestDigest"], purpose))
        grammar.digest(item["plaintextSha256"])
        size = grammar.integer(item["plaintextBytes"], maximum=material.MAX_PLAINTEXT_BYTES)
        material._decoded(item["wrappedKeyNonce"], 12, 12)
        material._decoded(item["wrappedKey"], 48, 48)
        material._decoded(item["ciphertextNonce"], 12, 12)
        material._decoded(item["ciphertext"], material.MAX_PLAINTEXT_BYTES + 16, size + 16)
    _require(pair["items"][1]["plaintextSha256"] == child["arguments"]["redacted_display_digest"])


def historical_retained_documents(*, retained_row, approval_row, now_epoch_ns):
    """Return owned parsed originals after consistency checks, NOT authority.

    No clock is sampled. ``now_epoch_ns`` belongs to the caller's independently
    admitted current read; merely passing it and two dictionaries proves none
    of their provenance. An expired sealing/assignment interval is historical,
    but the original pending approval and document must both remain unexpired.
    """
    try:
        _require(type(retained_row) is dict and set(retained_row) == set(storage.COLUMNS))
        row = retained_row
        _require(row["source_contract_digest"] == SEALED_MANIFEST
            and row["source_revision"] == SEALED_SOURCE_REVISION)
        for name in storage.DIGEST_COLUMNS:
            grammar.digest(row[name])
        grammar.kek(row["secret_kek_id"])
        for name in storage.EPOCH_COLUMNS:
            grammar.integer(row[name])
        now = grammar.integer(now_epoch_ns)
        recorded = row["recorded_at_epoch_ns"]
        _require(row["issued_at_epoch_ns"] <= recorded < row["seal_expires_at_epoch_ns"]
            <= row["document_expires_at_epoch_ns"] and recorded <= now < row["document_expires_at_epoch_ns"]
            and recorded % 1000 == 0)
        parent, child, pair = (grammar.document(row[name], storage.ORIGINAL_LIMITS[name]) for name in
            ("parent_request_original", "child_request_original", "pair_original"))
        proof = custody.authority_evidence(row["proof_original"])
        # The original submission bounded the escaped four-string channel as
        # well as individual literals. This does not enlarge a future reader's
        # distinct selected-row/transport/proof aggregate allowance.
        _require(len(core.canonical_bytes({wire: row[column] for wire, column in (
            ("parentOriginal", "parent_request_original"), ("childOriginal", "child_request_original"),
            ("pairOriginal", "pair_original"), ("evidenceOriginal", "proof_original"))})) <= 4 * 1024 * 1024)
        normalized = _requests(parent, child)
        for prefix, document in (("parent", parent), ("child", child)):
            _require(row[prefix + "_request_digest"] == document["requestDigest"]
                and row[prefix + "_operation_id"] == document["operationId"])
        for name in ("pair", "proof"):
            _require(row[name + "_sha256"] == grammar.sha256(row[name + "_original"].encode("ascii")))
        _require(pair["keyId"] == row["secret_kek_id"])
        _pair_bindings(row, parent, child, pair, proof)
        approval_id = core.deterministic_uuid(operation="jit.request",
            request_digest=child["requestDigest"], purpose="jit-approval-request")
        _require(row["approval_request_id"] == approval_id)
        values = [{"ciphertext_base64url": "native-jit:v1:" + core.canonical_bytes({
            "schema": "serverware.nativeJitReviewReference/v1", "approvalRequestId": approval_id,
            "parentRequestDigest": parent["requestDigest"], "pairSha256": row["pair_sha256"],
            "valueKind": kind}).decode("ascii"), "expires_at_epoch_ns": row["document_expires_at_epoch_ns"]}
            for kind in _KINDS]
        projected = quota.jit_pending_projection(normalized, approval_id=approval_id,
            canonical_value=values[0], display_value=values[1],
            database_now=_EPOCH + timedelta(microseconds=recorded // 1000))
        _require(type(approval_row) is dict and set(approval_row) == set(projected.row)
            and all(value is None or type(value) in (str, int) for value in approval_row.values())
            and all(type(value) is not str or len(value) <= 131072 for value in approval_row.values())
            and now < projected.expiry_epoch_ns)
        _same(approval_row, dict(projected.row))
        return parent, child, pair, proof
    except Exception:
        # Neither parser details nor retained private-looking values escape.
        raise RetainedHistoryError() from None
