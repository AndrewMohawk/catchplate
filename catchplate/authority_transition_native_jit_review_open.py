"""Original-replaying protected review effects, never disclosure or commit.

The public entrypoint invokes the fixed current-read replay and fresh native
proof verifier itself. A supplied successful carrier, actor, review digest or
unsigned root observation cannot replace those originals. Configuration and
root keys still belong to the independently admitted measured service owner.
Only an actual completed successor transaction and current-root completion may
produce the distinct disclosure acknowledgment. No signing API exists here.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
import json

from catchplate import authority_audit_capacity as audit_capacity
from catchplate import authority_contract as authority
from catchplate import authority_native_jit_retained_history as history
from catchplate import authority_native_jit_review_open_contract as wire
from catchplate import authority_native_jit_review_open_custody as custody
from catchplate import authority_native_jit_retention_contract as storage
from catchplate import authority_oidc_session_activation as session_support
from catchplate import authority_request_commitment as commitment
from catchplate import authority_revocation_configuration as configuration_capture
from catchplate import authority_transition_core as core
from catchplate import authority_transition_oidc_session_activation as activation
from catchplate import authority_transition_quota as quota

AUTHORIZE_RESULT = "catchplate.nativeJitReviewAuthorizeEffects/v1"
RECEIPT_RESULT = "catchplate.nativeJitReviewReceiptEffects/v1"
RECEIPT_PURPOSE = "native-jit-review-opening-receipt"
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class NativeJitReviewKernel:
    """Registered source dispatch only, never a configured authority owner."""

    operation: str

    def __post_init__(self):
        _require(self.operation in wire.OPERATIONS)

    def evaluate_on_work(self, **original_invocation):
        return evaluate_on_work(operation=self.operation, **original_invocation)


def _require(condition):
    if not condition:
        raise core.TransitionKernelError("Protected native review authority is unavailable")


def _same(left, right):
    _require(core.canonical_bytes(left) == core.canonical_bytes(right))


def _sha(original):
    _require(type(original) is str and original.isascii())
    return wire.grammar.sha256(original.encode("ascii"))


def _time(value, work):
    return session_support._time(value, "native review current timestamp", work)


def _row(context, table, key):
    selected = context.exact(table, key)
    _require(selected["present"] is True and type(selected["row"]) is dict)
    return selected["row"]


def _subset(context, tables):
    # Only already proof-replayed rows, never a replacement authentication API.
    return core.KernelContext(context.operation, context.arguments,
        tuple(item for item in context.selected_rows if item["table"] in tables),
        context.database_now, context.request_digest, query_reads=context.query_reads)


def _arguments(request, operation, work):
    _require(type(request) is dict and set(request) == {"schema", "operation", "operationId",
        "requestDigest", "handler", "operationManifestDigest", "arguments"})
    _require(operation in wire.OPERATIONS and request["operation"] == operation
        and request["schema"] == "catchplate.policyAuthorityV9Request/v1"
        and request["operationManifestDigest"] == authority.OPERATION_MANIFEST_DIGEST
        and request["handler"] == authority.operation_spec(operation)["handler"])
    values = request["arguments"]
    wire.grammar.require(type(values) is dict and set(values) ==
        (wire.AUTHORIZE_ARGUMENTS if operation == wire.AUTHORIZE else wire.RECEIPT_ARGUMENTS))
    for name in ("approval_request_id", "session_id"):
        wire.grammar.text(values[name], 128)
    for name in set(values) - {"approval_request_id", "session_id", "businessIntent"}:
        wire.grammar.digest(values[name])
    semantic = {name: value for name, value in values.items() if name != "businessIntent"}
    _same(values["businessIntent"], authority._synthesize_business_intent(operation, semantic, work=work))
    _same(request["requestDigest"], commitment._typed_request_digest(request, work=work))
    _same(request["operationId"], commitment.operation_id(operation, request["requestDigest"]))
    return values


def _current_reviewer(context, *, token_original, authn_policy, trust_policy, work):
    """Derive reviewer from actual possession and fresh authenticated raw rows."""
    token = session_support._token(token_original, work)
    session = _row(context, "oidc_browser_sessions", {"id": context.arguments["session_id"]})
    _require(set(session) == session_support._SESSION_FIELDS)
    session_support._row_text(session, integers={"activation_trust_bundle_sequence"},
        nullable={"pending_expires_at", "revoked_at", "revocation_reason"}, work=work)
    _require(session["status"] == "active" and session["pending_expires_at"] is None
        and session["revoked_at"] is None and session["revocation_reason"] is None)
    _same(session["token_digest"], session_support._digest(token, work))
    wire.grammar.digest(session["oidc_token_digest"])
    _require(session["user_id"].startswith("oidc:"))
    credential = _row(context, "webauthn_credentials", {"id": session["bound_webauthn_credential_id"]})
    _require(set(credential) == session_support._CREDENTIAL_FIELDS
        and credential["user_id"] == session["user_id"])
    session_support._row_text(credential,
        integers={"sign_count", "attestation_trusted", "attestation_trust_bundle_sequence"},
        nullable={"dev_private_key_pem", "last_used_at", "revoked_at", "revoked_by", "revocation_reason", "revocation_source",
            "attestation_trust_bundle_digest", "attestation_trust_bundle_sequence"}, work=work)
    for field in ("dev_private_key_pem", "revoked_at", "revoked_by", "revocation_reason", "revocation_source"):
        _require(credential[field] is None)
    wire.grammar.integer(credential["sign_count"], minimum=0, maximum=2**32 - 1)
    wire.grammar.decoded(credential["public_key_cose"], 4096)
    now = quota._database_epoch_ns(context.database_now)
    created, activated, updated, expires, provider = (_time(session[field], work) for field in
        ("created_at", "activated_at", "updated_at", "expires_at", "provider_expires_at"))
    _require(created <= activated <= updated <= now < expires <= provider)
    _require(_time(credential["created_at"], work) <= _time(credential["updated_at"], work) <= now)
    _require(_time(credential["attestation_verified_at"], work) <= now)
    if credential["last_used_at"] is not None:
        _require(_time(credential["last_used_at"], work) <= now)
    activation._rbac_scope(_subset(context, {"rbac_authority_state", "rbac_role_bindings"}),
        session, session["user_id"], now, work)
    roles = activation._roles(session["roles_json"], work)
    _require(bool({"approver", "admin"}.intersection(roles)))
    _current_trust_scope(context, trust_policy, now, work)
    trust = session_support._current_trust(credential, authn_policy, trust_policy, work)
    # Unlike activation-token delivery, review preserves the active browser's
    # strict generation equality; an older activation is not silently upgraded.
    _same((session["activation_trust_bundle_digest"], session["activation_trust_bundle_sequence"],
        session["activation_authenticator_class"]), (trust_policy["currentBundleDigest"],
        trust_policy["currentBundleSequence"], trust.effective_authenticator_class))
    return session, credential, roles, min(expires, provider)


def _current_trust_scope(context, policy, now, work):
    """Same activation metadata joins without copying opaque 12 MiB literals.

    Full publication bytes were independently primary-proof authenticated by
    this call's read replay. They remain unchanged in the acquired originals;
    this computation does not parse or substitute a caller trust bundle. The
    complete signed trust policy must be admitted by the measured owner.
    """
    trust = activation.registration.trust
    high = _row(context, trust.HIGH_WATER_TABLE, {"authority_scope": trust.AUTHORITY_SCOPE})
    publications = context.present_rows(trust.PUBLICATION_TABLE)
    _require(set(high) == activation._HIGH_FIELDS and len(publications) == 1)
    publication = publications[0]["row"]
    _require(type(publication) is dict and set(publication) == activation._PUBLICATION_FIELDS)
    document = trust.high_water_document(rollback_epoch=high["rollback_epoch"],
        sequence=high["publication_sequence"], publication_digest=high["publication_digest"],
        metadata_blob_digest=high["metadata_blob_digest"], revocation_set_digest=high["revocation_set_digest"],
        witness_receipt_digest=high["witness_receipt_digest"], witness_sequence=high["witness_sequence"])
    wire.grammar.integer(high["updated_at_epoch_ns"])
    wire.grammar.integer(publication["rollback_epoch"], minimum=0)
    wire.grammar.integer(publication["sequence"])
    _require(high["authority_scope"] == trust.AUTHORITY_SCOPE and high["updated_at_epoch_ns"] <= now)
    _same((publication["scope"], publication["status"], publication["bundle_digest"],
        publication["payload_digest"], publication["rollback_epoch"], publication["sequence"]),
        ("global", "published", high["publication_digest"], high["metadata_blob_digest"],
         high["rollback_epoch"], high["publication_sequence"]))
    _same((policy.get("currentBundleDigest"), policy.get("currentBundleSequence")),
        (high["publication_digest"], high["publication_sequence"]))
    for field in ("created_at", "published_at"):
        _require(_time(publication[field], work) <= now)
    return trust.high_water_digest(document, work=work)


def _history_scope(context, *, session, credential, roles, session_expiry, challenge,
        challenge_original, work):
    approval = _row(context, "approval_requests", {"id": context.arguments["approval_request_id"]})
    retained = _row(context, storage.TABLE, {"approval_request_id": approval["id"]})
    now = quota._database_epoch_ns(context.database_now)
    # This is bounded historical consistency after the entrypoint's genuine
    # primary/current-root replay; the parser itself supplies no admission.
    work.prepare_encoding(retained)
    parent, child, pair, _proof = history.historical_retained_documents(
        retained_row=retained, approval_row=approval, now_epoch_ns=now)
    policy, _policy_digest = quota._stored_jit_policy(approval)
    _require(policy["allowAnyApproverId"] is True or session["user_id"] in policy["allowedApproverIds"])
    _require(not policy["requiredRoles"] or bool(set(policy["requiredRoles"]).intersection(roles)))
    high = _row(context, "policy_high_water", {"scope": "global"})
    _same(high["policy_hash"], approval["policy_hash"])
    _same(challenge["approvalRequestId"], approval["id"])
    _same(challenge["identity"]["policyHash"], approval["policy_hash"])
    assignment = custody.parse_assignment_original(
        wire.validate_challenge_original(challenge_original)["assignmentOriginal"])["payload"]
    scope = {name: challenge[name] for name in ("reviewId", "approvalRequestId", "sourceContractDigest",
        "controlPlaneConfigurationDigest", "openingAssignmentSha256", "ownerScopeDigest",
        "browserNonceCommitment", "recipientPublicKey")}
    scope.update({"reviewerId": session["user_id"], "sessionId": session["id"],
        "credentialRecordId": credential["id"], "challengeSha256": _sha(challenge_original),
        "parentOriginalSha256": _sha(retained["parent_request_original"]),
        "childOriginalSha256": _sha(retained["child_request_original"]),
        "pairSha256": _sha(retained["pair_original"]), "sealProofSha256": _sha(retained["proof_original"]),
        "sealedSourceContractDigest": parent["operationManifestDigest"],
        "documentExpiresAtEpochNs": retained["document_expires_at_epoch_ns"],
        "approvalExpiresAtEpochNs": _time(approval["expires_at"], work),
        "sessionExpiresAtEpochNs": session_expiry,
        "assignmentExpiresAtEpochNs": assignment["expiresAtEpochNs"]})
    wire.validate_scope(scope)
    _same(pair["items"][1]["plaintextSha256"], child["arguments"]["redacted_display_digest"])
    return scope, child["arguments"]["redacted_display_digest"]


def _receipt_effects(context, *, scope, authorization_original, preparation_original,
        review_digest, expires, work):
    # The real shared finalizer needs only these four authenticated rows. Do
    # not repeatedly copy unrelated retained ciphertext/trust-publication rows
    # into its unchanged 64 MiB work stage.
    context = _subset(context, {"approval_review_receipts", "metadata_audit_outbox",
        audit_capacity.AGGREGATE_TABLE})
    _require(len(context.selected_rows) == 4)
    receipt_id = core.deterministic_uuid(operation=wire.RECEIPT,
        request_digest=context.request_digest, purpose=RECEIPT_PURPOSE)
    selected = context.exact("approval_review_receipts", {"id": receipt_id})
    # Historical completion belongs to the real retained execution owner. An
    # existing receipt is never turned into a fresh plan, ACK or renewed TTL.
    _require(selected["present"] is False and selected["row"] is None)
    now = quota._database_epoch_ns(context.database_now)
    expires = expires // 1000 * 1000
    _require(now < expires)
    receipt = {"id": receipt_id, "approval_request_id": scope["approvalRequestId"],
        "reviewer_id": scope["reviewerId"], "review_digest": review_digest,
        "expires_at": (_EPOCH + timedelta(microseconds=expires // 1000)).isoformat(),
        "used_at": None, "created_at": context.database_now.astimezone(timezone.utc).isoformat()}
    result = {"schema": RECEIPT_RESULT, "operation": wire.RECEIPT, "requestDigest": context.request_digest,
        "authorizationSha256": _sha(authorization_original), "preparationSha256": _sha(preparation_original),
        "scope": scope, "reviewDigest": review_digest, "receiptId": receipt_id,
        "receiptExpiresAtEpochNs": expires, "expiresAtEpochNs": expires, "canDecide": False}
    event = {"schema": "catchplate.nativeJitReviewOpeningReceiptAudit/v1",
        "reviewId": scope["reviewId"], "approvalRequestId": scope["approvalRequestId"],
        "sessionId": scope["sessionId"], "challengeSha256": scope["challengeSha256"],
        "authorizationSha256": result["authorizationSha256"], "preparationSha256": result["preparationSha256"],
        "scopeSha256": wire.grammar.sha256(core.canonical_bytes(scope)),
        "reviewDigest": review_digest, "receiptId": receipt_id, "expiresAtEpochNs": expires}
    audit, _audit_digest, replay = quota._audit_mutations(context,
        event_type="approval.review_prepared", actor_type="admin", actor_id=scope["reviewerId"], event=event)
    _require(replay is False and len(audit) == 1)
    aggregate_id = quota._aggregate_key("jit-review-receipts", "global")[0]
    old_capacity = _row(context, audit_capacity.AGGREGATE_TABLE, {"aggregate_id": aggregate_id})
    minimum = old_capacity["minimum_expiry_epoch_ns"]
    business = (core.mutation(operation=wire.RECEIPT, selected=selected, row=receipt),
        quota._aggregate_update(context, kind="jit-review-receipts", partition="global", live_delta=1,
            active_delta=1, next_sequence_delta=1,
            minimum_expiry_epoch_ns=expires if minimum is None else min(minimum, expires))) + audit
    effects = audit_capacity._finalize_capacity(context, business, work=work)
    _require(len(effects) == 4)
    total_work = audit_capacity.transition_work_units(wire.RECEIPT,
        query_work_units=13, kernel_work_units=8 + 12 + 4 * len(business), mutations=effects)
    return core.KernelTransition(tuple(sorted(effects,
        key=lambda value: (value["table"], value["keyDigest"], value["operation"]))), result, total_work)


def evaluate_on_work(*, operation, request, read_originals, session_token_original,
        challenge_original, configuration_payload, configuration_root_key, current_root_public_key,
        current_root_enrollment_original, authn_policy, trust_policy, live_window, read_budget, work,
        authorization_original=None, preparation_original=None):
    """Replay real admitted originals and derive effects; never sign a grant/ACK."""
    effects, _reads = _evaluate_with_reads_on_work(operation=operation, request=request,
        read_originals=read_originals, session_token_original=session_token_original,
        challenge_original=challenge_original, configuration_payload=configuration_payload,
        configuration_root_key=configuration_root_key, current_root_public_key=current_root_public_key,
        current_root_enrollment_original=current_root_enrollment_original, authn_policy=authn_policy,
        trust_policy=trust_policy, live_window=live_window, read_budget=read_budget, work=work,
        authorization_original=authorization_original, preparation_original=preparation_original)
    return effects


def _evaluate_with_reads_on_work(*, operation, request, read_originals, session_token_original,
        challenge_original, configuration_payload, configuration_root_key, current_root_public_key,
        current_root_enrollment_original, authn_policy, trust_policy, live_window, read_budget, work,
        authorization_original=None, preparation_original=None):
    """Keep same-call authenticated inputs for the actual plan owner's writer.

    This still invokes original replay itself. Neither a read verdict nor a
    precomputed transition is an input; returned observations are not authority.
    """
    from catchplate import authority_native_jit_review_current_read as reader
    from catchplate.authority_policy_canary_policy import full_configuration_digest

    _require(operation in wire.OPERATIONS and type(request) is dict)
    _require(type(read_budget) is reader.NativeJitReviewReadBudget and read_budget.parent_work is work
        and read_budget.live_window is live_window and read_budget.operation == operation)
    if operation == wire.AUTHORIZE:
        _require(authorization_original is None and preparation_original is None)
    with read_budget.stage("input-capture") as stage:
        wire.validate_challenge_original(challenge_original)
        if operation == wire.RECEIPT:
            wire.validate_authorization_original(authorization_original)
            wire.validate_preparation_original(preparation_original)
        # Requests and reviewer policies retain the strict, integer-only work
        # grammar. Only the separately admitted configuration permits finite
        # fractional timeouts; never rewrite its signed values or commitment.
        graph = {"request": request, "authn": authn_policy, "trust": trust_policy}
        stage.prepare_encoding(graph)
        captured = wire.grammar.document(core.canonical_bytes(graph).decode("ascii"), authority.MAX_REQUEST_BYTES)
        ledger = configuration_capture.capability.capture._SharedLedger(stage)
        captured["configuration"] = configuration_capture._ConfigurationCapture(
            ledger, maximum_bytes=authority.MAX_REQUEST_BYTES).visit(configuration_payload)
        # Keep the original aggregate graph byte/depth bounds after detaching
        # both branches. The configuration encoder does not relax other inputs.
        original = configuration_capture._configuration_wire(captured, ledger)
        stage.charge(input_bytes=3 * len(original))
        captured = wire.grammar.document(original.decode("ascii"), authority.MAX_REQUEST_BYTES)
        request, configuration_payload = captured["request"], captured["configuration"]
        authn_policy, trust_policy = captured["authn"], captured["trust"]
    # The raw token is sent only to actual same-call replay and possession
    # checking. It is not copied into typed requests, results or audit records.
    acquired = reader.admit_original_reads_on_work(read_originals, request=request,
        session_token_original=session_token_original, root_public_key=current_root_public_key,
        enrollment_original=current_root_enrollment_original, live_window=live_window,
        work=work, budget=read_budget)
    with read_budget.stage("native-challenge") as stage:
        values = _arguments(request, operation, stage)
        _same(values["challenge_sha256"], _sha(challenge_original))
        now = quota._database_epoch_ns(acquired.database_now)
        proof = custody.verify_native_original(challenge_original, purpose="challenge",
            configuration_payload=configuration_payload, root_key=configuration_root_key,
            now_epoch_ns=now, deadline_monotonic_ns=read_budget.deadline_ns)
        challenge = proof["statement"]
        _same(challenge["sourceContractDigest"], authority.OPERATION_MANIFEST_DIGEST)
        _same(challenge["controlPlaneConfigurationDigest"], full_configuration_digest(configuration_payload))
    context = core.KernelContext(operation, values, acquired.selected_rows, acquired.database_now,
        request["requestDigest"], query_reads=acquired.query_reads)
    _require(len(context.selected_rows) == (9 if operation == wire.AUTHORIZE else 13))
    with read_budget.stage("current-reviewer") as stage:
        session, credential, roles, expiry = _current_reviewer(context, token_original=session_token_original,
            authn_policy=authn_policy, trust_policy=trust_policy, work=stage)
    with read_budget.stage("retained-history") as stage:
        scope, display_digest = _history_scope(context, session=session, credential=credential,
            roles=roles, session_expiry=expiry, challenge=challenge, challenge_original=challenge_original, work=stage)
    # The exact final nonce-bound head was independently verified by replay.
    # Both grant and committing receipt retain its original shorter interval.
    head = json.loads(acquired.head_observation_original)["payload"]
    _require(head["pendingRequestDigest"] is None and head["pendingDecisionDigest"] is None)
    expires = min(wire.scope_expiry(scope), challenge["expiresAtEpochNs"], head["expiresAtEpochNs"],
        live_window[3], live_window[0] + read_budget.deadline_ns - live_window[1])
    _require(now < expires)
    if operation == wire.AUTHORIZE:
        with read_budget.stage("receipt-effects") as stage:
            _require(session_support.clock._check_on_work(live_window, work=stage) < expires)
            return core.KernelTransition((), {"schema": AUTHORIZE_RESULT, "operation": operation,
                "requestDigest": context.request_digest, "scope": scope,
                "currentRootVectorDigest": head["vectorDigest"], "currentRootHeadDigest": head["headDigest"],
                "currentRootSequence": head["sequence"], "issuedAtEpochNs": now,
                "expiresAtEpochNs": expires, "canDecide": False}, 9 + 8 + 9), acquired
    with read_budget.stage("native-preparation") as stage:
        _same(values["authorization_sha256"], _sha(authorization_original))
        _same(values["preparation_sha256"], _sha(preparation_original))
        policy = custody.validate_policy(configuration_payload.get(custody.FIELD),
            payload=configuration_payload, root_key=configuration_root_key)
        authorization = wire.verify_authorization_original(authorization_original,
            public_key=custody.purpose_key(policy["authorizerKey"]), now_epoch_ns=now)["payload"]
        preparation = custody.verify_native_original(preparation_original, purpose="preparation",
            configuration_payload=configuration_payload, root_key=configuration_root_key,
            now_epoch_ns=now, deadline_monotonic_ns=read_budget.deadline_ns)["statement"]
        _same(authorization["scope"], scope)
        _same(preparation["scope"], scope)
        _same(preparation["identity"], challenge["identity"])
        _same(preparation["authorizationSha256"], _sha(authorization_original))
        _same(preparation["reviewDigest"], display_digest)
        _require(authorization["issuedAtEpochNs"] <= preparation["preparedAtEpochNs"] <= now
            and preparation["expiresAtEpochNs"] <= authorization["expiresAtEpochNs"])
        expires = min(expires, authorization["expiresAtEpochNs"], preparation["expiresAtEpochNs"])
    with read_budget.stage("receipt-effects") as stage:
        _require(session_support.clock._check_on_work(live_window, work=stage) < expires)
        result = _receipt_effects(context, scope=scope, authorization_original=authorization_original,
            preparation_original=preparation_original, review_digest=display_digest, expires=expires, work=stage)
        _require(session_support.clock._check_on_work(live_window, work=stage) < expires)
        return result, acquired
