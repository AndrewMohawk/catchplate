"""Exact staged initial-issuance data for pending retirement.

Callers must independently authenticate database rows and current permission.
This module neither verifies a grant/quote nor authorizes mutation or contact.
In particular, minimal issued capture and normalized staged tokens are distinct
originals. A hash from one must never be used to open the other's envelope.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from catchplate import authority_oauth_activation as activation
from catchplate import authority_oauth_activation_policy as enrollment
from catchplate import authority_oauth_exchange as exchange
from catchplate import authority_oauth_measured_exchange as measured
from catchplate import native_oauth_refresh as common
from catchplate.authority_transition_oauth_exchange import _iso, _review


_LIFECYCLE = frozenset({
    "status", "revocation_status", "revocation_error", "revocation_attempts",
    "revocation_next_attempt_at", "revocation_lease_owner",
    "revocation_lease_until", "updated_at",
})
_OWNER_FIELDS = (
    "holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
    "deploymentId", "instanceId", "providerId", "enrollmentSha256",
    "policyHash", "dataPlaneBinarySha256", "callbackOrigin", "portalOrigin",
    "ingressLeafCertificateSha256", "ingressLeafSpkiSha256",
)


def _stored(value, maximum):
    common.require(type(value) is str and value.isascii())
    return common.document(value.encode("ascii"), maximum)


def _arguments(custody, name, operation):
    return measured.arguments(operation, _stored(custody[name], measured.MAX_ARGUMENT_BYTES))


def _same_owner(left, right):
    left, right = left["native_evidence"]["statement"], right["native_evidence"]["statement"]
    common.require(all(left[name] == right[name] for name in _OWNER_FIELDS))


@dataclass(frozen=True, slots=True)
class StagedPendingOriginals:
    """Immutable data only; freely constructible and not an authority token."""

    exchange_original: bytes
    custody_original: bytes
    initial_pending_original: bytes
    enrollment_original: bytes
    stage_arguments_original: bytes
    normalized_envelope_original: bytes
    normalized_token_sha256: str
    provider_id: str
    provider_subject: str
    provider_account: str


def read_staged_pending(exchange_row, custody_row, enrollment_original):
    """Join exact authenticated-row data without inventing refresh history."""
    history, custody = dict(exchange_row), dict(custody_row)
    history_raw = exchange.row_original(history)
    custody_raw = measured.row_original(custody)
    original = activation.enrollment_bytes(enrollment_original)
    application = enrollment.enrollment_document(original)["payload"]
    association = enrollment.association(original)
    common.require(history["status"] == custody["status"] == "staged"
        and history["id"] == custody["id"]
        and history["provider_id"] == application["providerId"]
        and history["enrollment_original"] == enrollment_original)

    preparation = _arguments(custody, "preparation_arguments_json", measured.OP_PREPARE)
    claim = _arguments(custody, "claim_arguments_json", measured.OP_CLAIM)
    capture = _arguments(custody, "capture_arguments_json", measured.OP_CAPTURE)
    stage = _arguments(custody, "stage_arguments_json", measured.OP_STAGE)
    consent = _stored(history["consent_json"], measured.MAX_ARGUMENT_BYTES)
    common.require(consent == preparation["request"])
    # Historical request commitments include the original operation manifest.
    # Never recompute them using the currently loaded manifest or invent an
    # old manifest from these rows. Their authentication belongs to the actual
    # protected row/receipt owner, not this data-only projection.
    common.digest(custody["prepare_request_digest"])
    common.digest(history["claim_request_digest"])
    for arguments in (preparation, claim, capture, stage):
        common.require(arguments["resource_id"] == history["id"]
            and arguments["request"]["exchangeId"] == history["id"]
            and arguments["actor_id"] == history["requester_id"]
            and arguments["enrollment_original"] == enrollment_original
            and common.canonical(arguments["credential_policy"]).decode("ascii") == history["credential_policy_json"]
            and arguments["request"]["limits"] == consent["limits"])
    _same_owner(preparation, claim)
    _same_owner(preparation, capture)
    common.require(claim["request"]["ownerNonceSha256"] == custody["owner_nonce_sha256"]
        == common.sha(common.decoded(capture["request"]["ownerNonce"], 32, 32))
        and capture["assignment_original"] == claim["assignment_original"]
        and history["code_sha256"] == claim["request"]["codeSha256"]
        and history["contact_request_sha256"] == claim["request"]["contactRequestSha256"]
        and custody["received_at_epoch_ns"] == capture["request"]["receivedAtEpochNs"]
        and history["raw_response_sha256"] == capture["request"]["rawResponseSha256"]
        and history["raw_response_envelope_json"] == common.canonical(capture["request"]["rawResponseEnvelope"]).decode("ascii")
        and history["token_secret_sha256"] == capture["request"]["issuedMaterialSha256"]
        and capture["request"]["issuedMaterialEnvelope"] is not None
        and history["token_envelope_json"] == common.canonical(capture["request"]["issuedMaterialEnvelope"]).decode("ascii"))

    request = stage["request"]
    if request["recoveryRequestDigest"] is None:
        common.require(custody["recovery_request_digest"] is None
            and stage["assignment_original"] == claim["assignment_original"]
            and common.sha(common.decoded(request["ownerNonce"], 32, 32)) == custody["owner_nonce_sha256"])
        _same_owner(preparation, stage)
    else:
        recovery = _arguments(custody, "recovery_arguments_json", measured.OP_RECOVER)
        common.require(request["recoveryRequestDigest"] == custody["recovery_request_digest"]
            and recovery["resource_id"] == history["id"]
            and recovery["actor_id"] == history["requester_id"]
            and recovery["enrollment_original"] == enrollment_original
            and common.canonical(recovery["credential_policy"]).decode("ascii") == history["credential_policy_json"]
            and recovery["request"]["limits"] == consent["limits"]
            and recovery["request"]["captureInputSha256"] == common.sha(custody["capture_arguments_json"].encode("ascii"))
            and recovery["request"]["ownerNonceSha256"] == custody["recovery_owner_nonce_sha256"]
            == common.sha(common.decoded(request["ownerNonce"], 32, 32))
            and recovery["request"]["expiresAtEpochNs"] == custody["recovery_expires_at_epoch_ns"]
            and stage["assignment_original"] == recovery["assignment_original"])
        _same_owner(recovery, stage)

    pending = _stored(custody["pending_original_json"], activation.MAX_PENDING_BYTES)
    pending_raw = activation.pending_original(pending)
    metadata = _review(request, consent, application, association)
    common.require(pending["id"] == history["id"]
        and pending["requester_id"] == history["requester_id"]
        and pending["kind"] == "oauth2" and pending["credential_version"] == 1
        and pending["status"] == "pending" and pending["revocation_attempts"] == 0
        and pending["name"] == consent["credentialName"]
        and pending["target_credential_id"] is None and pending["target_credential_version"] is None
        and all(pending[name] is None for name in _LIFECYCLE - {"status", "revocation_attempts", "updated_at"})
        and pending["metadata"] == common.canonical(metadata).decode("ascii")
        and pending["review_json"] == common.canonical(request["review"]).decode("ascii")
        and pending["payload_digest"] == request["payloadDigest"]
        and pending["expires_at"] == _iso(consent["pendingExpiresAtEpochNs"])
        and pending["created_at"] == pending["updated_at"]
        and exchange.timestamp(history["created_at"]) <= exchange.timestamp(pending["created_at"])
            < exchange.timestamp(pending["expires_at"]))
    envelope = {name: pending[name] for name in exchange.ENVELOPE_FIELDS}
    exchange.envelope(envelope)
    common.require(envelope == request["tokenEnvelope"])
    # request.tokenSecretSha256 commits the normalized staged material. The
    # capture's issuedMaterialSha256 deliberately has no equality join here.
    common.digest(request["tokenSecretSha256"])
    return StagedPendingOriginals(history_raw, custody_raw, pending_raw, original,
        custody["stage_arguments_json"].encode("ascii"), common.canonical(envelope),
        request["tokenSecretSha256"], application["providerId"],
        metadata["provider_subject"], metadata["provider_account"])


def current_pending_before_claim(originals, pending_row, *, database_now, reason):
    """Return exact pre-claim row bytes, not retirement or provider permission.

    A future controlled kernel must authenticate these rows, consume the
    independent grant and actual affected-lineage drains, and fence pending,
    family and affected credentials atomically before any helper contact.
    """
    common.require(type(originals) is StagedPendingOriginals
        and isinstance(database_now, datetime) and database_now.tzinfo is not None
        and database_now.utcoffset() == timedelta(0)
        and reason in {"cancelled", "expired", "rejected"})
    initial = common.document(originals.initial_pending_original, activation.MAX_PENDING_BYTES)
    activation.pending_original(initial)
    pending = dict(pending_row)
    raw = activation.pending_original(pending)
    common.require(all(type(pending[name]) is type(initial[name]) and pending[name] == initial[name]
        for name in activation.PENDING_FIELDS - _LIFECYCLE))
    common.require(pending["status"] in {"pending", reason}
        and pending["revocation_status"] in {None, "pending"}
        and pending["revocation_attempts"] == 0
        and all(pending[name] is None for name in ("revocation_error", "revocation_lease_owner", "revocation_lease_until"))
        and exchange.timestamp(initial["created_at"]) <= exchange.timestamp(pending["updated_at"]) <= database_now)
    if reason == "expired":
        common.require(exchange.timestamp(pending["expires_at"]) <= database_now)
    if pending["revocation_next_attempt_at"] is not None:
        common.require(exchange.timestamp(pending["revocation_next_attempt_at"]) <= database_now)
    return raw
