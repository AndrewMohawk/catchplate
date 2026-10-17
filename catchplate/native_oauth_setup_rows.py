"""Exact Setup rows consumed only after a genuine signed writer response.

These comparisons confer no database or signing authority. The private owner
retains the initial binding and actual committed originals separately; neither
an incremented revision nor a matching digest invents a successful transition.
"""
from datetime import datetime, timezone
from catchplate import native_oauth_refresh as m
from catchplate import native_oauth_exchange as exchange
from catchplate import native_oauth_setup as material

ROW_FIELDS = frozenset({"id", "owner_id", "current_assignee_id", "status", "phase", "revision", "template_id", "principal_id",
    "route_id", "route_policy_digest", "credential_id", "credential_version", "policy_hash", "assignment_digest",
    "oauth_provider", "oauth_state_digest", "oauth_pending_credential_id", "canary_id", "enrollment_session_id",
    "enrollment_packet_digest", "verifier_nonce_hash", "enrollment_verifier_receipt_digest", "enrollment_verifier_key_id",
    "attestation_challenge_digest", "attestation_challenge_issued_at", "attestation_challenge_expires_at",
    "attestation_challenge_value", "runtime_evidence_digest", "hardware_assurance_digest", "hardware_verification_receipt_digest",
    "hardware_verifier_key_id", "release_identity_digest", "current_host_identity_digest", "proxy_server_statement_digest",
    "trust_profile_digest", "completion_identity_digest", "final_authority_key_id", "final_consumption_id", "final_receipt_digest",
    "created_at", "updated_at", "expires_at", "terminal_at"})
REQUIRED = frozenset({"id", "owner_id", "status", "phase", "revision", "created_at", "updated_at", "expires_at"})
CUSTODY_FIELDS = frozenset({"id", "prepare_request_digest", "preparation_arguments_json", "claim_arguments_json",
    "capture_arguments_json", "stage_arguments_json", "cancel_arguments_json", "owner_nonce_sha256",
    "received_at_epoch_ns", "recovery_request_digest", "recovery_expires_at_epoch_ns", "recovery_arguments_json",
    "recovery_owner_nonce_sha256", "pending_original_json", "status", "created_at", "updated_at",
    "setup_initial_json", "setup_started_json", "setup_final_json"})
MAX_ROW = 64 * 1024


def epoch(value):
    m.require(type(value) is str)
    stamp = datetime.fromisoformat(value)
    m.require(stamp.tzinfo is not None and stamp.utcoffset() == timezone.utc.utcoffset(stamp))
    delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return m.integer((delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000)


def row(original):
    m.require(type(original) is str)
    raw = original.encode("ascii")
    value = m.document(raw, MAX_ROW)
    m.require(set(value) == ROW_FIELDS)
    for name, item in value.items():
        if item is None:
            m.require(name not in REQUIRED)
        elif name in {"revision", "credential_version"}:
            m.integer(item, minimum=0)
        else:
            m.require(type(item) is str)
    exchange.identifier(value["id"])
    for name in ("created_at", "updated_at", "expires_at"):
        epoch(value[name])
    return value


def initial_binding(original):
    value = row(original)
    return material.binding({"sessionId": value["id"], "revision": value["revision"],
        "rowSha256": m.sha(original.encode("ascii")), "ownerId": value["owner_id"],
        "currentAssigneeId": value["current_assignee_id"], "expiresAtEpochNs": epoch(value["expires_at"])})


class Originals:
    def __init__(self):
        self.initial = self.started = self.final = None

    def verify(self, stored, custody, expected, exchange_row, operation, setup_limits):
        m.require(type(stored) is dict and set(stored) == {"exchangeOriginal", "custodyOriginal", "setupOriginal"}
            and type(custody) is dict and set(custody) == CUSTODY_FIELDS)
        bound = material.binding(expected["request"]["setupBinding"])
        initial_raw, started_raw, final_raw = (custody[name] for name in (
            "setup_initial_json", "setup_started_json", "setup_final_json"))
        initial, started, actual = row(initial_raw), row(started_raw), row(stored["setupOriginal"])
        m.require(initial_binding(initial_raw) == bound and initial["revision"] == 0
            and initial["status"] == "active" and initial["phase"] == "created"
            and initial["owner_id"] == expected["actor_id"]
            and initial["current_assignee_id"] in {None, expected["actor_id"]}
            and all(initial[name] is None for name in ("credential_id", "credential_version",
                "oauth_provider", "oauth_state_digest", "oauth_pending_credential_id",
                "policy_hash", "assignment_digest", "enrollment_session_id", "terminal_at"))
            and 0 < epoch(initial["expires_at"]) - epoch(initial["created_at"])
                <= setup_limits["setupMaxSeconds"] * 1_000_000_000)
        consent = m.document(exchange_row["consent_json"].encode("ascii"), 1024 * 1024)
        m.require(consent["setupBinding"] == bound
            and exchange_row["requester_id"] == expected["actor_id"]
            and consent["pendingExpiresAtEpochNs"] <= bound["expiresAtEpochNs"])
        provider, state_digest = consent["providerId"], consent["stateSha256"]
        m.digest(state_digest)
        m.require(provider in exchange.AUTHORIZATION)
        expected_started = {**initial, "phase": "oauth_started", "revision": 1,
            "oauth_provider": provider, "oauth_state_digest": state_digest, "updated_at": started["updated_at"]}
        m.require(started == expected_started
            and epoch(initial["updated_at"]) <= epoch(started["updated_at"]) < bound["expiresAtEpochNs"])
        phase = operation.rsplit(".", 1)[-1]
        m.require(operation == "oauth.measured-setup." + phase
            and phase in {"prepare", "claim", "capture", "stage", "recover", "cancel"})
        if final_raw is None:
            m.require(phase in {"prepare", "claim", "capture", "recover"}
                and custody["status"] in {"prepared", "claimed", "captured"} and actual == started)
        else:
            final = row(final_raw)
            if custody["status"] == "staged":
                m.require(phase in {"stage", "recover"})
                changes = {"phase": "oauth_verified", "revision": 2,
                    "oauth_pending_credential_id": expected["resource_id"]}
            else:
                m.require(custody["status"] == "cancelled" and phase == "cancel")
                changes = {"status": "cancelled", "phase": "cancelled", "revision": 2,
                    "terminal_at": final["updated_at"]}
            m.require(final == {**started, **changes, "updated_at": final["updated_at"]} and actual == final
                and epoch(started["updated_at"]) <= epoch(final["updated_at"]) < bound["expiresAtEpochNs"])
        m.require(self.initial in {None, initial_raw} and self.started in {None, started_raw}
            and (self.final is None or self.final == final_raw))
        self.initial, self.started, self.final = initial_raw, started_raw, final_raw
        return actual
