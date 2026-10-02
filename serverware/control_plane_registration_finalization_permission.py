"""One live completion-possession challenge outside pending metadata roots.

The admitted enrollment owner retains one challenge for its lifetime. Its loss
or process restart invalidates the challenge; no recovery document can restore
permission. This is not a login, session activation or persisted counter
transition. The observed authenticator counter is checked against the unchanged
stored baseline, but deliberately is NOT written before exact-root completion.
The random signed challenge and irreversible in-owner claim supply request
replay protection. Generic mutation challenges and their DB writes stay intact.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass

from serverware import control_plane_enrollment_startup as startup
from serverware import control_plane_registration_finalization_completion_http as contract
from serverware import control_plane_registration_finalization_completion_subject as subjects


MAX_LIFETIME_NS = 120_000_000_000
_SPENT = object()


class FinalizationPermissionError(ValueError):
    pass


def _original(value):
    """Own bounded plain JSON; never retain aliases to a row or policy."""
    budget = [4096]

    def check(item, depth=0):
        budget[0] -= 1
        if budget[0] < 0 or depth > 8:
            raise FinalizationPermissionError("completion permission input is too large")
        if item is None or type(item) is bool:
            return
        if type(item) is int and -(1 << 63) <= item < (1 << 64):
            return
        if type(item) is str and len(item) <= 65536:
            return
        if type(item) is dict and len(item) <= 64 and all(type(k) is str for k in item):
            for key, value in item.items():
                check(key, depth + 1)
                check(value, depth + 1)
            return
        if type(item) is list and len(item) <= 64:
            for value in item:
                check(value, depth + 1)
            return
        raise FinalizationPermissionError("completion permission input is not plain bounded JSON")

    check(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(raw) > 128 * 1024:
        raise FinalizationPermissionError("completion permission input exceeds its bound")
    return raw


def _scope(owner, binding, authn_policy):
    """Replay actual retained originals; a caller binding is only a comparator."""
    from serverware import webauthn
    from serverware import app as application
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    startup._continuity(owner)
    if not owner.finalization_completion_enabled or not owner.sql_handoff_enabled:
        raise FinalizationPermissionError("completion permission requires admitted cold owners")
    if type(binding) is not dict or binding.get("purpose") not in {
            contract.COMPLETE_PURPOSE, contract.RECOVER_PURPOSE}:
        raise FinalizationPermissionError("completion permission purpose differs")
    # Use the existing full replay, including its original selected-context
    # narrowing and retained callback. The public raw8 projection alone omits
    # exactly those clocks and must not be used to renew a browser allowance.
    work = _ValidationWork(QueryReadValidationLimits())
    selected_owner, material, custody_binding, window = subjects._open_on_work(work)
    if (selected_owner is not owner or owner._material is not material
            or owner._binding is not custody_binding):
        raise FinalizationPermissionError("completion permission replay owner differs")
    selected = subjects._inspect_material_on_owner(owner, binding.get("localDigest"),
        live_window=window, transport_deadline_ns=window[4], work=work)
    selected.current()
    actual = contract.request_binding(selected.subject,
        recovery=binding["purpose"] == contract.RECOVER_PURPOSE)
    if _original(actual) != _original(binding):
        raise FinalizationPermissionError("completion permission retained subject differs")
    if type(authn_policy) is not dict or authn_policy.get("userVerification") != "required":
        raise FinalizationPermissionError("completion possession requires user verification")
    if _original(authn_policy) != _original(application._control_plane_mutation_authn_policy()):
        raise FinalizationPermissionError("completion permission policy is not the current source policy")
    row = webauthn.db.get_webauthn_credential(actual["credentialId"])
    if (type(row) is not dict or row.get("credential_id") != actual["credentialId"]
            or row.get("user_id") != actual["userId"]
            or type(row.get("id")) is not str or not row["id"]
            or "revoked_at" not in row or row["revoked_at"] is not None
            or type(row.get("sign_count")) is not int or not 0 <= row["sign_count"] <= 0xffffffff):
        raise FinalizationPermissionError("completion permission target credential is unavailable")
    row_original, policy_original = _original(row), _original(authn_policy)
    # This is the existing current attestation/class policy, not enrollment-time
    # trust or a successful caller-supplied verification result.
    trust_original = _original(webauthn._allowed_authenticator(row, authn_policy))
    startup._continuity(owner)
    selected.current()
    return (_original(actual), row_original, policy_original, trust_original), selected


@dataclass(frozen=True, slots=True)
class _Challenge:
    challenge: str
    scope: tuple[bytes, bytes, bytes, bytes]
    custody_binding: object
    material: object
    opened_ns: int
    deadline_ns: int
    expires_epoch_ns: int
    retained: object


def _current(owner, challenge):
    if type(challenge) is not _Challenge:
        raise FinalizationPermissionError("completion permission is not its retained challenge")
    challenge.retained.current()
    before = time.monotonic_ns()
    epoch = startup._continuity(owner)
    after = time.monotonic_ns()
    if (type(challenge) is not _Challenge
            or owner._binding is not challenge.custody_binding
            or owner._material is not challenge.material
            or before < challenge.opened_ns or after < before
            or after >= challenge.deadline_ns or epoch >= challenge.expires_epoch_ns):
        raise FinalizationPermissionError("completion permission owner or original window changed")


def issue(owner, binding, authn_policy):
    """Issue once through the actual owner; no metadata challenge is created."""
    from serverware import webauthn

    startup._require_pid()
    with startup._LOCK:
        startup._continuity(owner)
        if owner._finalization_permission is not None:
            raise FinalizationPermissionError("completion permission was already issued on this owner")
        before = time.monotonic_ns()
        epoch = startup._continuity(owner)
        lifetime = min(MAX_LIFETIME_NS, owner._binding.maximum_deadline_ns,
            owner._binding.attestation_interval[1] - epoch)
        scope, retained = _scope(owner, binding, authn_policy)
        deadline = min(before + lifetime, retained.deadline_ns, retained.window[4])
        # The selected transport bound can be earlier than its epoch window.
        # Convert conservatively from the genuine replay's trailing monotonic
        # sample, never relabel MONOTONIC as BOOTTIME or extend either bound.
        expires = min(epoch + lifetime, retained.window[3],
            retained.window[0] + deadline - retained.window[2])
        challenge = _Challenge(webauthn.b64u(secrets.token_bytes(32)), scope,
            owner._binding, owner._material, before, deadline, expires, retained)
        # Publish custody before further calls: even an uncertain issue cannot
        # silently replace the nonce on this admitted owner.
        owner._finalization_permission = challenge
        _current(owner, challenge)
        row = json.loads(scope[1])
        descriptor = webauthn._credential_descriptor(row)
        remaining_ms = min((challenge.deadline_ns - time.monotonic_ns()) // 1_000_000,
            (challenge.expires_epoch_ns - startup._continuity(owner)) // 1_000_000)
        if remaining_ms <= 0:
            raise FinalizationPermissionError("completion permission expired while opening")
        result = {"schema": contract.OPTIONS_SCHEMA, "purpose": binding["purpose"],
            "localDigest": binding["localDigest"], "action": binding["action"],
            "resourceId": binding["challengeId"],
            "payloadDigest": "sha256:" + hashlib.sha256(scope[0]).hexdigest(),
            "publicKey": {"challenge": challenge.challenge, "rpId": webauthn.WEBAUTHN_RP_ID,
                "allowCredentials": [descriptor], "timeout": remaining_ms,
                "userVerification": "required"},
            "expiresAtEpochNs": challenge.expires_epoch_ns, "automaticRetryAllowed": False}
        _current(owner, challenge)
        return result


def _verify(credential, authn_policy, assertion, challenge):
    """Actual signature check only, never a DB claim or counter advancement."""
    from serverware import webauthn

    if type(assertion) is not dict or assertion.get("type") != "public-key":
        raise FinalizationPermissionError("completion assertion type differs")
    selectors = [assertion[name] for name in ("id", "rawId") if name in assertion]
    if not selectors or any(value != credential["credential_id"] for value in selectors):
        raise FinalizationPermissionError("completion assertion credential differs")
    response = assertion.get("response")
    if type(response) is not dict:
        raise FinalizationPermissionError("completion assertion response differs")
    verified = webauthn._verify_assertion_signature(credential, response, authn_policy)
    parsed, client = verified["parsed"], verified["client_data"]
    if client.get("challenge") != challenge:
        raise FinalizationPermissionError("completion assertion challenge differs")
    count, baseline = parsed["sign_count"], credential["sign_count"]
    if (type(count) is not int or not 0 <= count <= 0xffffffff
            or not (count == baseline == 0 or count > baseline)
            or not parsed["user_present"] or not parsed["user_verified"]):
        raise FinalizationPermissionError("completion possession counter or presence differs")
    return {"user_id": credential["user_id"], "credential_id": credential["credential_id"],
        "credential_record_id": credential["id"], "observed_sign_count": count,
        "stored_sign_count": baseline, "persisted_counter_advanced": False,
        "session_activated": False}


def consume(owner, binding, authn_policy, assertion):
    """Burn before verifying; failure cannot restore/retry this permission."""
    startup._require_pid()
    with startup._LOCK:
        startup._continuity(owner)
        challenge = owner._finalization_permission
        if type(challenge) is not _Challenge:
            raise FinalizationPermissionError("completion permission is absent or spent")
        owner._finalization_permission = _SPENT
        _current(owner, challenge)
        if _scope(owner, binding, authn_policy)[0] != challenge.scope:
            raise FinalizationPermissionError("completion permission subject, credential or policy changed")
        _original(assertion)  # Bound signature input before parsing/crypto.
        result = _verify(json.loads(challenge.scope[1]), json.loads(challenge.scope[2]),
            assertion, challenge.challenge)
        _current(owner, challenge)
        if _scope(owner, binding, authn_policy)[0] != challenge.scope:
            raise FinalizationPermissionError("completion permission changed during verification")
        _current(owner, challenge)
        return result
