"""Original key assertion to ordinary OIDC activation CAS intent, not authority.

The caller independently admits the current rows, target, policy and trust
bundle. This module neither authenticates those inputs nor loads them. It does
verify the original assertion on the supplied work and unchanged live window.
No registry entry, database call, token generator, mutation verifier, signing,
delivery, retained-finalization admission or successful-activation token exists
here. A later protected owner must compose those separate prerequisites.
"""
from __future__ import annotations

import time

from serverware import authority_transition_webauthn_registration as registration
from serverware import authority_webauthn_evidence_plan_clock as clock
from serverware import webauthn_attestation_core as attestation
from serverware import webauthn_credential_trust as trust


SCHEMA = "serverware.oidcSessionActivationCasIntent/v1"
HISTORICAL_SCHEMA = "serverware.oidcSessionActivationHistoricalCasIntent/v1"
MAX_ASSERTION_BYTES = 128 * 1024
MAX_CONTEXT_BYTES = 2 * 1024 * 1024
MAX_CONTEXT_NODES = 100_000
_SESSION_FIELDS = frozenset({"id", "token_digest", "oidc_token_digest", "user_id",
    "roles_json", "status", "provider_expires_at", "expires_at", "pending_expires_at",
    "created_at", "updated_at", "activated_at", "revoked_at", "bound_webauthn_credential_id",
    "activation_trust_bundle_digest", "activation_trust_bundle_sequence",
    "activation_authenticator_class", "revocation_reason"})
_CREDENTIAL_FIELDS = frozenset({"id", "credential_id", "user_id", "label", "public_key_cose",
    "sign_count", "aaguid", "authenticator_class", "attestation_fmt", "attestation_trusted",
    "attestation_trust_path", "attestation_leaf_sha256", "attestation_root_sha256",
    "attestation_trust_bundle_digest", "attestation_trust_bundle_sequence",
    "attestation_verified_at", "transports", "dev_private_key_pem", "created_at", "updated_at",
    "last_used_at", "revoked_at", "revoked_by", "revocation_reason", "revocation_source"})
_PAYLOAD_FIELDS = frozenset({"v", "type", "session_id", "user_id", "session_expires_at",
    "pending_expires_at", "nonce"})
_ROOT_FIELDS = frozenset({"id", "certificate_sha256", "authenticator_class", "aaguids",
    "bundle_digest", "bundle_sequence"})
_CLASSES = frozenset({"hardware", "yubikey", "platform"})


class OidcSessionActivationAdmissionError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationAdmissionError(message)


class _Capture(registration.capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > 12 or self.nodes >= MAX_CONTEXT_NODES:
            _fail("activation context exceeds its structural bound")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_CONTEXT_NODES:
            _fail("activation context exceeds its structural bound")
        return result


def _json(raw, work, maximum=MAX_ASSERTION_BYTES):
    return registration.evidence.wire._decode_object(raw, work=work,
        maximum_bytes=maximum, maximum_nodes=4096, maximum_depth=8)


def _time(value, label, work):
    return registration._now(registration._utc(value, label, work))


def _digest(raw, work):
    return attestation.sha256_prefixed(raw, _work=work)


def _commitment(label, value, work):
    return attestation._commitment("serverware.oidcSessionActivation/" + label + "/v1",
        value, _work=work)


def _token(value, work):
    if (type(value) is not bytes or len(value) != 64
            or any(point not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                   for point in value)):
        _fail("activation token is not an exact bounded server-owned original")
    work.charge(input_bytes=64)
    return value


def _row_text(row, *, integers, nullable, work):
    """Raw database columns only; decoded API row graphs are not accepted."""
    for field, value in row.items():
        if field in integers or (value is None and field in nullable):
            continue
        maximum = (64 * 1024 if field in {"roles_json", "payload_json", "attestation_trust_path", "transports"}
                   else 5462 if field == "public_key_cose" else 4096)
        registration._text(value, "raw row " + field, maximum, work, empty=field == "label")


def _current_trust(credential, policy, roots, work):
    registration._closed(policy, {"userVerification", "allowedAuthenticatorClasses",
        "requireHardwareAttestation"}, "activation authentication policy")
    classes = policy["allowedAuthenticatorClasses"]
    if (policy["userVerification"] != "required"
            or type(policy["requireHardwareAttestation"]) is not bool
            or type(classes) is not list or not 1 <= len(classes) <= len(_CLASSES)
            or any(type(item) is not str or item not in _CLASSES for item in classes)
            or len(set(classes)) != len(classes)):
        _fail("activation authentication policy is outside the fixed profile")
    registration._closed(roots, {"roots", "currentBundleDigest", "currentBundleSequence"},
        "activation trust policy")
    registration._digest(roots["currentBundleDigest"])
    registration._integer(roots["currentBundleSequence"], "current trust sequence", 1)
    descriptors = roots["roots"]
    if type(descriptors) is not list or not 1 <= len(descriptors) <= trust.MAX_ROOTS:
        _fail("activation current root inventory is not bounded")
    policies = []
    for item in descriptors:
        registration._closed(item, _ROOT_FIELDS, "activation root descriptor")
        registration._text(item["id"], "root ID", 4096, work)
        registration._digest(item["certificate_sha256"])
        registration._same((item["bundle_digest"], item["bundle_sequence"]),
            (roots["currentBundleDigest"], roots["currentBundleSequence"]), work,
            "current root bundle scope")
        if item["authenticator_class"] is not None and (
                type(item["authenticator_class"]) is not str or item["authenticator_class"] not in _CLASSES):
            _fail("activation root class is unsupported")
        aaguids = item["aaguids"]
        if type(aaguids) is not list or len(aaguids) > trust.MAX_ROOT_AAGUIDS:
            _fail("activation root AAGUID inventory is not bounded")
        for aaguid in aaguids:
            registration._text(aaguid, "root AAGUID", 128, work)
        work.prepare_copy(item)
        policies.append(attestation._native(work, lambda: trust.RootTrustPolicy(
            item["id"], item["certificate_sha256"], item["authenticator_class"], tuple(aaguids),
            item["bundle_digest"], item["bundle_sequence"])))
    trusted = credential["attestation_trusted"]
    if not ((type(trusted) is bool and trusted is True) or (type(trusted) is int and trusted == 1)):
        _fail("activation credential lacks enrolled attestation trust")
    for field in ("attestation_root_sha256", "attestation_trust_bundle_digest",
                  "attestation_leaf_sha256"):
        registration._digest(credential[field])
    registration._integer(credential["attestation_trust_bundle_sequence"], "enrolled trust sequence", 1)
    registration._text(credential["authenticator_class"], "credential class", 128, work)
    registration._text(credential["aaguid"], "credential AAGUID", 128, work)
    work.prepare_copy(credential)
    facts = attestation._native(work, lambda: trust.CredentialTrustFacts(True,
        credential["authenticator_class"], False, credential["attestation_root_sha256"],
        credential["aaguid"], credential["attestation_trust_bundle_digest"],
        credential["attestation_trust_bundle_sequence"]))
    work.prepare_copy(roots)
    context = attestation._native(work, lambda: trust.CredentialTrustContext(tuple(policies), False))
    work.prepare_scan(roots)
    work.prepare_scan(credential)
    status = attestation._native(work, lambda: trust.classify(facts, context))
    # Preserve the actual live policy's hardware alias for trusted YubiKeys;
    # a platform credential does not acquire that alias.
    eligible_classes = {status.effective_authenticator_class}
    hardware = status.currently_trusted and status.effective_authenticator_class in {"hardware", "yubikey"}
    if hardware:
        eligible_classes.add("hardware")
    if (not status.currently_trusted or not eligible_classes.intersection(classes)
            or (policy["requireHardwareAttestation"] and not hardware)):
        _fail("activation credential is not eligible under current supplied trust")
    registration._same((status.current_trust_bundle_digest, status.current_trust_bundle_sequence),
        (roots["currentBundleDigest"], roots["currentBundleSequence"]), work, "classified trust bundle")
    return status


def _historical_interval(value):
    """Capture only an immutable original interval; it grants no processing time."""
    if type(value) is not tuple or len(value) != 2:
        _fail("activation historical plan interval is not an exact immutable pair")
    issued = registration._integer(value[0], "historical plan issue", 1)
    expires = registration._integer(value[1], "historical plan expiry", 1)
    if issued >= expires:
        _fail("activation historical plan interval is empty or reversed")
    return issued, expires


def _derive_originals_on_work(*, assertion_bytes, session_row, challenge_row, credential_row,
                    expected_user_id, expected_session_id, expected_credential_id,
                    rp_id, origin, authn_policy, trust_policy, old_token_bytes, new_token_bytes,
                    live_window, work, transport_deadline_ns=None,
                    historical_plan_interval=None, original_database_now_epoch_ns=None, _current=None):
    """Common original semantics with separate live and historical time rules."""
    ledger = registration.capture._SharedLedger(work)
    historical = None
    if historical_plan_interval is not None:
        historical = _historical_interval(historical_plan_interval)
        cutoff = registration._integer(original_database_now_epoch_ns,
            "historical database cutoff", 1)
        if cutoff >= historical[1]:
            _fail("activation historical database cutoff does not precede plan expiry")
    elif original_database_now_epoch_ns is not None:
        _fail("activation historical cutoff requires its original plan interval")
    if type(assertion_bytes) is not bytes or not 2 <= len(assertion_bytes) <= MAX_ASSERTION_BYTES:
        _fail("activation assertion is not a bounded immutable original")
    old_token_bytes, new_token_bytes = _token(old_token_bytes, work), _token(new_token_bytes, work)
    window = clock._validate(live_window)
    bound = window[4]
    if transport_deadline_ns is not None:
        registration._integer(transport_deadline_ns, "inherited monotonic deadline", 1)
        bound = min(bound, transport_deadline_ns)
    # Snapshot all mutable graphs and exact scalars before clock/hash/native callbacks.
    owned = _Capture(ledger, maximum_bytes=MAX_CONTEXT_BYTES).visit({
        "session": session_row, "challenge": challenge_row, "credential": credential_row,
        "user": expected_user_id, "sessionId": expected_session_id, "credentialId": expected_credential_id,
        "rpId": rp_id, "origin": origin, "policy": authn_policy, "trust": trust_policy})
    session, challenge, credential = owned["session"], owned["challenge"], owned["credential"]
    user, session_id, credential_id = owned["user"], owned["sessionId"], owned["credentialId"]
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = registration.evidence.production._callback(work, lambda: time.monotonic_ns())
        registration._integer(monotonic, "monotonic sample", 1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            _fail("activation processing window expired or reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    if _current is not None:
        from serverware import oidc_session_activation_delivery as delivery

        current = delivery._join_current(current, _current, work)
    now = current()
    if historical is not None and (historical[0] > now + window[6] or cutoff > now + window[6]):
        _fail("activation historical issue or database cutoff is in the future")
    for value, label, maximum in ((user, "user", 4096), (session_id, "session", 128),
            (credential_id, "credential", 1366), (owned["rpId"], "RP ID", 4096),
            (owned["origin"], "origin", 8192)):
        registration._text(value, label, maximum, work)
    registration._encoded_original(credential_id, 1024, work, minimum=1)
    registration._closed(session, _SESSION_FIELDS, "activation session row")
    registration._closed(challenge, registration._CHALLENGE_FIELDS, "activation challenge row")
    registration._closed(credential, _CREDENTIAL_FIELDS, "activation credential row")
    _row_text(session, integers={"activation_trust_bundle_sequence"}, nullable={"activated_at", "revoked_at",
        "bound_webauthn_credential_id", "activation_trust_bundle_digest", "activation_authenticator_class",
        "revocation_reason"}, work=work)
    _row_text(challenge, integers=set(), nullable={"approval_request_id", "used_at"}, work=work)
    _row_text(credential, integers={"sign_count", "attestation_trusted", "attestation_trust_bundle_sequence"},
        nullable={"dev_private_key_pem", "last_used_at", "revoked_at", "revoked_by", "revocation_reason",
            "revocation_source"}, work=work)
    registration._same((session["id"], session["user_id"], credential["credential_id"],
        credential["user_id"], challenge["user_id"], challenge["scope_key"]),
        (session_id, user, credential_id, user, user, session_id), work, "activation subject")
    for value, label in ((credential["id"], "credential row ID"), (challenge["id"], "challenge row ID")):
        registration._text(value, label, 4096, work)
    if session["status"] != "pending_webauthn" or any(session[field] is not None for field in (
            "activated_at", "revoked_at", "bound_webauthn_credential_id", "activation_trust_bundle_digest",
            "activation_trust_bundle_sequence", "activation_authenticator_class", "revocation_reason")):
        _fail("activation session is not unactivated and pending")
    if any(credential[field] is not None for field in (
            "revoked_at", "revoked_by", "revocation_reason", "revocation_source", "dev_private_key_pem")):
        _fail("activation credential is revoked or development-scoped")
    if (challenge["challenge_type"] != "oidc-session-binding" or challenge["used_at"] is not None
            or challenge["approval_request_id"] is not None):
        _fail("activation challenge is not an unused session-binding challenge")
    expiry = {field: _time(session[field], field, work) for field in (
        "provider_expires_at", "expires_at", "pending_expires_at")}
    if historical is None:
        if not now < expiry["pending_expires_at"] <= expiry["expires_at"] <= expiry["provider_expires_at"]:
            _fail("activation session interval is expired or inconsistent")
    elif not (cutoff < historical[1] <= expiry["pending_expires_at"]
            <= expiry["expires_at"] <= expiry["provider_expires_at"]):
        _fail("activation historical session does not contain the original plan interval")
    challenge_expiry = _time(challenge["expires_at"], "challenge expiry", work)
    if historical is None and challenge_expiry <= now:
        _fail("activation challenge expired")
    if historical is not None and historical[1] > challenge_expiry:
        _fail("activation historical challenge expires before the original plan")
    for row, fields in ((session, ("created_at", "updated_at")),
            (challenge, ("created_at",)),
            (credential, ("created_at", "updated_at", "attestation_verified_at"))):
        for field in fields:
            if _time(row[field], field, work) > (now if historical is None else cutoff):
                _fail("activation row time is in the future")
    if (credential["last_used_at"] is not None
            and _time(credential["last_used_at"], "last use", work) > (now if historical is None else cutoff)):
        _fail("activation credential last use is in the future")
    registration._digest(session["token_digest"])
    registration._digest(session["oidc_token_digest"])
    old_digest, new_digest = _digest(old_token_bytes, work), _digest(new_token_bytes, work)
    registration._same(old_digest, session["token_digest"], work, "old pending token")
    if old_digest == new_digest:
        _fail("activation must rotate the server-owned token")
    # Stored JSON remains original row material; only the challenge hash uses
    # canonical semantic payload bytes, matching the actual options producer.
    registration._text(challenge["payload_json"], "challenge payload", 64 * 1024, work)
    work.prepare_utf8(challenge["payload_json"])
    payload = _json(challenge["payload_json"].encode("utf-8"), work, 64 * 1024)
    registration._closed(payload, _PAYLOAD_FIELDS, "activation challenge payload")
    if type(payload["v"]) is not int or payload["v"] != 1:
        _fail("activation challenge payload version differs")
    registration._same((payload["type"], payload["session_id"], payload["user_id"],
        payload["session_expires_at"], payload["pending_expires_at"]),
        ("serverware.oidc_session_binding", session_id, user, session["expires_at"],
         session["pending_expires_at"]), work, "activation challenge payload scope")
    if len(registration._encoded_original(payload["nonce"], 24, work, minimum=24)) != 24:
        _fail("activation challenge nonce length differs")
    payload_digest = _digest(attestation._canonical(payload, _work=work), work)
    challenge_raw = registration._encoded_original(challenge["challenge"], 32, work, minimum=32)
    work.charge(input_bytes=len(challenge_raw))
    registration._same("sha256:" + challenge_raw.hex(), payload_digest, work, "activation payload hash")
    status = _current_trust(credential, owned["policy"], owned["trust"], work)
    original = _json(assertion_bytes, work)
    registration._closed(original, {"id", "rawId", "type", "response"}, "activation assertion")
    registration._same((original["id"], original["rawId"], original["type"]),
        (credential_id, credential_id, "public-key"), work, "assertion target")
    response = original["response"]
    required = {"clientDataJSON", "authenticatorData", "signature"}
    if type(response) is not dict or set(response) not in (required, required | {"userHandle"}):
        _fail("activation assertion response is not source closed")
    if response.get("userHandle") is not None:
        user_handle = registration._encoded_original(response["userHandle"], 4096, work, minimum=1)
        work.prepare_utf8(user)
        registration._same(user_handle, user.encode("utf-8"), work, "assertion user handle")
    client_raw = registration._encoded_original(response["clientDataJSON"],
        attestation.MAX_CLIENT_DATA_JSON_BYTES, work)
    _json(client_raw, work, attestation.MAX_CLIENT_DATA_JSON_BYTES)  # Reject duplicate keys before native parse.
    client = attestation.parse_client_data(client_raw, "webauthn.get", origin=owned["origin"], _work=work)
    registration._same(client.get("challenge"), challenge["challenge"], work, "assertion session challenge")
    if "crossOrigin" in client and client["crossOrigin"] is not False:
        _fail("activation assertion is not explicitly same-origin")
    auth_raw = registration._encoded_original(response["authenticatorData"],
        attestation.MAX_AUTHENTICATOR_DATA_BYTES, work, minimum=37)
    parsed = attestation.parse_authenticator_data(auth_raw, rp_id=owned["rpId"], _work=work)
    if not parsed["user_verified"] or parsed["attested_credential_data"]:
        _fail("activation requires an assertion with user verification")
    expected_count = registration._integer(credential["sign_count"], "old sign counter", 0, 2**32 - 1)
    next_count = parsed["sign_count"]
    if not ((expected_count == 0 and next_count == 0) or next_count > expected_count):
        _fail("activation sign counter did not advance")
    key_raw = registration._encoded_original(credential["public_key_cose"],
        attestation.MAX_COSE_PUBLIC_KEY_BYTES, work, minimum=1)
    public_key = attestation.public_key_from_cose(key_raw, _work=work)
    signature = registration._encoded_original(response["signature"], 128, work)
    client_digest = _digest(client_raw, work)
    work.charge(input_bytes=len(auth_raw) + 32)
    signed = auth_raw + bytes.fromhex(client_digest[7:])
    attestation.verify_es256_signature(public_key, signature, signed,
        "OIDC activation assertion signature is invalid", _work=work)
    # Live admission projects its inherited cap from the unchanged opening.
    # Historical admission returns only the original semantic expiry ceiling;
    # the separate current() guard still enforces today's processing cap.
    valid_until = (min(window[3], window[0] + bound - window[1],
        expiry["pending_expires_at"], challenge_expiry) if historical is None
        else min(expiry["pending_expires_at"], challenge_expiry))
    result = {"schema": SCHEMA if historical is None else HISTORICAL_SCHEMA,
        "sourceRevision": registration.authority.SOURCE_REVISION,
        "subject": {"userId": user, "sessionId": session_id, "credentialId": credential_id,
            "credentialRecordId": credential["id"], "challengeId": challenge["id"]},
        "rowDigests": {"session": _commitment("sessionRow", session, work),
            "challenge": _commitment("challengeRow", challenge, work),
            "credential": _commitment("credentialRow", credential, work)},
        "policyDigests": {"authentication": _commitment("authenticationPolicy", owned["policy"], work),
            "trust": _commitment("trustPolicy", owned["trust"], work),
            "ceremony": _commitment("ceremonyPolicy", {"rpId": owned["rpId"], "origin": owned["origin"]}, work)},
        "assertionDigest": _digest(assertion_bytes, work), "challengePayloadDigest": payload_digest,
        "validUntilEpochNs": valid_until,
        "challengeCas": {"expectedUsedAt": None, "markUsed": True},
        "credentialCas": {"expectedSignCount": expected_count, "newSignCount": next_count},
        "sessionCas": {"expectedStatus": "pending_webauthn", "expectedTokenDigest": old_digest,
            "expectedExpiresAt": session["expires_at"], "expectedPendingExpiresAt": session["pending_expires_at"],
            "newTokenDigest": new_digest, "newStatus": "active", "newPendingExpiresAt": None,
            "newBoundCredentialRecordId": credential["id"],
            "activationTrustBundleDigest": status.current_trust_bundle_digest,
            "activationTrustBundleSequence": status.current_trust_bundle_sequence,
            "activationAuthenticatorClass": status.effective_authenticator_class}}
    final_now = current()
    if historical is None and final_now >= valid_until:
        _fail("activation originals expired during derivation")
    return result


def _derive_on_work(*, assertion_bytes, session_row, challenge_row, credential_row,
                    expected_user_id, expected_session_id, expected_credential_id,
                    rp_id, origin, authn_policy, trust_policy, old_token_bytes, new_token_bytes,
                    live_window, work, transport_deadline_ns=None):
    """Verify live originals; the ordinary result is not activation permission."""
    return _derive_originals_on_work(assertion_bytes=assertion_bytes, session_row=session_row,
        challenge_row=challenge_row, credential_row=credential_row, expected_user_id=expected_user_id,
        expected_session_id=expected_session_id, expected_credential_id=expected_credential_id,
        rp_id=rp_id, origin=origin, authn_policy=authn_policy, trust_policy=trust_policy,
        old_token_bytes=old_token_bytes, new_token_bytes=new_token_bytes, live_window=live_window,
        work=work, transport_deadline_ns=transport_deadline_ns)


def _derive_historical_on_work(*, assertion_bytes, session_row, challenge_row, credential_row,
                    expected_user_id, expected_session_id, expected_credential_id,
                    rp_id, origin, authn_policy, trust_policy, old_token_bytes, new_token_bytes,
                    original_database_now_epoch_ns, historical_plan_interval,
                    live_window, work, transport_deadline_ns=None, _current=None):
    """Reverify original assertion semantics, never a live or executable result.

    The caller must authenticate the original plan interval and database cutoff
    independently. They are historical data, never a replacement current clock.
    """
    return _derive_originals_on_work(assertion_bytes=assertion_bytes, session_row=session_row,
        challenge_row=challenge_row, credential_row=credential_row, expected_user_id=expected_user_id,
        expected_session_id=expected_session_id, expected_credential_id=expected_credential_id,
        rp_id=rp_id, origin=origin, authn_policy=authn_policy, trust_policy=trust_policy,
        old_token_bytes=old_token_bytes, new_token_bytes=new_token_bytes, live_window=live_window,
        work=work, transport_deadline_ns=transport_deadline_ns,
        historical_plan_interval=_historical_interval(historical_plan_interval),
        original_database_now_epoch_ns=original_database_now_epoch_ns, _current=_current)
