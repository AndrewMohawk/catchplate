"""Cold-owned OAuth consent and one-attempt callback, without runtime DML.

The protected writer owns each state transition. Ciphertext and echoed request
fields are re-admitted against their decrypted originals, never used as permits.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
import uuid

from fastapi import Request

from serverware import auth, authority_contract, config, crypto, db, oauth, webauthn
from serverware import authority_oauth_exchange as profile
from serverware import control_plane_oauth_activation as activation
from serverware import oauth_application_owner as applications
from serverware import oauth_exchange_material as material
from serverware.control_plane_approval_verification import _epoch_ns, _request_pin

MFA_FIELD = "oauthExchangeProfile"
STATE_SCHEMA = "serverware.oauthExchangePrivateState/v1"
_STATE_FIELDS = frozenset({"schema", "exchangeId", "state", "browserNonceSha256", "codeVerifier",
    "providerId", "requesterId", "credentialName", "scopes", "metadata", "redirectUri",
    "issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs",
    "enrollmentSha256", "oauth_application_owner", "credentialPolicy", "limits"})
_PUBLIC_FIELDS = frozenset({"id", "status", "rowSha256", "contactExpiresAtEpochNs",
    "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs"})
_PENDING_FIELDS = frozenset({"id", "requester_id", "name", "kind", "payload_digest", "review",
    "target_credential_id", "target_credential_version", "status", "revocation_status", "revocation_error",
    "revocation_attempts", "revocation_next_attempt_at", "created_at", "expires_at", "updated_at"})
_STATUS = {profile.OP_PREPARE: "prepared", profile.OP_CLAIM: "claimed",
    profile.OP_RETAIN: "retained", profile.OP_STAGE: "staged"}
_STATE_RE = re.compile(r"([0-9a-f]{32})_[A-Za-z0-9_-]{43}\Z")


def selected():
    return applications.require_started() is not None


def _cookie_identity(request):
    profile.require(type(request) is Request and request.method == "POST" and not request.url.query
        and not request.headers.getlist("authorization") and not request.headers.getlist("x-serverware-admin-token")
        and request.headers.getlist("origin") == [webauthn.WEBAUTHN_ORIGIN]
        and webauthn.WEBAUTHN_ORIGIN not in ("", "null") and len(request.headers.getlist("cookie")) == 1)
    names = [part.strip().split("=", 1)[0] for part in request.headers["cookie"].split(";")]
    profile.require(len(names) == len(set(names)) and not request.cookies.get("serverware_admin"))
    identity = auth.oidc_identity_from_session_token(request.cookies.get(auth.OIDC_SESSION_COOKIE_NAME))
    profile.require(type(identity) is auth.AdminIdentity and identity.user_id.startswith("oidc:")
        and "credential_owner" in identity.roles)
    auth.validate_csrf_request(request)
    return identity


def _json(raw, maximum):
    profile.require(type(raw) is bytes and 1 <= len(raw) <= maximum)
    def pairs(items):
        result = {}
        for key, value in items:
            profile.require(key not in result)
            result[key] = value
        return result
    result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
        parse_constant=lambda _: profile.require(False))
    profile.require(type(result) is dict and profile.canonical(result) == raw)
    return result


def _row(exchange_id):
    profile.identifier(exchange_id)
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM oauth_exchange_reservations WHERE id = ?", (exchange_id,)).fetchone()
    profile.require(row is not None)
    row = dict(row)
    profile.row_original(row)
    return row


def _public(row):
    consent = _json(row["consent_json"].encode("utf-8"), profile.MAX_ARGUMENT_BYTES)
    return {"id": row["id"], "status": row["status"], "rowSha256": profile.row_digest(row),
        **{key: consent[key] for key in ("contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs")}}


def _encrypted(item_id, raw):
    profile.require(type(raw) is bytes)
    envelope = profile.envelope(db._envelope_values(item_id, raw.decode("utf-8"), 1))
    profile.require(_decrypted(item_id, envelope) == raw)
    return envelope


def _decrypted(item_id, envelope):
    profile.envelope(envelope)
    return crypto.decrypt_secret_envelope({"id": item_id, **envelope}).encode("utf-8")


def _state_id(state):
    profile.require(type(state) is str)
    match = _STATE_RE.fullmatch(state)
    profile.require(match is not None)
    return str(uuid.UUID(hex=match.group(1)))


class _Owner:
    def __init__(self, request, provider_id, *, callback=False):
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.mono, self.epoch = time.monotonic_ns(), time.time_ns()
        self.request, self.scope, self.pin = request, request.scope, _request_pin(request)
        self.callback = callback
        profile.require(type(request) is Request and request.method == ("GET" if callback else "POST"))
        self.identity = None if callback else _cookie_identity(request)
        self.policy = activation._policy()
        self.policy_original = profile.canonical(self.policy)
        self.provider = oauth.provider_for(provider_id)
        self.application = applications.begin(self.provider)
        profile.require(self.application is not None)
        self.custody = self.application.custody_owner()
        self.enrollment = self.application.enrollment_original()
        self.encoded_enrollment = base64.urlsafe_b64encode(self.enrollment).rstrip(b"=").decode("ascii")
        self.association = self.application.association()
        self.deadline = min(self.application.deadline_ns, self.mono + 30_000_000_000)
        self.expires = min(self.application.expires_ns, self.epoch + 30_000_000_000)
        self.credential = self.mfa = self.mfa_original = None
        self.actor = None if callback else self.identity.user_id
        self.attempts, self.poisoned = set(), False
        self.claim_original, self.contact_attempted = None, False
        self.check()

    def __copy__(self):
        raise ValueError("OAuth exchange owner cannot be copied")

    def __deepcopy__(self, memo):
        raise ValueError("OAuth exchange owner cannot be copied")

    def clip(self, expiry):
        profile.require(type(expiry) is int)
        self.expires = min(self.expires, expiry)
        self.deadline = min(self.deadline, self.mono + self.expires - self.epoch)
        self.check()

    def check(self):
        try:
            mono, epoch = time.monotonic_ns(), time.time_ns()
            profile.require(not self.poisoned and (os.getpid(), threading.get_ident()) == (self.pid, self.thread)
                and self.mono <= mono < self.deadline and self.epoch <= epoch < self.expires
                and self.request.scope is self.scope and _request_pin(self.request) == self.pin
                and profile.canonical(activation._policy()) == self.policy_original)
            if not self.callback:
                profile.require(_cookie_identity(self.request) == self.identity)
            self.application.check()
            profile.require(self.application.custody_owner() is self.custody
                and self.application.enrollment_original() == self.enrollment
                and self.application.association() == self.association)
            if self.mfa_original is not None:
                profile.require(profile.canonical(self.mfa) == self.mfa_original)
            if self.credential is not None:
                current = db.get_webauthn_credential_by_record_id(self.credential["id"])
                profile.require(type(current) is dict and current.get("revoked_at") is None
                    and all(current.get(key) == self.credential.get(key)
                        for key in ("id", "credential_id", "user_id", "public_key_cose")))
                trust = webauthn._allowed_authenticator(current, activation._authenticator_policy(self.policy))
                profile.require(trust["currently_trusted"] is True
                    and trust["effective_authenticator_class"] in {"hardware", "yubikey"})
            closing_mono, closing_epoch = time.monotonic_ns(), time.time_ns()
            profile.require(mono <= closing_mono < self.deadline and epoch <= closing_epoch < self.expires)
            self.mono, self.epoch = closing_mono, closing_epoch
        except BaseException:
            self.poisoned = True
            raise

    def arguments(self, operation, request):
        self.check()
        values = {"action": profile.ACTION, "resource_id": request["exchangeId"],
            "payload_digest": profile.sha256(profile.canonical(request)), "actor_id": self.actor,
            "request": request, "approval_id": None, "credential_policy": self.policy,
            "enrollment_original": self.encoded_enrollment}
        return profile.arguments(operation, values)

    def assertion(self, mfa):
        self.check()
        profile.require(not self.callback and type(mfa) is dict and set(mfa) == {MFA_FIELD, "assertion"}
            and mfa[MFA_FIELD] == profile.OPTIONS_SCHEMA and len(profile.canonical(mfa)) <= 16 * 1024)
        self.mfa, self.mfa_original = mfa, profile.canonical(mfa)
        assertion = mfa["assertion"]
        profile.require(type(assertion) is dict)
        self.credential = db.get_webauthn_credential(assertion.get("id"))
        profile.require(type(self.credential) is dict and self.credential["user_id"] == self.actor)
        self.check()
        client, _ = webauthn._parse_client_data(assertion.get("response", {}).get("clientDataJSON"), "webauthn.get")
        challenge = db.get_unused_webauthn_challenge(client["challenge"], challenge_type="policy_authority", user_id=self.actor)
        profile.require(challenge is not None)
        self.clip(_epoch_ns(challenge["expires_at"]))
        return {"challengeId": challenge["id"], "credentialRecordId": self.credential["id"], "assertion": assertion}

    def dispatch(self, operation, request, *, row=None, evidence=None):
        self.check()
        profile.require(operation not in self.attempts and ((operation == profile.OP_PREPARE) == (evidence is not None)))
        if row is not None:
            profile.require(profile.row_original(_row(row["id"])) == profile.row_original(row))
        arguments = self.arguments(operation, request)
        original = profile.canonical(arguments)
        expected_digest = profile.request_digest(operation, arguments)
        deadline = self.deadline
        if operation == profile.OP_CLAIM:
            consent = _json(row["consent_json"].encode("utf-8"), profile.MAX_ARGUMENT_BYTES)
            deadline = min(deadline, self.mono + consent["contactExpiresAtEpochNs"] - self.epoch)
            profile.require(time.monotonic_ns() < deadline)
        self.attempts.add(operation)
        from serverware.control_plane_custody_client import ControlPlaneCustodyClient
        result = ControlPlaneCustodyClient._request_authority(self.custody, operation=operation,
            input_value={"schema": "serverware.policyAuthorityControlledWriterInput/v1",
                "handler": authority_contract.operation_spec(operation)["handler"],
                "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
                "arguments": {**arguments, **({"authn_evidence": evidence} if evidence is not None else {})}},
            deadline_ns=deadline)
        self.check()
        expected = {"ok", "exchange", "operation", "requestDigest", "auditEventDigest", "idempotentReplay"}
        if operation == profile.OP_STAGE:
            expected.add("pending")
        profile.require(profile.canonical(arguments) == original and type(result) is dict and set(result) == expected
            and result["ok"] is True and result["operation"] == operation and result["requestDigest"] == expected_digest
            and result["idempotentReplay"] is False and type(result["exchange"]) is dict
            and set(result["exchange"]) == _PUBLIC_FIELDS)
        profile.digest(result["auditEventDigest"])
        if operation == profile.OP_STAGE:
            profile.require(type(result["pending"]) is dict and set(result["pending"]) == _PENDING_FIELDS)
        current = _row(request["exchangeId"])
        profile.require(current["status"] == _STATUS[operation] and _public(current) == result["exchange"])
        self.check()
        if operation == profile.OP_CLAIM:
            self.claim_original = profile.row_original(current)
        return current, result

    def contact(self, row, state, code):
        self.check()
        profile.require(self.callback and not self.contact_attempted and self.claim_original is not None
            and self.claim_original == profile.row_original(row)
            and self.claim_original == profile.row_original(_row(row["id"]))
            and row["status"] == "claimed" and row["code_sha256"] == profile.sha256(code.encode("utf-8")))
        request, digest = material.token_request(self.provider, state, code)
        profile.require(digest == row["contact_request_sha256"] and time.time_ns() < state["contactExpiresAtEpochNs"])
        contact_deadline = min(self.deadline, self.mono + state["contactExpiresAtEpochNs"] - self.epoch)
        self.check()
        self.contact_attempted = True
        # This source-owned bit can only be reached after this exact owner's
        # definite signed claim and matching full protected-row readback.
        return material.contact(request, self.application, deadline_ns=contact_deadline)


def _validate_state(owner, consent, browser_nonce, *, actor):
    profile.request_binding(profile.OP_PREPARE, consent)
    profile.require(consent["providerId"] == owner.provider.id and consent["redirectUri"] == owner.provider.redirect_uri
        and consent["enrollmentSha256"] == profile.sha256(owner.enrollment)
        and type(browser_nonce) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", browser_nonce) is not None
        and hmac.compare_digest(profile.sha256(browser_nonce.encode("ascii")), consent["browserNonceSha256"]))
    raw = _decrypted(profile.artifact_id(consent["exchangeId"], "state"), consent["stateEnvelope"])
    state = _json(raw, 64 * 1024)
    profile.require(set(state) == _STATE_FIELDS and state["schema"] == STATE_SCHEMA
        and profile.sha256(raw) == consent["stateOriginalSha256"] and state["requesterId"] == actor
        and _state_id(state["state"]) == consent["exchangeId"]
        and profile.sha256(state["state"].encode("ascii")) == consent["stateSha256"]
        and type(state["codeVerifier"]) is str and re.fullmatch(r"[A-Za-z0-9_-]{43,128}", state["codeVerifier"]) is not None
        and profile.sha256(state["codeVerifier"].encode("ascii")) == consent["pkceVerifierSha256"]
        and state["oauth_application_owner"] == owner.association and state["credentialPolicy"] == owner.policy
        and _decrypted(consent["exchangeId"], consent["reservedEnvelope"]) == b"{}")
    for field in ("exchangeId", "browserNonceSha256", "providerId", "credentialName", "scopes", "metadata", "redirectUri",
            "issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "enrollmentSha256", "limits"):
        profile.require(state[field] == consent[field])
    profile.require(state["limits"] == {"pendingCapacity": min(config.OAUTH_PENDING_CREDENTIAL_MAX_COUNT, 64), "revocationCapacity": 64})
    owner.application.require_association(state["oauth_application_owner"])
    owner.check()
    return state


def _set_cookie(response, state, nonce):
    response.set_cookie(oauth.browser_cookie_name(state["state"]), nonce,
        max_age=max(1, (state["contactExpiresAtEpochNs"] - time.time_ns()) // 1_000_000_000),
        path="/", secure=True, httponly=True, samesite="lax")


def options_on_request(request, response, payload):
    owner = _Owner(request, payload.provider)
    profile.require(payload.mfa is None and payload.credential_id is None
        and payload.setup_session_id is None and payload.setup_revision is None)
    metadata = oauth._bounded_metadata(payload.metadata)
    profile.require(applications.ASSOCIATION_KEY not in metadata)
    metadata[applications.ASSOCIATION_KEY] = owner.association
    scopes = list(oauth.resolve_requested_scopes(owner.provider.id, payload.scopes))
    name = oauth._bounded_credential_name(payload.credential_name, owner.provider.display_name + " OAuth credential")
    exchange_id, browser = str(uuid.uuid4()), secrets.token_urlsafe(32)
    state_text, verifier = uuid.UUID(exchange_id).hex + "_" + secrets.token_urlsafe(32), oauth._code_verifier()
    issued = time.time_ns()
    enrollment = _json(owner.enrollment, 64 * 1024)["payload"]
    contact = min(issued + min(config.OAUTH_STATE_TTL_SECONDS, 600) * 1_000_000_000, enrollment["expiresAtEpochNs"])
    pending = min(contact + config.OAUTH_PENDING_CREDENTIAL_TTL_SECONDS * 1_000_000_000, enrollment["expiresAtEpochNs"])
    retention = min(contact + 600_000_000_000, pending)
    state = {"schema": STATE_SCHEMA, "exchangeId": exchange_id, "state": state_text,
        "browserNonceSha256": profile.sha256(browser.encode("ascii")), "codeVerifier": verifier,
        "providerId": owner.provider.id, "requesterId": owner.actor, "credentialName": name,
        "scopes": scopes, "metadata": metadata, "redirectUri": owner.provider.redirect_uri,
        "issuedAtEpochNs": issued, "contactExpiresAtEpochNs": contact,
        "retentionExpiresAtEpochNs": retention, "pendingExpiresAtEpochNs": pending,
        "enrollmentSha256": profile.sha256(owner.enrollment), "oauth_application_owner": owner.association,
        "credentialPolicy": owner.policy,
        "limits": {"pendingCapacity": min(config.OAUTH_PENDING_CREDENTIAL_MAX_COUNT, 64), "revocationCapacity": 64}}
    raw = profile.canonical(state)
    consent = {name: state[name] for name in ("exchangeId", "browserNonceSha256", "providerId", "redirectUri",
        "credentialName", "scopes", "metadata", "issuedAtEpochNs", "contactExpiresAtEpochNs",
        "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "enrollmentSha256", "limits")}
    consent.update(stateSha256=profile.sha256(state_text.encode("ascii")), pkceVerifierSha256=profile.sha256(verifier.encode("ascii")),
        stateOriginalSha256=profile.sha256(raw), stateEnvelope=_encrypted(profile.artifact_id(exchange_id, "state"), raw),
        reservedEnvelope=_encrypted(exchange_id, b"{}"))
    _validate_state(owner, consent, browser, actor=owner.actor)
    owner.clip(issued + 30_000_000_000)
    arguments = owner.arguments(profile.OP_PREPARE, consent)
    descriptors = webauthn._credential_descriptors_for_policy(owner.actor, activation._authenticator_policy(owner.policy))
    profile.require(type(descriptors) is list and 1 <= len(descriptors) <= 64)
    owner.credential = db.get_webauthn_credential(descriptors[0]["id"])
    profile.require(type(owner.credential) is dict and owner.credential["user_id"] == owner.actor)
    owner.check()
    challenge = db.issue_policy_authority_webauthn_challenge(operation=profile.OP_PREPARE,
        input_value=arguments, user_id=owner.actor, credential_id=owner.credential["credential_id"], deadline_ns=owner.deadline)
    owner.check()
    value = challenge["payload"]
    profile.require(challenge["challenge_type"] == "policy_authority" and challenge["user_id"] == owner.actor
        and challenge["used_at"] is None and value["credentialId"] == owner.credential["credential_id"]
        and value["rpId"] == owner.policy["rpId"] and value["origin"] in owner.policy["origins"])
    profile.digest(value["operationId"])
    profile.digest(challenge["id"])
    profile.text(owner.credential["id"], 256)
    _set_cookie(response, state, browser)
    owner.check()
    return {"publicKey": {"challenge": challenge["challenge"], "rpId": value["rpId"],
        "allowCredentials": [{"type": "public-key", "id": owner.credential["credential_id"]}],
        "timeout": 30000, "userVerification": "required"},
        "serverware": {"schema": profile.OPTIONS_SCHEMA, "operation": profile.OP_PREPARE,
            "operationId": value["operationId"], "challengeId": challenge["id"],
            "credentialRecordId": owner.credential["id"], "payloadDigest": arguments["payload_digest"],
            "expiresAt": challenge["expires_at"]}, "request": consent}


def start_on_request(request, response, payload):
    consent = profile.request_binding(profile.OP_PREPARE, payload.request_binding)
    owner = _Owner(request, consent["providerId"])
    profile.require(payload.api_version == profile.OPTIONS_SCHEMA)
    private = _json(_decrypted(profile.artifact_id(consent["exchangeId"], "state"), consent["stateEnvelope"]), 64 * 1024)
    nonce = request.cookies.get(oauth.browser_cookie_name(private["state"]), "")
    state = _validate_state(owner, consent, nonce, actor=owner.actor)
    owner.clip(min(consent["issuedAtEpochNs"] + 30_000_000_000, consent["contactExpiresAtEpochNs"]))
    owner.dispatch(profile.OP_PREPARE, consent, evidence=owner.assertion(payload.mfa))
    query = {"response_type": "code", "client_id": owner.provider.client_id,
        "redirect_uri": owner.provider.redirect_uri, "scope": " ".join(state["scopes"]), "state": state["state"],
        "code_challenge": oauth._code_challenge(state["codeVerifier"]), "code_challenge_method": "S256",
        **owner.provider.auth_params}
    _set_cookie(response, state, nonce)
    owner.check()
    return {"provider": owner.provider.id,
        "authorizationUrl": owner.provider.authorization_url + "?" + urllib.parse.urlencode(query),
        "state": state["state"], "expiresAtEpoch": state["contactExpiresAtEpochNs"] // 1_000_000_000,
        "redirectUri": owner.provider.redirect_uri, "scopes": state["scopes"]}


def callback_on_request(request, provider_id, *, code, state, error, error_description):
    owner = _Owner(request, provider_id, callback=True)
    pairs = list(request.query_params.multi_items())
    profile.require(len(pairs) == len({key for key, _ in pairs}) and set(dict(pairs)) <= {"code", "state", "error", "error_description"}
        and all(dict(pairs).get(key) == value for key, value in
            (("code", code), ("state", state), ("error", error), ("error_description", error_description))))
    exchange_id = _state_id(state)
    row = _row(exchange_id)
    consent = _json(row["consent_json"].encode("utf-8"), profile.MAX_ARGUMENT_BYTES)
    profile.require(row["provider_id"] == owner.provider.id and row["enrollment_original"] == owner.encoded_enrollment
        and row["credential_policy_json"] == owner.policy_original.decode("ascii"))
    cookie_name = oauth.browser_cookie_name(state)
    profile.require(len(request.headers.getlist("cookie")) == 1)
    cookie_names = [part.strip().split("=", 1)[0] for part in request.headers["cookie"].split(";")]
    profile.require(cookie_names.count(cookie_name) == 1)
    nonce = request.cookies.get(cookie_name, "")
    owner.actor = row["requester_id"]
    private = _validate_state(owner, consent, nonce, actor=owner.actor)
    profile.require(private["state"] == state)
    owner.clip(consent["retentionExpiresAtEpochNs"])
    # Denial/malformed callbacks do not consume, delete or rewrite a protected
    # exchange through a development helper. They never contact the provider.
    profile.require(error is None and error_description is None and row["status"] == "prepared")
    _, contact_digest = material.token_request(owner.provider, private, code)
    def possession(current):
        return {"exchangeId": exchange_id, "exchangeRowSha256": profile.row_digest(current),
            "state": state, "browserNonce": nonce, "limits": consent["limits"]}
    row, _ = owner.dispatch(profile.OP_CLAIM, {**possession(row),
        "codeSha256": profile.sha256(code.encode("utf-8")), "contactRequestSha256": contact_digest}, row=row)
    response, response_original = owner.contact(row, private, code)
    token_original, token, stageable = material.token_original(response, private)
    response_envelope = _encrypted(profile.artifact_id(exchange_id, "response"), response_original)
    try:
        token_envelope = None if token_original is None else _encrypted(exchange_id, token_original)
    except (TypeError, ValueError, UnicodeError):
        # Preserve the raw reply even when its extracted material cannot fit
        # the separately closed credential envelope. It cannot be staged.
        token_original, token, token_envelope, stageable = None, None, None, False
    owner.check()
    row, _ = owner.dispatch(profile.OP_RETAIN, {**possession(row),
        "rawResponseSha256": profile.sha256(response_original), "rawResponseEnvelope": response_envelope,
        "tokenSecretSha256": None if token_original is None else profile.sha256(token_original),
        "tokenEnvelope": token_envelope}, row=row)
    # Definite retention precedes any identity GET. Check the actual encrypted
    # originals by decrypting them, not by calling ciphertext equality plaintext proof.
    stored_response = _json(row["raw_response_envelope_json"].encode("utf-8"), profile.MAX_ENVELOPE_BYTES)
    profile.require(_decrypted(profile.artifact_id(exchange_id, "response"), stored_response) == response_original)
    profile.require(stageable and token_original is not None)
    stored_token = _json(row["token_envelope_json"].encode("utf-8"), profile.MAX_ENVELOPE_BYTES)
    profile.require(_decrypted(exchange_id, stored_token) == token_original
        and row["token_secret_sha256"] == profile.sha256(token_original))
    owner.check()
    metadata, review = material.review_after_retention(owner.provider, private, token, owner.application)
    payload_digest = profile.sha256(profile.canonical({"action": "credential.oauth.activate", "review": review,
        "encrypted_token_source_sha256": profile.sha256(token_original)}))
    row, result = owner.dispatch(profile.OP_STAGE, {**possession(row), "metadata": metadata, "review": review,
        "payloadDigest": payload_digest, "tokenSecretSha256": profile.sha256(token_original)}, row=row)
    with db.connect() as connection:
        pending = connection.execute("SELECT * FROM pending_oauth_credentials WHERE id = ?", (exchange_id,)).fetchone()
    profile.require(pending is not None and db.row_to_pending_oauth_credential(pending) == result["pending"]
        and dict(pending)["requester_id"] == owner.actor and dict(pending)["payload_digest"] == payload_digest
        and _decrypted(exchange_id, {field: pending[field] for field in profile.ENVELOPE_FIELDS}) == token_original)
    owner.check()
    return {"pendingCredentialId": exchange_id, "expiresAt": result["pending"]["expires_at"]}
