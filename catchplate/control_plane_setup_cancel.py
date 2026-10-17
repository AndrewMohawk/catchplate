"""One explicit, hardware-bound cancellation of retained Setup tracking.

The controlled writer owns the mutation. No provider enrollment, credential
revocation, policy abort, workload stop, local DML or retry is supplied here.
"""
import os
import threading
import time

from fastapi import Request

from catchplate import auth, authority_contract, db, webauthn
from catchplate import authority_oauth_setup as rows
from catchplate import authority_setup_cancel as profile
from catchplate import control_plane_custody_client as custody_client
from catchplate import control_plane_custody_startup as startup
from catchplate import control_plane_oauth_activation as hardware
from catchplate.control_plane_approval_verification import _epoch_ns, _request_pin

ROLES = frozenset({"admin", "attestation_operator", "attestation_reviewer", "credential_owner", "policy_author", "policy_publisher"})
MAX_REQUEST = 1024 * 1024
MAX_RESPONSE = 1024 * 1024


def selected():
    """A current request transport, not proof of purpose admission or success."""
    return db.metadata_uses_postgres() and startup.require_started() is not None


def _identity(request, session_id):
    profile.require(type(request) is Request and request.method == "POST"
        and request.url.path in {"/api/setup/sessions/" + session_id + "/cancel/" + phase for phase in ("draft", "options", "execute", "settle")}
        and not request.url.query and not request.headers.getlist("authorization")
        and not request.headers.getlist("x-catchplate-admin-token")
        and request.headers.getlist("origin") == [webauthn.WEBAUTHN_ORIGIN]
        and webauthn.WEBAUTHN_ORIGIN not in ("", "null") and len(request.headers.getlist("cookie")) == 1)
    names = [item.strip().split("=", 1)[0] for item in request.headers["cookie"].split(";")]
    profile.require(len(names) == len(set(names)) and not request.cookies.get("catchplate_admin"))
    identity = auth.oidc_identity_from_session_token(request.cookies.get(auth.OIDC_SESSION_COOKIE_NAME))
    profile.require(type(identity) is auth.AdminIdentity and identity.user_id.startswith("oidc:")
        and bool(ROLES.intersection(identity.roles)))
    auth.validate_csrf_request(request)
    return identity


def _session(session_id):
    rows.identifier(session_id)
    with db.connect() as connection:
        value = connection.execute("SELECT * FROM setup_sessions WHERE id = ?", (session_id,)).fetchone()
    profile.require(value is not None, "Setup original unavailable; absence is not cancellation")
    value = dict(value)
    profile.row_original(value)
    return value


def _event(session_id, event_id):
    rows.identifier(event_id)
    with db.connect() as connection:
        value = connection.execute("SELECT * FROM setup_session_events WHERE id = ?", (event_id,)).fetchone()
    profile.require(value is not None)
    value = dict(value)
    profile.require(set(value) == profile.EVENT_FIELDS and value["session_id"] == session_id and value["transition"] == "cancel")
    document = rows.document(value["event_json"].encode("ascii"), profile.MAX_EVENT_BYTES)
    profile.require(document["details"]["authorityOperation"] == profile.OPERATION)
    return value


class _Owner:
    def __init__(self, request, session_id, *, settlement=False):
        rows.identifier(session_id)
        self.started_mono, self.started_epoch = time.monotonic_ns(), time.time_ns()
        self.request, self.scope, self.pin = request, request.scope, _request_pin(request)
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.session_id, self.identity = session_id, _identity(request, session_id)
        self.policy = profile.policy(hardware._policy())
        self.policy_original = profile.canonical(self.policy)
        self.custody = startup.require_started()
        profile.require(db.metadata_uses_postgres() and self.custody is not None)
        self.binding = custody_client._snapshot(self.custody)
        self.configuration = self.binding.configuration_digest
        self.last_mono, self.last_epoch = self.started_mono, self.started_epoch
        self.expires = min(self.started_epoch + 30_000_000_000, self.binding.attestation_interval[1])
        self.deadline = self.started_mono + self.expires - self.started_epoch
        self.session = _session(session_id)
        self.original = profile.row_original(self.session)
        self.credential = self.mfa = self.mfa_original = self.arguments_original = None
        self.dispatched, self.completed_original = False, None
        profile.require(type(settlement) is bool and settlement == request.url.path.endswith("/settle"))
        if settlement:
            profile.require(self.session["status"] == self.session["phase"] == "cancelled" and self.session["terminal_at"] is not None)
            self.check()
        else:
            profile.require(self.session["status"] == "active" and self.session["terminal_at"] is None)
            self.clip(rows.epoch(self.session["expires_at"]))

    def clip(self, expires):
        profile.require(type(expires) is int)
        self.expires = min(self.expires, expires)
        self.deadline = min(self.deadline, self.started_mono + self.expires - self.started_epoch)
        self.check()

    def check(self):
        mono, epoch = time.monotonic_ns(), time.time_ns()
        profile.require((os.getpid(), threading.get_ident()) == (self.pid, self.thread)
            and self.last_mono <= mono < self.deadline and self.last_epoch <= epoch < self.expires
            and self.request.scope is self.scope and _request_pin(self.request) == self.pin
            and _identity(self.request, self.session_id) == self.identity
            and profile.canonical(hardware._policy()) == self.policy_original
            and startup.require_started() is self.custody and custody_client._snapshot(self.custody) is self.binding
            and self.binding.configuration_digest == self.configuration
            and profile.row_original(self.session) == self.original
            and ("admin" in self.identity.roles or self.identity.user_id in {self.session["owner_id"], self.session["current_assignee_id"]}))
        custody_client._receipt_now(self.binding)
        expected = self.completed_original if self.dispatched else self.original
        if expected is not None:
            profile.require(profile.row_original(_session(self.session_id)) == expected)
        if self.mfa_original is not None:
            profile.require(profile.canonical(self.mfa) == self.mfa_original)
        if self.credential is not None:
            current = db.get_webauthn_credential_by_record_id(self.credential["id"])
            profile.require(type(current) is dict and current.get("revoked_at") is None
                and all(current.get(name) == self.credential.get(name) for name in ("id", "credential_id", "user_id", "public_key_cose")))
            trust = webauthn._allowed_authenticator(current, hardware._authenticator_policy(self.policy))
            profile.require(trust["currently_trusted"] is True and trust["effective_authenticator_class"] in {"hardware", "yubikey"})
        closing_mono, closing_epoch = time.monotonic_ns(), time.time_ns()
        profile.require(mono <= closing_mono < self.deadline and epoch <= closing_epoch < self.expires)
        self.last_mono, self.last_epoch = closing_mono, closing_epoch

    def arguments(self, original):
        profile.require(type(original) is str)
        value = profile.arguments(profile.OPERATION, rows.document(original.encode("ascii"), profile.MAX_ARGUMENT_BYTES))
        profile.require(profile.canonical(value).decode("ascii") == original and value["actor_id"] == self.identity.user_id
            and value["control_plane_configuration_digest"] == self.configuration and value["credential_policy"] == self.policy
            and value["request"]["sessionOriginal"].encode("ascii") == self.original
            and value["request"]["issuedAtEpochNs"] <= self.last_epoch)
        self.arguments_original = original
        self.clip(value["request"]["expiresAtEpochNs"])
        return value

    def options(self, arguments):
        descriptors = webauthn._credential_descriptors_for_policy(self.identity.user_id, hardware._authenticator_policy(self.policy))
        profile.require(type(descriptors) is list and 1 <= len(descriptors) <= 64)
        self.credential = db.get_webauthn_credential(descriptors[0]["id"])
        profile.require(type(self.credential) is dict and self.credential["user_id"] == self.identity.user_id)
        self.check()
        challenge = db.issue_policy_authority_webauthn_challenge(operation=profile.OPERATION, input_value=arguments,
            user_id=self.identity.user_id, credential_id=self.credential["credential_id"], deadline_ns=self.deadline)
        self.check()
        payload = challenge["payload"]
        profile.require(challenge["used_at"] is None and challenge["user_id"] == self.identity.user_id
            and challenge["challenge_type"] == "policy_authority" and payload["credentialId"] == self.credential["credential_id"]
            and payload["rpId"] == self.policy["rpId"] and payload["origin"] in self.policy["origins"])
        timeout_ms = min(30000, (self.expires - self.last_epoch) // 1_000_000)
        profile.require(1 <= timeout_ms <= 30000)
        result = {"publicKey": {"challenge": challenge["challenge"], "rpId": payload["rpId"],
            "allowCredentials": [{"type": "public-key", "id": self.credential["credential_id"]}],
            "timeout": timeout_ms, "userVerification": "required"}, "catchplate": {"schema": profile.OPTIONS_SCHEMA,
            "operation": profile.OPERATION, "requestDigest": profile.request_digest(profile.OPERATION, arguments),
            "challengeId": challenge["id"], "credentialRecordId": self.credential["id"], "expiresAt": challenge["expires_at"]}}
        self.check()
        return result

    def execute(self, arguments, mfa):
        profile.require(type(mfa) is dict and set(mfa) == {profile.MFA_FIELD, "assertion"}
            and mfa[profile.MFA_FIELD] == profile.OPTIONS_SCHEMA and len(profile.canonical(mfa)) <= 16384)
        self.mfa, self.mfa_original = mfa, profile.canonical(mfa)
        assertion = mfa["assertion"]
        profile.require(type(assertion) is dict)
        self.credential = db.get_webauthn_credential(assertion.get("id"))
        profile.require(type(self.credential) is dict and self.credential["user_id"] == self.identity.user_id)
        self.check()
        client, _ = webauthn._parse_client_data(assertion.get("response", {}).get("clientDataJSON"), "webauthn.get")
        challenge = db.get_unused_webauthn_challenge(client["challenge"], challenge_type="policy_authority", user_id=self.identity.user_id)
        profile.require(challenge is not None)
        self.clip(_epoch_ns(challenge["expires_at"]))
        evidence = {"challengeId": challenge["id"], "credentialRecordId": self.credential["id"], "assertion": assertion}
        profile.require(not self.dispatched and profile.canonical(arguments).decode("ascii") == self.arguments_original)
        self.check()
        self.dispatched = True
        result = custody_client.ControlPlaneCustodyClient._request_authority(self.custody, operation=profile.OPERATION,
            input_value={"schema": "catchplate.policyAuthorityControlledWriterInput/v1",
                "handler": authority_contract.operation_spec(profile.OPERATION)["handler"],
                "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
                "arguments": {**arguments, "authn_evidence": evidence}}, deadline_ns=self.deadline)
        self.check()
        profile.require(type(result) is dict and set(result) == {"ok", "operation", "requestDigest", "auditEventDigest",
            "idempotentReplay", "setupOriginal", "setupEventId", "auditState"}
            and result["ok"] is True and result["operation"] == profile.OPERATION and result["idempotentReplay"] is False
            and result["requestDigest"] == profile.request_digest(profile.OPERATION, arguments)
            and result["auditState"] == "controlled_pending")
        profile.digest(result["auditEventDigest"]); rows.identifier(result["setupEventId"])
        returned = profile.row(result["setupOriginal"])
        changed = {"status", "phase", "revision", "updated_at", "terminal_at"}
        profile.require(returned["id"] == self.session_id and returned["status"] == returned["phase"] == "cancelled"
            and returned["revision"] == self.session["revision"] + 1
            and all(returned[name] == value for name, value in self.session.items() if name not in changed))
        self.completed_original = profile.row_original(returned)
        self.check()
        return result


    def settle(self, event_id):
        event = _event(self.session_id, event_id)
        profile.require(event["audit_status"] == "controlled_pending")
        original = profile.canonical(event)
        arguments = profile.arguments(profile.OP_SETTLE, {"event_id": event_id})
        self.check()
        profile.require(not self.dispatched and profile.canonical(_event(self.session_id, event_id)) == original)
        self.dispatched, self.completed_original = True, self.original
        result = custody_client.ControlPlaneCustodyClient._request_authority(self.custody, operation=profile.OP_SETTLE,
            input_value={"schema": "catchplate.policyAuthorityControlledWriterInput/v1",
                "handler": authority_contract.operation_spec(profile.OP_SETTLE)["handler"],
                "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST, "arguments": arguments}, deadline_ns=self.deadline)
        self.check()
        profile.require(type(result) is dict and set(result) == {"ok", "operation", "requestDigest", "auditEventDigest",
            "idempotentReplay", "eventId", "auditState", "auditEventHash"}
            and result["ok"] is True and result["operation"] == profile.OP_SETTLE and result["idempotentReplay"] is False
            and result["eventId"] == event_id and result["auditState"] == "audited"
            and result["requestDigest"] == profile.request_digest(profile.OP_SETTLE, arguments))
        profile.digest(result["auditEventDigest"]); profile.digest(result["auditEventHash"])
        observed = _event(self.session_id, event_id)
        profile.require(observed["audit_status"] == "audited" and observed["audit_event_hash"] == result["auditEventHash"]
            and observed["audited_at"] is not None
            and all(observed[name] == value for name, value in event.items() if name not in {"audit_status", "audited_at", "audit_event_hash"}))
        self.check()
        return result


def on_request(request, session_id, raw):
    value = rows.document(raw, MAX_REQUEST)
    profile.require(profile.canonical(value) == raw and type(value) is dict and value.get("apiVersion") == profile.HTTP_SCHEMA)
    phase = request.url.path.rsplit("/", 1)[1]
    owner = _Owner(request, session_id, settlement=phase == "settle")
    if phase == "settle":
        profile.require(set(value) == {"apiVersion", "eventId"})
        return owner.settle(value["eventId"])
    if phase == "draft":
        profile.require(set(value) == {"apiVersion", "expectedRevision", "reason"}
            and type(value["expectedRevision"]) is int and value["expectedRevision"] == owner.session["revision"])
        issued = time.time_ns() // 1000 * 1000
        arguments = profile.arguments(profile.OPERATION, {"actor_id": owner.identity.user_id,
            "control_plane_configuration_digest": owner.configuration, "credential_policy": owner.policy,
            "request": {"sessionOriginal": owner.original.decode("ascii"), "reason": value["reason"],
                "issuedAtEpochNs": issued, "expiresAtEpochNs": min(owner.expires // 1000 * 1000, issued + 30_000_000_000)}})
        result = {"apiVersion": profile.HTTP_SCHEMA, "okForAction": False,
            "argumentsOriginal": profile.canonical(arguments).decode("ascii"),
            "requestDigest": profile.request_digest(profile.OPERATION, arguments)}
        owner.check()
        return result
    profile.require(phase in {"options", "execute"} and set(value) == ({"apiVersion", "argumentsOriginal"}
        if phase == "options" else {"apiVersion", "argumentsOriginal", "mfa"}))
    arguments = owner.arguments(value["argumentsOriginal"])
    return owner.options(arguments) if phase == "options" else owner.execute(arguments, value["mfa"])
