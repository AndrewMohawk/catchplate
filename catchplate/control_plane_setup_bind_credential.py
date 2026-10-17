"""One explicit protected binding of an existing public credential generation.

The source-controlled writer independently proves generation/currentness,
participation, hardware and durable effects. This owner reads only public
generation metadata; it never decrypts, mutates protected rows or retries.
Factual settlement is separate from a new binding or hardware approval.
"""
import os
import threading
import time

from fastapi import Request

from catchplate import auth, authority_contract, db, webauthn
from catchplate import authority_oauth_setup as rows
from catchplate import authority_setup_bind_credential as profile
from catchplate import control_plane_custody_client as custody_client
from catchplate import control_plane_custody_startup as startup
from catchplate import control_plane_oauth_activation as hardware
from catchplate.control_plane_approval_verification import _epoch_ns, _request_pin

MAX_REQUEST, MAX_RESPONSE = profile.MAX_HTTP_REQUEST, profile.MAX_HTTP_RESPONSE


def selected():
    """Current request transport only, not signed purpose or capacity admission."""
    return db.metadata_uses_postgres() and startup.require_started() is not None


def _identity(request, session_id):
    profile.require(type(request) is Request and request.method == "POST"
        and request.url.path in {"/api/setup/sessions/" + session_id + "/credential/" + phase
            for phase in ("draft", "options", "execute", "settle")}
        and not request.url.query and not request.headers.getlist("authorization")
        and not request.headers.getlist("x-catchplate-admin-token")
        and request.headers.getlist("origin") == [webauthn.WEBAUTHN_ORIGIN]
        and webauthn.WEBAUTHN_ORIGIN not in ("", "null") and len(request.headers.getlist("cookie")) == 1)
    names = [item.strip().split("=", 1)[0] for item in request.headers["cookie"].split(";")]
    profile.require(len(names) == len(set(names)) and not request.cookies.get("catchplate_admin"))
    identity = auth.oidc_identity_from_session_token(request.cookies.get(auth.OIDC_SESSION_COOKIE_NAME))
    profile.require(type(identity) is auth.AdminIdentity and identity.user_id.startswith("oidc:")
        and bool(profile.MUTATION_ROLES.intersection(identity.roles)))
    auth.validate_csrf_request(request)
    return identity


def _session(session_id):
    profile.identifier(session_id)
    with db.connect() as connection:
        value = connection.execute("SELECT * FROM setup_sessions WHERE id = ?", (session_id,)).fetchone()
    profile.require(value is not None, "Original Setup is unavailable; absence does not authorize a retry")
    value = dict(value)
    profile.row_original(value)
    return value


def _credential(credential_id):
    profile.identifier(credential_id)
    # The existing owner locks and reads exactly the five non-secret columns.
    # The kernel independently authenticates their actual generation/root.
    with db.credential_generation_snapshot(credential_id) as value:
        profile.require(value is not None, "Current public credential generation is unavailable")
        original = profile.credential_original(value)
    return profile.credential(original.decode("ascii"))


def _event(session_id, event_id):
    profile.identifier(event_id)
    with db.connect() as connection:
        value = connection.execute("SELECT * FROM setup_session_events WHERE id = ?", (event_id,)).fetchone()
    profile.require(value is not None)
    value = dict(value)
    profile.require(set(value) == profile.EVENT_FIELDS and value["session_id"] == session_id
        and value["transition"] == "bind_credential")
    raw = value["event_json"].encode("ascii")
    document = rows.document(raw, profile.MAX_EVENT_BYTES)
    profile.require(profile.canonical(document) == raw and value["payload_digest"] == profile.sha256(raw)
        and document["setup_session_id"] == session_id and document["transition"] == "bind_credential"
        and document["details"]["authorityOperation"] == profile.OPERATION)
    return value, document


class _Owner:
    def __init__(self, request, session_id, *, settlement=False):
        profile.identifier(session_id)
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
        self.values = self.arguments_original = self.target = self.target_original = None
        self.credential = self.mfa = self.mfa_original = None
        self.dispatched, self.completed_original = False, None
        profile.require(type(settlement) is bool and settlement == request.url.path.endswith("/settle"))
        if settlement:
            # An expired/terminal tracking run does not invalidate a factual
            # audit readback. Only the current processing/custody window applies.
            self.check()
        else:
            profile.require(self.session["status"] == "active" and self.session["phase"] == "created"
                and self.session["terminal_at"] is None and self.session["credential_id"] is None
                and self.session["credential_version"] is None)
            self.clip(profile.epoch(self.session["expires_at"]))

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
        if self.arguments_original is not None:
            profile.require(profile.canonical(self.values) == self.arguments_original)
        if self.target_original is not None:
            profile.require(profile.credential_original(self.target) == self.target_original
                and profile.credential_original(_credential(self.target["id"])) == self.target_original)
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
        profile.require(self.values is None and type(original) is str)
        raw = original.encode("ascii")
        value = profile.arguments(profile.OPERATION, rows.document(raw, profile.MAX_ARGUMENT_BYTES))
        profile.require(profile.canonical(value) == raw and value["actor_id"] == self.identity.user_id
            and value["control_plane_configuration_digest"] == self.configuration and value["credential_policy"] == self.policy
            and value["request"]["sessionOriginal"].encode("ascii") == self.original
            and value["request"]["issuedAtEpochNs"] <= self.last_epoch)
        self.values, self.arguments_original = value, raw
        self.target = profile.credential(value["request"]["credentialOriginal"])
        self.target_original = profile.credential_original(self.target)
        self.clip(value["request"]["expiresAtEpochNs"])
        return value

    def options(self):
        self.check()
        descriptors = webauthn._credential_descriptors_for_policy(self.identity.user_id, hardware._authenticator_policy(self.policy))
        profile.require(type(descriptors) is list and 1 <= len(descriptors) <= 64)
        self.credential = db.get_webauthn_credential(descriptors[0]["id"])
        profile.require(type(self.credential) is dict and self.credential["user_id"] == self.identity.user_id)
        self.check()
        challenge = db.issue_policy_authority_webauthn_challenge(operation=profile.OPERATION, input_value=self.values,
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
            "operation": profile.OPERATION, "requestDigest": profile.request_digest(profile.OPERATION, self.values),
            "challengeId": challenge["id"], "credentialRecordId": self.credential["id"], "expiresAt": challenge["expires_at"]}}
        self.check()
        return result

    def execute(self, mfa):
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
        self.check(); profile.require(not self.dispatched); self.dispatched = True
        result = custody_client.ControlPlaneCustodyClient._request_authority(self.custody, operation=profile.OPERATION,
            input_value={"schema": "catchplate.policyAuthorityControlledWriterInput/v1",
                "handler": authority_contract.operation_spec(profile.OPERATION)["handler"],
                "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
                "arguments": {**self.values, "authn_evidence": evidence}}, deadline_ns=self.deadline)
        self.check()
        profile.require(type(result) is dict and set(result) == {"ok", "operation", "requestDigest", "auditEventDigest",
            "idempotentReplay", "setupOriginal", "setupEventId", "auditState"}
            and result["ok"] is True and result["operation"] == profile.OPERATION and result["idempotentReplay"] is False
            and result["requestDigest"] == profile.request_digest(profile.OPERATION, self.values)
            and result["auditState"] == "controlled_pending")
        profile.digest(result["auditEventDigest"]); profile.identifier(result["setupEventId"])
        returned = profile.row(result["setupOriginal"])
        changed = {"credential_id", "credential_version", "phase", "revision", "updated_at"}
        updated = profile.epoch(returned["updated_at"])
        profile.require(returned["credential_id"] == self.target["id"]
            and returned["credential_version"] == self.target["credential_version"]
            and returned["phase"] == "credential_activated" and returned["revision"] == self.session["revision"] + 1
            and self.values["request"]["issuedAtEpochNs"] <= updated < self.values["request"]["expiresAtEpochNs"]
            and updated >= profile.epoch(self.session["updated_at"])
            and all(returned[name] == value for name, value in self.session.items() if name not in changed))
        self.completed_original = profile.row_original(returned)
        event, document = _event(self.session_id, result["setupEventId"])
        profile.require(event["audit_status"] == "controlled_pending" and type(event["sequence"]) is int and event["sequence"] >= 1
            and event["actor_id"] == self.identity.user_id and event["created_at"] == returned["updated_at"]
            and document["from_phase"] == "created" and document["to_phase"] == "credential_activated"
            and document["binding_updates"] == {"credential_id": self.target["id"], "credential_version": self.target["credential_version"]}
            and document["details"]["authorityRequestDigest"] == result["requestDigest"]
            and document["details"]["setupPreSha256"] == profile.sha256(self.original)
            and document["details"]["setupPostSha256"] == profile.sha256(self.completed_original)
            and document["details"]["credentialOriginalSha256"] == profile.sha256(self.target_original))
        self.check()
        return result

    def settle(self, event_id):
        profile.require(self.values is None and not self.dispatched)
        event, _ = _event(self.session_id, event_id)
        profile.require(event["audit_status"] == "controlled_pending")
        original = profile.canonical(event)
        arguments = profile.arguments(profile.OP_SETTLE, {"event_id": event_id})
        self.check()
        profile.require(profile.canonical(_event(self.session_id, event_id)[0]) == original)
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
        observed, _ = _event(self.session_id, event_id)
        profile.require(observed["audit_status"] == "audited" and observed["audit_event_hash"] == result["auditEventHash"]
            and observed["audited_at"] is not None
            and all(observed[name] == value for name, value in event.items() if name not in {"audit_status", "audited_at", "audit_event_hash"}))
        self.check()
        return result


def on_request(request, session_id, raw):
    value = rows.document(raw, MAX_REQUEST)
    profile.require(type(value) is dict and profile.canonical(value) == raw and value.get("apiVersion") == profile.HTTP_SCHEMA)
    phase = request.url.path.rsplit("/", 1)[1]
    owner = _Owner(request, session_id, settlement=phase == "settle")
    if phase == "settle":
        profile.require(set(value) == {"apiVersion", "eventId"})
        return owner.settle(value["eventId"])
    if phase == "draft":
        profile.require(set(value) == {"apiVersion", "expectedRevision", "credentialId", "expectedCredentialVersion"}
            and type(value["expectedRevision"]) is int and value["expectedRevision"] == owner.session["revision"]
            and type(value["expectedCredentialVersion"]) is int and 1 <= value["expectedCredentialVersion"] <= 2**63 - 1)
        target = _credential(value["credentialId"])
        profile.require(target["credential_version"] == value["expectedCredentialVersion"])
        issued = time.time_ns() // 1000 * 1000
        arguments = profile.arguments(profile.OPERATION, {"actor_id": owner.identity.user_id,
            "control_plane_configuration_digest": owner.configuration, "credential_policy": owner.policy,
            "request": {"sessionOriginal": owner.original.decode("ascii"),
                "credentialOriginal": profile.credential_original(target).decode("ascii"),
                "issuedAtEpochNs": issued, "expiresAtEpochNs": min(owner.expires // 1000 * 1000, issued + 30_000_000_000)}})
        owner.check()
        original = profile.canonical(arguments).decode("ascii")
        owner.arguments(original)
        result = {"apiVersion": profile.HTTP_SCHEMA, "okForAction": False, "argumentsOriginal": original,
            "requestDigest": profile.request_digest(profile.OPERATION, arguments)}
        owner.check()
        return result
    profile.require(phase in {"options", "execute"} and set(value) == ({"apiVersion", "argumentsOriginal"}
        if phase == "options" else {"apiVersion", "argumentsOriginal", "mfa"}))
    owner.arguments(value["argumentsOriginal"])
    return owner.options() if phase == "options" else owner.execute(value["mfa"])
