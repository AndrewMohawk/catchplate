"""Explicit provider-independent creation of normal protected Setup tracking.

Draft labels are not authority. The actual controlled writer proves current
capacity, roles and fresh hardware, then commits the row, event and audit. No
provider enrollment, direct DML, private material or automatic retry is used.
"""
import os
import threading
import time
import uuid

from fastapi import Request

from serverware import auth, authority_contract, db, webauthn
from serverware import authority_oauth_setup as rows
from serverware import authority_setup_create as profile
from serverware import control_plane_custody_client as custody_client
from serverware import control_plane_custody_startup as startup
from serverware import control_plane_oauth_activation as hardware
from serverware.control_plane_approval_verification import _epoch_ns, _request_pin

PREFIX = "/api/setup/sessions/create"
PATHS = frozenset(PREFIX + "/" + phase for phase in ("draft", "options", "execute", "settle"))
MAX_REQUEST, MAX_RESPONSE = profile.MAX_HTTP_REQUEST, profile.MAX_HTTP_RESPONSE


def selected():
    """Current controlled request transport, not signed purpose admission."""
    return db.metadata_uses_postgres() and startup.require_started() is not None


def _identity(request):
    profile.require(type(request) is Request and request.method == "POST" and request.url.path in PATHS
        and not request.url.query and not request.headers.getlist("authorization")
        and not request.headers.getlist("x-serverware-admin-token")
        and request.headers.getlist("origin") == [webauthn.WEBAUTHN_ORIGIN]
        and webauthn.WEBAUTHN_ORIGIN not in ("", "null") and len(request.headers.getlist("cookie")) == 1)
    names = [item.strip().split("=", 1)[0] for item in request.headers["cookie"].split(";")]
    profile.require(len(names) == len(set(names)) and not request.cookies.get("serverware_admin"))
    identity = auth.oidc_identity_from_session_token(request.cookies.get(auth.OIDC_SESSION_COOKIE_NAME))
    profile.require(type(identity) is auth.AdminIdentity and identity.user_id.startswith("oidc:")
        and bool(profile.MUTATION_ROLES.intersection(identity.roles)))
    auth.validate_csrf_request(request)
    return identity


def _session(session_id):
    profile.identifier(session_id)
    with db.connect() as connection:
        value = connection.execute("SELECT * FROM setup_sessions WHERE id = ?", (session_id,)).fetchone()
    if value is None:
        return None
    value = dict(value)
    profile.row_original(value)
    return value


def _event(session_id, event_id):
    profile.identifier(event_id)
    with db.connect() as connection:
        value = connection.execute("SELECT * FROM setup_session_events WHERE id = ?", (event_id,)).fetchone()
    profile.require(value is not None)
    value = dict(value)
    profile.require(set(value) == profile.EVENT_FIELDS and value["session_id"] == session_id and value["transition"] == "create")
    document = rows.document(value["event_json"].encode("ascii"), profile.MAX_EVENT_BYTES)
    profile.require(document["details"]["authorityOperation"] == profile.OPERATION)
    return value


def _route(request):
    from serverware import app

    app._require_authoritative_setup_route_binding(route_id=request["routeId"], route_policy_digest=request["routePolicyDigest"])


class _Owner:
    def __init__(self, request):
        self.started_mono, self.started_epoch = time.monotonic_ns(), time.time_ns()
        self.request, self.scope, self.pin = request, request.scope, _request_pin(request)
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.identity, self.policy = _identity(request), profile.policy(hardware._policy())
        self.policy_original = profile.canonical(self.policy)
        self.custody = startup.require_started()
        profile.require(db.metadata_uses_postgres() and self.custody is not None)
        self.binding = custody_client._snapshot(self.custody)
        self.configuration = self.binding.configuration_digest
        self.last_mono, self.last_epoch = self.started_mono, self.started_epoch
        self.expires = min(self.started_epoch + 30_000_000_000, self.binding.attestation_interval[1])
        self.deadline = self.started_mono + self.expires - self.started_epoch
        self.values = self.original = self.session_id = self.session_original = None
        self.credential = self.mfa = self.mfa_original = None
        self.dispatched = False
        self.check()

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
            and _identity(self.request) == self.identity and profile.canonical(hardware._policy()) == self.policy_original
            and startup.require_started() is self.custody and custody_client._snapshot(self.custody) is self.binding
            and self.binding.configuration_digest == self.configuration)
        custody_client._receipt_now(self.binding)
        if self.values is not None:
            profile.require(profile.canonical(self.values) == self.original)
            _route(self.values["request"])
            if not self.dispatched:
                profile.require(_session(self.session_id) is None, "Setup ID is already retained; absence cannot authorize a retry")
        if self.session_original is not None:
            current = _session(self.session_id)
            profile.require(current is not None and profile.row_original(current) == self.session_original
                and ("admin" in self.identity.roles or self.identity.user_id in {current["owner_id"], current["current_assignee_id"]}))
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
            and value["request"]["issuedAtEpochNs"] <= self.last_epoch)
        self.values, self.original, self.session_id = value, raw, value["request"]["sessionId"]
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
            "timeout": timeout_ms, "userVerification": "required"}, "serverware": {"schema": profile.OPTIONS_SCHEMA,
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
            input_value={"schema": "serverware.policyAuthorityControlledWriterInput/v1",
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
        request = self.values["request"]
        created = profile.epoch(returned["created_at"])
        profile.require(request["issuedAtEpochNs"] <= created < request["expiresAtEpochNs"]
            and returned["created_at"] == returned["updated_at"]
            and profile.epoch(returned["expires_at"]) - created == request["ttlSeconds"] * 1_000_000_000)
        expected = dict.fromkeys(profile.ROW_FIELDS)
        expected.update({"id": self.session_id, "owner_id": self.identity.user_id, "current_assignee_id": self.identity.user_id,
            "status": "active", "phase": "created", "revision": 0, "template_id": request["templateId"],
            "principal_id": request["principalId"], "route_id": request["routeId"], "route_policy_digest": request["routePolicyDigest"],
            **{name: returned[name] for name in ("created_at", "updated_at", "expires_at")}})
        profile.require(returned == expected)
        self.session_original = profile.row_original(returned)
        event = _event(self.session_id, result["setupEventId"])
        profile.require(event["audit_status"] == "controlled_pending" and event["sequence"] == 1
            and event["actor_id"] == self.identity.user_id)
        self.check()
        return result

    def settle(self, session_id, event_id):
        profile.require(self.values is None and not self.dispatched)
        current = _session(session_id)
        profile.require(current is not None)
        self.session_id, self.session_original = session_id, profile.row_original(current)
        self.check()
        event = _event(session_id, event_id)
        profile.require(event["audit_status"] == "controlled_pending")
        original = profile.canonical(event)
        arguments = profile.arguments(profile.OP_SETTLE, {"event_id": event_id})
        self.check()
        profile.require(profile.canonical(_event(session_id, event_id)) == original)
        self.dispatched = True
        result = custody_client.ControlPlaneCustodyClient._request_authority(self.custody, operation=profile.OP_SETTLE,
            input_value={"schema": "serverware.policyAuthorityControlledWriterInput/v1",
                "handler": authority_contract.operation_spec(profile.OP_SETTLE)["handler"],
                "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST, "arguments": arguments}, deadline_ns=self.deadline)
        self.check()
        profile.require(type(result) is dict and set(result) == {"ok", "operation", "requestDigest", "auditEventDigest",
            "idempotentReplay", "eventId", "auditState", "auditEventHash"}
            and result["ok"] is True and result["operation"] == profile.OP_SETTLE and result["idempotentReplay"] is False
            and result["eventId"] == event_id and result["auditState"] == "audited"
            and result["requestDigest"] == profile.request_digest(profile.OP_SETTLE, arguments))
        profile.digest(result["auditEventDigest"]); profile.digest(result["auditEventHash"])
        observed = _event(session_id, event_id)
        profile.require(observed["audit_status"] == "audited" and observed["audit_event_hash"] == result["auditEventHash"]
            and observed["audited_at"] is not None
            and all(observed[name] == value for name, value in event.items() if name not in {"audit_status", "audited_at", "audit_event_hash"}))
        self.check()
        return result


def on_request(request, raw):
    value = rows.document(raw, MAX_REQUEST)
    profile.require(type(value) is dict and profile.canonical(value) == raw and value.get("apiVersion") == profile.HTTP_SCHEMA)
    owner = _Owner(request)
    phase = request.url.path.rsplit("/", 1)[1]
    if phase == "draft":
        profile.require(set(value) == {"apiVersion", "templateId", "principalId", "routeId", "routePolicyDigest", "ttlSeconds"})
        issued = time.time_ns() // 1000 * 1000
        arguments = profile.arguments(profile.OPERATION, {"actor_id": owner.identity.user_id,
            "control_plane_configuration_digest": owner.configuration, "credential_policy": owner.policy,
            "request": {"sessionId": str(uuid.uuid4()), **{name: value[name] for name in ("templateId", "principalId", "routeId", "routePolicyDigest", "ttlSeconds")},
                "issuedAtEpochNs": issued, "expiresAtEpochNs": min(owner.expires // 1000 * 1000, issued + 30_000_000_000)}})
        owner.check()
        original = profile.canonical(arguments).decode("ascii")
        owner.arguments(original)
        result = {"apiVersion": profile.HTTP_SCHEMA, "okForAction": False, "argumentsOriginal": original,
            "requestDigest": profile.request_digest(profile.OPERATION, arguments)}
        owner.check()
        return result
    if phase == "settle":
        profile.require(set(value) == {"apiVersion", "sessionId", "eventId"})
        return owner.settle(value["sessionId"], value["eventId"])
    profile.require(phase in {"options", "execute"} and set(value) == ({"apiVersion", "argumentsOriginal"}
        if phase == "options" else {"apiVersion", "argumentsOriginal", "mfa"}))
    owner.arguments(value["argumentsOriginal"])
    return owner.options() if phase == "options" else owner.execute(value["mfa"])
