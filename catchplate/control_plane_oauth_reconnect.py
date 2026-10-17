"""Actual OIDC/hardware and signed-store owners for measured reconnect.

Read acquisition is not permission. A lost authorize/fence response is never
automatically replayed, and an inspection response cannot create a native draft.
"""
import os
import threading
import time
from urllib.parse import urlsplit
from fastapi import Request
from catchplate import db, webauthn
from catchplate import authority_oauth_reconnect as profile
from catchplate import authority_oauth_exchange as exchange
from catchplate import authority_oauth_refresh as refresh
from catchplate import authority_transition_oauth_reconnect_rows as rows
from catchplate import control_plane_oauth_exchange as consent
from catchplate import control_plane_oauth_activation as activation
from catchplate import control_plane_oauth_measured_exchange as measured
from catchplate import control_plane_oauth_setup as setup_ceremony
from catchplate import control_plane_custody_client as custody_client
from catchplate import control_plane_custody_startup as startup
from catchplate import oauth_application_owner as applications
from catchplate import oauth_reconnect_owner as cold
from catchplate.control_plane_approval_verification import _request_pin, _epoch_ns

MFA_FIELD = "oauthReconnectProfile"
LOOKUP_SCHEMA = "catchplate.oauthReconnectObservation/v1"


def _body(request, raw, path):
    profile.require(cold.selected() and type(request) is Request and request.method == "POST"
        and request.url.path == path and not request.url.query)
    return profile.document(raw, profile.MAX_HTTP_REQUEST)


def _read(identifier):
    profile.identifier(identifier)
    with db.connect() as connection:
        journal = connection.execute("SELECT * FROM oauth_reconnect_authorizations WHERE id = ?", (identifier,)).fetchone()
        custody = connection.execute("SELECT * FROM oauth_measured_reconnect_custody WHERE id = ?", (identifier,)).fetchone()
        exchanged = connection.execute("SELECT * FROM oauth_exchange_reservations WHERE id = ?", (identifier,)).fetchone()
    journal, custody, exchanged = (None if value is None else dict(value) for value in (journal, custody, exchanged))
    if journal is not None:
        profile.journal_original(journal)
    if custody is not None:
        profile.row_original(custody)
    if exchanged is not None:
        exchange.row_original(exchanged)
    profile.require(custody is None or journal is not None and exchanged is not None)
    return journal, custody, exchanged


def _arguments(human, grant_raw, operation, request, approval_id=None):
    expected = profile.grant_document(grant_raw)["payload"]
    return profile.arguments(operation, {"action": profile.ACTION, "resource_id": expected["authorizationId"],
        "payload_digest": profile.sha256(profile.canonical(request)), "actor_id": human.actor, "request": request,
        "approval_id": approval_id, "credential_policy": human.policy, "enrollment_original": human.encoded_enrollment,
        "authorization_original": profile.encoded(grant_raw)})


def _assertion(human, mfa):
    profile.require(type(mfa) is dict and set(mfa) == {MFA_FIELD, "assertion"} and mfa[MFA_FIELD] == profile.OPTIONS_SCHEMA
        and len(profile.canonical(mfa)) <= 16384 and type(mfa["assertion"]) is dict)
    human.mfa, human.mfa_original = mfa, profile.canonical(mfa)
    item = mfa["assertion"]
    human.credential = db.get_webauthn_credential(item.get("id"))
    profile.require(type(human.credential) is dict and human.credential["user_id"] == human.actor)
    client, _ = webauthn._parse_client_data(item.get("response", {}).get("clientDataJSON"), "webauthn.get")
    challenge = db.get_unused_webauthn_challenge(client["challenge"], challenge_type="policy_authority", user_id=human.actor)
    profile.require(challenge is not None)
    human.clip(_epoch_ns(challenge["expires_at"])); human.check()
    return {"challengeId": challenge["id"], "credentialRecordId": human.credential["id"], "assertion": item}


def _write(owner, operation, arguments):
    owner.check()
    request_raw, response_raw = custody_client.ControlPlaneCustodyClient._request_measured_reconnect(owner.custody,
        operation=operation, input_value=measured._input(operation, arguments), deadline_ns=owner.deadline)
    owner.check()
    response = profile.document(response_raw, 6 * 1024 * 1024)
    result = response["result"]
    extras = {"approval"} if operation in {profile.OP_REQUEST, profile.OP_DECIDE} else {"approval", "credential"} if operation == profile.OP_ACTIVATE else set()
    profile.require(type(result) is dict and set(result) == profile.RESULT_FIELDS | extras and result["ok"] is True
        and result["operation"] == operation and result["idempotentReplay"] is False
        and result["requestDigest"] == profile.request_digest(operation, {name: value for name, value in arguments.items() if name != "authn_evidence"})
        and type(result["originals"]) is dict and set(result["originals"]) == profile.ORIGINALS_FIELDS)
    profile.digest(result["auditEventDigest"])
    return request_raw, response_raw, result


class _Authorization:
    """Genuine requester and cold grant retained across the single drain/fence."""
    def __init__(self, request, identifier):
        self.application_owner, self.grant_raw = cold.original(identifier)
        self.grant = profile.grant_document(self.grant_raw)["payload"]
        self.human = consent._Owner(request, self.grant["providerId"])
        self.custody, self.binding = self.human.custody, custody_client._snapshot(self.human.custody)
        profile.require(self.human.actor == self.grant["requesterId"])
        self.human.clip(self.grant["contactExpiresAtEpochNs"])
        self.deadline, self.expires = self.human.deadline, self.human.expires
        self.arguments = _arguments(self.human, self.grant_raw, profile.OP_AUTHORIZE,
            {"credentialId": self.grant["credentialId"], "credentialVersion": self.grant["credentialVersion"],
                "authorizationSha256": profile.sha256(self.grant_raw)})
        self.authorized = self.fenced = self.sent = False
        self.journal, self.authorize_originals = None, None
        self.check()

    def check(self):
        self.human.check()
        actual, raw = cold.original(self.grant["authorizationId"])
        profile.require(actual is self.application_owner and raw == self.grant_raw
            and self.human.custody is self.custody and custody_client._snapshot(self.custody) is self.binding
            and self.human.actor == self.grant["requesterId"]
            and self.human.association["enrollmentSha256"] == self.grant["enrollmentSha256"]
            and self.binding.configuration_digest == self.grant["configurationDigest"]
            and time.monotonic_ns() < self.deadline and time.time_ns() < self.expires <= self.grant["contactExpiresAtEpochNs"])
        if self.authorized:
            profile.require(self.journal is not None and self.authorize_originals is not None
                and self.journal["authorize_request_digest"] == profile.request_digest(profile.OP_AUTHORIZE, self.arguments))

    def execute(self, mfa):
        evidence = _assertion(self.human, mfa)
        self.deadline, self.expires = min(self.deadline, self.human.deadline), min(self.expires, self.human.expires)
        self.check(); profile.require(not self.sent); self.sent = True
        request_raw, response_raw, result = _write(self, profile.OP_AUTHORIZE, {**self.arguments, "authn_evidence": evidence})
        journal = profile.document(result["originals"]["journalOriginal"].encode("ascii"), profile.MAX_ROW_BYTES)
        profile.journal_original(journal)
        profile.require(journal["status"] == "authorized" and journal["id"] == self.grant["authorizationId"]
            and journal["authorization_original"].encode("ascii") == self.grant_raw
            and _read(journal["id"])[0] == journal)
        self.journal, self.authorize_originals, self.authorized = journal, (request_raw, response_raw), True
        self.human.clip(rows.epoch(journal["admission_expires_at"]))
        self.deadline, self.expires = min(self.deadline, self.human.deadline), min(self.expires, self.human.expires)
        from catchplate.control_plane_credential_currentness import admit_reconnect_barriers
        barriers = admit_reconnect_barriers(self)
        self.check(); profile.require(not self.fenced); self.fenced = True
        fence = _arguments(self.human, self.grant_raw, profile.OP_FENCE, {
            "authorizationRowSha256": profile.sha256(profile.journal_original(journal)), "currentnessBarriers": barriers,
            "issuedAtEpochNs": rows.epoch(journal["created_at"]), "expiresAtEpochNs": rows.epoch(journal["admission_expires_at"])})
        request_raw, response_raw, result = _write(self, profile.OP_FENCE, fence)
        final = profile.document(result["originals"]["journalOriginal"].encode("ascii"), profile.MAX_ROW_BYTES)
        profile.journal_original(final)
        profile.require(final["status"] == "fenced" and final["authorize_request_digest"] == journal["authorize_request_digest"]
            and final["fence_request_digest"] == profile.request_digest(profile.OP_FENCE, fence) and _read(final["id"])[0] == final)
        target = next(row for row, _ in rows.affected(final, self.grant) if row["id"] == self.grant["credentialId"])
        intent = profile.intent({"schema": profile.INTENT_SCHEMA, "providerId": self.grant["providerId"],
            "requesterId": self.human.actor, "credentialName": target["name"], "scopes": self.grant["scopes"],
            "metadata": rows.metadata(target), "credentialPolicy": self.human.policy,
            "authorizationOriginal": profile.encoded(self.grant_raw), "fenceRequestOriginal": profile.encoded(request_raw),
            "fenceResponseOriginal": profile.encoded(response_raw)})
        uri = urlsplit(self.human.provider.redirect_uri)
        callback = profile.material.origin(uri.scheme + "://" + uri.netloc)
        profile.require(self.human.provider.redirect_uri == profile.material.callback_uri(callback, self.grant["providerId"])
            and callback != webauthn.WEBAUTHN_ORIGIN)
        self.check()
        return {"apiVersion": profile.INTENT_RESPONSE, "callbackOrigin": callback, "portalOrigin": webauthn.WEBAUTHN_ORIGIN, "intent": intent}


class _Activation:
    def __init__(self, request, identifier, operation, approval_id):
        profile.require(operation in {profile.OP_REQUEST, profile.OP_DECIDE, profile.OP_ACTIVATE})
        self.application_owner, self.grant_raw = cold.original(identifier)
        self.grant = profile.grant_document(self.grant_raw)["payload"]
        self.human = consent._Owner(request, self.grant["providerId"])
        self.human.clip(self.grant["pendingExpiresAtEpochNs"])
        self.custody, self.binding = self.human.custody, custody_client._snapshot(self.human.custody)
        self.deadline, self.expires, self.sent = self.human.deadline, self.human.expires, False
        self.journal, self.custody_row, _ = _read(identifier)
        profile.require(self.journal is not None and self.journal["status"] == "fenced" and self.custody_row is not None
            and self.custody_row["status"] == "staged")
        candidate = profile.document(self.custody_row["candidate_original_json"].encode("ascii"), profile.MAX_CANDIDATE_BYTES)
        profile.candidate_original(candidate, self.grant)
        self.arguments = _arguments(self.human, self.grant_raw, operation,
            {"authorizationSha256": profile.sha256(self.grant_raw), "candidateSha256": profile.sha256(profile.canonical(candidate))}, approval_id)
        self.operation = operation
        self.check()

    def check(self):
        self.human.check()
        owner, raw = cold.original(self.grant["authorizationId"])
        profile.require(owner is self.application_owner and raw == self.grant_raw
            and custody_client._snapshot(self.custody) is self.binding and time.monotonic_ns() < self.deadline
            and time.time_ns() < self.expires <= self.grant["pendingExpiresAtEpochNs"]
            and self.human.association["enrollmentSha256"] == self.grant["enrollmentSha256"])
        if not self.sent:
            journal, retained, _ = _read(self.grant["authorizationId"])
            profile.require(journal == self.journal and retained == self.custody_row)

    def execute(self, mfa):
        evidence = _assertion(self.human, mfa)
        self.deadline = min(self.deadline, self.human.deadline)
        self.check(); profile.require(not self.sent); self.sent = True
        _, _, result = _write(self, self.operation, {**self.arguments, "authn_evidence": evidence})
        # Public review/receipt digests, never ciphertext or a replay instruction.
        return {name: value for name, value in result.items() if name != "originals"}


class Opening:
    """One exact machine request under the original native statement window."""
    def __init__(self, request, raw):
        self.value = _body(request, raw, profile.HTTP_PATH)
        profile.require(set(self.value) == {"apiVersion", "operation", "arguments"} and self.value["apiVersion"] == profile.HTTP_SCHEMA
            and self.value["operation"] in profile.NATIVE_OPERATIONS)
        self.operation = self.value["operation"]
        self.arguments = profile.arguments(self.operation, self.value["arguments"])
        self.application_owner, grant_raw = cold.original(self.arguments["resource_id"])
        profile.require(profile.encoded(grant_raw) == self.arguments["authorization_original"])
        self.request, self.scope, self.pin, self.original = request, request.scope, _request_pin(request), raw
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.mono, self.epoch = time.monotonic_ns(), time.time_ns()
        self.expires = min(self.arguments["native_evidence"]["statement"]["expiresAtEpochNs"], self.epoch + 30_000_000_000)
        self.deadline = self.mono + self.expires - self.epoch
        self.custody = startup.require_started()
        profile.require(self.custody is not None and startup.credential_broker_selected())
        self.binding = custody_client._snapshot(self.custody)
        self.sent = self.poisoned = False
        self.check()

    def check(self):
        try:
            mono, epoch = time.monotonic_ns(), time.time_ns()
            self.application_owner.check()
            profile.require(not self.poisoned and (os.getpid(), threading.get_ident()) == (self.pid, self.thread)
                and self.mono <= mono < self.deadline and self.epoch <= epoch < self.expires
                and self.request.scope is self.scope and _request_pin(self.request) == self.pin
                and profile.canonical(self.value) == self.original and startup.require_started() is self.custody
                and custody_client._snapshot(self.custody) is self.binding
                and self.binding.configuration_digest == self.arguments["control_plane_configuration_digest"])
            custody_client._receipt_now(self.binding); self.mono, self.epoch = mono, epoch
        except BaseException:
            self.poisoned = True
            raise

    def dispatch(self):
        self.check(); profile.require(not self.sent); self.sent = True
        request, response, _ = _write(self, self.operation, self.arguments)
        value = {"apiVersion": profile.HTTP_RESPONSE, "requestOriginal": profile.encoded(request), "responseOriginal": profile.encoded(response)}
        profile.require(len(profile.canonical(value)) <= profile.MAX_HTTP_RESPONSE)
        return value


def human_on_request(request, raw):
    value = _body(request, raw, request.url.path)
    path = request.url.path
    if path == profile.HUMAN_PREFIX + "/inventory":
        profile.require(not value)
        identity = consent._cookie_identity(request)
        return {"apiVersion": LOOKUP_SCHEMA, "okForAction": False, "authorizations": cold.inventory_for(identity.user_id)}
    if path in {profile.HUMAN_PREFIX + "/authorize/options", profile.HUMAN_PREFIX + "/authorize"}:
        profile.require(set(value) == ({"authorizationId"} if path.endswith("/options") else {"authorizationId", "mfa"}))
        owner = _Authorization(request, value["authorizationId"])
    else:
        profile.require(path in {profile.HUMAN_PREFIX + "/activation/options", profile.HUMAN_PREFIX + "/activation"}
            and set(value) == ({"authorizationId", "operation", "approvalId"} if path.endswith("/options")
                else {"authorizationId", "operation", "approvalId", "mfa"}))
        owner = _Activation(request, value["authorizationId"], value["operation"], value["approvalId"])
    if path.endswith("/options"):
        return setup_ceremony._options(owner.human, profile.OP_AUTHORIZE if type(owner) is _Authorization else owner.operation,
            owner.arguments, profile.OPTIONS_SCHEMA)
    return owner.execute(value["mfa"])


def recovery_original_on_request(request, raw):
    value = _body(request, raw, profile.HTTP_PATH + "/original")
    profile.require(set(value) == {"apiVersion", "exchangeId"} and value["apiVersion"] == profile.RECOVERY_REQUEST)
    owner, grant = cold.original(value["exchangeId"])
    owner.check()
    journal, custody, exchanged = _read(value["exchangeId"])
    profile.require(journal is not None and journal["authorization_original"].encode("ascii") == grant
        and custody is not None and custody["status"] in {"captured", "staged", "committed"} and exchanged is not None)
    result = {"apiVersion": profile.RECOVERY_RESPONSE, "okForAction": False,
        "journalOriginal": profile.journal_original(journal).decode("ascii"),
        "exchangeOriginal": exchange.row_original(exchanged).decode("ascii"),
        "custodyOriginal": profile.row_original(custody).decode("ascii"), "candidateOriginal": custody["candidate_original_json"]}
    owner.check(); profile.require(len(profile.canonical(result)) <= 6 * 1024 * 1024)
    return result


def inspect_on_request(request, identifier):
    profile.require(cold.selected())
    identity = activation._identity(request, inspection=True)
    owner, raw = cold.original(identifier)
    expected = profile.grant_document(raw)["payload"]
    profile.require("credential_owner" in identity.roles)
    journal, custody, _ = _read(identifier)
    if journal is not None:
        profile.require(journal["authorization_original"].encode("ascii") == raw)
    candidate = None if custody is None or custody["candidate_original_json"] is None else profile.document(
        custody["candidate_original_json"].encode("ascii"), profile.MAX_CANDIDATE_BYTES)
    if candidate is not None:
        profile.candidate_original(candidate, expected)
    with db.connect() as connection:
        approvals = connection.execute("SELECT * FROM control_plane_approvals WHERE action = ? AND resource_id = ? ORDER BY id LIMIT 65",
            (profile.ACTION, identifier)).fetchall()
    profile.require(len(approvals) <= 64)
    owner.check()
    return {"apiVersion": LOOKUP_SCHEMA, "okForAction": False, "authorization": expected,
        "status": "no-local-association-outcome-unknown" if journal is None else custody["status"] if custody is not None else journal["status"],
        "review": None if candidate is None else candidate["review"],
        "candidateSha256": None if candidate is None else profile.sha256(profile.canonical(candidate)),
        "approvals": [{name: dict(row)[name] for name in ("id", "requester_id", "approved_by", "status", "expires_at")} for row in approvals],
        "continuationAllowed": False, "retiredFamilySuccessionImplemented": False}
