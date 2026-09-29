"""Actual cold-selected durable Setup OAuth HTTP owners.

No token plaintext, SQL mutation, approval substitution or automatic replay.
Browser rows are review data; the controlled writer re-admits every original.
"""
import time
import uuid
from urllib.parse import urlsplit

from serverware import authority_contract, db, oauth, webauthn
from serverware import authority_oauth_setup as setup
from serverware import authority_oauth_measured_setup as profile
from serverware import authority_oauth_exchange as exchange
from serverware import control_plane_oauth_exchange as consent
from serverware import control_plane_oauth_activation as activation
from serverware import control_plane_oauth_measured_exchange as measured
from serverware import control_plane_custody_client as custody_client
from serverware import control_plane_custody_startup as startup
from serverware import oauth_application_owner as applications
from serverware import native_oauth_exchange as material
from serverware.control_plane_approval_verification import _epoch_ns

CREATE_SCHEMA = "serverware.oauthSetupCreate/v1"
CREATE_OPTIONS_SCHEMA = "serverware.oauthSetupCreateOptions/v1"
MFA_FIELD = "oauthSetupProfile"
RECOVERY_PATH = profile.HTTP_PATH + "/original"


def read_session(session_id):
    setup.identifier(session_id)
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM setup_sessions WHERE id = ?", (session_id,)).fetchone()
    setup.require(row is not None, "Setup original is unavailable; absence is not completion")
    value = dict(row)
    setup.row_original(value)
    return value


def activation_session(pending):
    with db.connect() as connection:
        retained = connection.execute("SELECT * FROM oauth_measured_setup_custody WHERE id = ?", (pending["id"],)).fetchone()
    setup.require(retained is not None)
    retained = dict(retained)
    profile.row_original(retained)
    setup.require(retained["status"] == "staged" and retained["pending_original_json"] == setup.pending_original(pending).decode("ascii"))
    final = setup.document(retained["setup_final_json"].encode("ascii"), setup.MAX_ROW_BYTES)
    initial = setup.document(retained["setup_initial_json"].encode("ascii"), setup.MAX_ROW_BYTES)
    row = read_session(final["id"])
    setup.require(row == final and row["status"] == "active" and row["phase"] == "oauth_verified" and row["revision"] == 2
        and row["oauth_pending_credential_id"] == pending["id"] and row["credential_id"] is None
        and row["credential_version"] is None and row["owner_id"] == pending["requester_id"] == initial["owner_id"]
        and row["current_assignee_id"] == initial["current_assignee_id"]
        and row["expires_at"] == initial["expires_at"] and time.time_ns() < setup.epoch(row["expires_at"]))
    return row


def _body(request, raw, path):
    setup.require(applications.setup_profile_selected(), "durable Setup is not cold selected")
    return measured._body(request, raw, path)


class _Creation:
    def __init__(self, request, arguments):
        self.arguments = setup.arguments(setup.OP_CREATE, arguments)
        self.human = consent._Owner(request, self.arguments["request"]["providerId"])
        setup.require(applications.setup_selected(self.human.provider.id))
        self.original = setup.canonical(self.arguments)
        self.human.clip(self.arguments["request"]["issuedAtEpochNs"] + 30_000_000_000)
        self.sent = False
        self.check()

    def check(self):
        self.human.check()
        value = self.arguments
        setup.require(setup.canonical(value) == self.original and value["actor_id"] == self.human.actor
            and value["credential_policy"] == self.human.policy and value["enrollment_original"] == self.human.encoded_enrollment
            and value["request"]["enrollmentSha256"] == self.human.association["enrollmentSha256"]
            and value["request"]["issuedAtEpochNs"] <= time.time_ns() < value["request"]["issuedAtEpochNs"] + 30_000_000_000)


def _options(human, operation, arguments, schema):
    descriptors = webauthn._credential_descriptors_for_policy(human.actor, activation._authenticator_policy(human.policy))
    setup.require(type(descriptors) is list and 1 <= len(descriptors) <= 64)
    human.credential = db.get_webauthn_credential(descriptors[0]["id"])
    setup.require(type(human.credential) is dict and human.credential["user_id"] == human.actor)
    human.check()
    challenge = db.issue_policy_authority_webauthn_challenge(operation=operation, input_value=arguments,
        user_id=human.actor, credential_id=human.credential["credential_id"], deadline_ns=human.deadline)
    human.check()
    payload = challenge["payload"]
    setup.require(challenge["used_at"] is None and challenge["user_id"] == human.actor and challenge["challenge_type"] == "policy_authority"
        and payload["credentialId"] == human.credential["credential_id"] and payload["rpId"] == human.policy["rpId"]
        and payload["origin"] in human.policy["origins"])
    return {"publicKey": {"challenge": challenge["challenge"], "rpId": payload["rpId"],
        "allowCredentials": [{"type": "public-key", "id": human.credential["credential_id"]}], "timeout": 30000, "userVerification": "required"},
        "serverware": {"schema": schema, "operation": operation, "operationId": payload["operationId"],
            "challengeId": challenge["id"], "credentialRecordId": human.credential["id"],
            "payloadDigest": arguments["payload_digest"], "expiresAt": challenge["expires_at"]}}


def _assertion(human, mfa, schema):
    setup.require(type(mfa) is dict and set(mfa) == {MFA_FIELD, "assertion"} and mfa[MFA_FIELD] == schema
        and len(setup.canonical(mfa)) <= 16384)
    human.mfa, human.mfa_original = mfa, setup.canonical(mfa)
    assertion = mfa["assertion"]
    setup.require(type(assertion) is dict)
    human.credential = db.get_webauthn_credential(assertion.get("id"))
    setup.require(type(human.credential) is dict and human.credential["user_id"] == human.actor)
    client, _ = webauthn._parse_client_data(assertion.get("response", {}).get("clientDataJSON"), "webauthn.get")
    challenge = db.get_unused_webauthn_challenge(client["challenge"], challenge_type="policy_authority", user_id=human.actor)
    setup.require(challenge is not None)
    human.clip(_epoch_ns(challenge["expires_at"]))
    human.check()
    return {"challengeId": challenge["id"], "credentialRecordId": human.credential["id"], "assertion": assertion}


def create_on_request(request, raw):
    path = request.url.path
    value = _body(request, raw, path)
    if path == "/api/setup/oauth/create/draft":
        setup.require(set(value) == {"provider", "templateId", "principalId", "routeId", "expiresInSeconds"}
            and type(value["expiresInSeconds"]) is int and 300 <= value["expiresInSeconds"] <= 604800)
        human = consent._Owner(request, value["provider"])
        setup.require(applications.setup_selected(human.provider.id))
        issued = time.time_ns() // 1000 * 1000
        expiry = min(issued + value["expiresInSeconds"] * 1_000_000_000, human.application.expires_ns // 1000 * 1000)
        bound = setup.create_request({"sessionId": str(uuid.uuid4()), "providerId": human.provider.id,
            "templateId": value["templateId"], "principalId": value["principalId"], "routeId": value["routeId"], "routePolicyDigest": None,
            "enrollmentSha256": human.association["enrollmentSha256"], "issuedAtEpochNs": issued, "expiresAtEpochNs": expiry})
        arguments = setup.arguments(setup.OP_CREATE, {"action": setup.ACTION_CREATE, "resource_id": bound["sessionId"],
            "payload_digest": setup.sha256(setup.canonical(bound)), "actor_id": human.actor, "request": bound,
            "approval_id": None, "credential_policy": human.policy, "enrollment_original": human.encoded_enrollment})
        human.check()
        return {"apiVersion": CREATE_SCHEMA, "okForAction": False, "arguments": arguments}
    setup.require(path in {"/api/setup/oauth/create/options", "/api/setup/oauth/create"}
        and set(value) == ({"apiVersion", "arguments"} if path.endswith("/options") else {"apiVersion", "arguments", "mfa"})
        and value["apiVersion"] == CREATE_OPTIONS_SCHEMA)
    owner = _Creation(request, value["arguments"])
    if path.endswith("/options"):
        return _options(owner.human, setup.OP_CREATE, owner.arguments, CREATE_OPTIONS_SCHEMA)
    evidence = _assertion(owner.human, value["mfa"], CREATE_OPTIONS_SCHEMA)
    owner.check(); setup.require(not owner.sent); owner.sent = True
    result = custody_client.ControlPlaneCustodyClient._request_authority(owner.human.custody, operation=setup.OP_CREATE,
        input_value=measured._input(setup.OP_CREATE, {**owner.arguments, "authn_evidence": evidence}), deadline_ns=owner.human.deadline)
    owner.check()
    setup.require(type(result) is dict and set(result) == {"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "setupOriginal", "setupEventId", "auditState"}
        and result["ok"] is True and result["operation"] == setup.OP_CREATE and result["idempotentReplay"] is False
        and result["requestDigest"] == setup.request_digest(setup.OP_CREATE, owner.arguments)
        and result["auditState"] == "controlled_pending")
    row = read_session(owner.arguments["resource_id"])
    setup.require(setup.row_original(row).decode("ascii") == result["setupOriginal"] and row["owner_id"] == owner.human.actor
        and row["revision"] == 0 and row["phase"] == "created" and result["setupEventId"] == setup.event_id(row["id"], 1))
    return result


def intent_on_request(request, raw):
    value = _body(request, raw, profile.HUMAN_PREFIX + "/intent")
    setup.require(set(value) == {"provider", "credentialName", "scopes", "metadata", "sessionId", "revision"}
        and applications.setup_selected(value["provider"]))
    human = consent._Owner(request, value["provider"])
    row = read_session(value["sessionId"])
    setup.require(type(value["revision"]) is int and value["revision"] == row["revision"] == 0 and row["phase"] == "created"
        and row["status"] == "active" and row["owner_id"] == human.actor and row["current_assignee_id"] in {None, human.actor})
    human.clip(setup.epoch(row["expires_at"]))
    metadata = oauth._bounded_metadata(value["metadata"])
    setup.require(applications.ASSOCIATION_KEY not in metadata and not set(metadata) &
        {"setup_session_id", "setupSessionId", "reconnect", "reconnect_credential_id", "reconnect_credential_version"})
    uri = urlsplit(human.provider.redirect_uri)
    callback = material.origin(uri.scheme + "://" + uri.netloc)
    setup.require(human.provider.redirect_uri == material.callback_uri(callback, human.provider.id) and callback != webauthn.WEBAUTHN_ORIGIN)
    # Scalar validation only. The returned new label and separate initial row
    # are never converted to the legacy signed intent or permission.
    scalar = material.intent({"schema": material.INTENT_SCHEMA, "providerId": human.provider.id, "requesterId": human.actor,
        "credentialName": oauth._bounded_credential_name(value["credentialName"], human.provider.display_name + " OAuth credential"),
        "scopes": sorted(oauth.resolve_requested_scopes(human.provider.id, value["scopes"])), "metadata": metadata, "credentialPolicy": human.policy})
    intent = {**scalar, "schema": profile.INTENT_SCHEMA, "setupBinding": setup.row_binding(row)}
    human.check()
    return {"apiVersion": profile.INTENT_RESPONSE, "callbackOrigin": callback, "portalOrigin": webauthn.WEBAUTHN_ORIGIN, "intent": intent}


def native_on_request(request, raw):
    setup.require(applications.setup_profile_selected())
    if request.url.path == profile.HUMAN_PREFIX + "/intent":
        return intent_on_request(request, raw)
    if request.url.path == profile.HUMAN_PREFIX + "/options":
        return measured.options_on_request(request, raw, contract=profile)
    if request.url.path == profile.HUMAN_PREFIX + "/consent":
        return measured.consent_on_request(request, raw, contract=profile)
    setup.require(request.url.path == profile.HTTP_PATH)
    return measured.Opening(request, raw, contract=profile).dispatch()


def recovery_original_on_request(request, raw):
    value = _body(request, raw, RECOVERY_PATH)
    setup.require(set(value) == {"apiVersion", "exchangeId"} and value["apiVersion"] == "serverware.nativeOAuthSetupRecoveryOriginalRequest/v1")
    setup.identifier(value["exchangeId"])
    owner = startup.require_started()
    setup.require(owner is not None and startup.credential_broker_selected())
    binding = custody_client._snapshot(owner); custody_client._receipt_now(binding)
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM oauth_exchange_reservations WHERE id = ?", (value["exchangeId"],)).fetchone()
        custody = connection.execute("SELECT * FROM oauth_measured_setup_custody WHERE id = ?", (value["exchangeId"],)).fetchone()
        setup.require(row is not None and custody is not None and custody["status"] in {"captured", "staged"})
        initial = setup.document(custody["setup_initial_json"].encode("ascii"), setup.MAX_ROW_BYTES)
        current = connection.execute("SELECT * FROM setup_sessions WHERE id = ?", (initial["id"],)).fetchone()
    setup.require(current is not None and startup.require_started() is owner and custody_client._snapshot(owner) is binding)
    custody_client._receipt_now(binding)
    result = {"apiVersion": "serverware.nativeOAuthSetupRecoveryOriginalResponse/v1", "okForAction": False,
        "exchangeOriginal": exchange.row_original(dict(row)).decode("ascii"),
        "custodyOriginal": profile.row_original(dict(custody)).decode("ascii"), "setupOriginal": setup.row_original(dict(current)).decode("ascii")}
    setup.require(len(setup.canonical(result)) <= 6 * 1024 * 1024)
    return result


def inspect_on_request(request, session_id):
    setup.require(applications.setup_profile_selected())
    identity = activation._identity(request, inspection=True)
    row = read_session(session_id)
    setup.require(row["owner_id"] == identity.user_id or row["current_assignee_id"] == identity.user_id)
    with db.connect() as connection:
        events = connection.execute("SELECT * FROM setup_session_events WHERE session_id = ? ORDER BY sequence LIMIT 5", (session_id,)).fetchall()
    setup.require(1 <= len(events) <= 4)
    return {"apiVersion": "serverware.oauthSetupObservation/v1", "okForAction": False,
        "setupOriginal": setup.row_original(row).decode("ascii"), "events": [dict(event) for event in events],
        "completionClaimed": False}


def settle_on_request(request, raw):
    value = _body(request, raw, "/api/setup/oauth/audit-settle")
    setup.require(set(value) == {"eventId"}); setup.identifier(value["eventId"])
    with db.connect() as connection:
        event = connection.execute("SELECT * FROM setup_session_events WHERE id = ?", (value["eventId"],)).fetchone()
    setup.require(event is not None)
    document = setup.document(event["event_json"].encode("ascii"), setup.MAX_EVENT_BYTES)
    human = consent._Owner(request, document["details"]["providerId"])
    row = read_session(event["session_id"])
    setup.require(row["owner_id"] == human.actor or row["current_assignee_id"] == human.actor)
    arguments = {"event_id": value["eventId"]}
    human.check()
    result = custody_client.ControlPlaneCustodyClient._request_authority(human.custody, operation=setup.OP_SETTLE,
        input_value=measured._input(setup.OP_SETTLE, arguments), deadline_ns=human.deadline)
    human.check()
    setup.require(type(result) is dict and result.get("ok") is True and result.get("operation") == setup.OP_SETTLE
        and result.get("requestDigest") == setup.request_digest(setup.OP_SETTLE, arguments)
        and result.get("eventId") == value["eventId"] and result.get("auditState") == "audited")
    return result
