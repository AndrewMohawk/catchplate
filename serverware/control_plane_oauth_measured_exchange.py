"""Real authenticated consent and fixed native issuance storage ingress.

The human path retains actual OIDC/CSRF/current hardware ceremony ownership.
The machine path accepts only encrypted originals and native proofs; actual
verifier and planner independently admit every effect. No callback code, PKCE,
browser cookie, client secret, token decryption or provider HTTP occurs here.
"""
import os
import threading
import time
from urllib.parse import urlsplit
from fastapi import Request
from serverware import authority_contract, db, oauth, webauthn
from serverware import authority_oauth_measured_exchange as profile
from serverware import authority_oauth_measured_setup as setup_profile
from serverware import authority_oauth_setup as setup
from serverware import authority_oauth_exchange as exchange
from serverware import control_plane_oauth_activation as activation
from serverware import control_plane_oauth_exchange as consent
from serverware import control_plane_custody_client as custody_client
from serverware import control_plane_custody_startup as startup
from serverware import oauth_application_owner as applications
from serverware import native_oauth_exchange as material
from serverware.control_plane_approval_verification import _epoch_ns, _request_pin

HTTP_SCHEMA = "serverware.nativeOAuthExchangeRequest/v1"
HTTP_RESPONSE = "serverware.nativeOAuthExchangeResponse/v1"
INTENT_RESPONSE = "serverware.nativeOAuthIntentResponse/v1"
MFA_FIELD = "nativeOAuthConsentProfile"
MAX_REQUEST = 3 * 1024 * 1024
MAX_RESPONSE = 8 * 1024 * 1024
HUMAN_PATHS = frozenset({"/api/oauth/native/intent", "/api/oauth/native/options", "/api/oauth/native/consent"})
MACHINE_PATH = "/api/data-plane/oauth-issuance"
RECOVERY_PATH = "/api/data-plane/oauth-issuance/original"
LEGACY_PROFILE = profile


def _body(request, raw, path):
    profile.require(type(request) is Request and request.method == "POST" and request.url.path == path and not request.url.query)
    return profile.document(raw, MAX_REQUEST)


def _input(operation, arguments):
    return {"schema": "serverware.policyAuthorityControlledWriterInput/v1",
        "handler": authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST, "arguments": arguments}


def _originals(owner, operation, arguments):
    profile = owner.contract
    owner.check()
    if profile is setup_profile:
        request_original, response_original = custody_client.ControlPlaneCustodyClient._request_measured_setup(owner.custody,
            operation=operation, input_value=_input(operation, arguments), deadline_ns=owner.deadline)
    else:
        request_original, response_original = custody_client.ControlPlaneCustodyClient._request_measured_exchange(owner.custody,
            operation=operation, input_value=_input(operation, arguments), deadline_ns=owner.deadline)
    owner.check()
    response = profile.document(response_original, 6 * 1024 * 1024)
    result = response["result"]
    fields = {"ok", "exchange", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "originals"}
    profile.require(type(result) is dict and fields <= set(result) <= fields | {"pending"}
        and result["ok"] is True and result["idempotentReplay"] is False and result["operation"] == operation
        and result["requestDigest"] == profile.request_digest(operation, {key: item for key, item in arguments.items() if key != "authn_evidence"}))
    profile.digest(result["auditEventDigest"])
    reply = {"apiVersion": setup_profile.HTTP_RESPONSE if profile is setup_profile else HTTP_RESPONSE,
        "requestOriginal": profile.encoded(request_original), "responseOriginal": profile.encoded(response_original)}
    profile.require(len(profile.canonical(reply)) <= MAX_RESPONSE)
    return reply


class _Consent:
    def __init__(self, request, arguments, *, contract=profile):
        from serverware.oauth_reconnect_owner import selected as reconnect_selected
        from serverware.oauth_retirement_succession_owner import selected as succession_selected
        setup.require(not succession_selected(), "retired-scope succession has a distinct cold purpose")
        setup.require(not reconnect_selected(), "reconnect has a distinct cold purpose")
        setup.require(contract is LEGACY_PROFILE or contract is setup_profile)
        self.contract = contract
        profile = contract
        self.arguments = profile.arguments(profile.OP_PREPARE, arguments)
        provider = self.arguments["request"]["providerId"]
        profile.require(applications.measured_selected(provider))
        profile.require(applications.setup_selected(provider) == (profile is setup_profile))
        # This retained owner supplies only current human/application custody;
        # none of the old plaintext state/encryption/contact methods is called.
        self.human = consent._Owner(request, provider)
        self.custody, self.deadline = self.human.custody, self.human.deadline
        self.binding = custody_client._snapshot(self.custody)
        self.original = profile.canonical(self.arguments)
        statement = self.arguments["native_evidence"]["statement"]
        self.human.clip(statement["expiresAtEpochNs"])
        self.deadline = self.human.deadline
        self.sent = False
        self.check()

    def check(self):
        profile = self.contract
        self.human.check()
        values, human = self.arguments, self.human
        request = values["request"]
        profile.require(profile.canonical(values) == self.original and self.custody is human.custody
            and custody_client._snapshot(self.custody) is self.binding
            and values["control_plane_configuration_digest"] == self.binding.configuration_digest
            and values["actor_id"] == human.actor and values["credential_policy"] == human.policy
            and values["enrollment_original"] == human.encoded_enrollment
            and request["metadata"].get(applications.ASSOCIATION_KEY) == human.association
            and request["portalOrigin"] == webauthn.WEBAUTHN_ORIGIN
            and request["redirectUri"] == human.provider.redirect_uri
            and request["callbackOrigin"] != request["portalOrigin"]
            and request["scopes"] == sorted(oauth.resolve_requested_scopes(human.provider.id, request["scopes"]))
            and self.deadline <= human.deadline and time.monotonic_ns() < self.deadline)
        if profile is setup_profile and not self.sent:
            from serverware import control_plane_oauth_setup as owner
            row = owner.read_session(request["setupBinding"]["sessionId"])
            profile.require(setup.row_binding(row) == request["setupBinding"] and row["owner_id"] == human.actor
                and row["current_assignee_id"] in {None, human.actor} and row["phase"] == "created" and row["revision"] == 0
                and time.time_ns() < request["setupBinding"]["expiresAtEpochNs"])

    def assertion(self, mfa):
        profile = self.contract
        self.check()
        profile.require(type(mfa) is dict and set(mfa) == {MFA_FIELD, "assertion"}
            and mfa[MFA_FIELD] == profile.OPTIONS_SCHEMA and len(profile.canonical(mfa)) <= 16384)
        human = self.human
        human.mfa, human.mfa_original = mfa, profile.canonical(mfa)
        assertion = mfa["assertion"]
        profile.require(type(assertion) is dict)
        human.credential = db.get_webauthn_credential(assertion.get("id"))
        profile.require(type(human.credential) is dict and human.credential["user_id"] == human.actor)
        self.check()
        client, _ = webauthn._parse_client_data(assertion.get("response", {}).get("clientDataJSON"), "webauthn.get")
        challenge = db.get_unused_webauthn_challenge(client["challenge"], challenge_type="policy_authority", user_id=human.actor)
        profile.require(challenge is not None)
        human.clip(_epoch_ns(challenge["expires_at"]))
        self.deadline = min(self.deadline, human.deadline)
        return {"challengeId": challenge["id"], "credentialRecordId": human.credential["id"], "assertion": assertion}


def intent_on_request(request, raw):
    from serverware.oauth_reconnect_owner import selected as reconnect_selected
    from serverware.oauth_retirement_succession_owner import selected as succession_selected
    profile.require(not succession_selected(), "retired-scope succession cannot use unbound issuance")
    profile.require(not reconnect_selected(), "reconnect cannot use unbound issuance")
    value = _body(request, raw, "/api/oauth/native/intent")
    profile.require(set(value) == {"provider", "credentialName", "scopes", "metadata"} and applications.measured_selected(value["provider"]))
    profile.require(not applications.setup_selected(value["provider"]), "unbound issuance is not the cold Setup purpose")
    owner = consent._Owner(request, value["provider"])
    metadata = oauth._bounded_metadata(value["metadata"])
    profile.require(applications.ASSOCIATION_KEY not in metadata
        and not set(metadata) & {"setup_session_id", "setupSessionId", "reconnect", "reconnect_credential_id", "reconnect_credential_version"})
    uri = urlsplit(owner.provider.redirect_uri)
    callback_origin = material.origin(uri.scheme + "://" + uri.netloc)
    profile.require(owner.provider.redirect_uri == material.callback_uri(callback_origin, owner.provider.id)
        and callback_origin != webauthn.WEBAUTHN_ORIGIN)
    value = material.intent({"schema": material.INTENT_SCHEMA, "providerId": owner.provider.id, "requesterId": owner.actor,
        "credentialName": oauth._bounded_credential_name(value["credentialName"], owner.provider.display_name + " OAuth credential"),
        "scopes": sorted(oauth.resolve_requested_scopes(owner.provider.id, value["scopes"])),
        "metadata": metadata, "credentialPolicy": owner.policy})
    owner.check()
    return {"apiVersion": INTENT_RESPONSE, "callbackOrigin": callback_origin, "portalOrigin": webauthn.WEBAUTHN_ORIGIN, "intent": value}


def options_on_request(request, raw, *, contract=profile):
    setup.require(contract is LEGACY_PROFILE or contract is setup_profile)
    profile = contract
    value = _body(request, raw, "/api/setup/oauth/native/options" if profile is setup_profile else "/api/oauth/native/options")
    profile.require(set(value) == {"apiVersion", "arguments"} and value["apiVersion"] == profile.OPTIONS_SCHEMA)
    owner = _Consent(request, value["arguments"], contract=profile)
    human = owner.human
    descriptors = webauthn._credential_descriptors_for_policy(human.actor, activation._authenticator_policy(human.policy))
    profile.require(type(descriptors) is list and 1 <= len(descriptors) <= 64)
    human.credential = db.get_webauthn_credential(descriptors[0]["id"])
    profile.require(type(human.credential) is dict and human.credential["user_id"] == human.actor)
    owner.check()
    challenge = db.issue_policy_authority_webauthn_challenge(operation=profile.OP_PREPARE, input_value=owner.arguments,
        user_id=human.actor, credential_id=human.credential["credential_id"], deadline_ns=owner.deadline)
    owner.check()
    data = challenge["payload"]
    profile.require(challenge["challenge_type"] == "policy_authority" and challenge["user_id"] == human.actor
        and challenge["used_at"] is None and data["credentialId"] == human.credential["credential_id"]
        and data["rpId"] == human.policy["rpId"] and data["origin"] in human.policy["origins"])
    return {"publicKey": {"challenge": challenge["challenge"], "rpId": data["rpId"],
        "allowCredentials": [{"type": "public-key", "id": human.credential["credential_id"]}], "timeout": 30000, "userVerification": "required"},
        "serverware": {"schema": profile.OPTIONS_SCHEMA, "operation": profile.OP_PREPARE,
            "operationId": data["operationId"], "challengeId": challenge["id"], "credentialRecordId": human.credential["id"],
            "payloadDigest": owner.arguments["payload_digest"], "expiresAt": challenge["expires_at"]}}


def consent_on_request(request, raw, *, contract=profile):
    setup.require(contract is LEGACY_PROFILE or contract is setup_profile)
    profile = contract
    value = _body(request, raw, "/api/setup/oauth/native/consent" if profile is setup_profile else "/api/oauth/native/consent")
    profile.require(set(value) == {"apiVersion", "arguments", "mfa"} and value["apiVersion"] == profile.OPTIONS_SCHEMA)
    owner = _Consent(request, value["arguments"], contract=profile)
    evidence = owner.assertion(value["mfa"])
    owner.check(); profile.require(not owner.sent); owner.sent = True
    return _originals(owner, profile.OP_PREPARE, {**owner.arguments, "authn_evidence": evidence})


class Opening:
    def __init__(self, request, raw, *, contract=profile):
        from serverware.oauth_reconnect_owner import selected as reconnect_selected
        from serverware.oauth_retirement_succession_owner import selected as succession_selected
        setup.require(not succession_selected(), "retired-scope succession has a distinct machine purpose")
        setup.require(not reconnect_selected(), "reconnect has a distinct machine purpose")
        setup.require(contract is LEGACY_PROFILE or contract is setup_profile)
        self.contract = contract
        profile = contract
        self.value = _body(request, raw, setup_profile.HTTP_PATH if profile is setup_profile else MACHINE_PATH)
        profile.require(set(self.value) == {"apiVersion", "operation", "arguments"}
            and self.value["apiVersion"] == (setup_profile.HTTP_SCHEMA if profile is setup_profile else HTTP_SCHEMA))
        self.operation = self.value["operation"]
        profile.require(self.operation != profile.OP_PREPARE)
        self.arguments = profile.arguments(self.operation, self.value["arguments"])
        profile.require(applications.setup_selected(self.arguments["native_evidence"]["statement"]["providerId"]) == (profile is setup_profile))
        self.request, self.scope, self.pin, self.original = request, request.scope, _request_pin(request), raw
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.mono, self.epoch = time.monotonic_ns(), time.time_ns()
        self.expires = min(self.arguments["native_evidence"]["statement"]["expiresAtEpochNs"], self.epoch + 30_000_000_000)
        self.deadline = self.mono + self.expires - self.epoch
        self.custody = startup.require_started()
        profile.require(self.custody is not None and startup.credential_broker_selected())
        self.binding = custody_client._snapshot(self.custody)
        self.poisoned, self.sent = False, False
        self.check()

    def check(self):
        profile = self.contract
        try:
            mono, epoch = time.monotonic_ns(), time.time_ns()
            profile.require(not self.poisoned and (os.getpid(), threading.get_ident()) == (self.pid, self.thread)
                and self.mono <= mono < self.deadline and self.epoch <= epoch < self.expires
                and self.request.scope is self.scope and _request_pin(self.request) == self.pin
                and profile.canonical(self.value) == self.original and startup.require_started() is self.custody
                and custody_client._snapshot(self.custody) is self.binding
                and self.binding.configuration_digest == self.arguments["control_plane_configuration_digest"])
            custody_client._receipt_now(self.binding)
            self.mono, self.epoch = mono, epoch
        except BaseException:
            self.poisoned = True
            raise

    def dispatch(self):
        profile = self.contract
        self.check(); profile.require(not self.sent); self.sent = True
        return _originals(self, self.operation, self.arguments)


def on_request(request, raw):
    return Opening(request, raw).dispatch()


def recovery_original_on_request(request, raw):
    """SELECT-only encrypted acquisition, explicitly not a recovery grant.

    The actual native owner forms a fresh recovery request from these bytes;
    both authority roles compare it against the protected store before any
    decryption or fixed identity GET is permitted by the helper.
    """
    value = _body(request, raw, RECOVERY_PATH)
    profile.require(set(value) == {"apiVersion", "exchangeId"}
        and value["apiVersion"] == "serverware.nativeOAuthRecoveryOriginalRequest/v1")
    material.identifier(value["exchangeId"])
    custody = startup.require_started()
    profile.require(custody is not None and startup.credential_broker_selected())
    binding = custody_client._snapshot(custody)
    custody_client._receipt_now(binding)
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM oauth_exchange_reservations WHERE id = ?", (value["exchangeId"],)).fetchone()
        retained = connection.execute("SELECT * FROM oauth_measured_exchange_custody WHERE id = ?", (value["exchangeId"],)).fetchone()
    profile.require(row is not None and retained is not None and retained["status"] in {"captured", "staged"}
        and startup.require_started() is custody and custody_client._snapshot(custody) is binding)
    custody_client._receipt_now(binding)
    return {"apiVersion": "serverware.nativeOAuthRecoveryOriginalResponse/v1", "okForAction": False,
        "exchangeOriginal": exchange.row_original(dict(row)).decode("ascii"),
        "custodyOriginal": profile.row_original(dict(retained)).decode("ascii")}
