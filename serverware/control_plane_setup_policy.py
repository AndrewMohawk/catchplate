"""Owner-bound Setup candidate association; no policy contact or runtime DML."""
import os
import threading
import time

from fastapi import Request
from serverware import authority_contract, db, webauthn
from serverware import authority_oauth_setup as setup
from serverware import authority_policy_candidate as candidate
from serverware import authority_setup_policy as profile
from serverware import control_plane_custody_client as custody_client
from serverware import control_plane_custody_startup as startup
from serverware import control_plane_oauth_activation as activation
from serverware import control_plane_oauth_exchange as consent
from serverware.control_plane_approval_verification import _epoch_ns, _request_pin

PREFIX = "/api/setup/policy-candidate"
PATHS = frozenset(PREFIX + suffix for suffix in ("/draft", "/options", "/bind", "/lookup"))
MAX_REQUEST = 4 * 1024 * 1024 + 32768
MAX_RESPONSE = 5 * 1024 * 1024
MFA_FIELD = "setupPolicyProfile"
OBSERVATION_SCHEMA = "serverware.setupPolicyCandidateObservation/v1"
ERRORS = (ValueError, KeyError, TypeError, db.PolicyCandidateAuthorityError, db.MetadataStoreError,
    custody_client.CustodyClientError)


def _identity(request):
    profile.require(type(request) is Request and request.method == "POST" and request.url.path in PATHS
        and not request.scope.get("query_string", b"") and request.headers.get("content-type") == "application/json")
    # Genuine OIDC cookie, exact Origin/CSRF, no bearer/admin-token identity,
    # literal credential_owner (not an admin override or policy_publisher).
    return consent._cookie_identity(request)


def _session(session_id):
    setup.identifier(session_id)
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM setup_sessions WHERE id = ?", (session_id,)).fetchone()
    profile.require(row is not None, "Setup original unavailable; absence is not completion")
    row = dict(row); setup.row_original(row)
    return row


def _claim(request_id):
    setup.identifier(request_id)
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM policy_shadow_generation_claims WHERE request_id = ?", (request_id,)).fetchone()
    profile.require(row is not None, "completed protected generation claim is required")
    row = dict(row)
    profile.claim_original(candidate.row_original(row).decode("ascii"))
    return row


def _continuation(session_id):
    setup.identifier(session_id)
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM setup_policy_continuations WHERE session_id = ?", (session_id,)).fetchone()
    if row is None:
        return None
    row = dict(row); profile.row_original(row)
    return row


class _Owner:
    def __init__(self, request):
        self.request, self.scope, self.pin = request, request.scope, _request_pin(request)
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.identity, self.policy = _identity(request), activation._policy()
        self.policy_original = profile.canonical(self.policy)
        self.custody = startup.require_started()
        profile.require(self.custody is not None, "Setup continuation requires genuine cold controlled-writer custody")
        self.binding = custody_client._snapshot(self.custody)
        self.configuration = self.binding.configuration_digest
        self.started_mono, self.started_epoch = time.monotonic_ns(), time.time_ns()
        self.last_mono, self.last_epoch = self.started_mono, self.started_epoch
        self.deadline, self.expires = self.started_mono + 30_000_000_000, self.started_epoch + 30_000_000_000
        self.session, self.claim, self.credential = None, None, None
        self.session_original, self.claim_original, self.arguments_original = None, None, None
        self.dispatched = False
        self.check()

    def clip(self, expires):
        candidate.epoch(expires)
        self.expires = min(self.expires, expires)
        self.deadline = min(self.deadline, self.started_mono + self.expires - self.started_epoch)
        self.check()

    def check(self):
        mono, epoch = time.monotonic_ns(), time.time_ns()
        profile.require((os.getpid(), threading.get_ident()) == (self.pid, self.thread)
            and self.last_mono <= mono < self.deadline and self.last_epoch <= epoch < self.expires
            and self.request.scope is self.scope and _request_pin(self.request) == self.pin
            and _identity(self.request) == self.identity and profile.canonical(activation._policy()) == self.policy_original
            and startup.require_started() is self.custody and custody_client._snapshot(self.custody) is self.binding
            and self.binding.configuration_digest == self.configuration)
        custody_client._receipt_now(self.binding)
        if self.session is not None:
            profile.require(setup.row_original(_session(self.session["id"])) == self.session_original
                and self.session["owner_id"] == self.identity.user_id)
        if self.claim is not None:
            profile.require(candidate.row_original(_claim(self.claim["request_id"])) == self.claim_original)
        if self.credential is not None:
            current = db.get_webauthn_credential_by_record_id(self.credential["id"])
            profile.require(type(current) is dict and current.get("revoked_at") is None
                and all(current[name] == self.credential[name] for name in ("id", "credential_id", "user_id", "public_key_cose")))
            actual = webauthn._allowed_authenticator(current, activation._authenticator_policy(self.policy))
            profile.require(actual["currently_trusted"] is True and actual["effective_authenticator_class"] in {"hardware", "yubikey"})
        end_mono, end_epoch = time.monotonic_ns(), time.time_ns()
        profile.require(mono <= end_mono < self.deadline and epoch <= end_epoch < self.expires)
        self.last_mono, self.last_epoch = end_mono, end_epoch

    def retain(self, session_id, generation_id):
        profile.require(self.session is None and self.claim is None)
        self.session, self.claim = _session(session_id), _claim(generation_id)
        row = self.session
        profile.require(row["owner_id"] == self.identity.user_id and row["current_assignee_id"] in {None, self.identity.user_id}
            and row["revision"] == 3 and row["phase"] == "credential_activated" and row["status"] == "active"
            and row["terminal_at"] is None and row["credential_version"] == 1)
        self.session_original, self.claim_original = setup.row_original(row), candidate.row_original(self.claim)
        self.clip(setup.epoch(row["expires_at"]))
        profile.require(_continuation(session_id) is None, "candidate association exists; use read-only lookup")
        self.check()

    def arguments(self, original):
        profile.require(type(original) is str)
        value = setup.document(original.encode("ascii"), profile.MAX_ARGUMENT_BYTES)
        value = profile.arguments(profile.OP_BIND, value)
        profile.require(profile.canonical(value).decode("ascii") == original and value["actor_id"] == self.identity.user_id
            and value["control_plane_configuration_digest"] == self.configuration and value["credential_policy"] == self.policy)
        bound = value["request"]
        claim = profile.claim_original(bound["generationClaimOriginal"])
        self.retain(bound["setupBinding"]["sessionId"], claim["request_id"])
        assignment, assignment_digest = profile.reviewed_assignment(self.session, candidate.management_original(self.claim["management_request_json"]))
        profile.require(bound["setupBinding"] == setup.row_binding(self.session)
            and bound["generationClaimOriginal"].encode("ascii") == self.claim_original
            and bound["credentialId"] == self.session["credential_id"] and bound["credentialVersion"] == self.session["credential_version"]
            and bound["routePolicyDigest"] == assignment["routePolicyDigest"] and bound["assignmentDigest"] == assignment_digest
            and bound["issuedAtEpochNs"] <= self.last_epoch)
        self.arguments_original = original
        self.clip(bound["expiresAtEpochNs"])
        return value

    def assertion(self, value):
        profile.require(type(value) is dict and set(value) == {MFA_FIELD, "assertion"}
            and value[MFA_FIELD] == profile.OPTIONS_SCHEMA and len(profile.canonical(value)) <= 16384)
        assertion = value["assertion"]
        profile.require(type(assertion) is dict)
        self.credential = db.get_webauthn_credential(assertion.get("id"))
        profile.require(type(self.credential) is dict and self.credential["user_id"] == self.identity.user_id)
        self.check()
        client, _ = webauthn._parse_client_data(assertion.get("response", {}).get("clientDataJSON"), "webauthn.get")
        challenge = db.get_unused_webauthn_challenge(client["challenge"], challenge_type="policy_authority", user_id=self.identity.user_id)
        profile.require(challenge is not None)
        self.clip(_epoch_ns(challenge["expires_at"]))
        return {"challengeId": challenge["id"], "credentialRecordId": self.credential["id"], "assertion": assertion}

    def bind(self, arguments, evidence):
        self.check()
        profile.require(not self.dispatched and profile.canonical(arguments).decode("ascii") == self.arguments_original)
        self.dispatched = True
        result = custody_client.ControlPlaneCustodyClient._request_authority(self.custody, operation=profile.OP_BIND,
            input_value={"schema": "serverware.policyAuthorityControlledWriterInput/v1",
                "handler": authority_contract.operation_spec(profile.OP_BIND)["handler"],
                "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
                "arguments": {**arguments, "authn_evidence": evidence}}, deadline_ns=self.deadline)
        self.check()
        profile.require(type(result) is dict and set(result) == {"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "continuationOriginal"}
            and result["ok"] is True and result["operation"] == profile.OP_BIND and result["idempotentReplay"] is False
            and result["requestDigest"] == profile.request_digest(profile.OP_BIND, arguments))
        profile.digest(result["auditEventDigest"])
        row = _continuation(self.session["id"])
        profile.require(row is not None and profile.row_original(row).decode("ascii") == result["continuationOriginal"]
            and row["request_digest"] == result["requestDigest"] and row["request_original"] == self.arguments_original
            and row["setup_original"].encode("ascii") == self.session_original)
        self.check()
        return result


def _draft(owner, value):
    profile.require(set(value) == {"apiVersion", "sessionId", "expectedRevision", "generationRequestId"}
        and value["apiVersion"] == profile.HTTP_SCHEMA and type(value["expectedRevision"]) is int and value["expectedRevision"] == 3)
    owner.retain(value["sessionId"], value["generationRequestId"])
    assignment, digest = profile.reviewed_assignment(owner.session, candidate.management_original(owner.claim["management_request_json"]))
    context = candidate.context(setup.document(owner.claim["context_json"].encode("ascii"), 8192))
    now = time.time_ns() // 1000 * 1000
    expires = min(owner.expires // 1000 * 1000, now + 30_000_000_000)
    arguments = profile.arguments(profile.OP_BIND, {"actor_id": owner.identity.user_id,
        "control_plane_configuration_digest": owner.configuration, "credential_policy": owner.policy,
        "request": {"setupBinding": setup.row_binding(owner.session), "credentialId": owner.session["credential_id"],
            "credentialVersion": owner.session["credential_version"], "generationClaimOriginal": owner.claim_original.decode("ascii"),
            "routePolicyDigest": assignment["routePolicyDigest"], "assignmentDigest": digest,
            "issuedAtEpochNs": now, "expiresAtEpochNs": expires}})
    review = {**assignment, "assignmentDigest": digest, "sessionId": owner.session["id"], "setupRevision": 3,
        "continuationRevision": 0, "ownerId": owner.identity.user_id, "generationRequestId": owner.claim["request_id"],
        "generationPublicationDigest": owner.claim["publication_envelope_digest"], "candidateId": context["candidateId"],
        "canaryId": context["canaryId"], "expiresAtEpochNs": expires}
    owner.check()
    return {"apiVersion": profile.HTTP_SCHEMA, "okForAction": False,
        "argumentsOriginal": profile.canonical(arguments).decode("ascii"), "review": review}


def _options(owner, arguments):
    descriptors = webauthn._credential_descriptors_for_policy(owner.identity.user_id, activation._authenticator_policy(owner.policy))
    profile.require(type(descriptors) is list and 1 <= len(descriptors) <= 64)
    owner.credential = db.get_webauthn_credential(descriptors[0]["id"])
    profile.require(type(owner.credential) is dict and owner.credential["user_id"] == owner.identity.user_id)
    owner.check()
    challenge = db.issue_policy_authority_webauthn_challenge(operation=profile.OP_BIND, input_value=arguments,
        user_id=owner.identity.user_id, credential_id=owner.credential["credential_id"], deadline_ns=owner.deadline)
    owner.check(); payload = challenge["payload"]
    profile.require(challenge["used_at"] is None and challenge["user_id"] == owner.identity.user_id
        and challenge["challenge_type"] == "policy_authority" and payload["credentialId"] == owner.credential["credential_id"]
        and payload["rpId"] == owner.policy["rpId"] and payload["origin"] in owner.policy["origins"])
    return {"publicKey": {"challenge": challenge["challenge"], "rpId": payload["rpId"], "allowCredentials": [
            {"type": "public-key", "id": owner.credential["credential_id"]}], "timeout": 30000, "userVerification": "required"},
        "serverware": {"schema": profile.OPTIONS_SCHEMA, "operation": profile.OP_BIND, "operationId": payload["operationId"],
            "challengeId": challenge["id"], "credentialRecordId": owner.credential["id"],
            "payloadDigest": profile.sha256(owner.arguments_original.encode("ascii")), "expiresAt": challenge["expires_at"]}}


def on_request(request, raw):
    profile.require(type(raw) is bytes and 0 < len(raw) <= MAX_REQUEST
        and request.headers.get("content-length") == str(len(raw)))
    value = setup.document(raw, MAX_REQUEST)
    owner = _Owner(request)
    path = request.url.path
    if path.endswith("/draft"):
        result = _draft(owner, value)
    elif path.endswith("/lookup"):
        profile.require(set(value) == {"apiVersion", "sessionId"} and value["apiVersion"] == profile.HTTP_SCHEMA)
        session = _session(value["sessionId"])
        profile.require(session["owner_id"] == owner.identity.user_id)
        row = _continuation(session["id"])
        profile.require(row is None or row["owner_id"] == owner.identity.user_id)
        owner.check()
        result = {"apiVersion": OBSERVATION_SCHEMA, "okForAction": False, "automaticRetryAllowed": False,
            "continuationOriginal": None if row is None else profile.row_original(row).decode("ascii")}
    else:
        profile.require(path in {PREFIX + "/options", PREFIX + "/bind"} and value.get("apiVersion") == profile.OPTIONS_SCHEMA
            and set(value) == ({"apiVersion", "argumentsOriginal"} if path.endswith("/options") else {"apiVersion", "argumentsOriginal", "mfa"}))
        arguments = owner.arguments(value["argumentsOriginal"])
        result = _options(owner, arguments) if path.endswith("/options") else owner.bind(arguments, owner.assertion(value["mfa"]))
    profile.require(len(profile.canonical(result)) <= MAX_RESPONSE)
    return result
