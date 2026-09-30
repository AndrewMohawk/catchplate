"""Two-person native activation, one retained PREPARE and publication contact.

Drafts and SQL reads are observations. The actual protected writer authenticates
the complete populations, assertion, approval and durable effect hold. No route
resends an old PREPARE or promotes a lost native reply into completion.
"""
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

from fastapi import Request
from serverware import auth, db, webauthn, http_client
from serverware import authority_contract as contract
from serverware import authority_policy_canary as p
from serverware import authority_policy_native_activation as profile
from serverware import authority_native_activation_hold as hold
from serverware import authority_native_activation_publication as publication_proof
from serverware import authority_transition_policy_native_activation as kernel
from serverware import authority_transition_policy_native_activation_state as originals
from serverware import control_plane_custody_startup as custody_startup
from serverware import control_plane_custody_client as custody
from serverware import control_plane_policy_canary_startup as cold
from serverware import control_plane_policy_canary as acquisition
from serverware import control_plane_publication_authorization as publisher
from serverware.control_plane_approval_verification import _epoch_ns, _request_pin

PREFIX = "/api/policy/authority/native-activations"
PHASES = frozenset({"request", "decide", "publish", "record-inclusion", "finalize"})
PATHS = frozenset(PREFIX + "/" + name for name in PHASES | {"draft", "options", "lookup"})
MAX_REQUEST = profile.MAX_NATIVE
MFA_FIELD = "nativePolicyActivationProfile"
MANAGEMENT_PATH = "/v1/policy-shadow/native-activations"


def _identity(request):
    p.require(type(request) is Request and request.method == "POST" and request.url.path in PATHS
        and not request.scope.get("query_string", b"") and request.headers.get("content-type") == "application/json")
    identity = auth.require_admin(request, x_serverware_admin_token=request.headers.get("X-Serverware-Admin-Token"))
    auth.validate_csrf_request(request)
    p.require(identity.user_id.startswith("oidc:") and profile.ROLE in identity.roles)
    return identity


def _row(table, key, value, maximum=profile.MAX_BEFORE):
    # These exact identifiers are source-owned, not HTTP-selected SQL.
    p.require((table, key) in {(p.TABLE, "request_id"), ("control_plane_approvals", "id"),
        (profile.PREPARATION_TABLE, "canary_id"), (profile.FINALIZATION_TABLE, "canary_id"), (hold.TABLE, "scope")})
    with db.connect() as connection:
        p.require(isinstance(connection, db.PostgresMetadataConnection))
        found = connection.execute("WITH selected AS (SELECT row_to_json(source)::text AS original FROM " + table
            + " AS source WHERE " + key + " = ?) SELECT CASE WHEN octet_length(original) <= ? THEN original ELSE NULL END AS original FROM selected",
            (value, maximum)).fetchone()
    if found is None:
        return None
    p.require(type(found["original"]) is str)
    result = p.document(found["original"].encode("utf-8"), maximum, exact=False)
    p.require(type(result) is dict and len(p.canonical(result)) <= maximum)
    return result


class _Owner:
    def __init__(self, request):
        self.request, self.scope, self.pin = request, request.scope, _request_pin(request)
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.identity, self.credential_policy = _identity(request), publisher._policy()
        self.policy_original = p.canonical(self.credential_policy)
        self.cold, self.activation_policy, self.epoch = cold.native_activation_owner()
        self.custody, self.binding = self.cold.custody, self.cold.binding
        self.configuration = self.binding.configuration_digest
        self.mono = time.monotonic_ns()
        self.origin_mono, self.origin_epoch = self.mono, self.epoch
        self.expires = min(self.epoch + 30_000_000_000, self.cold.expires, self.binding.attestation_interval[1])
        self.deadline = min(self.cold.deadline, self.mono + self.expires - self.epoch)
        self.credential, self.contacted, self.operations = None, False, set()
        self.check()

    def check(self):
        owner, policy, epoch = cold.native_activation_owner()
        mono = time.monotonic_ns()
        p.require((os.getpid(), threading.get_ident()) == (self.pid, self.thread)
            and self.mono <= mono < self.deadline and self.epoch <= epoch < self.expires
            and self.request.scope is self.scope and _request_pin(self.request) == self.pin
            and _identity(self.request) == self.identity and p.canonical(publisher._policy()) == self.policy_original
            and owner is self.cold and policy == self.activation_policy
            and custody_startup.require_started() is self.custody and custody._snapshot(self.custody) is self.binding
            and self.binding.configuration_digest == self.configuration)
        if self.credential is not None:
            actual = db.get_webauthn_credential_by_record_id(self.credential["id"])
            p.require(type(actual) is dict and actual.get("revoked_at") is None and all(actual[name] == self.credential[name]
                for name in ("id", "credential_id", "user_id", "public_key_cose")))
            trust = webauthn._allowed_authenticator(actual, publisher._authenticator_policy(self.credential_policy))
            p.require(trust["currently_trusted"] is True and trust["effective_authenticator_class"] in {"hardware", "yubikey"})
        self.mono, self.epoch = mono, epoch

    def clip(self, expiry):
        p.epoch(expiry)
        self.expires = min(self.expires, expiry)
        self.deadline = min(self.deadline, self.origin_mono + self.expires - self.origin_epoch)
        self.check()

    def arguments(self, phase, original):
        operation = profile.PREFIX + ("consume" if phase == "publish" else phase)
        value = profile.arguments(operation, profile.canonical_original(original, MAX_REQUEST))
        p.require(value["actor_id"] == self.identity.user_id and value["control_plane_configuration_digest"] == self.configuration
            and value["credential_policy"] == self.credential_policy and value["activation_policy"] == self.activation_policy)
        if operation in profile.ASSERTION_OPERATIONS:
            p.require(self.activation_policy["issuedAtEpochNs"] <= self.epoch < self.activation_policy["expiresAtEpochNs"])
            self.clip(value["request"]["expiresAtUnixNanos"])
        return operation, value

    def assertion(self, mfa):
        p.require(type(mfa) is dict and set(mfa) == {MFA_FIELD, "assertion"} and mfa[MFA_FIELD] == profile.HTTP
            and len(p.canonical(mfa)) <= 16384 and type(mfa["assertion"]) is dict)
        assertion = mfa["assertion"]
        self.credential = db.get_webauthn_credential(assertion.get("id"))
        p.require(type(self.credential) is dict and self.credential["user_id"] == self.identity.user_id)
        self.check()
        client, _ = webauthn._parse_client_data(assertion.get("response", {}).get("clientDataJSON"), "webauthn.get")
        challenge = db.get_unused_webauthn_challenge(client["challenge"], challenge_type="policy_authority", user_id=self.identity.user_id)
        p.require(challenge is not None)
        self.clip(_epoch_ns(challenge["expires_at"]))
        return {"challengeId": challenge["id"], "credentialRecordId": self.credential["id"], "assertion": assertion}

    def dispatch(self, operation, values, assertion=None):
        self.check()
        p.require(operation not in self.operations)
        self.operations.add(operation)  # Unknown completion is not replay permission.
        controlled = {"schema": "serverware.policyAuthorityControlledWriterInput/v1", "handler": contract.operation_spec(operation)["handler"],
            "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
            "arguments": {**values, **({"authn_evidence": assertion} if assertion is not None else {})}}
        native = None
        if operation == profile.PREFIX + "consume":
            raw = custody.ControlPlaneCustodyClient._request_native_activation(self.custody, input_value=controlled, deadline_ns=self.deadline)
            response = profile.canonical_original(raw[1].decode("ascii"), MAX_REQUEST)
            p.require(response["schema"] == profile.RESPONSE_SCHEMA
                and p.decoded(response["authorityConfigurationOriginal"], contract.MAX_REQUEST_BYTES) == self.cold.originals[2].raw)
            result = response["result"]
            native = profile.native_request({"apiVersion": profile.NATIVE_REQUEST, "requestId": values["request"]["activationId"],
                "replayId": values["request"]["replayId"], "prepareRequestOriginal": raw[0].decode("ascii"),
                "prepareResponseOriginal": raw[1].decode("ascii")})
        else:
            result = custody.ControlPlaneCustodyClient._request_authority(self.custody, operation=operation,
                input_value=controlled, deadline_ns=self.deadline)
        self.check()
        p.require(type(result) is dict and set(result) == profile.RESULT_FIELDS and result["ok"] is True
            and result["operation"] == operation and result["requestDigest"] == profile.request_digest(operation, values)
            and result["idempotentReplay"] is False)
        p.digest(result["auditEventDigest"])
        row = _row("control_plane_approvals", "id", result["approval"]["id"])
        p.require(row is not None and db.row_to_control_plane_approval(row) == result["approval"]
            and row["request_json"] == p.canonical(values["request"]).decode("ascii"))
        if result["preparedOriginal"] is not None:
            held = _row(profile.PREPARATION_TABLE, "canary_id", values["request"]["canaryId"])
            p.require(held is not None and held["prepared_original"] == result["preparedOriginal"]
                and held["prepared_sha256"] == result["preparedSha256"])
        self.check()
        return result, native

    def contact(self, native, result, values):
        from serverware import app
        self.check()
        p.require(not self.contacted and profile.PREFIX + "consume" in self.operations)
        prepared = profile.prepared(profile.canonical_original(result["preparedOriginal"]))
        self.clip(prepared["expiresAtUnixNanos"])
        url, token = app._policy_shadow_generation_url(MANAGEMENT_PATH), app.DATA_PLANE_MANAGEMENT_TOKEN
        p.require(type(token) is str and 0 < len(token.encode("utf-8")) <= 4096)
        raw = p.canonical(native)
        p.require(len(raw) <= MAX_REQUEST)
        returned = {"apiVersion": profile.HTTP, "phase": "publish", "automaticRetryAllowed": False,
            "result": result, "nativeRequest": native, "publicationOriginal": ""}
        p.require(len(p.canonical(returned)) + 2 * 32768 <= MAX_REQUEST,
            "complete publication handoff exceeds the unchanged HTTP bound")
        request = urllib.request.Request(url, data=raw, method="POST", headers={"Accept": "application/json", "Accept-Encoding": "identity",
            "Content-Type": "application/json", "X-Serverware-Data-Plane-Token": token})
        self.contacted = True
        try:
            response = http_client.request_bytes(request, timeout=30, max_bytes=32768,
                deadline=http_client.HttpDeadline(self.deadline / 1_000_000_000), require_https=False,
                expected_statuses=(201,), expected_content_types=("application/json",))
        except urllib.error.HTTPError as error:
            error.close()
            raise ValueError("native activation unavailable or outcome unknown") from None
        self.check()
        receipt = p.document(response.body, 32768, exact=False)
        original = p.canonical(receipt).decode("ascii")
        before = profile.canonical_original(values["before_original"], profile.MAX_BEFORE)
        assigned = [row for row in before["policy_canary_assignments"] if row["canary_id"] == prepared["canaryId"]]
        p.require(len(assigned) == 1 and app._policy_shadow_generation_url(MANAGEMENT_PATH) == url and app.DATA_PLANE_MANAGEMENT_TOKEN == token)
        publication_proof.verify(original, prepared=prepared, request_sha256=p.sha256(raw),
            assignment=profile.canonical_original(assigned[0]["assignment_payload_json"]), policy=self.activation_policy)
        self.check()
        return original


def _draft(owner, value):
    p.require(value.get("apiVersion") == profile.HTTP and value.get("phase") in PHASES)
    phase = value["phase"]
    operation = profile.PREFIX + ("consume" if phase == "publish" else phase)
    approval = None
    if phase == "request":
        p.require(set(value) == {"apiVersion", "phase", "readinessRequestId", "generationPublicationEnvelopeSha256"})
        p.identifier(value["readinessRequestId"]); p.digest(value["generationPublicationEnvelopeSha256"])
        row = _row(p.TABLE, "request_id", value["readinessRequestId"], p.MAX_RESPONSE)
    else:
        fields = {"apiVersion", "phase", "approvalId"} | ({"nativeRequest", "publicationOriginal"} if phase == "record-inclusion" else set())
        p.require(set(value) == fields and str(uuid.UUID(value["approvalId"])) == value["approvalId"])
        approval = _row("control_plane_approvals", "id", value["approvalId"])
        p.require(approval is not None and approval["action"] == profile.ACTION and approval["resource_id"] == profile.RESOURCE)
        intent = profile.intent(profile.canonical_original(approval["request_json"], 16384))
        p.require((phase == "decide" and approval["status"] == "pending" and approval["requester_id"] != owner.identity.user_id)
            or (phase == "publish" and approval["status"] == "approved" and approval["requester_id"] == owner.identity.user_id)
            or (phase in {"record-inclusion", "finalize"} and approval["status"] == "consumed" and approval["requester_id"] == owner.identity.user_id))
        row = _row(p.TABLE, "request_id", intent["readinessRequestId"], p.MAX_RESPONSE)
    p.require(row is not None)
    p.row_original(row)
    batch, intake = p.batch(row["batch_original"]), p.result(profile.canonical_original(row["result_original"], p.MAX_RESULT))
    p.require(len(batch["events"]) == intake["accepted"] == len(intake["results"]) == 1 and batch["events"][0]["kind"] == "readiness")
    original = profile.canonical_original(intake["results"][0]["storedOriginal"])
    core = original["core"]
    before_original = acquisition._snapshot(owner, batch["events"])
    before = profile.canonical_original(before_original, profile.MAX_BEFORE)
    if phase == "request":
        generations = [item for item in before["policy_shadow_generation_publications"]
            if item["generation_publication_envelope_digest"] == value["generationPublicationEnvelopeSha256"] and item["canary_id"] == core["canaryId"]]
        p.require(len(generations) == 1)
        generation = generations[0]
        publication = profile.canonical_original(generation["generation_publication_payload_json"])
        result_sha = p.sha256(p.canonical(original))
        intent = profile.intent({"apiVersion": profile.INTENT, "activationId": str(uuid.uuid4()), "replayId": str(uuid.uuid4()),
            "canaryId": core["canaryId"], "readinessRequestId": row["request_id"], "readinessResultSha256": result_sha,
            "readinessCoreSha256": original["coreSha256"], "readyStateSha256": p.sha256(p.canonical(originals.ready_payload(core, result_sha))),
            "generationPublicationEnvelopeSha256": value["generationPublicationEnvelopeSha256"], "generationId": generation["generation_id_digest"],
            "publicationBefore": {"revision": publication["custody"]["publicationRevision"], "policySha256": core["currentPublication"]["policy_hash"],
                "policySequence": core["currentPublication"]["sequence"], "rollbackEpoch": core["currentPublication"]["rollback_epoch"]},
            "publicationAfter": {"policySha256": core["policyIdentity"]["candidatePolicySha256"],
                "policySequence": core["policyIdentity"]["candidatePolicySequence"], "rollbackEpoch": core["policyIdentity"]["rollbackEpoch"]},
            "trustCheckpoint": core["trustCheckpoint"], "issuedAtUnixNanos": core["issuedAtUnixNanos"], "expiresAtUnixNanos": core["expiresAtUnixNanos"]})
    values = {"actor_id": owner.identity.user_id, "control_plane_configuration_digest": owner.configuration, "request": intent,
        "approval_id": None if approval is None else approval["id"], "approval_original": None if approval is None else p.canonical(approval).decode("ascii"),
        "credential_policy": owner.credential_policy, "before_original": before_original, "activation_policy": owner.activation_policy}
    if phase == "record-inclusion":
        values.update(native_request=value["nativeRequest"], publication_original=value["publicationOriginal"])
    profile.arguments(operation, values)
    if operation in profile.ASSERTION_OPERATIONS:
        owner.clip(intent["expiresAtUnixNanos"])
        profile.verify_original(operation, values, configuration_payload=owner.cold.payload, root_key=owner.cold.root, now_epoch_ns=owner.epoch)
        database_now = datetime.fromtimestamp(owner.epoch // 1_000_000_000, timezone.utc).replace(microsecond=(owner.epoch % 1_000_000_000) // 1000)
        originals.associated_intent(kernel.state_from(values, database_now, before), values)
    owner.check()
    result = {"apiVersion": profile.HTTP, "phase": phase, "okForAction": False, "automaticRetryAllowed": False,
        "argumentsOriginal": p.canonical(values).decode("ascii")}
    p.require(len(p.canonical(result)) <= MAX_REQUEST)
    return result


def on_request(request, raw):
    p.require(type(raw) is bytes and 0 < len(raw) <= MAX_REQUEST and request.headers.get("content-length") == str(len(raw)))
    value = p.document(raw, MAX_REQUEST)
    p.require(type(value) is dict and value.get("apiVersion") == profile.HTTP)
    owner = _Owner(request)
    name = request.url.path.removeprefix(PREFIX + "/")
    if name == "draft":
        return _draft(owner, value)
    if name == "lookup":
        p.require(set(value) == {"apiVersion", "approvalId"} and str(uuid.UUID(value["approvalId"])) == value["approvalId"])
        approval = _row("control_plane_approvals", "id", value["approvalId"])
        p.require(approval is not None and approval["action"] == profile.ACTION and approval["resource_id"] == profile.RESOURCE
            and owner.identity.user_id in {approval["requester_id"], approval["approved_by"]})
        intent = profile.intent(profile.canonical_original(approval["request_json"], 16384))
        prepared = _row(profile.PREPARATION_TABLE, "canary_id", intent["canaryId"])
        finalized = _row(profile.FINALIZATION_TABLE, "canary_id", intent["canaryId"])
        active_hold = _row(hold.TABLE, "scope", hold.SCOPE)
        owner.check()
        result = {"apiVersion": profile.HTTP, "okForAction": False, "automaticRetryAllowed": False,
            "approvalOriginal": p.canonical(approval).decode("ascii"), "preparationOriginal": None if prepared is None else p.canonical(prepared).decode("ascii"),
            "finalizationOriginal": None if finalized is None else p.canonical(finalized).decode("ascii"),
            "effectHoldOriginal": None if active_hold is None or active_hold["activation_id"] != intent["activationId"] else p.canonical(active_hold).decode("ascii")}
        p.require(len(p.canonical(result)) <= MAX_REQUEST)
        return result
    phase = value.get("phase")
    p.require(phase in PHASES and (name == phase or name == "options" and phase in {"request", "decide", "publish"}))
    fields = {"apiVersion", "phase", "argumentsOriginal"}
    needs_assertion = name in {"request", "decide", "publish"}
    p.require(set(value) == fields | ({"mfa"} if needs_assertion else set()))
    operation, arguments = owner.arguments(phase, value["argumentsOriginal"])
    if name == "options":
        descriptors = webauthn._credential_descriptors_for_policy(owner.identity.user_id, publisher._authenticator_policy(owner.credential_policy))
        p.require(type(descriptors) is list and 1 <= len(descriptors) <= 64)
        owner.credential = db.get_webauthn_credential(descriptors[0]["id"])
        p.require(type(owner.credential) is dict and owner.credential["user_id"] == owner.identity.user_id)
        owner.check()
        challenge = db.issue_policy_authority_webauthn_challenge(operation=operation, input_value=arguments,
            user_id=owner.identity.user_id, credential_id=owner.credential["credential_id"], deadline_ns=owner.deadline)
        owner.check()
        payload = challenge["payload"]
        p.require(challenge["used_at"] is None and challenge["user_id"] == owner.identity.user_id
            and payload["credentialId"] == owner.credential["credential_id"] and payload["rpId"] == owner.credential_policy["rpId"]
            and payload["origin"] in owner.credential_policy["origins"])
        return {"publicKey": {"challenge": challenge["challenge"], "rpId": payload["rpId"], "allowCredentials": [
            {"type": "public-key", "id": owner.credential["credential_id"]}], "timeout": 30000, "userVerification": "required"},
            "serverware": {"schema": profile.HTTP, "operation": operation, "operationId": payload["operationId"], "challengeId": challenge["id"],
                "credentialRecordId": owner.credential["id"], "payloadDigest": p.sha256(value["argumentsOriginal"].encode("ascii")), "expiresAt": challenge["expires_at"]}}
    result, native = owner.dispatch(operation, arguments, owner.assertion(value["mfa"]) if needs_assertion else None)
    receipt = owner.contact(native, result, arguments) if phase == "publish" else None
    response = {"apiVersion": profile.HTTP, "phase": phase, "automaticRetryAllowed": False,
        "result": result, "nativeRequest": native, "publicationOriginal": receipt}
    p.require(len(p.canonical(response)) <= MAX_REQUEST)
    owner.check()
    return response
