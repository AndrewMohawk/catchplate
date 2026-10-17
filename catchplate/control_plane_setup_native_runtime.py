"""Protected challenge and original-capture completion; no proxy contact."""
from fastapi.responses import JSONResponse

from catchplate import authority_setup_native_runtime as p
from catchplate import authority_setup_native_runtime_policy as policy
from catchplate import control_plane_setup_native_canary as prior
from catchplate import control_plane_policy_canary_startup as cold
from catchplate import authority_contract, db, webauthn

PREFIX = "/api/setup/native-runtime"
PATHS = frozenset(PREFIX + "/" + name for name in ("options", "prepare", "complete", "lookup"))
MAX_HTTP, MAX_RESPONSE = 768 * 1024, 128 * 1024
COMMON = {"apiVersion": "catchplate.setupNativeRuntimeResponse/v1", "okForAction": False, "automaticRetryAllowed": False,
    "nativeHostVerified": False, "enrollmentComplete": False, "proxyReady": False}


def error(status=409, *, unknown=False):
    return JSONResponse({**COMMON, "status": "capture-outcome-unknown" if unknown else "refused"},
        status_code=status if status in (400, 401, 403, 409, 412, 413, 415, 428, 503) else 503,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"})


def _row(session):
    with db.connect() as connection:
        # Bound the actual SQL byte result before JSON materialization.
        p.require(isinstance(connection, db.PostgresMetadataConnection))
        row = connection.execute("WITH chosen AS (SELECT row_to_json(source)::text AS original FROM setup_native_runtime_attempts AS source WHERE session_id = ?) "
            "SELECT CASE WHEN octet_length(original) <= ? THEN original ELSE NULL END AS original FROM chosen", (session, p.MAX_ROW_BYTES)).fetchone()
    if row is None:
        return None
    p.require(type(row["original"]) is str)
    value = p.enrollment.setup.document(row["original"].encode("utf-8"), p.MAX_ROW_BYTES, exact=False)
    p.row_original(value); return value


def _bundle(row):
    if row is None:
        return None
    attempt = p.prepared(row["attempt_original"])
    scope = policy.scope(p.enrollment.setup.document(row["scope_original"].encode("ascii"), 32768))
    expected = {key: value for key, value in scope["nativeAssignment"].items() if key != "holderId"}
    expected.update(apiVersion="catchplate.nativeResponseAttestationExpectations/v2", statementProfile="catchplate.nativeResponseStatements/v1", nonce=attempt["nonce"])
    return {"attemptOriginal": row["attempt_original"], "scopeOriginal": row["scope_original"],
        "expectationsOriginal": p.canonical(expected).decode("ascii")}


class _Owner(prior._Owner):
    def __init__(self, request):
        self.runtime_cold = self.runtime_policy = self.association_original = None
        super().__init__(request)

    def bind(self, sid):
        self.retain_native(sid)
        self.runtime_cold, self.runtime_policy, now = cold.native_setup_runtime_owner()
        p.require(self.runtime_cold.custody is self.custody and self.runtime_cold.binding is self.binding
            and self.runtime_policy["credentialPolicy"] == self.policy)
        row = prior._row(sid); p.require(row is not None and row["owner_id"] == self.identity.user_id)
        self.association_original = p.canary.row_original(row).decode("ascii")
        matches = [item for item in self.runtime_policy["scopes"] if item["sessionId"] == sid]
        p.require(len(matches) == 1); self.runtime_scope = matches[0]
        p.require(self.runtime_scope["issuedAtEpochNs"] <= now < self.runtime_scope["expiresAtEpochNs"])
        self.clip(min(self.runtime_scope["expiresAtEpochNs"], self.runtime_cold.expires)); self.check()

    def check(self):
        super().check()
        if self.runtime_cold is not None:
            owner, selected, now = cold.native_setup_runtime_owner()
            p.require(owner is self.runtime_cold and selected == self.runtime_policy
                and p.canary.row_original(prior._row(self.session["id"])).decode("ascii") == self.association_original)
        super().check()

    def values(self, operation, row=None, capture=None):
        return p.arguments(operation, {"actor_id": self.identity.user_id, "control_plane_configuration_digest": self.configuration,
            "credential_policy": self.policy, "association_original": self.association_original,
            "scope_original": p.canonical(self.runtime_scope).decode("ascii"),
            "attempt_original": None if row is None else row["attempt_original"], "capture_original_base64url": capture})


def _options(owner, values):
    descriptors = webauthn._credential_descriptors_for_policy(owner.identity.user_id, prior.setup.activation._authenticator_policy(owner.policy))
    p.require(type(descriptors) is list and 1 <= len(descriptors) <= 64)
    owner.credential = db.get_webauthn_credential(descriptors[0]["id"])
    p.require(type(owner.credential) is dict and owner.credential["user_id"] == owner.identity.user_id)
    owner.check()
    challenge = db.issue_policy_authority_webauthn_challenge(operation=p.PREPARE, input_value=values, user_id=owner.identity.user_id,
        credential_id=owner.credential["credential_id"], deadline_ns=owner.deadline)
    payload = challenge["payload"]
    p.require(challenge["used_at"] is None and challenge["challenge_type"] == "policy_authority" and challenge["user_id"] == owner.identity.user_id
        and payload["credentialId"] == owner.credential["credential_id"] and payload["rpId"] == owner.policy["rpId"] and payload["origin"] in owner.policy["origins"])
    owner.check()
    return {"publicKey": {"challenge": challenge["challenge"], "rpId": payload["rpId"], "allowCredentials": [{"type": "public-key", "id": owner.credential["credential_id"]}],
        "timeout": 30000, "userVerification": "required"}, "catchplate": {"schema": p.OPTIONS, "operation": p.PREPARE,
        "operationId": payload["operationId"], "challengeId": challenge["id"], "credentialRecordId": owner.credential["id"],
        "payloadDigest": p.sha256(p.canonical(values))}}


def _call(owner, operation, values, assertion_value):
    evidence = None
    if operation == p.PREPARE:
        evidence = owner.assertion({prior.setup.MFA_FIELD: prior.setup.profile.OPTIONS_SCHEMA, "assertion": assertion_value})
    owner.check(); p.require(not owner.dispatched); owner.dispatched = True
    result = prior.setup.custody_client.ControlPlaneCustodyClient._request_authority(owner.custody, operation=operation,
        input_value={"schema": "catchplate.policyAuthorityControlledWriterInput/v1", "handler": authority_contract.operation_spec(operation)["handler"],
            "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
            "arguments": {**values, **({"authn_evidence": evidence} if evidence is not None else {})}}, deadline_ns=owner.deadline)
    owner.check()
    p.require(type(result) is dict and set(result) == {"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "runtimeOriginal"}
        and result["ok"] is True and result["operation"] == operation and result["idempotentReplay"] is False
        and result["requestDigest"] == p.request_digest(operation, values))
    p.digest(result["auditEventDigest"])
    row = _row(owner.session["id"])
    p.require(row is not None and p.row_original(row).decode("ascii") == result["runtimeOriginal"]
        and row["prepare_request_digest" if operation == p.PREPARE else "complete_request_digest"] == result["requestDigest"])
    owner.check(); return row


def on_request(request, raw):
    owner = None
    try:
        p.require(request.url.path in PATHS and type(raw) is bytes and 0 < len(raw) <= MAX_HTTP
            and request.headers.get("content-length") == str(len(raw)))
        value = p.enrollment.setup.document(raw, MAX_HTTP, exact=False); phase = request.url.path.rsplit("/", 1)[-1]
        fields = {"apiVersion", "sessionId"} | ({"assertion"} if phase == "prepare" else {"captureOriginalBase64url"} if phase == "complete" else set())
        p.require(set(value) == fields and value["apiVersion"] == p.HTTP); p.enrollment.setup.identifier(value["sessionId"])
        owner = _Owner(request)
        if phase == "lookup":
            owner.session = prior.setup._session(value["sessionId"]); owner.session_original = p.enrollment.setup.row_original(owner.session)
            p.require(owner.session["owner_id"] == owner.identity.user_id)
            row = _row(owner.session["id"]); p.require(row is None or row["owner_id"] == owner.identity.user_id)
            owner.check(); p.require(_row(owner.session["id"]) == row)
            response = {**COMMON, "status": "observation", "runtime": p.public(row), "bundle": _bundle(row),
                "resultOriginal": None if row is None else row["result_original"]}
        else:
            owner.bind(value["sessionId"]); row = _row(owner.session["id"])
            if phase in {"options", "prepare"}:
                p.require(row is None, "one attempt exists; observe it without renewal")
                values = owner.values(p.PREPARE)
                if phase == "options":
                    response = {**COMMON, "status": "fresh-assertion-required", "options": _options(owner, values)}
                else:
                    row = _call(owner, p.PREPARE, values, value["assertion"])
                    response = {**COMMON, "status": "capture-outcome-unknown", "runtime": p.public(row), "bundle": _bundle(row)}
            else:
                p.require(row is not None and row["phase"] == "capture_outcome_unknown")
                owner.clip(p.prepared(row["attempt_original"])["expiresAtEpochNs"])
                values = owner.values(p.COMPLETE, row, value["captureOriginalBase64url"])
                row = _call(owner, p.COMPLETE, values, None)
                response = {**COMMON, "status": "runtime-evidence-recorded", "runtime": p.public(row), "resultOriginal": row["result_original"]}
        owner.check(); p.require(len(p.canonical(response)) <= MAX_RESPONSE)
        return JSONResponse(response, status_code=201 if phase == "prepare" else 200,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"})
    except Exception:
        return error(unknown=owner is not None and owner.dispatched)
