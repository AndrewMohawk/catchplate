"""One-shot host-install preparation and fixed signed-readback completion."""
import time

from fastapi import Request
from fastapi.responses import JSONResponse
from serverware import authority_setup_native_ca as p
from serverware import control_plane_setup_native_enrollment as issued
from serverware import authority_contract, db, webauthn

PREFIX = "/api/setup/native-ca"
PATHS = frozenset(PREFIX + "/" + suffix for suffix in ("options", "prepare", "complete"))
LOOKUP = PREFIX + "/lookup"
MAX_HTTP, MAX_RESPONSE = 3 * 1024 * 1024, 2 * 1024 * 1024
COMMON = {"apiVersion": "serverware.setupNativeCaInstallationResponse/v1", "automaticRetryAllowed": False,
    "nativeHostVerified": False, "enrollmentComplete": False, "proxyReady": False}


def error(status=503, *, unknown=False):
    return JSONResponse({**COMMON, "status": "installation-outcome-unknown" if unknown else "refused"},
        status_code=status if status in (400, 401, 403, 409, 412, 413, 415, 428, 503) else 503,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"})


def _row(session):
    with db.connect() as conn:
        value = conn.execute("SELECT * FROM setup_native_ca_installations WHERE session_id = ?", (session,)).fetchone()
    if value is None:
        return None
    row = dict(value); p.row_original(row); return row


def _public(row):
    if row is None:
        return None
    return {"revision": row["revision"], "phase": row["phase"], "preparedSha256": row["prepared_sha256"],
        "enrollmentSha256": row["enrollment_sha256"], "observationSha256": row["observation_sha256"],
        "prepareRequestDigest": row["prepare_request_digest"], "completeRequestDigest": row["complete_request_digest"]}


def _bundle(row, enrollment):
    if row is None:
        return None
    original = p.enrollment.row_original(enrollment).decode("ascii")
    p.require(p.sha256(original.encode("ascii")) == row["enrollment_sha256"])
    return {"preparedOriginal": row["prepared_original"], "preparedSha256": row["prepared_sha256"],
        "enrollmentOriginal": original, "enrollmentSha256": row["enrollment_sha256"],
        "installationAuthorization": issued._certificate(p.enrollment.original(row["installation_original"], p.installation.MAX_BYTES))}


def _arguments(owner, operation, row, installation, host, observation=None):
    return p.arguments(operation, {"actor_id": owner.frame.identity.user_id, "control_plane_configuration_digest": owner.configuration,
        "credential_policy": owner.policy, "enrollment_original": p.enrollment.row_original(row).decode("ascii"),
        "installation_original": installation, "host_key_id": host, "observation_original": observation})


def _options(owner, values):
    keys = webauthn._credential_descriptors_for_policy(owner.frame.identity.user_id, issued.hardware._authenticator_policy(owner.policy))
    p.require(type(keys) is list and 1 <= len(keys) <= 64)
    credential = db.get_webauthn_credential(keys[0]["id"])
    p.require(type(credential) is dict and credential["user_id"] == owner.frame.identity.user_id)
    owner.check()
    challenge = db.issue_policy_authority_webauthn_challenge(operation=p.PREPARE, input_value=values,
        user_id=owner.frame.identity.user_id, credential_id=credential["credential_id"], deadline_ns=owner.frame.context.deadline_ns)
    payload = challenge["payload"]
    p.require(challenge["used_at"] is None and challenge["challenge_type"] == "policy_authority"
        and challenge["user_id"] == owner.frame.identity.user_id and payload["credentialId"] == credential["credential_id"]
        and payload["rpId"] == owner.policy["rpId"] and payload["origin"] in owner.policy["origins"])
    owner.check()
    return {"publicKey": {"challenge": challenge["challenge"], "rpId": payload["rpId"], "allowCredentials": [
        {"type": "public-key", "id": credential["credential_id"]}], "timeout": 30000, "userVerification": "required"},
        "serverware": {"schema": "serverware.setupNativeCaInstallationOptions/v1", "operation": p.PREPARE,
            "operationId": payload["operationId"], "challengeId": challenge["id"], "credentialRecordId": credential["id"]}}


def _call(owner, operation, arguments, assertion=None):
    owner.check(); evidence = None
    if operation == p.PREPARE:
        p.require(type(assertion) is dict and len(p.canonical(assertion)) <= 16384)
        credential = db.get_webauthn_credential(assertion.get("id"))
        p.require(type(credential) is dict and credential["user_id"] == owner.frame.identity.user_id)
        owner.frame.credential = (credential["id"], credential["public_key_cose"], credential["user_id"])
        client, _ = webauthn._parse_client_data(assertion.get("response", {}).get("clientDataJSON"), "webauthn.get")
        challenge = db.get_unused_webauthn_challenge(client["challenge"], challenge_type="policy_authority", user_id=owner.frame.identity.user_id)
        p.require(challenge is not None)
        evidence = {"challengeId": challenge["id"], "credentialRecordId": credential["id"], "assertion": assertion}
    result = issued.custody_client.ControlPlaneCustodyClient._request_authority(owner.custody, operation=operation,
        input_value={"schema": "serverware.policyAuthorityControlledWriterInput/v1", "handler": authority_contract.operation_spec(operation)["handler"],
            "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
            "arguments": {**arguments, **({"authn_evidence": evidence} if evidence is not None else {})}}, deadline_ns=owner.frame.context.deadline_ns)
    owner.check()
    p.require(type(result) is dict and set(result) == {"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "installationOriginal"}
        and result["ok"] is True and result["operation"] == operation and result["idempotentReplay"] is False
        and result["requestDigest"] == p.request_digest(operation, arguments))
    p.digest(result["auditEventDigest"])
    row = _row(owner.session["id"])
    p.require(row is not None and p.row_original(row).decode("ascii") == result["installationOriginal"])
    return row


def run(frame, request):
    from serverware import control_plane_workload_identity_routes as routes
    try:
        phase = request.url.path.rsplit("/", 1)[-1]
        value = p.enrollment.setup.document(frame.original, MAX_HTTP, exact=False)
        fields = {"apiVersion", "sessionId", "observationOriginal"} if phase == "complete" else {"apiVersion", "sessionId", "installationAuthorization", "hostKeyId"}
        if phase == "prepare":
            fields.add("assertion")
        p.require(set(value) == fields and value["apiVersion"] == p.HTTP and phase in {"options", "prepare", "complete"})
        frame.bind(request)
        owner = issued._Setup(frame, value["sessionId"], approver=False)
        enrollment = issued._enrollment(owner.session["id"])
        p.require(enrollment is not None and enrollment["phase"] == "certificate_issued")
        owner.bind(enrollment["intent_original"])
        original = p.enrollment.row_original(enrollment)
        def unchanged():
            owner.check()
            p.require(p.enrollment.row_original(issued._enrollment(owner.session["id"])) == original)
        frame.context._retain_current(unchanged, frame.context.window, frame.context.deadline_ns)
        row = _row(owner.session["id"])
        if phase == "complete":
            p.require(row is not None and row["phase"] == "installation_unknown")
            operation = p.COMPLETE
            args = _arguments(owner, operation, enrollment, row["installation_original"], row["host_key_id"], value["observationOriginal"])
        else:
            p.require(row is None, "an installation attempt exists; use historical lookup only")
            installation = routes._original(value["installationAuthorization"], p.installation.MAX_BYTES, frame.context.work)
            operation = p.PREPARE
            args = _arguments(owner, operation, enrollment, p.enrollment.encoded(installation), value["hostKeyId"])
        if phase == "options":
            return routes._response(frame, {**COMMON, "status": "fresh-assertion-required", "options": _options(owner, args)})
        frame.dispatched = True
        row = _call(owner, operation, args, value.get("assertion"))
        if phase == "prepare":
            return routes._response(frame, {**COMMON, "status": "installation-outcome-unknown", **_bundle(row, enrollment)}, 201)
        return routes._response(frame, {**COMMON, "status": "ca-readback-authenticated", "installation": _public(row)})
    except Exception:
        return error(unknown=frame.dispatched)


def lookup(request, raw):
    """Historical exact recovery only; no issuer/installer contact or reset."""
    from serverware import control_plane_workload_identity_routes as routes
    p.require(type(request) is Request and request.url.path == LOOKUP and request.method == "POST"
        and not request.scope.get("query_string", b"") and request.headers.get("content-type") == "application/json"
        and request.headers.get("content-length") == str(len(raw)))
    value = p.enrollment.setup.document(raw, 4096, exact=False)
    p.require(set(value) == {"apiVersion", "sessionId"} and value["apiVersion"] == p.HTTP)
    p.enrollment.setup.identifier(value["sessionId"])
    identity = routes._cookie_identity(request)
    p.require(identity.user_id.startswith("oidc:") and {"credential_owner", "policy_author"} <= identity.roles)
    started = time.monotonic_ns(); owner = issued.custody_startup.require_started()
    p.require(owner is not None); binding = issued.custody_client._snapshot(owner); issued.custody_client._receipt_now(binding)
    session = issued.setup._session(value["sessionId"])
    p.require(session["owner_id"] == identity.user_id)
    row = _row(session["id"]); enrollment = issued._enrollment(session["id"])
    p.require(row is None or row["owner_id"] == identity.user_id)
    bundle = _bundle(row, enrollment)
    observation = row["observation_original"] if row is not None and row["phase"] == "ca_readback_authenticated" else None
    p.require(routes._cookie_identity(request) == identity and time.monotonic_ns() - started < 30000000000
        and issued.custody_startup.require_started() is owner and issued.custody_client._snapshot(owner) is binding
        and p.enrollment.setup.row_original(issued.setup._session(session["id"])) == p.enrollment.setup.row_original(session)
        and _row(session["id"]) == row and issued._enrollment(session["id"]) == enrollment)
    issued.custody_client._receipt_now(binding)
    return {**COMMON, "status": "observation", "installation": _public(row), "observationOriginal": observation, "bundle": bundle}
