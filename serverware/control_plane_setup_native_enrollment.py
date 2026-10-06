"""One actual native issuer exchange following protected Setup preparation."""
import time

from fastapi import Request
from fastapi.responses import JSONResponse
from serverware import authority_contract, db, webauthn
from serverware import authority_setup_native_enrollment as p
from serverware import control_plane_setup_policy as setup
from serverware import control_plane_oauth_activation as hardware
from serverware import control_plane_custody_client as custody_client
from serverware import control_plane_custody_startup as custody_startup
from serverware import control_plane_workload_identity_client as issuer
from serverware import control_plane_credential_currentness as currentness

PREFIX = "/api/setup/native-enrollment"
PATHS = frozenset(PREFIX + "/" + phase for phase in ("draft", "options", "request", "decide", "issue"))
LOOKUP = PREFIX + "/lookup"
RESPONSE = "serverware.setupNativeEnrollmentResponse/v1"
OPTIONS = "serverware.setupNativeEnrollmentOptions/v1"
MAX_HTTP = 3 * 1024 * 1024
MAX_RESPONSE = 2 * 1024 * 1024
PHASES = {"request": p.REQUEST, "decide": p.DECIDE, "issue": p.PREPARE}
COMMON = {"apiVersion": RESPONSE, "automaticRetryAllowed": False, "caInstalled": False,
    "enrollmentComplete": False, "proxyReady": False}


def error(status=503, *, unknown=False):
    return JSONResponse({**COMMON, "status": "issuance-outcome-unknown" if unknown else "refused"},
        status_code=status if status in (400, 401, 403, 409, 412, 413, 415, 428, 503) else 503,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"})


def _enrollment(session):
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM setup_native_enrollments WHERE session_id = ?", (session,)).fetchone()
    if row is None:
        return None
    value = dict(row); p.row_original(value)
    return value


def _public(row):
    if row is None:
        return None
    value = p.intent(row["intent_original"])
    return {"revision": row["revision"], "phase": row["phase"], "intentSha256": row["intent_sha256"],
        "assignmentSha256": value["assignmentSha256"], "certificateSha256": row["certificate_sha256"],
        "approvalId": row["approval_id"], "prepareRequestDigest": row["prepare_request_digest"],
        "completeRequestDigest": row["complete_request_digest"]}


def _certificate(raw):
    return {"base64Url": p.encoded(raw), "byteCount": len(raw), "bytesDigest": p.sha256(raw)}


class _Setup:
    def __init__(self, frame, session_id, *, approver):
        self.frame, self.approver = frame, approver
        self.policy = hardware._policy()
        self.policy_original = p.canonical(self.policy)
        self.custody = custody_startup.require_started()
        p.require(self.custody is not None)
        self.binding = custody_client._snapshot(self.custody)
        self.configuration = self.binding.configuration_digest
        self.session, self.continuation = setup._session(session_id), setup._continuation(session_id)
        p.require(self.continuation is not None)
        self.session_original = p.setup.row_original(self.session)
        self.continuation_original = p.candidate.row_original(self.continuation)
        retained = p.setup.document(self.continuation["request_original"].encode("ascii"), p.candidate.MAX_ARGUMENT_BYTES)
        self.rotated = set(retained["request"]) == p.candidate.ROTATED_STATIC_REQUEST_FIELDS
        if self.rotated or set(retained["request"]) == p.candidate.STATIC_REQUEST_FIELDS:
            p.candidate.require_static_session(self.session, rotated=self.rotated)
        else:
            p.require(set(retained["request"]) == p.candidate.REQUEST_FIELDS and self.session["revision"] == 3)
        p.require(self.session["phase"] == "credential_activated"
            and self.session["status"] == "active" and self.session["terminal_at"] is None
            and self.session["current_assignee_id"] in {None, self.session["owner_id"]}
            and self.continuation["setup_original"].encode("ascii") == self.session_original
            and self.continuation["configuration_digest"] == self.configuration)
        self.current_original = p.canonical(setup._PostBindOwner.current(self))
        self.credential_original = self.current_credential()
        self.check()
        frame.context._retain_current(self.check, frame.context.window, frame.context.deadline_ns)

    def check(self):
        self.frame.base()
        identity = self.frame.identity
        p.require(identity.user_id.startswith("oidc:") and ("approver" in identity.roles if self.approver else
            {"credential_owner", "policy_author"} <= identity.roles)
            and (identity.user_id != self.session["owner_id"] if self.approver else identity.user_id == self.session["owner_id"])
            and p.canonical(hardware._policy()) == self.policy_original
            and custody_startup.require_started() is self.custody and custody_client._snapshot(self.custody) is self.binding
            and p.setup.row_original(setup._session(self.session["id"])) == self.session_original
            and p.candidate.row_original(setup._continuation(self.session["id"])) == self.continuation_original
            and p.canonical(setup._PostBindOwner.current(self)) == self.current_original
            and self.current_credential() == self.credential_original)
        now = custody_client._receipt_now(self.binding)
        p.require(now < p.setup.epoch(self.session["expires_at"]))
        return now

    def current_credential(self):
        rows = currentness._rows(self.continuation["credential_id"], self.continuation["credential_version"])
        p.require(rows[2]["status"] == "open")
        return p.canonical(rows)

    def bind(self, text):
        value = p.intent(text)
        p.require((p.rotated_continuation(value) == self.continuation) if self.rotated
            else value["apiVersion"] == p.SCHEMA)
        expected = {"sessionId": self.session["id"], "ownerId": self.session["owner_id"],
            "setupSha256": p.sha256(self.session_original), "continuationSha256": p.sha256(self.continuation_original),
            "assignmentSha256": self.continuation["assignment_digest"], "policyHash": self.continuation["policy_hash"],
            "routePolicyDigest": self.continuation["route_policy_digest"], "principalId": self.session["principal_id"],
            "credentialId": self.continuation["credential_id"], "credentialVersion": self.continuation["credential_version"]}
        p.require(all(value[name] == field for name, field in expected.items())
            and p.original(value["issuerBootstrap"], 131072) == self.frame.context.issuer_bootstrap_bytes
            and value["issuedAtEpochNs"] <= self.check() < value["expiresAtEpochNs"] <= p.setup.epoch(self.session["expires_at"]))
        raw = tuple(p.original(value[name], limit) for name, limit in (("authorization", 32768), ("packet", 524288), ("request", 65536)))
        admitted = issuer._admit_on_context(self.frame.context, originals=raw)
        p.require(type(admitted) is issuer.native_authorization._NativeIssuanceMaterial
            and admitted.principal_id == self.session["principal_id"])
        grant = p.setup.document(raw[0], 32768, exact=False)["payload"]
        p.require(grant["policyHash"] == value["policyHash"]
            and grant["issuedAtEpochNs"] <= value["issuedAtEpochNs"] < value["expiresAtEpochNs"] <= grant["expiresAtEpochNs"])
        def live():
            now = self.check()
            p.require(value["issuedAtEpochNs"] <= now < value["expiresAtEpochNs"])
            return now
        self.frame.context._retain_current(live, self.frame.context.window, self.frame.context.deadline_ns)
        return value, raw

    def arguments(self, operation, text, approval_id, certificate=None):
        return p.arguments(operation, {"actor_id": self.frame.identity.user_id,
            "control_plane_configuration_digest": self.configuration, "credential_policy": self.policy,
            "intent_original": text, "approval_id": approval_id, "certificate_original": certificate})

    def options(self, operation, arguments):
        keys = webauthn._credential_descriptors_for_policy(self.frame.identity.user_id, hardware._authenticator_policy(self.policy))
        p.require(type(keys) is list and 1 <= len(keys) <= 64)
        credential = db.get_webauthn_credential(keys[0]["id"])
        p.require(type(credential) is dict and credential["user_id"] == self.frame.identity.user_id)
        self.check()
        challenge = db.issue_policy_authority_webauthn_challenge(operation=operation, input_value=arguments,
            user_id=self.frame.identity.user_id, credential_id=credential["credential_id"], deadline_ns=self.frame.context.deadline_ns)
        payload = challenge["payload"]
        p.require(challenge["used_at"] is None and challenge["challenge_type"] == "policy_authority"
            and challenge["user_id"] == self.frame.identity.user_id and payload["credentialId"] == credential["credential_id"]
            and payload["rpId"] == self.policy["rpId"] and payload["origin"] in self.policy["origins"])
        self.check()
        return {"publicKey": {"challenge": challenge["challenge"], "rpId": payload["rpId"], "allowCredentials": [
            {"type": "public-key", "id": credential["credential_id"]}], "timeout": 30000, "userVerification": "required"},
            "serverware": {"schema": OPTIONS, "operation": operation, "operationId": payload["operationId"],
                "challengeId": challenge["id"], "credentialRecordId": credential["id"],
                "intentSha256": p.sha256(arguments["intent_original"].encode("ascii"))}}

    def call(self, operation, arguments, assertion=None):
        self.check()
        evidence = None
        if operation in p.ASSERTION_OPERATIONS:
            p.require(type(assertion) is dict and len(p.canonical(assertion)) <= 16384)
            credential = db.get_webauthn_credential(assertion.get("id"))
            p.require(type(credential) is dict and credential["user_id"] == self.frame.identity.user_id)
            self.frame.credential = (credential["id"], credential["public_key_cose"], credential["user_id"])
            client, _ = webauthn._parse_client_data(assertion.get("response", {}).get("clientDataJSON"), "webauthn.get")
            challenge = db.get_unused_webauthn_challenge(client["challenge"], challenge_type="policy_authority", user_id=self.frame.identity.user_id)
            p.require(challenge is not None)
            evidence = {"challengeId": challenge["id"], "credentialRecordId": credential["id"], "assertion": assertion}
        result = custody_client.ControlPlaneCustodyClient._request_authority(self.custody, operation=operation,
            input_value={"schema": "serverware.policyAuthorityControlledWriterInput/v1",
                "handler": authority_contract.operation_spec(operation)["handler"], "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
                "arguments": {**arguments, **({"authn_evidence": evidence} if evidence is not None else {})}},
            deadline_ns=self.frame.context.deadline_ns)
        self.check()
        p.require(type(result) is dict and set(result) == {"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "approvalId", "enrollmentOriginal"}
            and result["ok"] is True and result["operation"] == operation and result["idempotentReplay"] is False
            and result["requestDigest"] == p.request_digest(operation, arguments))
        p.digest(result["auditEventDigest"])
        if operation in {p.PREPARE, p.COMPLETE}:
            row = _enrollment(self.session["id"])
            p.require(row is not None and p.row_original(row).decode("ascii") == result["enrollmentOriginal"])
        return result


def run(frame, request):
    from serverware import control_plane_workload_identity_routes as routes
    phase = request.url.path.rsplit("/", 1)[-1]
    try:
        value = p.setup.document(frame.original, MAX_HTTP, exact=False)
        p.require(value.get("apiVersion") == p.HTTP_SCHEMA)
        selected_phase = value.get("phase") if phase == "options" else phase
        frame.bind(request, approver=selected_phase == "decide")
        if phase == "draft":
            p.require(set(value) == {"apiVersion", "sessionId", "authorization", "packet", "request"})
            owner = _Setup(frame, value["sessionId"], approver=False)
            p.require(_enrollment(owner.session["id"]) is None)
            raw = tuple(routes._original(value[name], limit, frame.context.work) for name, limit in
                (("authorization", 32768), ("packet", 524288), ("request", 65536)))
            admitted = issuer._admit_on_context(frame.context, originals=raw)
            p.require(type(admitted) is issuer.native_authorization._NativeIssuanceMaterial and admitted.principal_id == owner.session["principal_id"])
            now = owner.check()
            selected = {"apiVersion": p.ROTATED_SCHEMA if owner.rotated else p.SCHEMA, "sessionId": owner.session["id"], "ownerId": owner.session["owner_id"],
                "setupSha256": p.sha256(owner.session_original), "continuationSha256": p.sha256(owner.continuation_original),
                "assignmentSha256": owner.continuation["assignment_digest"], "policyHash": owner.continuation["policy_hash"],
                "routePolicyDigest": owner.continuation["route_policy_digest"], "principalId": owner.session["principal_id"],
                "credentialId": owner.continuation["credential_id"], "credentialVersion": owner.continuation["credential_version"],
                "issuerBootstrap": p.encoded(frame.context.issuer_bootstrap_bytes),
                **{name: p.encoded(raw[index]) for index, name in enumerate(("authorization", "packet", "request"))},
                "issuedAtEpochNs": now, "expiresAtEpochNs": min(now + 300_000_000_000,
                    admitted.not_after_epoch_seconds * 1_000_000_000, p.setup.epoch(owner.session["expires_at"]))}
            if owner.rotated:
                selected["continuationOriginal"] = owner.continuation_original.decode("ascii")
            text = p.canonical(selected).decode("ascii"); owner.bind(text)
            return routes._response(frame, {**COMMON, "status": "draft", "intentOriginal": text, "intentSha256": p.sha256(text.encode("ascii"))})
        fields = {"apiVersion", "intentOriginal", "approvalId", "phase" if phase == "options" else "assertion"}
        p.require(set(value) == fields and selected_phase in PHASES)
        text = value["intentOriginal"]; selected = p.intent(text)
        owner = _Setup(frame, selected["sessionId"], approver=selected_phase == "decide")
        _, raw = owner.bind(text)
        p.require(_enrollment(owner.session["id"]) is None, "a native issuance attempt already exists; only lookup is allowed")
        operation = PHASES[selected_phase]
        args = owner.arguments(operation, text, value["approvalId"])
        identity = {"approvalId": value["approvalId"], "intentSha256": p.sha256(text.encode("ascii"))}
        if phase == "options":
            return routes._response(frame, {**COMMON, "status": "fresh-assertion-required", **identity,
                "phase": selected_phase, "options": owner.options(operation, args)})
        # Fence browser uncertainty before the first controlled write; a failed
        # response never grants replay, even if the issuer has not been called.
        frame.dispatched = True
        result = owner.call(operation, args, value["assertion"])
        identity["approvalId"] = result["approvalId"]
        if phase != "issue":
            return routes._response(frame, {**COMMON, "status": "approval-required" if phase == "request" else "approved", **identity},
                428 if phase == "request" else 200)
        # The same actual source owner retains the signed originals and old
        # deadline. No issuance can occur without the durable unknown fence.
        issued = issuer._issue_on_context(frame.context, authorization_bytes=raw[0], packet_bytes=raw[1], request_bytes=raw[2])
        frame.result = issuer._require_result(issued, context=frame.context)
        completion = owner.arguments(p.COMPLETE, text, result["approvalId"], p.encoded(issued.certificate_bytes))
        p.require(p.canonical(p.association(text, completion["certificate_original"])) == issued.association_bytes)
        completed = owner.call(p.COMPLETE, completion)
        row = p.setup.document(completed["enrollmentOriginal"].encode("ascii"), p.MAX_ROW_BYTES)
        p.require(row["phase"] == "certificate_issued")
        issued.current()
        return routes._response(frame, {**COMMON, "status": "certificate-issued", "enrollment": _public(row),
            "certificate": _certificate(issued.certificate_bytes), "association": p.setup.document(issued.association_bytes, 4096)}, 201)
    except Exception:
        return error(unknown=frame.dispatched)


def lookup(request, raw):
    """Read stored public originals, including after issuance expiry; no send."""
    from serverware import control_plane_workload_identity_routes as routes
    p.require(type(request) is Request and request.url.path == LOOKUP and request.method == "POST"
        and not request.scope.get("query_string", b"") and request.headers.get("content-type") == "application/json"
        and request.headers.get("content-length") == str(len(raw)))
    value = p.setup.document(raw, 4096, exact=False)
    p.require(set(value) == {"apiVersion", "sessionId"} and value["apiVersion"] == p.HTTP_SCHEMA)
    p.setup.identifier(value["sessionId"])
    identity = routes._cookie_identity(request)
    p.require(identity.user_id.startswith("oidc:") and {"credential_owner", "policy_author"} <= identity.roles)
    started = time.monotonic_ns(); owner = custody_startup.require_started()
    p.require(owner is not None); binding = custody_client._snapshot(owner)
    custody_client._receipt_now(binding)
    session = setup._session(value["sessionId"])
    p.require(session["owner_id"] == identity.user_id)
    row = _enrollment(value["sessionId"])
    p.require(row is None or row["owner_id"] == identity.user_id)
    certificate = association = None
    if row is not None and row["phase"] == "certificate_issued":
        certificate = _certificate(p.original(row["certificate_original"], 65536))
        association = p.setup.document(row["association_original"].encode("ascii"), 4096)
    p.require(routes._cookie_identity(request) == identity and time.monotonic_ns() - started < 30_000_000_000
        and custody_startup.require_started() is owner and custody_client._snapshot(owner) is binding
        and p.setup.row_original(setup._session(value["sessionId"])) == p.setup.row_original(session)
        and _enrollment(value["sessionId"]) == row)
    custody_client._receipt_now(binding)
    return {**COMMON, "status": "observation", "enrollment": _public(row), "certificate": certificate, "association": association}
