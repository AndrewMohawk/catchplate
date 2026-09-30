"""Existing native producers into a fixed Setup association; no native contact."""
from fastapi.responses import JSONResponse

from serverware import authority_setup_native_canary as p
from serverware import control_plane_setup_policy as setup
from serverware import control_plane_setup_native_enrollment as enrollment
from serverware import control_plane_setup_native_ca as installation
from serverware import control_plane_native_policy_activation as native
from serverware import control_plane_credential_currentness as currentness
from serverware import authority_contract, db, webauthn

PREFIX = "/api/setup/native-canary"
PATHS = frozenset(PREFIX + "/" + phase for phase in ("draft", "options", "record", "lookup"))
MAX_HTTP, MAX_RESPONSE = 32768, 65536
COMMON = {"apiVersion": "serverware.setupNativeCanaryResponse/v1", "okForAction": False, "automaticRetryAllowed": False,
    "nativeHostVerified": False, "enrollmentComplete": False, "proxyReady": False}


def error(status=409, *, unknown=False):
    return JSONResponse({**COMMON, "status": "association-outcome-unknown" if unknown else "refused"},
        status_code=status if status in (400, 401, 403, 409, 412, 413, 415, 428, 503) else 503,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"})


def _row(session):
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM setup_native_canary_associations WHERE session_id = ?", (session,)).fetchone()
    if row is None:
        return None
    row = dict(row); p.row_original(row); return row


def _sources(owner):
    enrolled, installed = enrollment._enrollment(owner.session["id"]), installation._row(owner.session["id"])
    p.require(enrolled is not None and installed is not None and enrolled["phase"] == "certificate_issued"
        and installed["phase"] == "ca_readback_authenticated" and enrolled["owner_id"] == installed["owner_id"] == owner.identity.user_id)
    final = native._row(p.activation.FINALIZATION_TABLE, "canary_id", owner.continuation["canary_id"])
    preparation = native._row(p.activation.PREPARATION_TABLE, "canary_id", owner.continuation["canary_id"])
    p.require(final is not None and preparation is not None)
    credential = currentness._rows(owner.continuation["credential_id"], owner.continuation["credential_version"])
    p.require(credential[2]["status"] == "open")
    return enrolled, installed, final, credential, preparation


class _Owner(setup._PostBindOwner):
    def __init__(self, request):
        self.sources_original = None
        super().__init__(request)

    def retain_native(self, session_id):
        self.retain_bound(session_id)
        p.require({"credential_owner", "policy_author"} <= self.identity.roles)
        self.current_original = p.canonical(self.current())
        self.sources_original = p.canonical(_sources(self))
        self.check()

    def check(self):
        super().check()
        if self.sources_original is not None:
            p.require(p.canonical(_sources(self)) == self.sources_original)
        super().check()

    def arguments(self, original):
        p.require(type(original) is str and len(original.encode("ascii")) <= p.MAX_ARGUMENT_BYTES)
        values = p.arguments(p.RECORD, p.enrollment.setup.document(original.encode("ascii"), p.MAX_ARGUMENT_BYTES))
        p.require(p.canonical(values).decode("ascii") == original and values["actor_id"] == self.identity.user_id
            and values["control_plane_configuration_digest"] == self.configuration and values["credential_policy"] == self.policy)
        self.retain_native(values["request"]["sessionId"])
        expected = _binding(self)
        p.require(all(values["request"][name] == value for name, value in expected.items())
            and values["request"]["issuedAtEpochNs"] <= self.last_epoch)
        self.arguments_original = original
        self.clip(values["request"]["expiresAtEpochNs"])
        p.require(_row(self.session["id"]) is None, "association exists; use historical lookup")
        return values


def _binding(owner):
    enrolled, installed, final, _, preparation = _sources(owner)
    p.require(final["policy_hash"] == owner.continuation["policy_hash"])
    return {"apiVersion": p.REQUEST, "sessionId": owner.session["id"],
        "setupSha256": p.sha256(owner.session_original), "continuationSha256": p.sha256(owner.continuation_original),
        "enrollmentSha256": p.sha256(p.enrollment.row_original(enrolled)), "installationSha256": p.sha256(p.ca.row_original(installed)),
        "canaryId": owner.continuation["canary_id"], "finalizationSha256": final["finalization_digest"],
        "publicationSha256": final["publication_sha256"], "policyHash": final["policy_hash"],
        "activationPolicySha256": p.sha256(final["activation_policy_original"].encode("ascii")),
        "credentialId": owner.continuation["credential_id"], "credentialVersion": owner.continuation["credential_version"],
        "enrollmentApprovalId": enrolled["approval_id"], "nativeApprovalId": preparation["approval_id"],
        "auditIds": p.audit_ids(enrolled, installed, final)}


def _options(owner, values):
    descriptors = webauthn._credential_descriptors_for_policy(owner.identity.user_id, setup.activation._authenticator_policy(owner.policy))
    p.require(type(descriptors) is list and 1 <= len(descriptors) <= 64)
    owner.credential = db.get_webauthn_credential(descriptors[0]["id"])
    p.require(type(owner.credential) is dict and owner.credential["user_id"] == owner.identity.user_id)
    owner.check()
    challenge = db.issue_policy_authority_webauthn_challenge(operation=p.RECORD, input_value=values,
        user_id=owner.identity.user_id, credential_id=owner.credential["credential_id"], deadline_ns=owner.deadline)
    payload = challenge["payload"]
    p.require(challenge["used_at"] is None and challenge["challenge_type"] == "policy_authority"
        and challenge["user_id"] == owner.identity.user_id and payload["credentialId"] == owner.credential["credential_id"]
        and payload["rpId"] == owner.policy["rpId"] and payload["origin"] in owner.policy["origins"])
    owner.check()
    return {"publicKey": {"challenge": challenge["challenge"], "rpId": payload["rpId"], "allowCredentials": [
        {"type": "public-key", "id": owner.credential["credential_id"]}], "timeout": 30000, "userVerification": "required"},
        "serverware": {"schema": p.OPTIONS, "operation": p.RECORD, "operationId": payload["operationId"],
            "challengeId": challenge["id"], "credentialRecordId": owner.credential["id"],
            "payloadDigest": p.sha256(owner.arguments_original.encode("ascii"))}}


def _record(owner, values, assertion):
    # Reuse actual assertion/current-key owner, not its unrelated operation.
    evidence = owner.assertion({setup.MFA_FIELD: setup.profile.OPTIONS_SCHEMA, "assertion": assertion})
    owner.check(); p.require(not owner.dispatched); owner.dispatched = True
    result = setup.custody_client.ControlPlaneCustodyClient._request_authority(owner.custody, operation=p.RECORD,
        input_value={"schema": "serverware.policyAuthorityControlledWriterInput/v1",
            "handler": authority_contract.operation_spec(p.RECORD)["handler"], "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
            "arguments": {**values, "authn_evidence": evidence}}, deadline_ns=owner.deadline)
    owner.check()
    p.require(type(result) is dict and set(result) == {"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "associationOriginal"}
        and result["ok"] is True and result["operation"] == p.RECORD and result["idempotentReplay"] is False
        and result["requestDigest"] == p.request_digest(p.RECORD, values))
    row = _row(owner.session["id"])
    p.require(row is not None and p.row_original(row).decode("ascii") == result["associationOriginal"]
        and row["request_digest"] == result["requestDigest"] and row["audit_event_digest"] == result["auditEventDigest"]
        and row["request_original"] == owner.arguments_original)
    owner.check(); return row


def on_request(request, raw):
    owner = None
    try:
        p.require(request.url.path in PATHS and type(raw) is bytes and 0 < len(raw) <= MAX_HTTP
            and request.headers.get("content-length") == str(len(raw)))
        value = p.enrollment.setup.document(raw, MAX_HTTP, exact=False)
        phase = request.url.path.rsplit("/", 1)[-1]
        fields = {"apiVersion", "sessionId"} if phase in {"draft", "lookup"} else {"apiVersion", "argumentsOriginal"}
        if phase == "record":
            fields.add("assertion")
        p.require(set(value) == fields and value["apiVersion"] == p.HTTP)
        owner = _Owner(request)
        if phase == "lookup":
            # Historical owner observation, not a currentness or renewal API.
            owner.session = setup._session(value["sessionId"])
            owner.session_original = p.enrollment.setup.row_original(owner.session)
            p.require(owner.session["owner_id"] == owner.identity.user_id)
            row = _row(owner.session["id"])
            p.require(row is None or row["owner_id"] == owner.identity.user_id)
            owner.check(); p.require(_row(owner.session["id"]) == row)
            response = {**COMMON, "status": "observation", "association": p.public(row),
                "associationOriginal": None if row is None else p.row_original(row).decode("ascii")}
        elif phase == "draft":
            owner.retain_native(value["sessionId"])
            p.require(_row(owner.session["id"]) is None)
            before = owner.last_epoch // 1000 * 1000
            values = p.arguments(p.RECORD, {"actor_id": owner.identity.user_id, "control_plane_configuration_digest": owner.configuration,
                "credential_policy": owner.policy, "request": {**_binding(owner), "issuedAtEpochNs": before,
                    "expiresAtEpochNs": min(owner.expires // 1000 * 1000, before + 30_000_000_000)}})
            original = p.canonical(values).decode("ascii"); r = values["request"]
            review = {name: r[name] for name in ("sessionId", "canaryId", "policyHash", "credentialId", "credentialVersion",
                "enrollmentSha256", "installationSha256", "finalizationSha256", "publicationSha256", "expiresAtEpochNs")}
            response = {**COMMON, "status": "draft", "argumentsOriginal": original, "argumentsSha256": p.sha256(original.encode("ascii")), "review": review}
        else:
            values = owner.arguments(value["argumentsOriginal"])
            response = {**COMMON, "status": "fresh-assertion-required", "options": _options(owner, values)} if phase == "options" else {
                **COMMON, "status": "canary-publication-associated", "association": p.public(_record(owner, values, value["assertion"]))}
        owner.check(); p.require(len(p.canonical(response)) <= MAX_RESPONSE)
        return JSONResponse(response, status_code=201 if phase == "record" else 200,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"})
    except Exception:
        return error(unknown=owner is not None and owner.dispatched)
