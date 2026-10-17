"""Purpose-fixed candidate generation ceremony and one retained native contact.

The new HTTP label never invokes legacy claim/stage/audit DML. Exact known
publication lookup is read-only; explicit retained-receipt recovery never retries
an uncertain native publication or renews its original claim.
"""
import os
import threading
import time

from fastapi import Request
from catchplate import authority_contract, auth, db, webauthn
from catchplate import authority_policy_candidate as profile
from catchplate import control_plane_custody_startup as startup
from catchplate import control_plane_custody_client as custody_client
from catchplate import control_plane_publication_authorization as publication
from catchplate.control_plane_approval_verification import _request_pin, _epoch_ns

PREFIX = "/api/policy/authority/candidates/controlled-generation"
PATHS = frozenset(PREFIX + suffix for suffix in ("/draft", "/options", "/publish", "/lookup", "/recover"))
MAX_REQUEST = profile.MAX_ARGUMENT_BYTES + 32768
MFA_FIELD = "policyCandidateProfile"


def _identity(request):
    profile.require(type(request) is Request and request.method == "POST" and request.url.path in PATHS
        and not request.scope.get("query_string", b"") and request.headers.get("content-type") == "application/json")
    identity = auth.require_admin(request, x_catchplate_admin_token=request.headers.get("X-Catchplate-Admin-Token"))
    auth.validate_csrf_request(request)
    profile.require(identity.user_id.startswith("oidc:") and "policy_publisher" in identity.roles)
    return identity


def _claim(request_id):
    profile.scalar.identifier(request_id)
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM policy_shadow_generation_claims WHERE request_id = ?", (request_id,)).fetchone()
    if row is None:
        return None
    value = dict(row); profile.row_original(value)
    return value


def _verification_inputs(record):
    pairs = (("generation_publication", record["signing_key_id"]),
        ("generation_runtime_attestation_verification", record["runtime_attestation_verifier_signing_key_id"]))
    result = {}
    with db.connect() as connection:
        revocation = connection.execute("SELECT COALESCE(MAX(revocation_sequence), 0) AS sequence FROM policy_authority_trusted_key_revocations").fetchone()
        for kind, signer in pairs:
            head = connection.execute("SELECT * FROM policy_authority_trusted_key_heads WHERE evidence_kind = ?", (kind,)).fetchone()
            profile.require(head is not None and head["head_signing_key_id"] == signer)
            key = connection.execute("SELECT * FROM policy_authority_trusted_keys WHERE evidence_kind = ? AND key_revision = ?",
                (kind, head["head_key_revision"])).fetchone()
            profile.require(key is not None)
            result[kind] = {"key": dict(key), "head": dict(head), "revocationSequence": revocation["sequence"]}
    return result


class _Owner:
    def __init__(self, request):
        self.request, self.scope, self.pin = request, request.scope, _request_pin(request)
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.identity, self.policy = _identity(request), publication._policy()
        self.policy_original = profile.canonical(self.policy)
        self.custody = startup.require_started()
        profile.require(self.custody is not None, "candidate intake requires real cold controlled-writer custody")
        self.binding = custody_client._snapshot(self.custody)
        self.configuration = self.binding.configuration_digest
        self.mono, self.epoch = time.monotonic_ns(), time.time_ns()
        self.deadline, self.expires = self.mono + 30_000_000_000, self.epoch + 30_000_000_000
        self.credential, self.claim_original = None, None
        self.operations, self.contacted = set(), False
        self.check()

    def clip(self, expires):
        profile.epoch(expires)
        self.expires = min(self.expires, expires)
        self.deadline = min(self.deadline, self.mono + self.expires - self.epoch)
        self.check()

    def check(self):
        mono, epoch = time.monotonic_ns(), time.time_ns()
        profile.require((os.getpid(), threading.get_ident()) == (self.pid, self.thread)
            and self.mono <= mono < self.deadline and self.epoch <= epoch < self.expires
            and self.request.scope is self.scope and _request_pin(self.request) == self.pin
            and _identity(self.request) == self.identity and profile.canonical(publication._policy()) == self.policy_original
            and startup.require_started() is self.custody and custody_client._snapshot(self.custody) is self.binding
            and self.binding.configuration_digest == self.configuration)
        custody_client._receipt_now(self.binding)
        if self.credential is not None:
            row = db.get_webauthn_credential_by_record_id(self.credential["id"])
            profile.require(type(row) is dict and row.get("revoked_at") is None and all(row[field] == self.credential[field]
                for field in ("id", "credential_id", "user_id", "public_key_cose")))
            actual = webauthn._allowed_authenticator(row, publication._authenticator_policy(self.policy))
            profile.require(actual["currently_trusted"] is True and actual["effective_authenticator_class"] in {"hardware", "yubikey"})
        end_mono, end_epoch = time.monotonic_ns(), time.time_ns()
        profile.require(mono <= end_mono < self.deadline and epoch <= end_epoch < self.expires)
        self.mono, self.epoch = end_mono, end_epoch

    def arguments(self, original):
        profile.require(type(original) is str)
        value = profile.scalar.document(original.encode("ascii"), profile.MAX_ARGUMENT_BYTES)
        profile.require(profile.canonical(value).decode("ascii") == original)
        value = profile.arguments(profile.OP_CLAIM, value)
        profile.require(value["actor_id"] == self.identity.user_id and value["control_plane_configuration_digest"] == self.configuration
            and value["credential_policy"] == self.policy and value["request"]["issuedAtEpochNs"] <= self.epoch)
        self.clip(value["request"]["expiresAtEpochNs"])
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

    def dispatch(self, operation, arguments, assertion=None):
        self.check(); profile.arguments(operation, arguments)
        profile.require(operation not in self.operations)
        self.operations.add(operation)
        original = profile.canonical(arguments)
        result = custody_client.ControlPlaneCustodyClient._request_authority(self.custody, operation=operation,
            input_value={"schema": "catchplate.policyAuthorityControlledWriterInput/v1",
                "handler": authority_contract.operation_spec(operation)["handler"],
                "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
                "arguments": {**arguments, **({"authn_evidence": assertion} if assertion is not None else {})}}, deadline_ns=self.deadline)
        self.check()
        result_field = "claimOriginal" if operation == profile.OP_CLAIM else "publication"
        profile.require(type(result) is dict and set(result) == {"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", result_field}
            and result["ok"] is True and result["operation"] == operation and result["idempotentReplay"] is False
            and result["requestDigest"] == profile.request_digest(operation, arguments) and profile.canonical(arguments) == original)
        profile.digest(result["auditEventDigest"])
        if operation == profile.OP_CLAIM:
            request = profile.management_original(arguments["request"]["managementRequestOriginal"])
            row = _claim(request["requestId"])
            profile.require(row is not None and profile.row_original(row).decode("ascii") == result["claimOriginal"]
                and row["request_digest"] == result["requestDigest"] and row["publication_envelope_digest"] is None)
            self.claim_original = result["claimOriginal"]
        return result

    def contact(self, arguments):
        from catchplate import app
        self.check()
        request = profile.management_original(arguments["request"]["managementRequestOriginal"])
        row = _claim(request["requestId"])
        profile.require(self.claim_original is not None and row is not None
            and profile.row_original(row).decode("ascii") == self.claim_original and not self.contacted
            and row["payload_digest"] == profile.sha256(arguments["request"]["managementRequestOriginal"].encode("ascii")))
        self.check(); self.contacted = True
        # One call only, fixed source-selected native route; the HTTP transport
        # receives this same absolute deadline, including all earlier custody.
        response = app._post_policy_shadow_generation(body=arguments["request"]["managementRequestOriginal"].encode("ascii"),
            deadline_ns=self.deadline)
        self.check()
        return app._policy_shadow_publication_stage_record(response,
            management_request_json=arguments["request"]["managementRequestOriginal"], actor_id=self.identity.user_id)


def _draft(owner, value):
    from catchplate import app
    profile.require(set(value) == {"apiVersion", "handoff"} and value["apiVersion"] == profile.HTTP_SCHEMA)
    payload = app.PolicyAuthorityCandidateHandoffRequest.model_validate(value["handoff"])
    raw = payload.model_dump(by_alias=True)
    retained = app._exact_policy_candidate_handoff_context(raw)
    candidate = app.compile_policy_bundle(payload.candidate_policy_bundle, verify_signature=True, validate_schema=True)
    app._assert_policy_candidate_credential_bindings(candidate)
    artifact, assignment, load, native = (retained[name] for name in ("artifact", "assignment", "load_receipt", "generation_trust"))
    profile.require(candidate.hash == artifact["policy_hash"] and profile.sha256(profile.canonical(payload.candidate_policy_bundle))
        == artifact["policy_bundle_digest"] == assignment["policy_bundle_digest"] and native["attestation_mode"] == "aws-nitro-enclave")
    request = {"apiVersion": "catchplate.policyShadowGenerationInstall/v2", "activePolicyBundle": retained["active"].raw,
        "candidatePolicyBundle": payload.candidate_policy_bundle, "assignment": db.loads(assignment["assignment_envelope_json"], None),
        "loadReceipt": db.loads(load["load_receipt_envelope_json"], None), "requestId": payload.request_id,
        "runtimeAttestation": db.loads(native["runtime_attestation_json"], None)}
    identities = db.derive_policy_shadow_generation_request_identities(request_id=payload.request_id, actor_id=owner.identity.user_id,
        candidate_id=payload.candidate_id, canary_id=payload.canary_id, instance_id=payload.instance_id, boot_id=payload.boot_id,
        assignment_envelope_digest=payload.assignment_envelope_digest, load_receipt_envelope_digest=payload.load_receipt_envelope_digest,
        active_policy_hash=retained["active"].hash, active_policy_bundle_digest=profile.sha256(profile.canonical(retained["active"].raw)),
        candidate_policy_hash=candidate.hash, candidate_policy_bundle_digest=artifact["policy_bundle_digest"],
        runtime_attestation_chain_digest=native["runtime_attestation_chain_digest"], request_identity_digest=profile.sha256(profile.canonical(request)))
    request.update(replayId=identities["replay_id"], managementHandoffId=identities["management_handoff_id"])
    bound = {name: raw[name] for name in profile.CONTEXT_FIELDS - {"memberOrdinal", "shadowKeySha256"}}
    bound.update(memberOrdinal=load["member_ordinal"], shadowKeySha256=native["signing_key_spki_digest"])
    now = time.time_ns() // 1000 * 1000
    expires = min(owner.expires // 1000 * 1000, now + 30_000_000_000, assignment["expires_at_epoch_ns"] // 1000 * 1000)
    values = profile.arguments(profile.OP_CLAIM, {"actor_id": owner.identity.user_id, "control_plane_configuration_digest": owner.configuration,
        "request": {"context": bound, "managementRequestOriginal": profile.canonical(request).decode("ascii"),
            "issuedAtEpochNs": now, "expiresAtEpochNs": expires}, "credential_policy": owner.policy})
    profile.require(_claim(payload.request_id) is None, "request is already claimed; use read-only lookup")
    owner.check()
    return {"apiVersion": profile.HTTP_SCHEMA, "okForAction": False, "argumentsOriginal": profile.canonical(values).decode("ascii")}


def on_request(request, raw):
    profile.require(type(raw) is bytes and 0 < len(raw) <= MAX_REQUEST
        and request.headers.get("content-length") == str(len(raw)))
    value = profile.scalar.document(raw, MAX_REQUEST)
    profile.require(type(value) is dict)
    owner = _Owner(request)
    path = request.url.path
    if path == PREFIX + "/draft":
        return _draft(owner, value)
    if path == PREFIX + "/recover":
        from catchplate.control_plane_policy_candidate_recovery import recover
        return recover(owner, value)
    if path == PREFIX + "/lookup":
        profile.require(set(value) == {"apiVersion", "requestId"} and value["apiVersion"] == profile.HTTP_SCHEMA)
        row = _claim(value["requestId"])
        profile.require(row is None or row["actor_id"] == owner.identity.user_id)
        publication_row = None
        if row is not None and row["publication_envelope_digest"] is not None:
            with db.connect() as connection:
                stored = connection.execute("SELECT * FROM policy_shadow_generation_publications WHERE generation_publication_envelope_digest = ?",
                    (row["publication_envelope_digest"],)).fetchone()
            profile.require(stored is not None and stored["request_id"] == row["request_id"]
                and stored["management_request_json"] == row["management_request_json"])
            publication_row = dict(stored)
        owner.check()
        return {"apiVersion": "catchplate.policyCandidateGenerationObservation/v1", "okForAction": False,
            "automaticRetryAllowed": False, "claimOriginal": None if row is None else profile.row_original(row).decode("ascii"),
            "publicationOriginal": None if publication_row is None else profile.canonical(publication_row).decode("ascii")}
    profile.require(path in {PREFIX + "/options", PREFIX + "/publish"} and value.get("apiVersion") == profile.OPTIONS_SCHEMA
        and set(value) == ({"apiVersion", "argumentsOriginal"} if path.endswith("/options") else {"apiVersion", "argumentsOriginal", "mfa"}))
    arguments = owner.arguments(value["argumentsOriginal"])
    if path.endswith("/options"):
        descriptors = webauthn._credential_descriptors_for_policy(owner.identity.user_id, publication._authenticator_policy(owner.policy))
        profile.require(type(descriptors) is list and 1 <= len(descriptors) <= 64)
        owner.credential = db.get_webauthn_credential(descriptors[0]["id"])
        profile.require(type(owner.credential) is dict and owner.credential["user_id"] == owner.identity.user_id)
        owner.check()
        challenge = db.issue_policy_authority_webauthn_challenge(operation=profile.OP_CLAIM, input_value=arguments,
            user_id=owner.identity.user_id, credential_id=owner.credential["credential_id"], deadline_ns=owner.deadline)
        owner.check(); payload = challenge["payload"]
        profile.require(challenge["used_at"] is None and challenge["user_id"] == owner.identity.user_id
            and payload["credentialId"] == owner.credential["credential_id"] and payload["rpId"] == owner.policy["rpId"]
            and payload["origin"] in owner.policy["origins"])
        return {"publicKey": {"challenge": challenge["challenge"], "rpId": payload["rpId"], "allowCredentials": [
                {"type": "public-key", "id": owner.credential["credential_id"]}], "timeout": 30000, "userVerification": "required"},
            "catchplate": {"schema": profile.OPTIONS_SCHEMA, "operation": profile.OP_CLAIM, "operationId": payload["operationId"],
                "challengeId": challenge["id"], "credentialRecordId": owner.credential["id"],
                "payloadDigest": profile.sha256(value["argumentsOriginal"].encode("ascii")), "expiresAt": challenge["expires_at"]}}
    assertion = owner.assertion(value["mfa"])
    owner.dispatch(profile.OP_CLAIM, arguments, assertion)
    record = owner.contact(arguments)
    inputs = {"actor_id": owner.identity.user_id, "control_plane_configuration_digest": owner.configuration,
        "request": {"claimOriginal": owner.claim_original, "record": record, "verificationInputs": _verification_inputs(record)}}
    result = owner.dispatch(profile.OP_PUBLISH, inputs)
    row = _claim(record["request_id"])
    profile.require(row is not None and row["publication_envelope_digest"] == result["publication"]["generation_publication_envelope_digest"])
    with db.connect() as connection:
        stored = connection.execute("SELECT * FROM policy_shadow_generation_publications WHERE generation_publication_envelope_digest = ?",
            (row["publication_envelope_digest"],)).fetchone()
    profile.require(stored is not None and dict(stored) == result["publication"])
    owner.check()
    from catchplate import app
    return {"apiVersion": "catchplate.policyCandidateGenerationResult/v1", "automaticRetryAllowed": False,
        "requestId": record["request_id"], "publication": app._policy_shadow_publication_result(result["publication"], recovered=False)}
