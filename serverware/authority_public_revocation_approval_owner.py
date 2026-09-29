"""Original-held measured verifier admission for approval-only SQL operations.

The dedicated public caller key is independently enrolled for these exact four
operations and the configured policy. The generic runtime API lacks this owner
and is refused. Its one-use handoff only enters the existing protected v3
approval writer; it never authorizes the final v5 revocation cascade.
"""
from __future__ import annotations

import base64
import hashlib

from serverware import authority_public_revocation_approval as profile
from serverware import authority_public_revocation_preparation as preparation
from serverware import authority_public_revocation_terminal as terminal
from serverware import authority_contract as authority


caller, public, clock = preparation.caller, profile.public, preparation.clock
SCHEMA = "serverware.signedPublicWebAuthnRevocationApprovalAuthorization/v1"
PAYLOAD_SCHEMA = "serverware.publicWebAuthnRevocationApprovalAuthorization/v1"
BODY_SCHEMA = "serverware.publicWebAuthnRevocationApprovalRequest/v1"
FIELDS = frozenset({"schema", "sourceRevision", "purpose", "configurationDigest", "authorizationEnrollmentDigest",
    "bodySha256", "issuedAtEpochNs", "expiresAtEpochNs"})
BODY_FIELDS = frozenset({"schema", "operation", "arguments", "actor", "assertion", "issuedAtEpochNs", "expiresAtEpochNs"})
MAX_BYTES = 64 * 1024


def _body(raw, work):
    value = caller.authorization.wire._decode_object(raw, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=8192, maximum_depth=16)
    public._object(value, BODY_FIELDS)
    public._require(value["schema"] == BODY_SCHEMA)
    arguments = profile.arguments(value["operation"], value["arguments"])
    public._object(value["actor"], public.ACTOR_FIELDS)
    actor = value["actor"]
    public._require(actor["userId"] == arguments["actor_id"] and actor["roles"] == arguments["actor_roles"])
    public._text(actor["authMethod"], 128)
    caller.shape._digest(actor["requestSha256"])
    public._require((value["assertion"] is not None) == (value["operation"] in profile.ASSERTION_OPERATIONS))
    if value["assertion"] is not None:
        public._object(value["assertion"], frozenset({"authorityChallengeId", "credentialRecordId", "assertion"}))
        public._text(value["assertion"]["authorityChallengeId"])
        public._text(value["assertion"]["credentialRecordId"])
        public._require(type(value["assertion"]["assertion"]) is dict)
    caller.authorization._interval(value, public.MAX_AGE_NS)
    caller.primitives._unchanged(raw, value, MAX_BYTES, work)
    return value


def sign_on_owner(owner, *, operation, arguments, assertion):
    from serverware import control_plane_public_revocation as http
    public._require(type(owner) is http._Operation)
    owner.check()
    values = profile.arguments(operation, arguments)
    caller.plan._same(values["mutation_policy"], owner.material.mutation_policy, owner.work,
        "public approval policy differs from its genuine cold owner")
    caller.plan._same((values["actor_id"], values["actor_roles"]),
        (owner.identity.user_id, sorted(owner.identity.roles)), owner.work,
        "public approval differs from present authenticated caller")
    issued, expires = owner.last_epoch, min(owner.window[3], owner.window[0] + owner.deadline - owner.window[2])
    ledger = caller.capture._SharedLedger(owner.work)
    raw = caller.authorization.capability._wire({"schema": BODY_SCHEMA, "operation": operation,
        "arguments": values, "actor": owner.actor, "assertion": assertion,
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}, ledger, MAX_BYTES, 8192)
    _body(raw, owner.work)
    owner.work.charge(hashes=1, input_bytes=len(raw))
    payload = {"schema": PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "purpose": "authorize-public-revocation-approval", "configurationDigest": owner.configuration["configuration_digest"],
        "authorizationEnrollmentDigest": owner.enrollment.enrollment_digest,
        "bodySha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    encoded = caller.authorization.capability._wire(payload, ledger, MAX_BYTES, 8192)
    message = caller.plan._frame(SCHEMA, (encoded,), owner.work).encode("ascii")
    signature = caller.production._sign_and_verify(owner.owner._revocation_key,
        owner.enrollment.caller_public_key, message, owner.work)
    owner.work.charge(input_bytes=64 + 88 + 86)
    authorization = caller.authorization.capability._wire({"schema": SCHEMA, "payload": payload,
        "signatureBase64Url": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")}, ledger, MAX_BYTES, 8192)
    owner.check()
    return (owner.material.current_root_enrollment_bytes, owner.material.grant_enrollment_bytes,
        owner.material.authorization_enrollment_bytes, authorization, raw)


def _verify(process, raw, window, bound, work):
    owner = terminal.require_started(process)
    owner.require_role("verifier")
    owner.check(work=work)
    owner.require_originals(raw[:3], work=work)
    _configuration, _generation, pins = preparation._actual_configuration(process, work)
    enrolled = caller._admit_enrollment_on_work(authorization_enrollment_bytes=raw[2],
        current_root_enrollment_bytes=raw[0], grant_enrollment_bytes=raw[1], root_public_key=owner.root,
        configuration_digest=owner.configuration_digest, planner_public_key=pins[0], evidence_public_key=pins[1], work=work)
    envelope = caller.authorization.wire._decode_object(raw[3], work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=8192, maximum_depth=16)
    public._object(envelope, frozenset({"schema", "payload", "signatureBase64Url"}))
    public._require(envelope["schema"] == SCHEMA)
    payload = envelope["payload"]
    public._object(payload, FIELDS)
    public._require(payload["schema"] == PAYLOAD_SCHEMA
        and payload["sourceRevision"] == authority.SOURCE_REVISION
        and payload["purpose"] == "authorize-public-revocation-approval"
        and payload["configurationDigest"] == owner.configuration_digest
        and payload["authorizationEnrollmentDigest"] == enrolled.enrollment_digest)
    caller.shape._digest(payload["bodySha256"])
    caller.authorization._interval(payload, min(public.MAX_AGE_NS, enrolled.payload["maximumAgeNs"]))
    caller.authorization._verify_signature(envelope, SCHEMA, enrolled.caller_public_key, MAX_BYTES, work)
    caller.primitives._unchanged(raw[3], envelope, MAX_BYTES, work)
    work.charge(hashes=1, input_bytes=len(raw[4]))
    caller.plan._same(payload["bodySha256"], "sha256:" + hashlib.sha256(raw[4]).hexdigest(), work,
        "public approval changed its actual caller original")
    body = _body(raw[4], work)
    values = body["arguments"]
    caller.plan._same(values["mutation_policy"], enrolled.payload["mutationPolicy"], work,
        "public approval cannot choose another enrolled MFA/two-person policy")
    public._require(body["operation"] in enrolled.payload["approvalOperations"]
        and (body["issuedAtEpochNs"], body["expiresAtEpochNs"])
            == (payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]))
    now, _mono = preparation._current(window, bound, work)
    public._require(payload["issuedAtEpochNs"] <= now < payload["expiresAtEpochNs"])
    owner.check(work=work)
    return body, min(bound, window[2] + payload["expiresAtEpochNs"] - window[0])


class _ApprovalExecution:
    def __init__(self):
        raise RuntimeError("public approval execution requires actual verified originals")

    def consume(self, process, operation, runtime_input, deadline):
        public._require(process is self.process and not self.consumed and deadline == self.bound)
        body, bound = _verify(process, self.raw, self.window, self.bound, self.work)
        public._require(operation == body["operation"] and bound == self.bound and runtime_input == self.runtime_input)
        self.consumed = True


def execute_on_process(process, *, raw, live_window, transport_deadline_ns, work):
    from serverware import authority_service as service
    body, bound = _verify(process, raw, live_window, transport_deadline_ns, work)
    reference = body["assertion"]
    runtime = ({"input": body["arguments"], "webauthnAuthorization": {
        "assertion": reference["assertion"], "challenge_id": reference["authorityChallengeId"],
        "credential_record_id": reference["credentialRecordId"]}} if reference is not None else {
        "schema": "serverware.policyAuthorityControlledWriterInput/v1", "handler": profile.handler(body["operation"]),
        "operationManifestDigest": authority.OPERATION_MANIFEST_DIGEST, "arguments": body["arguments"]})
    held = object.__new__(_ApprovalExecution)
    held.process, held.raw, held.window, held.bound, held.work = process, raw, live_window, bound, work
    held.runtime_input, held.consumed = runtime, False
    result = service.AuthorityProcess._execute_v9_operation(process, operation=body["operation"],
        handler_name=profile.handler(body["operation"]), runtime_input=runtime,
        deadline_monotonic_ns=bound, _public_revocation=held)
    terminal.require_started(process).check(work=work)
    preparation._current(live_window, bound, work)
    return (caller.authorization.capability._wire(result, caller.capture._SharedLedger(work),
        4 * 1024 * 1024, 65536),)
