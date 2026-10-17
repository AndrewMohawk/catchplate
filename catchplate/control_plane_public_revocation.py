"""Actual request-held public passkey-revocation owner and source-fixed preparation.

Caller authentication is freshly repeated under the same original HTTP scope.
Only the cold enrollment owns the dedicated signing key and custody journal.
Browser values are bounded selectors, raw assertions and explicit human intent;
they supply no trust root, database endpoint, policy or successful verdict.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import threading
import time

from fastapi import HTTPException, Request

from catchplate import auth, db, webauthn
from catchplate import control_plane_enrollment_startup as startup
from catchplate import control_plane_custody_client as custody
from catchplate import authority_public_revocation_request as request_wire
from catchplate import authority_public_revocation_preparation as preparation
from catchplate import authority_public_revocation_transport as transport
from catchplate import authority_revocation_verifier as configured
from catchplate.control_plane_approval_verification import _request_pin, _epoch_ns
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


caller, public, clock = preparation.caller, preparation.aggregate, preparation.clock
OPTIONS_SCHEMA = "catchplate.publicWebAuthnRevocationOptionsRequest/v1"
EXECUTE_SCHEMA = "catchplate.publicWebAuthnRevocationExecuteRequest/v1"
RECOVERY_SCHEMA = "catchplate.publicWebAuthnRevocationRecoveryRequest/v1"
MAX_HTTP_BYTES = 64 * 1024
ZERO = "sha256:" + "0" * 64


def body_original(request):
    # FastAPI has already parsed the explicit closed Body model and retained
    # these exact request bytes. Never reconstruct the signed HTTP original
    # from a Pydantic object or accept a caller-provided request digest.
    value = getattr(request, "_body", None)
    if type(request) is not Request or type(value) is not bytes or not 2 <= len(value) <= MAX_HTTP_BYTES:
        raise HTTPException(status_code=413, detail="public revocation requires its bounded actual HTTP body")
    return value


def selected():
    owner = startup.require_started()
    return owner is not None and owner.public_revocation_enabled


def policy():
    from catchplate import app
    value = {"mfaRequired": app._control_plane_mutation_webauthn_required(public.OPERATION),
        "twoPersonRequired": app._control_plane_two_person_required(public.OPERATION),
        "credentialPolicy": app._control_plane_mutation_authn_policy()}
    public.policy_shape(value)
    return value


def _identity(request):
    if type(request) is not Request or request.method != "POST" or request.url.query:
        raise HTTPException(status_code=400, detail="public revocation requires its exact POST original")
    fresh = Request(request.scope)
    identity = auth.require_admin(fresh, x_catchplate_admin_token=fresh.headers.get("X-Catchplate-Admin-Token"))
    auth.validate_csrf_request(fresh)
    if type(identity) is not auth.AdminIdentity or not identity.has_any_role({"admin", "approver"}):
        raise HTTPException(status_code=403, detail="public revocation requires current self/admin rights")
    return identity


def _http_digest(pin, original):
    # Only the digest leaves this request owner. Authentication headers and
    # session cookies are not copied into an outcome or durable request record.
    digest = hashlib.sha256()
    digest.update(b"catchplate.publicWebAuthnRevocationHttpOriginal/v1\x00")
    for value in (repr(pin).encode("utf-8"), original):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return "sha256:" + digest.hexdigest()


class _Operation:
    def __init__(self, request, original, *, schema, fields):
        if (type(request) is not Request or type(original) is not bytes
                or not 2 <= len(original) <= MAX_HTTP_BYTES or getattr(request, "_body", None) is not original):
            raise HTTPException(status_code=413, detail="public revocation request exceeds its bound")
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self._phase = "admitting"
        self.request, self.scope, self.pin, self.original = request, request.scope, _request_pin(request), original
        self.identity, self.selected_policy = _identity(request), policy()
        self.policy_original = public.core.canonical_bytes(self.selected_policy)
        self.work = _ValidationWork(QueryReadValidationLimits())
        self.window = clock._open_on_work(deadline_epoch_ns=time.time_ns() + public.MAX_AGE_NS,
            maximum_lifetime_ns=public.MAX_AGE_NS, maximum_clock_skew_ns=0, work=self.work)
        self.last_epoch, self.last_mono, self.deadline = self.window[0], self.window[2], self.window[4]
        self.owner = startup.require_started()
        if type(self.owner) is not startup._EnrollmentOwner or not self.owner.public_revocation_enabled:
            raise HTTPException(status_code=409, detail="public revocation is not independently cold admitted")
        self.client, self.binding = self.owner._custody, self.owner._binding
        self.material = self.owner._material.public_revocation
        self.configuration = dict(payload=self.owner._material.configuration_payload,
            configuration_digest=self.owner._material.configuration_digest,
            generation=self.owner._material.generation,
            runtime_role_identities=self.owner._material.runtime_role_identities,
            root_public_key=self.binding.runtime_root_public_key)
        self.deadline = min(self.deadline, self.window[2] + self.binding.attestation_interval[1] - self.window[0])
        self.body = caller.authorization.wire._decode_object(original, work=self.work,
            maximum_bytes=MAX_HTTP_BYTES, maximum_nodes=8192, maximum_depth=16)
        public._object(self.body, frozenset(fields))
        public._require(self.body["apiVersion"] == schema)
        self.body_original = public.core.canonical_bytes(self.body)
        verifier = configured._verifier_from_configuration_on_work(
            payload=self.configuration["payload"], configuration_digest=self.configuration["configuration_digest"],
            generation=self.configuration["generation"],
            runtime_role_identities=self.configuration["runtime_role_identities"], work=self.work)
        pins = configured.RevocationPlanVerifier._snapshot_configuration(verifier)
        self.enrollment = caller._admit_enrollment_on_work(
            authorization_enrollment_bytes=self.material.authorization_enrollment_bytes,
            current_root_enrollment_bytes=self.material.current_root_enrollment_bytes,
            grant_enrollment_bytes=self.material.grant_enrollment_bytes,
            root_public_key=self.configuration["root_public_key"], configuration_digest=self.configuration["configuration_digest"],
            planner_public_key=pins[0], evidence_public_key=pins[1], work=self.work)
        self.pins = pins
        self.actor = {"userId": self.identity.user_id, "roles": sorted(self.identity.roles),
            "authMethod": self.identity.auth_method, "requestSha256": _http_digest(self.pin, original)}
        self.check()

    def __copy__(self):
        raise RuntimeError("public revocation request owner cannot be copied")

    def __deepcopy__(self, _memo):
        raise RuntimeError("public revocation request owner cannot be copied")

    def check(self):
        if (os.getpid() != self.pid or threading.get_ident() != self.thread
                or self.request.scope is not self.scope or _request_pin(self.request) != self.pin
                or getattr(self.request, "_body", None) is not self.original
                or self._phase != "terminal" and _identity(self.request) != self.identity
                or public.core.canonical_bytes(policy()) != self.policy_original
                or public.core.canonical_bytes(self.body) != self.body_original
                or startup.require_started() is not self.owner
                or self.owner._material.public_revocation is not self.material
                or custody._snapshot(self.client) is not self.binding):
            raise RuntimeError("public revocation actual request or cold owner changed")
        startup._live(self.owner, work=self.work)
        caller.plan._same(self.selected_policy, self.material.mutation_policy, self.work,
            "public revocation configured policy differs from independent enrollment")
        now, mono = preparation._current(self.window, self.deadline, self.work)
        if now < self.last_epoch or mono < self.last_mono:
            raise RuntimeError("public revocation original clock reversed")
        self.last_epoch, self.last_mono = now, mono

    def narrow(self, expires):
        caller.shape._integer(expires, 2**63 - 1, minimum=1)
        self.deadline = min(self.deadline, self.window[2] + expires - self.window[0])
        self.check()

    def append(self, kind, parent, originals):
        self.check()
        result = custody.ControlPlaneCustodyClient.append_public_revocation(self.client, kind, parent, originals)
        self.check()
        return result

    def exchange(self, kind, raw):
        self.check()
        if self._phase == "terminal" and kind != "complete":
            raise RuntimeError("public terminal continuation cannot authorize another effect")
        if kind == "execute":
            if self._phase != "executing":
                raise RuntimeError("public SQL execution lacks its original one-use request transition")
            # Consume before contact. Post-effect response publication retains
            # the admitted HTTP original even when this very cascade revokes
            # its session. It cannot admit another effect or a new read request.
            self._phase = "terminal"
        result = transport.exchange(self.binding.relay_path, kind=kind,
            configuration_digest=self.binding.configuration_digest,
            deadline_epoch_ns=min(self.window[3], self.window[0] + self.deadline - self.window[2]),
            raw=raw, deadline_ns=self.deadline,
            expected_peer_uid=self.binding.relay_uid, expected_peer_gid=self.binding.relay_gid)
        self.check()
        return result

    def begin_execution(self):
        self.check()
        if self._phase != "admitting":
            raise RuntimeError("public request cannot enter execution twice")
        self._phase = "executing"

    def sign_request(self, original, typed):
        self.check()
        enrolled = self.enrollment
        payload = {name: enrolled.payload[name] for name in caller._SCOPE_FIELDS}
        payload.update(schema=caller.REQUEST_PAYLOAD_SCHEMA, sourceRevision=request_wire.authority.SOURCE_REVISION,
            purpose=caller.PURPOSE, operation=public.OPERATION,
            authorizationEnrollmentDigest=enrolled.enrollment_digest,
            callerMeasurementDigest=enrolled.payload["callerKey"]["measurementDigest"],
            requestDigest=typed["requestDigest"], requestOriginalDigest=request_wire.original_digest(original, work=self.work),
            operationId=typed["operationId"], authorizationId=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("="),
            issuedAtEpochNs=self.last_epoch,
            expiresAtEpochNs=min(self.window[3], self.last_epoch + enrolled.payload["maximumAgeNs"],
                self.window[0] + self.deadline - self.window[2]))
        signed = caller._sign_request_on_work(payload=payload, private_key=self.owner._revocation_key,
            public_key=enrolled.caller_public_key, work=self.work)
        self.check()
        return (self.material.current_root_enrollment_bytes, self.material.grant_enrollment_bytes,
            self.material.authorization_enrollment_bytes, signed, original)


def _target(owner, record_id):
    public._text(record_id)
    target = db.get_webauthn_credential_by_record_id(record_id, include_revoked=True)
    if target is None:
        raise HTTPException(status_code=404, detail="WebAuthn credential not found")
    if target.get("revoked_at") is not None:
        raise HTTPException(status_code=409, detail="WebAuthn credential is already revoked; use retained recovery")
    if target["user_id"] != owner.identity.user_id and "admin" not in owner.identity.roles:
        raise HTTPException(status_code=403, detail="only an admin can revoke another operator's credential")
    owner.check()
    return target


def _approval(owner, identifier, record_id, digest, mutation):
    if not owner.selected_policy["twoPersonRequired"]:
        public._require(identifier is None)
        return None
    from catchplate import control_plane_public_revocation_approval as approval_owner
    return approval_owner.require_approved(owner, identifier, record_id, digest, mutation)


def _arguments(owner, target, reason):
    public._require(type(reason) is str and 1 <= len(reason) <= 500)
    mutation = {"credential_record_id": target["id"], "credential_id_sha256": "sha256:" + hashlib.sha256(
        target["credential_id"].encode("utf-8")).hexdigest(), "credential_user_id": target["user_id"],
        "label": target["label"], "attestation_root_sha256": target.get("attestation_root_sha256"), "reason": reason}
    digest = public.original_sha256(mutation, work=owner.work)
    arguments = {"record_id": target["id"], "actor_id": owner.identity.user_id, "reason": reason,
        "source": "explicit", "audit_event": {**mutation, "payload_digest": digest}}
    # These are only bounded address hints. The real planner proves every
    # complete predicate and exact current row before any cascade is admitted.
    with db.connect() as connection:
        now = db._metadata_utcnow(connection).isoformat()
        selections = (
            ("oidc_session_ids", "SELECT id FROM oidc_browser_sessions WHERE bound_webauthn_credential_id = ? AND status IN ('pending_webauthn', 'active') ORDER BY id LIMIT 33", (target["id"],)),
            ("approval_grant_ids", "SELECT id FROM approval_grants WHERE approver_webauthn_credential_id = ? AND state = 'active' ORDER BY id LIMIT 33", (target["id"],)),
            ("control_plane_approval_ids", "SELECT id FROM control_plane_approvals WHERE approver_webauthn_credential_id = ? AND status = 'approved' ORDER BY id LIMIT 33", (target["id"],)),
            ("registration_challenge_ids", "SELECT id FROM webauthn_challenges WHERE challenge_type = 'registration' AND used_at IS NULL AND expires_at > ? ORDER BY id LIMIT 33", (now,)),
        )
        for name, query, parameters in selections:
            rows = connection.execute(query, parameters).fetchall()
            public._require(len(rows) <= 32, "public revocation complete cascade exceeds this signed profile's capacity")
            arguments[name] = [row["id"] for row in rows]
    owner.check()
    return arguments, mutation, digest


def options_on_request(request, record_id, original):
    owner = _Operation(request, original, schema=OPTIONS_SCHEMA,
        fields={"apiVersion", "reason", "approvalId", "credentialRecordId"})
    target = _target(owner, record_id)
    arguments, mutation, digest = _arguments(owner, target, owner.body["reason"])
    approval = _approval(owner, owner.body["approvalId"], record_id, digest, mutation)
    typed = request_wire.typed_request(arguments, work=owner.work)
    options = {"schema": request_wire.OPTIONS_SCHEMA, "request": typed, "actorId": owner.identity.user_id,
        "policy": owner.selected_policy, "payloadDigest": digest, "approval": approval,
        "issuedAtEpochNs": owner.window[0], "expiresAtEpochNs": min(owner.window[3],
            owner.window[0] + owner.deadline - owner.window[2])}
    encoded = request_wire.encode(options, options=True, work=owner.work)
    locator = owner.append("options", ZERO, (encoded,))
    challenge = None
    credential_id = owner.body["credentialRecordId"]
    if owner.selected_policy["mfaRequired"]:
        public._text(credential_id)
        credential = db.get_webauthn_credential_by_record_id(credential_id)
        public._require(type(credential) is dict and credential.get("user_id") == owner.identity.user_id
            and credential.get("revoked_at") is None)
        descriptors = webauthn._credential_descriptors_for_policy(owner.identity.user_id,
            owner.selected_policy["credentialPolicy"])
        public._require(any(item.get("id") == credential["credential_id"] for item in descriptors))
        owner.check()
        row = db.issue_policy_authority_webauthn_challenge(operation=public.OPERATION,
            input_value=arguments, user_id=owner.identity.user_id,
            credential_id=credential["credential_id"], deadline_ns=owner.deadline)
        owner.check()
        bound = row["payload"]
        public._require(row["user_id"] == owner.identity.user_id and row["used_at"] is None
            and row["challenge_type"] == "policy_authority" and bound["operationId"] == typed["operationId"]
            and bound["credentialId"] == credential["credential_id"]
            and bound["rpId"] == webauthn.WEBAUTHN_RP_ID and bound["origin"] == webauthn.WEBAUTHN_ORIGIN)
        owner.narrow(min(_epoch_ns(row["expires_at"]), bound["expiresAtEpochNs"]))
        challenge = {"authorityChallengeId": row["id"], "credentialRecordId": credential["id"],
            "publicKey": {"challenge": row["challenge"], "rpId": bound["rpId"],
                "allowCredentials": [{"type": "public-key", "id": credential["credential_id"]}],
                "timeout": max(1, (owner.deadline - time.monotonic_ns()) // 1_000_000),
                "userVerification": "required"}}
    else:
        public._require(credential_id is None)
    owner.check()
    return {"apiVersion": "catchplate.publicWebAuthnRevocationOptionsResponse/v1", "localDigest": locator,
        "recordId": record_id, "payloadDigest": digest, "expiresAtEpochNs": options["expiresAtEpochNs"],
        "mfaRequired": owner.selected_policy["mfaRequired"], "challenge": challenge,
        "revocationExecuted": False, "automaticRetryAllowed": False}
