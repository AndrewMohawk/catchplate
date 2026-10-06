"""Protected static onboarding from public originals, never portal plaintext.

The optional cold selection owns public signed policy originals only. Native
intake seals the secret; actual authority roles independently verify custody,
hardware, current roles and any distinct-person approval. A lost dispatch or
readback is uncertainty, never permission to retry or create another candidate.
"""
import json
import os
import threading
import time
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import authority_contract as contract
from serverware import authority_request_commitment as commitment
from serverware import authority_static_credential_create as profile
from serverware import authority_static_credential_approval as approval
from serverware import authority_static_credential_custody as proof
from serverware import authority_static_credential_assignment as assignment_profile
from serverware import authority_policy_canary_policy as config_digest
from serverware import oauth_application_owner as originals

PREFIX = "/api/credentials/static"
PATHS = frozenset({PREFIX + "/assignment", PREFIX + "/intent", PREFIX + "/candidate", PREFIX + "/approval/status"} | {
    PREFIX + "/" + operation + "/" + phase
    for operation in ("approval/request", "approval/decide", "create")
    for phase in ("draft", "options", "execute")})
HTTP_SCHEMA = "serverware.staticCredentialPortalRequest/v1"
APPROVAL_STATUS_SCHEMA = "serverware.staticCredentialApprovalStatus/v1"
CREATE_OPTIONS_SCHEMA = "serverware.staticCredentialCreationOptions/v1"
CREATE_MFA_FIELD = "staticCredentialCreationProfile"
MAX_REQUEST = MAX_RESPONSE = 4 * 1024 * 1024
CONFIG_ENVIRONMENT = "SERVERWARE_STATIC_CREDENTIAL_CONFIG_FD"
CONFIG_SCHEMA = "serverware.staticCredentialPortalConfiguration/v2"
CONFIG_FIELDS = frozenset({"schema", "sourceRevision", "controlPlaneConfigurationDigest",
    "authorityRootFd", "authorityRootSha256", "authorityRootSpkiSha256", "authorityConfigurationFd",
    "authorityConfigurationSha256", "authorityConfigurationDigest"})
AUTHORITY_SCHEMA = "serverware.policyAuthorityServiceConfiguration/v6"
SIGNED_AUTHORITY_SCHEMA = "serverware.signedPolicyAuthorityServiceConfiguration/v6"
_PID, _LOCK = os.getpid(), threading.RLock()
_state, _cold, _namespace = "new", None, None


class CommitUncertain(ValueError):
    """Dispatch may have committed; this owner never resends it."""

    def __init__(self, operation, request_digest):
        self.operation, self.request_digest = operation, request_digest
        super().__init__("Static credential outcome is uncertain; do not retry the operation")


def _document(raw, maximum=MAX_REQUEST, *, exact=True):
    profile.require(type(raw) is bytes and 0 < len(raw) <= maximum)
    def pairs(items):
        value = {}
        for key, item in items:
            profile.require(key not in value)
            value[key] = item
        return value
    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
        parse_constant=lambda _: profile.require(False))
    profile.require(type(value) is dict and (not exact or profile.canonical(value) == raw))
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop(); count += 1
        profile.require(depth <= 32 and count <= 65536)
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
    # Reject overflowed numeric constants without narrowing finite metadata.
    profile.require(len(profile.canonical(value)) <= maximum)
    return value


def _literal(value, maximum=MAX_REQUEST):
    profile.require(type(value) is str)
    return _document(value.encode("ascii"), maximum)


def _environment():
    return tuple(sorted((name, value) for name, value in os.environ.items()
        if name.startswith("SERVERWARE_STATIC_CREDENTIAL_")))


class _Cold:
    def check(self):
        from serverware import control_plane_custody_startup as startup
        from serverware import control_plane_custody_client as custody
        with _LOCK:
            try:
                profile.require(os.getpid() == _PID and _state == "started" and self is _cold
                    and not self.poisoned and _environment() == _namespace
                    and startup.require_started() is self.custody and custody._snapshot(self.custody) is self.binding
                    and profile.canonical(self.payload) == self.payload_original
                    and self.policy is self.payload[profile.FIELD]
                    and profile.canonical(self.target) == self.target_original
                    and (self.assignment_original is None and self.assignment_payload is None
                        or self.assignment_original is not None
                        and profile.canonical(self.assignment_payload) == self.assignment_payload_original
                        and profile.sha256(self.assignment_original.encode("ascii")) == self.assignment_digest))
                for original in self.originals:
                    original.check()
                now, mono = custody._receipt_now(self.binding), time.monotonic_ns()
                profile.require(self.now <= now < self.expires and self.mono <= mono < self.deadline)
                self.now, self.mono = now, mono
                return now
            except BaseException:
                self.poisoned = True
                raise


def initialize_from_environment():
    global _state, _cold, _namespace
    from serverware import control_plane_custody_startup as startup
    from serverware import control_plane_custody_client as custody
    with _LOCK:
        profile.require(os.getpid() == _PID and _state == "new")
        _namespace = _environment()
        if not _namespace:
            _state = "disabled"
            return
        _state = "admitting"
        try:
            profile.require(set(dict(_namespace)) == {CONFIG_ENVIRONMENT})
            actual = startup.require_started(); binding = custody._snapshot(actual)
            text = os.environ[CONFIG_ENVIRONMENT]
            profile.require(text.isascii() and text.isdecimal() and str(int(text)) == text)
            fd = originals._fd(int(text))
            profile.require(fd in binding.inherited_descriptors)
            selector = originals._Original(fd, 16384)
            config = _document(selector.raw, 16384)
            profile.require(set(config) == CONFIG_FIELDS and config["schema"] == CONFIG_SCHEMA
                and config["sourceRevision"] == contract.SOURCE_REVISION
                and config["controlPlaneConfigurationDigest"] == binding.configuration_digest)
            for name in CONFIG_FIELDS - {"schema", "sourceRevision", "authorityRootFd", "authorityConfigurationFd"}:
                profile.digest(config[name])
            root_fd, payload_fd = originals._fd(config["authorityRootFd"]), originals._fd(config["authorityConfigurationFd"])
            profile.require(len({fd, root_fd, payload_fd}) == 3
                and {root_fd, payload_fd} <= set(binding.inherited_descriptors))
            root_original = originals._Original(root_fd, 4096)
            authority_original = originals._Original(payload_fd, contract.MAX_REQUEST_BYTES)
            profile.require(profile.sha256(root_original.raw) == config["authorityRootSha256"]
                and profile.sha256(authority_original.raw) == config["authorityConfigurationSha256"])
            root = serialization.load_pem_public_key(root_original.raw)
            profile.require(isinstance(root, Ed25519PublicKey)
                and root.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == root_original.raw)
            spki = root.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            profile.require(profile.sha256(spki) == config["authorityRootSpkiSha256"]
                and spki != binding.runtime_root_public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
            envelope = _document(authority_original.raw, contract.MAX_REQUEST_BYTES, exact=False)
            profile.require(set(envelope) == {"schema", "payload", "signature"} and envelope["schema"] == SIGNED_AUTHORITY_SCHEMA)
            payload = envelope["payload"]
            profile.require(type(payload) is dict and payload.get("schema") == AUTHORITY_SCHEMA
                and payload.get("sourceRevision") == contract.SOURCE_REVISION
                and config_digest.full_configuration_digest(payload) == config["authorityConfigurationDigest"] == binding.configuration_digest)
            root.verify(proof.decoded(envelope["signature"], 64, 64),
                commitment.framed_digest(SIGNED_AUTHORITY_SCHEMA, profile.canonical(payload)).encode("ascii"))
            policy = profile.validate_policy(payload.get(profile.FIELD), payload=payload, root_key=root)
            native = proof.validate_policy(payload.get(proof.FIELD), payload=payload, root_key=root)
            profile.require(policy is not None and native is not None)
            enabled = set(payload["roles"]["planner"]["enabledOperations"])
            required = profile.OPERATIONS | (approval.OPERATIONS if policy["twoPersonRequired"] else set())
            profile.require(required <= enabled)
            owner = _Cold()
            owner.custody, owner.binding, owner.payload, owner.root = actual, binding, payload, root
            owner.policy, owner.target = policy, native["target"]
            owner.payload_original, owner.target_original = profile.canonical(payload), profile.canonical(owner.target)
            # Runtime boot/key/configuration commitments are admitted only after
            # boot, outside both immutable configuration hashes. CP trust can
            # serve before that explicit independent assignment is available.
            owner.assignment_original = owner.assignment_payload = owner.assignment_payload_original = owner.assignment_digest = None
            owner.originals = (selector, root_original, authority_original)
            owner.now, owner.mono = custody._receipt_now(binding), time.monotonic_ns()
            owner.expires = binding.attestation_interval[1]
            owner.deadline = owner.mono + owner.expires - owner.now
            owner.poisoned = False
            _cold, _state = owner, "started"
            owner.check()
        except BaseException:
            _state = "poisoned"
            raise


def selected():
    with _LOCK:
        profile.require(os.getpid() == _PID)
        if _state == "new" and not _environment():
            return False
        profile.require(_environment() == _namespace)
        if _state == "disabled":
            return False
        profile.require(_state == "started")
        _cold.check()
        return True


def protected_available():
    """Transport presence, never a license to use the old plaintext route."""
    from serverware import control_plane_custody_startup as startup
    return startup.require_started() is not None


def close():
    global _state
    with _LOCK:
        profile.require(os.getpid() == _PID)
        if _cold is not None:
            _cold.poisoned = True
        _state = "closed"


def _identity(request):
    from fastapi import Request
    from serverware import auth, webauthn
    profile.require(type(request) is Request and request.method == "POST" and request.url.path in PATHS
        and not request.scope.get("query_string") and request.headers.getlist("content-type") == ["application/json"]
        and not request.headers.getlist("authorization") and not request.headers.getlist("x-serverware-admin-token")
        and request.headers.getlist("origin") == [webauthn.WEBAUTHN_ORIGIN]
        and len(request.headers.getlist("cookie")) == 1)
    names = [item.strip().split("=", 1)[0] for item in request.headers["cookie"].split(";")]
    profile.require(len(names) == len(set(names)) and not request.cookies.get("serverware_admin"))
    identity = auth.oidc_identity_from_session_token(request.cookies.get(auth.OIDC_SESSION_COOKIE_NAME))
    allowed = profile.APPROVER_ROLES if "/approval/decide/" in request.url.path else profile.REQUESTER_ROLES
    profile.require(type(identity) is auth.AdminIdentity and identity.user_id.startswith("oidc:")
        and bool(allowed.intersection(identity.roles)))
    auth.validate_csrf_request(request)
    return identity


def _approval_row(item_id):
    from serverware import db
    profile.identifier(item_id)
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)).fetchone()
    profile.require(row is not None, "Approval is unavailable; this does not authorize retry")
    row = dict(row)
    profile.require(set(row) == approval.ROW_FIELDS)
    approval.provenance(row["approval_authn"])
    return row


class _Owner:
    def __init__(self, request):
        from serverware import db, webauthn, control_plane_custody_client as custody
        from serverware import control_plane_oauth_activation as hardware
        from serverware.control_plane_approval_verification import _request_pin
        from serverware import app
        profile.require(selected() and protected_available() and db.metadata_uses_postgres())
        self.request, self.scope, self.pin = request, request.scope, _request_pin(request)
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.cold, self.identity = _cold, _identity(request)
        self.started_epoch, self.started_mono = self.cold.check(), time.monotonic_ns()
        self.last_epoch, self.last_mono = self.started_epoch, self.started_mono
        self.expires = min(self.started_epoch + 30_000_000_000, self.cold.expires)
        self.deadline = min(self.cold.deadline, self.started_mono + self.expires - self.started_epoch)
        self.policy = self.cold.policy
        self.assignment_original, self.assignment_payload = self.cold.assignment_original, self.cold.assignment_payload
        if request.url.path != PREFIX + "/assignment":
            profile.require(self.assignment_original is not None, "Admit the independently signed native assignment first")
            admitted = assignment_profile.verify_original(self.assignment_original,
                configuration_payload=self.cold.payload, root_key=self.cold.root, now_epoch_ns=self.started_epoch)
            profile.require(profile.canonical(admitted) == self.cold.assignment_payload_original)
            self.expires = min(self.expires, admitted["expiresAtEpochNs"])
            self.deadline = min(self.deadline, self.started_mono + self.expires - self.started_epoch)
        profile.require(self.policy["credentialPolicy"] == hardware._policy()
            and self.policy["twoPersonRequired"] == app._control_plane_two_person_required(profile.ACTION)
            and self.cold.target["portalOrigin"] == webauthn.WEBAUTHN_ORIGIN)
        self.values = self.arguments_original = self.operation = self.credential = self.mfa = self.mfa_original = None
        self.dispatched = False
        self.check()

    def check(self):
        from serverware import db, app, webauthn
        from serverware import control_plane_oauth_activation as hardware
        from serverware.control_plane_approval_verification import _request_pin
        epoch, mono = self.cold.check(), time.monotonic_ns()
        profile.require((self.pid, self.thread) == (os.getpid(), threading.get_ident())
            and _cold is self.cold and self.request.scope is self.scope and _request_pin(self.request) == self.pin
            and _identity(self.request) == self.identity and self.last_epoch <= epoch < self.expires
            and self.last_mono <= mono < self.deadline
            and self.assignment_original == self.cold.assignment_original
            and self.assignment_payload is self.cold.assignment_payload
            and self.policy["credentialPolicy"] == hardware._policy()
            and self.policy["twoPersonRequired"] == app._control_plane_two_person_required(profile.ACTION)
            and self.cold.target["portalOrigin"] == webauthn.WEBAUTHN_ORIGIN)
        if self.arguments_original is not None:
            profile.require(profile.canonical(self.values) == self.arguments_original)
            if not self.dispatched and self.operation == approval.OP_DECIDE:
                profile.require(approval.approval_original(_approval_row(self.values["approval_id"]))
                    == self.values["request"]["approvalOriginal"])
        if self.mfa_original is not None:
            profile.require(profile.canonical(self.mfa) == self.mfa_original)
        if self.credential is not None:
            current = db.get_webauthn_credential_by_record_id(self.credential["id"])
            profile.require(type(current) is dict and current.get("revoked_at") is None
                and all(current.get(name) == self.credential.get(name) for name in ("id", "credential_id", "user_id", "public_key_cose")))
            trust = webauthn._allowed_authenticator(current, hardware._authenticator_policy(self.policy["credentialPolicy"]))
            profile.require(trust["currently_trusted"] is True and trust["effective_authenticator_class"] in {"hardware", "yubikey"})
        closing_epoch, closing_mono = self.cold.check(), time.monotonic_ns()
        profile.require(epoch <= closing_epoch < self.expires and mono <= closing_mono < self.deadline)
        self.last_epoch, self.last_mono = closing_epoch, closing_mono

    def clip(self, expiry):
        profile.require(type(expiry) is int)
        self.expires = min(self.expires, expiry)
        self.deadline = min(self.deadline, self.started_mono + self.expires - self.started_epoch)
        self.check()

    def arguments(self, operation, original):
        codec = profile if operation == profile.OPERATION else approval
        value = codec.arguments(operation, _literal(original, codec.MAX_ARGUMENT_BYTES))
        profile.require(value["actor_id"] == self.identity.user_id
            and value["control_plane_configuration_digest"] == self.cold.binding.configuration_digest
            and value["credential_policy"] == self.policy["credentialPolicy"])
        codec.verify_request_context(operation, value, selected_policy=self.policy,
            expected_configuration_digest=self.cold.binding.configuration_digest, now_epoch_ns=self.last_epoch)
        self.operation, self.values, self.arguments_original = operation, value, profile.canonical(value)
        self.clip(value["request"]["executionExpiresAtEpochNs" if operation == profile.OPERATION else "expiresAtEpochNs"])
        return value

    def draft(self, operation, values):
        original = profile.canonical(values).decode("ascii")
        self.arguments(operation, original)
        codec = profile if operation == profile.OPERATION else approval
        result = {"apiVersion": HTTP_SCHEMA, "okForAction": False, "operation": operation,
            "argumentsOriginal": original, "requestDigest": codec.request_digest(operation, self.values),
            "expiresAtEpochNs": str(self.expires)}
        self.check()
        return result

    def options(self):
        from serverware import db, webauthn
        from serverware import control_plane_oauth_activation as hardware
        policy = self.policy["credentialPolicy"]
        descriptors = webauthn._credential_descriptors_for_policy(self.identity.user_id, hardware._authenticator_policy(policy))
        profile.require(type(descriptors) is list and 1 <= len(descriptors) <= 64)
        self.credential = db.get_webauthn_credential(descriptors[0]["id"])
        profile.require(type(self.credential) is dict and self.credential["user_id"] == self.identity.user_id)
        self.check()
        challenge = db.issue_policy_authority_webauthn_challenge(operation=self.operation, input_value=self.values,
            user_id=self.identity.user_id, credential_id=self.credential["credential_id"], deadline_ns=self.deadline)
        from serverware.control_plane_approval_verification import _epoch_ns
        self.clip(_epoch_ns(challenge["expires_at"]))
        payload = challenge["payload"]
        profile.require(challenge["used_at"] is None and challenge["user_id"] == self.identity.user_id
            and challenge["challenge_type"] == "policy_authority" and payload["credentialId"] == self.credential["credential_id"]
            and payload["rpId"] == policy["rpId"] and payload["origin"] in policy["origins"])
        codec = profile if self.operation == profile.OPERATION else approval
        timeout = min(30000, (self.expires - self.last_epoch) // 1_000_000)
        profile.require(timeout >= 1)
        result = {"publicKey": {"challenge": challenge["challenge"], "rpId": payload["rpId"],
            "allowCredentials": [{"type": "public-key", "id": self.credential["credential_id"]}],
            "timeout": timeout, "userVerification": "required"}, "serverware": {
                "schema": CREATE_OPTIONS_SCHEMA if self.operation == profile.OPERATION else approval.OPTIONS_SCHEMA,
                "operation": self.operation, "requestDigest": codec.request_digest(self.operation, self.values),
                "challengeId": challenge["id"], "credentialRecordId": self.credential["id"], "expiresAt": challenge["expires_at"]}}
        self.check()
        return result

    def execute(self, mfa, preparation=None):
        from serverware import db, webauthn, control_plane_custody_client as custody
        from serverware.control_plane_approval_verification import _epoch_ns
        field, schema = ((CREATE_MFA_FIELD, CREATE_OPTIONS_SCHEMA) if self.operation == profile.OPERATION
            else (approval.MFA_FIELD, approval.OPTIONS_SCHEMA))
        profile.require(type(mfa) is dict and set(mfa) == {field, "assertion"}
            and mfa[field] == schema and len(profile.canonical(mfa)) <= 16384)
        self.mfa, self.mfa_original = mfa, profile.canonical(mfa)
        assertion = mfa["assertion"]
        profile.require(type(assertion) is dict)
        self.credential = db.get_webauthn_credential(assertion.get("id"))
        profile.require(type(self.credential) is dict and self.credential["user_id"] == self.identity.user_id)
        self.check()
        client, _ = webauthn._parse_client_data(assertion.get("response", {}).get("clientDataJSON"), "webauthn.get")
        challenge = db.get_unused_webauthn_challenge(client["challenge"], challenge_type="policy_authority", user_id=self.identity.user_id)
        profile.require(challenge is not None)
        self.clip(_epoch_ns(challenge["expires_at"]))
        authorization = {"challengeId": challenge["id"], "credentialRecordId": self.credential["id"], "assertion": assertion}
        input_value = {"input": self.values, "webauthnAuthorization": authorization}
        if self.operation == profile.OPERATION:
            reply = _literal(preparation)
            profile.require(set(reply) == {"apiVersion", "argumentsOriginal", "evidence"}
                and reply["apiVersion"] == "serverware.nativeStaticCredentialPreparationResponse/v1"
                and reply["argumentsOriginal"].encode("ascii") == self.arguments_original)
            native = proof.evidence(reply["evidence"])
            profile.require(native["statement"]["holderId"] == self.assignment_payload["assignment"]["holderId"])
            native = proof.authority_evidence({**native, "assignmentOriginal": self.assignment_original})
            self.clip(native["statement"]["expiresAtEpochNs"])
            proof.verify_original(self.operation, self.values, evidence=native,
                configuration_payload=self.cold.payload, root_key=self.cold.root, now_epoch_ns=self.last_epoch)
            self.check()
            input_value["nativeEvidence"] = native
        else:
            profile.require(preparation is None)
        self.check(); profile.require(not self.dispatched); self.dispatched = True
        result = custody.ControlPlaneCustodyClient._request_authority(self.cold.custody,
            operation=self.operation, input_value=input_value, deadline_ns=self.deadline)
        self.check()
        self.validate_result(result)
        self.check()
        return result

    def validate_result(self, result):
        from serverware import db
        common = {"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "candidateSha256", "auditState"}
        codec = profile if self.operation == profile.OPERATION else approval
        profile.require(type(result) is dict and set(result) == common | ({"credential", "approvalId"}
            if self.operation == profile.OPERATION else {"approval"})
            and result["ok"] is True and result["operation"] == self.operation and result["idempotentReplay"] is False
            and result["requestDigest"] == codec.request_digest(self.operation, self.values)
            and result["auditState"] == "controlled_pending")
        profile.digest(result["auditEventDigest"])
        if self.operation == profile.OPERATION:
            requested, public = self.values["request"], result["credential"]
            profile.require(type(public) is dict and set(public) == {"id", "name", "kind", "credential_version",
                "metadata", "lifecycle_status", "created_at", "updated_at"}
                and public["id"] == requested["credentialId"] and public["name"] == requested["name"]
                and public["kind"] == requested["kind"] and type(public["credential_version"]) is int
                and public["credential_version"] == 1
                and profile.canonical(public["metadata"]) == profile.canonical(requested["metadata"])
                and public["lifecycle_status"] == "active"
                and public["created_at"] == public["updated_at"] and result["approvalId"] == self.values["approval_id"]
                and result["candidateSha256"] == profile.approval_payload_digest(self.values))
            from serverware.control_plane_approval_verification import _epoch_ns
            profile.require(requested["executionIssuedAtEpochNs"] <= _epoch_ns(public["created_at"])
                < requested["executionExpiresAtEpochNs"])
            with db.connect() as connection:
                row = connection.execute("SELECT id, name, kind, credential_version, metadata, lifecycle_status, created_at, updated_at FROM credentials WHERE id = ?",
                    (requested["credentialId"],)).fetchone()
            profile.require(row is not None)
            actual = dict(row)
            actual["metadata"] = json.loads(actual["metadata"])
            profile.require(profile.canonical(actual) == profile.canonical(public))
            if self.values["approval_id"] is not None:
                consumed = _approval_row(self.values["approval_id"])
                provenance = approval.provenance(consumed["approval_authn"])
                profile.require(consumed["status"] == "consumed" and consumed["requester_id"] == self.identity.user_id
                    and consumed["consumed_by"] == self.identity.user_id and consumed["consumed_at"] == public["created_at"]
                    and consumed["request_json"] == approval.approval_request(self.values)
                    and consumed["payload_digest"] == result["candidateSha256"]
                    and provenance["consumptionDigest"] == result["requestDigest"])
        else:
            returned = result["approval"]
            profile.require(type(returned) is dict)
            actual = _approval_row(returned.get("id"))
            public = {name: actual[name] for name in approval.ROW_FIELDS - {"request_json", "approval_authn"}}
            public["request"] = json.loads(actual["request_json"])
            profile.require(profile.canonical(public) == profile.canonical(returned)
                and actual["action"] == profile.ACTION and actual["payload_digest"] == result["candidateSha256"])
            if self.operation == approval.OP_REQUEST:
                from serverware import authority_transition_core as core
                candidate = approval.candidate(self.values["request"]["candidateOriginal"])
                expected_id = core.deterministic_uuid(operation=self.operation,
                    request_digest=result["requestDigest"], purpose="static-credential-approval")
                profile.require(actual["status"] == "pending" and actual["requester_id"] == self.identity.user_id
                    and actual["id"] == expected_id
                    and actual["request_json"] == approval.approval_request(candidate)
                    and actual["payload_digest"] == profile.approval_payload_digest(candidate))
                approval.approval_original(actual)
                profile.require(self.values["request"]["issuedAtEpochNs"] <= approval.epoch(actual["requested_at"])
                    < self.values["request"]["expiresAtEpochNs"])
            else:
                before = approval.approval_row(self.values["request"]["approvalOriginal"])
                changed = {"status", "approved_by", "approved_at", "approver_webauthn_credential_id", "approval_authn"}
                profile.require(actual["id"] == self.values["approval_id"] and actual["approved_by"] == self.identity.user_id
                    and actual["status"] == ("approved" if self.values["decision"] == "approve" else "denied")
                    and all(actual[name] == item for name, item in before.items() if name not in changed))
                provenance = approval.provenance(actual["approval_authn"])
                profile.require(provenance["decisionDigest"] == result["requestDigest"]
                    and actual["approver_webauthn_credential_id"] == self.credential["id"])
                if self.values["decision"] == "approve":
                    profile.require(self.values["request"]["issuedAtEpochNs"] <= approval.epoch(actual["approved_at"])
                        < self.values["request"]["expiresAtEpochNs"])
                else:
                    profile.require(actual["approved_at"] is None)


def _candidate(owner, original):
    values = approval.candidate(original)
    profile.require(values["actor_id"] == owner.identity.user_id
        and values["control_plane_configuration_digest"] == owner.cold.binding.configuration_digest
        and values["credential_policy"] == owner.policy["credentialPolicy"]
        and values["request"]["issuedAtEpochNs"] <= owner.last_epoch < values["request"]["expiresAtEpochNs"]
        and values["request"]["expiresAtEpochNs"] - values["request"]["issuedAtEpochNs"] <= owner.policy["intentMaxSeconds"] * 1_000_000_000
        and profile.generation(values["request"]["nativeGenerationOriginal"])["envelope"]["secret_kek_id"] == owner.policy["nativeSecretKekId"])
    return values


def _approval_status(owner, value):
    """Observe this requester's exact candidate; never authorize or consume it."""
    profile.require(set(value) == {"apiVersion", "candidateArgumentsOriginal", "approvalId"}
        and owner.policy["twoPersonRequired"] is True)
    values = _candidate(owner, value["candidateArgumentsOriginal"])
    owner.clip(values["request"]["expiresAtEpochNs"])
    row = _approval_row(value["approvalId"])
    # A decision can commit during the read; compare it with the retained
    # clock sampled after that read, not the earlier request-start sample.
    owner.check()
    provenance = approval.provenance(row["approval_authn"])
    candidate_digest = profile.approval_payload_digest(values)
    profile.require(row["id"] == value["approvalId"] and row["action"] == profile.ACTION
        and row["resource_id"] == values["request"]["credentialId"]
        and row["requester_id"] == owner.identity.user_id
        and row["payload_digest"] == provenance["candidateSha256"] == candidate_digest
        and row["request_json"] == approval.approval_request(values)
        and provenance["controlPlaneConfigurationDigest"] == values["control_plane_configuration_digest"]
        and provenance["credentialPolicy"] == values["credential_policy"]
        and row["status"] in {"pending", "approved", "denied", "consumed", "invalidated"})
    expires = approval.epoch(row["expires_at"])
    profile.require(values["request"]["issuedAtEpochNs"] <= approval.epoch(row["requested_at"])
        < expires <= values["request"]["expiresAtEpochNs"])
    consumed = row["consumed_at"] is not None or row["consumed_by"] is not None
    if row["status"] == "approved":
        profile.require(row["approved_by"] is not None and row["approved_by"] != row["requester_id"]
            and approval.epoch(row["requested_at"]) <= approval.epoch(row["approved_at"]) <= owner.last_epoch
            and approval.epoch(row["approved_at"]) < expires
            and provenance["decisionDigest"] is not None)
    owner.check()
    return {"apiVersion": APPROVAL_STATUS_SCHEMA, "okForAction": False,
        "approvalId": row["id"], "credentialId": row["resource_id"], "candidateSha256": candidate_digest,
        "status": row["status"], "consumed": consumed or provenance["consumptionDigest"] is not None,
        "expiresAtEpochNs": str(expires), "observedAtEpochNs": str(owner.last_epoch)}


def on_request(request, raw):
    # HTTP envelopes have no canonical wire requirement. Literal originals
    # inside them retain their separate byte-exact canonical admission.
    value = _document(raw, exact=False)
    profile.require(value.get("apiVersion") == HTTP_SCHEMA)
    owner = _Owner(request)
    route = request.url.path[len(PREFIX) + 1:]
    try:
        result = _handle(owner, route, value)
        profile.require(len(profile.canonical(result)) <= MAX_RESPONSE)
        owner.check()
        return result
    except BaseException:
        if owner.dispatched:
            codec = profile if owner.operation == profile.OPERATION else approval
            raise CommitUncertain(owner.operation, codec.request_digest(owner.operation, owner.values)) from None
        raise


def _handle(owner, route, value):
    if route == "approval/status":
        return _approval_status(owner, value)
    if route == "assignment":
        profile.require(set(value) == {"apiVersion", "assignmentOriginal"})
        original = value["assignmentOriginal"]
        admitted = assignment_profile.verify_original(original, configuration_payload=owner.cold.payload,
            root_key=owner.cold.root, now_epoch_ns=owner.last_epoch)
        owner.check()
        with _LOCK:
            # Exact re-observation is allowed; replacement never renews this
            # process's original native assignment or any in-flight action.
            profile.require(owner.cold.assignment_original in (None, original),
                "A different native assignment is already retained for this process")
            if owner.cold.assignment_original is None:
                owner.cold.assignment_original = original
                owner.cold.assignment_payload = admitted
                owner.cold.assignment_payload_original = profile.canonical(admitted)
                owner.cold.assignment_digest = profile.sha256(original.encode("ascii"))
            owner.assignment_original, owner.assignment_payload = owner.cold.assignment_original, owner.cold.assignment_payload
        owner.clip(admitted["expiresAtEpochNs"])
        return {"apiVersion": HTTP_SCHEMA, "okForAction": False,
            "assignmentSha256": owner.cold.assignment_digest, "holderId": admitted["assignment"]["holderId"],
            "expiresAtEpochNs": str(admitted["expiresAtEpochNs"])}
    if route == "intent":
        profile.require(set(value) == {"apiVersion", "name", "kind", "metadata", "ttlSeconds"}
            and type(value["ttlSeconds"]) is int and 1 <= value["ttlSeconds"] <= owner.policy["intentMaxSeconds"])
        issued = owner.last_epoch // 1000 * 1000
        expires = min(issued + value["ttlSeconds"] * 1_000_000_000, owner.cold.expires // 1000 * 1000,
            owner.assignment_payload["expiresAtEpochNs"] // 1000 * 1000)
        intent = {"credentialId": str(uuid.uuid4()), "credentialVersion": 1, "name": value["name"],
            "kind": value["kind"], "metadata": value["metadata"], "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
        original = profile.intent_original(actor_id=owner.identity.user_id,
            configuration_digest=owner.cold.binding.configuration_digest, credential_policy=owner.policy["credentialPolicy"], request=intent)
        return {"apiVersion": HTTP_SCHEMA, "okForAction": False, "intentOriginal": original.decode("ascii"),
            "credentialId": intent["credentialId"], "expiresAtEpochNs": str(expires),
            "intakeOrigin": owner.cold.target["intakeOrigin"], "portalOrigin": owner.cold.target["portalOrigin"],
            "twoPersonRequired": owner.policy["twoPersonRequired"]}
    if route == "candidate":
        profile.require(set(value) == {"apiVersion", "candidateOriginal"})
        reply = _literal(value["candidateOriginal"])
        profile.require(set(reply) == {"apiVersion", "candidate"}
            and reply["apiVersion"] == "serverware.nativeStaticCredentialCandidateResponse/v1")
        item = reply["candidate"]
        profile.require(type(item) is dict and set(item) == {"credentialId", "intentOriginal", "nativeGenerationOriginal",
            "intentSha256", "generationSha256", "expiresAtEpochNs"})
        intent = _literal(item["intentOriginal"], profile.MAX_ARGUMENT_BYTES)
        expected = profile.intent_original(actor_id=owner.identity.user_id,
            configuration_digest=owner.cold.binding.configuration_digest, credential_policy=owner.policy["credentialPolicy"], request=intent["request"])
        profile.require(expected == item["intentOriginal"].encode("ascii")
            and profile.sha256(expected) == item["intentSha256"]
            and profile.sha256(item["nativeGenerationOriginal"].encode("ascii")) == item["generationSha256"]
            and item["credentialId"] == intent["request"]["credentialId"]
            and item["expiresAtEpochNs"] == intent["request"]["expiresAtEpochNs"])
        issued = owner.last_epoch // 1000 * 1000
        values = {"actor_id": owner.identity.user_id, "control_plane_configuration_digest": owner.cold.binding.configuration_digest,
            "credential_policy": owner.policy["credentialPolicy"], "approval_id": None,
            "request": {**intent["request"], "nativeGenerationOriginal": item["nativeGenerationOriginal"],
                "executionIssuedAtEpochNs": issued, "executionExpiresAtEpochNs": min(issued + 30_000_000_000, item["expiresAtEpochNs"])}}
        original = profile.canonical(values).decode("ascii")
        _candidate(owner, original)
        return {"apiVersion": HTTP_SCHEMA, "okForAction": False, "candidateArgumentsOriginal": original,
            "candidateSha256": profile.approval_payload_digest(values), "credentialId": item["credentialId"],
            "expiresAtEpochNs": str(item["expiresAtEpochNs"]), "intakeOrigin": owner.cold.target["intakeOrigin"],
            "portalOrigin": owner.cold.target["portalOrigin"], "twoPersonRequired": owner.policy["twoPersonRequired"]}
    family, phase = route.rsplit("/", 1)
    operation = {"create": profile.OPERATION, "approval/request": approval.OP_REQUEST, "approval/decide": approval.OP_DECIDE}[family]
    if phase == "draft":
        issued = owner.last_epoch // 1000 * 1000
        expires = min(owner.expires // 1000 * 1000, issued + owner.policy["operationMaxSeconds"] * 1_000_000_000)
        if operation == profile.OPERATION:
            profile.require(set(value) == {"apiVersion", "candidateArgumentsOriginal", "approvalId"})
            values = _candidate(owner, value["candidateArgumentsOriginal"])
            if owner.policy["twoPersonRequired"]:
                row = _approval_row(value["approvalId"])
                profile.require(row["status"] == "approved" and row["requester_id"] == owner.identity.user_id
                    and row["payload_digest"] == profile.approval_payload_digest(values)
                    and row["request_json"] == approval.approval_request(values)
                    and row["consumed_at"] is None and row["consumed_by"] is None)
                from serverware.control_plane_approval_verification import _epoch_ns
                expires = min(expires, _epoch_ns(row["expires_at"]))
            else:
                profile.require(value["approvalId"] is None)
            values = {**values, "approval_id": value["approvalId"], "request": {**values["request"],
                "executionIssuedAtEpochNs": issued, "executionExpiresAtEpochNs": min(expires, values["request"]["expiresAtEpochNs"])}}
        elif operation == approval.OP_REQUEST:
            profile.require(set(value) == {"apiVersion", "candidateArgumentsOriginal", "ttlSeconds"})
            candidate = _candidate(owner, value["candidateArgumentsOriginal"])
            values = {"actor_id": owner.identity.user_id, "control_plane_configuration_digest": owner.cold.binding.configuration_digest,
                "credential_policy": owner.policy["credentialPolicy"], "approval_id": None, "request": {
                    "candidateOriginal": value["candidateArgumentsOriginal"], "ttlSeconds": value["ttlSeconds"],
                    "issuedAtEpochNs": issued, "expiresAtEpochNs": min(expires, candidate["request"]["expiresAtEpochNs"])}}
        else:
            profile.require(set(value) == {"apiVersion", "approvalId", "decision"})
            row = _approval_row(value["approvalId"])
            from serverware.control_plane_approval_verification import _epoch_ns
            values = {"actor_id": owner.identity.user_id, "control_plane_configuration_digest": owner.cold.binding.configuration_digest,
                "credential_policy": owner.policy["credentialPolicy"], "approval_id": value["approvalId"], "decision": value["decision"],
                "request": {"approvalOriginal": approval.approval_original(row), "issuedAtEpochNs": issued,
                    "expiresAtEpochNs": min(expires, _epoch_ns(row["expires_at"]))}}
        return owner.draft(operation, values)
    expected = {"apiVersion", "argumentsOriginal"} | ({"mfa"} if phase == "execute" else set())
    if phase == "execute" and operation == profile.OPERATION:
        expected.add("preparationOriginal")
    profile.require(phase in {"options", "execute"} and set(value) == expected)
    owner.arguments(operation, value["argumentsOriginal"])
    return owner.options() if phase == "options" else owner.execute(value["mfa"], value.get("preparationOriginal"))
