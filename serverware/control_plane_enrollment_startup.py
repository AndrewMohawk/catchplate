"""Cold ownership of the explicitly provisioned enrollment authorization key.

Initialize after custody runtime admission and before application startup. The
already admitted runtime root and original descriptor inventory are the only
bootstrap trust source. No second runtime loader, file/key generation, public
key publication, environment secret or alternate transport is used here.

An admitted null policy creates an explicit disabled owner. Only genuinely
unconfigured development may return None. A registration-originals container
is ordinary raw data: issuance requires the real application's preceding
authenticated enrollment admission and never establishes that admission itself.
Imports alone perform no authority admission or application initialization.
"""
from __future__ import annotations

import errno
import fcntl
import os
import stat
import threading
from datetime import datetime, timezone


BOOTSTRAP_FD_ENVIRONMENT = "SERVERWARE_CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_FD"
MAX_BOOTSTRAP_BYTES = 4 * 1024 * 1024
MAX_PRIVATE_KEY_BYTES = 4096
_PREFIX = "SERVERWARE_CONTROL_PLANE_ENROLLMENT_"
_DEVELOPMENT = frozenset({"dev", "development", "local", "test"})
_PID = os.getpid()
_LOCK = threading.RLock()
_state = "new"
_namespace = None
_identity_at_start = None
_owner = None


class EnrollmentStartupError(RuntimeError):
    pass


def _require_pid():
    if os.getpid() != _PID:
        raise EnrollmentStartupError("forked process cannot use the enrollment startup owner")


def _environment():
    release = os.environ.get("SERVERWARE_RELEASE_CHANNEL", "dev").strip().lower()
    # Every mention is significant, not just well-spelled FD/PATH suffixes.
    return release, tuple(sorted((name, value) for name, value in os.environ.items()
        if name.startswith(_PREFIX)))


def _development(namespace):
    return namespace[0] in _DEVELOPMENT and not namespace[1]


def _descriptor(namespace):
    settings = namespace[1]
    if len(settings) != 1 or settings[0][0] != BOOTSTRAP_FD_ENVIRONMENT:
        raise EnrollmentStartupError("enrollment startup permits only its fixed bootstrap FD")
    value = settings[0][1]
    if (type(value) is not str or not 1 <= len(value) <= 4
            or not value.isascii() or not value.isdecimal()):
        raise EnrollmentStartupError("enrollment bootstrap FD is not canonical decimal")
    descriptor = int(value)
    if not 3 <= descriptor <= 1023 or str(descriptor) != value:
        raise EnrollmentStartupError("enrollment bootstrap FD is outside its inherited range")
    return descriptor


def _descriptor_identity(descriptor, *, private):
    metadata = os.fstat(descriptor)
    seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    target = os.readlink("/proc/self/fd/" + str(descriptor))
    required = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    maximum = MAX_PRIVATE_KEY_BYTES if private else MAX_BOOTSTRAP_BYTES
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 0
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or private and stat.S_IMODE(metadata.st_mode) not in (0o400, 0o600)
            or not 2 <= metadata.st_size <= maximum or seals & required != required
            or not target.startswith("/memfd:") or not target.endswith(" (deleted)")):
        raise EnrollmentStartupError("enrollment descriptor is not bounded root-owned sealed memfd material")
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
        metadata.st_gid, metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns,
        metadata.st_ctime_ns, seals, target)


def _read_original(descriptor, *, private):
    before = _descriptor_identity(descriptor, private=private)
    size = before[6]
    value = bytearray()
    while len(value) < size:
        chunk = os.pread(descriptor, min(4096, size - len(value)), len(value))
        if not chunk:
            raise EnrollmentStartupError("enrollment descriptor was truncated")
        value.extend(chunk)
    if os.pread(descriptor, 1, size) or _descriptor_identity(descriptor, private=private) != before:
        raise EnrollmentStartupError("enrollment descriptor changed while reading")
    return bytes(value), before


def _continuity(owner):
    """Check the same owner/receipt and return its actual sampled epoch."""
    _require_pid()
    if (type(owner) is not _EnrollmentOwner or owner._closed
            or _owner is not owner or _state != "started"
            or _environment() != _namespace
            or (os.geteuid(), os.getegid()) != _identity_at_start):
        raise EnrollmentStartupError("enrollment owner or its process namespace changed")
    from serverware import control_plane_custody_client as client
    from serverware import control_plane_custody_startup as custody

    actual = custody.require_started()
    if actual is not owner._custody or client._snapshot(actual) is not owner._binding:
        raise EnrollmentStartupError("enrollment custody runtime owner changed")
    observed_epoch = client._receipt_now(owner._binding)
    if _descriptor_identity(owner._bootstrap_fd, private=False) != owner._bootstrap_identity:
        raise EnrollmentStartupError("enrollment bootstrap custody changed")
    if (owner._key_fd is not None
            and _descriptor_identity(owner._key_fd, private=True) != owner._key_identity):
        raise EnrollmentStartupError("enrollment issuer key custody changed")
    if (owner._execution_key_fd is not None and _descriptor_identity(
            owner._execution_key_fd, private=True) != owner._execution_key_identity):
        raise EnrollmentStartupError("registration execution caller key custody changed")
    if (owner._finalization_key_fd is not None and _descriptor_identity(
            owner._finalization_key_fd, private=True) != owner._finalization_key_identity):
        raise EnrollmentStartupError("registration finalization caller key custody changed")
    if (owner._activation_key_fd is not None and _descriptor_identity(
            owner._activation_key_fd, private=True) != owner._activation_key_identity):
        raise EnrollmentStartupError("activation execution caller key custody changed")
    if (owner._consume_key_fd is not None and _descriptor_identity(
            owner._consume_key_fd, private=True) != owner._consume_key_identity):
        raise EnrollmentStartupError("consume execution caller key custody changed")
    return observed_epoch


def _response_spki(path, uid, work=None):
    """Read the actual provisioned HTTP key, with no generation/publication."""
    from serverware import response_identity

    if response_identity.RESPONSE_SIGNING_KEY_PATH != path:
        raise EnrollmentStartupError("HTTP response signing key path changed after enrollment admission")
    if work is None:
        # Lifecycle access has no request work and creates no new allowance.
        import hashlib
        from cryptography.hazmat.primitives import serialization

        key = response_identity._load_response_key_file(path, expected_uid=uid)
        der = key.public_key().public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        if type(der) is not bytes or len(der) != 44:
            raise EnrollmentStartupError("HTTP response signing key SPKI is not Ed25519")
        return "sha256:" + hashlib.sha256(der).hexdigest()
    from serverware import authority_webauthn_enrollment_issuer as issuer

    key = issuer.evidence.production._callback(work,
        lambda: response_identity._load_response_key_file(path, expected_uid=uid))
    public = issuer.evidence.production._callback(work, key.public_key)
    return issuer.evidence.keys._spki_on_work(public, work)


def _live(owner, *, work=None):
    # Hold the admitted comparison before descriptor/clock/key callbacks.
    _require_pid()
    if type(owner) is not _EnrollmentOwner:
        raise EnrollmentStartupError("enrollment owner is unavailable")
    path, response_pin, binding = owner._response_path, owner._response_pin, owner._binding
    if work is None:
        _continuity(owner)
    else:
        from serverware import authority_webauthn_enrollment_issuer as issuer

        issuer.evidence.production._callback(work, lambda: _continuity(owner))
    if (response_pin is not None
            and _response_spki(path, binding.caller_uid, work) != response_pin):
        raise EnrollmentStartupError("HTTP response signing key changed; enrollment requires fresh cold admission")
    # File/key work cannot extend the original receipt's validity.
    if work is None:
        _continuity(owner)
    else:
        issuer.evidence.production._callback(work, lambda: _continuity(owner))


class _EnrollmentOwner:
    __slots__ = ("_material", "_private_key", "_custody", "_binding", "_bootstrap_fd",
        "_bootstrap_identity", "_key_fd", "_key_identity", "_response_path", "_response_pin", "_closed",
        "_execution_key", "_execution_key_fd", "_execution_key_identity",
        "_finalization_key", "_finalization_key_fd", "_finalization_key_identity",
        "_release_spent", "_activation_key", "_activation_key_fd",
        "_activation_key_identity", "_activation_permission",
        "_consume_key", "_consume_key_fd", "_consume_key_identity")

    def __init__(self):
        raise EnrollmentStartupError("enrollment owner requires fixed cold startup")

    @property
    def enabled(self):
        _live(self)
        return self._private_key is not None

    @property
    def execution_enabled(self):
        _live(self)
        return self._execution_key is not None

    @property
    def finalization_enabled(self):
        _live(self)
        return self._finalization_key is not None

    @property
    def activation_execution_enabled(self):
        """Cold signer configuration only, never present-user permission."""
        _live(self)
        return (self._activation_key is not None and self._material is not None
            and self._material.activation_execution is not None)

    def _oidc_session_activation_permission(self, *, request, permission_bytes,
            live_window, transport_deadline_ns, work):
        """Enter a live, lock-owned permission scope; never renew an allowance.

        Genuine permission precedes planning because its assertion advances the
        credential counter. The actual context owns the parent lock and revokes
        its fixed post-plan signer on exit; a past success cannot authorize it.
        """
        from serverware import control_plane_oidc_session_activation_execution as activation

        _require_pid()
        return activation._permission_on_owner(self, request=request,
            permission_bytes=permission_bytes, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work)

    def _prepare_oidc_session_activation_authorization(self, *, request,
            permission_bytes, assertion_bytes, expected_challenge_id,
            live_window, transport_deadline_ns, work):
        """One genuine permission, durable planner claim and original signature.

        This private composition neither executes activation nor returns a
        reusable permission carrier. A distinct session-binding assertion is
        checked by the real planner after the permission assertion's counter
        update. All preparation shares the caller's original work and window.
        """
        from serverware import control_plane_oidc_session_activation_planning as planning

        _require_pid()
        assertion, challenge = planning._planning_inputs(assertion_bytes, expected_challenge_id)
        with _EnrollmentOwner._oidc_session_activation_permission(self,
                request=request, permission_bytes=permission_bytes,
                live_window=live_window, transport_deadline_ns=transport_deadline_ns,
                work=work) as permission:
            return permission.prepare_authorization(assertion_bytes=assertion,
                expected_challenge_id=challenge)

    def _dispatch_oidc_session_activation(self, *, request, permission_bytes,
            assertion_bytes, expected_challenge_id, live_window, transport_deadline_ns, work):
        """One original-bound private dispatch, returning only SQL observation.

        All genuine permission, planning and downstream operations remain in
        one live parent-owned call. The exact unsigned response is not an
        authenticated commit, token delivery or active-session confirmation.
        """
        from serverware import control_plane_oidc_session_activation_planning as planning

        _require_pid()
        assertion, challenge = planning._planning_inputs(assertion_bytes, expected_challenge_id)
        with _EnrollmentOwner._oidc_session_activation_permission(self,
                request=request, permission_bytes=permission_bytes,
                live_window=live_window, transport_deadline_ns=transport_deadline_ns,
                work=work) as permission:
            return permission.dispatch(assertion_bytes=assertion,
                expected_challenge_id=challenge)

    def _dispatch_oidc_session_activation_completion(self, *, request, permission_bytes,
            assertion_bytes, expected_challenge_id, live_window, transport_deadline_ns, work):
        """One dispatch plus completion exchange; return only exact originals.

        The pair is an unsigned SQL observation and an original completion
        response. Public control authenticity does not replace private replay,
        prove current state, release a token or authorize another SQL attempt.
        """
        from serverware import control_plane_oidc_session_activation_planning as planning

        _require_pid()
        assertion, challenge = planning._planning_inputs(assertion_bytes, expected_challenge_id)
        with _EnrollmentOwner._oidc_session_activation_permission(self,
                request=request, permission_bytes=permission_bytes,
                live_window=live_window, transport_deadline_ns=transport_deadline_ns,
                work=work) as permission:
            return permission.dispatch_completion(assertion_bytes=assertion,
                expected_challenge_id=challenge)

    def _prepare_oidc_session_activation_consume(self, *, planner_bootstrap_bytes,
            history_custody_bytes):
        """Prepare/export only inside this parent's actual live completion call.

        Independently issued per-request root originals arrive after activation.
        This facade cannot create or reopen a permission context or allowance;
        callers must still hold its original completion context. No token is
        released and no externally supplied completion result is accepted.
        """
        from serverware import control_plane_oidc_session_activation_execution as execution

        _require_pid()
        permission = self._activation_permission
        if type(permission) is not execution._ActivationPermission or permission._owner is not self:
            raise EnrollmentStartupError("consume preparation requires the actual active parent permission")
        return permission.prepare_consume(planner_bootstrap_bytes=planner_bootstrap_bytes,
            history_custody_bytes=history_custody_bytes)

    @property
    def consume_execution_enabled(self):
        """Cold configuration only, never permission to sign or execute."""
        _live(self)
        return (self._consume_key is not None and self._material is not None
            and self._material.consume_execution is not None)

    def _authorize_oidc_session_activation_consume(self):
        """Sign only this still-active permission's exact prepared consume plan."""
        from serverware import control_plane_oidc_session_activation_execution as execution

        _require_pid()
        permission = self._activation_permission
        if type(permission) is not execution._ActivationPermission or permission._owner is not self:
            raise EnrollmentStartupError("consume authorization requires the actual active parent permission")
        return permission.authorize_consume()

    def _dispatch_oidc_session_activation_consume(self):
        """Dispatch once on the exact still-live consume-authorized context."""
        from serverware import control_plane_oidc_session_activation_execution as execution

        _require_pid()
        permission = self._activation_permission
        if type(permission) is not execution._ActivationPermission or permission._owner is not self:
            raise EnrollmentStartupError("consume dispatch requires the actual active parent permission")
        return permission.dispatch_consume()

    @property
    def finalization_reservation_enabled(self):
        _live(self)
        finalization = None if self._material is None else self._material.finalization
        return (self._finalization_key is not None and finalization is not None
            and finalization.reservation_endpoint is not None
            and finalization.reservation_predecessor is not None)

    @property
    def finalization_sql_enabled(self):
        """Admitted cold configuration only, not dispatch or action-time currentness."""
        _live(self)
        finalization = None if self._material is None else self._material.finalization
        return (self._finalization_key is not None and finalization is not None
            and finalization.sql_endpoint is not None
            and finalization.current_pending is not None)

    @property
    def finalization_completion_enabled(self):
        """Independent nested-v4 scope only, not present completion permission."""
        _live(self)
        finalization = None if self._material is None else self._material.finalization
        return (self._finalization_key is not None and finalization is not None
            and finalization.completion_endpoint is not None
            and finalization.completion_packet_digest is not None
            and finalization.completion_authorization_digest is not None
            and finalization.current_pending is not None)

    @property
    def release_client_enabled(self):
        """Explicit v5 public configuration, not request or session authority."""
        _continuity(self)
        if type(self._release_spent) is not bool:
            raise EnrollmentStartupError("release caller dispatch state changed")
        return (self._material is not None and self._material.release_client is not None
            and not self._release_spent)

    def _request_oidc_session_activation_release(self, *, request_originals,
            live_window, transport_deadline_ns, work):
        """One private, original-bound release; no public permission or retry.

        The actual composition owns fresh root admission, the durable token-free
        dispatch claim, fixed transport and original receiving verification.
        It borrows no issuer/finalization signing key and starts no allowance.
        """
        from serverware import control_plane_oidc_session_activation_release_client as release

        _require_pid()
        with _LOCK:
            return release._request_on_owner(self, request_originals=request_originals,
                live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)

    def _authorize_registration_finalization(self, *, request_originals, response_originals,
            sibling_challenge_ids, live_window, work, transport_deadline_ns=None):
        """Private finalization-only continuation after fresh present permission."""
        from serverware import control_plane_registration_finalization_execution as finalization

        _require_pid()
        with _LOCK:
            return finalization._authorize_on_owner(self, request_originals=request_originals,
                response_originals=response_originals, sibling_challenge_ids=sibling_challenge_ids,
                live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns)

    def _request_registration_finalization_grant(self, *, originals, before_vector_bytes,
            live_window, work, transport_deadline_ns=None):
        """Exchange dedicated original finalization material once; never execute."""
        from serverware import control_plane_registration_finalization_execution as finalization

        _require_pid()
        with _LOCK:
            return finalization._request_on_owner(self, originals=originals,
                before_vector_bytes=before_vector_bytes, live_window=live_window,
                work=work, transport_deadline_ns=transport_deadline_ns)

    def _request_registration_finalization_reservation(self, *, originals, live_window,
            transport_deadline_ns, work):
        """One genuine raw10-to-raw3 reserve exchange after separate present permission.

        Only explicit nested finalization v2/v3/v4 supplies its independent scope.
        This neither stores the response nor establishes latest state or SQL authority.
        """
        from serverware import control_plane_registration_finalization_execution as finalization

        _require_pid()
        with _LOCK:
            return finalization._reserve_on_owner(self, originals=originals,
                live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)

    def _request_registration_finalization_sql(self, *, local_digest, originals, live_window,
            transport_deadline_ns, work):
        """One explicit private SQL exchange; separate present permission is required.

        Nested v3/v4 supplies independently root-admitted pending pins and endpoint.
        The actual retained association owns a durable no-retry dispatch claim
        and opaque outcome record. This does not authenticate signed completion
        or activate sessions. Failure may follow a remote attempt or commit.
        """
        from serverware import control_plane_registration_finalization_sql as sql

        _require_pid()
        with _LOCK:
            return sql._request_on_owner(self, local_digest=local_digest, originals=originals,
                live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)

    def _request_retained_registration_finalization_completion(self, *, local_digest,
            expected_user_id, expected_session_id, live_window, transport_deadline_ns, work):
        """Private original-bound completion after separate present permission."""
        from serverware import control_plane_registration_finalization_completion as completion

        _require_pid()
        with _LOCK:
            return completion._complete_on_owner(self, local_digest=local_digest,
                expected_user_id=expected_user_id, expected_session_id=expected_session_id,
                recovery=False, live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)

    def _recover_retained_registration_finalization_completion(self, *, local_digest,
            expected_user_id, expected_session_id, live_window, transport_deadline_ns, work):
        """Private uncertainty reconciliation after separate recovery permission."""
        from serverware import control_plane_registration_finalization_completion as completion

        _require_pid()
        with _LOCK:
            return completion._complete_on_owner(self, local_digest=local_digest,
                expected_user_id=expected_user_id, expected_session_id=expected_session_id,
                recovery=True, live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)

    def _inspect_retained_registration_activation_subject(self, *, local_digest,
            expected_user_id, expected_session_id, live_window, transport_deadline_ns, work):
        """Local original replay only; no activation, completion fetch or retry."""
        from serverware import control_plane_registration_activation_subject as activation

        _require_pid()
        with _LOCK:
            _live(self, work=work)
            return activation._inspect_on_owner(self, local_digest=local_digest,
                expected_user_id=expected_user_id, expected_session_id=expected_session_id,
                live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)

    @property
    def reservation_enabled(self):
        _live(self)
        execution = None if self._material is None else self._material.execution
        return (self._execution_key is not None and execution is not None
            and execution.reservation_endpoint is not None and execution.reservation_predecessor is not None)

    @property
    def sql_handoff_enabled(self):
        _live(self)
        execution = None if self._material is None else self._material.execution
        return (self._execution_key is not None and execution is not None
            and execution.sql_endpoint is not None and execution.completion_endpoint is not None
            and execution.current_pending is not None and execution.completion_packet_digest is not None)

    def _execute_retained_registration(self, *, local_digest, expected_user_id, expected_session_id,
            deadline_epoch_ns, deadline_ns, work):
        """Private one-use dispatch after separate present-caller authorization."""
        from serverware import control_plane_registration_handoff as handoff

        _require_pid()
        with _LOCK:
            return handoff._execute_on_owner(self, local_digest=local_digest,
                expected_user_id=expected_user_id, expected_session_id=expected_session_id,
                deadline_epoch_ns=deadline_epoch_ns, deadline_ns=deadline_ns, work=work)

    def _request_retained_registration_completion(self, *, local_digest, expected_user_id, expected_session_id,
            deadline_epoch_ns, deadline_ns, work):
        """Private live-original completion request, never historical recovery."""
        from serverware import control_plane_registration_handoff as handoff

        _require_pid()
        with _LOCK:
            return handoff._complete_on_owner(self, local_digest=local_digest,
                expected_user_id=expected_user_id, expected_session_id=expected_session_id,
                deadline_epoch_ns=deadline_epoch_ns, deadline_ns=deadline_ns, work=work)

    def _recover_retained_registration_completion(self, *, local_digest, expected_user_id, expected_session_id,
            live_window, work, transport_deadline_ns=None):
        """Separate historical recovery after fresh present-purpose admission."""
        from serverware import control_plane_registration_recovery as recovery

        _require_pid()
        with _LOCK:
            return recovery._recover_on_owner(self, local_digest=local_digest,
                expected_user_id=expected_user_id, expected_session_id=expected_session_id,
                live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns)

    def _authorize_registration_execution(self, *, request_originals, response_originals,
            deadline_epoch_ns, deadline_ns, work):
        """Private continuation after real present caller/purpose admission.

        Original evidence replay establishes request identity, not actor/session
        permission. The authenticated application must admit that separately.
        No existing public evidence-only preparation route invokes this method.
        """
        from serverware import control_plane_registration_execution as execution

        _require_pid()
        with _LOCK:
            return execution._authorize_on_owner(self, request_originals=request_originals,
                response_originals=response_originals, deadline_epoch_ns=deadline_epoch_ns,
                deadline_ns=deadline_ns, work=work)

    def _request_registration_execution_grant(self, *, authorization_bytes,
            request_originals, response_originals, before_vector_bytes,
            deadline_epoch_ns, deadline_ns, work):
        """Exchange once and genuinely admit the original grant; never execute."""
        from serverware import control_plane_registration_execution as execution

        _require_pid()
        with _LOCK:
            return execution._request_on_owner(self, authorization_bytes=authorization_bytes,
                request_originals=request_originals, response_originals=response_originals,
                before_vector_bytes=before_vector_bytes, deadline_epoch_ns=deadline_epoch_ns,
                deadline_ns=deadline_ns, work=work)

    def _request_registration_reservation(self, *, originals,
            deadline_epoch_ns, deadline_ns, work):
        """Private new-purpose reserve exchange, not public execution authority.

        Caller/session authorization precedes this method. The returned raw3
        is genuine original data, not independent currentness or SQL permission.
        Existing grant-only public preparation handlers never invoke it.
        """
        from serverware import control_plane_registration_execution as execution

        _require_pid()
        with _LOCK:
            return execution._reserve_on_owner(self, originals=originals,
                deadline_epoch_ns=deadline_epoch_ns, deadline_ns=deadline_ns, work=work)

    def request_registration_evidence(self, originals, *, source_originals,
            verified_at, deadline_epoch_ns, work, deadline_ns=None):
        """Preserve the evidence/request/inputs result from one grant/exchange."""
        _, response, request, inputs = _EnrollmentOwner._request_registration_evidence_exchange(
            self, originals, source_originals=source_originals, verified_at=verified_at,
            deadline_epoch_ns=deadline_epoch_ns, work=work, deadline_ns=deadline_ns)
        return response[0], request, inputs

    def _request_registration_evidence_exchange(self, originals, *, source_originals,
            verified_at, deadline_epoch_ns, work, deadline_ns=None):
        """Issue once, exchange once, and retain exact request8/response2.

        Enrollment and source-acquisition authority remain caller prerequisites.
        The endpoint and configuration come only from this cold root-admitted
        owner; no browser/caller field can select them. This neither retries a
        grant/exchange nor performs custody or registration finalization.
        Returned derived fields never replace independent original replay.
        """
        _require_pid()
        with _LOCK:
            from serverware import webauthn
            from serverware import authority_webauthn_enrollment_issuer as issuer
            from serverware import authority_webauthn_registration_signer_client as client

            material, binding = self._material, self._binding
            if self._private_key is None or material is None or material.signer_endpoint is None:
                raise EnrollmentStartupError("registration evidence requests are disabled or closed")
            endpoint, digest = material.signer_endpoint, material.configuration_digest
            skew = material.issuer_policy["maximumClockSkewNs"]
            receipt_expiry = binding.attestation_interval[1]
            instant, deadline, original_deadline = verified_at, deadline_epoch_ns, deadline_ns
            if type(instant) is not datetime or instant.tzinfo is not timezone.utc:
                raise EnrollmentStartupError("evidence request requires the unchanged original UTC time")
            issuer.evidence.plan.contract._integer(deadline, minimum=1)
            if original_deadline is not None:
                issuer.evidence.plan.contract._integer(original_deadline, minimum=1)
            if type(source_originals) is not tuple or len(source_originals) != 4:
                raise EnrollmentStartupError("evidence request requires exact original source four")
            source = (client.wire.source_request._raw2(source_originals[0], source_originals[1])
                + client.wire.source_response._raw2(source_originals[2], source_originals[3]))
            if type(originals) is not webauthn._RegistrationOriginals:
                raise EnrollmentStartupError("evidence request requires the real original-input carrier")
            scope = originals.scope
            if type(scope) is not issuer.production.attestation.CeremonyScope:
                raise EnrollmentStartupError("evidence request requires the original ceremony scope")
            raw_client, raw_attestation, transports = issuer.authorization._originals(
                originals.client_data_json, originals.attestation_object, originals.transports)
            authorization_bytes = scope.authorization_json
            if (type(authorization_bytes) is not bytes
                    or not 2 <= len(authorization_bytes) <= issuer.authorization.MAX_BYTES
                    or sum(len(raw) for raw in source) + len(raw_client) + len(raw_attestation)
                        + client.wire.REQUEST_MINIMUMS[4] + client.wire.REQUEST_MINIMUMS[7]
                        > client.wire.MAX_BYTES):
                raise EnrollmentStartupError("evidence request originals exceed their fixed bounds")
            ledger = issuer.evidence.capture._SharedLedger(work)
            work.prepare_copy(transports)
            held = issuer.authorization._capture({"credentialId": originals.credential_id,
                "transports": list(transports), "challengeId": scope.challenge_id,
                "challenge": scope.challenge, "userId": scope.user_id, "label": scope.label,
                "rpId": originals.rp_id, "origin": originals.origin}, work)
            payload = issuer.configuration._ConfigurationCapture(ledger,
                maximum_bytes=issuer.authority.MAX_REQUEST_BYTES).visit(material.configuration_payload)
            generation = issuer.evidence.capture._JSONCapture(ledger).visit(material.generation)
            runtime = issuer.evidence.capture._JSONCapture(ledger,
                maximum_bytes=8192).visit(material.runtime_role_identities)
            held_endpoint = client.transport._endpoint(endpoint)
            work.prepare_copy(held["transports"])
            held_transports = tuple(held["transports"])
            # All original browser/source/configuration/cohort values and the
            # admitted endpoint are held before the first actual clock/native
            # callback. This single opening also charges preparation time.
            window = issuer.authorization.clock._open_on_work(
                deadline_epoch_ns=min(deadline, receipt_expiry),
                maximum_lifetime_ns=int(held_endpoint[1] * 1_000_000_000),
                maximum_clock_skew_ns=skew, work=work)
            clipped_deadline, monotonic_deadline = window[3], window[4]
            if original_deadline is not None:
                monotonic_deadline = min(monotonic_deadline, original_deadline)
            callback = issuer.evidence.production._callback
            callback(work, lambda: client.transport._check_deadline(monotonic_deadline))
            _live(self, work=work)
            issuer.authorization.clock._check_on_work(window, work=work)
            held_scope = issuer.production.attestation.CeremonyScope(
                held["challengeId"], held["challenge"], held["userId"], held["label"],
                authorization_bytes, _work=work)
            captured = webauthn._RegistrationOriginals(raw_client, raw_attestation,
                held["credentialId"], held_transports, held_scope, held["rpId"], held["origin"])
            request = _EnrollmentOwner.prepare_registration_signer_request(self, captured,
                source_originals=source, verified_at=instant,
                deadline_epoch_ns=clipped_deadline, work=work)
            issuer.authorization.clock._check_on_work(window, work=work)
            callback(work, lambda: client.transport._check_deadline(monotonic_deadline))
            result = client._request_exchange_on_configuration(payload=payload,
                configuration_digest=digest, generation=generation,
                runtime_role_identities=runtime, endpoint=held_endpoint,
                request_originals=request, deadline_ns=monotonic_deadline, work=work)
            _live(self, work=work)
            issuer.authorization.clock._check_on_work(window, work=work)
            callback(work, lambda: client.transport._check_deadline(monotonic_deadline))
            return result

    def prepare_registration_signer_request(self, originals, *, source_originals,
            verified_at, deadline_epoch_ns, work):
        """Issue the real grant and frame raw eight, without sending anything.

        The actual authenticated application must have admitted enrollment
        before this call. Source-four framing checks are not source signature,
        root or membership admission. No endpoint, retry, new evaluation time,
        approval consumption or finalization authority is introduced here.
        """
        _require_pid()
        with _LOCK:
            from serverware import webauthn
            from serverware import authority_webauthn_enrollment_issuer as issuer
            from serverware import authority_webauthn_registration_signer_wire as wire

            if self._private_key is None or self._material is None:
                raise EnrollmentStartupError("enrollment authorization is disabled or closed")
            if type(source_originals) is not tuple or len(source_originals) != 4:
                raise EnrollmentStartupError("signer preparation requires exact original source four")
            source = (wire.source_request._raw2(source_originals[0], source_originals[1])
                + wire.source_response._raw2(source_originals[2], source_originals[3]))
            if type(originals) is not webauthn._RegistrationOriginals:
                raise EnrollmentStartupError("signer preparation requires the real original-input carrier")
            scope = originals.scope
            if type(scope) is not issuer.production.attestation.CeremonyScope:
                raise EnrollmentStartupError("signer preparation requires the original ceremony scope")
            raw_client, raw_attestation, transports = issuer.authorization._originals(
                originals.client_data_json, originals.attestation_object, originals.transports)
            authorization_bytes = scope.authorization_json
            instant, deadline = verified_at, deadline_epoch_ns
            if type(instant) is not datetime or instant.tzinfo is not timezone.utc:
                raise EnrollmentStartupError("signer preparation requires the unchanged original UTC time")
            issuer.evidence.plan.contract._integer(deadline, minimum=1)
            if (type(authorization_bytes) is not bytes
                    or not 2 <= len(authorization_bytes) <= issuer.authorization.MAX_BYTES
                    or sum(len(raw) for raw in source) + len(raw_client) + len(raw_attestation)
                        + wire.REQUEST_MINIMUMS[4] + wire.REQUEST_MINIMUMS[7] > wire.MAX_BYTES):
                raise EnrollmentStartupError("signer preparation originals exceed their fixed bounds")
            issuer.evidence.capture._SharedLedger(work)
            work.prepare_copy(transports)
            held = issuer.authorization._capture({"credentialId": originals.credential_id,
                "transports": list(transports), "challengeId": scope.challenge_id,
                "challenge": scope.challenge, "userId": scope.user_id, "label": scope.label,
                "rpId": originals.rp_id, "origin": originals.origin}, work)
            work.prepare_copy(held["transports"])
            held_transports = tuple(held["transports"])
            # Every source/browser byte reference, scalar and ceremony member
            # is now held before the actual core constructor's JSON callback.
            held_scope = issuer.production.attestation.CeremonyScope(
                held["challengeId"], held["challenge"], held["userId"], held["label"],
                authorization_bytes, _work=work)
            captured = webauthn._RegistrationOriginals(raw_client, raw_attestation,
                held["credentialId"], held_transports, held_scope, held["rpId"], held["origin"])
            grant = _EnrollmentOwner.issue_registration(self, captured,
                verified_at=instant, deadline_epoch_ns=deadline, work=work)
            result = wire._produce_request_on_work(source_originals=source,
                enrollment_authorization_bytes=grant, client_data_json=raw_client,
                attestation_object=raw_attestation, credential_id=held["credentialId"],
                transports=held_transports, verified_at=instant, work=work)
            _live(self, work=work)
            return result

    def issue_registration(self, originals, *, verified_at, deadline_epoch_ns, work):
        """Bind real authenticated app admission, not arbitrary browser claims."""
        _require_pid()
        with _LOCK:
            # Hold all original fields and configured graphs before decoder,
            # clock, descriptor, key or issuer callbacks. No raw carrier is
            # accepted as proof of its caller's authentication/authorization.
            from serverware import webauthn
            from serverware import authority_webauthn_enrollment_issuer as issuer

            material, signer, binding = self._material, self._private_key, self._binding
            if signer is None or material is None:
                raise EnrollmentStartupError("enrollment authorization is disabled or closed")
            if type(originals) is not webauthn._RegistrationOriginals:
                raise EnrollmentStartupError("enrollment requires the real original-input carrier")
            scope = originals.scope
            if type(scope) is not issuer.production.attestation.CeremonyScope:
                raise EnrollmentStartupError("enrollment requires the original ceremony scope")
            raw_client, raw_attestation, transports = issuer.authorization._originals(
                originals.client_data_json, originals.attestation_object, originals.transports)
            authorization_bytes = scope.authorization_json
            instant, deadline = verified_at, deadline_epoch_ns
            if type(instant) is not datetime or instant.tzinfo is not timezone.utc:
                raise EnrollmentStartupError("enrollment requires the unchanged original UTC evaluation time")
            issuer.evidence.plan.contract._integer(deadline, minimum=1)
            if (type(authorization_bytes) is not bytes
                    or not 2 <= len(authorization_bytes) <= issuer.authorization.MAX_BYTES):
                raise EnrollmentStartupError("enrollment authorization originals exceed their bounds")
            ledger = issuer.evidence.capture._SharedLedger(work)
            work.prepare_copy(transports)
            inputs = issuer.authorization._capture({"credentialId": originals.credential_id,
                "transports": list(transports), "userId": scope.user_id, "label": scope.label,
                "challengeId": scope.challenge_id, "rpId": originals.rp_id,
                "origin": originals.origin}, work)
            payload = issuer.configuration._ConfigurationCapture(ledger,
                maximum_bytes=issuer.authority.MAX_REQUEST_BYTES).visit(material.configuration_payload)
            generation = issuer.evidence.capture._JSONCapture(ledger).visit(material.generation)
            runtime = issuer.evidence.capture._JSONCapture(ledger,
                maximum_bytes=8192).visit(material.runtime_role_identities)
            digest = material.configuration_digest
            effective_deadline = min(deadline, binding.attestation_interval[1])
            _live(self, work=work)
            authorization = issuer.evidence.wire._decode_object(authorization_bytes, work=work,
                maximum_bytes=issuer.authorization.MAX_BYTES,
                maximum_nodes=issuer.authorization.MAX_NODES,
                maximum_depth=issuer.authorization.MAX_DEPTH)
            authorization = issuer.authorization._capture(authorization, work)
            issuer.evidence.capability._canonical(authorization_bytes, authorization, ledger,
                issuer.authorization.MAX_BYTES, issuer.authorization.MAX_NODES)
            issuer.evidence.plan._same((inputs["rpId"], inputs["origin"]),
                (payload["webauthn"]["rpId"], payload["webauthn"]["origin"]), work,
                "enrollment originals differ from the admitted RP/origin")
            session_id = authorization.get("session_id") if authorization.get("mode") == "oidc-session-first-enrollment" else None
            work.prepare_copy(inputs["transports"])
            held_transports = tuple(inputs["transports"])
            _live(self, work=work)
            result = issuer._produce_on_configuration(payload=payload,
                configuration_digest=digest, generation=generation, runtime_role_identities=runtime,
                enrollment_private_key=signer, client_data_json=raw_client,
                attestation_object=raw_attestation, credential_id=inputs["credentialId"],
                transports=held_transports, user_id=inputs["userId"], label=inputs["label"],
                expected_authorization=authorization, registration_challenge_id=inputs["challengeId"],
                oidc_session_id=session_id, verified_at=instant,
                deadline_epoch_ns=effective_deadline, work=work)
            _live(self, work=work)
            return result


def initialize_from_environment():
    """Admit once after custody startup; failure/shutdown never permits retry."""
    global _state, _namespace, _identity_at_start, _owner
    _require_pid()
    with _LOCK:
        if _state in ("started", "disabled"):
            return require_started()
        if _state != "new":
            raise EnrollmentStartupError("enrollment startup cannot repeat after failure or shutdown")
        namespace = _environment()
        identity = (os.geteuid(), os.getegid())
        _namespace, _identity_at_start, _state = namespace, identity, "initializing"
        try:
            if _development(namespace):
                _state = "disabled"
                return None
            descriptor = _descriptor(namespace)
            from serverware import control_plane_custody_client as client
            from serverware import control_plane_custody_startup as custody
            from serverware import control_plane_enrollment_bootstrap as bootstrap
            from serverware import authority_webauthn_enrollment_issuer as issuer
            from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

            custody_owner = custody.require_started()
            binding = client._snapshot(custody_owner)
            root_key, inventory, digest = (binding.runtime_root_public_key,
                binding.inherited_descriptors, binding.configuration_digest)
            if type(inventory) is not tuple or descriptor not in inventory:
                raise EnrollmentStartupError("enrollment bootstrap was not in the root-admitted inherited inventory")
            client._receipt_now(binding)
            original, original_identity = _read_original(descriptor, private=False)
            work = _ValidationWork(QueryReadValidationLimits())
            material = bootstrap._admit_on_work(bootstrap_bytes=original,
                runtime_root_public_key=root_key, expected_configuration_digest=digest, work=work)
            key_fd, policy, public_key = (material.issuer_private_key_fd,
                material.issuer_policy, material.issuer_public_key)
            key, key_identity, response_path, response_pin = None, None, None, None
            execution_key, execution_fd, execution_identity = None, None, None
            finalization_key, finalization_fd, finalization_identity = None, None, None
            activation_key, activation_fd, activation_identity = None, None, None
            consume_key, consume_fd, consume_identity = None, None, None
            if material.release_client is not None and identity != (65532, 65532):
                raise EnrollmentStartupError("release caller requires the fixed control-plane identity")
            if (material.finalization_slot_reserved and material.finalization is None
                    and 204 in inventory):
                raise EnrollmentStartupError("disabled v4 finalization forbids its reserved inherited key slot")
            if material.finalization_slot_reserved and material.finalization is None:
                try:
                    fcntl.fcntl(204, fcntl.F_GETFD)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    raise EnrollmentStartupError("disabled v4 finalization has an undeclared open key slot")
            if material.activation_slot_reserved and material.activation_execution is None:
                if 205 in inventory:
                    raise EnrollmentStartupError("disabled v6 activation forbids its reserved inherited key slot")
                try:
                    fcntl.fcntl(205, fcntl.F_GETFD)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    raise EnrollmentStartupError("disabled v6 activation has an undeclared open key slot")
            if material.consume_slot_reserved and key_fd == 206:
                raise EnrollmentStartupError("v8 reserves the consume caller slot independently of issuer policy")
            if material.consume_slot_reserved and material.consume_execution is None:
                if 206 in inventory:
                    raise EnrollmentStartupError("disabled v8 consume forbids its reserved inherited key slot")
                try:
                    fcntl.fcntl(206, fcntl.F_GETFD)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
                else:
                    raise EnrollmentStartupError("disabled v8 consume has an undeclared open key slot")
            if policy is None:
                if key_fd is not None or public_key is not None:
                    raise EnrollmentStartupError("disabled enrollment bootstrap contains issuer key material")
            else:
                issuer_pin = policy["signingSpkiDigest"]
                if (type(key_fd) is not int or not 32 <= key_fd <= 1023
                        or key_fd == descriptor or key_fd not in inventory):
                    raise EnrollmentStartupError("enrollment issuer key is not a distinct admitted inherited FD")
                raw_key, key_identity = _read_original(key_fd, private=True)
                if (not raw_key.startswith(b"-----BEGIN PRIVATE KEY-----\n")
                        or not raw_key.endswith(b"-----END PRIVATE KEY-----\n")):
                    raise EnrollmentStartupError("enrollment issuer key must be fixed unencrypted PKCS8 PEM")
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                from serverware import response_identity

                response_path = response_identity.RESPONSE_SIGNING_KEY_PATH
                work.charge(input_bytes=len(raw_key))
                key = issuer.evidence.production._callback(work,
                    lambda: serialization.load_pem_private_key(raw_key, password=None))
                if not isinstance(key, Ed25519PrivateKey):
                    raise EnrollmentStartupError("enrollment issuer key is not Ed25519")
                issuer.evidence.keys._pair_on_work(key, public_key, work)
                issuer.evidence.keys._public_binding(public_key, issuer_pin, work)
                # Read only the already provisioned response key. Never invoke
                # its generating loader or any response-identity publication.
                response_pin = _response_spki(response_path, identity[0], work)
                if response_pin == issuer_pin:
                    raise EnrollmentStartupError("enrollment issuer and actual HTTP response key must differ")
            if material.execution is not None:
                execution = material.execution
                execution_fd = execution.caller_private_key_fd
                if (identity != (65532, 65532) or policy is None or key is None
                        or execution_fd != 203 or execution_fd in (descriptor, key_fd)
                        or execution_fd not in inventory):
                    raise EnrollmentStartupError("execution caller key requires its distinct original admitted slot")
                execution_raw, execution_identity = _read_original(execution_fd, private=True)
                if (not execution_raw.startswith(b"-----BEGIN PRIVATE KEY-----\n")
                        or not execution_raw.endswith(b"-----END PRIVATE KEY-----\n")):
                    raise EnrollmentStartupError("execution caller key must be unencrypted PKCS8 PEM")
                work.charge(input_bytes=len(execution_raw))
                execution_key = issuer.evidence.production._callback(work,
                    lambda: serialization.load_pem_private_key(execution_raw, password=None))
                del execution_raw
                if not isinstance(execution_key, Ed25519PrivateKey):
                    raise EnrollmentStartupError("execution caller key must be Ed25519")
                issuer.evidence.keys._pair_on_work(execution_key, execution.caller_public_key, work)
                execution_pin = issuer.evidence.keys._spki_on_work(execution.caller_public_key, work)
                if execution_pin in (issuer_pin, response_pin):
                    raise EnrollmentStartupError("execution caller key reuses an enrollment or HTTP response key")
            if material.finalization is not None:
                finalization = material.finalization
                finalization_fd = finalization.caller_private_key_fd
                if (identity != (65532, 65532) or policy is None or key is None
                        or not material.finalization_slot_reserved
                        or finalization_fd != 204 or finalization_fd in (descriptor, key_fd, execution_fd)
                        or finalization_fd not in inventory):
                    raise EnrollmentStartupError("finalization caller key requires its distinct original admitted slot")
                finalization_raw, finalization_identity = _read_original(finalization_fd, private=True)
                if (not finalization_raw.startswith(b"-----BEGIN PRIVATE KEY-----\n")
                        or not finalization_raw.endswith(b"-----END PRIVATE KEY-----\n")):
                    raise EnrollmentStartupError("finalization caller key must be unencrypted PKCS8 PEM")
                work.charge(input_bytes=len(finalization_raw))
                finalization_key = issuer.evidence.production._callback(work,
                    lambda: serialization.load_pem_private_key(finalization_raw, password=None))
                del finalization_raw
                if not isinstance(finalization_key, Ed25519PrivateKey):
                    raise EnrollmentStartupError("finalization caller key must be Ed25519")
                issuer.evidence.keys._pair_on_work(finalization_key, finalization.caller_public_key, work)
                finalization_pin = issuer.evidence.keys._spki_on_work(finalization.caller_public_key, work)
                if finalization_pin in (issuer_pin, response_pin,
                        None if execution_key is None else execution_pin):
                    raise EnrollmentStartupError("finalization caller key reuses another retained purpose key")
            if material.activation_execution is not None:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                from serverware import response_identity

                activation = material.activation_execution
                activation_fd = activation.caller_private_key_fd
                if (identity != (65532, 65532) or not material.activation_slot_reserved
                        or activation_fd != 205
                        or activation_fd in (descriptor, key_fd, execution_fd, finalization_fd)
                        or activation_fd not in inventory):
                    raise EnrollmentStartupError("activation caller key requires its distinct admitted slot")
                activation_raw, activation_identity = _read_original(activation_fd, private=True)
                if (not activation_raw.startswith(b"-----BEGIN PRIVATE KEY-----\n")
                        or not activation_raw.endswith(b"-----END PRIVATE KEY-----\n")):
                    raise EnrollmentStartupError("activation caller key must be unencrypted PKCS8 PEM")
                work.charge(input_bytes=len(activation_raw))
                activation_key = issuer.evidence.production._callback(work,
                    lambda: serialization.load_pem_private_key(activation_raw, password=None))
                del activation_raw
                if not isinstance(activation_key, Ed25519PrivateKey):
                    raise EnrollmentStartupError("activation caller key must be Ed25519")
                issuer.evidence.keys._pair_on_work(activation_key, activation.caller_public_key, work)
                activation_pin = issuer.evidence.keys._spki_on_work(activation.caller_public_key, work)
                if response_path is None:
                    response_path = response_identity.RESPONSE_SIGNING_KEY_PATH
                    response_pin = _response_spki(response_path, identity[0], work)
                if activation_pin in (response_pin,
                        None if key is None else issuer_pin,
                        None if execution_key is None else execution_pin,
                        None if finalization_key is None else finalization_pin):
                    raise EnrollmentStartupError("activation caller key reuses another retained purpose key")
            if material.consume_execution is not None:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

                consume = material.consume_execution
                consume_fd = consume.caller_private_key_fd
                if (identity != (65532, 65532) or not material.consume_slot_reserved
                        or material.activation_execution is None or activation_key is None
                        or material.activation_planning is None or response_pin is None
                        or consume_fd != 206
                        or consume_fd in (descriptor, key_fd, execution_fd, finalization_fd, activation_fd)
                        or consume_fd not in inventory):
                    raise EnrollmentStartupError("consume caller key requires its distinct admitted slot and activation context")
                consume_raw, consume_identity = _read_original(consume_fd, private=True)
                if (not consume_raw.startswith(b"-----BEGIN PRIVATE KEY-----\n")
                        or not consume_raw.endswith(b"-----END PRIVATE KEY-----\n")):
                    raise EnrollmentStartupError("consume caller key must be unencrypted PKCS8 PEM")
                work.charge(input_bytes=len(consume_raw))
                consume_key = issuer.evidence.production._callback(work,
                    lambda: serialization.load_pem_private_key(consume_raw, password=None))
                del consume_raw
                if not isinstance(consume_key, Ed25519PrivateKey):
                    raise EnrollmentStartupError("consume caller key must be Ed25519")
                issuer.evidence.keys._pair_on_work(consume_key, consume.caller_public_key, work)
                consume_pin = issuer.evidence.keys._spki_on_work(consume.caller_public_key, work)
                if consume_pin in (response_pin, activation_pin,
                        None if key is None else issuer_pin,
                        None if execution_key is None else execution_pin,
                        None if finalization_key is None else finalization_pin):
                    raise EnrollmentStartupError("consume caller key reuses another retained purpose key")
            if (material.configuration_digest != digest or _environment() != namespace
                    or (os.geteuid(), os.getegid()) != identity
                    or _descriptor_identity(descriptor, private=False) != original_identity
                    or key_fd is not None and _descriptor_identity(key_fd, private=True) != key_identity
                    or execution_fd is not None and _descriptor_identity(
                        execution_fd, private=True) != execution_identity
                    or finalization_fd is not None and _descriptor_identity(
                        finalization_fd, private=True) != finalization_identity
                    or activation_fd is not None and _descriptor_identity(
                        activation_fd, private=True) != activation_identity
                    or consume_fd is not None and _descriptor_identity(
                        consume_fd, private=True) != consume_identity
                    or custody.require_started() is not custody_owner
                    or client._snapshot(custody_owner) is not binding):
                raise EnrollmentStartupError("enrollment startup inputs changed during admission")
            client._receipt_now(binding)
            owner = object.__new__(_EnrollmentOwner)
            owner._material, owner._private_key = material, key
            owner._custody, owner._binding = custody_owner, binding
            owner._bootstrap_fd, owner._bootstrap_identity = descriptor, original_identity
            owner._key_fd, owner._key_identity, owner._closed = key_fd, key_identity, False
            owner._execution_key, owner._execution_key_fd = execution_key, execution_fd
            owner._execution_key_identity = execution_identity
            owner._finalization_key, owner._finalization_key_fd = finalization_key, finalization_fd
            owner._finalization_key_identity = finalization_identity
            owner._activation_key, owner._activation_key_fd = activation_key, activation_fd
            owner._activation_key_identity, owner._activation_permission = activation_identity, None
            owner._consume_key, owner._consume_key_fd = consume_key, consume_fd
            owner._consume_key_identity = consume_identity
            owner._release_spent = False
            owner._response_path, owner._response_pin = response_path, response_pin
            _owner, _state = owner, "started"
            return owner
        except BaseException:
            _owner, _state = None, "failed"
            # Borrowed inherited descriptors and the custody owner belong to
            # their existing lifecycles; this owner never closes or mutates them.
            raise


def require_started():
    """Return an admitted owner; no lazy startup or trust renewal is allowed."""
    _require_pid()
    with _LOCK:
        namespace = _environment()
        if _state == "new" and _development(namespace):
            return None
        if (_state not in ("started", "disabled") or namespace != _namespace
                or (os.geteuid(), os.getegid()) != _identity_at_start):
            raise EnrollmentStartupError("enrollment requires unchanged cold startup admission")
        if _state == "disabled":
            if not _development(namespace) or _owner is not None:
                raise EnrollmentStartupError("enrollment development opt-out is inconsistent")
            return None
        owner = _owner
        _live(owner)
        return owner


def close():
    """Release this PID's retained key references, never borrowed descriptors."""
    global _state, _owner
    _require_pid()
    with _LOCK:
        if _state == "closed":
            return
        if _state == "initializing":
            raise EnrollmentStartupError("enrollment cannot close during admission")
        owner = _owner
        _owner, _state = None, "closed"
        if owner is not None:
            owner._closed = True
            owner._release_spent = True
            owner._private_key, owner._material = None, None
            owner._execution_key = None
            owner._finalization_key = None
            owner._activation_key, owner._activation_permission = None, None
            owner._consume_key = None
