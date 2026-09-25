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
    """Check the same cold owner and original receipt; never renew either."""
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
    client._receipt_now(owner._binding)
    if _descriptor_identity(owner._bootstrap_fd, private=False) != owner._bootstrap_identity:
        raise EnrollmentStartupError("enrollment bootstrap custody changed")
    if (owner._key_fd is not None
            and _descriptor_identity(owner._key_fd, private=True) != owner._key_identity):
        raise EnrollmentStartupError("enrollment issuer key custody changed")


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
        "_bootstrap_identity", "_key_fd", "_key_identity", "_response_path", "_response_pin", "_closed")

    def __init__(self):
        raise EnrollmentStartupError("enrollment owner requires fixed cold startup")

    @property
    def enabled(self):
        _live(self)
        return self._private_key is not None

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
            if (material.configuration_digest != digest or _environment() != namespace
                    or (os.geteuid(), os.getegid()) != identity
                    or _descriptor_identity(descriptor, private=False) != original_identity
                    or key_fd is not None and _descriptor_identity(key_fd, private=True) != key_identity
                    or custody.require_started() is not custody_owner
                    or client._snapshot(custody_owner) is not binding):
                raise EnrollmentStartupError("enrollment startup inputs changed during admission")
            client._receipt_now(binding)
            owner = object.__new__(_EnrollmentOwner)
            owner._material, owner._private_key = material, key
            owner._custody, owner._binding = custody_owner, binding
            owner._bootstrap_fd, owner._bootstrap_identity = descriptor, original_identity
            owner._key_fd, owner._key_identity, owner._closed = key_fd, key_identity, False
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
            owner._private_key, owner._material = None, None
