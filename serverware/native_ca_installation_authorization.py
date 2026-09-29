"""Independent root-signed local native CA installation authorization originals.

This module verifies/produces the permission record, not a completed install or
an authority-bearing Python receipt. The actual installer must independently
verify this original and join genuine same-connection native evidence, setup,
protected token, host/namespace owner and destination before any effect.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from serverware import native_enrollment_assignment as assignment
from serverware import native_enrollment_bootstrap_setup as setup
from serverware import workload_identity_issuer_bootstrap as shared
from serverware_agent_trust import _workload_signed_packet as packets


SCHEMA = "serverware.signedNativeCaInstallationAuthorization/v1"
PAYLOAD_SCHEMA = "serverware.nativeCaInstallationAuthorization/v1"
PURPOSE = "native-ca-installation"
MAX_BYTES = 32 * 1024
MAX_KEY_BYTES = 16 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
MAX_LIFETIME_NS = 300_000_000_000
_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "trustMode",
    "authorizationId", "setupSha256", "delegationSha256", "targetRequestSha256",
    "runtimeCaCertificateSha256", "runtimeCaSpkiSha256", "caInstall", "networkOwner",
    "machineIdSha256", "journal", "issuedAtEpochNs", "expiresAtEpochNs"})
_DIGEST_FIELDS = ("setupSha256", "delegationSha256", "targetRequestSha256",
    "runtimeCaCertificateSha256", "runtimeCaSpkiSha256", "machineIdSha256")


class NativeCaInstallationAuthorizationError(ValueError):
    pass


def _fail():
    raise NativeCaInstallationAuthorizationError("native CA installation authorization is invalid")


@dataclass(frozen=True, slots=True, repr=False)
class _InstallationAuthorizationMaterial:
    authorization_bytes: bytes
    authorization_digest: str
    payload_bytes: bytes
    root_pem_digest: str
    root_spki_digest: str
    authorization_id: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple
    deadline_ns: int
    live: object


def _preflight(originals, work, additional, *, producing=False):
    shared.clock.evidence.capture._SharedLedger(work)
    shared._integer(additional, MAX_ORIGINAL_BYTES)
    total = MAX_BYTES if producing else 0
    for raw, maximum in originals:
        shared._raw(raw, maximum)
        total += len(raw)
    if additional + 16 * total + 128 * 1024 > min(MAX_ORIGINAL_BYTES,
            work.limits.max_input_bytes - work.metrics.input_bytes):
        _fail()


def _journal(value):
    shared._object(value, {"path", "device", "inode", "namespace"})
    path = assignment._ascii(value["path"], 4096)
    parts = path[1:].split("/")
    if (not path.startswith("/") or path == "/" or "\\" in path or len(parts) > 64
            or any(part in ("", ".", "..") or len(part) > 255 for part in parts)):
        _fail()
    shared._integer(value["device"], minimum=1)
    shared._integer(value["inode"], minimum=1)
    shared._identifier(value["namespace"])


def _payload(value, budget):
    shared._object(value, _FIELDS)
    if (value["schema"] != PAYLOAD_SCHEMA
            or value["sourceRevision"] != shared.authority.SOURCE_REVISION
            or value["purpose"] != PURPOSE or value["trustMode"] != "trusted-host-local"):
        _fail()
    shared._identifier(value["authorizationId"])
    for name in _DIGEST_FIELDS:
        assignment._digest(value[name])
    capability_expiry = setup._install(value["caInstall"])
    setup._network_owner(value["networkOwner"])
    if value["networkOwner"]["ownerUid"] != 0:
        _fail()
    _journal(value["journal"])
    issued = shared._integer(value["issuedAtEpochNs"], minimum=1)
    expires = shared._integer(value["expiresAtEpochNs"], minimum=issued + 1)
    if expires - issued > MAX_LIFETIME_NS or expires > capability_expiry * 1_000_000:
        _fail()
    budget.interval(issued, expires)


def _admit(original, public, root_pin, budget):
    payload = shared._signed(original, SCHEMA, PAYLOAD_SCHEMA, public, MAX_BYTES, budget)
    _payload(payload, budget)
    result = _InstallationAuthorizationMaterial(
        authorization_bytes=original, authorization_digest=packets._digest(original, budget),
        payload_bytes=packets._canonical(payload, MAX_BYTES, budget), root_pem_digest=root_pin,
        root_spki_digest=packets._digest(shared._spki(public, budget), budget),
        authorization_id=payload["authorizationId"],
        issued_at_epoch_ns=payload["issuedAtEpochNs"], expires_at_epoch_ns=payload["expiresAtEpochNs"],
        window=budget.window, deadline_ns=budget.bound, live=budget.current)
    result.live()
    return result


def _verify_on_work(*, authorization_bytes, root_public_key_bytes, expected_root_pem_sha256,
        work, live_window, transport_deadline_ns, _current=None, _additional_original_bytes=0):
    """Genuine signed original only; no setup/session or installation verdict input."""
    try:
        _preflight(((authorization_bytes, MAX_BYTES), (root_public_key_bytes, MAX_KEY_BYTES)),
            work, _additional_original_bytes)
        budget = shared._Budget(work, live_window, transport_deadline_ns, _current)
        public = assignment._public_key(root_public_key_bytes, expected_root_pem_sha256, budget)
        return _admit(authorization_bytes, public, expected_root_pem_sha256, budget)
    except NativeCaInstallationAuthorizationError:
        raise
    except Exception:
        raise NativeCaInstallationAuthorizationError("native CA installation authorization verification failed") from None


def _produce_on_work(*, payload_bytes, root_private_key_bytes, root_public_key_bytes,
        expected_root_pem_sha256, work, live_window, transport_deadline_ns,
        _current=None, _additional_original_bytes=0):
    """Explicit protected canonical PKCS8 original; no files, key generation or network."""
    try:
        _preflight(((payload_bytes, MAX_BYTES), (root_private_key_bytes, MAX_KEY_BYTES),
            (root_public_key_bytes, MAX_KEY_BYTES)), work, _additional_original_bytes, producing=True)
        budget = shared._Budget(work, live_window, transport_deadline_ns, _current)
        public = assignment._public_key(root_public_key_bytes, expected_root_pem_sha256, budget)
        payload = shared._decode(payload_bytes, MAX_BYTES, budget)
        _payload(payload, budget)
        budget.charge(input_bytes=len(root_private_key_bytes))
        private = serialization.load_pem_private_key(root_private_key_bytes, password=None)
        budget.check()
        if (not isinstance(private, ed25519.Ed25519PrivateKey)
                or private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()) != root_private_key_bytes
                or shared._spki(private.public_key(), budget) != shared._spki(public, budget)):
            _fail()
        original = shared._produce(payload_bytes, SCHEMA, PAYLOAD_SCHEMA,
            private, public, MAX_BYTES, budget)
        admitted = _admit(original, public, expected_root_pem_sha256, budget)
        admitted.live()
        budget.check()
        return original
    except NativeCaInstallationAuthorizationError:
        raise
    except Exception:
        raise NativeCaInstallationAuthorizationError("native CA installation authorization production failed") from None
