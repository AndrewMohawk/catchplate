"""Public-only, runtime-root-admitted configuration for one workload issuer.

Nested worker originals are genuinely admitted during cold processing. Their
startup live closure is never a long-lived request permission: later requests
use the retained originals under their own already-open work/window instead.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import workload_identity_issuer_bootstrap as issuer
from catchplate_agent_trust import _workload_signed_packet as packets


SCHEMA = "catchplate.signedControlPlaneWorkloadIdentityBootstrap/v1"
PAYLOAD_SCHEMA = "catchplate.controlPlaneWorkloadIdentityBootstrap/v1"
NATIVE_SCHEMA = "catchplate.signedControlPlaneWorkloadIdentityBootstrap/v2"
NATIVE_PAYLOAD_SCHEMA = "catchplate.controlPlaneWorkloadIdentityBootstrap/v2"
NATIVE_SERVICE_SCHEMA = "catchplate.signedControlPlaneWorkloadIdentityBootstrap/v3"
NATIVE_SERVICE_PAYLOAD_SCHEMA = "catchplate.controlPlaneWorkloadIdentityBootstrap/v3"
MAX_BYTES = 256 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "trustMode", "processMode",
    "callerUid", "callerGid", "configurationDigest", "issuedAtEpochNs", "expiresAtEpochNs", "issuer"})
_ISSUER_FIELDS = frozenset({"root", "bootstrap", "endpoint", "requestTimeoutNs", "maximumOriginalBytes"})
_ENDPOINT_FIELDS = frozenset({"path", "device", "inode", "uid", "gid", "mode", "serverUid", "serverGid"})


@dataclass(frozen=True, slots=True, repr=False)
class _CallerMaterial:
    original_bytes: bytes
    configuration_digest: str
    enabled: bool
    issuer_root_bytes: bytes | None
    issuer_root_public_key: object
    issuer_bootstrap_bytes: bytes | None
    issuer_material: object
    endpoint: str | None
    peer_uid: int | None
    peer_gid: int | None
    request_timeout_ns: int
    maximum_original_bytes: int
    valid_from_epoch_ns: int
    valid_until_epoch_ns: int
    profile: str = issuer.LEGACY_PROFILE


def _admit_on_work(*, bootstrap_bytes, runtime_root_public_key,
        expected_configuration_digest, expected_uid, expected_gid,
        live_window, transport_deadline_ns, work, _current=None):
    """Strict legacy caller admission; native originals cannot fall back here."""
    return _admit_profile_on_work(bootstrap_bytes=bootstrap_bytes,
        runtime_root_public_key=runtime_root_public_key,
        expected_configuration_digest=expected_configuration_digest,
        expected_uid=expected_uid, expected_gid=expected_gid, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, _current=_current,
        native_profile=False)


def _admit_native_on_work(*, bootstrap_bytes, runtime_root_public_key,
        expected_configuration_digest, expected_uid, expected_gid,
        live_window, transport_deadline_ns, work, _current=None):
    """Strict native caller admission under the actual runtime root original."""
    return _admit_profile_on_work(bootstrap_bytes=bootstrap_bytes,
        runtime_root_public_key=runtime_root_public_key,
        expected_configuration_digest=expected_configuration_digest,
        expected_uid=expected_uid, expected_gid=expected_gid, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, _current=_current,
        native_profile=True)


def _admit_native_service_on_work(*, bootstrap_bytes, runtime_root_public_key,
        expected_configuration_digest, expected_uid, expected_gid,
        live_window, transport_deadline_ns, work, _current=None):
    """Strict v3 caller and exact v3 issuer; no cross-version adoption."""
    return _admit_profile_on_work(bootstrap_bytes=bootstrap_bytes,
        runtime_root_public_key=runtime_root_public_key,
        expected_configuration_digest=expected_configuration_digest,
        expected_uid=expected_uid, expected_gid=expected_gid, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, _current=_current,
        native_profile=True, native_service=True)


def _admit_launch_on_work(*, bootstrap_bytes, runtime_root_public_key,
        expected_configuration_digest, expected_uid, expected_gid,
        live_window, transport_deadline_ns, work, _current=None):
    """Cold-only version selection; the selected verifier still checks all originals."""
    budget = issuer._Budget(work, live_window, transport_deadline_ns, _current)
    envelope = issuer._decode(bootstrap_bytes, MAX_BYTES, budget)
    issuer._object(envelope, {"schema", "payload", "signature"})
    if envelope["schema"] == SCHEMA:
        verifier = _admit_on_work
    elif envelope["schema"] == NATIVE_SCHEMA:
        verifier = _admit_native_on_work
    elif envelope["schema"] == NATIVE_SERVICE_SCHEMA:
        verifier = _admit_native_service_on_work
    else:
        issuer._fail()
    return verifier(bootstrap_bytes=bootstrap_bytes, runtime_root_public_key=runtime_root_public_key,
        expected_configuration_digest=expected_configuration_digest,
        expected_uid=expected_uid, expected_gid=expected_gid, live_window=budget.window,
        transport_deadline_ns=budget.bound, work=work, _current=budget.current)


def _admit_profile_on_work(*, bootstrap_bytes, runtime_root_public_key,
        expected_configuration_digest, expected_uid, expected_gid,
        live_window, transport_deadline_ns, work, _current, native_profile, native_service=False):
    if (type(native_profile) is not bool or type(native_service) is not bool
            or native_service and not native_profile):
        issuer._fail()
    budget = issuer._Budget(work, live_window, transport_deadline_ns, _current)
    schema = NATIVE_SERVICE_SCHEMA if native_service else NATIVE_SCHEMA if native_profile else SCHEMA
    payload_schema = (NATIVE_SERVICE_PAYLOAD_SCHEMA if native_service
        else NATIVE_PAYLOAD_SCHEMA if native_profile else PAYLOAD_SCHEMA)
    p = issuer._signed(bootstrap_bytes, schema, payload_schema,
        runtime_root_public_key, MAX_BYTES, budget)
    issuer._object(p, _FIELDS)
    issuer._digest(expected_configuration_digest)
    issuer._integer(expected_uid, (1 << 32) - 2)
    issuer._integer(expected_gid, (1 << 32) - 2)
    selected_profile = (issuer.NATIVE_SERVICE_PROFILE if native_service
        else issuer.NATIVE_PROFILE if native_profile else issuer.LEGACY_PROFILE)
    fixed = {"purpose": "native-workload-identity-caller" if native_profile else "workload-identity-caller",
        "trustMode": "trusted-host-local",
        "processMode": "catchplate-control-plane", "callerUid": expected_uid,
        "callerGid": expected_gid, "configurationDigest": expected_configuration_digest}
    if any(type(p[name]) is not type(value) or p[name] != value for name, value in fixed.items()):
        issuer._fail()
    budget.interval(p["issuedAtEpochNs"], p["expiresAtEpochNs"])
    start, end = p["issuedAtEpochNs"], p["expiresAtEpochNs"]
    if p["issuer"] is None:
        budget.check()
        return _CallerMaterial(bootstrap_bytes, expected_configuration_digest, False,
            None, None, None, None, None, None, None, issuer._MAX_TIMEOUT_NS,
            MAX_ORIGINAL_BYTES, start, end, selected_profile)
    profile = issuer._object(p["issuer"], _ISSUER_FIELDS)
    if (expected_uid, expected_gid) != (issuer.PEER_UID, issuer.PEER_GID):
        issuer._fail()
    root_bytes = issuer._wrapped(profile["root"], 1024, budget)
    root = packets._public_key(root_bytes, budget)
    worker_bytes = issuer._wrapped(profile["bootstrap"], issuer.MAX_BYTES, budget)
    verifier = (issuer._verify_native_service_on_work if native_service
        else issuer._verify_native_on_work if native_profile else issuer._verify_on_work)
    worker = verifier(bootstrap_bytes=worker_bytes, root_public_key=root,
        live_window=budget.window, transport_deadline_ns=budget.bound, work=work,
        _current=budget.current)
    if type(worker) is not issuer._IssuerMaterial or worker.profile != selected_profile:
        issuer._fail()
    issuer._enrollment_original_byte_count(worker)
    endpoint = issuer._object(profile["endpoint"], _ENDPOINT_FIELDS)
    expected = {"path": issuer.LISTENER_PATH,
        "device": worker.listener_path_device, "inode": worker.listener_path_inode,
        "uid": issuer.SERVICE_UID, "gid": issuer.PEER_GID, "mode": 0o660,
        # SO_PEERCRED names this profile's root systemd listener creator, not
        # the named socket owner or the accepted control-plane caller.
        "serverUid": 0, "serverGid": 0}
    if any(type(endpoint[name]) is not type(value) or endpoint[name] != value for name, value in expected.items()):
        issuer._fail()
    maximum = issuer._integer(profile["maximumOriginalBytes"], MAX_ORIGINAL_BYTES, 1)
    if maximum != MAX_ORIGINAL_BYTES:
        issuer._fail()
    timeout = issuer._integer(profile["requestTimeoutNs"],
        min(issuer._MAX_TIMEOUT_NS, worker.request_timeout_ns), 1)
    ca = worker.issuer_certificate.certificate
    start = max(start, worker.attestation_interval[0], int(ca.not_valid_before_utc.timestamp()) * 1_000_000_000)
    end = min(end, worker.attestation_interval[1], int(ca.not_valid_after_utc.timestamp()) * 1_000_000_000)
    budget.interval(start, end)
    worker.live()
    budget.check()
    return _CallerMaterial(bootstrap_bytes, expected_configuration_digest, True,
        root_bytes, root, worker_bytes, worker, issuer.LISTENER_PATH, 0, 0,
        timeout, maximum, start, end, selected_profile)


def _produce_on_work(*, payload_bytes, runtime_root_private_key, runtime_root_public_key,
        expected_configuration_digest, expected_uid, expected_gid, live_window,
        transport_deadline_ns, work, _current=None):
    return _produce_profile_on_work(payload_bytes=payload_bytes,
        runtime_root_private_key=runtime_root_private_key, runtime_root_public_key=runtime_root_public_key,
        expected_configuration_digest=expected_configuration_digest,
        expected_uid=expected_uid, expected_gid=expected_gid, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, _current=_current,
        native_profile=False)


def _produce_native_on_work(*, payload_bytes, runtime_root_private_key, runtime_root_public_key,
        expected_configuration_digest, expected_uid, expected_gid, live_window,
        transport_deadline_ns, work, _current=None):
    return _produce_profile_on_work(payload_bytes=payload_bytes,
        runtime_root_private_key=runtime_root_private_key, runtime_root_public_key=runtime_root_public_key,
        expected_configuration_digest=expected_configuration_digest,
        expected_uid=expected_uid, expected_gid=expected_gid, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, _current=_current,
        native_profile=True)


def _produce_native_service_on_work(*, payload_bytes, runtime_root_private_key, runtime_root_public_key,
        expected_configuration_digest, expected_uid, expected_gid, live_window,
        transport_deadline_ns, work, _current=None):
    return _produce_profile_on_work(payload_bytes=payload_bytes,
        runtime_root_private_key=runtime_root_private_key, runtime_root_public_key=runtime_root_public_key,
        expected_configuration_digest=expected_configuration_digest,
        expected_uid=expected_uid, expected_gid=expected_gid, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, _current=_current,
        native_profile=True, native_service=True)


def _produce_profile_on_work(*, payload_bytes, runtime_root_private_key, runtime_root_public_key,
        expected_configuration_digest, expected_uid, expected_gid, live_window,
        transport_deadline_ns, work, _current, native_profile, native_service=False):
    if (type(native_profile) is not bool or type(native_service) is not bool
            or native_service and not native_profile):
        issuer._fail()
    budget = issuer._Budget(work, live_window, transport_deadline_ns, _current)
    schema = NATIVE_SERVICE_SCHEMA if native_service else NATIVE_SCHEMA if native_profile else SCHEMA
    payload_schema = (NATIVE_SERVICE_PAYLOAD_SCHEMA if native_service
        else NATIVE_PAYLOAD_SCHEMA if native_profile else PAYLOAD_SCHEMA)
    raw = issuer._produce(payload_bytes, schema, payload_schema, runtime_root_private_key,
        runtime_root_public_key, MAX_BYTES, budget)
    verifier = (_admit_native_service_on_work if native_service
        else _admit_native_on_work if native_profile else _admit_on_work)
    verifier(bootstrap_bytes=raw, runtime_root_public_key=runtime_root_public_key,
        expected_configuration_digest=expected_configuration_digest,
        expected_uid=expected_uid, expected_gid=expected_gid,
        live_window=budget.window, transport_deadline_ns=budget.bound,
        work=work, _current=budget.current)
    budget.check()
    return raw
