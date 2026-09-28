"""Public-only, runtime-root-admitted configuration for one workload issuer.

Nested worker originals are genuinely admitted during cold processing. Their
startup live closure is never a long-lived request permission: later requests
use the retained originals under their own already-open work/window instead.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import workload_identity_issuer_bootstrap as issuer
from serverware_agent_trust import _workload_signed_packet as packets


SCHEMA = "serverware.signedControlPlaneWorkloadIdentityBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.controlPlaneWorkloadIdentityBootstrap/v1"
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


def _admit_on_work(*, bootstrap_bytes, runtime_root_public_key,
        expected_configuration_digest, expected_uid, expected_gid,
        live_window, transport_deadline_ns, work, _current=None):
    budget = issuer._Budget(work, live_window, transport_deadline_ns, _current)
    p = issuer._signed(bootstrap_bytes, SCHEMA, PAYLOAD_SCHEMA,
        runtime_root_public_key, MAX_BYTES, budget)
    issuer._object(p, _FIELDS)
    issuer._digest(expected_configuration_digest)
    issuer._integer(expected_uid, (1 << 32) - 2)
    issuer._integer(expected_gid, (1 << 32) - 2)
    fixed = {"purpose": "workload-identity-caller", "trustMode": "trusted-host-local",
        "processMode": "serverware-control-plane", "callerUid": expected_uid,
        "callerGid": expected_gid, "configurationDigest": expected_configuration_digest}
    if any(type(p[name]) is not type(value) or p[name] != value for name, value in fixed.items()):
        issuer._fail()
    budget.interval(p["issuedAtEpochNs"], p["expiresAtEpochNs"])
    start, end = p["issuedAtEpochNs"], p["expiresAtEpochNs"]
    if p["issuer"] is None:
        budget.check()
        return _CallerMaterial(bootstrap_bytes, expected_configuration_digest, False,
            None, None, None, None, None, None, None, issuer._MAX_TIMEOUT_NS,
            MAX_ORIGINAL_BYTES, start, end)
    profile = issuer._object(p["issuer"], _ISSUER_FIELDS)
    if (expected_uid, expected_gid) != (issuer.PEER_UID, issuer.PEER_GID):
        issuer._fail()
    root_bytes = issuer._wrapped(profile["root"], 1024, budget)
    root = packets._public_key(root_bytes, budget)
    worker_bytes = issuer._wrapped(profile["bootstrap"], issuer.MAX_BYTES, budget)
    worker = issuer._verify_on_work(bootstrap_bytes=worker_bytes, root_public_key=root,
        live_window=budget.window, transport_deadline_ns=budget.bound, work=work,
        _current=budget.current)
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
        timeout, maximum, start, end)


def _produce_on_work(*, payload_bytes, runtime_root_private_key, runtime_root_public_key,
        expected_configuration_digest, expected_uid, expected_gid, live_window,
        transport_deadline_ns, work, _current=None):
    budget = issuer._Budget(work, live_window, transport_deadline_ns, _current)
    raw = issuer._produce(payload_bytes, SCHEMA, PAYLOAD_SCHEMA, runtime_root_private_key,
        runtime_root_public_key, MAX_BYTES, budget)
    _admit_on_work(bootstrap_bytes=raw, runtime_root_public_key=runtime_root_public_key,
        expected_configuration_digest=expected_configuration_digest,
        expected_uid=expected_uid, expected_gid=expected_gid,
        live_window=budget.window, transport_deadline_ns=budget.bound,
        work=work, _current=budget.current)
    budget.check()
    return raw
