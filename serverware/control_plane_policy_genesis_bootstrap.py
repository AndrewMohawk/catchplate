"""Offline root-signed cold maintenance selection; never publication permission."""
from __future__ import annotations

import base64
import json
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "serverware.controlPlaneCustodyStartup/v3"
PROFILE = "finalized-genesis-file-maintenance-v1"
DOMAIN = b"serverware/control-plane-policy-genesis-maintenance/v1\0"
BASE_FIELDS = frozenset({"schema", "sourceRevision", "configurationDigest", "directoryFd",
    "device", "inode", "uid", "gid", "quotaBytes", "maximumRecords"})
FIELDS = BASE_FIELDS | {"policyFileGenesisMaintenance", "signature"}
SCOPE_FIELDS = frozenset({"profile", "genesisPreparationDigest", "genesisFinalizationDigest",
    "policyId", "sequence", "rollbackEpoch", "policyHash", "genesisDsnSha256", "issuedAtEpochNs", "expiresAtEpochNs"})
MAX_BYTES = 16384


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def require(value):
    if not value:
        raise ValueError("genesis maintenance cold authorization is not exact")


def _unsigned(document):
    require(type(document) is dict and set(document) == FIELDS and document["schema"] == SCHEMA)
    scope = document["policyFileGenesisMaintenance"]
    require(type(scope) is dict and set(scope) == SCOPE_FIELDS and scope["profile"] == PROFILE)
    for value in (document["configurationDigest"], *(scope[key] for key in
            ("genesisPreparationDigest", "genesisFinalizationDigest", "policyHash", "genesisDsnSha256"))):
        require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None)
    revision, policy_id = document["sourceRevision"], scope["policyId"]
    require(type(revision) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", revision) is not None
        and type(policy_id) is str and 1 <= len(policy_id.encode("utf-8")) <= 256)
    for key, low, high in (("directoryFd", 32, 1023), ("device", 0, 2**64 - 1), ("inode", 1, 2**64 - 1),
            ("uid", 0, 2**32 - 2), ("gid", 0, 2**32 - 2), ("quotaBytes", 1, 8 * 1024**3), ("maximumRecords", 1, 4096)):
        require(type(document[key]) is int and low <= document[key] <= high)
    for key in ("sequence", "rollbackEpoch", "issuedAtEpochNs", "expiresAtEpochNs"):
        require(type(scope[key]) is int and 1 <= scope[key] <= 2**63 - 1)
    require(0 < scope["expiresAtEpochNs"] - scope["issuedAtEpochNs"] <= 900_000_000_000
        and len(canonical(document)) <= MAX_BYTES)
    return {key: value for key, value in document.items() if key != "signature"}


def verify(document, *, runtime_root_public_key, configuration_digest, source_revision):
    unsigned = _unsigned(document)
    require(isinstance(runtime_root_public_key, Ed25519PublicKey)
        and unsigned["configurationDigest"] == configuration_digest and unsigned["sourceRevision"] == source_revision)
    signature = document["signature"]
    require(type(signature) is str and re.fullmatch(r"ed25519:[A-Za-z0-9_-]{86}", signature) is not None)
    raw = base64.b64decode((signature[8:] + "==").encode("ascii"), altchars=b"-_", validate=True)
    require(len(raw) == 64 and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == signature[8:])
    runtime_root_public_key.verify(raw, DOMAIN + canonical(unsigned))
    return dict(unsigned["policyFileGenesisMaintenance"])


def sign_configuration(configuration, maintenance, *, runtime_root_private_key):
    """Offline producer only; the online process never obtains this key."""
    require(type(configuration) is dict and set(configuration) == BASE_FIELDS
        and configuration["schema"] == "serverware.controlPlaneCustodyStartup/v1"
        and isinstance(runtime_root_private_key, Ed25519PrivateKey))
    document = {**configuration, "schema": SCHEMA, "policyFileGenesisMaintenance": dict(maintenance),
        "signature": "ed25519:" + "A" * 86}
    raw = runtime_root_private_key.sign(DOMAIN + canonical(_unsigned(document)))
    document["signature"] = "ed25519:" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    verify(document, runtime_root_public_key=runtime_root_private_key.public_key(),
        configuration_digest=configuration["configurationDigest"], source_revision=configuration["sourceRevision"])
    return document
