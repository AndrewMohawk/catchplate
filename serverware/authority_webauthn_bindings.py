"""Original verifier-reader projections, without authority or registry imports.

These hashes bind content, not authorization. Callers retain full stored-row
shape, currentness and CAS checks; retention-only columns are not part of the
historical reader's assertion commitment.
"""
from __future__ import annotations

import hashlib
import json


CHALLENGE_FIELDS = ("id", "challenge", "challenge_type", "user_id", "scope_key",
    "approval_request_id", "payload_json", "expires_at", "used_at", "created_at")
CREDENTIAL_FIELDS = ("id", "credential_id", "user_id", "public_key_cose", "sign_count",
    "aaguid", "authenticator_class", "attestation_trusted", "attestation_leaf_sha256",
    "attestation_root_sha256", "attestation_trust_bundle_digest",
    "attestation_trust_bundle_sequence", "revoked_at")


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")


def challenge_row_digest(original, *, work=None):
    """Hash the exact ten selected columns with the original null-domain frame."""
    if work is not None:
        # Reserve a conservative full-input copy before building the projection;
        # the caller's complete retained row remains separately checked/held.
        work.prepare_copy(original)
    value = {name: original[name] for name in CHALLENGE_FIELDS}
    if work is not None:
        work.prepare_encoding(value)
    encoded = _canonical(value)
    if work is not None:
        work.charge(hashes=1)
    domain = b"serverware.policyAuthorityWebAuthnChallengeRow/v1"
    return "sha256:" + hashlib.sha256(domain + b"\x00"
        + len(encoded).to_bytes(8, "big") + encoded).hexdigest()


def credential_binding_digest(original):
    """The distinct pre-existing credential commitment length-frames its domain."""
    encoded = _canonical({name: original[name] for name in CREDENTIAL_FIELDS})
    domain = b"serverware.policyAuthorityWebAuthnCredentialBinding/v1"
    return "sha256:" + hashlib.sha256(len(domain).to_bytes(8, "big") + domain
        + len(encoded).to_bytes(8, "big") + encoded).hexdigest()
