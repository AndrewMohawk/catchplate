"""Bounded startup binding for the writer's dedicated response-signing key.

The service must first admit its measured configuration and retained descriptor.
This inert helper parses original key bytes and checks public-key identities;
ordinary inputs or its returned key are not launch or signing-authority tokens.
It performs no signature, request admission, clock read, database operation or
ACK construction. Fixed bounded startup loading is outside request H/B/N work.
A descriptor-loaded host key is not proof of HSM/enclave custody.
"""
from __future__ import annotations

import hashlib
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


MAX_PRIVATE_BYTES = 64 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SPKI_PREFIX = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"


class RevocationWriterSignerError(ValueError):
    pass


def _digest(value):
    if type(value) is not str or len(value) != 71 or _DIGEST.fullmatch(value) is None:
        raise RevocationWriterSignerError("writer response signing pin is not a canonical digest")


def _public_spki_digest(key):
    if not isinstance(key, Ed25519PublicKey):
        raise RevocationWriterSignerError("writer response signing identity is not Ed25519")
    encoded = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if type(encoded) is not bytes or len(encoded) != 44 or not encoded.startswith(_SPKI_PREFIX):
        raise RevocationWriterSignerError("writer response signing SPKI is not canonical Ed25519")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _signer_from_pem(private_bytes, *, response_spki_digest,
        other_response_spki_digests, launch_public_key):
    """Return only the actual separately pinned key, without signing anything.

    The caller captures the writer pin, four other-role pins and actual launch
    public handle before descriptor access. Immutable byte/string/tuple inputs
    cannot be rebound through configuration aliases by key parser callbacks.
    This does not independently authenticate those pins or the launch handle.
    """
    if type(private_bytes) is not bytes or not 2 <= len(private_bytes) <= MAX_PRIVATE_BYTES:
        raise RevocationWriterSignerError("writer response signing key exceeds its original-byte bound")
    _digest(response_spki_digest)
    if type(other_response_spki_digests) is not tuple or len(other_response_spki_digests) != 4:
        raise RevocationWriterSignerError("writer response signing exclusions are not the four role pins")
    for pin in other_response_spki_digests:
        _digest(pin)
    if response_spki_digest in other_response_spki_digests:
        raise RevocationWriterSignerError("writer response signer reuses another authority role key")
    if not isinstance(launch_public_key, Ed25519PublicKey):
        raise RevocationWriterSignerError("writer launch identity is not an Ed25519 public key")
    try:
        private_key = serialization.load_pem_private_key(private_bytes, password=None)
    except (TypeError, ValueError) as exc:
        raise RevocationWriterSignerError("writer response signing key is not an unencrypted private PEM") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RevocationWriterSignerError("writer response signing key is not Ed25519")
    observed = _public_spki_digest(private_key.public_key())
    if observed != response_spki_digest:
        raise RevocationWriterSignerError("writer response signing key differs from the measured pin")
    if observed == _public_spki_digest(launch_public_key):
        raise RevocationWriterSignerError("writer response signer reuses the launch identity key")
    return private_key
