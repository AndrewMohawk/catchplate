"""Two independently approved endpoint authorization purposes, one key per call.

This software signer cannot establish independent approval, kernel provenance,
hardware key custody, provisioning or successful native admission. Its exact
public input must be independently approved before the matching sealed key is
made available; no challenge, authority or replacement window is generated.
"""
from __future__ import annotations

import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import native_pilot_key_profile as profile
from serverware import native_shadow_nitro_originals as originals

p = profile.p
ROLES = profile.ROLES
OPERATIONS = profile.OPERATIONS
MAX_INPUT = profile.MAX_INPUT
MAX_OUTPUT = profile.MAX_OUTPUT


def _current(context, boot, previous_boot, previous_wall):
    now = profile.c9._live(context["window"], previous_boot)
    wall = time.time_ns()
    p.require(originals._boot() == boot and previous_wall <= wall)
    payload = context["payload"]
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], wall)
    return now, wall


def sign(operation, role, input_original: bytes, signing_key) -> tuple[bytes, int]:
    """Return only the existing envelope and unchanged original startup bound."""
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    boot, before, wall = originals._boot(), originals._clock(), time.time_ns()
    context = profile.prepare_input(operation, role, input_original,
        boot=boot, now_boottime_ns=before, now_unix_ns=wall)
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == context["authorityKeys"][-1]["publicKeyBase64url"])
    payload = context["payload"]
    adopted = profile.input_document(input_original)["apiVersion"] == profile.ADOPTED_API
    message = profile.preimage(profile.DOMAINS[operation], payload, adopted=adopted)
    before, wall = _current(context, boot, before, wall)
    signature = signing_key.sign(message)
    signing_key.public_key().verify(signature, message)
    raw = profile.canonical({"payload": payload, "signature": p.encoded(signature)}, adopted=adopted)
    p.require(len(raw) <= MAX_OUTPUT)
    after, later = _current(context, boot, before, wall)
    profile.checked_result(operation, role, input_original,
        {"original": raw.decode("ascii"), "sha256": p.sha(raw)},
        boot=boot, now_boottime_ns=after, now_unix_ns=later)
    _current(context, boot, after, later)
    return raw, p.ns(context["window"]["startupDeadlineBoottimeNs"])
