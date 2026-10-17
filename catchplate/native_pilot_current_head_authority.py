"""One separately approved checkpoint-authority current-head decision signature.

The caller must supply the genuine retained trust request and an independently
approved currentness decision; historical signatures alone authorize neither.
This entrypoint does not obtain an approval, receive a request, generate keys,
advance authority history, contact services or create replacement timestamps.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from catchplate import native_pilot_current_head_profile as profile
from catchplate import native_shadow_nitro_originals as originals

p = profile.p
MAX_INPUT = profile.MAX_INPUT
MAX_OUTPUT = profile.MAX_OUTPUT


def sign(*, input_original: bytes, signing_key, adopted=False) -> tuple[bytes, int]:
    p.require(type(input_original) is bytes and isinstance(signing_key, Ed25519PrivateKey))
    boot, now = originals._boot(), originals._clock()
    prepared = profile.prepare_input(input_original, boot=boot, now_boottime_ns=now, adopted=adopted)
    selected = prepared["authority"]
    public = profile.history_authority._key(selected)
    p.require(profile.history_authority._raw_key(signing_key.public_key())
        == profile.history_authority._raw_key(public))
    message = profile.signature_preimage(prepared["statement"], selected["keyId"], selected["keySpkiSha256"])
    p.require(originals._boot() == boot)
    before = originals._clock()
    p.require(now <= before < prepared["deadline"])
    signature = signing_key.sign(message)
    public.verify(signature, message)
    value = profile.envelope(prepared["statement"], selected["keyId"], selected["keySpkiSha256"], p.encoded(signature))
    raw = p.canonical(value)
    p.require(len(raw) <= MAX_OUTPUT)
    p.require(originals._boot() == boot)
    after = originals._clock()
    p.require(before <= after < prepared["deadline"])
    profile.checked_result(input_original, {"original": raw.decode("ascii"), "sha256": p.sha(raw)},
        boot=boot, now_boottime_ns=after, adopted=adopted)
    p.require(originals._boot() == boot)
    final = originals._clock()
    p.require(after <= final < prepared["deadline"])
    return raw, prepared["deadline"]
