"""One separately approved cold key-purpose signature with an existing key."""
from __future__ import annotations

import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from catchplate import native_pilot_genesis_key_profile as profile
from catchplate import native_shadow_nitro_originals as originals

p = profile.p
ROLES, OPERATIONS = profile.ROLES, profile.OPERATIONS
MAX_INPUT, MAX_OUTPUT = profile.MAX_INPUT, profile.MAX_OUTPUT
input_document, prepare_input, checked_result = profile.input_document, profile.prepare_input, profile.checked_result


def current(context, owner, previous_boot, previous_wall):
    p.require((os.getpid(), originals._start(), originals._boot()) == owner)
    now, wall = originals._clock(), time.time_ns()
    p.require(previous_boot <= now < context["deadline"] and previous_wall <= wall < context["epochLimit"])
    return now, wall


def sign(operation, role, input_original, signing_key):
    """No file IO, generated key, inferred approval, owner or renewed clock."""
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    owner = os.getpid(), originals._start(), originals._boot()
    now, wall = originals._clock(), time.time_ns()
    context = prepare_input(operation, role, input_original, boot=owner[2], now_boottime_ns=now, now_unix_ns=wall)
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == context["authorityKeys"][-1]["publicKeyBase64url"])
    before, epoch = current(context, owner, now, wall)
    message = profile.preimage(profile.DOMAINS[operation], context["payload"])
    signature = signing_key.sign(message)
    signing_key.public_key().verify(signature, message)
    raw = profile.g.canonical({"payload": context["payload"], "signature": p.encoded(signature)})
    p.require(len(raw) <= MAX_OUTPUT)
    after, later = current(context, owner, before, epoch)
    checked_result(operation, role, input_original, {"original": raw.decode("ascii"), "sha256": p.sha(raw)},
        boot=owner[2], now_boottime_ns=after, now_unix_ns=later)
    current(context, owner, after, later)
    return raw, context["deadline"]
