"""Explicit cold Closure/Assignment v6 over actual approved C9 originals.

The image pin is an independently approved identity, not a claim that Python
loaded the image. Native admission measures the immutable image and executed
guest. Only the coordinator has a measured-bootstrap/late-runtime split; the
two endpoint manifests retain exact static runtime binding.
"""
from __future__ import annotations

import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from catchplate import native_pilot_genesis_key_profile as keys
from catchplate import native_pilot_genesis_key_authority as signer
from catchplate import native_pilot_genesis_parent_authority as parent
from catchplate import native_shadow_nitro_originals as originals

p = keys.p
API = "catchplate.nativePilotGenesisClosureAuthorityInput/v1"
ROLES = keys.ROLES
MAX_INPUT = keys.MAX_INPUT
MAX_OUTPUT = 1024 * 1024
DOMAIN = "catchplate.nativeCustodyClosureAssignment.signature/v6"
PROFILE = "native-publication-genesis-closure-set-v2"
INPUT_FIELDS = ("apiVersion", "role", *keys.SOURCE_FIELDS, "policy")


def input_document(raw):
    value = p.fields(p.document(raw, MAX_INPUT), INPUT_FIELDS)
    p.require(value["apiVersion"] == API and value["role"] in ROLES)
    p.fields(value["policy"], ("issuedAtUnixNanos", "expiresAtUnixNanos"))
    return value


def prepare_input(role, input_raw, *, boot, now_boottime_ns, now_unix_ns):
    value = input_document(input_raw)
    p.require(value["role"] == role and role in ROLES)
    context = keys.source_context(role, value, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    row = value["policy"]
    epoch_limit = keys.require_interval(context, row["issuedAtUnixNanos"], row["expiresAtUnixNanos"], now_unix_ns)
    assignment = context["source"]["assignment"]
    supervisor, checkpoint = context["authorityKeys"][-1], context["trustCheckpoint"]
    payload = {"apiVersion": "catchplate.nativeCustodyClosureAssignment/v6", "purpose": "shadow-custody-closure-set-member",
        "profile": PROFILE, "assignmentId": assignment["payload"]["assignmentId"],
        "assignmentPayloadSha256": assignment["payloadSha256"], "assignmentRevision": assignment["payload"]["assignmentRevision"],
        "manifestSha256": context["manifest"]["manifestSha256"], "guest": context["guest"],
        "trustCheckpointId": checkpoint["checkpointId"], "revocationGeneration": checkpoint["revocationGeneration"],
        "revocationRootSha256": checkpoint["revocationRootSha256"], "issuedAtUnixNanos": row["issuedAtUnixNanos"],
        "expiresAtUnixNanos": row["expiresAtUnixNanos"], "signingKeyId": supervisor["keyId"],
        "signingKeySpkiSha256": supervisor["keySpkiSha256"], "guestRole": role,
        **{name: context["leaf"][name] for name in ("setRootSha256", "seccompSetRootSha256", "leafSha256")}}
    p.fields(payload, parent.ASSIGNMENT_FIELDS)
    result = {"apiVersion": "catchplate.nativeCustodyClosure/v6", "manifest": context["manifest"],
        "closureSet": context["source"]["closureSet"], "authorization": {"payload": payload, "signature": ""}}
    # Exact Ed25519 unpadded base64url size. The empty string is sizing only,
    # never an emitted or accepted signature/authority placeholder.
    p.require(len(keys.g.canonical(result)) + 86 <= MAX_OUTPUT)
    return {**context, "payload": payload, "epochLimit": epoch_limit, "result": result}


def checked_result(role, input_raw, result, *, boot, now_boottime_ns, now_unix_ns):
    context = prepare_input(role, input_raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(result, ("original", "sha256"))
    raw = keys.original(result["original"], MAX_OUTPUT)
    p.require(p.sha(raw) == result["sha256"])
    value = p.fields(keys.g.document(raw, MAX_OUTPUT), ("apiVersion", "manifest", "closureSet", "authorization"))
    for name in ("apiVersion", "manifest", "closureSet"):
        keys.same(value[name], context["result"][name])
    signed = p.fields(value["authorization"], ("payload", "signature"))
    keys.same(signed["payload"], context["payload"])
    p.public_key(context["authorityKeys"][-1]).verify(p.decoded(signed["signature"], size=64), keys.preimage(DOMAIN, context["payload"]))
    return raw


def sign(role, input_original, signing_key):
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    owner = os.getpid(), originals._start(), originals._boot()
    now, wall = originals._clock(), time.time_ns()
    context = prepare_input(role, input_original, boot=owner[2], now_boottime_ns=now, now_unix_ns=wall)
    raw_public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(raw_public) == context["authorityKeys"][-1]["publicKeyBase64url"])
    before, epoch = signer.current(context, owner, now, wall)
    message = keys.preimage(DOMAIN, context["payload"])
    signature = signing_key.sign(message)
    signing_key.public_key().verify(signature, message)
    value = context["result"]
    value["authorization"]["signature"] = p.encoded(signature)
    raw = keys.g.canonical(value)
    p.require(len(raw) <= MAX_OUTPUT)
    after, later = signer.current(context, owner, before, epoch)
    checked_result(role, input_original, {"original": raw.decode("ascii"), "sha256": p.sha(raw)},
        boot=owner[2], now_boottime_ns=after, now_unix_ns=later)
    signer.current(context, owner, after, later)
    return raw, context["deadline"]
