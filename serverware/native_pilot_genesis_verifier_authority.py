"""Cold-only public verifier transport under the actual assigned supervisor.

No verifier, port, attestation or owner is created. The complete pair and
transport interval require independent approval; native admission separately
resolves the assigned verifier key at its real current checkpoint. Each cold
role has one source-fixed path, with no shared legacy-path fallback.
"""
from __future__ import annotations

import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_key_profile as keys
from serverware import native_pilot_genesis_key_authority as signer
from serverware import native_pilot_launch_publication as launch
from serverware import native_shadow_nitro_originals as originals

p = g.p
API = "serverware.nativePilotGenesisVerifierAuthorityInput/v1"
ROLES = keys.ROLES
DOMAIN = "serverware.nativeShadowVerifierTransport.signature/v1"
OUTPUT_API = "serverware.nativeShadowVerifierTransport/v1"
MAX_INPUT = 32 * 1024 * 1024
MAX_OUTPUT = 32768
PAIR_FIELDS = ("roleKeyInputOriginal", "roleKeyOriginal", "admissionInputOriginal", "admissionOriginal")
FIELDS = ("apiVersion", "role", *PAIR_FIELDS, "parentPort", "issuedAtUnixNanos", "expiresAtUnixNanos")
PATHS = {role: "/etc/serverware/native-pilot-inputs/native-" + role + "-verifier.json" for role in ROLES}


def input_document(raw):
    value = p.fields(p.document(raw, MAX_INPUT), FIELDS)
    p.require(value["apiVersion"] == API and value["role"] in ROLES)
    return value


def signature_preimage(payload):
    return (b"serverware.signedEnvelope/v1\0" + DOMAIN.encode("ascii")
        + b"\0serverware.canonicalJson/ascii-integer-v1\0" + g.canonical(payload))


def prepare_input(role, input_raw, *, boot, now_boottime_ns, now_unix_ns):
    value = input_document(input_raw)
    p.require(role in ROLES and value["role"] == role)
    pair_raws = [keys.original(value[name], keys.MAX_INPUT if name.endswith("InputOriginal") else keys.MAX_OUTPUT)
        for name in PAIR_FIELDS]
    pair = keys.admitted_pair(role, *pair_raws, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    authorization = pair["authorization"]["payload"]
    admission = pair["admissionAuthorization"]["payload"]
    supervisor, verifier = pair["authorityKeys"][-1], pair["authorityKeys"][-2]
    p.require(supervisor["role"] == "custody-supervisor-capability" and verifier["role"] == "custody-attestation-verifier")
    p.integer(value["parentPort"], minimum=1024, maximum=(1 << 32) - 2)
    issued, expires = value["issuedAtUnixNanos"], value["expiresAtUnixNanos"]
    p.freshness(issued, expires, now_unix_ns)
    for prior in (authorization, admission):
        p.require(prior["issuedAtUnixNanos"] <= issued < expires <= prior["expiresAtUnixNanos"])
    p.require(expires <= pair["epochLimit"])
    payload = {"apiVersion": "serverware.nativeShadowVerifierTransportAssignment/v1", "purpose": "public-shadow-nitro-verification",
        **{name: authorization[name] for name in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision", "guest",
            "fullKeySetRootSha256", "challengeBase64url", "trustCheckpointId", "revocationGeneration", "revocationRootSha256",
            "signingKeyId", "signingKeySpkiSha256")},
        "keyAuthorizationSha256": p.sha(pair_raws[1]), "verifierKeyId": verifier["keyId"],
        "verifierKeySpkiSha256": verifier["keySpkiSha256"], "verifierKeyMaterialSha256": verifier["keyMaterialSha256"],
        "parentPort": value["parentPort"], "issuedAtUnixNanos": issued, "expiresAtUnixNanos": expires}
    p.fields(payload, launch._VERIFIER)
    p.require(payload["signingKeyId"] == supervisor["keyId"] and payload["signingKeySpkiSha256"] == supervisor["keySpkiSha256"])
    deadline = pair["deadline"]
    epoch_limit = min(pair["epochLimit"], expires, issued + keys.binding.MAX_AGE + 1)
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch_limit
        and len(g.canonical(payload)) + len(OUTPUT_API) + 160 <= MAX_OUTPUT)
    return {"payload": payload, "pair": pair, "supervisor": supervisor, "window": pair["expectedScope"]["guest"],
        "deadline": deadline, "epochLimit": epoch_limit, "domain": DOMAIN, "apiVersion": OUTPUT_API, "path": PATHS[role]}


def checked_result(role, input_raw, result, *, boot, now_boottime_ns, now_unix_ns):
    checked = prepare_input(role, input_raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(result, ("original", "sha256"))
    raw = keys.original(result["original"], MAX_OUTPUT)
    value = p.fields(g.document(raw, MAX_OUTPUT), ("apiVersion", "authorization"))
    p.require(value["apiVersion"] == OUTPUT_API and result["sha256"] == p.sha(raw))
    signed = p.fields(value["authorization"], ("payload", "signature"))
    keys.same(signed["payload"], checked["payload"])
    p.public_key(checked["supervisor"]).verify(p.decoded(signed["signature"], size=64), signature_preimage(signed["payload"]))
    return raw


def sign(role, input_original, signing_key):
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    owner = os.getpid(), originals._start(), originals._boot()
    now, wall = originals._clock(), time.time_ns()
    checked = prepare_input(role, input_original, boot=owner[2], now_boottime_ns=now, now_unix_ns=wall)
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == checked["supervisor"]["publicKeyBase64url"])
    before, epoch = signer.current(checked, owner, now, wall)
    message = signature_preimage(checked["payload"])
    signature = signing_key.sign(message)
    signing_key.public_key().verify(signature, message)
    raw = g.canonical({"apiVersion": OUTPUT_API, "authorization": {"payload": checked["payload"], "signature": p.encoded(signature)}})
    p.require(len(raw) <= MAX_OUTPUT)
    after, later = signer.current(checked, owner, before, epoch)
    checked_result(role, input_original, {"original": raw.decode("ascii"), "sha256": p.sha(raw)},
        boot=owner[2], now_boottime_ns=after, now_unix_ns=later)
    signer.current(checked, owner, after, later)
    return raw, checked["deadline"]
