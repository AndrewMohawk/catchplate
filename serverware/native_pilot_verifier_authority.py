"""Purpose-fixed verifier transport for ten authenticated endpoint guests.

The complete public input must be independently approved before its matching
supervisor key is made available. This producer neither starts a verifier nor
claims Nitro attestation, live kernel provenance or hardware key custody. The
port and UNIX interval are supplied originals; no replacement window is made.
"""
from __future__ import annotations

import copy
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import native_pilot_key_profile as keys
from serverware import native_pilot_launch_publication as launch
from serverware import native_shadow_nitro_originals as originals

p = keys.p
ROLES = keys.ROLES
API = "serverware.nativePilotVerifierAuthorityInput/v1"
DOMAIN = "serverware.nativeShadowVerifierTransport.signature/v1"
MAX_INPUT = 32 * 1024 * 1024
MAX_OUTPUT = 32768
PAIR_FIELDS = ("roleKeyInputOriginal", "roleKeyOriginal", "admissionInputOriginal", "admissionOriginal")
INPUT_FIELDS = ("apiVersion", "role", *PAIR_FIELDS, "parentPort", "issuedAtUnixNanos", "expiresAtUnixNanos")


def prepare_input(role, input_raw, *, boot, now_boottime_ns, now_unix_ns) -> dict:
    """Authenticate the complete pair and derive the sole permitted payload."""
    p.require(role in ROLES)
    value = p.fields(p.document(input_raw, MAX_INPUT), INPUT_FIELDS)
    p.require(value["apiVersion"] == API and value["role"] == role)
    options = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    pair = [keys.c9._original(value[name], keys.MAX_INPUT if name.endswith("InputOriginal")
        else keys.MAX_OUTPUT)[0] for name in PAIR_FIELDS]
    admitted = keys.admitted_pair(role, *pair, **options)
    context = keys.prepare_input("admission", role, pair[2], **options)
    authorization = admitted["authorization"]["payload"]
    admission = admitted["admissionAuthorization"]["payload"]
    supervisor, verifier = admitted["authorityKeys"][-1], admitted["authorityKeys"][-2]
    p.integer(value["parentPort"], minimum=1024, maximum=(1 << 32) - 2)
    issued, expires = value["issuedAtUnixNanos"], value["expiresAtUnixNanos"]
    p.freshness(issued, expires, now_unix_ns)
    for prior in (authorization, admission):
        p.require(prior["issuedAtUnixNanos"] <= issued < expires <= prior["expiresAtUnixNanos"])
    payload = {"apiVersion": "serverware.nativeShadowVerifierTransportAssignment/v1",
        "purpose": "public-shadow-nitro-verification",
        **{name: authorization[name] for name in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision",
            "guest", "fullKeySetRootSha256", "challengeBase64url", "trustCheckpointId", "revocationGeneration",
            "revocationRootSha256", "signingKeyId", "signingKeySpkiSha256")},
        "keyAuthorizationSha256": p.sha(pair[1]), "verifierKeyId": verifier["keyId"],
        "verifierKeySpkiSha256": verifier["keySpkiSha256"],
        "verifierKeyMaterialSha256": verifier["keyMaterialSha256"], "parentPort": value["parentPort"],
        "issuedAtUnixNanos": issued, "expiresAtUnixNanos": expires}
    p.fields(payload, launch._VERIFIER)
    p.require(payload["signingKeyId"] == supervisor["keyId"]
        and payload["signingKeySpkiSha256"] == supervisor["keySpkiSha256"])
    return copy.deepcopy({"payload": payload, "supervisor": supervisor, "window": context["window"],
        "deadline": p.ns(context["window"]["startupDeadlineBoottimeNs"]),
        "epochLimit": min(authorization["expiresAtUnixNanos"], admission["expiresAtUnixNanos"]), "domain": DOMAIN})


def checked_result(role, input_raw, result, *, boot, now_boottime_ns, now_unix_ns) -> bytes:
    """Verify exact original bytes, closed existing wire and actual authority."""
    context = prepare_input(role, input_raw, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(result, ("original", "sha256"))
    raw, value = keys.c9._original(result["original"], MAX_OUTPUT)
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    launch.shape("native-" + role + "-verifier", raw)
    signed = value["authorization"]
    keys.c9._same(signed["payload"], context["payload"])
    p.public_key(context["supervisor"]).verify(p.decoded(signed["signature"], size=64),
        p.preimage(DOMAIN, context["payload"]))
    return raw


def _current(context, boot, previous_boot, previous_wall):
    now = keys.c9._live(context["window"], previous_boot)
    wall = time.time_ns()
    p.require(originals._boot() == boot and previous_wall <= wall < context["epochLimit"])
    p.freshness(context["payload"]["issuedAtUnixNanos"], context["payload"]["expiresAtUnixNanos"], wall)
    return now, wall


def sign(role, input_original: bytes, signing_key) -> tuple[bytes, int]:
    """Sign once with the assigned supervisor key; retain the original deadline."""
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    boot, before, wall = originals._boot(), originals._clock(), time.time_ns()
    context = prepare_input(role, input_original, boot=boot,
        now_boottime_ns=before, now_unix_ns=wall)
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == context["supervisor"]["publicKeyBase64url"])
    message = p.preimage(DOMAIN, context["payload"])
    before, wall = _current(context, boot, before, wall)
    signature = signing_key.sign(message)
    signing_key.public_key().verify(signature, message)
    raw = p.canonical({"apiVersion": "serverware.nativeShadowVerifierTransport/v1",
        "authorization": {"payload": context["payload"], "signature": p.encoded(signature)}})
    p.require(len(raw) <= MAX_OUTPUT)
    after, later = _current(context, boot, before, wall)
    checked_result(role, input_original, {"original": raw.decode("ascii"), "sha256": p.sha(raw)},
        boot=boot, now_boottime_ns=after, now_unix_ns=later)
    _current(context, boot, after, later)
    return raw, context["deadline"]
