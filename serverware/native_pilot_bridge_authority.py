"""Four explicit bridge-only late authorizations, one existing key per call.

Complete public inputs require independent approval. The software issuer does
not provision ciphertext, keys, a verifier, an attestation or a live owner.
Encrypted delivery uses only the original bootstrap continuation transport.
All endpoint-only producers retain their existing ten-role contract.
"""
from __future__ import annotations

import copy
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import native_pilot_bridge_key_profile as keys
from serverware import native_pilot_encrypted_authority as encrypted
from serverware import native_pilot_launch_publication as launch
from serverware import native_shadow_key_contract as contract
from serverware import native_shadow_nitro_originals as originals

p = keys.p
OPERATIONS = (*keys.OPERATIONS, "encrypted-delivery", "verifier-transport")
API = "serverware.nativePilotBridgeLateAuthorityInput/v1"
MAX_INPUT = keys.MAX_INPUT
MAX_OUTPUT = keys.MAX_OUTPUT
PAIR_FIELDS = ("roleKeyInputOriginal", "roleKeyOriginal", "admissionInputOriginal", "admissionOriginal")
INPUT_FIELDS = ("apiVersion", "operation", *PAIR_FIELDS, "issuedAtUnixNanos", "expiresAtUnixNanos")
DOMAINS = {**keys.DOMAINS, "encrypted-delivery": "serverware.nativeShadowEncryptedKeyDelivery.signature/v1",
    "verifier-transport": "serverware.nativeShadowVerifierTransport.signature/v1"}


def prepare_input(operation, input_raw, *, boot, now_boottime_ns, now_unix_ns):
    """Derive the sole payload from independently approved complete originals."""
    p.require(type(operation) is str and operation in OPERATIONS)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    if operation in keys.OPERATIONS:
        return keys.prepare_input(operation, input_raw, **clocks)
    value = p.fields(p.document(input_raw, MAX_INPUT),
        INPUT_FIELDS + (("parentPort",) if operation == "verifier-transport" else ()))
    p.require(value["apiVersion"] == API and value["operation"] == operation)
    raw = {name: keys.c9._original(value[name], MAX_INPUT if name.endswith("InputOriginal") else MAX_OUTPUT)[0]
        for name in PAIR_FIELDS}
    pair = keys.admitted_pair(*(raw[name] for name in PAIR_FIELDS), **clocks)
    context = keys.prepare_input("admission", raw["admissionInputOriginal"], **clocks)
    scope, supervisor = pair["expectedScope"], pair["authorityKeys"][-1]
    issued, expires = value["issuedAtUnixNanos"], value["expiresAtUnixNanos"]
    # Reuse the existing exact authenticated-pair time/checkpoint projection;
    # it accepts data, not a synthetic Nitro verifier configuration.
    common = encrypted._common(pair, issued, expires, now_unix_ns)
    if operation == "encrypted-delivery":
        continuation = p.fields(context["configuration"]["continuation"], ("apiVersion", "keyTransport"))
        p.require(continuation["apiVersion"] == "serverware.nativeShadowDriverContinuationPreparation/v3")
        transport = contract.transport(continuation["keyTransport"])
        p.require(transport["apiVersion"] == "serverware.nativeShadowKeyKmsTransport/v1")
        credentials = context["delivery"]["credentials"]
        ciphertext = [entry for entry in credentials if entry["name"] == "shadow-encrypted-role-inventory"]
        p.require(len(ciphertext) == 1 and ciphertext[0]["signing"] is None
            and 0 < ciphertext[0]["length"] <= 32768
            and ciphertext[0]["original"]["sha256"] == transport["encryptedInventorySha256"]
            and all(not entry["name"].startswith("shadow-key-custody-") for entry in credentials))
        payload = {**common, "apiVersion": "serverware.nativeShadowEncryptedKeyDeliveryAssignment/v1",
            "purpose": "kms-recipient-shadow-local-keys",
            **{name: copy.deepcopy(scope[name]) for name in ("assignmentId", "assignmentRevision", "fullKeySetRootSha256",
                "localKeySetRootSha256", "challengeBase64url")}, "transport": copy.deepcopy(transport)}
        p.fields(payload, launch._ENCRYPTED)
        wrapper_api = "serverware.nativeShadowEncryptedKeyDelivery/v1"
    else:
        verifier = pair["authorityKeys"][-2]
        p.integer(value["parentPort"], minimum=1024, maximum=(1 << 32) - 2)
        payload = {**common, "apiVersion": "serverware.nativeShadowVerifierTransportAssignment/v1",
            "purpose": "public-shadow-nitro-verification",
            **{name: copy.deepcopy(scope[name]) for name in ("assignmentId", "assignmentRevision",
                "fullKeySetRootSha256", "challengeBase64url")},
            "verifierKeyId": verifier["keyId"], "verifierKeySpkiSha256": verifier["keySpkiSha256"],
            "verifierKeyMaterialSha256": verifier["keyMaterialSha256"], "parentPort": value["parentPort"]}
        p.fields(payload, launch._VERIFIER)
        wrapper_api = "serverware.nativeShadowVerifierTransport/v1"
    result = {"apiVersion": wrapper_api, "authorization": {"payload": payload, "signature": ""}}
    maximum = 32768 if operation == "verifier-transport" else MAX_OUTPUT
    p.require(len(p.canonical(result)) + 86 <= maximum)
    return {"payload": payload, "supervisor": supervisor, "window": context["window"],
        "deadline": context["deadline"], "epochLimit": expires, "domain": DOMAINS[operation], "result": result}


def build(operation, *, pair_context, issued_at, expires_at, boot, now_boottime_ns, now_unix_ns, parent_port=None):
    p.require(operation in ("encrypted-delivery", "verifier-transport"))
    p.fields(pair_context, PAIR_FIELDS)
    value = {"apiVersion": API, "operation": operation, **pair_context,
        "issuedAtUnixNanos": issued_at, "expiresAtUnixNanos": expires_at}
    if operation == "verifier-transport":
        value["parentPort"] = parent_port
    else:
        p.require(parent_port is None)
    raw = p.canonical(value)
    prepare_input(operation, raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    return raw


def _envelope(context, signature):
    value = copy.deepcopy(context["result"])
    signed = value["authorization"] if "authorization" in value else value
    signed["signature"] = p.encoded(signature)
    return value


def checked_result(operation, input_raw, result, *, boot, now_boottime_ns, now_unix_ns):
    context = prepare_input(operation, input_raw, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(result, ("original", "sha256"))
    raw, value = keys.c9._original(result["original"], 32768 if operation == "verifier-transport" else MAX_OUTPUT)
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    signed = value["authorization"] if operation not in keys.OPERATIONS else value
    p.fields(signed, ("payload", "signature"))
    signature = p.decoded(signed["signature"], size=64)
    p.require(p.canonical(value) == p.canonical(_envelope(context, signature)))
    p.public_key(context["supervisor"]).verify(signature, p.preimage(context["domain"], context["payload"]))
    if operation in ("admission", "encrypted-delivery", "verifier-transport"):
        suffix = {"admission": "admission", "encrypted-delivery": "encrypted-keys", "verifier-transport": "verifier"}[operation]
        launch.shape("native-bridge-" + suffix, raw)
    return raw


def _current(context, boot, previous, previous_wall):
    now = keys.c9._live(context["window"], previous)
    wall = time.time_ns()
    p.require(originals._boot() == boot and previous_wall <= wall < context["epochLimit"]
        and now < context["deadline"])
    p.freshness(context["payload"]["issuedAtUnixNanos"], context["payload"]["expiresAtUnixNanos"], wall)
    return now, wall


def sign(operation, input_original, signing_key):
    """One approved supervisor signature; no private material or window creation."""
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    boot, before, wall = originals._boot(), originals._clock(), time.time_ns()
    context = prepare_input(operation, input_original, boot=boot, now_boottime_ns=before, now_unix_ns=wall)
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == context["supervisor"]["publicKeyBase64url"])
    message = p.preimage(context["domain"], context["payload"])
    before, wall = _current(context, boot, before, wall)
    signature = signing_key.sign(message)
    signing_key.public_key().verify(signature, message)
    raw = p.canonical(_envelope(context, signature))
    p.require(len(raw) <= MAX_OUTPUT)
    after, later = _current(context, boot, before, wall)
    checked_result(operation, input_original, {"original": raw.decode("ascii"), "sha256": p.sha(raw)},
        boot=boot, now_boottime_ns=after, now_unix_ns=later)
    _current(context, boot, after, later)
    return raw, context["deadline"]
