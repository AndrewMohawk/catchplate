"""Fixed endpoint HMAC-descriptor and encrypted-delivery authorizations.

Each independently approved call makes one existing supervisor signature. The
request-commitment operation consumes a provisioner's public secret commitment;
delivery consumes provisioned transport metadata and, for CommitRequest, the
actual preceding signed descriptor. No secret, ciphertext, KMS operation, key,
approval, transport endpoint or replacement window is created here. Public
signature/pin checks do not establish successful native or KMS admission.
"""
from __future__ import annotations

import copy
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import native_pilot_key_profile as keys
from serverware import native_pilot_launch_publication as launch
from serverware import native_shadow_commitment_artifacts as commitment
from serverware import native_shadow_key_contract as contract
from serverware import native_shadow_nitro_originals as originals

p = keys.p
API = "serverware.nativePilotEncryptedAuthorityInput/v1"
ROLES = keys.ROLES
OPERATIONS = ("request-commitment", "delivery")
PAIR_FIELDS = ("roleKeyInputOriginal", "roleKeyOriginal", "admissionInputOriginal", "admissionOriginal")
INPUT_FIELDS = ("apiVersion", "operation", "role") + PAIR_FIELDS + ("issuedAtUnixNanos", "expiresAtUnixNanos")
MAX_INPUT = keys.MAX_INPUT
MAX_OUTPUT = 65536
REQUEST_DOMAIN = "serverware.nativeShadowRequestCommitmentAssignment.signature/v2"
DELIVERY_DOMAINS = {False: "serverware.nativeShadowEncryptedKeyDelivery.signature/v1", True: commitment.KEY_DOMAIN}


def _original(value, maximum):
    raw, _ = keys.c9._original(value, maximum)
    return raw


def _pair(role, value, clocks):
    raw = {name: _original(value[name], keys.MAX_INPUT if "Input" in name else keys.MAX_OUTPUT)
        for name in PAIR_FIELDS}
    pair = keys.admitted_pair(role, raw["roleKeyInputOriginal"], raw["roleKeyOriginal"],
        raw["admissionInputOriginal"], raw["admissionOriginal"], **clocks)
    first = p.document(raw["roleKeyInputOriginal"], keys.MAX_INPUT)
    signed_assignment = p.document(_original(first["recipeOriginals"]["assignmentOriginal"], p.MAX_CONFIG), p.MAX_CONFIG)
    # The actual signed assignment and C9 have already been authenticated by
    # admitted_pair; preserve those literals instead of accepting a new DTO.
    assignment = signed_assignment["payload"]
    delivery = p.document(_original(first["deliveryOriginal"], keys.MAX_OUTPUT), keys.MAX_OUTPUT)["payload"]
    return pair, assignment, delivery


def _common(pair, issued, expires, now):
    # _common consumes exactly the authentic pair's authorization, admission
    # and checkpoint. This does not invent a Nitro-verifier configuration.
    value = commitment._common(pair, pair["expectedScope"], pair["authorityKeys"], issued, expires, now)
    p.require(max(pair[name]["payload"]["issuedAtUnixNanos"] for name in ("authorization", "admissionAuthorization"))
        <= issued < expires <= min(pair[name]["payload"]["expiresAtUnixNanos"]
            for name in ("authorization", "admissionAuthorization")))
    return value


def _descriptor(value, assignment, pair):
    descriptor = contract.commitment(value)
    window = assignment["observationWindow"]
    p.require(descriptor["keyId"] == window["requestCommitmentKeyId"]
        and descriptor["keyEpoch"] == window["requestCommitmentKeyEpoch"]
        and descriptor["keyId"] not in {key["keyId"] for key in pair["authorityKeys"]})
    return descriptor


def _request_payload(pair, assignment, descriptor, issued, expires, now):
    payload = _common(pair, issued, expires, now)
    payload.update(apiVersion="serverware.nativeShadowRequestCommitmentAssignment/v2",
        purpose="native-shadow-request-and-ingress-commitments",
        requestCommitment=copy.deepcopy(_descriptor(descriptor, assignment, pair)))
    p.fields(payload, commitment.HMAC_FIELDS)
    return payload


def prepare_input(operation, role, input_raw, *, boot, now_boottime_ns, now_unix_ns):
    """Authenticate complete public input; return no key or live owner."""
    p.require(operation in OPERATIONS and role in ROLES
        and (operation != "request-commitment" or role == "commitRequest"))
    extra = ("requestCommitmentOriginal",) if operation == "request-commitment" else ("transportOriginal",)
    if operation == "delivery" and role == "commitRequest":
        extra += ("requestCommitmentOriginal",)
    value = p.fields(p.document(input_raw, MAX_INPUT), INPUT_FIELDS + extra)
    p.require(value["apiVersion"] == API and value["operation"] == operation and value["role"] == role)
    p.integer(now_boottime_ns, maximum=p.MAX_U64); p.integer(now_unix_ns)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    pair, assignment, delivery = _pair(role, value, clocks)
    scope, supervisor = pair["expectedScope"], pair["authorityKeys"][-1]
    issued, expires = value["issuedAtUnixNanos"], value["expiresAtUnixNanos"]
    common = _common(pair, issued, expires, now_unix_ns)
    if role == "commitRequest":
        p.require(pair["authorization"]["payload"]["localRoles"] == ["custody-ledger-append"])
    request = None
    wrapper_api = None
    if operation == "request-commitment":
        descriptor = p.document(_original(value["requestCommitmentOriginal"], 4096), 4096)
        payload = _request_payload(pair, assignment, descriptor, issued, expires, now_unix_ns)
        domain = REQUEST_DOMAIN
    else:
        extended = role == "commitRequest"
        version = "2" if extended else "1"
        transport = contract.transport(p.document(_original(value["transportOriginal"], 16384), 16384))
        p.require(transport["apiVersion"] == "serverware.nativeShadowKeyKmsTransport/v" + version)
        ciphertext = [entry for entry in delivery["credentials"] if entry["name"] == "shadow-encrypted-role-inventory"]
        p.require(len(ciphertext) == 1 and ciphertext[0]["signing"] is None
            and 0 < ciphertext[0]["length"] <= 32768
            and ciphertext[0]["original"]["sha256"] == transport["encryptedInventorySha256"]
            and all(not entry["name"].startswith("shadow-key-custody-") for entry in delivery["credentials"]))
        if extended:
            request = p.fields(p.document(_original(value["requestCommitmentOriginal"], MAX_OUTPUT), MAX_OUTPUT), ("payload", "signature"))
            supplied = p.fields(request["payload"], commitment.HMAC_FIELDS)
            expected = _request_payload(pair, assignment, supplied["requestCommitment"],
                supplied["issuedAtUnixNanos"], supplied["expiresAtUnixNanos"], now_unix_ns)
            p.require(p.canonical(supplied) == p.canonical(expected)
                and supplied["issuedAtUnixNanos"] <= issued < expires <= supplied["expiresAtUnixNanos"])
            p.public_key(supervisor).verify(p.decoded(request["signature"], size=64), p.preimage(REQUEST_DOMAIN, expected))
        payload = {**common, "apiVersion": "serverware.nativeShadowEncryptedKeyDeliveryAssignment/v" + version,
            "purpose": "kms-recipient-shadow-local-keys-and-request-commitment" if extended else "kms-recipient-shadow-local-keys",
            **{name: copy.deepcopy(scope[name]) for name in ("assignmentId", "assignmentRevision", "fullKeySetRootSha256",
                "localKeySetRootSha256", "challengeBase64url")}, "transport": copy.deepcopy(transport)}
        p.fields(payload, launch._ENCRYPTED)
        domain = DELIVERY_DOMAINS[extended]
        wrapper_api = "serverware.nativeShadowEncryptedKeyDelivery/v" + version
    deadline = p.ns(scope["guest"]["startupDeadlineBoottimeNs"])
    # Exact size accounting before signing: 64 signature bytes encode to 86
    # unpadded ASCII characters. No placeholder signature is constructed.
    output_length = len(p.canonical(payload)) + len(b'{"payload":,"signature":""}') + 86
    if wrapper_api is not None:
        sizing = {"apiVersion": wrapper_api, "authorization": None}
        if request is not None:
            sizing["requestCommitment"] = request
        output_length += len(p.canonical(sizing)) - len(b"null")
    p.require(now_boottime_ns < deadline and output_length <= MAX_OUTPUT)
    return {"payload": payload, "supervisor": supervisor, "window": scope["guest"], "deadline": deadline,
        "epochLimit": expires, "domain": domain, "requestCommitment": request, "apiVersion": wrapper_api}


def _envelope(context, signature):
    signed = {"payload": context["payload"], "signature": p.encoded(signature)}
    if context["apiVersion"] is None:
        return signed
    result = {"apiVersion": context["apiVersion"], "authorization": signed}
    if context["requestCommitment"] is not None:
        result["requestCommitment"] = context["requestCommitment"]
    return result


def checked_result(operation, role, input_raw, result, *, boot, now_boottime_ns, now_unix_ns):
    context = prepare_input(operation, role, input_raw, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(result, ("original", "sha256"))
    raw = _original(result["original"], MAX_OUTPUT)
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    value = p.document(raw, MAX_OUTPUT)
    if operation == "delivery":
        launch.shape("native-" + role + "-encrypted-keys", raw)
        signed = value["authorization"]
    else:
        signed = p.fields(value, ("payload", "signature"))
    signature = p.decoded(signed["signature"], size=64)
    p.require(p.canonical(value) == p.canonical(_envelope(context, signature)))
    p.public_key(context["supervisor"]).verify(signature, p.preimage(context["domain"], context["payload"]))
    return raw


def _current(context, boot, previous, previous_wall):
    now = keys.c9._live(context["window"], previous)
    wall = time.time_ns()
    p.require(originals._boot() == boot and previous_wall <= wall < context["epochLimit"]
        and now < context["deadline"])
    p.freshness(context["payload"]["issuedAtUnixNanos"], context["payload"]["expiresAtUnixNanos"], wall)
    return now, wall


def sign(operation, role, input_original, signing_key):
    """One existing signature only; no implicit HMAC or encrypted provisioning."""
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    boot, before, wall = originals._boot(), originals._clock(), time.time_ns()
    context = prepare_input(operation, role, input_original, boot=boot, now_boottime_ns=before, now_unix_ns=wall)
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == context["supervisor"]["publicKeyBase64url"])
    message = p.preimage(context["domain"], context["payload"])
    before, wall = _current(context, boot, before, wall)
    signature = signing_key.sign(message)
    signing_key.public_key().verify(signature, message)
    raw = p.canonical(_envelope(context, signature))
    p.require(len(raw) <= MAX_OUTPUT)
    after, later = _current(context, boot, before, wall)
    checked_result(operation, role, input_original, {"original": raw.decode("ascii"), "sha256": p.sha(raw)},
        boot=boot, now_boottime_ns=after, now_unix_ns=later)
    _current(context, boot, after, later)
    return raw, context["deadline"]
