"""Cold-only authorization of supplied ciphertext and KMS transport originals.

This producer authenticates the independently approved cold C9/key pair and
joins its held ciphertext metadata to the supplied literal encrypted inventory.
It creates no keys, seeds, ciphertext, KMS request, recipient, approval or owner.
Public ciphertext framing does not prove decryption or successful provisioning.
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
from serverware import native_shadow_commitment_artifacts as common
from serverware import native_shadow_key_contract as contract
from serverware import native_shadow_nitro_originals as originals

p = g.p
API = "serverware.nativePilotGenesisEncryptedAuthorityInput/v1"
ROLES = keys.ROLES
DOMAIN = "serverware.nativeShadowEncryptedKeyDelivery.signature/v1"
OUTPUT_API = "serverware.nativeShadowEncryptedKeyDelivery/v1"
MAX_INPUT = 32 * 1024 * 1024
MAX_OUTPUT = 65536
PAIR_FIELDS = ("roleKeyInputOriginal", "roleKeyOriginal", "admissionInputOriginal", "admissionOriginal")
FIELDS = ("apiVersion", "role", *PAIR_FIELDS, "transportOriginal", "encryptedInventoryOriginal",
    "issuedAtUnixNanos", "expiresAtUnixNanos")
CREDENTIAL = "shadow-encrypted-role-inventory"


def input_document(raw):
    # Embedded native originals retain their u64 grammar independently of this
    # outer string envelope and its i64 UNIX interval.
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
    scope = pair["expectedScope"]
    issued, expires = value["issuedAtUnixNanos"], value["expiresAtUnixNanos"]
    # This existing helper only assembles shared fields from the checked pair;
    # it does not run the old hot selector or reinterpret the native guest.
    payload = common._common(pair, scope, pair["authorityKeys"], issued, expires, now_unix_ns)
    p.require(max(pair[name]["payload"]["issuedAtUnixNanos"] for name in ("authorization", "admissionAuthorization"))
        <= issued < expires <= pair["epochLimit"])
    transport_raw = keys.original(value["transportOriginal"], 16384)
    transport = contract.transport(g.document(transport_raw, 16384))
    p.require(transport["apiVersion"] == "serverware.nativeShadowKeyKmsTransport/v1")
    inventory = contract.inventory({"apiVersion": "serverware.nativeShadowLocalKeyInventory/v1",
        **{name: scope[name] for name in ("fullKeySetRootSha256", "localKeySetRootSha256", "localKeys")}})
    ciphertext_raw = keys.original(value["encryptedInventoryOriginal"], 32768)
    contract.encrypted(g.document(ciphertext_raw, 32768), inventory)
    supplied = pair["source"]["delivery"]["payload"]["credentials"]
    entries = [entry for entry in supplied if entry["name"] == CREDENTIAL]
    p.require(len(entries) == 1 and entries[0]["signing"] is None
        and entries[0]["length"] == len(ciphertext_raw)
        and entries[0]["original"]["sha256"] == transport["encryptedInventorySha256"] == p.sha(ciphertext_raw)
        and all(not entry["name"].startswith("shadow-key-custody-") for entry in supplied))
    payload.update(apiVersion="serverware.nativeShadowEncryptedKeyDeliveryAssignment/v1",
        purpose="kms-recipient-shadow-local-keys", transport=transport,
        **{name: scope[name] for name in ("assignmentId", "assignmentRevision", "fullKeySetRootSha256",
            "localKeySetRootSha256", "challengeBase64url")})
    p.fields(payload, launch._ENCRYPTED)
    deadline = pair["deadline"]
    epoch_limit = min(pair["epochLimit"], expires, issued + keys.binding.MAX_AGE + 1)
    # Bound the actual native wrapper before signing; signature is 86 ASCII
    # characters, with no accepted/emitted placeholder signature.
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch_limit
        and len(g.canonical(payload)) + len(OUTPUT_API) + 160 <= MAX_OUTPUT)
    return {"payload": payload, "pair": pair, "supervisor": pair["authorityKeys"][-1], "window": scope["guest"],
        "deadline": deadline, "epochLimit": epoch_limit, "domain": DOMAIN, "apiVersion": OUTPUT_API,
        "encrypted_inventory_raw": ciphertext_raw, "inventory_raw": g.canonical(inventory), "transport_raw": transport_raw}


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
