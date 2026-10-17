"""Two independent ordinary approvals of the exact adopted publication chain.

This produces the native Grant/v2, not an adoption journal record or evidence of
running services. The complete inputs are independently approved. Native grants
precede this root signature; neither native grant contains this later signature.
Actual receivers persist adoption only after admitting their retained resources.
"""
from __future__ import annotations

import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_adopted_ordinary as adopted
from catchplate import native_pilot_adopted_service_authority as native
from catchplate import native_pilot_ordinary_key_authority as history_keys
from catchplate import native_pilot_service_authority as service
from catchplate import native_shadow_nitro_originals as host

p = g.p
API = "catchplate.nativePilotOrdinaryPublicationAuthorityInput/v1"
GRANT_API = "catchplate.nativePublicationServiceGrant/v2"
DOMAIN = b"catchplate.nativePublicationServiceGrant.signature/v2"
MAX_INPUT = 32 * 1024 * 1024
MAX_OUTPUT = 3 * 1024 * 1024
FIELDS = ("apiVersion", "serviceRole", "launchOriginal", "services", "payloadOriginal",
    "nativePublicationInputOriginal", "nativePublicationGrantOriginal",
    "nativeRetrievalInputOriginal", "nativeRetrievalGrantOriginal")
PAYLOAD = ("apiVersion", "purpose", "serviceRole", "guest", "runtimeConfigurationSha256",
    "authorityHistoryManifestSha256", "admission", "native", "retrieval", "initialTransitionHeadSha256",
    "initialDurableTransitionHeadSha256", "durableAuthorityEpoch", "durablePublicKeyBase64url")


def message(payload):
    # Native signed payloads deliberately retain the signed-i64 codec.
    raw = p.canonical(payload)
    return b"catchplate-signature-v1\0" + len(DOMAIN).to_bytes(8, "big") + DOMAIN + len(raw).to_bytes(8, "big") + raw


def input_document(role, raw):
    p.require(role in adopted.ROLES)
    value = p.fields(p.document(raw, MAX_INPUT), FIELDS)
    p.require(value["apiVersion"] == API and value["serviceRole"] == role)
    p.fields(value["services"], adopted.ROLES)
    return value


def _native(operation, input_text, grant_text, clocks):
    input_raw, _ = native.original(input_text, native.MAX_INPUT)
    grant_raw = service._original(grant_text, native.PROFILES[operation][3])
    context = native.prepare_input(operation, input_raw, **clocks)
    signed = native.grant_original(operation, grant_raw)
    p.require(p.canonical(signed["payload"]) == p.canonical(context["payload"]))
    p.public_key(context["supervisor"]).verify(p.decoded(signed["signature"], size=64),
        p.preimage(context["domain"], context["payload"]))
    return input_raw, grant_raw, context


def prepare_input(role, raw, *, boot, now_boottime_ns, now_unix_ns):
    value = input_document(role, raw)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    launch_raw = service._original(value["launchOriginal"], 65536)
    launch, startup, lifetime = service._launch(launch_raw, boot, now_boottime_ns, adopted=True)
    items = {name: service._service(row, name, launch, boot, startup, lifetime,
        now_boottime_ns, granted=True, adopted=True) for name, row in value["services"].items()}
    pub_input, pub_raw, publication = _native("publication", value["nativePublicationInputOriginal"],
        value["nativePublicationGrantOriginal"], clocks)
    ret_input, ret_raw, retrieval = _native("retrieval", value["nativeRetrievalInputOriginal"],
        value["nativeRetrievalGrantOriginal"], clocks)
    pub, ret = publication["payload"], retrieval["payload"]
    p.require(native.input_document("retrieval", ret_input)["publicationGrantOriginal"].encode("ascii") == pub_raw
        and pub["retrievalGuest"] == ret["guest"] and ret["publication"]["admission"] == pub["admission"]
        and publication["supervisor"] == retrieval["supervisor"])
    admission = pub["admission"]
    authorization = admission["adoption"]["payload"]
    native_key = {"role": native.LOCAL_ROLES["publication"], **authorization["native"], "grantSha256": p.sha(pub_raw)}
    retrieval_key = {"role": native.LOCAL_ROLES["retrieval"], **authorization["retrieval"], "grantSha256": p.sha(ret_raw)}
    p.require(ret["publication"]["native"] == native_key and pub["retrieval"] == authorization["retrieval"])
    targets = {row["serviceRole"]: row for row in authorization["targetHistories"]}
    p.fields(targets, adopted.ROLES)
    for name, item in items.items():
        source = pub["ordinaryServices"][name]
        p.require(source["runtimeOriginal"].encode("ascii") == item["runtime_raw"]
            and source["historyOriginal"].encode("ascii") == item["history_raw"]
            and source["generationGrantOriginal"].encode("ascii") == item["grant_raw"]
            and item["header"]["expectedPeer"] == pub["expectedPeer"] == ret["expectedPeer"]
            and targets[name]["authorityEpoch"] == adopted.epoch_reference(item["epoch"]))
        service._scope(admission["scope"], item, now_boottime_ns)
        p.require(targets[name]["publicKeyBase64url"] == p.encoded(service._public(history_keys._key(item["epoch"]["serviceSigningKey"]))))
    payload_raw = service._original(value["payloadOriginal"], MAX_OUTPUT)
    payload = p.fields(p.document(payload_raw, MAX_OUTPUT), PAYLOAD)
    item, durable = items[role], items[adopted.ROLES[0]]
    durable_epoch = adopted.epoch_reference(durable["epoch"])
    durable_public = p.encoded(service._public(history_keys._key(durable["epoch"]["serviceSigningKey"])))
    p.require(payload["apiVersion"] == GRANT_API and payload["purpose"] == "native-policy-publication-state"
        and payload["serviceRole"] == role and payload["guest"] == item["guest"]
        and payload["runtimeConfigurationSha256"] == p.sha(item["runtime_raw"])
        and payload["authorityHistoryManifestSha256"] == item["history"]["manifestSha256"]
        and payload["admission"] == admission and payload["native"] == native_key and payload["retrieval"] == retrieval_key
        and payload["durableAuthorityEpoch"] == durable_epoch == ret["publication"]["drsAuthorityEpoch"]
        and payload["durablePublicKeyBase64url"] == durable_public == ret["publication"]["drsPublicKeyBase64url"])
    for field in ("initialTransitionHeadSha256", "initialDurableTransitionHeadSha256"):
        p.require(p.digest(payload[field]) not in {p.sha(b""), "sha256:" + "0" * 64})
    if role == adopted.ROLES[0]:
        p.require(payload["initialTransitionHeadSha256"] == payload["initialDurableTransitionHeadSha256"])
    keys = [p.decoded(record["publicKeyBase64url"], size=32) for record in (native_key, retrieval_key)]
    durable_bytes = p.decoded(durable_public, size=32)
    current_bytes = service._public(history_keys._key(item["epoch"]["serviceSigningKey"]))
    p.require(len(set(keys + [durable_bytes])) == 3 and current_bytes not in keys
        and service._public(item["root"]) not in keys + [durable_bytes]
        and (role == adopted.ROLES[0] or current_bytes != durable_bytes))
    deadline = min(startup, admission["scope"]["expiresAtBoottimeNanos"], authorization["expiresAtBoottimeNanos"],
        publication["deadline"], retrieval["deadline"], *(entry["deadline"] for entry in items.values()))
    epoch_limit = min(publication["epochLimit"], retrieval["epochLimit"])
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch_limit and len(payload_raw) + 128 <= MAX_OUTPUT)
    return dict(payload=payload, root=item["root"], message=message(payload), deadline=deadline,
        epochLimit=epoch_limit, window=launch, maximum=MAX_OUTPUT)


def checked_result(role, input_raw, signed_raw, **clocks):
    prepared = prepare_input(role, input_raw, **clocks)
    signed = p.fields(p.document(signed_raw, MAX_OUTPUT), ("payload", "signatureBase64url"))
    p.require(signed["payload"] == prepared["payload"])
    prepared["root"].verify(p.decoded(signed["signatureBase64url"], size=64), prepared["message"])
    return signed_raw


def sign(role, input_original, signing_key):
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    boot = host._boot()
    before, wall = host._clock(), time.time_ns()
    prepared = prepare_input(role, input_original, boot=boot, now_boottime_ns=before, now_unix_ns=wall)
    p.require(service._public(signing_key.public_key()) == service._public(prepared["root"]))
    p.require(host._boot() == boot)
    now, epoch = host._clock(), time.time_ns()
    p.require(before <= now < prepared["deadline"] and wall <= epoch < prepared["epochLimit"])
    signature = signing_key.sign(prepared["message"])
    prepared["root"].verify(signature, prepared["message"])
    raw = p.canonical({"payload": prepared["payload"], "signatureBase64url": p.encoded(signature)})
    p.require(len(raw) <= MAX_OUTPUT and host._boot() == boot)
    final, final_epoch = host._clock(), time.time_ns()
    p.require(now <= final < prepared["deadline"] and epoch <= final_epoch < prepared["epochLimit"])
    return raw, prepared["deadline"]
