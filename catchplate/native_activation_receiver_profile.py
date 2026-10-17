"""Public inputs for independently approved activation receiver issuance.

An observation is not process ownership, attestation, currentness or permission.
Remote BOOTTIME is never compared with a host clock. Sample-anchored C9 output
keeps its original interval; only the actual enclave can admit it as current.
"""
import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import native_shadow_guest_delivery as delivery
from catchplate import native_shadow_key_admission_profile as admission
from catchplate.native_policy_activation_inputs import initial_state

p = delivery.p
MAX_INPUT = 8 * 1024 * 1024
DELIVERY_INPUT_API = "catchplate.nativeActivationReceiverDeliveryAuthorityInput/v1"
SERVICE_INPUT_API = "catchplate.nativeActivationReceiverServiceAuthorityInput/v1"
SERVICE_API = "catchplate.nativeShadowActivationServiceAssignment/v2"
SERVICE_DOMAIN = "catchplate.nativeShadowActivationServiceAssignment.signature/v2"
DELIVERY_FIELDS = ("apiVersion", "receiverConfigurationOriginal", "receiverConfigurationSha256",
    "deliveryConfigurationOriginal", "observationOriginal", "observationSha256", "payloadOriginal")
SERVICE_FIELDS = ("apiVersion", "deliveryInputOriginal", "signedDeliveryOriginal",
    "admissionConfigurationOriginal", "admissionConfigurationSha256", "initialStateOriginal",
    "initialStateSha256", "payloadOriginal")
OBSERVATION_FIELDS = ("apiVersion", "okForAction", "configurationSha256", "deliveryConfigurationSha256",
    "processId", "processStartTicks", "processPidfdInode", "bootIdBase64url", "timeNamespaceDevice",
    "timeNamespaceInode", "observedAtBoottimeNs", "localCid", "localPort", "peerCid", "peerPort", "activation")
SERVICE_PAYLOAD_FIELDS = ("apiVersion", "purpose", "guest", "assignmentPayloadSha256", "keyAuthorizationSha256",
    "authority", "initialStateSha256", "generationId", "generationPublicationEnvelopeSha256", "trustCheckpointId",
    "revocationGeneration", "revocationRootSha256", "issuedAtUnixNanos", "expiresAtUnixNanos",
    "signingKeyId", "signingKeySpkiSha256")


def original(value, maximum):
    p.require(type(value) is str and value.isascii() and 0 < len(value) <= maximum)
    raw = value.encode("ascii")
    return raw, p.document(raw, maximum)


def receiver_configuration(raw, cold_raw):
    receiver = p.document(raw, 32768)
    version = receiver.get("apiVersion")
    p.require(version in {"catchplate.nativeShadowActivationReceiverConfiguration/v1",
        "catchplate.nativeShadowActivationReceiverConfiguration/v2"})
    p.fields(receiver, ("apiVersion", "deliveryConfiguration") +
        (("installationAuthority",) if version.endswith("/v2") else ()))
    delivery._pin(receiver["deliveryConfiguration"])
    cold = delivery.configuration(cold_raw, receiver["deliveryConfiguration"]["sha256"])
    if version.endswith("/v2"):
        authority = p.fields(receiver["installationAuthority"], ("publicKeyBase64url", "keyId"))
        p.require(authority == cold["authority"])
    return receiver, cold


def observation(raw, receiver_raw, cold_raw, cold):
    observed = p.fields(p.document(raw, 8192), OBSERVATION_FIELDS)
    p.require(observed["apiVersion"] == "catchplate.nativeShadowActivationReceiverObservation/v1"
        and observed["okForAction"] is False and observed["configurationSha256"] == p.sha(receiver_raw)
        and observed["deliveryConfigurationSha256"] == p.sha(cold_raw))
    p.integer(observed["processId"], maximum=(1 << 31) - 1)
    for name in ("processStartTicks", "processPidfdInode", "timeNamespaceDevice", "timeNamespaceInode"):
        p.integer(observed[name], maximum=p.MAX_U64)
    p.require(p.decoded(observed["bootIdBase64url"], size=16) != bytes(16))
    p.ns(observed["observedAtBoottimeNs"])
    p.integer(observed["localCid"], minimum=4, maximum=(1 << 32) - 2)
    p.integer(observed["peerPort"], minimum=1024, maximum=(1 << 32) - 2)
    p.require(type(observed["localPort"]) is int and observed["localPort"] == 9102
        and type(observed["peerCid"]) is int and observed["peerCid"] == 3)
    entries = observed["activation"]
    p.require(type(entries) is list and len(entries) == 2)
    identities = set()
    for index, (entry, name, kind) in enumerate(zip(entries,
            ("activation-channel", "activation-journal"), (stat.S_IFSOCK, stat.S_IFDIR)), 6):
        p.fields(entry, ("name", "fd", "device", "inode", "mode", "uid", "gid"))
        p.require(entry["name"] == name and type(entry["fd"]) is int and entry["fd"] == index)
        p.integer(entry["device"], minimum=0, maximum=p.MAX_U64)
        p.integer(entry["inode"], maximum=p.MAX_U64)
        for field in ("mode", "uid", "gid"):
            p.integer(entry[field], minimum=0, maximum=(1 << 32) - 1)
        p.require(stat.S_IFMT(entry["mode"]) == kind)
        pair = (entry["device"], entry["inode"])
        p.require(pair not in identities); identities.add(pair)
        if index == 7:
            p.require(stat.S_IMODE(entry["mode"]) == 0o700
                and (entry["uid"], entry["gid"]) == (cold["uid"], cold["gid"]))
    return observed


def prepare_delivery(raw):
    value = p.fields(p.document(raw, 1024 * 1024), DELIVERY_FIELDS)
    p.require(value["apiVersion"] == DELIVERY_INPUT_API)
    receiver_raw, _ = original(value["receiverConfigurationOriginal"], 32768)
    cold_raw, _ = original(value["deliveryConfigurationOriginal"], delivery.MAX_DELIVERY)
    observed_raw, _ = original(value["observationOriginal"], 8192)
    payload_raw, _ = original(value["payloadOriginal"], delivery.MAX_DELIVERY)
    p.require(p.sha(receiver_raw) == p.digest(value["receiverConfigurationSha256"])
        and p.sha(observed_raw) == p.digest(value["observationSha256"]))
    receiver, cold = receiver_configuration(receiver_raw, cold_raw)
    observed = observation(observed_raw, receiver_raw, cold_raw, cold)
    boot = tuple(observed[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"))
    arguments = {"configuration_raw": cold_raw, "configuration_sha256": p.sha(cold_raw),
        "payload_raw": payload_raw, "activation": observed["activation"], "boot": boot,
        "observed_at_boottime_ns": p.ns(observed["observedAtBoottimeNs"])}
    _, payload = delivery.validate_activation_delivery_sample_anchored(**arguments)
    return {"arguments": arguments, "receiver": receiver, "receiver_raw": receiver_raw, "cold": cold,
        "observed": observed, "observation_raw": observed_raw, "payload": payload, "payload_raw": payload_raw,
        "signer": Ed25519PublicKey.from_public_bytes(p.decoded(cold["authority"]["publicKeyBase64url"], size=32))}


def verify_delivery(context, raw):
    signed = p.fields(p.document(raw, delivery.MAX_DELIVERY), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "catchplate.policyCustodyGuestDelivery/v1"
        and p.canonical(signed["payload"]) == context["payload_raw"])
    context["signer"].verify(p.decoded(signed["signatureBase64url"], size=64), delivery.DOMAIN + context["payload_raw"])
    return delivery._delivery_guest(signed["payload"], raw)


def service_live(context, now_unix_ns):
    config, payload = context["configuration"], context["payload"]
    admission.authorization(config, now_unix_ns)
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], now_unix_ns)
    p.require(payload["expiresAtUnixNanos"] <= min(config[name]["payload"]["expiresAtUnixNanos"]
        for name in ("authorization", "admissionAuthorization")))


def prepare_service(raw, *, now_unix_ns):
    value = p.fields(p.document(raw, 4 * 1024 * 1024), SERVICE_FIELDS)
    p.require(value["apiVersion"] == SERVICE_INPUT_API)
    delivery_input, _ = original(value["deliveryInputOriginal"], 1024 * 1024)
    context = prepare_delivery(delivery_input)
    signed_delivery, _ = original(value["signedDeliveryOriginal"], delivery.MAX_DELIVERY)
    guest = verify_delivery(context, signed_delivery)
    configuration_raw, config = original(value["admissionConfigurationOriginal"], p.MAX_CONFIG)
    p.require(p.sha(configuration_raw) == p.digest(value["admissionConfigurationSha256"]))
    scope, keys = admission.authorization(config, now_unix_ns)
    state_raw, _ = original(value["initialStateOriginal"], 1024 * 1024 + 16384)
    state = initial_state(state_raw, value["initialStateSha256"])
    p.require(scope["guest"] == guest and state["assignmentPayloadSha256"] == scope["assignmentPayloadSha256"]
        and "custody-activation-publication" in config["authorization"]["payload"]["localRoles"])
    supervisor = keys[p.ROLES.index("custody-supervisor-capability")]
    p.require(supervisor["publicKeyBase64url"] != context["cold"]["authority"]["publicKeyBase64url"])
    payload_raw, payload = original(value["payloadOriginal"], delivery.MAX_DELIVERY)
    p.fields(payload, SERVICE_PAYLOAD_FIELDS)
    delivery._pin(payload["authority"])
    expected = {"apiVersion": SERVICE_API, "purpose": "native-policy-activation-publication", "guest": guest,
        "assignmentPayloadSha256": scope["assignmentPayloadSha256"], "keyAuthorizationSha256": scope["keyAuthorizationSha256"],
        "authority": payload["authority"], "initialStateSha256": p.sha(state_raw), "generationId": state["generationId"],
        "generationPublicationEnvelopeSha256": state["generationPublicationEnvelopeSha256"],
        "trustCheckpointId": config["trustCheckpoint"]["checkpointId"],
        "revocationGeneration": config["trustCheckpoint"]["revocationGeneration"],
        "revocationRootSha256": config["trustCheckpoint"]["revocationRootSha256"],
        "issuedAtUnixNanos": payload["issuedAtUnixNanos"], "expiresAtUnixNanos": payload["expiresAtUnixNanos"],
        "signingKeyId": supervisor["keyId"], "signingKeySpkiSha256": supervisor["keySpkiSha256"]}
    p.require(p.canonical(expected) == payload_raw)
    result = {"delivery": context, "delivery_original": signed_delivery, "configuration": config,
        "payload": payload, "payload_raw": payload_raw, "signer": p.public_key(supervisor)}
    service_live(result, now_unix_ns)
    return result


def verify_service(context, raw):
    signed = p.fields(p.document(raw, delivery.MAX_DELIVERY), ("payload", "signature"))
    p.require(p.canonical(signed["payload"]) == context["payload_raw"])
    context["signer"].verify(p.decoded(signed["signature"], size=64), p.preimage(SERVICE_DOMAIN, signed["payload"]))
    return signed
