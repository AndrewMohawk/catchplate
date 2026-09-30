"""Issue one genuine direct-next ordinary endpoint key checkpoint.

The independently approved exact input selects a fresh-history profile: one
existing triple-signed retained epoch, no transitions, compaction anchors or
replay tombstones, and a separately approved history-root ID/SPKI pin. This
module verifies that history before selecting its checkpoint authority. It
does not create a first checkpoint, retained anchor, predecessor or history.
The initial three-party anchor ceremony and coordinator jobs remain separate.

The actual parked-pre-exec preparation binds a retained child and measured
target executable. The output authorizes that intended fixed exec; it is NOT
evidence that the child has executed the service. Native post-connect process
verification is unchanged. No timestamps, keys, revocation facts or counters
are generated, and the caller must independently approve the complete input.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import custody_generation_grants as generation
from serverware import native_pilot_ordinary_key_profile as profile
from serverware import native_pilot_service_authority as service
from serverware import native_pilot_window_authority as window_authority
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_nitro_originals as originals

p = generation.p
MAX_INPUT = 8 * 1024 * 1024
MAX_HISTORY = generation.MAX_BYTES
MAX_OUTPUT = 65536
INPUT_FIELDS = ("apiVersion", "profile", "serviceRole", "driverConfigurationOriginal", "driverWindowOriginal",
    "launchOriginal", "configurationOriginal", "preparationOriginal", "historyOriginal", "rootAuthority", "payloadOriginal")
HISTORY_API = "serverware.policyCustodyAuthorityHistory/v3"
EPOCH_FIELDS = ("apiVersion", "authorityRole", "authorityEpochSequence", "predecessorEpochSha256",
    "checkpointSequence", "checkpointSha256", "checkpointAuthority", "serviceSigningKey", "endpointProcessIdentity",
    "endpointProcessIdentitySha256", "endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch",
    "durableEpochHeadSha256", "deploymentGenerationSha256", "epochSha256")
ANCHOR_FIELDS = ("apiVersion", "retainedEpoch", "prunedThroughEpochSequence", "prunedHistoryRootSha256",
    "prunedTerminalEpochSha256", "rootAuthorityKeyId", "rootAuthorityKeySpkiSha256", "rootSignatureBase64",
    "checkpointAuthoritySignatureBase64", "serviceKeySignatureBase64", "retainedAnchorSha256")
RETENTION_FIELDS = ("oldestRetainedEpochSequence", "currentEpochSequence", "oldestRetainedCheckpointSequence",
    "currentCheckpointSequence", "oldestRetainedEndpointGeneration", "currentEndpointGeneration",
    "oldestRetainedServiceGeneration", "currentServiceGeneration", "oldestRetainedOperationGeneration",
    "currentOperationGeneration", "oldestRetainedDurableEpoch", "currentDurableEpoch", "oldestReplayableRecordSequence",
    "currentRecordSequence", "oldestRetainedCompactionSequence", "currentCompactionSequence",
    "maximumRetainedEpochs", "maximumCompactionAnchors", "maximumReplayTombstones")
EPOCH_DOMAIN = b"serverware.policyCustodyAuthorityEpochStatement/v3"
ANCHOR_SIGNATURE_DOMAIN = b"serverware.policyCustodyRetainedAuthorityEpochAnchor/v3"
ANCHOR_DIGEST_DOMAIN = b"serverware.policyCustodyRetainedAuthorityEpochAnchorDigest/v3"
HISTORY_DOMAIN = b"serverware.policyCustodyAuthorityHistoryManifest/v3"


def _original(text, maximum):
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= maximum)
    raw = text.encode("ascii")
    return raw, generation.document(raw, maximum)


def _same(first, second):
    p.require(generation.canonical(first) == generation.canonical(second))


def _raw_key(key):
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _key(value):
    p.fields(value, ("keyId", "keySpkiSha256", "publicKeySpkiBase64"))
    p.digest(value["keyId"]); p.digest(value["keySpkiSha256"])
    raw = p.decoded(value["publicKeySpkiBase64"], size=44)
    key = serialization.load_der_public_key(raw)
    p.require(isinstance(key, Ed25519PublicKey) and _raw_key(key) != bytes(32)
        and key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == raw
        and p.sha(raw) == value["keySpkiSha256"])
    return key


def _signature_preimage(domain, raw):
    # Literal existing protocol.rs domain_separated_signature_preimage.
    return (b"serverware-signature-v1\0" + len(domain).to_bytes(8, "big") + domain
        + len(raw).to_bytes(8, "big") + raw)


def _retention(value, epoch):
    p.fields(value, RETENTION_FIELDS)
    for name in RETENTION_FIELDS:
        maximum = {"maximumRetainedEpochs": 64, "maximumCompactionAnchors": 64,
            "maximumReplayTombstones": 4096}.get(name, p.MAX_U64)
        minimum = 1 if name.startswith("maximum") else 0
        p.integer(value[name], minimum=minimum, maximum=maximum)
    for first, last, source in (
            ("oldestRetainedEpochSequence", "currentEpochSequence", "authorityEpochSequence"),
            ("oldestRetainedCheckpointSequence", "currentCheckpointSequence", "checkpointSequence"),
            ("oldestRetainedEndpointGeneration", "currentEndpointGeneration", "endpointGeneration"),
            ("oldestRetainedServiceGeneration", "currentServiceGeneration", "serviceGeneration"),
            ("oldestRetainedOperationGeneration", "currentOperationGeneration", "operationGeneration"),
            ("oldestRetainedDurableEpoch", "currentDurableEpoch", "durableEpoch")):
        p.require(value[first] == value[last] == epoch[source])
    first, last = value["oldestReplayableRecordSequence"], value["currentRecordSequence"]
    p.require((first == last == 0) or 0 < first <= last)
    # No compaction/tombstone history is accepted by this fixed profile.
    p.require(value["oldestRetainedCompactionSequence"] == value["currentCompactionSequence"] == 0)


def _history(raw, *, role, root_pin):
    """Authenticate exactly one supplied fresh retained epoch, not a chain."""
    history = p.fields(generation.document(raw, MAX_HISTORY), generation.HISTORY)
    expected_role = {"authorityKind": "isolated-service", "role": role}
    p.require(history["apiVersion"] == HISTORY_API)
    _same(history["authorityRole"], expected_role)
    for field in ("adjacentTransitions", "compactionAnchors", "replayTombstones"):
        p.require(type(history[field]) is list and history[field] == [])
    p.fields(root_pin, ("keyId", "keySpkiSha256"))
    for name in root_pin:
        p.require(p.digest(root_pin[name]) == history["rootAuthority"][name])
    root_key = _key(history["rootAuthority"])
    anchor = p.fields(history["firstRetainedEpoch"], ANCHOR_FIELDS)
    epoch = p.fields(anchor["retainedEpoch"], EPOCH_FIELDS)
    p.require(anchor["apiVersion"] == epoch["apiVersion"] == HISTORY_API)
    _same(epoch["authorityRole"], expected_role)
    for name in ("authorityEpochSequence", "checkpointSequence", "endpointGeneration", "serviceGeneration",
                 "operationGeneration", "durableEpoch"):
        p.integer(epoch[name], maximum=p.MAX_U64)
    p.require(epoch["authorityEpochSequence"] == 1 and epoch["predecessorEpochSha256"] is None)
    for name in ("checkpointSha256", "endpointProcessIdentitySha256", "durableEpochHeadSha256",
                 "deploymentGenerationSha256", "epochSha256"):
        p.digest(epoch[name])
    identity = profile.validate_identity(epoch["endpointProcessIdentity"])
    p.require(epoch["endpointProcessIdentitySha256"] == identity["identitySha256"])
    checkpoint_key, service_key = (_key(epoch[name]) for name in ("checkpointAuthority", "serviceSigningKey"))
    keys = (history["rootAuthority"], epoch["checkpointAuthority"], epoch["serviceSigningKey"])
    p.require(len({item["keyId"] for item in keys}) == 3 and len({item["keySpkiSha256"] for item in keys}) == 3
        and len({_raw_key(key) for key in (root_key, checkpoint_key, service_key)}) == 3)
    epoch_values = [
        [epoch[name] for name in ("apiVersion", "authorityRole", "authorityEpochSequence", "predecessorEpochSha256")],
        [epoch[name] for name in ("checkpointSequence", "checkpointSha256", "checkpointAuthority", "serviceSigningKey")],
        [epoch[name] for name in ("endpointProcessIdentity", "endpointProcessIdentitySha256", "endpointGeneration", "serviceGeneration")],
        [epoch[name] for name in ("operationGeneration", "durableEpoch", "durableEpochHeadSha256", "deploymentGenerationSha256")],
    ]
    p.require(epoch["epochSha256"] == p.framed(EPOCH_DOMAIN, (generation.canonical(epoch_values),)))
    p.require(p.integer(anchor["prunedThroughEpochSequence"], minimum=0, maximum=p.MAX_U64) == 0
        and anchor["prunedTerminalEpochSha256"] is None)
    for name in ("prunedHistoryRootSha256", "rootAuthorityKeyId", "rootAuthorityKeySpkiSha256", "retainedAnchorSha256"):
        p.digest(anchor[name])
    p.require(anchor["rootAuthorityKeyId"] == root_pin["keyId"]
        and anchor["rootAuthorityKeySpkiSha256"] == root_pin["keySpkiSha256"])
    anchor_raw = generation.canonical([anchor[name] for name in ANCHOR_FIELDS[:7]])
    message = _signature_preimage(ANCHOR_SIGNATURE_DOMAIN, anchor_raw)
    signature_names = ("rootSignatureBase64", "checkpointAuthoritySignatureBase64", "serviceKeySignatureBase64")
    for field, key in zip(signature_names, (root_key, checkpoint_key, service_key), strict=True):
        key.verify(p.decoded(anchor[field], size=64), message)
    p.require(anchor["retainedAnchorSha256"] == p.framed(ANCHOR_DIGEST_DOMAIN,
        (anchor_raw, *(anchor[name].encode("ascii") for name in signature_names))))
    _retention(history["retention"], epoch)
    p.require(p.digest(history["manifestSha256"]) == p.framed(HISTORY_DOMAIN,
        (generation.canonical([history[name] for name in generation.HISTORY[:-1]]),)))
    return epoch, checkpoint_key


def sign(*, input_original: bytes, signing_key) -> tuple[bytes, int]:
    """Sign the unchanged approved direct-next payload; return raw/deadline.

    The startup deadline is only shortened by the supplied checkpoint expiry.
    There is no claim of globally current revocation or executed service state.
    Unsupported rotated/pruned history fails rather than falling back to a key
    from the checkpoint or an unverified history summary.
    """
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    value = p.fields(p.document(input_original, MAX_INPUT), INPUT_FIELDS)
    p.require(value["apiVersion"] == "serverware.nativePilotOrdinaryKeyAuthorityInput/v1"
        and value["profile"] == "fresh-retained-epoch-v1" and value["serviceRole"] in generation.ROLES)
    role = value["serviceRole"]
    configuration_raw, _ = _original(value["driverConfigurationOriginal"], 65536)
    configuration = window_authority.validate_configuration(configuration_raw)
    _, signed_window = _original(value["driverWindowOriginal"], 32768)
    p.fields(signed_window, ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed_window["apiVersion"] == "serverware.nativeShadowDriverBootstrapWindow/v1")
    window = signed_window["payload"]
    driver._key(configuration["bootstrapAuthority"]).verify(p.decoded(signed_window["signatureBase64url"], size=64),
        driver.WINDOW_DOMAIN + p.canonical(window))
    boot, now = originals._boot(), originals._clock()
    window_authority.validate_window(window, configuration_raw, configuration, boot=boot, now=now)
    launch_raw, _ = _original(value["launchOriginal"], 65536)
    launch, startup, lifetime = service._launch(launch_raw, boot, now)
    p.require(startup == p.ns(window["startupDeadlineBoottimeNs"])
        and lifetime == p.ns(window["lifetimeDeadlineBoottimeNs"]) and launch["invocationId"] == window["invocationId"])
    cold_raw, _ = _original(value["configurationOriginal"], 65536)
    cold = generation.configuration(cold_raw, launch["services"][role]["deliveryConfiguration"]["sha256"], role)
    preparation_raw, _ = _original(value["preparationOriginal"], profile.MAX_PREPARATION)
    observation = profile.preparation(preparation_raw)
    p.require(observation["configurationSha256"] == p.sha(launch_raw))
    history_raw, _ = _original(value["historyOriginal"], MAX_HISTORY)
    epoch, authority = _history(history_raw, role=role, root_pin=value["rootAuthority"])
    identity = profile.prepared_identity(observation, role=role,
        endpoint_role=epoch["endpointProcessIdentity"]["endpointRole"], launch=launch,
        configuration=cold, window=window, now=now)
    _same(identity, epoch["endpointProcessIdentity"])
    _, payload = _original(value["payloadOriginal"], MAX_OUTPUT)
    profile.validate_payload(payload, identity=identity, window=window, now=now)
    p.require(payload["exactEndpointGeneration"] == epoch["endpointGeneration"]
        and payload["authorizedSigningKeyId"] == epoch["serviceSigningKey"]["keyId"]
        and payload["authorizedSigningKeySpkiSha256"] == epoch["serviceSigningKey"]["keySpkiSha256"]
        and epoch["checkpointSequence"] < p.MAX_U64
        and payload["checkpointSequence"] == epoch["checkpointSequence"] + 1
        and payload["predecessorCheckpointSha256"] == epoch["checkpointSha256"]
        and payload["validFromBoottime"]["absoluteBoottimeNanos"] >= p.ns(observation["issuedAtBoottimeNs"]))
    selected = epoch["checkpointAuthority"]
    public = _raw_key(authority)
    p.require(_raw_key(signing_key.public_key()) == public)
    # Never use this role's C9 key (or a driver authority) as checkpoint key.
    excluded = (cold["authority"], configuration["bootstrapAuthority"], configuration["phaseTwoAuthority"],
        configuration["lifecycle"]["constructedAdmissionAuthority"])
    for key in excluded:
        p.require(public != p.decoded(key["publicKeyBase64url"], size=32) and selected["keyId"] != key["keyId"])
    deadline = min(startup, payload["validUntilBoottime"]["absoluteBoottimeNanos"])

    def check():
        after = originals._clock()
        p.require(originals._boot() == boot and now <= after < deadline)
        window_authority.validate_window(window, configuration_raw, configuration, boot=boot, now=after)
        profile.prepared_identity(observation, role=role, endpoint_role=identity["endpointRole"],
            launch=launch, configuration=cold, window=window, now=after)
        profile.validate_payload(payload, identity=identity, window=window, now=after)

    # Account for the fixed 86 ASCII signature characters and 71-character
    # prefixed digest before signing; do not construct a substitute checkpoint.
    output_fields = {"payload": payload, "authorityKeyId": selected["keyId"],
        "authorityKeySpkiSha256": selected["keySpkiSha256"], "authoritySignatureBase64": "",
        "checkpointSha256": ""}
    p.require(len(generation.canonical(output_fields)) + 86 + 71 <= MAX_OUTPUT)
    check()
    message = profile.signature_preimage(payload, selected["keyId"], selected["keySpkiSha256"])
    signature = signing_key.sign(message)
    authority.verify(signature, message)
    result = profile.envelope(payload, selected["keyId"], selected["keySpkiSha256"], p.encoded(signature))
    raw = generation.canonical(result)
    p.require(len(raw) <= MAX_OUTPUT)
    check()
    return raw, deadline
