"""Cold C9 and ordinary genesis grants from complete approved public originals.

This separate issuer has no hot driver/generation fallback. Native publication
and retrieval grants must already be genuinely signed under the independently
selected assignment supervisor. Their actual guest/key admission and retained
resources remain native responsibilities, not claims made by public parsing.
Every signing input requires separate complete-input approval by the caller.
"""
from __future__ import annotations

import copy
import os
import stat
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_ordinary_initial_authority as initial_authority
from catchplate import native_pilot_genesis_ordinary_initial_profile as initial
from catchplate import native_pilot_genesis_ordinary_runtime as runtime
from catchplate import native_pilot_ordinary_key_authority as history_authority
from catchplate import native_pilot_ordinary_runtime_recipe as recipe
from catchplate import native_pilot_publication_cold_binding as binding
from catchplate import native_shadow_nitro_originals as originals

p = g.p
API = "catchplate.nativePilotGenesisOrdinaryAuthorityInput/v1"
OPERATIONS = ("delivery", "grant")
MAX_INPUT = g.MAX_BYTES
MAX_DELIVERY = 65536
MAX_GRANT = 256 * 1024
DOMAIN = b"catchplate.nativePublicationGenesisGrant.signature/v1"
COMMON = ("apiVersion", "operation", "serviceRole", "source", "runtimePolicy", "historyOriginals",
    "coordinatorPeerPreparationOriginal", "expectedPeer")
GRANT_EXTRA = ("deliveryOriginals", "activation", "coldBindingInputOriginal", "coldBindingInputSha256",
    "nativePublicationOriginal", "nativeRetrievalOriginal", "initialTransitionHeadSha256")
AUTHORIZATION_FIELDS = ("guest", "assignmentPayloadSha256", "keyAuthorizationSha256", "trustCheckpointId",
    "revocationGeneration", "revocationRootSha256", "issuedAtUnixNanos", "expiresAtUnixNanos", "signingKeyId", "signingKeySpkiSha256")
GRANT_FIELDS = ("apiVersion", "purpose", "serviceRole", "guest", "runtimeConfigurationSha256",
    "authorityHistoryManifestSha256", "scope", "native", "retrieval", "initialTransitionHeadSha256",
    "durableAuthorityEpoch", "durablePublicKeyBase64url", "currentAuthorityEpoch", "currentPublicKeyBase64url")
EPOCH_FIELDS = ("apiVersion", "authorityRole", "authorityEpochSequence", "authorityEpochSha256", "checkpointSequence",
    "checkpointSha256", "checkpointAuthorityKeyId", "checkpointAuthorityKeySpkiSha256", "serviceSigningKeyId",
    "serviceSigningKeySpkiSha256", "endpointProcessIdentitySha256", "endpointGeneration", "serviceGeneration",
    "operationGeneration", "durableEpoch", "durableEpochHeadSha256", "deploymentGenerationSha256")


def _original(text, bound):
    return initial_authority._original(text, bound)[0]


def _raw_key(public):
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _message(payload):
    raw = g.canonical(payload)
    return b"catchplate-signature-v1\0" + len(DOMAIN).to_bytes(8, "big") + DOMAIN + len(raw).to_bytes(8, "big") + raw


def native_message(domain, payload):
    return b"catchplate.signedEnvelope/v1\0" + domain.encode("ascii") + b"\0catchplate.canonicalJson/ascii-integer-v1\0" + g.canonical(payload)


def epoch_reference(history):
    epoch = history["firstRetainedEpoch"]["retainedEpoch"]
    result = {name: copy.deepcopy(epoch[name]) for name in ("apiVersion", "authorityRole", "authorityEpochSequence",
        "checkpointSequence", "checkpointSha256", "endpointProcessIdentitySha256", "endpointGeneration",
        "serviceGeneration", "operationGeneration", "durableEpoch", "durableEpochHeadSha256", "deploymentGenerationSha256")}
    result["authorityEpochSha256"] = epoch["epochSha256"]
    for target, source in (("checkpointAuthority", "checkpointAuthority"), ("serviceSigning", "serviceSigningKey")):
        result[target + "KeyId"] = epoch[source]["keyId"]
        result[target + "KeySpkiSha256"] = epoch[source]["keySpkiSha256"]
    return result


def _guest(value, *, scope=None):
    p.fields(value, p.GUEST_FIELDS)
    for name in ("configurationSha256", "deliverySha256", "runtimeConfigurationSha256"):
        recipe.digest(value[name])
    p.require(value["serviceRole"] in (*initial.ROLES, "production-bridge"))
    for name in ("uid", "gid"):
        p.integer(value[name], maximum=(1 << 32) - 2)
        p.require(value[name] not in {64988, 64989, 64990, 65534})
    p.require(p.decoded(value["bootIdBase64url"], size=16) != bytes(16))
    p.integer(value["timeNamespaceDevice"], minimum=0, maximum=p.MAX_U64)
    p.integer(value["timeNamespaceInode"], maximum=p.MAX_U64)
    p.require(p.ns(value["issuedAtBoottimeNs"]) < p.ns(value["startupDeadlineBoottimeNs"]) <= p.ns(value["lifetimeDeadlineBoottimeNs"]))
    initial_authority.key._invocation(value["invocationId"])
    if scope is not None:
        for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"):
            initial.same(value[name], scope[name])
        p.require(p.ns(value["issuedAtBoottimeNs"]) <= scope["issuedAtBoottimeNanos"]
            < scope["expiresAtBoottimeNanos"] <= p.ns(value["lifetimeDeadlineBoottimeNs"]))
    return value


def _activation(value, role, cold):
    names = runtime.ACTIVATION_NAMES[role]
    p.require(type(value) is list and len(value) == len(names))
    identities = set()
    for index, (row, name) in enumerate(zip(value, names, strict=True), 6):
        p.fields(row, ("name", "fd", "device", "inode", "mode", "uid", "gid"))
        p.require(row["name"] == name and type(row["fd"]) is int and row["fd"] == index)
        p.integer(row["device"], minimum=0, maximum=p.MAX_U64); p.integer(row["inode"], maximum=p.MAX_U64)
        for field in ("mode", "uid", "gid"):
            p.integer(row[field], minimum=0, maximum=(1 << 32) - 1)
        identity = row["device"], row["inode"]
        p.require(identity not in identities); identities.add(identity)
        if name == "listener":
            # The inherited socket inode is not the separately chowned/chmoded
            # filesystem pathname. Actual retained FD metadata is signed here.
            p.require(stat.S_ISSOCK(row["mode"]) and row["mode"] & ~0o170777 == 0
                and (row["uid"], row["gid"]) == (0, 0))
        else:
            p.require((row["uid"], row["gid"]) == (cold["uid"], cold["gid"]))
            expected = (stat.S_IFREG | 0o600) if name == "publication-genesis-grant" else (stat.S_IFDIR | 0o700)
            p.require(row["mode"] == expected)
    return value


def _credentials(value, cold):
    p.require(type(value) is list and 2 <= len(value) <= 64)
    names, paths, total = {}, set(), 0
    for row in value:
        p.fields(row, ("name", "original", "length", "signing"))
        name = row["name"]
        if name not in (recipe.HISTORY_NAME, recipe.INSPECTION_NAME):
            recipe.name(name)
        p.require(name not in names); names[name] = row
        g.c9._pin(row["original"])
        p.require(row["original"]["path"] not in paths); paths.add(row["original"]["path"])
        total += p.integer(row["length"], maximum=g.MAX_BYTES)
        if row["signing"] is not None:
            selected = p.fields(row["signing"], ("publicKeyBase64url", "keyId"))
            public = p.decoded(selected["publicKeyBase64url"], size=32)
            p.require(public != bytes(32) and row["length"] == 32
                and selected["publicKeyBase64url"] != cold["authority"]["publicKeyBase64url"]
                and p.digest(selected["keyId"]) != cold["authority"]["keyId"])
    p.require(total <= 16 * 1024 * 1024)
    return names


def _delivery_payload(payload, *, configuration_raw, runtime_raw, history_raw, activation, boot, now_boottime_ns):
    p.fields(payload, g.c9.FIELDS)
    role = payload["serviceRole"]
    p.require(role in initial.ROLES)
    cold = g.configuration(configuration_raw, payload["configurationSha256"], role)
    p.require(payload["authorityKeyId"] == cold["authority"]["keyId"])
    for name in ("serviceRole", "uid", "gid"):
        initial.same(payload[name], cold[name])
    for name, selected in zip(("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"), boot, strict=True):
        initial.same(payload[name], selected)
    p.require(p.decoded(payload["bootIdBase64url"], size=16) != bytes(16))
    initial_authority.key._invocation(payload["invocationId"])
    issued, startup, lifetime = (p.ns(payload[name]) for name in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued <= now_boottime_ns < startup <= lifetime and startup - issued <= 30_000_000_000)
    g.c9._pin(payload["runtimeConfig"])
    p.require(payload["runtimeConfig"]["sha256"] == p.sha(runtime_raw))
    header = runtime.validate_runtime(role, runtime_raw)["runtime"]
    initial.same(payload["activation"], _activation(activation, role, cold))
    for row in activation:
        if row["name"] in header["activationDirectoryIdentities"]:
            identity = header["activationDirectoryIdentities"][row["name"]]
            p.require((os.major(row["device"]), os.minor(row["device"]), row["inode"], row["uid"], row["gid"], row["mode"])
                == tuple(identity[name] for name in ("deviceMajor", "deviceMinor", "inode", "uid", "gid", "mode")))
    credentials = _credentials(payload["credentials"], cold)
    for name, raw in ((recipe.HISTORY_NAME, history_raw), (recipe.INSPECTION_NAME,
            runtime.inspection_original(role, runtime_raw, cold, payload))):
        selected = credentials.get(name)
        p.require(selected is not None and selected["signing"] is None
            and selected["original"]["sha256"] == p.sha(raw) and selected["length"] == len(raw))
    return cold, header


def verify_delivery(*, signed_raw, configuration_raw, runtime_raw, history_raw, activation, boot, now_boottime_ns):
    signed = p.fields(g.document(signed_raw, MAX_DELIVERY), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "catchplate.policyCustodyGuestDelivery/v1")
    payload = signed["payload"]
    cold, header = _delivery_payload(payload, configuration_raw=configuration_raw, runtime_raw=runtime_raw,
        history_raw=history_raw, activation=activation, boot=boot, now_boottime_ns=now_boottime_ns)
    public = Ed25519PublicKey.from_public_bytes(p.decoded(cold["authority"]["publicKeyBase64url"], size=32))
    public.verify(p.decoded(signed["signatureBase64url"], size=64), g.c9.DOMAIN + g.canonical(payload))
    guest = {name: payload[name] for name in p.GUEST_FIELDS if name not in ("deliverySha256", "runtimeConfigurationSha256")}
    guest.update(deliverySha256=p.sha(signed_raw), runtimeConfigurationSha256=p.sha(runtime_raw)); _guest(guest)
    history = initial.runtime_manifest(history_raw, runtime=header, guest=guest)
    initial.require_window(history_raw, role=guest["serviceRole"], root_pin={"keyId": header["authorityHistoryRootKeyId"],
        "keySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]}, boot=boot, now_boottime_ns=now_boottime_ns)
    return dict(cold=cold, guest=guest, header=header, history=history, delivery_raw=signed_raw,
        runtime_raw=runtime_raw, history_raw=history_raw)


def verify_grant(raw, *, item):
    """Root-authenticate a retained C9-associated grant, not native ownership.

    The real owner supplies item only after verify_delivery at its current
    original clock. The native Gate separately checks live scope/history and
    actual resources. This does not replace the issuer's complete source check.
    """
    envelope = p.fields(g.document(raw, MAX_GRANT), ("payload", "signatureBase64url"))
    payload = p.fields(envelope["payload"], GRANT_FIELDS)
    role = item["guest"]["serviceRole"]
    p.require(role in initial.ROLES and payload["serviceRole"] == role
        and payload["apiVersion"] == "catchplate.nativePublicationGenesisGrant/v1"
        and payload["purpose"] == "native-cold-publication-genesis"
        and payload["runtimeConfigurationSha256"] == p.sha(item["runtime_raw"])
        and payload["authorityHistoryManifestSha256"] == item["history"]["manifestSha256"])
    initial.same(payload["guest"], item["guest"])
    recipe.digest(payload["initialTransitionHeadSha256"])
    scope = p.fields(payload["scope"], binding.GENESIS_FIELDS)
    p.require(scope["apiVersion"] == binding.GENESIS_API)
    for field in binding.GENESIS_FIELDS:
        if field.endswith("Sha256"): recipe.digest(scope[field])
    for field in ("assignmentRevision", "initialPublicationRevision", "issuedAtBoottimeNanos", "expiresAtBoottimeNanos"):
        p.integer(scope[field], maximum=p.MAX_U64)
    _guest(item["guest"], scope=scope)
    # Explicit cold proofScope/v2, preserving native u64 assignment revision.
    retrieval = binding.retrieval
    proof = p.fields(g.document(_original(scope["proofScopeOriginal"], 16384), 16384), retrieval.SCOPE_SET_FIELDS)
    p.require(proof["api_version"] == retrieval.SCOPE_SET_API)
    values = retrieval.SCOPE_VALUES + retrieval.SCOPE_SET_VALUES
    for field in values:
        if field == "assignment_revision": p.integer(proof[field], maximum=p.MAX_U64)
        else: recipe.digest(proof[field])
    p.require(proof["binding_sha256"] == p.framed(retrieval.SCOPE_SET_API.encode("ascii"), (g.canonical([proof[name] for name in values]),)))
    for field, expected_role in (("store_response_authority", "custody-store-response"), ("retrieval_response_authority", "custody-retrieval-response")):
        selected = p.fields(proof[field], ("role", "key_id", "key_spki_sha256", "key_material_sha256"))
        p.require(selected["role"] == expected_role)
        for name in ("key_id", "key_spki_sha256", "key_material_sha256"): recipe.digest(selected[name])
    for target, source in (("assignment_payload_sha256", "assignmentPayloadSha256"), ("assignment_revision", "assignmentRevision"),
            ("production_configuration_binding_sha256", "productionConfigurationBindingSha256"), ("retrieval_namespace_sha256", "retrievalNamespaceSha256")):
        initial.same(proof[target], scope[source])
    root = history_authority._key(item["history"]["rootAuthority"])
    root.verify(p.decoded(envelope["signatureBase64url"], size=64), _message(payload))
    materials = []
    for prefix, expected_role in (("durable", initial.ROLES[0]), ("current", initial.ROLES[1])):
        epoch = p.fields(payload[prefix + "AuthorityEpoch"], EPOCH_FIELDS)
        p.require(epoch["apiVersion"] == "catchplate.policyCustodyAuthorityHistory/v3"
            and epoch["authorityRole"] == {"authorityKind": "isolated-service", "role": expected_role})
        for name in EPOCH_FIELDS:
            if name.endswith("Sha256") or name.endswith("KeyId"): recipe.digest(epoch[name])
            elif name not in ("apiVersion", "authorityRole"): p.integer(epoch[name], maximum=p.MAX_U64)
        public = p.decoded(payload[prefix + "PublicKeyBase64url"], size=32)
        p.require(public != bytes(32) and p.sha(bytes.fromhex("302a300506032b6570032100") + public) == epoch["serviceSigningKeySpkiSha256"])
        if role == expected_role: initial.same(epoch, epoch_reference(item["history"]))
        materials.append(public)
    for name, expected_role in (("native", "custody-publication-reconciliation"), ("retrieval", "custody-retrieval-response")):
        row = p.fields(payload[name], ("role", "keyId", "keySpkiSha256", "publicKeyBase64url", "grantSha256"))
        public = p.decoded(row["publicKeyBase64url"], size=32)
        p.require(row["role"] == expected_role and public != bytes(32)
            and row["keySpkiSha256"] == p.sha(bytes.fromhex("302a300506032b6570032100") + public))
        recipe.digest(row["keyId"]); recipe.digest(row["grantSha256"]); materials.append(public)
    p.require(len(set(materials)) == 4 and _raw_key(root) not in materials)
    return raw


def _native_originals(*, cold_binding_raw, cold_binding_sha256, native_original, retrieval_original,
        items, boot, now_boottime_ns, now_unix_ns):
    approved = binding.input_document(cold_binding_raw)
    bound = binding.result_document(binding.prepare(cold_binding_raw, expected_input_sha256=cold_binding_sha256,
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns))
    _, assignment, trust, keys, _ = binding._authorities(approved, now_unix_ns)
    scope = g.document(bound["genesisScopeOriginal"].encode("ascii"), 16384)
    supervisor = next(row for row in keys if row["role"] == "custody-supervisor-capability")
    verifier = Ed25519PublicKey.from_public_bytes(p.decoded(supervisor["publicKeyBase64url"], size=32))
    selected = {name: next(row for row in keys if row["role"] == role) for name, role in (
        ("native", "custody-publication-reconciliation"), ("retrieval", "custody-retrieval-response"))}
    role_keys = {name: {**{field: row[field] for field in ("role", "keyId", "keySpkiSha256", "publicKeyBase64url")},
        "grantSha256": p.sha(native_original if name == "native" else retrieval_original)} for name, row in selected.items()}
    authorities = {name: {"epoch": epoch_reference(items[role]["history"]), "publicKeyBase64url": p.encoded(_raw_key(
        history_authority._key(items[role]["history"]["firstRetainedEpoch"]["retainedEpoch"]["serviceSigningKey"])))}
        for name, role in (("durableAuthority", initial.ROLES[0]), ("currentAuthority", initial.ROLES[1]))}
    for item in items.values():
        _guest(item["guest"], scope=scope)
        initial.require_window(item["history_raw"], role=item["guest"]["serviceRole"], root_pin={
            "keyId": item["header"]["authorityHistoryRootKeyId"], "keySpkiSha256": item["header"]["authorityHistoryRootKeySpkiSha256"]},
            boot=boot, now_boottime_ns=now_boottime_ns, issued=scope["issuedAtBoottimeNanos"], expires=scope["expiresAtBoottimeNanos"])
    payloads, ceilings = {}, [bound["expiresAtUnixNanos"], trust["issuedAtUnixNanos"] + binding.MAX_AGE + 1,
        assignment["payload"]["issuedAtUnixNanos"] + binding.MAX_AGE + 1]
    for name, raw, stem, purpose, extra, maximum in (
        ("native", native_original, "nativePublicationGenesisAssignment", "native-policy-publication-genesis", ("retrieval", "retrievalGuest"), g.MAX_BYTES),
        ("retrieval", retrieval_original, "nativePublicationGenesisRetrievalGrant", "native-policy-publication-genesis-retrieval", ("native", "store"), 65536)):
        envelope = p.fields(g.document(raw, maximum), ("payload", "signature"))
        payload = p.fields(envelope["payload"], ("apiVersion", "purpose", "authorization", "scope", "durableAuthority", "currentAuthority", "expectedPeer") + extra)
        p.require(payload["apiVersion"] == "catchplate." + stem + "/v1" and payload["purpose"] == purpose)
        initial.same(payload["scope"], scope)
        for field, authority in authorities.items(): initial.same(payload[field], authority)
        for item in items.values(): initial.same(payload["expectedPeer"], item["header"]["expectedPeer"])
        runtime.validate_peer(payload["expectedPeer"])
        authorization = p.fields(payload["authorization"], AUTHORIZATION_FIELDS)
        guest = _guest(authorization["guest"], scope=scope)
        p.require(guest["serviceRole"] == "production-bridge" and guest["uid"] != payload["expectedPeer"]["uid"])
        checkpoint = trust["checkpoint"]
        p.require(authorization["assignmentPayloadSha256"] == scope["assignmentPayloadSha256"]
            and p.digest(authorization["keyAuthorizationSha256"]) != p.sha(b"")
            and authorization["trustCheckpointId"] == checkpoint["checkpointId"]
            and authorization["revocationGeneration"] == checkpoint["revocationGeneration"]
            and authorization["revocationRootSha256"] == checkpoint["revocationRootSha256"]
            and authorization["signingKeyId"] == supervisor["keyId"]
            and authorization["signingKeySpkiSha256"] == supervisor["keySpkiSha256"])
        issued, expires = authorization["issuedAtUnixNanos"], authorization["expiresAtUnixNanos"]
        p.freshness(issued, expires, now_unix_ns, binding.MAX_AGE)
        p.require(bound["issuedAtUnixNanos"] <= issued < expires <= bound["expiresAtUnixNanos"])
        verifier.verify(p.decoded(envelope["signature"], size=64), native_message("catchplate." + stem + ".signature/v1", payload))
        payloads[name] = payload; ceilings.extend((expires, issued + binding.MAX_AGE + 1))
    native, retrieval = payloads["native"], payloads["retrieval"]
    initial.same(native["retrieval"], {field: selected["retrieval"][field] for field in ("keyId", "keySpkiSha256", "publicKeyBase64url")})
    initial.same(native["retrievalGuest"], retrieval["authorization"]["guest"])
    initial.same(retrieval["native"], role_keys["native"])
    store = p.fields(retrieval["store"], ("genesisSha256", "sequence", "headSha256"))
    p.require(type(store["sequence"]) is int and store["sequence"] == 0
        and p.digest(store["genesisSha256"]) != p.sha(b"") and store["headSha256"] == store["genesisSha256"])
    guests = [item["guest"] for item in items.values()] + [payloads[name]["authorization"]["guest"] for name in payloads]
    p.require(len({row["uid"] for row in guests}) == len(guests)
        and len({row["gid"] for row in guests}) == len(guests))
    public_keys = [row["publicKeyBase64url"] for row in authorities.values()] + [row["publicKeyBase64url"] for row in selected.values()]
    p.require(len(set(public_keys)) == 4)
    for item in items.values():
        root = history_authority._key(item["history"]["rootAuthority"])
        p.require(p.encoded(_raw_key(root)) not in public_keys)
    return scope, role_keys, authorities, min(ceilings)


def input_document(raw):
    value = g.document(raw, MAX_INPUT)
    p.require(value.get("apiVersion") == API and value.get("operation") in OPERATIONS and value.get("serviceRole") in initial.ROLES)
    p.fields(value, COMMON + (("payloadOriginal", "activation") if value["operation"] == "delivery" else GRANT_EXTRA))
    return value


def prepare_input(operation, input_original, *, boot, now_boottime_ns, now_unix_ns):
    value = input_document(input_original)
    p.require(operation in OPERATIONS and value["operation"] == operation)
    role = value["serviceRole"]
    histories = {name: _original(text, g.MAX_BYTES) for name, text in p.fields(value["historyOriginals"], initial.ROLES).items()}
    args = dict(fragment=value["runtimePolicy"], history_originals=histories, source=value["source"],
        peer_preparation_raw=_original(value["coordinatorPeerPreparationOriginal"], 131072),
        approved_peer=value["expectedPeer"], boot=boot, now_boottime_ns=now_boottime_ns)
    # Complete source authentication precedes every signature, for both roles.
    held, peer = runtime.contexts(**args)
    runtimes = {name: runtime._compose(name, value["runtimePolicy"], held, peer) for name in initial.ROLES}
    original_deadline = min(min(item["deadline"], item["observed"]["deadline"]) for item in held.values())
    source = runtime.source_arguments(value["source"], role)
    window = g.document(histories[role], g.MAX_BYTES)["initialState"]
    if operation == "delivery":
        payload = g.document(_original(value["payloadOriginal"], MAX_DELIVERY), MAX_DELIVERY)
        p.require(payload["serviceRole"] == role)
        cold, _ = _delivery_payload(payload, configuration_raw=source["configuration_raw"], runtime_raw=runtimes[role],
            history_raw=histories[role], activation=value["activation"], boot=boot, now_boottime_ns=now_boottime_ns)
        for name in initial_authority.parent.WINDOW_FIELDS[2:]: initial.same(payload[name], window[name])
        supplied = _credentials(payload["credentials"], cold)
        expected = recipe.credentials(value["runtimePolicy"]["services"][role]["credentials"])
        p.require(set(supplied) == set(expected) | {recipe.HISTORY_NAME, recipe.INSPECTION_NAME})
        for name, row in expected.items(): initial.same(supplied[name], row)
        public = Ed25519PublicKey.from_public_bytes(p.decoded(cold["authority"]["publicKeyBase64url"], size=32))
        message, epoch_limit = g.c9.DOMAIN + g.canonical(payload), None
        deadline = original_deadline
    else:
        deliveries, activation = p.fields(value["deliveryOriginals"], initial.ROLES), p.fields(value["activation"], initial.ROLES)
        items = {name: verify_delivery(signed_raw=_original(deliveries[name], MAX_DELIVERY),
            configuration_raw=runtime.source_arguments(value["source"], name)["configuration_raw"],
            runtime_raw=runtimes[name], history_raw=histories[name], activation=activation[name], boot=boot,
            now_boottime_ns=now_boottime_ns) for name in initial.ROLES}
        for name, item in items.items():
            state = g.document(histories[name], g.MAX_BYTES)["initialState"]
            delivery = g.document(item["delivery_raw"], MAX_DELIVERY)["payload"]
            for field in initial_authority.parent.WINDOW_FIELDS[2:]: initial.same(delivery[field], state[field])
            supplied = _credentials(delivery["credentials"], item["cold"])
            expected = recipe.credentials(value["runtimePolicy"]["services"][name]["credentials"])
            p.require(set(supplied) == set(expected) | {recipe.HISTORY_NAME, recipe.INSPECTION_NAME})
            for field, row in expected.items(): initial.same(supplied[field], row)
        scope, keys, authorities, epoch_limit = _native_originals(
            cold_binding_raw=_original(value["coldBindingInputOriginal"], binding.MAX_INPUT),
            cold_binding_sha256=value["coldBindingInputSha256"], native_original=_original(value["nativePublicationOriginal"], g.MAX_BYTES),
            retrieval_original=_original(value["nativeRetrievalOriginal"], 65536), items=items,
            boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
        item = items[role]
        recipe.digest(value["initialTransitionHeadSha256"])
        payload = {"apiVersion": "catchplate.nativePublicationGenesisGrant/v1", "purpose": "native-cold-publication-genesis",
            "serviceRole": role, "guest": item["guest"], "runtimeConfigurationSha256": p.sha(runtimes[role]),
            "authorityHistoryManifestSha256": item["history"]["manifestSha256"], "scope": scope,
            **keys, "initialTransitionHeadSha256": value["initialTransitionHeadSha256"],
            "durableAuthorityEpoch": authorities["durableAuthority"]["epoch"],
            "durablePublicKeyBase64url": authorities["durableAuthority"]["publicKeyBase64url"],
            "currentAuthorityEpoch": authorities["currentAuthority"]["epoch"],
            "currentPublicKeyBase64url": authorities["currentAuthority"]["publicKeyBase64url"]}
        public = history_authority._key(item["history"]["rootAuthority"])
        message = _message(payload)
        deadline = min(scope["expiresAtBoottimeNanos"], original_deadline)
    p.require(now_boottime_ns < deadline and (epoch_limit is None or now_unix_ns < epoch_limit))
    p.require(len(g.canonical(payload)) < (MAX_DELIVERY if operation == "delivery" else MAX_GRANT) - 256)
    return dict(payload=payload, message=message, key=public, deadline=deadline, epochLimit=epoch_limit, operation=operation)


def checked_result(operation, input_original, result, *, boot, now_boottime_ns, now_unix_ns):
    prepared = prepare_input(operation, input_original, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(result, ("original", "sha256"))
    raw = _original(result["original"], MAX_DELIVERY if operation == "delivery" else MAX_GRANT)
    p.require(p.sha(raw) == result["sha256"])
    value = p.fields(g.document(raw, MAX_DELIVERY if operation == "delivery" else MAX_GRANT),
        ("apiVersion", "payload", "signatureBase64url") if operation == "delivery" else ("payload", "signatureBase64url"))
    if operation == "delivery": p.require(value["apiVersion"] == "catchplate.policyCustodyGuestDelivery/v1")
    initial.same(value["payload"], prepared["payload"])
    prepared["key"].verify(p.decoded(value["signatureBase64url"], size=64), prepared["message"])
    return raw


def sign(operation, *, input_original, signing_key):
    p.require(operation in OPERATIONS and isinstance(signing_key, Ed25519PrivateKey))
    owner = os.getpid(), originals._start(), originals._boot()
    now, epoch = originals._clock(), time.time_ns()
    prepared = prepare_input(operation, input_original, boot=owner[2], now_boottime_ns=now, now_unix_ns=epoch)
    p.require(_raw_key(signing_key.public_key()) == _raw_key(prepared["key"]))
    def check(previous, prior_epoch):
        p.require((os.getpid(), originals._start(), originals._boot()) == owner)
        current, wall = originals._clock(), time.time_ns()
        p.require(previous <= current < prepared["deadline"] and prior_epoch <= wall
            and (prepared["epochLimit"] is None or wall < prepared["epochLimit"]))
        return current, wall
    before, before_epoch = check(now, epoch)
    signature = signing_key.sign(prepared["message"])
    prepared["key"].verify(signature, prepared["message"])
    value = {"payload": prepared["payload"], "signatureBase64url": p.encoded(signature)}
    if operation == "delivery": value["apiVersion"] = "catchplate.policyCustodyGuestDelivery/v1"
    raw = g.canonical(value)
    after, after_epoch = check(before, before_epoch)
    checked_result(operation, input_original, {"original": raw.decode("ascii"), "sha256": p.sha(raw)},
        boot=owner[2], now_boottime_ns=after, now_unix_ns=after_epoch)
    check(after, after_epoch)
    return raw
