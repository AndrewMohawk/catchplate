"""Fixed v2 late-runtime closure issuer over independently approved originals.

Runs after genuine driver observation and operational C9 delivery, before bridge
launch installation. C9 signing does not consume a closure. This producer neither
creates the image/build provenance nor approves the complete input: the separate
authority must do that before invoking it with its existing supervisor key.
The protected trust original, not a candidate payload, selects verification keys.

The native receiver still validates seccomp semantics, trusted time/currentness,
actual image and retained driver/guest ownership. Local checks/signatures here
are not those measurements or approval. No v1 endpoint profile, key generation,
installation, history creation, renewed deadline or automatic retry is offered.
"""
from __future__ import annotations

import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import authority_policy_canary_native_opening as opening
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_driver_authority as driver_authority
from serverware import native_pilot_launch_publication as launch
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_nitro_originals as originals

p = delivery.p
MAX_INPUT = 8 * 1024 * 1024
MAX_BYTES = 1024 * 1024
PROFILE = "measured-bootstrap-late-runtime-static-amd64-v1"
DOMAIN = "serverware.nativeCustodyClosureAssignment.signature/v2"
INPUT_FIELDS = ("apiVersion", "controlOriginal", "configurationOriginal", "windowOriginal",
    "observationOriginal", "deliveryConfigurationOriginal", "deliveryOriginal", "runtimeOriginal",
    "trustOriginal", "trustSha256", "assignmentOriginal", "manifestOriginal", "payloadOriginal")
PAYLOAD_FIELDS = launch._CLOSURE
MANIFEST_FIELDS = launch._MANIFEST
PROVENANCE_FIELDS = ("sourceTreeSha256", "dependencyLockSha256", "buildRecipeSha256",
    "toolchainClosureSha256", "provenanceStatementSha256", "transparencyLogEntrySha256",
    "reproducibleBuildRequired", "provenanceSha256")


def _guest(value):
    _, control = c9._original(value["controlOriginal"], 4096)
    p.fields(control, ("apiVersion", "supervisorExecutableSha256", "configurationSha256", "windowSha256"))
    p.require(control["apiVersion"] == "serverware.nativeShadowDriverBootstrapControl/v1")
    for name in ("supervisorExecutableSha256", "configurationSha256", "windowSha256"):
        p.digest(control[name])
    config_raw, config = c9._original(value["configurationOriginal"], 65536)
    window_raw, signed_window = c9._original(value["windowOriginal"], 32768)
    observation_raw, observed = c9._original(value["observationOriginal"], 65536)
    cold_raw, _ = c9._original(value["deliveryConfigurationOriginal"], 65536)
    cold = delivery.configuration(cold_raw, p.sha(cold_raw))
    p.require(p.sha(config_raw) == control["configurationSha256"]
        and p.sha(window_raw) == control["windowSha256"])
    window = c9._bridge_owner(cold, cold_raw, config_raw, window_raw, signed_window, observed)
    now = c9._live(window)
    driver_authority._observation(observation_raw, control, config, window, now)
    driver._key(config["phaseTwoAuthority"])
    p.require(config["bootstrapAuthority"]["publicKeyBase64url"] != config["phaseTwoAuthority"]["publicKeyBase64url"])
    runtime_raw, _ = c9._original(value["runtimeOriginal"], 65536)
    inventory, _ = c9._bridge_inventory(runtime_raw, cold)
    signed_raw, signed = c9._original(value["deliveryOriginal"], delivery.MAX_DELIVERY)
    p.fields(signed, ("apiVersion", "payload", "signatureBase64url"))
    payload = p.fields(signed["payload"], delivery.FIELDS)
    p.require(signed["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1"
        and payload["configurationSha256"] == p.sha(cold_raw)
        and payload["authorityKeyId"] == cold["authority"]["keyId"])
    for name in ("serviceRole", "uid", "gid"):
        c9._same(payload[name], cold[name])
    for name in c9.WINDOW_FIELDS:
        c9._same(payload[name], window[name])
    delivery._pin(payload["runtimeConfig"])
    p.require(payload["runtimeConfig"]["sha256"] == p.sha(runtime_raw))
    c9._activation(payload["activation"], inventory)
    c9._credentials(payload["credentials"], cold["authority"])
    driver._key(cold["authority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
        delivery.DOMAIN + p.canonical(payload))
    return config, window, observed, delivery._delivery_guest(payload, signed_raw)


def _authority(value, signing_key, now):
    trust_raw, _ = c9._original(value["trustOriginal"], 1024 * 1024)
    p.require(p.sha(trust_raw) == p.digest(value["trustSha256"]))
    trust = launch.shape("native-bridge-trust", trust_raw)
    p.freshness(trust["issuedAtUnixNanos"], trust["expiresAtUnixNanos"], now)
    checkpoint = trust["checkpoint"]
    p.digest(checkpoint["checkpointId"]); p.digest(checkpoint["revocationRootSha256"])
    p.integer(checkpoint["revocationGeneration"], minimum=0, maximum=p.MAX_U64)
    p.require(p.integer(checkpoint["asOfUnixNanos"]) <= now
        < checkpoint["asOfUnixNanos"] + 300_000_000_000)
    assignment_key = launch._key(trust["assignmentKey"], now)
    launch._key(trust["timeKey"], now)
    role_keys = {}
    material = {trust["assignmentKey"]["publicKeyBase64url"], trust["timeKey"]["publicKeyBase64url"]}
    p.require(len(material) == 2)
    for row in trust["roleKeys"]:
        role, key = row["role"], row["key"]
        p.require(type(role) is str and role.isascii() and 1 <= len(role) <= 128
            and role not in role_keys and key["publicKeyBase64url"] not in material)
        launch._key(key, now)
        material.add(key["publicKeyBase64url"]); role_keys[role] = key
    p.require(set(p.ROLES).issubset(role_keys))
    assignment_raw, _ = c9._original(value["assignmentOriginal"], 4 * 1024 * 1024)
    envelope = launch.shape("native-bridge-assignment", assignment_raw)
    assignment = opening.assignment_payload(envelope["payload"])
    p.require(envelope["signingKeyId"] == trust["assignmentKey"]["keyId"]
        and envelope["signingKeySpkiSha256"] == trust["assignmentKey"]["keySpkiSha256"])
    assignment_key.verify(p.decoded(envelope["signature"], size=64),
        p.preimage("serverware.policyShadowAssignment/v1", assignment))
    p.freshness(assignment["issuedAtUnixNanos"], assignment["expiresAtUnixNanos"], now)
    p.digest(assignment["assignmentId"])
    p.integer(assignment["assignmentRevision"], maximum=p.MAX_U64)
    binding, _ = opening._keys(assignment, "custody-supervisor-capability")
    # Authenticate the complete existing independent role set against cold
    # trust, including SPKI and key-material hashes, before selecting the signer.
    for role in p.ROLES:
        rows = [row for row in assignment["authorityKeyIndependence"]["bindings"]
            if row["role"] == role and row["scopeSha256"] == assignment["assignmentId"]]
        p.require(len(rows) == 1)
        row, key = rows[0], role_keys[role]
        p.require(row["keyId"] == key["keyId"] and row["keySpkiSha256"] == key["keySpkiSha256"])
        p.public_key({name: row[name] for name in ("role", "keyId", "keySpkiSha256", "keyMaterialSha256")}
            | {"publicKeyBase64url": key["publicKeyBase64url"]})
    selected = role_keys["custody-supervisor-capability"]
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == selected["publicKeyBase64url"])
    issued_floor = max(trust["issuedAtUnixNanos"], assignment["issuedAtUnixNanos"],
        trust["assignmentKey"]["notBeforeUnixNanos"], selected["notBeforeUnixNanos"])
    expires_ceiling = min(trust["expiresAtUnixNanos"], assignment["expiresAtUnixNanos"],
        trust["assignmentKey"]["notAfterUnixNanos"], selected["notAfterUnixNanos"],
        checkpoint["asOfUnixNanos"] + 300_000_000_000)
    return envelope, checkpoint, binding, issued_floor, expires_ceiling


def _manifest(value, config, observed, assignment):
    _, manifest = c9._original(value["manifestOriginal"], MAX_BYTES)
    p.fields(manifest, MANIFEST_FIELDS)
    p.require(manifest["apiVersion"] == "serverware.nativeCustodyExecutionClosure/v2"
        and manifest["profile"] == PROFILE)
    for name in ("imageSha256", "workerExecutableSha256", "runtimeConfigurationSha256", "manifestSha256"):
        p.digest(manifest[name])
    image = p.fields(config["image"], ("imageSha256", "executableSha256", "seccompPolicy",
        "bootstrapRuntimeSha256", "dependencyLockSha256", "buildRecipeSha256", "provenanceSha256"))
    for name in set(image) - {"seccompPolicy"}:
        p.digest(image[name])
    c9._same([manifest["imageSha256"], manifest["workerExecutableSha256"], manifest["seccompPolicy"],
        manifest["runtimeConfigurationSha256"]], [image["imageSha256"], image["executableSha256"],
        image["seccompPolicy"], image["bootstrapRuntimeSha256"]])
    p.require(manifest["workerExecutableSha256"] == observed["driver"]["driverExecutableSha256"])
    # The real bootstrap receiver validates this exact approved policy. This
    # issuer checks its association, not a replay of the Rust BPF compiler.
    policy = p.fields(manifest["seccompPolicy"], ("architecture", "defaultAction", "noNewPrivilegesRequired",
        "installedBeforeUntrustedInput", "instructions", "syscallRules", "exactInstructionStreamSha256",
        "rawBpfSha256", "exactArgumentSemanticsSha256", "structurallyVerifiedPolicySha256"))
    p.require(policy["architecture"] == "x86-64" and policy["defaultAction"] == "kill-process"
        and policy["noNewPrivilegesRequired"] is True and policy["installedBeforeUntrustedInput"] is True)
    for name in ("exactInstructionStreamSha256", "rawBpfSha256", "exactArgumentSemanticsSha256",
                 "structurallyVerifiedPolicySha256"):
        p.digest(policy[name])
    provenance = p.fields(manifest["buildProvenance"], PROVENANCE_FIELDS)
    p.require(provenance["reproducibleBuildRequired"] is True)
    for name in set(provenance) - {"reproducibleBuildRequired"}:
        p.digest(provenance[name])
    p.require(provenance["provenanceSha256"] == p.framed(b"serverware.policyShadowCustodyBuildProvenance/v1",
        (p.canonical([provenance[name] for name in PROVENANCE_FIELDS[:-1]]),)))
    for field, source in (("dependencyLockSha256", "dependencyLockSha256"),
            ("buildRecipeSha256", "buildRecipeSha256"), ("provenanceStatementSha256", "provenanceSha256")):
        p.require(provenance[field] == image[source])
    p.require(manifest["manifestSha256"] == p.framed(b"serverware.nativeCustodyExecutionClosure/v2",
        (p.canonical([manifest[name] for name in MANIFEST_FIELDS[:-1]]),))
        == assignment["custodyAuthority"]["executionClosureManifestSha256"]
        and policy["structurallyVerifiedPolicySha256"]
        == assignment["custodyAuthority"]["structurallyVerifiedSeccompPolicySha256"])
    return manifest


def sign(*, input_original: bytes, signing_key):
    """Return the existing full v2 closure original and unchanged startup deadline.

    INPUT_FIELDS is closed; all *Original values are literal canonical ASCII
    strings, not paths. The entire input and explicit trustSha256 need separate
    authority approval. No authorization is inferred from observations or pins.
    """
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    value = p.fields(p.document(input_original, MAX_INPUT), INPUT_FIELDS)
    p.require(value["apiVersion"] == "serverware.nativePilotClosureAuthorityInput/v1")
    boot, wall = originals._boot(), time.time_ns()
    config, window, observed, guest = _guest(value)
    envelope, checkpoint, binding, issued_floor, expires_ceiling = _authority(value, signing_key, wall)
    manifest = _manifest(value, config, observed, envelope["payload"])
    _, payload = c9._original(value["payloadOriginal"], 65536)
    p.fields(payload, PAYLOAD_FIELDS)
    expected = {"apiVersion": "serverware.nativeCustodyClosureAssignment/v2",
        "purpose": "shadow-custody-bootstrap-late-runtime", "profile": PROFILE,
        "assignmentId": envelope["payload"]["assignmentId"], "assignmentPayloadSha256": envelope["payloadSha256"],
        "assignmentRevision": envelope["payload"]["assignmentRevision"], "manifestSha256": manifest["manifestSha256"],
        "guest": guest, "trustCheckpointId": checkpoint["checkpointId"],
        "revocationGeneration": checkpoint["revocationGeneration"], "revocationRootSha256": checkpoint["revocationRootSha256"],
        "issuedAtUnixNanos": payload["issuedAtUnixNanos"], "expiresAtUnixNanos": payload["expiresAtUnixNanos"],
        "signingKeyId": binding["keyId"], "signingKeySpkiSha256": binding["keySpkiSha256"]}
    c9._same(payload, expected)
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], wall)
    p.require(issued_floor <= payload["issuedAtUnixNanos"] < payload["expiresAtUnixNanos"] <= expires_ceiling
        and payload["expiresAtUnixNanos"] - payload["issuedAtUnixNanos"] <= p.DAY_NS)

    def check(previous_boot=0, previous_wall=wall):
        now = c9._live(window, previous_boot)
        current_wall = time.time_ns()
        p.require(originals._boot() == boot and previous_wall <= current_wall < expires_ceiling)
        p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], current_wall)
        return now, current_wall

    before_boot, before_wall = check()
    message = p.preimage(DOMAIN, payload)
    signature = signing_key.sign(message)
    signing_key.public_key().verify(signature, message)
    raw = p.canonical({"apiVersion": "serverware.nativeCustodyClosure/v2", "manifest": manifest,
        "authorization": {"payload": payload, "signature": p.encoded(signature)}})
    p.require(len(raw) <= MAX_BYTES)
    launch.shape("native-bridge-closure", raw)
    check(before_boot, before_wall)
    return raw, p.ns(window["startupDeadlineBoottimeNs"])
