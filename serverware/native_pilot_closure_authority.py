"""Fixed legacy bridge v2 and multi-guest v3 closure issuers.

Runs after genuine driver observation and operational C9 delivery, before bridge
launch installation. C9 signing does not consume a closure. This producer neither
creates the image/build provenance nor approves the complete input: the separate
authority must do that before invoking it with its existing supervisor key.
The protected trust original, not a candidate payload, selects verification keys.

The native receiver still validates seccomp semantics, trusted time/currentness,
actual image and retained driver/guest ownership. Local checks/signatures here
are not those measurements or approval. No legacy v1 endpoint issuer, key generation,
installation, history creation, renewed deadline or automatic retry is offered.

Input/v1 remains exact and bridge-only. Explicit Input/v2 has the same fields,
plus guestRole and closureSetOriginal; controlOriginal is present only for
bridge. Endpoint configuration/window/observation are the actual v7 cohort
configuration, signed precreation, and originals/v6. Every input is separately
approved; no arbitrary JSON is treated as a kernel owner. Both profiles retain
the same 8 MiB input and 1 MiB complete live closure bounds.
"""
from __future__ import annotations

import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import authority_policy_canary_native_opening as opening
from serverware import native_pilot_assignment as assignment_profile
from serverware import native_pilot_closure_set as closure_set
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
SET_INPUT_FIELDS = tuple(name for name in INPUT_FIELDS if name != "controlOriginal") + ("guestRole", "closureSetOriginal")
SET_DOMAIN = "serverware.nativeCustodyClosureAssignment.signature/v3"
SET_PROFILE = "native-multi-guest-closure-set-v1"
PAYLOAD_FIELDS = launch._CLOSURE
MANIFEST_FIELDS = launch._MANIFEST
PROVENANCE_FIELDS = ("sourceTreeSha256", "dependencyLockSha256", "buildRecipeSha256",
    "toolchainClosureSha256", "provenanceStatementSha256", "transparencyLogEntrySha256",
    "reproducibleBuildRequired", "provenanceSha256")


def _guest(value, *, boot, now):
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
    window = c9.bridge_owner(cold, cold_raw, config_raw, window_raw, signed_window, observed,
        boot=boot, now=now)
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


def _authority(value, now):
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
    assignment = opening.assignment_payload(envelope["payload"], version=assignment_profile.version(envelope))
    p.require(envelope["signingKeyId"] == trust["assignmentKey"]["keyId"]
        and envelope["signingKeySpkiSha256"] == trust["assignmentKey"]["keySpkiSha256"])
    assignment_key.verify(p.decoded(envelope["signature"], size=64),
        p.preimage(assignment_profile.domain(envelope), assignment))
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
    supervisor = {name: binding[name] for name in ("role", "keyId", "keySpkiSha256", "keyMaterialSha256")}
    supervisor["publicKeyBase64url"] = selected["publicKeyBase64url"]
    p.public_key(supervisor)
    issued_floor = max(trust["issuedAtUnixNanos"], assignment["issuedAtUnixNanos"],
        trust["assignmentKey"]["notBeforeUnixNanos"], selected["notBeforeUnixNanos"])
    expires_ceiling = min(trust["expiresAtUnixNanos"], assignment["expiresAtUnixNanos"],
        trust["assignmentKey"]["notAfterUnixNanos"], selected["notAfterUnixNanos"],
        checkpoint["asOfUnixNanos"] + 300_000_000_000)
    return envelope, checkpoint, binding, issued_floor, expires_ceiling, supervisor


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


def _endpoint_guest(value, role, *, boot, now):
    config_raw, config = c9._original(value["configurationOriginal"], 32768)
    window_raw, signed_window = c9._original(value["windowOriginal"], 32768)
    _, observed = c9._original(value["observationOriginal"], 32768)
    cold_raw, _ = c9._original(value["deliveryConfigurationOriginal"], 65536)
    cold = delivery.configuration(cold_raw, p.sha(cold_raw))
    window = c9.endpoint_owner(role, cold, cold_raw, config_raw, window_raw, signed_window, observed,
        boot=boot, now=now)
    c9.window_at(window, boot=boot, now=now)
    runtime_raw, _ = c9._original(value["runtimeOriginal"], 65536)
    launch.shape("native-runtime-" + role, runtime_raw)
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
    c9._same(payload["runtimeConfig"], {"path": launch.DESTINATIONS["native-runtime-" + role], "sha256": p.sha(runtime_raw)})
    c9._activation(payload["activation"], c9.ENDPOINTS[role])
    c9._credentials(payload["credentials"], cold["authority"])
    driver._key(cold["authority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
        delivery.DOMAIN + p.canonical(payload))
    return config, window, observed, delivery._delivery_guest(payload, signed_raw)


def prepare_input(input_original: bytes, *, boot, now_boottime_ns, now_unix_ns):
    """Pure existing closure checks and a full unsigned result template.

    INPUT_FIELDS is closed; all *Original values are literal canonical ASCII
    strings, not paths. The entire input and explicit trustSha256 need separate
    authority approval. Supplied clocks are data, never a reconstructed owner.
    """
    p.integer(now_boottime_ns, maximum=p.MAX_U64); p.integer(now_unix_ns)
    value = p.document(input_original, MAX_INPUT)
    multi = value.get("apiVersion") == "serverware.nativePilotClosureAuthorityInput/v2"
    role = value.get("guestRole") if multi else "bridge"
    p.require(type(role) is str and role in closure_set.ROLES)
    fields = SET_INPUT_FIELDS + (("controlOriginal",) if role == "bridge" else ()) if multi else INPUT_FIELDS
    p.fields(value, fields)
    p.require(value["apiVersion"] == "serverware.nativePilotClosureAuthorityInput/v" + ("2" if multi else "1"))
    wall = now_unix_ns
    config, window, observed, guest = (_guest(value, boot=boot, now=now_boottime_ns) if role == "bridge"
        else _endpoint_guest(value, role, boot=boot, now=now_boottime_ns))
    envelope, checkpoint, binding, issued_floor, expires_ceiling, supervisor = _authority(value, wall)
    p.require(assignment_profile.version(envelope) == (2 if multi else 1))
    selected = leaf = None
    if multi:
        set_raw, _ = c9._original(value["closureSetOriginal"], MAX_BYTES)
        leaf = assignment_profile.closure_binding(envelope, set_raw, role)
        selected = closure_set.validate(set_raw)
        _, manifest = c9._original(value["manifestOriginal"], MAX_BYTES)
        c9._same(manifest, selected["members"][closure_set.ROLES.index(role)]["manifest"])
        if role == "bridge":
            _manifest(value, config, observed, envelope["payload"])
        else:
            p.require(manifest["workerExecutableSha256"] == observed[role]["executable"]["sha256"]
                and manifest["runtimeConfigurationSha256"] == guest["runtimeConfigurationSha256"])
    else:
        manifest = _manifest(value, config, observed, envelope["payload"])
    _, payload = c9._original(value["payloadOriginal"], 65536)
    p.fields(payload, launch._CLOSURE_SET if multi else PAYLOAD_FIELDS)
    expected = {"apiVersion": "serverware.nativeCustodyClosureAssignment/v" + ("3" if multi else "2"),
        "purpose": "shadow-custody-closure-set-member" if multi else "shadow-custody-bootstrap-late-runtime",
        "profile": SET_PROFILE if multi else PROFILE,
        "assignmentId": envelope["payload"]["assignmentId"], "assignmentPayloadSha256": envelope["payloadSha256"],
        "assignmentRevision": envelope["payload"]["assignmentRevision"], "manifestSha256": manifest["manifestSha256"],
        "guest": guest, "trustCheckpointId": checkpoint["checkpointId"],
        "revocationGeneration": checkpoint["revocationGeneration"], "revocationRootSha256": checkpoint["revocationRootSha256"],
        "issuedAtUnixNanos": payload["issuedAtUnixNanos"], "expiresAtUnixNanos": payload["expiresAtUnixNanos"],
        "signingKeyId": binding["keyId"], "signingKeySpkiSha256": binding["keySpkiSha256"]}
    if multi:
        expected.update(guestRole=role, **{name: leaf[name] for name in ("setRootSha256", "seccompSetRootSha256", "leafSha256")})
    c9._same(payload, expected)
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], wall)
    p.require(issued_floor <= payload["issuedAtUnixNanos"] < payload["expiresAtUnixNanos"] <= expires_ceiling
        and payload["expiresAtUnixNanos"] - payload["issuedAtUnixNanos"] <= p.DAY_NS)

    result = {"apiVersion": "serverware.nativeCustodyClosure/v" + ("3" if multi else "2"), "manifest": manifest,
        "authorization": {"payload": payload, "signature": ""}}
    if multi:
        result["closureSet"] = selected
    # The whole original, not just its member, retains the live 1 MiB cap.
    # Check the exact encoded size before signing (Ed25519 base64url is86).
    p.require(len(p.canonical(result)) + 86 <= MAX_BYTES)
    return {"payload": payload, "supervisor": supervisor, "window": window,
        "deadline": p.ns(window["startupDeadlineBoottimeNs"]), "epochLimit": expires_ceiling,
        "domain": SET_DOMAIN if multi else DOMAIN, "result": result}


def checked_result(input_original, result, *, boot, now_boottime_ns, now_unix_ns):
    """Check the complete existing wrapper and real signature, not provenance."""
    prepared = prepare_input(input_original, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(result, ("original", "sha256"))
    raw, value = c9._original(result["original"], MAX_BYTES)
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    role = prepared["payload"].get("guestRole", "bridge")
    launch.shape("native-" + role + "-closure", raw)
    signature = value["authorization"]["signature"]
    expected = prepared["result"]
    expected["authorization"]["signature"] = signature
    c9._same(value, expected)
    p.public_key(prepared["supervisor"]).verify(p.decoded(signature, size=64),
        p.preimage(prepared["domain"], prepared["payload"]))
    return raw


def sign(*, input_original: bytes, signing_key):
    """Sign the existing v2/v3 wrapper with the original live key/window checks."""
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    boot, now, wall = originals._boot(), originals._clock(), time.time_ns()
    prepared = prepare_input(input_original, boot=boot, now_boottime_ns=now, now_unix_ns=wall)
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == prepared["supervisor"]["publicKeyBase64url"])
    payload, window = prepared["payload"], prepared["window"]

    def check(previous_boot=now, previous_wall=wall):
        current = c9._live(window, previous_boot)
        current_wall = time.time_ns()
        p.require(originals._boot() == boot and previous_wall <= current_wall < prepared["epochLimit"])
        p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], current_wall)
        return current, current_wall

    before_boot, before_wall = check()
    message = p.preimage(prepared["domain"], payload)
    result = prepared["result"]
    signature = signing_key.sign(message)
    p.public_key(prepared["supervisor"]).verify(signature, message)
    result["authorization"]["signature"] = p.encoded(signature)
    raw = p.canonical(result)
    p.require(len(raw) <= MAX_BYTES)
    launch.shape("native-" + payload.get("guestRole", "bridge") + "-closure", raw)
    check(before_boot, before_wall)
    return raw, prepared["deadline"]
