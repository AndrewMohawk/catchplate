"""Two existing driver-admission signatures over independently approved inputs.

No process is opened, sampled or reconstructed here. Observations/census must be
approved from the real retained conductor by the independent authority. These
data/signature checks do not authenticate that provenance, install a generation,
settle a reaper, reverify Nitro hardware, or replace receiving live-owner checks.

The canonical no-LF wrapper uses apiVersion
serverware.nativePilotDriverAuthorityInput/v1, operation, controlOriginal, configurationOriginal,
windowOriginal, deliveryConfigurationOriginal, and payloadOriginal. Bootstrap
adds observationOriginal. Constructed adds bootstrapAdmissionOriginal,
censusOriginal, publicAdmissionOriginal, launchOriginal,
verifierConfigurationOriginal, verifierConfigurationSha256,
assignmentPublicKeyOriginal, and assignmentPublicKeySha256. No other fields.
All originals are literal ASCII strings; the assignment public key is canonical
Ed25519 SPKI PEM, not JSON. Control/configuration/window and the separately pinned
verifier configuration/assignment public key require independent approval before
this API is called. Keys must never be selected from an unapproved request.

The existing prepared payload must match the fields derived from these originals
exactly. Only its genuinely observed process data and original issuance time are
accepted as approved observations; there is no new timestamp or renewed window.
"""
from __future__ import annotations

import copy
import re
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from serverware import native_pilot_assignment as assignment_profile
from serverware import native_pilot_bridge_runtime as bridge_runtime
from serverware import native_pilot_scope_authority as scope_authority
from serverware import native_shadow_bridge_admission_profile as bridge
from serverware import native_shadow_constructed_driver as admission
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_nitro_profile as p
from serverware import native_shadow_nitro_originals as originals

MAX_INPUT = 24 * 1024 * 1024
BOOTSTRAP_FIELDS = scope_authority.BOOTSTRAP_FIELDS
CONSTRUCTED_FIELDS = ("apiVersion", "purpose", "configurationSha256", "windowSha256",
    "bootstrapObservationSha256", "phaseScopeSha256", "censusSha256", "publicAdmissionSha256",
    "bootstrapAdmissionSha256", "kernelDriverIdentitySha256", "productionConfigurationBindingSha256",
    "assignmentId", "assignmentPayloadSha256", "assignmentRevision", "trustCheckpointId",
    "revocationGeneration", "revocationRootSha256", "issuedAtUnixNanos", "expiresAtUnixNanos",
    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "signingKeyId", "signingKeySpkiSha256")
INPUT_FIELDS = ("apiVersion", "operation", "controlOriginal", "configurationOriginal",
    "windowOriginal", "deliveryConfigurationOriginal", "payloadOriginal")
CONSTRUCTED_INPUTS = ("bootstrapAdmissionOriginal", "censusOriginal", "publicAdmissionOriginal",
    "launchOriginal", "verifierConfigurationOriginal", "verifierConfigurationSha256",
    "assignmentPublicKeyOriginal", "assignmentPublicKeySha256")
OBSERVATION_FIELDS = ("apiVersion", "configurationSha256", "windowSha256", "invocationId", "processId",
    "uid", "gid", "cgroupOriginalSha256", "root", "seccompFilterCount", "descriptors", "driver")
CONTEXT_RESULT_FIELDS = tuple(name for name in p.RESULT_FIELDS if name not in {
    "platform", "workerExecutableSha256", "executionClosureManifestSha256",
    "structurallyVerifiedSeccompPolicySha256", "quoteBoundCustodyKeySetRootSha256", "signature"}) + (
    "apiVersion", "purpose", "statementSha256", "nativeContextSha256", "admissionAuthorizationSha256",
    "keyAuthorizationSha256", "fullKeySetRootSha256", "localKeySetRootSha256")
_original = scope_authority._original
_same = scope_authority._same


def _process(value):
    p.fields(value, admission.PROCESS)
    for name in admission.PROCESS:
        p.integer(value[name], minimum=0 if name == "pidfdDevice" else 1,
                  maximum=(1 << 31) - 1 if name in ("processId", "parentId") else p.MAX_U64)
    p.require(value["processId"] > 1 and value["processId"] != value["parentId"])


def _common(value):
    _, control = _original(value["controlOriginal"], 4096)
    p.fields(control, ("apiVersion", "supervisorExecutableSha256", "configurationSha256", "windowSha256"))
    p.require(control["apiVersion"] == "serverware.nativeShadowDriverBootstrapControl/v1")
    for name in ("supervisorExecutableSha256", "configurationSha256", "windowSha256"):
        p.digest(control[name])
    config_raw, config = _original(value["configurationOriginal"], 65536)
    window_raw, signed = _original(value["windowOriginal"], 32768)
    p.require(p.sha(config_raw) == control["configurationSha256"] and p.sha(window_raw) == control["windowSha256"])
    p.fields(config, ("apiVersion", "bootstrapAuthority", "phaseTwoAuthority", "deliveryConfiguration",
        "uid", "gid", "image", "continuation", "lifecycle"))
    p.require(config["apiVersion"] == "serverware.nativeShadowDriverBootstrapConfiguration/v4")
    bootstrap_key = driver._key(config["bootstrapAuthority"])
    driver._key(config["phaseTwoAuthority"])
    p.require(config["bootstrapAuthority"]["publicKeyBase64url"] != config["phaseTwoAuthority"]["publicKeyBase64url"])
    policy = p.fields(config["lifecycle"], ("apiVersion", "gate", "cleanupReserveNanos", "constructedAdmissionAuthority"))
    p.require(policy["apiVersion"] == "serverware.nativeShadowDriverLifecyclePolicy/v3")
    gate = p.fields(policy["gate"], ("uid", "gid", "executableSha256"))
    p.require(gate["uid"] == gate["gid"] == 65534)
    p.digest(gate["executableSha256"])
    authority = policy["constructedAdmissionAuthority"]
    public = admission.authority(authority)
    p.require(authority["publicKeyBase64url"] not in (config["bootstrapAuthority"]["publicKeyBase64url"],
        config["phaseTwoAuthority"]["publicKeyBase64url"]))
    continuation = p.fields(config["continuation"], ("apiVersion", "keyTransport"))
    p.require(continuation["apiVersion"] == "serverware.nativeShadowDriverContinuationPreparation/v3")
    p.fields(config["image"], ("imageSha256", "executableSha256", "seccompPolicy", "bootstrapRuntimeSha256",
        "dependencyLockSha256", "buildRecipeSha256", "provenanceSha256"))
    for name in set(config["image"]) - {"seccompPolicy"}:
        p.digest(config["image"][name])
    cold_raw, _ = _original(value["deliveryConfigurationOriginal"], 65536)
    delivery._pin(config["deliveryConfiguration"])
    cold = delivery.configuration(cold_raw, config["deliveryConfiguration"]["sha256"])
    _same([cold["uid"], cold["gid"]], [config["uid"], config["gid"]])
    p.fields(signed, ("apiVersion", "payload", "signatureBase64url"))
    window = p.fields(signed["payload"], scope_authority.WINDOW_FIELDS)
    p.require(signed["apiVersion"] == "serverware.nativeShadowDriverBootstrapWindow/v1"
        and window["configurationSha256"] == control["configurationSha256"]
        and window["signingKeyId"] == config["bootstrapAuthority"]["keyId"])
    bootstrap_key.verify(p.decoded(signed["signatureBase64url"], size=64), driver.WINDOW_DOMAIN + p.canonical(window))
    issued, startup, lifetime = (p.ns(window[name]) for name in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued < startup <= lifetime and startup - issued <= 30_000_000_000
        and startup < lifetime - p.integer(policy["cleanupReserveNanos"], minimum=1_000_000, maximum=5_000_000_000)
        and type(window["invocationId"]) is str and re.fullmatch(r"[0-9a-f]{32}", window["invocationId"])
        and window["invocationId"] != "0" * 32)
    return control, config, cold, window, authority, public


def _observation(raw, control, config, window, now):
    observed = p.fields(p.document(raw, 65536), OBSERVATION_FIELDS)
    p.require(observed["apiVersion"] == "serverware.nativeShadowDriverObservation/v1"
        and observed["configurationSha256"] == control["configurationSha256"]
        and observed["windowSha256"] == control["windowSha256"] and observed["invocationId"] == window["invocationId"])
    _same([observed["uid"], observed["gid"]], [config["uid"], config["gid"]])
    p.integer(observed["processId"], minimum=2, maximum=(1 << 31) - 1)
    p.integer(observed["seccompFilterCount"], maximum=p.MAX_U64)
    p.digest(observed["cgroupOriginalSha256"])
    descriptors = observed["descriptors"]
    p.require(type(descriptors) is list and len(descriptors) == 4)
    for item, name in zip(descriptors, ("self-pidfd", "executable", "cgroup", "root"), strict=True):
        p.fields(item, ("name", "device", "inode", "mode", "mountId"))
        p.require(item["name"] == name)
        for field in ("device", "inode", "mode", "mountId"):
            p.integer(item[field], minimum=0 if field in ("device", "mode") else 1,
                      maximum=(1 << 32) - 1 if field == "mode" else p.MAX_U64)
    _same(observed["root"], descriptors[3])
    identity = p.fields(observed["driver"], scope_authority.DRIVER_FIELDS)
    for name in scope_authority.DRIVER_FIELDS:
        if name.endswith("Sha256"):
            p.digest(identity[name])
        else:
            p.integer(identity[name], maximum=p.MAX_U64)
    p.require(identity["identitySha256"] == p.framed(b"serverware.policyShadowCustodyKernelDriverIdentity/v1",
        (p.canonical([identity[name] for name in scope_authority.DRIVER_FIELDS[:-1]]),))
        and identity["driverExecutableSha256"] == config["image"]["executableSha256"]
        and identity["supervisorBootIdSha256"] == p.sha(p.decoded(window["bootIdBase64url"], size=16))
        and identity["retainedDescriptorManifestSha256"] == p.sha(p.canonical(descriptors))
        and identity["pidfdInode"] == descriptors[0]["inode"]
        and identity["cgroupInode"] == descriptors[2]["inode"] and identity["cgroupMountId"] == descriptors[2]["mountId"]
        and identity["driverInstanceSha256"] == p.sha(p.canonical([window["invocationId"], observed["processId"],
            identity["processStartTimeTicks"], identity["pidfdInode"]]))
        and p.ns(window["issuedAtBoottimeNs"]) <= identity["verifiedAtBoottimeNanos"] <= now)
    return observed


def _bootstrap(payload, observation_raw, control, window, authority):
    p.fields(payload, BOOTSTRAP_FIELDS)
    _process(payload["parent"])
    p.digest(payload["pidNamespaceSha256"])
    p.require(payload["expiresAtUnixNanos"] == p.integer(payload["issuedAtUnixNanos"]) + 30_000_000_000)
    expected = {"apiVersion": "serverware.nativeShadowBootstrapDriverAdmission/v1",
        "purpose": "native-driver-bootstrap-admission", "configurationSha256": control["configurationSha256"],
        "windowSha256": control["windowSha256"], "bootstrapObservationOriginal": observation_raw.decode("ascii"),
        "parent": payload["parent"], "parentExecutableSha256": control["supervisorExecutableSha256"],
        "pidNamespaceSha256": payload["pidNamespaceSha256"], "issuedAtUnixNanos": payload["issuedAtUnixNanos"],
        "expiresAtUnixNanos": payload["expiresAtUnixNanos"],
        **{name: window[name] for name in ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs")},
        "signingKeyId": authority["keyId"], "signingKeySpkiSha256": authority["keySpkiSha256"]}
    _same(payload, expected)


def _phase_bundle(original):
    """Public grammar and version-selected bounds, not signed scope admission."""
    raw, bundle = _original(original, bridge_runtime.MAX_BRIDGE_INPUT)
    p.fields(bundle, ("runtimeOriginal", "deliveryOriginal", "generationOriginals"))
    runtime_raw, runtime = bridge_runtime.original(bundle["runtimeOriginal"])
    version = bridge_runtime.version(runtime)
    p.require(version in (9, 10, 11) and (version in (10, 11) or len(raw) <= 1024 * 1024))
    return raw, bundle, runtime_raw, runtime


def _phase(value, exported, control, config, cold, window, observed):
    scope_raw, signed = _original(exported["phaseScopeOriginal"], 32768)
    p.fields(signed, ("payload", "signatureBase64url"))
    phase = p.fields(signed["payload"], ("apiVersion", "configurationSha256", "windowSha256", "observationSha256",
        "kernelDriverIdentitySha256", "invocationId", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs",
        "originals", "publicBundleSha256", "signingKeyId", "operation"))
    p.require(phase["apiVersion"] == "serverware.nativeShadowDriverScope/v4"
        and phase["signingKeyId"] == config["phaseTwoAuthority"]["keyId"])
    driver._key(config["phaseTwoAuthority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
        scope_authority.DOMAIN + p.canonical(phase))
    for field in ("configurationSha256", "windowSha256"):
        p.require(phase[field] == control[field])
    for field in ("invocationId", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"):
        p.require(phase[field] == window[field])
    p.require(phase["observationSha256"] == p.sha(exported["bootstrapObservationOriginal"].encode("ascii"))
        and phase["kernelDriverIdentitySha256"] == observed["driver"]["identitySha256"])
    bundle_raw, bundle, runtime_raw, runtime = _phase_bundle(exported["phaseBundleOriginal"])
    p.require(phase["publicBundleSha256"] == p.sha(bundle_raw))
    delivery_raw, signed_delivery = _original(bundle["deliveryOriginal"], 65536)
    p.fields(signed_delivery, ("apiVersion", "payload", "signatureBase64url"))
    c9 = p.fields(signed_delivery["payload"], delivery.FIELDS)
    p.require(signed_delivery["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1"
        and c9["configurationSha256"] == config["deliveryConfiguration"]["sha256"]
        and c9["authorityKeyId"] == cold["authority"]["keyId"])
    driver._key(cold["authority"]).verify(p.decoded(signed_delivery["signatureBase64url"], size=64),
        delivery.DOMAIN + p.canonical(c9))
    for name in ("serviceRole", "uid", "gid"):
        _same(c9[name], cold[name])
    for name in scope_authority.WINDOW_FIELDS[2:]:
        _same(c9[name], window[name])
    delivery._pin(c9["runtimeConfig"])
    p.require(c9["runtimeConfig"]["sha256"] == p.sha(runtime_raw))
    grants = p.fields(bundle["generationOriginals"], driver.ROLES)
    _same(phase["originals"], {"runtimeSha256": p.sha(runtime_raw), "deliverySha256": p.sha(delivery_raw),
        "generationGrants": {role: p.sha(scope_authority._generation_original(grants[role])[0]) for role in driver.ROLES}})
    launch_raw, launch = _original(value["launchOriginal"], 32768)
    p.fields(launch, ("apiVersion", "keyAdmission", "trustedTime"))
    p.require(launch["apiVersion"] == bridge_runtime.launch_for_runtime(runtime_raw))
    inner = p.fields(launch["keyAdmission"], ("apiVersion", "deliveryConfiguration", "delivery", "trust", "timeBootstrap",
        "assignment", "closure", "keys", "encryptedKeys", "admission", "verifierTransport"))
    p.require(inner["apiVersion"] == "serverware.nativeShadowGuestLaunch/v1"
        and inner["delivery"]["sha256"] == p.sha(delivery_raw))
    _same(inner["deliveryConfiguration"], config["deliveryConfiguration"])
    scope_authority._operation(phase["operation"], launch, c9, {"launch": launch_raw,
        "c9-configuration": value["deliveryConfigurationOriginal"].encode("ascii"),
        "c9-delivery": delivery_raw, "c9-runtime": runtime_raw})
    for field, original in (("closure", "closureOriginal"), ("assignment", "assignmentOriginal"),
                            ("keys", "keyConfigurationOriginal"), ("admission", "admissionAuthorizationOriginal")):
        p.require(inner[field]["sha256"] == p.sha(exported[original].encode("ascii")))
    return scope_raw, delivery._delivery_guest(c9, delivery_raw)


def _assignment(value, exported, verifier, keys, now):
    from serverware import authority_policy_canary_native_opening as opening
    text = value["assignmentPublicKeyOriginal"]
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= 4096)
    raw = text.encode("ascii")
    p.require(p.sha(raw) == p.digest(value["assignmentPublicKeySha256"]))
    key = serialization.load_pem_public_key(raw)
    p.require(isinstance(key, Ed25519PublicKey) and key.public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo) == raw)
    _, envelope = _original(exported["assignmentOriginal"], 4 * 1024 * 1024)
    p.fields(envelope, ("apiVersion", "kind", "canonicalProfile", "signatureDomain", "payload",
        "payloadSha256", "signatureAlgorithm", "signingKeyId", "signingKeySpkiSha256", "signature"))
    assignment_profile.shape(envelope)
    payload = opening.assignment_payload(envelope["payload"], version=assignment_profile.version(envelope))
    spki = p.sha(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    domain = assignment_profile.domain(envelope)
    p.require(envelope["apiVersion"] == envelope["signatureDomain"] == domain
        and envelope["kind"] == "PolicyShadowAssignment" and envelope["canonicalProfile"] == "serverware.canonicalJson/ascii-integer-v1"
        and envelope["signatureAlgorithm"] == "Ed25519" and envelope["signingKeyId"] == envelope["signingKeySpkiSha256"] == spki
        and envelope["payloadSha256"] == p.sha(p.canonical(payload)))
    key.verify(p.decoded(envelope["signature"], size=64), p.preimage(domain, payload))
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], now)
    authorized = verifier["authorization"]["payload"]
    for name in ("assignmentId", "assignmentRevision"):
        p.require(payload[name] == authorized[name])
    p.require(envelope["payloadSha256"] == authorized["assignmentPayloadSha256"])
    _, root = opening._keys(payload, "custody-supervisor-capability")
    p.require(root == p.key_root(keys))
    bindings = {entry["role"]: entry for entry in payload["authorityKeyIndependence"]["bindings"]
                if entry["scopeSha256"] == payload["assignmentId"] and entry["role"] in p.ROLES}
    for entry in keys:
        p.require(all(bindings[entry["role"]][name] == entry[name]
                      for name in ("keyId", "keySpkiSha256", "keyMaterialSha256")))
    return envelope


def _closure(exported, config, verifier, scope, key, now, assignment):
    from serverware import native_pilot_launch_publication as launch
    _, closure = _original(exported["closureOriginal"], 1024 * 1024)
    multi = assignment_profile.version(assignment) == 2
    launch.shape("native-bridge-closure", p.canonical(closure))
    p.require(closure["apiVersion"] == "serverware.nativeCustodyClosure/v" + ("3" if multi else "2"))
    fields = ("apiVersion", "profile", "imageSha256", "workerExecutableSha256", "seccompPolicy",
              "runtimeConfigurationSha256", "buildProvenance", "manifestSha256")
    manifest = p.fields(closure["manifest"], fields)
    p.require(manifest["apiVersion"] == "serverware.nativeCustodyExecutionClosure/v2"
        and manifest["profile"] == "measured-bootstrap-late-runtime-static-amd64-v1"
        and manifest["manifestSha256"] == scope["executionClosureManifestSha256"]
        and manifest["manifestSha256"] == p.framed(b"serverware.nativeCustodyExecutionClosure/v2",
            (p.canonical([manifest[name] for name in fields[:-1]]),)))
    image = config["image"]
    _same([manifest["imageSha256"], manifest["workerExecutableSha256"], manifest["seccompPolicy"], manifest["runtimeConfigurationSha256"]],
          [image["imageSha256"], image["executableSha256"], image["seccompPolicy"], image["bootstrapRuntimeSha256"]])
    p.require(manifest["workerExecutableSha256"] == scope["workerExecutableSha256"]
        and manifest["seccompPolicy"]["structurallyVerifiedPolicySha256"] == scope["structurallyVerifiedSeccompPolicySha256"])
    provenance = p.fields(manifest["buildProvenance"], ("sourceTreeSha256", "dependencyLockSha256", "buildRecipeSha256",
        "toolchainClosureSha256", "provenanceStatementSha256", "transparencyLogEntrySha256", "reproducibleBuildRequired", "provenanceSha256"))
    p.require(provenance["reproducibleBuildRequired"] is True)
    for name in set(provenance) - {"reproducibleBuildRequired"}:
        p.digest(provenance[name])
    p.require(provenance["dependencyLockSha256"] == image["dependencyLockSha256"]
        and provenance["buildRecipeSha256"] == image["buildRecipeSha256"]
        and provenance["provenanceStatementSha256"] == image["provenanceSha256"])
    signed = p.fields(closure["authorization"], ("payload", "signature"))
    payload = p.fields(signed["payload"], launch._CLOSURE_SET if multi else launch._CLOSURE)
    p.require(payload["manifestSha256"] == manifest["manifestSha256"])
    if multi:
        leaf = assignment_profile.closure_binding(assignment, p.canonical(closure["closureSet"]), "bridge")
        p.require(payload["guestRole"] == "bridge")
        for name in ("setRootSha256", "seccompSetRootSha256", "leafSha256", "manifestSha256"):
            p.require(payload[name] == leaf[name])
    else:
        p.require(payload["apiVersion"] == "serverware.nativeCustodyClosureAssignment/v2"
            and payload["purpose"] == "shadow-custody-bootstrap-late-runtime" and payload["profile"] == manifest["profile"])
    auth = verifier["authorization"]["payload"]
    for name in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision", "guest", "trustCheckpointId",
                 "revocationGeneration", "revocationRootSha256", "signingKeyId", "signingKeySpkiSha256"):
        _same(payload[name], auth[name])
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], now)
    key.verify(p.decoded(signed["signature"], size=64),
        p.preimage("serverware.nativeCustodyClosureAssignment.signature/v" + ("3" if multi else "2"), payload))
    return payload["expiresAtUnixNanos"]


def _evidence(exported, verifier, scope, keys, now):
    from serverware.native_shadow_nitro_verifier import _revocation
    _, evidence = _original(exported["evidenceOriginal"], 131072)
    p.fields(evidence, p.EVIDENCE_FIELDS)
    p.require(evidence["apiVersion"] == "serverware.nativeShadowBridgeAdmissionEvidence/v1")
    statement = bridge.statement(evidence["statement"], scope)
    proofs = evidence["possession"]
    p.require(type(proofs) is list and len(proofs) == len(statement["localKeys"]))
    statement_sha = p.sha(p.canonical(statement))
    for key, proof in zip(statement["localKeys"], proofs, strict=True):
        p.fields(proof, ("role", "keyId", "signature"))
        p.require(proof["role"] == key["role"] and proof["keyId"] == key["keyId"])
        p.public_key(key).verify(p.decoded(proof["signature"], size=64),
            p.preimage(bridge.POSSESSION_DOMAIN, [key["role"], key["keyId"], statement_sha]))
    user_data = bridge.PREFIX + b"".join(p.raw_digest(item) for item in (statement_sha,
        statement["fullKeySetRootSha256"], statement["localKeySetRootSha256"], p.sha(p.canonical(proofs))))
    p.require(p.decoded(evidence["userDataBase64url"], maximum=1024) == user_data
        and p.decoded(evidence["publicKeyBase64url"], size=32) == p.raw_digest(statement["localKeySetRootSha256"])
        and p.decoded(evidence["nonceBase64url"], size=32) == p.decoded(statement["challengeBase64url"], size=32))
    quote_sha = p.sha(p.decoded(evidence["attestationDocumentBase64url"]))
    _, combined = _original(exported["combinedResultOriginal"], 32768)
    p.fields(combined, ("apiVersion", "contextResultOriginal", "productionResultOriginal"))
    p.require(combined["apiVersion"] == "serverware.nativeShadowBridgeAdmissionVerifierResult/v1")
    _, context = _original(combined["contextResultOriginal"], 32768)
    p.fields(context, ("apiVersion", "payload", "signature"))
    p.require(context["apiVersion"] == "serverware.nativeShadowBridgeContextVerifierResult/v1")
    result = p.fields(context["payload"], CONTEXT_RESULT_FIELDS)
    p.require(result["apiVersion"] == "serverware.nativeShadowBridgeContextResult/v1"
        and result["purpose"] == "native-shadow-context-and-production-admission")
    signer = keys[-2]
    verify = p.public_key(signer)
    verify.verify(p.decoded(context["signature"], size=64), p.preimage(bridge.RESULT_DOMAIN, result))
    _, production = _original(combined["productionResultOriginal"], 32768)
    p.fields(production, ("apiVersion", "result"))
    p.require(production["apiVersion"] == "serverware.nativeShadowNitroVerifierResult/v1")
    actual = p.fields(production["result"], p.RESULT_FIELDS)
    verify.verify(p.decoded(actual["signature"], size=64), p.preimage(p.RESULT_DOMAIN,
        p.result_payload({name: actual[name] for name in p.RESULT_FIELDS[:-1]})))
    for name in ("productionConfigurationBindingSha256", "nativeContextSha256", "admissionAuthorizationSha256",
                 "keyAuthorizationSha256", "fullKeySetRootSha256", "localKeySetRootSha256"):
        p.require(result[name] == statement[name])
    p.require(result["quoteSha256"] == quote_sha and result["statementSha256"] == statement_sha
        and result["signingKeyId"] == signer["keyId"] and result["signingKeySpkiSha256"] == signer["keySpkiSha256"])
    expected = p.fields(verifier["expectedAttestation"], ("platform", "expectedMeasurementSha256",
        "endorsementRootSha256", "collateralPolicySha256", "revocationSourceSha256"))
    p.require(expected["platform"] == "aws-nitro-enclave" and result["measurementSha256"] == expected["expectedMeasurementSha256"])
    for name in ("endorsementRootSha256", "collateralPolicySha256", "revocationSourceSha256"):
        p.require(result[name] == expected[name])
    _, revocation_source, revocation_root = _revocation(verifier["collateralRevocation"], now)
    p.require(result["revocationSourceSha256"] == revocation_source
        and result["collateralRevocationGeneration"] == verifier["collateralRevocation"]["generation"]
        and result["collateralRevocationRootSha256"] == revocation_root)
    checkpoint = verifier["trustCheckpoint"]
    for field, name in (("trustCheckpointId", "checkpointId"), ("trustRevocationGeneration", "revocationGeneration"),
                        ("trustRevocationRootSha256", "revocationRootSha256")):
        p.require(result[field] == checkpoint[name])
    p.freshness(result["verifiedAtUnixNanos"], result["expiresAtUnixNanos"], now, verifier["maximumResultAgeNanos"])
    p.require(result["expiresAtUnixNanos"] <= min(result["verifiedAtUnixNanos"] + verifier["maximumResultAgeNanos"],
        verifier["authorization"]["payload"]["expiresAtUnixNanos"], verifier["admissionAuthorization"]["payload"]["expiresAtUnixNanos"],
        verifier["collateralRevocation"]["expiresAtUnixNanos"], checkpoint["asOfUnixNanos"] + 300_000_000_000))
    expected_production = {name: result[name] for name in p.RESULT_FIELDS if name in result}
    expected_production.update(platform="aws-nitro-enclave", workerExecutableSha256=statement["workerExecutableSha256"],
        executionClosureManifestSha256=statement["executionClosureManifestSha256"],
        structurallyVerifiedSeccompPolicySha256=statement["structurallyVerifiedSeccompPolicySha256"],
        quoteBoundCustodyKeySetRootSha256=statement["fullKeySetRootSha256"], signature=actual["signature"])
    _same(actual, expected_production)
    return statement, result["expiresAtUnixNanos"]


def _census(raw, early, observed, control, window, scope_raw, statement, now):
    census = p.fields(p.document(raw, 48 * 1024), admission.CENSUS)
    p.require(census["apiVersion"] == "serverware.nativeShadowDriverLifecycleObservation/v1"
        and census["phase"] == "constructed-driver-subtree" and census["configurationSha256"] == control["configurationSha256"]
        and census["windowSha256"] == control["windowSha256"] and census["scopeSha256"] == p.sha(scope_raw)
        and census["bootstrapObservationSha256"] == p.sha(early["bootstrapObservationOriginal"].encode("ascii"))
        and census["lifetimeDeadlineBoottimeNs"] == window["lifetimeDeadlineBoottimeNs"]
        and p.ns(window["issuedAtBoottimeNs"]) <= p.ns(census["observedAtBoottimeNs"]) <= now)
    for name in ("parent", "parentExecutableSha256", "pidNamespaceSha256"):
        _same(census[name], early[name])
    _process(census["driver"])
    current = census["driver"]
    p.require(current["processId"] == observed["processId"] and current["parentId"] == early["parent"]["processId"]
        and current["startTimeTicks"] == observed["driver"]["processStartTimeTicks"]
        and current["pidfdInode"] == observed["driver"]["pidfdInode"]
        and current["pidfdDevice"] == observed["descriptors"][0]["device"])
    descendants, descriptors = census["descendants"], census["descriptors"]
    p.require(type(descendants) is list and 1 <= len(descendants) <= 16 and current in descendants
        and type(descriptors) is list and 1 <= len(descriptors) <= 256)
    for item in descendants:
        _process(item)
    pids = [item["processId"] for item in descendants]
    p.require(pids == sorted(set(pids)) and early["parent"]["processId"] not in pids)
    for item in descriptors:
        p.fields(item, admission.DESCRIPTOR)
        for name in admission.DESCRIPTOR:
            p.integer(item[name], minimum=0, maximum=p.MAX_U64)
    fds = [item["fd"] for item in descriptors]
    p.require(fds == sorted(set(fds)) and census["descriptorSetSha256"] == p.sha(p.canonical(descriptors)))
    for expected in observed["descriptors"]:
        p.require(any(all(item[name] == expected[name] for name in ("device", "inode", "mode", "mountId")) for item in descriptors))
    context = statement["nativeContext"]
    for process, prefix in ((current, ""), (early["parent"], "parent")):
        fields = ("processId", "processStartTicks", "pidfdInode") if not prefix else ("parentProcessId", "parentStartTicks", "parentPidfdInode")
        _same([context[name] for name in fields], [process[name] for name in ("processId", "startTimeTicks", "pidfdInode")])
    p.require(context["cgroupSha256"] == observed["cgroupOriginalSha256"]
        and context["rootDevice"] == observed["root"]["device"] and context["rootInode"] == observed["root"]["inode"]
        and p.ns(context["observedAtBoottimeNs"]) <= now)


def prepare_input(operation: str, input_original: bytes, *, boot, now_boottime_ns, now_unix_ns):
    """Validate the real issuer input at explicit clocks, without signing.

    These data checks do not establish the provenance of an observation. The
    protected producer and retained supervisor separately own that boundary.
    Preparation always requires the original startup window, including when
    an already signed result will later be consumed during the lifetime phase.
    """
    p.require(operation in ("bootstrap", "constructed"))
    extra = ("observationOriginal",) if operation == "bootstrap" else CONSTRUCTED_INPUTS
    value = p.fields(p.document(input_original, MAX_INPUT), INPUT_FIELDS + extra)
    p.require(value["apiVersion"] == "serverware.nativePilotDriverAuthorityInput/v1" and value["operation"] == operation)
    control, config, cold, window, authority, public = _common(value)
    maximum = 8192 if operation == "bootstrap" else 16384
    payload_raw, payload = _original(value["payloadOriginal"], maximum)
    if operation == "bootstrap":
        observation_raw, _ = _original(value["observationOriginal"], 65536)
        early = payload
    else:
        bootstrap_raw, signed_bootstrap = _original(value["bootstrapAdmissionOriginal"], 8192)
        p.fields(signed_bootstrap, ("payload", "signature"))
        early = signed_bootstrap["payload"]
        public.verify(p.decoded(signed_bootstrap["signature"], size=64), p.preimage(admission.BOOTSTRAP_DOMAIN, early))
        public_raw, exported = _original(value["publicAdmissionOriginal"], 8 * 1024 * 1024)
        p.fields(exported, admission.PUBLIC)
        p.require(exported["apiVersion"] == "serverware.nativeShadowDriverPublicAdmission/v1")
        observation_raw, _ = _original(exported["bootstrapObservationOriginal"], 65536)
    _bootstrap(early, observation_raw, control, window, authority)
    now, wall = p.integer(now_boottime_ns, maximum=p.MAX_U64), p.integer(now_unix_ns)
    p.require(type(boot) is tuple and boot == (window["bootIdBase64url"],
        window["timeNamespaceDevice"], window["timeNamespaceInode"])
        and p.ns(window["issuedAtBoottimeNs"]) <= now < p.ns(window["startupDeadlineBoottimeNs"]))
    p.freshness(early["issuedAtUnixNanos"], early["expiresAtUnixNanos"], wall)
    observed = _observation(observation_raw, control, config, window, now)
    p.require(early["parent"]["processId"] != observed["processId"])
    expiries = [early["expiresAtUnixNanos"]]
    if operation == "constructed":
        p.fields(payload, CONSTRUCTED_FIELDS)
        scope_raw, guest = _phase(value, exported, control, config, cold, window, observed)
        verifier_raw, verifier = _original(value["verifierConfigurationOriginal"], p.MAX_CONFIG)
        p.require(p.sha(verifier_raw) == p.digest(value["verifierConfigurationSha256"]))
        scope, keys = bridge.authorization(verifier, wall)
        _same(keys[-1], {"role": "custody-supervisor-capability", **authority})
        _same(scope["guest"], guest)
        _, key_configuration = _original(exported["keyConfigurationOriginal"], 65536)
        p.fields(key_configuration, ("apiVersion", "authorization"))
        p.require(key_configuration["apiVersion"] == "serverware.nativeShadowRoleKeys/v2")
        _same(key_configuration["authorization"], verifier["authorization"])
        _, admitted = _original(exported["admissionAuthorizationOriginal"], 65536)
        _same(admitted, verifier["admissionAuthorization"])
        assignment_envelope = _assignment(value, exported, verifier, keys, wall)
        assignment = assignment_envelope["payload"]
        custody = assignment["custodyAuthority"]
        p.require(custody["executionClosureManifestSha256"] == scope["executionClosureManifestSha256"]
            and custody["structurallyVerifiedSeccompPolicySha256"] == scope["structurallyVerifiedSeccompPolicySha256"])
        mode = custody["attestationMode"]
        _same({name: mode[name] for name in verifier["expectedAttestation"]}, verifier["expectedAttestation"])
        expiries.append(_closure(exported, config, verifier, scope, public, wall, assignment_envelope))
        statement, result_expiry = _evidence(exported, verifier, scope, keys, wall)
        expiries.extend((result_expiry, assignment["expiresAtUnixNanos"], verifier["authorization"]["payload"]["expiresAtUnixNanos"],
            verifier["admissionAuthorization"]["payload"]["expiresAtUnixNanos"]))
        census_raw, _ = _original(value["censusOriginal"], 48 * 1024)
        _census(census_raw, early, observed, control, window, scope_raw, statement, now)
        authorized = verifier["authorization"]["payload"]
        expected = {"apiVersion": "serverware.nativeShadowConstructedDriverAdmission/v1", "purpose": "constructed-native-driver-admission",
            "configurationSha256": control["configurationSha256"], "windowSha256": control["windowSha256"],
            "bootstrapObservationSha256": p.sha(observation_raw), "phaseScopeSha256": p.sha(scope_raw),
            "censusSha256": p.sha(census_raw), "publicAdmissionSha256": p.sha(public_raw),
            "bootstrapAdmissionSha256": p.sha(bootstrap_raw), "kernelDriverIdentitySha256": observed["driver"]["identitySha256"],
            "productionConfigurationBindingSha256": statement["productionConfigurationBindingSha256"],
            **{name: authorized[name] for name in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision",
                "trustCheckpointId", "revocationGeneration", "revocationRootSha256")},
            "issuedAtUnixNanos": payload["issuedAtUnixNanos"], "expiresAtUnixNanos": min(authorized["expiresAtUnixNanos"], early["expiresAtUnixNanos"]),
            **{name: window[name] for name in ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs")},
            "signingKeyId": authority["keyId"], "signingKeySpkiSha256": authority["keySpkiSha256"]}
        _same(payload, expected)
        p.require(early["issuedAtUnixNanos"] <= payload["issuedAtUnixNanos"])
    p.require(p.canonical(payload) == payload_raw)
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], wall, 30_000_000_000)
    p.require(wall < min(expiries))
    domain = admission.BOOTSTRAP_DOMAIN if operation == "bootstrap" else admission.DOMAIN
    return copy.deepcopy({"payload": payload, "authority": authority, "window": window,
        "deadline": p.ns(window["startupDeadlineBoottimeNs"]),
        "epochLimit": min(payload["expiresAtUnixNanos"], *expiries), "domain": domain})


def checked_result(operation, input_original, result, *, boot, now_boottime_ns, now_unix_ns):
    """Check an existing result's exact bytes/signature, not publication."""
    prepared = prepare_input(operation, input_original, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    return _checked_result(operation, input_original, result, prepared)


def _checked_result(operation, input_original, result, prepared):
    # Internal same-call continuation after complete preparation, not an
    # alternate public admission route accepting a caller's expected payload.
    p.fields(result, ("original", "sha256"))
    maximum = 8192 if operation == "bootstrap" else 16384
    raw, signed = _original(result["original"], maximum)
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    extra = () if operation == "bootstrap" else ("bootstrapAdmissionOriginal",)
    p.fields(signed, ("payload", "signature") + extra)
    _same(signed["payload"], prepared["payload"])
    if extra:
        value = p.document(input_original, MAX_INPUT)
        p.require(signed["bootstrapAdmissionOriginal"] == value["bootstrapAdmissionOriginal"])
    admission.authority(prepared["authority"]).verify(p.decoded(signed["signature"], size=64),
        p.preimage(prepared["domain"], prepared["payload"]))
    return raw


def sign(operation: str, input_original: bytes, signing_key: Ed25519PrivateKey) -> bytes:
    """Return only the selected existing envelope, never a live owner/verdict."""
    boot = originals._boot()
    now, wall = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
    prepared = prepare_input(operation, input_original, boot=boot,
        now_boottime_ns=now, now_unix_ns=wall)
    value = p.document(input_original, MAX_INPUT)
    payload, window, domain = prepared["payload"], prepared["window"], prepared["domain"]
    public = admission.authority(prepared["authority"])
    p.require(isinstance(signing_key, Ed25519PrivateKey)
        and signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        == public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    early = payload if operation == "bootstrap" else _original(value["bootstrapAdmissionOriginal"], 8192)[1]["payload"]
    current_boot, current_wall = scope_authority._live(window, early, now, wall)
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], current_wall, 30_000_000_000)
    p.require(current_wall < prepared["epochLimit"])
    signature = signing_key.sign(p.preimage(domain, payload))
    public.verify(signature, p.preimage(domain, payload))
    result = {"payload": payload, "signature": p.encoded(signature)}
    if operation == "constructed":
        result["bootstrapAdmissionOriginal"] = value["bootstrapAdmissionOriginal"]
    raw = p.canonical(result)
    p.require(len(raw) <= (8192 if operation == "bootstrap" else 16384))
    _, after = scope_authority._live(window, early, current_boot, current_wall)
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], after, 30_000_000_000)
    p.require(after < prepared["epochLimit"])
    return raw
