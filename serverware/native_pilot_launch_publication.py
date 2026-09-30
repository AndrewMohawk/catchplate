"""Install one independently approved native-pilot launch and its public pins.

The closed bundle supplies complete originals; nothing here signs, allocates a
guest, creates a credential, selects an authority, or constructs runtime state.
The actual C9/grant/guest receivers still authenticate authority, trusted time,
kernel resources and native evidence. Local epoch checks are not trusted time.
Public key authorization and encrypted-delivery metadata contain no key seeds;
the separately provisioned C9 credential files are never opened here.

Existing cold/C9/grant files and the original owner configuration/window are
retained. New nested originals (including the per-role verifier transport) and
endpoint runtime are installed before the selected launch, exclusively. The
first three endpoint C9 intakes only validate the runtime PIN; publication here
precedes their actual native runtime read. Bridge runtime was installed earlier
by native_pilot_bridge_install and is checked, never reinstalled or adopted.

Each fixed role can be attempted once per process. Partial files remain after
failure; there is no replacement, repair, retry, renewed window or cleanup.
An independently operated watchdog must bound filesystem/cryptographic stalls.
"""
from __future__ import annotations

import os
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_generation_install_authority as generation
from serverware import native_pilot_native_service_authority as services
from serverware import native_pilot_publication as publication
from serverware import native_shadow_bridge_admission_profile as bridge_admission
from serverware import native_shadow_commitment_artifacts as commitment
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_driver_outgoing as outgoing
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_key_admission_profile as admission
from serverware import native_shadow_key_contract as encrypted
from serverware import native_shadow_proof_cohort_assignment as cohort
from serverware import native_shadow_proof_cohort_control as control

p = delivery.p
MAX_INPUT = 16 * 1024 * 1024
FIELDS = ("apiVersion", "role", "ownerConfigurationSha256", "windowSha256", "observationOriginal",
    "keyAdmission", "runtimeOriginal", "originals", "serviceGrant")
ROLES = cohort.ENDPOINT_ROLES + ("bridge",)
# Exact existing native_guest::selection profiles, not a caller version switch.
LAUNCHES = {
    "retrieval": ("nativeShadowRetrievalGuestLaunch/v4", "retrieval", "retrieval"),
    "persistence": ("nativeShadowPersistenceGuestLaunch/v2", "persistence", "persistence"),
    "trustedTime": ("nativeShadowTrustedTimeGuestLaunch/v1", "trustedTime", "trustedTime"),
    "generationInstall": ("nativeShadowGenerationGuestLaunch/v1", "generation", None),
    "commitRequest": ("nativeShadowCommitRequestGuestLaunch/v3", "commitRequest", "ledger"),
    "ingressAdmission": ("nativeShadowIngressGuestLaunch/v1", "ingress", "ingress"),
    "terminalAppend": ("nativeShadowTerminalSpoolGuestLaunch/v1", "terminalSpool", "terminal"),
    "dispatchBarrier": ("nativeShadowDispatchBarrierGuestLaunch/v1", "dispatchBarrier", "dispatchBarrier"),
    "activeEffectBarrier": ("nativeShadowActiveEffectBarrierGuestLaunch/v1", "activeEffectBarrier", "activeEffectBarrier"),
    "activeEffectCommit": ("nativeShadowActiveEffectCommitGuestLaunch/v1", "activeEffectCommit", "activeEffectCommit"),
    "bridge": ("nativeProofBridgeLaunch/v5", "trustedTime", "trustedTime"),
}
COMPONENTS = {
    "trust": ("trust", 1024 * 1024), "timeBootstrap": ("time-bootstrap", 65536),
    "assignment": ("assignment", 4 * 1024 * 1024), "closure": ("closure", 1024 * 1024),
    "keys": ("keys", 65536), "encryptedKeys": ("encrypted-keys", 65536),
    "admission": ("admission", 65536), "verifierTransport": ("verifier", 32768),
}
PURPOSES = {**{"native-launch-" + role: 32768 for role in ROLES},
    **{"native-runtime-" + role: 65536 for role in cohort.ENDPOINT_ROLES},
    **{"native-" + role + "-" + suffix: maximum for role in ROLES for suffix, maximum in COMPONENTS.values()}}
DESTINATIONS = {purpose: "/etc/serverware/native-pilot-inputs/" + purpose + ".json" for purpose in PURPOSES}
INNER_FIELDS = ("apiVersion", "deliveryConfiguration", "delivery") + tuple(COMPONENTS)
_ENVELOPE = ("apiVersion", "kind", "canonicalProfile", "signatureDomain", "payload", "payloadSha256",
    "signatureAlgorithm", "signingKeyId", "signingKeySpkiSha256", "signature")
_ASSIGNMENT = ("assignmentId", "canaryId", "assignmentRevision", "generationEpoch", "minimumGenerationTombstoneEpoch",
    "policyIdentity", "expectedLoadedSnapshots", "responseValidationObligations", "responseValidationObligationsRootSha256",
    "fleet", "custodyAuthority", "authorityKeyIndependence", "observationWindow", "readinessThresholds",
    "issuedAtUnixNanos", "expiresAtUnixNanos")
_MANIFEST = ("apiVersion", "profile", "imageSha256", "workerExecutableSha256", "seccompPolicy",
    "runtimeConfigurationSha256", "buildProvenance", "manifestSha256")
_CLOSURE = ("apiVersion", "purpose", "profile", "assignmentId", "assignmentPayloadSha256", "assignmentRevision",
    "manifestSha256", "guest", "trustCheckpointId", "revocationGeneration", "revocationRootSha256",
    "issuedAtUnixNanos", "expiresAtUnixNanos", "signingKeyId", "signingKeySpkiSha256")
_ENCRYPTED = ("apiVersion", "purpose", "assignmentId", "assignmentPayloadSha256", "assignmentRevision",
    "keyAuthorizationSha256", "guest", "fullKeySetRootSha256", "localKeySetRootSha256", "challengeBase64url",
    "transport", "trustCheckpointId", "revocationGeneration", "revocationRootSha256", "issuedAtUnixNanos",
    "expiresAtUnixNanos", "signingKeyId", "signingKeySpkiSha256")
_VERIFIER = ("apiVersion", "purpose", "assignmentId", "assignmentPayloadSha256", "assignmentRevision",
    "keyAuthorizationSha256", "guest", "fullKeySetRootSha256", "challengeBase64url", "verifierKeyId",
    "verifierKeySpkiSha256", "verifierKeyMaterialSha256", "parentPort", "trustCheckpointId", "revocationGeneration",
    "revocationRootSha256", "issuedAtUnixNanos", "expiresAtUnixNanos", "signingKeyId", "signingKeySpkiSha256")
_KEY = ("keyId", "keySpkiSha256", "publicKeyBase64url", "notBeforeUnixNanos", "notAfterUnixNanos")
_ATTEMPTED = set()
_FAILED = False
_COUNT = _BYTES = 0


def _signed(value, fields):
    p.fields(value, ("payload", "signature"))
    p.decoded(value["signature"], size=64)
    return p.fields(value["payload"], fields)


def _inner(value, role):
    p.fields(value, INNER_FIELDS)
    p.require(value["apiVersion"] == "serverware.nativeShadowGuestLaunch/v1")
    for name in INNER_FIELDS[1:]:
        delivery._pin(value[name])
    p.require(value["delivery"]["path"] == publication.DESTINATIONS["native-delivery-" + role])
    if role != "bridge":
        p.require(value["deliveryConfiguration"]["path"] == publication.DESTINATIONS["native-cold-" + role])
    for name, (suffix, _) in COMPONENTS.items():
        p.require(value[name]["path"] == DESTINATIONS["native-" + role + "-" + suffix])


def _grant_purpose(role):
    if role == "generationInstall":
        return "native-generation-install-grant"
    return "native-service-" + LAUNCHES[role][2]


def shape(purpose: str, raw: bytes) -> dict:
    """Pure closed wire shape for fixed publication slots, not admission."""
    p.require(purpose in PURPOSES)
    value = p.document(raw, PURPOSES[purpose])
    if purpose.startswith("native-launch-"):
        role = purpose[len("native-launch-"):]
        api, field, _ = LAUNCHES[role]
        p.fields(value, ("apiVersion", "keyAdmission", field))
        p.require(value["apiVersion"] == "serverware." + api)
        _inner(value["keyAdmission"], role)
        delivery._pin(value[field])
        p.require(value[field]["path"] == publication.DESTINATIONS[_grant_purpose(role)])
        return value
    if purpose.startswith("native-runtime-"):
        # Exact existing serde version/optional-field combinations. The actual
        # native endpoint, not this installer, validates operational semantics.
        extra = {4: (), 5: ("generationAdmission",), 6: ("generationAdmission", "commitRequest"),
            7: ("generationAdmission", "commitRequest", "spool"),
            8: ("generationAdmission", "commitRequest", "spool"),
            9: ("generationAdmission", "commitRequest", "spool")}
        versions = {"serverware.policyCustodyProductionRpcRuntime/v" + str(version): fields
            for version, fields in extra.items()}
        p.require(value.get("apiVersion") in versions)
        p.fields(value, outgoing._RUNTIME_FIELDS[:-1] + versions[value["apiVersion"]])
        for name in versions[value["apiVersion"]]:
            p.require(type(value[name]) is dict)
        p.integer(value["startupTimeoutMillis"], maximum=30000)
        return value
    matches = [(role, name) for role in ROLES for name, (suffix, _) in COMPONENTS.items()
        if purpose == "native-" + role + "-" + suffix]
    p.require(len(matches) == 1)
    role, name = matches[0]
    if name == "trust":
        p.fields(value, ("apiVersion", "checkpoint", "assignmentKey", "timeKey", "roleKeys",
            "issuedAtUnixNanos", "expiresAtUnixNanos"))
        p.require(value["apiVersion"] == "serverware.nativeShadowGuestTrust/v1")
        p.fields(value["checkpoint"], ("checkpointId", "asOfUnixNanos", "revocationGeneration", "revocationRootSha256"))
        p.fields(value["assignmentKey"], _KEY); p.fields(value["timeKey"], _KEY)
        p.require(type(value["roleKeys"]) is list and 1 <= len(value["roleKeys"]) <= 128)
        for row in value["roleKeys"]:
            p.fields(row, ("role", "key")); p.fields(row["key"], _KEY)
    elif name == "timeBootstrap":
        p.fields(value, ("apiVersion", "guest", "signingKeyId", "parentPort", "maximumBracketNanos",
            "timestampErrorNanos", "maximumClockRateErrorPpm"))
        p.require(value["apiVersion"] == "serverware.nativeShadowGuestTimeBootstrap/v1")
        p.guest(value["guest"]); p.digest(value["signingKeyId"])
        p.integer(value["parentPort"], minimum=1024, maximum=(1 << 32) - 2)
        p.require(p.ns(value["maximumBracketNanos"]) <= 1_000_000_000)
        p.integer(value["timestampErrorNanos"], minimum=0, maximum=1_000_000_000)
        p.integer(value["maximumClockRateErrorPpm"], minimum=0, maximum=10000)
    elif name == "assignment":
        p.fields(value, _ENVELOPE); p.fields(value["payload"], _ASSIGNMENT)
        p.require(value["apiVersion"] == value["signatureDomain"] == "serverware.policyShadowAssignment/v1"
            and value["kind"] == "PolicyShadowAssignment" and value["signatureAlgorithm"] == "Ed25519"
            and value["canonicalProfile"] == "serverware.canonicalJson/ascii-integer-v1"
            and p.digest(value["payloadSha256"]) == p.sha(p.canonical(value["payload"])))
        p.decoded(value["signature"], size=64)
    elif name == "closure":
        p.fields(value, ("apiVersion", "manifest", "authorization"))
        manifest = p.fields(value["manifest"], _MANIFEST)
        version = "2" if role == "bridge" else "1"
        p.require(value["apiVersion"] == "serverware.nativeCustodyClosure/v" + version
            and manifest["apiVersion"] == "serverware.nativeCustodyExecutionClosure/v" + version
            and manifest["profile"] == ("measured-bootstrap-late-runtime-static-amd64-v1" if role == "bridge"
                else "sealed-memfd-squashfs-static-amd64-v1"))
        _signed(value["authorization"], _CLOSURE)
    elif name == "keys":
        p.fields(value, ("apiVersion", "authorization"))
        p.require(value["apiVersion"] == "serverware.nativeShadowRoleKeys/v2")
        auth = _signed(value["authorization"], p.AUTH_FIELDS)
        p.require(auth["apiVersion"] == "serverware.nativeShadowRoleKeyAssignment/v2"
            and auth["profile"] == "preassigned-encrypted-local-v1" and auth["purpose"] == "shadow-role-key-possession")
    elif name == "encryptedKeys":
        extended = role == "commitRequest"
        p.fields(value, ("apiVersion", "authorization", "requestCommitment") if extended else ("apiVersion", "authorization"))
        version = "2" if extended else "1"
        p.require(value["apiVersion"] == "serverware.nativeShadowEncryptedKeyDelivery/v" + version)
        auth = _signed(value["authorization"], _ENCRYPTED)
        p.require(auth["apiVersion"] == "serverware.nativeShadowEncryptedKeyDeliveryAssignment/v" + version
            and auth["purpose"] == ("kms-recipient-shadow-local-keys-and-request-commitment" if extended else "kms-recipient-shadow-local-keys"))
        encrypted.transport(auth["transport"])
        p.require(auth["transport"]["apiVersion"] == "serverware.nativeShadowKeyKmsTransport/v" + version)
        if extended:
            request = _signed(value["requestCommitment"], commitment.HMAC_FIELDS)
            p.require(request["apiVersion"] == "serverware.nativeShadowRequestCommitmentAssignment/v2"
                and request["purpose"] == "native-shadow-request-and-ingress-commitments")
            encrypted.commitment(request["requestCommitment"])
    elif name == "admission":
        profile = bridge_admission if role == "bridge" else admission
        auth = _signed(value, profile.ADMISSION_FIELDS)
        p.require(auth["apiVersion"] == ("serverware.nativeShadowBridgeAdmissionAssignment/v1" if role == "bridge"
            else "serverware.nativeShadowKeyAdmissionAssignment/v1")
            and auth["purpose"] == ("native-shadow-context-and-production-admission" if role == "bridge"
                else "native-shadow-key-admission"))
    else:
        p.require(name == "verifierTransport")
        p.fields(value, ("apiVersion", "authorization"))
        p.require(value["apiVersion"] == "serverware.nativeShadowVerifierTransport/v1")
        auth = _signed(value["authorization"], _VERIFIER)
        p.require(auth["apiVersion"] == "serverware.nativeShadowVerifierTransportAssignment/v1"
            and auth["purpose"] == "public-shadow-nitro-verification")
        p.integer(auth["parentPort"], minimum=1024, maximum=(1 << 32) - 2)
    return value


def _key(value, now):
    p.fields(value, _KEY)
    raw = p.decoded(value["publicKeyBase64url"], size=32)
    p.require(raw != bytes(32))
    key = Ed25519PublicKey.from_public_bytes(raw)
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    p.require(p.sha(spki) == p.digest(value["keyId"]) == p.digest(value["keySpkiSha256"])
        and p.integer(value["notBeforeUnixNanos"], minimum=0) <= now < p.integer(value["notAfterUnixNanos"]))
    return key


def _public_joins(role, documents, guest, runtime_raw, grant, observed, config, companion, now):
    """Check exact public byte associations; never substitute for native admission."""
    trust, assignment = documents["trust"], documents["assignment"]
    p.freshness(trust["issuedAtUnixNanos"], trust["expiresAtUnixNanos"], now)
    checkpoint = trust["checkpoint"]
    p.require(p.integer(checkpoint["asOfUnixNanos"]) <= now <= checkpoint["asOfUnixNanos"] + 300_000_000_000)
    p.digest(checkpoint["checkpointId"]); p.digest(checkpoint["revocationRootSha256"])
    p.integer(checkpoint["revocationGeneration"], minimum=0, maximum=p.MAX_U64)
    assignment_key = _key(trust["assignmentKey"], now)
    _key(trust["timeKey"], now)
    role_keys, material = {}, {trust["assignmentKey"]["publicKeyBase64url"], trust["timeKey"]["publicKeyBase64url"]}
    p.require(len(material) == 2)
    for row in trust["roleKeys"]:
        name, key = row["role"], row["key"]
        p.require(type(name) is str and name.isascii() and 1 <= len(name) <= 128 and name not in role_keys
            and key["publicKeyBase64url"] not in material)
        material.add(key["publicKeyBase64url"])
        role_keys[name] = (_key(key, now), key)
    p.require(set(p.ROLES).issubset(role_keys))
    a = assignment["payload"]
    p.require(assignment["signingKeyId"] == trust["assignmentKey"]["keyId"]
        and assignment["signingKeySpkiSha256"] == trust["assignmentKey"]["keySpkiSha256"])
    assignment_key.verify(p.decoded(assignment["signature"], size=64), p.preimage(assignment["signatureDomain"], a))
    p.freshness(a["issuedAtUnixNanos"], a["expiresAtUnixNanos"], now)
    independence = p.fields(a["authorityKeyIndependence"], ("bindings", "keyIdSetRootSha256", "spkiSetRootSha256",
        "keyMaterialSetRootSha256", "independenceRootSha256"))
    p.require(type(independence["bindings"]) is list and 1 <= len(independence["bindings"]) <= 128)
    public_keys = []
    for name in p.ROLES:
        matches = [row for row in independence["bindings"] if row.get("role") == name and row.get("scopeSha256") == a["assignmentId"]]
        p.require(len(matches) == 1)
        binding = p.fields(matches[0], ("role", "scopeSha256", "keyAlgorithm", "keyId", "keySpkiSha256", "keyMaterialSha256"))
        p.require(type(binding["keyAlgorithm"]) is str and binding["keyAlgorithm"].lower() == "ed25519")
        record = {field: binding[field] for field in ("role", "keyId", "keySpkiSha256", "keyMaterialSha256")}
        record["publicKeyBase64url"] = role_keys[name][1]["publicKeyBase64url"]
        p.public_key(record)
        p.require(record["keyId"] == role_keys[name][1]["keyId"] and record["keySpkiSha256"] == role_keys[name][1]["keySpkiSha256"])
        public_keys.append(record)
    supervisor, signer = public_keys[-1], role_keys[p.ROLES[-1]][0]
    key_auth = documents["keys"]["authorization"]
    k = key_auth["payload"]
    p.guest(guest)
    common = {"assignmentId": a["assignmentId"], "assignmentPayloadSha256": assignment["payloadSha256"],
        "assignmentRevision": a["assignmentRevision"], "guest": guest,
        "trustCheckpointId": checkpoint["checkpointId"], "revocationGeneration": checkpoint["revocationGeneration"],
        "revocationRootSha256": checkpoint["revocationRootSha256"], "signingKeyId": supervisor["keyId"],
        "signingKeySpkiSha256": supervisor["keySpkiSha256"]}

    def verify(envelope, domain, *, other_guest=False):
        payload = envelope["payload"]
        for name, expected in common.items():
            if name in payload and not (other_guest and name == "guest"):
                c9._same(payload[name], expected)
        p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], now)
        signer.verify(p.decoded(envelope["signature"], size=64), p.preimage(domain, payload))

    verify(key_auth, "serverware.nativeShadowRoleKeyAssignment.signature/v2")
    local = k["localRoles"]
    p.require(type(local) is list and 1 <= len(local) <= 16 and all(name in p.ROLES[:16] for name in local)
        and local == sorted(set(local), key=p.ROLES.index) and k["fullKeySetRootSha256"] == p.key_root(public_keys)
        and p.decoded(k["challengeBase64url"], size=32) != bytes(32))
    if role != "bridge":
        required_role = "custody-result-envelope" if role == "generationInstall" else services._LOCAL_ROLE[LAUNCHES[role][2]]
        p.require(required_role in local)
    common.update(keyAuthorizationSha256=p.sha(p.canonical(key_auth)), fullKeySetRootSha256=k["fullKeySetRootSha256"],
        localKeySetRootSha256=p.key_root([public_keys[p.ROLES.index(name)] for name in local]), challengeBase64url=k["challengeBase64url"])
    clock = documents["timeBootstrap"]
    c9._same(clock["guest"], guest)
    p.require(clock["signingKeyId"] == trust["timeKey"]["keyId"])
    closure, manifest = documents["closure"], documents["closure"]["manifest"]
    c = closure["authorization"]["payload"]
    version = "2" if role == "bridge" else "1"
    p.require(c["apiVersion"] == "serverware.nativeCustodyClosureAssignment/v" + version
        and c["purpose"] == ("shadow-custody-bootstrap-late-runtime" if role == "bridge" else "shadow-custody-execution-closure")
        and c["profile"] == manifest["profile"]
        and c["manifestSha256"] == manifest["manifestSha256"] == k["executionClosureManifestSha256"]
        == a["custodyAuthority"]["executionClosureManifestSha256"])
    p.require(manifest["manifestSha256"] == p.framed(("serverware.nativeCustodyExecutionClosure/v" + version).encode("ascii"),
        (p.canonical([manifest[name] for name in _MANIFEST[:-1]]),)))
    executable = observed["driver"]["driverExecutableSha256"] if role == "bridge" else observed[role]["executable"]["sha256"]
    p.require(manifest["workerExecutableSha256"] == executable)
    p.require(manifest["seccompPolicy"]["structurallyVerifiedPolicySha256"]
        == a["custodyAuthority"]["structurallyVerifiedSeccompPolicySha256"])
    if role == "bridge":
        image = config["image"]
        p.require(manifest["imageSha256"] == image["imageSha256"]
            and manifest["runtimeConfigurationSha256"] == image["bootstrapRuntimeSha256"])
        c9._same(manifest["seccompPolicy"], image["seccompPolicy"])
        for target, source in (("dependencyLockSha256", "dependencyLockSha256"),
                ("buildRecipeSha256", "buildRecipeSha256"), ("provenanceStatementSha256", "provenanceSha256")):
            p.require(manifest["buildProvenance"][target] == image[source])
        c9._same(documents["encryptedKeys"]["authorization"]["payload"]["transport"], config["continuation"]["keyTransport"])
    else:
        p.require(manifest["runtimeConfigurationSha256"] == guest["runtimeConfigurationSha256"] == p.sha(runtime_raw))
    verify(closure["authorization"], "serverware.nativeCustodyClosureAssignment.signature/v" + version)
    common["executionClosureManifestSha256"] = manifest["manifestSha256"]
    profile = bridge_admission if role == "bridge" else admission
    verify(documents["admission"], profile.ADMISSION_DOMAIN)
    encrypted_value = documents["encryptedKeys"]
    verify(encrypted_value["authorization"], "serverware.nativeShadowEncryptedKeyDelivery.signature/v" + ("2" if role == "commitRequest" else "1"))
    if role == "commitRequest":
        request = encrypted_value["requestCommitment"]
        verify(request, "serverware.nativeShadowRequestCommitmentAssignment.signature/v2")
        descriptor = request["payload"]["requestCommitment"]
        p.require(descriptor["keyId"] == a["observationWindow"]["requestCommitmentKeyId"]
            and descriptor["keyEpoch"] == a["observationWindow"]["requestCommitmentKeyEpoch"]
            and descriptor["keyId"] not in {key["keyId"] for key in public_keys})
        p.require(companion is not None)
        verify(companion, services.PROFILES["commitRequest"][2])
        c9._same(companion["payload"]["expectedPeer"], grant["payload"]["expectedPeer"])
    verifier = documents["verifierTransport"]["authorization"]
    verify(verifier, "serverware.nativeShadowVerifierTransport.signature/v1")
    for field in ("keyId", "keySpkiSha256", "keyMaterialSha256"):
        p.require(verifier["payload"]["verifier" + field[0].upper() + field[1:]] == public_keys[-2][field])
    operation = LAUNCHES[role][2]
    domain = generation.DOMAIN if operation is None else services.PROFILES[operation][2]
    # Bridge consumes the endpoint's trusted-time grant, not a bridge-guest grant.
    if role == "bridge":
        retained = common.pop("keyAuthorizationSha256")
        verify(grant, domain, other_guest=True)
        common["keyAuthorizationSha256"] = retained
        peer = grant["payload"]["expectedPeer"]
        p.require((peer["uid"], peer["gid"], peer["pid"], peer["startTimeTicks"])
            == (guest["uid"], guest["gid"], observed["processId"], observed["driver"]["processStartTimeTicks"]))
        runtime = p.document(runtime_raw, 65536)
        endpoints = [entry for entry in runtime["proofEndpoints"] if entry["endpointKind"] == "trusted-time"]
        p.require(len(endpoints) == 1)
        endpoint = endpoints[0]
        p.require((endpoint["expectedPeer"]["uid"], endpoint["expectedPeer"]["gid"])
            == (grant["payload"]["guest"]["uid"], grant["payload"]["guest"]["gid"])
            and endpoint["authorityKeyId"] == public_keys[p.ROLES.index("custody-trusted-time-response")]["keyId"]
            and endpoint["authorityKeySpkiSha256"] == public_keys[p.ROLES.index("custody-trusted-time-response")]["keySpkiSha256"])
    else:
        verify(grant, domain)
        if role == "trustedTime":
            p.require(grant["payload"]["clockBootstrapSha256"] == p.sha(p.canonical(clock)))
    deadlines = [trust["expiresAtUnixNanos"], a["expiresAtUnixNanos"], checkpoint["asOfUnixNanos"] + 300_000_000_000,
        *(documents[name]["authorization"]["payload"]["expiresAtUnixNanos"] for name in ("closure", "keys", "encryptedKeys", "verifierTransport")),
        documents["admission"]["payload"]["expiresAtUnixNanos"], grant["payload"]["expiresAtUnixNanos"],
        trust["assignmentKey"]["notAfterUnixNanos"], trust["timeKey"]["notAfterUnixNanos"],
        *(row["key"]["notAfterUnixNanos"] for row in trust["roleKeys"])]
    if role == "commitRequest":
        deadlines.append(encrypted_value["requestCommitment"]["payload"]["expiresAtUnixNanos"])
    return min(deadlines)


def install(bundle_original: bytes, *, expected_sha256: str) -> dict:
    """Install one fixed role; return exact pins only, never launch/readiness."""
    global _FAILED, _COUNT, _BYTES
    p.require(not _FAILED)
    held, publisher = [], None

    def retain(pin, maximum):
        delivery._pin(pin)
        original = control._Original(pin["path"], maximum, pin["sha256"])
        held.append(original)
        return original.raw

    try:
        p.require(threading.current_thread() is threading.main_thread()
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
        p.require(type(bundle_original) is bytes and 0 < len(bundle_original) <= MAX_INPUT
            and p.sha(bundle_original) == p.digest(expected_sha256))
        value = p.fields(p.document(bundle_original, MAX_INPUT), FIELDS)
        role = value["role"]
        p.require(value["apiVersion"] == "serverware.nativePilotLaunchBundle/v1"
            and type(role) is str and role in ROLES and role not in _ATTEMPTED)
        _ATTEMPTED.add(role)  # Before opening originals or creating any path.
        inner = value["keyAdmission"]
        _inner(inner, role)
        config_path, window_path = ((driver.CONFIGURATION, driver.WINDOW) if role == "bridge"
            else (control.CONFIGURATION, control.PRECREATION))
        config_raw = retain({"path": config_path, "sha256": value["ownerConfigurationSha256"]}, 65536 if role == "bridge" else 32768)
        window_raw = retain({"path": window_path, "sha256": value["windowSha256"]}, 32768)
        _, observed = c9._original(value["observationOriginal"], 65536 if role == "bridge" else 32768)
        config = p.document(config_raw, 65536)
        c9._same(inner["deliveryConfiguration"], config["deliveryConfiguration"] if role == "bridge" else config[role + "Configuration"])
        cold_raw = retain(inner["deliveryConfiguration"], 65536)
        cold = delivery.configuration(cold_raw, inner["deliveryConfiguration"]["sha256"])
        owner = c9._bridge_owner if role == "bridge" else lambda *args: c9._endpoint_owner(role, *args)
        window = owner(cold, cold_raw, config_raw, window_raw, p.document(window_raw, 32768), observed)
        delivery_raw = retain(inner["delivery"], 65536)
        signed = p.fields(p.document(delivery_raw, 65536), ("apiVersion", "payload", "signatureBase64url"))
        payload = p.fields(signed["payload"], delivery.FIELDS)
        p.require(signed["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1"
            and payload["configurationSha256"] == p.sha(cold_raw) and payload["authorityKeyId"] == cold["authority"]["keyId"])
        for name in ("serviceRole", "uid", "gid"):
            c9._same(payload[name], cold[name])
        for name in c9.WINDOW_FIELDS:
            c9._same(payload[name], window[name])
        driver._key(cold["authority"]).verify(p.decoded(signed["signatureBase64url"], size=64), delivery.DOMAIN + p.canonical(payload))
        runtime_raw, _ = c9._original(value["runtimeOriginal"], 65536)
        runtime_purpose = "bridge-runtime" if role == "bridge" else "native-runtime-" + role
        c9._same(payload["runtimeConfig"], {"path": publication.DESTINATIONS[runtime_purpose], "sha256": p.sha(runtime_raw)})
        if role == "bridge":
            p.require(retain(payload["runtimeConfig"], 65536) == runtime_raw)
            expected, _ = c9._bridge_inventory(runtime_raw, cold)
        else:
            shape(runtime_purpose, runtime_raw)
            expected = c9.ENDPOINTS[role]
        c9._activation(payload["activation"], expected)
        c9._credentials(payload["credentials"], cold["authority"])
        guest = delivery._delivery_guest(payload, delivery_raw)
        p.fields(value["originals"], COMPONENTS)
        prepared, documents = {}, {}
        if role != "bridge":
            prepared[runtime_purpose] = runtime_raw
        for name, (suffix, maximum) in COMPONENTS.items():
            raw, _ = c9._original(value["originals"][name], maximum)
            purpose = "native-" + role + "-" + suffix
            c9._same(inner[name], {"path": DESTINATIONS[purpose], "sha256": p.sha(raw)})
            documents[name] = shape(purpose, raw)
            prepared[purpose] = raw
        grant_pin = value["serviceGrant"]
        delivery._pin(grant_pin)
        grant_purpose = _grant_purpose(role)
        p.require(grant_pin["path"] == publication.DESTINATIONS[grant_purpose])
        grant_raw = retain(grant_pin, 65536)
        publication._shape(grant_purpose, grant_raw)
        grant = p.document(grant_raw, 65536)
        operation = LAUNCHES[role][2]
        _signed(grant, generation.PAYLOAD_FIELDS if operation is None else services.PAYLOAD_FIELDS[operation])
        companion = None
        if role == "commitRequest":
            pin = grant["payload"]["commitRequest"]
            delivery._pin(pin)
            p.require(pin["path"] == publication.DESTINATIONS["native-service-commitRequest"])
            raw = retain(pin, 65536)
            publication._shape("native-service-commitRequest", raw)
            companion = p.document(raw, 65536)
            _signed(companion, services.PAYLOAD_FIELDS["commitRequest"])
        now = time.time_ns()
        expiry = _public_joins(role, documents, guest, runtime_raw, grant, observed, config, companion, now)
        if companion is not None:
            expiry = min(expiry, companion["payload"]["expiresAtUnixNanos"])
        # Never read the ciphertext credential (or any credential). Bind only
        # its already independently approved public pin to encrypted metadata.
        transport = documents["encryptedKeys"]["authorization"]["payload"]["transport"]
        ciphertext = [entry for entry in payload["credentials"] if entry["name"] == "shadow-encrypted-role-inventory"]
        p.require(len(ciphertext) == 1 and ciphertext[0]["signing"] is None and 0 < ciphertext[0]["length"] <= 32768
            and ciphertext[0]["original"]["sha256"] == transport["encryptedInventorySha256"]
            and all(not entry["name"].startswith("shadow-key-custody-") for entry in payload["credentials"]))
        api, field, _ = LAUNCHES[role]
        launch_raw = p.canonical({"apiVersion": "serverware." + api, "keyAdmission": inner, field: grant_pin})
        launch_purpose = "native-launch-" + role
        shape(launch_purpose, launch_raw)
        prepared[launch_purpose] = launch_raw  # Fixed final publication point.
        count, total = len(prepared), sum(len(raw) for raw in prepared.values())
        p.require(_COUNT + count <= 128 and _BYTES + total <= 32 * 1024 * 1024)
        _COUNT += count; _BYTES += total  # Failure cannot restore the budget.
        for purpose in prepared:
            p.require(publication.DESTINATIONS[purpose] == DESTINATIONS[purpose]
                and publication.LIMITS[purpose] == PURPOSES[purpose])

        def check(previous=0, previous_wall=now):
            for original in held:
                original.check()
            current = time.time_ns()
            p.require(previous_wall <= current < expiry)
            return c9._live(window, previous), current

        previous, wall = check()
        publisher = publication.PublicPublisher.open()
        publisher.require_absent(tuple(prepared))
        pins = {}
        for purpose, raw in prepared.items():
            previous, wall = check(previous, wall)
            pins[purpose] = publisher.publish(purpose=purpose, raw=raw, expected_sha256=p.sha(raw))
            previous, wall = check(previous, wall)
        publisher.check(); check(previous, wall)
        return {"apiVersion": "serverware.nativePilotLaunchInstallation/v1", "role": role,
            "bundleSha256": expected_sha256, "startupDeadlineBoottimeNs": window["startupDeadlineBoottimeNs"],
            "lifetimeDeadlineBoottimeNs": window["lifetimeDeadlineBoottimeNs"], "launch": pins[launch_purpose], "pins": pins}
    except BaseException:
        _FAILED = True
        raise
    finally:
        if publisher is not None:
            publisher.close()  # Only FDs. Complete/partial installed paths remain.
        for original in reversed(held):
            original.close()
