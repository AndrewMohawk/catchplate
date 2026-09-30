"""Purpose-fixed offline input authoring, not launch/readiness evidence.

All keys are independently provisioned opaque objects. No secret key is
generated, read from a path, derived from a signing seed, or returned here.
Native admission and both services still verify their actual retained owners.
"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import native_shadow_key_admission_profile as admission
from serverware import native_shadow_key_contract as delivery
from serverware import native_shadow_nitro_profile as p
from serverware import native_shadow_retrieval_artifacts as retrieval
from serverware import custody_generation_grants as g

HMAC_DOMAIN = "serverware.nativeShadowRequestCommitmentAssignment.signature/v1"
KEY_DOMAIN = "serverware.nativeShadowEncryptedKeyDelivery.signature/v2"
NATIVE_DOMAIN = "serverware.nativeShadowCommitRequestServiceAssignment.signature/v1"
SERVICE_DOMAIN = b"serverware.custodyCommitRequestServiceGrant.signature/v1"
ROLES = ("durable-recovery-store", "current-signature-authority")
SCOPE = ("productionConfigurationBindingSha256", "kernelDriverIdentitySha256", "retainedDescriptorSetSha256",
    "driverGenerationReceiptSha256", "assignmentPayloadSha256", "assignmentRevision", "runtime",
    "requestCommitmentKeyId", "requestCommitmentKeyEpoch", "issuedAtBoottimeNanos", "expiresAtBoottimeNanos")
RUNTIME = ("instanceId", "spiffeId", "bootIdSha256", "teePlatform", "teeEvidenceSha256", "teeMeasurementSha256",
    "teeAttestationKeyId", "teeAttestationKeySpkiSha256", "ingressSigningKeyId", "ingressSigningKeySpkiSha256",
    "activeDecisionSigningKeyId", "activeDecisionSigningKeySpkiSha256", "shadowSigningKeyId", "shadowSigningKeySpkiSha256")
SERVICE_FIELDS = ("apiVersion", "purpose", "serviceRole", "guest", "runtimeConfigurationSha256",
    "authorityHistoryManifestSha256", "scope", "nativeGrantSha256", "nativeLedgerKeyId",
    "nativeLedgerKeySpkiSha256", "nativeLedgerPublicKeyBase64url", "initialHeadSha256")
HMAC_FIELDS = ("apiVersion", "purpose", "guest", "assignmentPayloadSha256", "keyAuthorizationSha256",
    "requestCommitment", "trustCheckpointId", "revocationGeneration", "revocationRootSha256",
    "issuedAtUnixNanos", "expiresAtUnixNanos", "signingKeyId", "signingKeySpkiSha256")
NATIVE_FIELDS = tuple(field for field in HMAC_FIELDS if field != "requestCommitment") + ("scope", "expectedPeer")


def _inputs(raw, pin, assignment_raw, now, signing_key):
    p.require(p.sha(raw) == p.digest(pin))
    config = p.document(raw, p.MAX_CONFIG)
    admitted, keys = admission.authorization(config, now)
    p.require(config["authorization"]["payload"]["localRoles"] == ["custody-ledger-append"])
    assignment = p.document(assignment_raw, p.MAX_CONFIG)
    p.require(p.sha(assignment_raw) == admitted["assignmentPayloadSha256"]
        and assignment["assignmentRevision"] == admitted["assignmentRevision"])
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == keys[-1]["publicKeyBase64url"])
    return config, admitted, keys, assignment


def _common(config, admitted, keys, issued, expires, now):
    p.freshness(issued, expires, now)
    p.require(issued >= config["authorization"]["payload"]["issuedAtUnixNanos"]
        and expires <= min(config[name]["payload"]["expiresAtUnixNanos"] for name in ("authorization", "admissionAuthorization")))
    checkpoint = config["trustCheckpoint"]
    return {"guest": admitted["guest"], "assignmentPayloadSha256": admitted["assignmentPayloadSha256"],
        "keyAuthorizationSha256": admitted["keyAuthorizationSha256"], "trustCheckpointId": checkpoint["checkpointId"],
        "revocationGeneration": checkpoint["revocationGeneration"], "revocationRootSha256": checkpoint["revocationRootSha256"],
        "issuedAtUnixNanos": issued, "expiresAtUnixNanos": expires,
        "signingKeyId": keys[-1]["keyId"], "signingKeySpkiSha256": keys[-1]["keySpkiSha256"]}


def _signed(payload, domain, signing_key):
    signature = signing_key.sign(p.preimage(domain, payload))
    signing_key.public_key().verify(signature, p.preimage(domain, payload))
    original = p.canonical({"payload": payload, "signature": p.encoded(signature)})
    p.require(len(original) <= 65536)
    return original


def sign_hmac_assignment(*, configuration_original, configuration_sha256, assignment_payload_original,
                         secret_sha256, issued_at, expires_at, now, signing_key):
    config, admitted, keys, assignment = _inputs(configuration_original, configuration_sha256,
        assignment_payload_original, now, signing_key)
    window = assignment["observationWindow"]
    descriptor = delivery.commitment({"keyId": window["requestCommitmentKeyId"],
        "keyEpoch": window["requestCommitmentKeyEpoch"], "secretSha256": p.digest(secret_sha256)})
    p.require(descriptor["keyId"] not in {key["keyId"] for key in keys})
    payload = _common(config, admitted, keys, issued_at, expires_at, now)
    payload.update(apiVersion="serverware.nativeShadowRequestCommitmentAssignment/v1",
        purpose="native-shadow-request-commitment-hmac", requestCommitment=descriptor)
    return _signed(payload, HMAC_DOMAIN, signing_key)


def sign_encrypted_delivery(*, configuration_original, configuration_sha256, assignment_payload_original,
                            hmac_authorization_original, transport_original, issued_at, expires_at, now, signing_key):
    config, admitted, keys, assignment = _inputs(configuration_original, configuration_sha256,
        assignment_payload_original, now, signing_key)
    hmac = p.fields(p.document(hmac_authorization_original, 65536), ("payload", "signature"))
    hp = p.fields(hmac["payload"], HMAC_FIELDS)
    expected = _common(config, admitted, keys, hp["issuedAtUnixNanos"], hp["expiresAtUnixNanos"], now)
    descriptor = delivery.commitment(hp["requestCommitment"])
    p.require(descriptor["keyId"] == assignment["observationWindow"]["requestCommitmentKeyId"]
        and descriptor["keyEpoch"] == assignment["observationWindow"]["requestCommitmentKeyEpoch"]
        and descriptor["keyId"] not in {key["keyId"] for key in keys})
    expected.update(apiVersion="serverware.nativeShadowRequestCommitmentAssignment/v1",
        purpose="native-shadow-request-commitment-hmac", requestCommitment=descriptor)
    p.require(hp == expected)
    p.public_key(keys[-1]).verify(p.decoded(hmac["signature"], size=64), p.preimage(HMAC_DOMAIN, hp))
    transport = delivery.transport(p.document(transport_original, 16384))
    p.require(transport["apiVersion"] == "serverware.nativeShadowKeyKmsTransport/v2")
    payload = _common(config, admitted, keys, issued_at, expires_at, now)
    payload.update(apiVersion="serverware.nativeShadowEncryptedKeyDeliveryAssignment/v2",
        purpose="kms-recipient-shadow-local-keys-and-request-commitment", assignmentId=admitted["assignmentId"],
        assignmentRevision=admitted["assignmentRevision"], fullKeySetRootSha256=admitted["fullKeySetRootSha256"],
        localKeySetRootSha256=admitted["localKeySetRootSha256"], challengeBase64url=admitted["challengeBase64url"], transport=transport)
    signed = p.document(_signed(payload, KEY_DOMAIN, signing_key), 65536)
    return p.canonical({"apiVersion": "serverware.nativeShadowEncryptedKeyDelivery/v2",
        "authorization": signed, "requestCommitment": hmac})


def scope_original(raw):
    value = p.fields(g.document(raw, 32768), SCOPE)
    for name in SCOPE:
        if name == "runtime":
            continue
        if name in ("assignmentRevision", "requestCommitmentKeyEpoch", "issuedAtBoottimeNanos", "expiresAtBoottimeNanos"):
            p.integer(value[name], maximum=(1 << 63)-1 if name == "requestCommitmentKeyEpoch" else (1 << 64)-1)
        else:
            p.require(p.digest(value[name]) != p.sha(b""))
    runtime = p.fields(value["runtime"], RUNTIME)
    for name in RUNTIME:
        if name.endswith(("Sha256", "KeyId")):
            p.digest(runtime[name])
    p.require(type(runtime["instanceId"]) is str and 1 <= len(runtime["instanceId"]) <= 128
        and type(runtime["spiffeId"]) is str and runtime["spiffeId"].startswith("spiffe://")
        and runtime["teePlatform"] in ("aws-nitro-enclave", "amd-sev-snp", "intel-tdx")
        and value["issuedAtBoottimeNanos"] < value["expiresAtBoottimeNanos"])
    return value


def sign_native_service(*, configuration_original, configuration_sha256, assignment_payload_original,
                        scope_original_bytes, scope_sha256, peer_original, peer_sha256,
                        issued_at, expires_at, now, signing_key):
    config, admitted, keys, assignment = _inputs(configuration_original, configuration_sha256,
        assignment_payload_original, now, signing_key)
    p.require(p.sha(scope_original_bytes) == p.digest(scope_sha256) and p.sha(peer_original) == p.digest(peer_sha256))
    scope, peer = scope_original(scope_original_bytes), retrieval._peer(peer_original)
    p.require(scope["assignmentPayloadSha256"] == admitted["assignmentPayloadSha256"]
        and scope["assignmentRevision"] == admitted["assignmentRevision"]
        and scope["requestCommitmentKeyId"] == assignment["observationWindow"]["requestCommitmentKeyId"]
        and scope["requestCommitmentKeyEpoch"] == assignment["observationWindow"]["requestCommitmentKeyEpoch"]
        and p.ns(admitted["guest"]["issuedAtBoottimeNs"]) <= scope["issuedAtBoottimeNanos"]
        and scope["expiresAtBoottimeNanos"] <= p.ns(admitted["guest"]["lifetimeDeadlineBoottimeNs"])
        and peer["uid"] != admitted["guest"]["uid"])
    payload = _common(config, admitted, keys, issued_at, expires_at, now)
    payload.update(apiVersion="serverware.nativeShadowCommitRequestServiceAssignment/v1",
        purpose="native-shadow-ledger-commit-request", scope=scope, expectedPeer=peer)
    return _signed(payload, NATIVE_DOMAIN, signing_key)


def sign_service_transition_grant(*, payload_original, native_grant_original, runtime_original,
                                  history_original, delivery_original, signing_key, now,
                                  native_configuration_original, native_configuration_sha256, native_now):
    """Independent history-root signature; never the LedgerAppend/HMAC key."""
    payload = p.fields(g.document(payload_original, 65536), SERVICE_FIELDS)
    guest = p.guest(payload["guest"])
    # p.guest validates in place and intentionally returns no authority owner.
    guest = payload["guest"]
    role = guest["serviceRole"]
    p.require(role in ROLES and payload["serviceRole"] == role
        and payload["apiVersion"] == "serverware.custodyCommitRequestServiceGrant/v1"
        and payload["purpose"] == "commit-request-service-transition")
    runtime = g.document(runtime_original, g.MAX_BYTES)["runtime"]
    history = p.fields(g.document(history_original, g.MAX_BYTES), g.HISTORY)
    c9 = g.document(delivery_original, 65536)["payload"]
    scope = scope_original(g.canonical(payload["scope"]))
    native = p.fields(p.document(native_grant_original, 65536), ("payload", "signature"))
    p.require(p.sha(native_configuration_original) == p.digest(native_configuration_sha256))
    native_configuration = p.document(native_configuration_original, p.MAX_CONFIG)
    admitted, keys = admission.authorization(native_configuration, native_now)
    np = p.fields(native["payload"], NATIVE_FIELDS)
    expected = _common(native_configuration, admitted, keys, np["issuedAtUnixNanos"], np["expiresAtUnixNanos"], native_now)
    expected.update(apiVersion="serverware.nativeShadowCommitRequestServiceAssignment/v1",
        purpose="native-shadow-ledger-commit-request", scope=scope, expectedPeer=retrieval._peer(p.canonical(np["expectedPeer"])))
    p.require(np == expected and native_configuration["authorization"]["payload"]["localRoles"] == ["custody-ledger-append"])
    p.public_key(keys[-1]).verify(p.decoded(native["signature"], size=64), p.preimage(NATIVE_DOMAIN, np))
    ledger = keys[p.ROLES.index("custody-ledger-append")]
    p.require(payload["nativeLedgerKeyId"] == ledger["keyId"]
        and payload["nativeLedgerKeySpkiSha256"] == ledger["keySpkiSha256"]
        and payload["nativeLedgerPublicKeyBase64url"] == ledger["publicKeyBase64url"])
    p.require(runtime["apiVersion"] == "serverware.policyCustodyServiceRuntimeConfig/v6"
        and runtime["generationAdmission"] == {"grantFdName": "generation-grant"}
        and runtime["dispatchAdmission"] == {"grantFdName": "dispatch-grant"}
        and payload["nativeGrantSha256"] == p.sha(native_grant_original) and native["payload"]["scope"] == scope
        and p.sha(delivery_original) == guest["deliverySha256"]
        and p.sha(runtime_original) == guest["runtimeConfigurationSha256"] == payload["runtimeConfigurationSha256"])
    for name in p.GUEST_FIELDS:
        if name not in ("runtimeConfigurationSha256", "deliverySha256"):
            p.require(guest[name] == c9[name])
    p.require(history["authorityRole"] == {"authorityKind": "isolated-service", "role": role})
    semantic = p.framed(b"serverware.policyCustodyAuthorityHistoryManifest/v3",
        (g.canonical([history[field] for field in g.HISTORY[:-1]]),))
    p.require(history["manifestSha256"] == semantic == runtime["authorityHistoryManifestSha256"]
        == payload["authorityHistoryManifestSha256"])
    retained = [item for item in c9["credentials"] if item["name"] == runtime["authorityHistoryManifestCredential"]]
    p.require(len(retained) == 1 and retained[0]["original"]["sha256"] == p.sha(history_original)
        and retained[0]["length"] == len(history_original) and retained[0]["signing"] is None)
    root = p.fields(history["rootAuthority"], ("keyId", "keySpkiSha256", "publicKeySpkiBase64"))
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    spki = signing_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    p.require(p.encoded(spki) == root["publicKeySpkiBase64"] and p.sha(spki) == root["keySpkiSha256"]
        == runtime["authorityHistoryRootKeySpkiSha256"] and root["keyId"] == runtime["authorityHistoryRootKeyId"])
    public = p.decoded(payload["nativeLedgerPublicKeyBase64url"], size=32)
    native_spki = bytes.fromhex("302a300506032b6570032100")+public
    p.require(payload["nativeLedgerKeySpkiSha256"] == p.sha(native_spki)
        and public != signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        and p.digest(payload["initialHeadSha256"]) != p.sha(b"")
        and p.ns(guest["issuedAtBoottimeNs"]) <= scope["issuedAtBoottimeNanos"] <= now
        < scope["expiresAtBoottimeNanos"] <= p.ns(guest["lifetimeDeadlineBoottimeNs"]))
    message = b"serverware-signature-v1\0"+len(SERVICE_DOMAIN).to_bytes(8,"big")+SERVICE_DOMAIN+len(payload_original).to_bytes(8,"big")+payload_original
    signature = signing_key.sign(message)
    signing_key.public_key().verify(signature, message)
    result = g.canonical({"payload":payload,"signatureBase64url":p.encoded(signature)})
    p.require(len(result) <= 65536)
    return result


def sign_service_delivery(*, cold_raw, cold_sha, role, payload_raw, activation, boot, startup, lifetime, now, signing_key):
    """Explicit two-role successor, never a widened generation-only call."""
    p.require(role in ROLES)
    return g._sign_delivery(cold_raw=cold_raw,cold_sha=cold_sha,role=role,payload_raw=payload_raw,
        activation=activation,boot=boot,startup=startup,lifetime=lifetime,now=now,signing_key=signing_key,commitment=True)


def sign_service_generation_grant(*, payload_raw, guest, runtime_raw, history_raw, delivery_raw, signing_key, now):
    p.require(guest["serviceRole"] in ROLES)
    return g._sign_grant(payload_raw=payload_raw,guest=guest,runtime_raw=runtime_raw,history_raw=history_raw,
        delivery_raw=delivery_raw,signing_key=signing_key,now=now,commitment=True)
