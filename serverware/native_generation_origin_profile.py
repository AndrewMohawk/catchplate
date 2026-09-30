"""Fixed native generation provenance issuer grammar, not spool permission."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import native_shadow_nitro_profile as p
from serverware.native_shadow_time_profile import key_live
from serverware.native_shadow_nitro_verifier import _nitro_policy, _revocation
from scripts import verify_nitro_tee as nitro

MAX_FRAME = 2 * 1024 * 1024
MAX_EVIDENCE = 1024 * 1024
CONFIG_NAME = "native-generation-origin-issuer.json"
CHALLENGE_TAG, EVIDENCE_TAG, ANCHOR_TAG = b"SWNGOC1\0", b"SWNGOE1\0", b"SWNGOR1\0"
AUTH_DOMAIN = "serverware.nativeGenerationOriginIssuerAuthorization.signature/v1"
CHALLENGE_DOMAIN = "serverware.nativeGenerationOriginChallenge.signature/v1"
ORIGIN_DOMAIN = "serverware.nativeGenerationOrigin.signature/v1"
STATEMENT = "serverware.nativeGenerationOriginStatement/v1"
QUOTE_DOMAIN = b"serverware/native-generation-origin-attestation/v1\0"
CONFIG_FIELDS = ("apiVersion", "uid", "gid", "operation", "issuerAuthorityKey", "originKey", "target",
    "nitro", "collateralRevocation", "transport", "authorization")
SCOPE_DIGESTS = ("releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256",
    "caPublicKeySpkiSha256", "expectedBinaryDigest")
HOLDER_FIELDS = ("bootId", "keyId", "controlPlaneResponseSigningKeyId", *SCOPE_DIGESTS)
TARGET_FIELDS = ("holder", "assignmentPayloadSha256", "generationId", "productionConfigurationBindingSha256",
    "policyOriginalSha256", "initializationScopeSha256")
REQUEST_FIELDS = ("apiVersion", "challenge", "contextSha256", "policyHash", "assignmentPayloadSha256", "generationId",
    "issuedAtEpochNs", "expiresAtEpochNs")
STATEMENT_FIELDS = ("apiVersion", "request", "originals", "policyOriginalSha256", "bootId", "keyId",
    "controlPlaneResponseSigningKeyId", "dataPlaneBinarySha256", "observedAtEpochNs")
ORIGINAL_FIELDS = ("apiVersion", "installRequestSha256", "generation", "assignment", "loadReceipt", "runtimeAttestation",
    "runtimeAttestationVerification", "runtimeIdentity", "publication", "productionConfigurationBindingSha256", "trustCheckpoint", "ledgerBaseline")
ORIGIN_FIELDS = ("apiVersion", "purpose", "request", "evidenceOriginal", "issuedAtUnixNanos", "expiresAtUnixNanos",
    "signingKeyId", "signingKeySpkiSha256")


def authorization(config, now):
    p.fields(config, CONFIG_FIELDS)
    p.require(config["apiVersion"] == "serverware.nativeGenerationOriginIssuerConfiguration/v1")
    authority = key_live(config["issuerAuthorityKey"], now)
    key_live(config["originKey"], now)
    target = p.fields(config["target"], TARGET_FIELDS)
    holder = p.fields(target["holder"], HOLDER_FIELDS)
    p.decoded(holder["bootId"], size=32)
    for name in HOLDER_FIELDS[1:]:
        p.digest(holder[name])
    for name in TARGET_FIELDS[1:]:
        p.digest(target[name])
    keys = {config["issuerAuthorityKey"]["keyId"], config["originKey"]["keyId"], target["holder"]["keyId"],
        target["holder"]["controlPlaneResponseSigningKeyId"]}
    p.require(len(keys) == 4)
    _nitro_policy(config["nitro"])
    _revocation(config["collateralRevocation"], now)
    envelope = p.fields(config["authorization"], ("payload", "signature"))
    payload = p.fields(envelope["payload"], ("apiVersion", "purpose", "configurationSha256",
        "issuedAtUnixNanos", "expiresAtUnixNanos", "signingKeyId"))
    p.require(payload["apiVersion"] == "serverware.nativeGenerationOriginIssuerAuthorization/v1"
        and payload["purpose"] == "native-generation-origin-verification"
        and payload["signingKeyId"] == config["issuerAuthorityKey"]["keyId"]
        and payload["configurationSha256"] == p.sha(p.canonical({k: v for k, v in config.items() if k != "authorization"})))
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], now, 300_000_000_000)
    p.require(payload["expiresAtUnixNanos"] - payload["issuedAtUnixNanos"] <= 300_000_000_000)
    authority.verify(p.decoded(envelope["signature"], size=64), p.preimage(AUTH_DOMAIN, payload))
    return payload


def verify_evidence(config, request, raw, now):
    import hashlib
    authorization(config, now)
    p.fields(request, REQUEST_FIELDS)
    p.require(request["issuedAtEpochNs"] <= now < request["expiresAtEpochNs"])
    envelope = p.fields(p.document(raw, MAX_EVIDENCE), ("statement", "signature", "nativeKeyEvidence"))
    statement = p.fields(envelope["statement"], STATEMENT_FIELDS)
    expected = config["target"]["holder"]
    p.require(statement["apiVersion"] == STATEMENT and p.canonical(statement["request"]) == p.canonical(request)
        and statement["policyOriginalSha256"] == config["target"]["policyOriginalSha256"]
        and p.integer(statement["observedAtEpochNs"]) >= request["issuedAtEpochNs"]
        and statement["observedAtEpochNs"] <= now)
    for name in ("bootId", "keyId", "controlPlaneResponseSigningKeyId"):
        p.require(statement[name] == expected[name])
    p.require(statement["dataPlaneBinarySha256"] == expected["expectedBinaryDigest"]
        and type(statement["originals"]) is str and statement["originals"].isascii())
    originals = p.fields(p.document(statement["originals"].encode("ascii"), 768 * 1024), ORIGINAL_FIELDS)
    p.require(originals["apiVersion"] == "serverware.nativeInstalledGenerationOriginals/v1"
        and originals["generation"]["generationId"] == request["generationId"]
        and originals["generation"]["assignmentPayloadSha256"] == request["assignmentPayloadSha256"]
        and originals["productionConfigurationBindingSha256"] == config["target"]["productionConfigurationBindingSha256"])
    p.digest(originals["installRequestSha256"])
    baseline = p.fields(originals["ledgerBaseline"], ("eventOrdinal", "headSha256", "originalCount", "lastIngress", "observedAtUnixNanos"))
    generation = originals["generation"]
    p.require(p.integer(baseline["eventOrdinal"], minimum=0, maximum=p.MAX_I64) == generation["authoritativeLedgerEventOrdinal"]
        and baseline["headSha256"] == generation["authoritativeLedgerHeadSha256"]
        and baseline["originalCount"] == 0 and baseline["lastIngress"] is None
        and request["issuedAtEpochNs"] <= p.integer(baseline["observedAtUnixNanos"]) <= now)
    evidence = p.fields(envelope["nativeKeyEvidence"], ("apiVersion", "attestationDocumentB64", "responseProofPublicKey"))
    p.require(evidence["apiVersion"] == "serverware.nativeResponseProofKeyEvidence/v1")
    public = p.decoded(evidence["responseProofPublicKey"], size=32)
    key = Ed25519PublicKey.from_public_bytes(public)
    p.require(p.sha(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)) == expected["keyId"])
    p.require(type(envelope["signature"]) is str and envelope["signature"].startswith("ed25519:"))
    signature = p.decoded(envelope["signature"][8:], size=64)
    original = p.canonical(statement)
    key.verify(signature, STATEMENT.encode("ascii") + b"\0" + original)
    challenge = hashlib.sha256(QUOTE_DOMAIN + p.decoded(request["challenge"], size=32) + hashlib.sha256(original).digest() + signature).digest()
    boot = hashlib.sha256(b"serverware/native-proof-custody-boot/v1\0" + p.decoded(expected["bootId"], size=32)
        + bytes.fromhex(expected["keyId"][7:]) + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    binding = b"serverware/enclave-runtime-key-binding/v1\0\x04" + b"".join(bytes.fromhex(expected[name][7:])
        for name in SCOPE_DIGESTS[:5]) + hashlib.sha256(public).digest() + boot
    document = p.decoded(evidence["attestationDocumentB64"], maximum=12288)
    policy = config["nitro"]
    roots, certificates = _nitro_policy(policy)
    denied, _, _ = _revocation(config["collateralRevocation"], now)
    quote, _, _, _, root = nitro._verify_nitro_document_common(document, claims=None,
        expected_user_data_bytes=binding, challenge=challenge, expected_pcrs=policy["expectedPcrs"], expected_eif=policy["expectedEif"],
        roots=roots, crls=[], certificate_profile=certificates, expected_module_id=policy["expectedModuleId"],
        now=now // 1_000_000_000, max_age=policy["maxAgeSeconds"], future_skew=policy["futureSkewSeconds"], native_profile=True)
    p.require(type(quote["public_key"]) is bytes and quote["public_key"] == public)
    p.require(not {p.sha(value) for value in [quote["certificate"], *quote["cabundle"],
        root.public_bytes(serialization.Encoding.DER)]} & denied)
    return originals
