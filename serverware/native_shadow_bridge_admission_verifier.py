"""One genuine Nitro verification, two distinct assigned result signatures."""
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import verify_nitro_tee as nitro
from serverware import native_shadow_nitro_profile as p
from serverware import native_shadow_bridge_admission_profile as a
from serverware import native_shadow_nitro_verifier as shared


def result(originals):
    from serverware.native_shadow_nitro_originals import Originals
    p.require(type(originals) is Originals)
    now = originals.check()
    config = originals.configuration
    scope, keys = a.authorization(config, now)
    roots, certificates = shared._nitro_policy(config["nitro"])
    denied, revocation_source, revocation_root = shared._revocation(config["collateralRevocation"], now)
    expected = p.fields(config["expectedAttestation"], ("platform", "expectedMeasurementSha256", "endorsementRootSha256",
        "collateralPolicySha256", "revocationSourceSha256"))
    p.require(expected["platform"] == "aws-nitro-enclave")
    for name in ("expectedMeasurementSha256", "endorsementRootSha256", "collateralPolicySha256", "revocationSourceSha256"):
        p.digest(expected[name])
    evidence = p.fields(originals.request, p.EVIDENCE_FIELDS)
    p.require(evidence["apiVersion"] == "serverware.nativeShadowBridgeAdmissionEvidence/v1")
    statement = a.statement(evidence["statement"], scope)
    statement_sha = p.sha(p.canonical(statement))
    proofs = evidence["possession"]
    p.require(type(proofs) is list and len(proofs) == len(statement["localKeys"]))
    for key, proof in zip(statement["localKeys"], proofs):
        p.fields(proof, ("role", "keyId", "signature"))
        p.require(proof["role"] == key["role"] and proof["keyId"] == key["keyId"])
        p.public_key(key).verify(p.decoded(proof["signature"], size=64),
            p.preimage(a.POSSESSION_DOMAIN, [key["role"], key["keyId"], statement_sha]))
    user_data = a.PREFIX + b"".join(p.raw_digest(value) for value in (
        statement_sha, statement["fullKeySetRootSha256"], statement["localKeySetRootSha256"], p.sha(p.canonical(proofs))))
    nonce = p.decoded(statement["challengeBase64url"], size=32)
    public = p.raw_digest(statement["localKeySetRootSha256"])
    p.require(p.decoded(evidence["userDataBase64url"], maximum=1024) == user_data
        and p.decoded(evidence["publicKeyBase64url"], size=32) == public
        and p.decoded(evidence["nonceBase64url"], size=32) == nonce)
    document = p.decoded(evidence["attestationDocumentBase64url"])
    now = originals.check()
    n = config["nitro"]
    payload, issued_at, pcrs, _leaf, trusted_root = nitro._verify_nitro_document_common(document, claims=None,
        expected_user_data_bytes=user_data, challenge=nonce, expected_pcrs=n["expectedPcrs"], expected_eif=n["expectedEif"],
        roots=roots, crls=[], certificate_profile=certificates, expected_module_id=n["expectedModuleId"],
        now=now // 1_000_000_000, max_age=n["maxAgeSeconds"], future_skew=n["futureSkewSeconds"], native_profile=True)
    p.require(type(payload["public_key"]) is bytes and payload["public_key"] == public)
    chain = [payload["certificate"], *payload["cabundle"], trusted_root.public_bytes(serialization.Encoding.DER)]
    p.require(not {p.sha(raw) for raw in chain} & denied)
    measurement = p.framed(b"serverware.nativeShadowNitroMeasurement/v1", (p.canonical([
        payload["module_id"], pcrs, n["expectedEif"], statement["workerExecutableSha256"],
        statement["executionClosureManifestSha256"], statement["structurallyVerifiedSeccompPolicySha256"]]),))
    endorsement = p.framed(b"serverware.nativeShadowNitroEndorsementEvidence/v1", (p.canonical([
        p.encoded(payload["certificate"]), [p.encoded(raw) for raw in payload["cabundle"]]]),))
    endorsement_root = nitro.certificate_sha256(trusted_root)
    collateral_policy = p.framed(b"serverware.nativeShadowNitroCollateralPolicy/v1", (p.canonical(n),))
    p.require(measurement == expected["expectedMeasurementSha256"] and endorsement_root == expected["endorsementRootSha256"]
        and collateral_policy == expected["collateralPolicySha256"] and revocation_source == expected["revocationSourceSha256"])
    now = originals.check()
    a.authorization(config, now)
    shared._revocation(config["collateralRevocation"], now)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    certificate_expiries = []
    for raw in chain:
        cert = x509.load_der_x509_certificate(raw)
        delta = nitro.certificate_time(cert, "not_valid_after") - epoch
        certificate_expiries.append((delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000)
    expires = min(now + config["maximumResultAgeNanos"], config["authorization"]["payload"]["expiresAtUnixNanos"],
        config["admissionAuthorization"]["payload"]["expiresAtUnixNanos"], config["collateralRevocation"]["expiresAtUnixNanos"],
        config["trustCheckpoint"]["asOfUnixNanos"] + 300_000_000_000, (issued_at + n["maxAgeSeconds"]) * 1_000_000_000,
        now + originals.remaining(), *certificate_expiries)
    p.require(now < expires)
    checkpoint, signer = config["trustCheckpoint"], keys[-2]
    result_payload = {
        "apiVersion": "serverware.nativeShadowBridgeContextResult/v1", "purpose": "native-shadow-context-and-production-admission",
        "productionConfigurationBindingSha256": statement["productionConfigurationBindingSha256"],
        "statementSha256": statement_sha, "quoteSha256": p.sha(document), "nativeContextSha256": statement["nativeContextSha256"],
        "admissionAuthorizationSha256": statement["admissionAuthorizationSha256"], "keyAuthorizationSha256": statement["keyAuthorizationSha256"],
        "fullKeySetRootSha256": statement["fullKeySetRootSha256"], "localKeySetRootSha256": statement["localKeySetRootSha256"],
        "measurementSha256": measurement, "endorsementEvidenceSha256": endorsement, "endorsementRootSha256": endorsement_root,
        "collateralPolicySha256": collateral_policy, "revocationSourceSha256": revocation_source,
        "collateralRevocationGeneration": config["collateralRevocation"]["generation"], "collateralRevocationRootSha256": revocation_root,
        "trustCheckpointId": checkpoint["checkpointId"], "trustRevocationGeneration": checkpoint["revocationGeneration"],
        "trustRevocationRootSha256": checkpoint["revocationRootSha256"], "verifiedAtUnixNanos": now, "expiresAtUnixNanos": expires,
        "signingKeyId": signer["keyId"], "signingKeySpkiSha256": signer["keySpkiSha256"],
    }
    production = {name: result_payload[name] for name in (
        "quoteSha256", "endorsementEvidenceSha256", "endorsementRootSha256", "collateralPolicySha256",
        "revocationSourceSha256", "collateralRevocationGeneration", "collateralRevocationRootSha256",
        "measurementSha256", "productionConfigurationBindingSha256", "verifiedAtUnixNanos", "expiresAtUnixNanos",
        "trustCheckpointId", "trustRevocationGeneration", "trustRevocationRootSha256", "signingKeyId", "signingKeySpkiSha256")}
    production.update(platform="aws-nitro-enclave",
        workerExecutableSha256=statement["workerExecutableSha256"],
        executionClosureManifestSha256=statement["executionClosureManifestSha256"],
        structurallyVerifiedSeccompPolicySha256=statement["structurallyVerifiedSeccompPolicySha256"],
        quoteBoundCustodyKeySetRootSha256=statement["fullKeySetRootSha256"])
    seed = originals.take_seed()
    try:
        key = Ed25519PrivateKey.from_private_bytes(seed)
        p.require(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            == p.decoded(signer["publicKeyBase64url"], size=32))
        originals.check()
        signature = p.encoded(key.sign(p.preimage(a.RESULT_DOMAIN, result_payload)))
        # This is the existing FULL production verification domain over the
        # genuinely checked combined quote, not a context-result conversion.
        production["signature"] = p.encoded(key.sign(p.preimage(p.RESULT_DOMAIN, p.result_payload(production))))
        after = originals.check()
        p.require(now <= after < expires)
        a.authorization(config, after)
        shared._revocation(config["collateralRevocation"], after)
    finally:
        seed[:] = b"\0" * len(seed)
    # Same fixed process exits; no Python key-object zeroization claim or sign RPC.
    context_original = p.canonical({"apiVersion": "serverware.nativeShadowBridgeContextVerifierResult/v1",
        "payload": result_payload, "signature": signature})
    production_original = p.canonical({"apiVersion": "serverware.nativeShadowNitroVerifierResult/v1", "result": production})
    output = p.canonical({"apiVersion": "serverware.nativeShadowBridgeAdmissionVerifierResult/v1",
        "contextResultOriginal": context_original.decode("ascii"),
        "productionResultOriginal": production_original.decode("ascii")})
    p.require(len(output) <= p.MAX_RESULT and now <= originals.check() < expires)
    return output
