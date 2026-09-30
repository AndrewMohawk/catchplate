"""Purpose-fixed independent verifier producer; original COSE is always checked.

No request may select trust, keys, PCRs, freshness, or signed result fields.
The only signing path consumes the actual retained one-shot originals owner.
"""
from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import verify_nitro_tee as nitro
from serverware import native_shadow_nitro_profile as p


def _nitro_policy(value):
    p.fields(value, ("expectedPcrs", "expectedEif", "expectedModuleId", "awsNitroRootCertificatesPem",
        "nitroCertificateProfile", "maxAgeSeconds", "futureSkewSeconds"))
    pcrs = value["expectedPcrs"]
    p.require(type(pcrs) is dict and 3 <= len(pcrs) <= 32 and {"PCR0", "PCR1", "PCR2"} <= set(pcrs))
    for name, digest in pcrs.items():
        p.require(name in {"PCR" + str(index) for index in range(32)})
        nitro.require_sha384(digest, "shadow independently selected PCR")
        if name in {"PCR0", "PCR1", "PCR2"}:
            p.require(digest != "sha384:" + "0" * 96)
    p.require(value["expectedEif"] == pcrs["PCR0"])
    p.require(type(value["expectedModuleId"]) is str and 1 <= len(value["expectedModuleId"]) <= 256
        and value["expectedModuleId"].isascii())
    p.integer(value["maxAgeSeconds"], maximum=300)
    p.integer(value["futureSkewSeconds"], minimum=0, maximum=30)
    profile = p.fields(value["nitroCertificateProfile"], ("profileId", "allowedLeafExtendedKeyUsageOids"))
    p.require(profile["profileId"] == "aws-nitro-attestation-pki-native-v1")
    oids = profile["allowedLeafExtendedKeyUsageOids"]
    p.require(type(oids) is list and len(oids) <= 32 and all(type(oid) is str and 1 <= len(oid) <= 128
        and all(part.isascii() and part.isdigit() for part in oid.split(".")) and "." in oid for oid in oids)
        and oids == sorted(set(oids)))
    pem_roots = value["awsNitroRootCertificatesPem"]
    p.require(type(pem_roots) is list and 1 <= len(pem_roots) <= nitro.MAX_CERTIFICATES)
    roots = []
    for text in pem_roots:
        p.require(type(text) is str and 1 <= len(text) <= nitro.MAX_CERT_BYTES)
        raw = text.encode("ascii")
        root = x509.load_pem_x509_certificate(raw)
        p.require(root.public_bytes(serialization.Encoding.PEM) == raw and nitro.basic_constraints(root, "shadow root").ca)
        roots.append(root)
    p.require(len({nitro.certificate_sha256(root) for root in roots}) == len(roots))
    return roots, profile


def _revocation(value, now):
    p.fields(value, ("apiVersion", "profile", "generation", "issuedAtUnixNanos", "expiresAtUnixNanos", "deniedCertificateSha256s"))
    p.require(value["apiVersion"] == "serverware.nativeShadowNitroApplicationRevocation/v1"
        and value["profile"] == "application-denial-inventory-no-vendor-crl-v1")
    p.integer(value["generation"])
    p.freshness(value["issuedAtUnixNanos"], value["expiresAtUnixNanos"], now, 300_000_000_000)
    denied = value["deniedCertificateSha256s"]
    p.require(type(denied) is list and len(denied) <= 1024)
    for item in denied:
        p.digest(item)
    p.require(denied == sorted(set(denied)))
    return set(denied), p.sha(p.canonical(value)), p.framed(b"serverware.nativeShadowNitroApplicationRevocationRoot/v1",
        (p.canonical([value["generation"], denied]),))


def _result(originals):
    # Only the fixed entrypoint constructs Originals from protected real inputs.
    # The actual owner is retained through every check, key read and signature.
    from serverware.native_shadow_nitro_originals import Originals
    p.require(type(originals) is Originals)
    now = originals.check()
    config = originals.configuration
    statement, keys = p.authorization(config, now)
    roots, certificates = _nitro_policy(config["nitro"])
    denied, revocation_source, revocation_root = _revocation(config["collateralRevocation"], now)
    expected = p.fields(config["expectedAttestation"], ("platform", "expectedMeasurementSha256", "endorsementRootSha256",
        "collateralPolicySha256", "revocationSourceSha256"))
    p.require(expected["platform"] == "aws-nitro-enclave")
    for name in ("expectedMeasurementSha256", "endorsementRootSha256", "collateralPolicySha256", "revocationSourceSha256"):
        p.digest(expected[name])
    evidence = p.fields(originals.request, p.EVIDENCE_FIELDS)
    p.require(evidence["apiVersion"] == "serverware.nativeShadowRoleKeyEvidence/v1"
        and p.canonical(evidence["statement"]) == p.canonical(statement))
    proofs = evidence["possession"]
    p.require(type(proofs) is list and len(proofs) == len(statement["localKeys"]))
    statement_sha = p.sha(p.canonical(statement))
    for key, proof in zip(statement["localKeys"], proofs):
        p.fields(proof, ("role", "keyId", "signature"))
        p.require(proof["role"] == key["role"] and proof["keyId"] == key["keyId"])
        p.public_key(key).verify(p.decoded(proof["signature"], size=64), p.preimage(p.POSSESSION_DOMAIN,
            [key["role"], key["keyId"], statement_sha]))
    user_data = p.EVIDENCE_PREFIX + b"".join(p.raw_digest(value) for value in (
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
    # Every supplied certificate was included by the genuine chain verifier;
    # reject independent current app-level denials, without claiming an AWS CRL.
    chain_originals = [payload["certificate"], *payload["cabundle"], trusted_root.public_bytes(serialization.Encoding.DER)]
    p.require(not {p.sha(raw) for raw in chain_originals} & denied)
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
    p.authorization(config, now)
    _revocation(config["collateralRevocation"], now)
    # Use exact integer certificate seconds, not a floating-point lifetime.
    from datetime import datetime, timezone
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    certificate_expiries = []
    for raw in chain_originals:
        cert = x509.load_der_x509_certificate(raw)
        delta = nitro.certificate_time(cert, "not_valid_after") - epoch
        certificate_expiries.append((delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000)
    expires = min(now + config["maximumResultAgeNanos"], config["authorization"]["payload"]["expiresAtUnixNanos"],
        config["collateralRevocation"]["expiresAtUnixNanos"], config["trustCheckpoint"]["asOfUnixNanos"] + 300_000_000_000,
        (issued_at + n["maxAgeSeconds"]) * 1_000_000_000, now + originals.remaining(), *certificate_expiries)
    p.require(now < expires)
    checkpoint, signer = config["trustCheckpoint"], keys[-2]
    result = {
        "platform": "aws-nitro-enclave", "quoteSha256": p.sha(document), "endorsementEvidenceSha256": endorsement,
        "endorsementRootSha256": endorsement_root, "collateralPolicySha256": collateral_policy,
        "revocationSourceSha256": revocation_source, "collateralRevocationGeneration": config["collateralRevocation"]["generation"],
        "collateralRevocationRootSha256": revocation_root, "measurementSha256": measurement,
        "productionConfigurationBindingSha256": statement["productionConfigurationBindingSha256"],
        "workerExecutableSha256": statement["workerExecutableSha256"],
        "executionClosureManifestSha256": statement["executionClosureManifestSha256"],
        "structurallyVerifiedSeccompPolicySha256": statement["structurallyVerifiedSeccompPolicySha256"],
        "quoteBoundCustodyKeySetRootSha256": statement["fullKeySetRootSha256"], "verifiedAtUnixNanos": now,
        "expiresAtUnixNanos": expires, "trustCheckpointId": checkpoint["checkpointId"],
        "trustRevocationGeneration": checkpoint["revocationGeneration"], "trustRevocationRootSha256": checkpoint["revocationRootSha256"],
        "signingKeyId": signer["keyId"], "signingKeySpkiSha256": signer["keySpkiSha256"],
    }
    seed = originals.take_seed()
    try:
        key = Ed25519PrivateKey.from_private_bytes(seed)
        public_key = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        p.require(public_key == p.decoded(signer["publicKeyBase64url"], size=32))
        originals.check()
        result["signature"] = p.encoded(key.sign(p.preimage(p.RESULT_DOMAIN, p.result_payload(result))))
        after = originals.check()
        p.require(now <= after < expires)
        p.authorization(config, after)
        _revocation(config["collateralRevocation"], after)
    finally:
        seed[:] = b"\0" * len(seed)
        # Python/cryptography key-object memory is not claimed zeroized. The
        # fixed process must exit; it provides no further signing operation.
    output = p.canonical({"apiVersion": "serverware.nativeShadowNitroVerifierResult/v1", "result": result})
    p.require(len(output) <= p.MAX_RESULT)
    p.require(now <= originals.check() < expires)
    return output


def run():
    from serverware.native_shadow_nitro_originals import Originals
    with Originals.open() as originals:
        if originals.configuration["apiVersion"] == "serverware.nativeShadowNitroVerifierConfiguration/v3":
            from serverware.native_shadow_bridge_admission_verifier import result
            return result(originals)
        if originals.configuration["apiVersion"] == "serverware.nativeShadowNitroVerifierConfiguration/v2":
            from serverware.native_shadow_key_admission_verifier import result
            return result(originals)
        return _result(originals)
