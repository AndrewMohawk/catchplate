"""One independently configured verification/signing exchange. No store effect."""
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import native_shadow_nitro_profile as p
from serverware import native_generation_origin_profile as profile


def _signed(key, domain, payload):
    return {"payload": payload, "signature": p.encoded(key.sign(p.preimage(domain, payload)))}


def issue(originals):
    from serverware.native_generation_origin_originals import Originals
    p.require(type(originals) is Originals)
    now = originals.check()
    config, target = originals.configuration, originals.configuration["target"]
    auth = profile.authorization(config, now)
    seed = originals.take_seed()
    try:
        key = Ed25519PrivateKey.from_private_bytes(bytes(seed))
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        p.require(p.encoded(public) == config["originKey"]["publicKeyBase64url"])
        nonce = os.getrandom(32)
        p.require(len(nonce) == 32 and nonce != bytes(32))
        now = originals.check()
        expires = min(now + originals.remaining(), now + 30_000_000_000, auth["expiresAtUnixNanos"],
            config["originKey"]["notAfterUnixNanos"], config["issuerAuthorityKey"]["notAfterUnixNanos"],
            config["collateralRevocation"]["expiresAtUnixNanos"])
        p.require(now < expires)
        request = {"apiVersion": "serverware.nativeGenerationOriginRequest/v1", "challenge": p.encoded(nonce),
            "contextSha256": target["initializationScopeSha256"], "policyHash": target["holder"]["policyHash"],
            "assignmentPayloadSha256": target["assignmentPayloadSha256"], "generationId": target["generationId"],
            "issuedAtEpochNs": now, "expiresAtEpochNs": expires}
        p.fields(request, profile.REQUEST_FIELDS)
        challenge = {"apiVersion": "serverware.nativeGenerationOriginChallenge/v1", "request": request,
            "expiresAtUnixNanos": expires, "signingKeyId": config["originKey"]["keyId"]}
        originals.send(profile.CHALLENGE_TAG, p.canonical(_signed(key, profile.CHALLENGE_DOMAIN, challenge)))
        evidence_raw = originals.receive()
        now = originals.check()
        profile.verify_evidence(config, request, evidence_raw, now)
        # The independent issuer endorses exactly the fresh measured source
        # observation. It does not assert a durable spool initialization, a
        # current head, a Fleet load signature, or an effect permission.
        result = {"apiVersion": "serverware.nativeGenerationOrigin/v1", "purpose": "native-installed-generation-origin",
            "request": request, "evidenceOriginal": evidence_raw.decode("ascii"), "issuedAtUnixNanos": now,
            "expiresAtUnixNanos": expires, "signingKeyId": config["originKey"]["keyId"],
            "signingKeySpkiSha256": config["originKey"]["keySpkiSha256"]}
        p.fields(result, profile.ORIGIN_FIELDS)
        now = originals.check()
        profile.authorization(config, now)
        p.require(now < expires)
        originals.quiet()
        originals.send(profile.ANCHOR_TAG, p.canonical(_signed(key, profile.ORIGIN_DOMAIN, result)))
    finally:
        seed[:] = b"\0" * len(seed)
        # Python/backend key-object copies are not claimed zeroized. The fixed
        # isolated process exits after this one two-signature exchange.


def run():
    from serverware.native_generation_origin_originals import Originals
    with Originals.open() as owner:
        issue(owner)
