"""Independent one-shot NSM-time issuer, never an arrival-clock guest anchor."""
from __future__ import annotations

import os
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from scripts import verify_nitro_tee as nitro
from catchplate import native_shadow_nitro_profile as p
from catchplate import native_shadow_time_profile as t
from catchplate.native_shadow_nitro_verifier import _nitro_policy, _revocation


def _signed(key, domain, payload):
    return {"payload": payload, "signature": p.encoded(key.sign(p.preimage(domain, payload)))}


def _certificate_expiry(raw):
    cert = x509.load_der_x509_certificate(raw)
    delta = nitro.certificate_time(cert, "not_valid_after") - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def _anchor(originals, key, challenge, evidence_raw, guest):
    config = originals.configuration
    now = originals.check()
    auth = t.authorization(config, now)
    p.require(now < challenge["payload"]["expiresAtUnixNanos"])
    evidence = p.fields(p.document(evidence_raw, t.MAX_FRAME), t.EVIDENCE_FIELDS)
    statement = p.fields(evidence["statement"], t.STATEMENT_FIELDS)
    p.require(evidence["apiVersion"] == "catchplate.nativeShadowGuestTimeEvidence/v1"
        and statement["apiVersion"] == "catchplate.nativeShadowGuestTimeStatement/v1"
        and statement["purpose"] == "native-shadow-guest-time-sample"
        and p.canonical(statement["guest"]) == p.canonical(guest)
        and statement["challengeSha256"] == p.sha(p.canonical(challenge)))
    before, after = p.ns(statement["beforeBoottimeNs"]), p.ns(evidence["afterBoottimeNs"])
    width = after - before
    p.require(p.ns(guest["issuedAtBoottimeNs"]) <= before < after < p.ns(guest["startupDeadlineBoottimeNs"])
        and width <= p.ns(config["maximumBracketNanos"]))
    public = p.decoded(statement["publicKeyBase64url"], size=32)
    p.require(public != bytes(32) and statement["publicKeyBase64url"] not in (
        config["timeKey"]["publicKeyBase64url"], config["issuerAuthorityKey"]["publicKeyBase64url"],
        config["guestAuthorityPublicKeyBase64url"]))
    document = p.decoded(evidence["attestationDocumentBase64url"])
    quote_sha = p.sha(document)
    proof = {"statement": statement, "afterBoottimeNs": evidence["afterBoottimeNs"], "quoteSha256": quote_sha}
    Ed25519PublicKey.from_public_bytes(public).verify(p.decoded(evidence["signature"], size=64), p.preimage(t.SAMPLE_DOMAIN, proof))
    roots, certificates = _nitro_policy(config["nitro"])
    denied, _, _ = _revocation(config["collateralRevocation"], now)
    user_data = t.EVIDENCE_PREFIX + p.raw_digest(p.sha(p.canonical(statement)))
    nonce = p.decoded(challenge["payload"]["nonceBase64url"], size=32)
    n = config["nitro"]
    payload, _, _, _, root = nitro._verify_nitro_document_common(document, claims=None,
        expected_user_data_bytes=user_data, challenge=nonce, expected_pcrs=n["expectedPcrs"], expected_eif=n["expectedEif"],
        roots=roots, crls=[], certificate_profile=certificates, expected_module_id=n["expectedModuleId"],
        now=now // 1_000_000_000, max_age=n["maxAgeSeconds"], future_skew=n["futureSkewSeconds"], native_profile=True)
    p.require(type(payload["public_key"]) is bytes and payload["public_key"] == public)
    chain = [payload["certificate"], *payload["cabundle"], root.public_bytes(serialization.Encoding.DER)]
    p.require(not {p.sha(raw) for raw in chain} & denied)
    millis = p.integer(payload["timestamp"], maximum=p.MAX_I64 // 1_000_000)
    timestamp = millis * 1_000_000
    ppm = config["maximumClockRateErrorPpm"]
    # AWS authenticates millisecond UTC creation time. Neither rounding mode
    # nor a precise guest sample is invented. The independently authorized
    # error/rate bounds remain explicit trust assumptions, not quote claims.
    tolerance = 1_000_000 + config["timestampErrorNanos"] + t.drift(width, ppm)
    lower, upper = timestamp - width - tolerance, timestamp + tolerance
    p.integer(lower); p.integer(upper)
    p.require(challenge["payload"]["issuedAtUnixNanos"] <= lower <= upper
        and upper + width + t.drift(width, ppm) < challenge["payload"]["expiresAtUnixNanos"])
    expires = min(lower + config["maximumAnchorAgeNanos"], auth["expiresAtUnixNanos"],
        config["timeKey"]["notAfterUnixNanos"], config["issuerAuthorityKey"]["notAfterUnixNanos"],
        config["collateralRevocation"]["expiresAtUnixNanos"], timestamp + n["maxAgeSeconds"] * 1_000_000_000,
        *(_certificate_expiry(raw) for raw in chain))
    p.require(upper < expires and config["timeKey"]["notBeforeUnixNanos"] <= lower)
    result = {"apiVersion": "catchplate.nativeShadowGuestTimeAnchor/v2", "purpose": "native-shadow-guest-trusted-time",
        "guest": guest, "challengeSha256": statement["challengeSha256"], "evidenceSha256": p.sha(evidence_raw),
        "quoteSha256": quote_sha, "anchorBoottimeNs": statement["beforeBoottimeNs"],
        "earliestUnixNanos": lower, "latestUnixNanos": upper, "expiresAtUnixNanos": expires,
        "maximumClockRateErrorPpm": ppm, "signingKeyId": config["timeKey"]["keyId"]}
    p.fields(result, t.ANCHOR_FIELDS)
    now = originals.check()
    t.authorization(config, now); _revocation(config["collateralRevocation"], now)
    p.require(now < min(expires, challenge["payload"]["expiresAtUnixNanos"]))
    originals.quiet()
    wire = p.canonical(_signed(key, t.ANCHOR_DOMAIN, result))
    p.require(len(wire) <= t.MAX_FRAME)
    now = originals.check()
    t.authorization(config, now); _revocation(config["collateralRevocation"], now)
    p.require(now < min(expires, challenge["payload"]["expiresAtUnixNanos"]))
    return wire


def _issue(originals):
    from catchplate.native_shadow_time_originals import Originals
    p.require(type(originals) is Originals)
    config, now = originals.configuration, originals.check()
    auth = t.authorization(config, now)
    guest = t.guest_originals(config)
    p.require(originals.uid != guest["uid"] and originals.gid != guest["gid"])
    _nitro_policy(config["nitro"]); _revocation(config["collateralRevocation"], now)
    seed = originals.take_seed()
    try:
        key = Ed25519PrivateKey.from_private_bytes(bytes(seed))
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        p.require(p.encoded(public) == config["timeKey"]["publicKeyBase64url"])
        now = originals.check()
        t.authorization(config, now)
        nonce = os.getrandom(32)
        p.require(len(nonce) == 32 and nonce != bytes(32))
        expires = min(now + originals.remaining(), now + 30_000_000_000, auth["expiresAtUnixNanos"],
            config["timeKey"]["notAfterUnixNanos"], config["issuerAuthorityKey"]["notAfterUnixNanos"])
        p.require(now < expires)
        challenge_payload = {"apiVersion": "catchplate.nativeShadowGuestTimeChallenge/v1",
            "purpose": "native-shadow-guest-time-challenge", "guest": guest, "nonceBase64url": p.encoded(nonce),
            "issuedAtUnixNanos": now, "expiresAtUnixNanos": expires,
            "maximumBracketNanos": config["maximumBracketNanos"], "timestampErrorNanos": config["timestampErrorNanos"],
            "maximumClockRateErrorPpm": config["maximumClockRateErrorPpm"], "signingKeyId": config["timeKey"]["keyId"]}
        p.fields(challenge_payload, t.CHALLENGE_FIELDS)
        challenge = _signed(key, t.CHALLENGE_DOMAIN, challenge_payload)
        originals.send(t.CHALLENGE_TAG, p.canonical(challenge))
        evidence = originals.receive()
        anchor = _anchor(originals, key, challenge, evidence, guest)
        originals.send(t.ANCHOR_TAG, anchor)
    finally:
        seed[:] = b"\0" * len(seed)
        # cryptography/Python key-object copies are not claimed zeroized. The
        # fixed process exits after these two purpose-fixed signatures only.


def run():
    from catchplate.native_shadow_time_originals import Originals
    with Originals.open() as originals:
        _issue(originals)
