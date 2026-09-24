"""Closed optional configuration for purpose-specific WebAuthn evidence.

The surrounding signed configuration supplies authority; these validators only
own bounded data and genuinely join each explicit Ed25519 public key to its
SPKI digest. An absent extension grants no purpose. A present extension must
be closed, with a null slot disabling that purpose. No generic role key is
inferred, no key is enrolled, and returned policy/key values are not admission.

The public configuration-loader entry owns a standalone source-bounded meter.
Measured callers must use the private existing-work entry instead: it never
replaces or resets their allowance. Native cryptography internals remain the
existing bounded primitive boundary, not a whole-process work claim. Neither
entry imports the database or active transition registry.
"""
from __future__ import annotations

from serverware import authority_contract as authority
from serverware import authority_revocation_configuration as configuration
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


FIELD = "webauthnEvidenceAdmission"
SCHEMA = "serverware.policyAuthorityWebAuthnEvidenceAdmissionPolicy/v1"
_FIELDS = frozenset({"schema", "registration", "installation"})
_COMMON_FIELDS = frozenset({"operation", "purpose", "signingPublicKeyBase64Url",
    "signingSpkiDigest", "signerIdentity", "maximumAgeNs", "maximumClockSkewNs"})
_IDENTITY_FIELDS = frozenset({"sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest"})
_WEBAUTHN_FIELDS = frozenset({"rpId", "origin", "challengeLifetimeNs",
    "maximumChallengeAgeNs", "allowedAuthenticatorClasses", "requireAttestationTrusted"})
_PURPOSES = (
    ("registration", "webauthn.registration.evidence.admit", "registration-attestation"),
    ("installation", "webauthn.trust.installation.admit", "trust-installation"),
)
_REGISTRATION_FIELDS = _COMMON_FIELDS | {"rpId", "origin"}
_INSTALLATION_FIELDS = _COMMON_FIELDS | {"installationTargetDigest"}


class WebAuthnEvidencePolicyError(ValueError):
    pass


def _shape(value, *, webauthn):
    """Fixed closed shapes only; no encoding, hashing, key or JSON callback."""
    shape = configuration.capability.shape
    shape._object(value, _FIELDS, "WebAuthn evidence admission policy")
    shape._literal(value["schema"], SCHEMA)
    shape._object(webauthn, _WEBAUTHN_FIELDS, "configured WebAuthn values")
    for name, operation, purpose in _PURPOSES:
        entry = value[name]
        if entry is None:
            continue
        shape._object(entry, _REGISTRATION_FIELDS if name == "registration" else _INSTALLATION_FIELDS,
            "WebAuthn evidence purpose policy")
        shape._literal(entry["operation"], operation)
        shape._literal(entry["purpose"], purpose)
        shape._text(entry["signingPublicKeyBase64Url"], 43, minimum=43)
        shape._base64url(entry["signingPublicKeyBase64Url"])
        shape._digest(entry["signingSpkiDigest"])
        shape._object(entry["signerIdentity"], _IDENTITY_FIELDS, "WebAuthn evidence signer identity")
        for digest in entry["signerIdentity"].values():
            shape._digest(digest)
        shape._integer(entry["maximumAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
        shape._integer(entry["maximumClockSkewNs"], authority.VERIFIER_MAX_CLOCK_SKEW_NS)
        if name == "registration":
            for field, maximum in (("rpId", 4096), ("origin", 8192)):
                shape._text(entry[field], maximum)
                shape._text(webauthn[field], maximum)
        else:
            shape._digest(entry["installationTargetDigest"])


def _registration_binding(policy, webauthn, work):
    entry = policy["registration"]
    if entry is None:
        return
    for field, maximum in (("rpId", 4096), ("origin", 8192)):
        for value in (entry[field], webauthn[field]):
            size = work.prepare_utf8(value)
            encoded = value.encode("utf-8")
            if size != len(encoded) or not 1 <= size <= maximum:
                raise WebAuthnEvidencePolicyError("registration evidence RP/origin exceeds its source byte bound")
        configuration.capability.plan._same(entry[field], webauthn[field], work,
            "registration evidence RP/origin differs from the configured WebAuthn values")


def _validate_policy_on_work(value, *, webauthn, work):
    """Return owned policy and newly reconstructed keys on the original meter.

    Both complete input graphs are owned before the first real key constructor
    or SPKI serialization. The existing key helper performs canonical raw32
    decoding and Ed25519 reconstruction, guards its native callbacks, and pays
    for its real DER serialization/SHA join. This is not signed-config or
    purpose admission, and no caller-supplied successful result is accepted.
    """
    try:
        ledger = configuration.capability.capture._SharedLedger(work)
        _shape(value, webauthn=webauthn)
        owned = configuration._ConfigurationCapture(ledger,
            maximum_bytes=authority.MAX_REQUEST_BYTES).visit({"policy": value, "webauthn": webauthn})
        policy, owned_webauthn = owned["policy"], owned["webauthn"]
        _shape(policy, webauthn=owned_webauthn)
        _registration_binding(policy, owned_webauthn, work)
        keys = {}
        for name, _, _ in _PURPOSES:
            entry = policy[name]
            if entry is not None:
                keys[name] = configuration._key(entry["signingPublicKeyBase64Url"], work,
                    expected_spki=entry["signingSpkiDigest"])
        return policy, keys
    except ValueError as exc:
        if isinstance(exc, WebAuthnEvidencePolicyError):
            raise
        raise WebAuthnEvidencePolicyError("WebAuthn evidence admission policy is invalid") from exc


def validate_policy(value, *, webauthn):
    """Validate one top-level configuration extension, never existing work.

    The two enabled purposes require at most two actual SPKI SHA operations.
    Other work keeps the existing global source ceilings; this standalone
    allowance is never used by the measured configuration mapper.
    """
    work = _ValidationWork(QueryReadValidationLimits(max_hashes=2))
    policy, _ = _validate_policy_on_work(value, webauthn=webauthn, work=work)
    return policy
