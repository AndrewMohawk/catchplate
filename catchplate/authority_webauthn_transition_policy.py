"""Closed optional configuration for three genuine WebAuthn transitions.

The surrounding signed configuration supplies authority. This module owns
bounded policy data and genuinely binds each explicit Ed25519 raw public key
to its SPKI digest; it does not enroll keys or enable an operation. Absence
grants no authority, and each null slot disables that fixed operation. No
generic role key, evidence policy or default policy is substituted.

Measured callers retain their original cumulative work. Only the standalone
configuration-loader entry creates its source-bounded three-hash allowance.
Native cryptography keeps its existing guarded primitive boundary; neither
entry imports the database or active transition registry.
"""
from __future__ import annotations

from catchplate import authority_contract as authority
from catchplate import authority_revocation_configuration as configuration
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


FIELD = "webauthnTransitions"
SCHEMA = "catchplate.policyAuthorityWebAuthnTransitionPolicy/v1"
_FIELDS = frozenset({"schema", "registration", "stage", "completion"})
_COMMON_FIELDS = frozenset({"operation", "signingPublicKeyBase64Url", "signingSpkiDigest",
    "signerIdentity", "maximumAgeNs", "maximumClockSkewNs", "maximumPlanAgeNs"})
_IDENTITY_FIELDS = frozenset({"sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest"})
_WEBAUTHN_FIELDS = frozenset({"rpId", "origin", "challengeLifetimeNs",
    "maximumChallengeAgeNs", "allowedAuthenticatorClasses", "requireAttestationTrusted"})
_OPERATIONS = (
    ("registration", "webauthn.registration.finalize"),
    ("stage", "webauthn.trust.stage"),
    ("completion", "webauthn.trust.complete"),
)
_REGISTRATION_FIELDS = _COMMON_FIELDS | {"rpId", "origin"}
_STAGE_FIELDS = (_COMMON_FIELDS - {"signerIdentity"}) | {"candidateSigningKeyId", "developmentEnabled",
    "requireApproval", "requireApproverWebauthn"}
_COMPLETION_FIELDS = _COMMON_FIELDS | {"installationTargetDigest"}
_ENTRY_FIELDS = {"registration": _REGISTRATION_FIELDS, "stage": _STAGE_FIELDS,
    "completion": _COMPLETION_FIELDS}


class WebAuthnTransitionPolicyError(ValueError):
    pass


def _shape(value, *, webauthn):
    """Close all fixed shapes without encoding, hashing or key callbacks."""
    shape = configuration.capability.shape
    shape._object(value, _FIELDS, "WebAuthn transition policy")
    shape._literal(value["schema"], SCHEMA)
    shape._object(webauthn, _WEBAUTHN_FIELDS, "configured WebAuthn values")
    for slot, operation in _OPERATIONS:
        entry = value[slot]
        if entry is None:
            continue
        shape._object(entry, _ENTRY_FIELDS[slot], "WebAuthn operation-specific transition policy")
        shape._literal(entry["operation"], operation)
        shape._text(entry["signingPublicKeyBase64Url"], 43, minimum=43)
        shape._base64url(entry["signingPublicKeyBase64Url"])
        shape._digest(entry["signingSpkiDigest"])
        if slot != "stage":
            shape._object(entry["signerIdentity"], _IDENTITY_FIELDS, "WebAuthn transition signer identity")
            for digest in entry["signerIdentity"].values():
                shape._digest(digest)
        # Stage uses the actual configured verifier role. Its session identity
        # includes the complete configuration digest, so retaining that identity
        # inside this policy would create a circular configuration commitment.
        # The measured mapper derives it after owning the full configuration.
        for field in ("maximumAgeNs", "maximumPlanAgeNs"):
            shape._integer(entry[field], authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
        shape._integer(entry["maximumClockSkewNs"], authority.VERIFIER_MAX_CLOCK_SKEW_NS)
        if slot == "registration":
            for field, maximum in (("rpId", 4096), ("origin", 8192)):
                shape._text(entry[field], maximum)
                shape._text(webauthn[field], maximum)
        elif slot == "stage":
            shape._digest(entry["candidateSigningKeyId"])
            for field in ("developmentEnabled", "requireApproval", "requireApproverWebauthn"):
                if type(entry[field]) is not bool:
                    raise WebAuthnTransitionPolicyError("WebAuthn stage policy flags must be exact booleans")
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
            if size != len(encoded) or not 1 <= size <= maximum or "\x00" in value:
                raise WebAuthnTransitionPolicyError("registration RP/origin exceeds its source text bound")
        configuration.capability.plan._same(entry[field], webauthn[field], work,
            "registration transition RP/origin differs from configured WebAuthn values")


def _validate_policy_on_work(value, *, webauthn, work):
    """Return owned policy and actual reconstructed slot keys on existing work.

    Both complete input graphs are captured before the first native key or
    SPKI callback. Canonical raw32 decoding, genuine Ed25519 construction,
    guarded DER serialization and the actual SPKI SHA join use the existing
    configuration helper and original meter. Outputs are ordinary data/keys,
    not a successful-policy or signed-configuration admission token.
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
        for slot, _operation in _OPERATIONS:
            entry = policy[slot]
            if entry is not None:
                keys[slot] = configuration._key(entry["signingPublicKeyBase64Url"], work,
                    expected_spki=entry["signingSpkiDigest"])
        return policy, keys
    except ValueError as exc:
        if isinstance(exc, WebAuthnTransitionPolicyError):
            raise
        raise WebAuthnTransitionPolicyError("WebAuthn transition policy is invalid") from exc


def validate_policy(value, *, webauthn):
    """Standalone configuration validation, never a replacement caller meter.

    At most three enabled slots perform three actual SPKI SHA operations.
    Byte/node work retains the existing source ceilings. Measured configuration
    mappers must call the existing-work entry directly instead.
    """
    work = _ValidationWork(QueryReadValidationLimits(max_hashes=3))
    policy, _ = _validate_policy_on_work(value, webauthn=webauthn, work=work)
    return policy
