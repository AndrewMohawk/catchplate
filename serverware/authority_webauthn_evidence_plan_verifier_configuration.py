"""Shared admitted purpose pins and a fixed evidence-plan verifier mapper.

The service supplies genuinely root-verified configuration and active launch
bindings. Each fixed mapper performs one full configuration capture before
using the private owned-graph continuation below. That continuation establishes
consistency, not configuration or launch provenance, and never substitutes a
generic verifier key for the explicit evidence-purpose key.

Planner identity, response/signing pins, enabled operation and all selected
purpose scalars are held before actual policy/planner key callbacks. Shared
pins are an immutable thirteen-tuple of ordinary configured inputs, not proof
authority. The verifier has no DSN, private key, clock, SQL or signing path.
Original bytes and independently admitted historical expectations remain
mandatory at the actual verifier boundary; stored context cannot enroll them.
"""
from __future__ import annotations

from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_plan as plan
from serverware import authority_webauthn_evidence_configuration as read_configuration
from serverware import authority_webauthn_evidence_plan_admission as admission
from serverware import authority_webauthn_evidence_policy as policy


_IDENTITY_FIELDS = admission._IDENTITY_FIELDS


class WebAuthnEvidencePlanVerifierConfigurationError(ValueError):
    pass


def _pins_from_owned_configuration_on_work(*, purpose, owned_payload, owned_runtime_identities,
        configuration_digest, work):
    """Continue only after this invocation's genuine full configuration capture.

    Callers must retain their role-specific settings before this helper's key
    callbacks. No full configuration is recaptured and no database/read owner
    is constructed to obtain these independently configured public pins.
    """
    try:
        configuration.capability.capture._SharedLedger(work)
        if type(purpose) is not str or purpose not in ("registration", "installation"):
            raise WebAuthnEvidencePlanVerifierConfigurationError("evidence plan purpose is not source fixed")
        if type(owned_payload) is not dict:
            raise WebAuthnEvidencePlanVerifierConfigurationError("owned evidence configuration is not an exact object")
        shape = configuration.capability.shape
        shape._digest(configuration_digest)
        roles = owned_payload["roles"]
        if type(roles) is not dict or type(roles.get("planner")) is not dict:
            raise WebAuthnEvidencePlanVerifierConfigurationError("evidence plan planner role is absent")
        planner = roles["planner"]
        shape._literal(planner["processMode"], "policy-authority-planner")
        operation = ("webauthn.registration.evidence.admit" if purpose == "registration"
            else "webauthn.trust.installation.admit")
        read_configuration._require_enabled_operation(planner, operation, work)
        plan._same(owned_payload["queryManifestDigest"], plan._QUERY_MANIFEST_DIGEST, work,
            "evidence plan query manifest differs from the source")
        planner_encoded = planner["signingPublicKeyBase64Url"]
        planner_spki, response_spki = planner["signingSpkiDigest"], planner["responseSigningSpkiDigest"]
        planner_identity = (planner["plannerSessionIdentityDigest"],
            planner["measurementDigest"], owned_runtime_identities["roles"]["planner"]["attestationReceiptDigest"])
        shape._text(planner_encoded, 43, minimum=43)
        shape._base64url(planner_encoded)
        for digest in (*planner_identity, planner_spki, response_spki):
            shape._digest(digest)
        plan._same(response_spki, planner_spki, work,
            "evidence plan planner key differs from its response pin")
        if policy.FIELD not in owned_payload:
            raise WebAuthnEvidencePlanVerifierConfigurationError("evidence plan has no signed purpose policy")
        purpose_policy, webauthn = owned_payload[policy.FIELD], owned_payload["webauthn"]
        policy._shape(purpose_policy, webauthn=webauthn)
        selected = purpose_policy[purpose]
        if selected is None:
            raise WebAuthnEvidencePlanVerifierConfigurationError("evidence plan purpose is disabled")
        evidence_identity = tuple(selected["signerIdentity"][name] for name in _IDENTITY_FIELDS)
        evidence_spki = selected["signingSpkiDigest"]
        age, skew = selected["maximumAgeNs"], selected["maximumClockSkewNs"]
        rp_id = selected["rpId"] if purpose == "registration" else None
        origin = selected["origin"] if purpose == "registration" else None
        target = selected["installationTargetDigest"] if purpose == "installation" else None
        # Every relevant scalar is now held. The actual policy validator owns
        # its policy/WebAuthn graphs and reconstructs real configured keys; no
        # returned policy graph supplies a new authority or later scalar pin.
        _purposes, public_keys = policy._validate_policy_on_work(purpose_policy, webauthn=webauthn, work=work)
        evidence_key = public_keys[purpose]
        planner_key = configuration._key(planner_encoded, work, expected_spki=planner_spki)
        return admission._validate_pins((operation, planner_key, planner_identity, planner_spki,
            evidence_key, evidence_identity, evidence_spki, configuration_digest,
            age, skew, rp_id, origin, target))
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnEvidencePlanVerifierConfigurationError):
            raise
        raise WebAuthnEvidencePlanVerifierConfigurationError("evidence plan pin configuration failed") from exc


def _verifier_from_configuration_on_work(*, purpose, payload, configuration_digest, generation,
        runtime_role_identities, work):
    try:
        if type(purpose) is not str or purpose not in ("registration", "installation"):
            raise WebAuthnEvidencePlanVerifierConfigurationError("evidence verifier purpose is not source fixed")
        owned, _launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        runtime = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime_role_identities, owned_payload=owned,
            configuration_digest=configuration_digest, launch=_launch, work=work)
        roles = owned["roles"]
        if type(roles) is not dict or type(roles.get("verifier")) is not dict:
            raise WebAuthnEvidencePlanVerifierConfigurationError("evidence verifier role is absent")
        role = roles["verifier"]
        shape = configuration.capability.shape
        shape._literal(role["processMode"], "policy-authority-verifier")
        for field in ("measurementDigest", "responseSigningSpkiDigest",
                "signingSpkiDigest"):
            shape._digest(role[field])
        plan._same(role["responseSigningSpkiDigest"], role["signingSpkiDigest"], work,
            "evidence verifier role differs from its measured response pin")
        pins = _pins_from_owned_configuration_on_work(purpose=purpose, owned_payload=owned,
            owned_runtime_identities=runtime, configuration_digest=configuration_digest, work=work)
        from serverware import authority_webauthn_evidence_plan_verifier as verifier

        return verifier.EvidencePlanVerifier(pins=pins)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnEvidencePlanVerifierConfigurationError):
            raise
        raise WebAuthnEvidencePlanVerifierConfigurationError("evidence plan verifier configuration failed") from exc


def _registration_plan_verifier_from_configuration_on_work(*, payload, configuration_digest, generation,
        runtime_role_identities, work):
    return _verifier_from_configuration_on_work(purpose="registration", payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)


def _installation_plan_verifier_from_configuration_on_work(*, payload, configuration_digest, generation,
        runtime_role_identities, work):
    return _verifier_from_configuration_on_work(purpose="installation", payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
