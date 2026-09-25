"""Map one admitted configuration into the fixed evidence-plan signing owner.

The service supplies the genuinely root-verified configuration, active launch
generation, protected planner read descriptor and descriptor-loaded signer.
This mapper checks their consistency; it does not manufacture that provenance.
One real full configuration capture precedes every key callback. The fixed
read-owner continuation uses that same owned graph, never a later copy of
caller data. Planner raw key, response/signing pins and identity scalars are
held before the purpose-policy key callbacks and paired with the actual signer.

Evidence signer authority still comes only from the explicit signed purpose
policy. No generic verifier key is substituted. The actual plan owner derives
its maximum plan age from the held purpose evidence age, with no request or
mapper override. No policy field, allowlist, SQL, signing call, registry entry,
route, clock or new work allowance is introduced by constructing this owner.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_evidence as evidence
from serverware import authority_webauthn_evidence_configuration as read_configuration
from serverware import authority_webauthn_evidence_plan_owner as owner


class WebAuthnEvidencePlanConfigurationError(ValueError):
    pass


def _producer_from_configuration_on_work(*, purpose, payload, configuration_digest,
        generation, read_dsn, planner_private_key, work):
    try:
        if type(purpose) is not str or purpose not in ("registration", "installation"):
            raise WebAuthnEvidencePlanConfigurationError("evidence plan purpose is not source fixed")
        if not isinstance(planner_private_key, Ed25519PrivateKey):
            raise WebAuthnEvidencePlanConfigurationError("evidence plan local planner signer is not Ed25519")
        owned, _launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        roles = owned["roles"]
        if type(roles) is not dict or type(roles.get("planner")) is not dict:
            raise WebAuthnEvidencePlanConfigurationError("evidence plan planner role is absent")
        planner = roles["planner"]
        shape = configuration.capability.shape
        shape._literal(planner["processMode"], "policy-authority-planner")
        encoded_key = planner["signingPublicKeyBase64Url"]
        planner_spki = planner["signingSpkiDigest"]
        response_spki = planner["responseSigningSpkiDigest"]
        identity = {"sessionIdentityDigest": planner["plannerSessionIdentityDigest"],
            "measurementDigest": planner["measurementDigest"],
            "attestationReceiptDigest": planner["attestationReceiptDigest"]}
        shape._text(encoded_key, 43, minimum=43)
        shape._base64url(encoded_key)
        for pin in (*identity.values(), planner_spki, response_spki):
            shape._digest(pin)
        evidence.plan._same(response_spki, planner_spki, work,
            "evidence plan signer differs from its measured planner response pin")
        # This fixed continuation admits the actual signed operation allowlist
        # and purpose policy, and constructs its genuine evidence public key.
        # No later lookup reads the caller's or the owned planner role graph.
        read_planner = read_configuration._planner_from_owned_configuration_on_work(
            purpose=purpose, owned_payload=owned, read_dsn=read_dsn, work=work)
        planner_public_key = configuration._key(encoded_key, work, expected_spki=planner_spki)
        evidence.keys._pair_on_work(planner_private_key, planner_public_key, work)
        from serverware import authority_transition_registry as registry

        operation = (read_configuration.planning.registration.OPERATION if purpose == "registration"
            else read_configuration.planning.installation.OPERATION)
        program = registry.successor_program(operation)
        return program.factory(read_planner=read_planner,
            planner_private_key=planner_private_key, planner_public_key=planner_public_key,
            expected_planner_identity=identity, expected_planner_spki_digest=planner_spki,
            configuration_digest=configuration_digest)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnEvidencePlanConfigurationError):
            raise
        raise WebAuthnEvidencePlanConfigurationError("evidence plan configuration failed") from exc


def _registration_plan_producer_from_configuration_on_work(*, payload, configuration_digest,
        generation, read_dsn, planner_private_key, work):
    return _producer_from_configuration_on_work(purpose="registration", payload=payload,
        configuration_digest=configuration_digest, generation=generation, read_dsn=read_dsn,
        planner_private_key=planner_private_key, work=work)


def _installation_plan_producer_from_configuration_on_work(*, payload, configuration_digest,
        generation, read_dsn, planner_private_key, work):
    return _producer_from_configuration_on_work(purpose="installation", payload=payload,
        configuration_digest=configuration_digest, generation=generation, read_dsn=read_dsn,
        planner_private_key=planner_private_key, work=work)
