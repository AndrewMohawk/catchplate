"""Map admitted full configuration to fixed successor read/sign/verify owners.

The service supplies root-verified configuration, active launch bindings and,
where needed, a protected read descriptor and planner signer. One genuine full
configuration capture precedes owned continuations and native key callbacks.
These consistency checks do not manufacture configuration or history authority.

Every operation requires its explicit signed policy slot and selected planner
allowlist membership. Stage's explicit assertion key is joined to the actual
verifier role; its session identity is derived from this configuration rather
than stored self-referentially inside it. No evidence or installer role-key
fallback, caller policy override, database call or replacement work is provided.
"""
from __future__ import annotations

import math

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_revocation_plan as plan
from catchplate import authority_revocation_root_reader as reader
from catchplate import authority_webauthn_evidence as evidence
from catchplate import authority_webauthn_evidence_configuration as read_configuration
from catchplate import authority_webauthn_transition_plan_admission as admission
from catchplate import authority_webauthn_transition_policy as policy


_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_SLOTS = {"webauthn.registration.finalize": "registration",
    "webauthn.trust.stage": "stage", "webauthn.trust.complete": "completion"}


class WebAuthnTransitionConfigurationError(ValueError):
    pass


def _operation(operation):
    if type(operation) is not str or operation not in _SLOTS:
        raise WebAuthnTransitionConfigurationError("transition configuration operation is not source fixed")
    return _SLOTS[operation]


def _role(owned, name):
    roles = owned["roles"]
    if type(roles) is not dict or type(roles.get(name)) is not dict:
        raise WebAuthnTransitionConfigurationError("transition configuration role is absent")
    role = roles[name]
    configuration.capability.shape._literal(role["processMode"], "policy-authority-" + name)
    return role


def _key_material(role, runtime_role, work):
    """Hold measured role scalars before any actual key construction callback."""
    shape = configuration.capability.shape
    encoded, spki, response = (role["signingPublicKeyBase64Url"],
        role["signingSpkiDigest"], role["responseSigningSpkiDigest"])
    measurement, attestation = role["measurementDigest"], runtime_role["attestationReceiptDigest"]
    shape._text(encoded, 43, minimum=43)
    shape._base64url(encoded)
    for value in (spki, response, measurement, attestation):
        shape._digest(value)
    plan._same(response, spki, work, "transition role signing key differs from its measured response pin")
    return encoded, spki, measurement, attestation


def _read_settings(owned, owned_runtime_identities, read_dsn):
    """Hold the complete real read connection tuple before policy key callbacks."""
    reader._bounded_text(read_dsn, 65536)
    if "\n" in read_dsn or "\r" in read_dsn:
        raise WebAuthnTransitionConfigurationError("transition read DSN is not one descriptor value")
    planner = _role(owned, "planner")
    timeout = planner["databaseConnectTimeoutSeconds"]
    if (type(timeout) not in (int, float)
            or type(timeout) is float and not math.isfinite(timeout)
            or not 2 <= timeout <= 300):
        raise WebAuthnTransitionConfigurationError("transition planner timeout is outside its bounded interval")
    database = (planner["databaseRole"], planner["tlsClientDn"], planner["tlsClientSerial"],
        planner["tlsIssuerDn"], planner["plannerSessionIdentityDigest"],
        planner["measurementDigest"], owned_runtime_identities["roles"]["planner"]["attestationReceiptDigest"])
    reader._bounded_text(database[0], 63)
    for value in database[1:4]:
        reader._bounded_text(value, 4096)
    for value in database[4:]:
        configuration.capability.shape._digest(value)
    return read_dsn, int(timeout), database


def _pins_from_owned_configuration_on_work(*, operation, owned_payload, owned_runtime_identities,
        configuration_digest, work):
    """Shared fixed pins without another full capture, DSN, clock or signer.

    Only callers that just performed the real full configuration/generation
    capture use this continuation. Role settings needed later are held by those
    callers before entering this helper's policy/key callbacks.
    """
    configuration.capability.capture._SharedLedger(work)
    slot = _operation(operation)
    if type(owned_payload) is not dict:
        raise WebAuthnTransitionConfigurationError("owned transition configuration is not exact")
    shape = configuration.capability.shape
    shape._digest(configuration_digest)
    planner, verifier = _role(owned_payload, "planner"), _role(owned_payload, "verifier")
    read_configuration._require_enabled_operation(planner, operation, work)
    plan._same(owned_payload["queryManifestDigest"], plan._QUERY_MANIFEST_DIGEST, work,
        "transition query manifest differs from the source")
    planner_encoded, planner_spki, planner_measurement, planner_attestation = _key_material(
        planner, owned_runtime_identities["roles"]["planner"], work)
    planner_session = planner["plannerSessionIdentityDigest"]
    shape._digest(planner_session)
    planner_identity = (planner_session, planner_measurement, planner_attestation)
    verifier_encoded, verifier_spki, verifier_measurement, verifier_attestation = _key_material(
        verifier, owned_runtime_identities["roles"]["verifier"], work)
    if policy.FIELD not in owned_payload:
        raise WebAuthnTransitionConfigurationError("transition operation has no signed purpose policy")
    purpose_policy, webauthn = owned_payload[policy.FIELD], owned_payload["webauthn"]
    policy._shape(purpose_policy, webauthn=webauthn)
    selected = purpose_policy[slot]
    if selected is None:
        raise WebAuthnTransitionConfigurationError("transition operation is disabled")
    plan._same(selected["operation"], operation, work, "transition policy operation differs from its fixed slot")
    encoded, spki = selected["signingPublicKeyBase64Url"], selected["signingSpkiDigest"]
    age, skew, plan_age = (selected["maximumAgeNs"], selected["maximumClockSkewNs"],
        selected["maximumPlanAgeNs"])
    if slot == "stage":
        # An explicit session identity inside this signed policy would depend
        # on the configuration digest that commits to itself. Derive it only
        # from held, admitted role/configuration scalars, never from a request.
        session = configuration._frame_text(configuration._VERIFIER_SESSION,
            (configuration_digest, verifier_measurement, verifier_attestation), work)
        signer_identity = (session, verifier_measurement, verifier_attestation)
        plan._same((encoded, spki), (verifier_encoded, verifier_spki), work,
            "trust-stage assertion key differs from the actual verifier role")
        tail = (selected["candidateSigningKeyId"], selected["developmentEnabled"],
            selected["requireApproval"], selected["requireApproverWebauthn"])
    else:
        signer_identity = tuple(selected["signerIdentity"][name] for name in _IDENTITY_FIELDS)
        tail = ((selected["rpId"], selected["origin"]) if slot == "registration"
            else (selected["installationTargetDigest"],))
    purpose_pins = (age, skew, plan_age, signer_identity, spki) + tail
    # Every scalar and role binding used after this point is immutable and
    # held. The real validator owns its graphs and reconstructs explicit keys;
    # neither its returned policy graph nor the caller payload is read again.
    _owned_policy, keys = policy._validate_policy_on_work(purpose_policy, webauthn=webauthn, work=work)
    operation_key = keys[slot]
    planner_key = configuration._key(planner_encoded, work, expected_spki=planner_spki)
    return admission._validate_pins((operation, planner_key, planner_identity, planner_spki,
        operation_key, configuration_digest, purpose_pins))


def _read_owner(settings, pins):
    from catchplate import authority_transition_registry as registry

    operation, _planner_key, _planner_identity, _planner_spki, key, _digest, purpose = pins
    factory = registry.successor_program(operation).factory
    common = {"read_dsn": settings[0], "connect_timeout_seconds": settings[1],
        "database_identity": settings[2], "maximum_age_ns": purpose[0],
        "maximum_clock_skew_ns": purpose[1]}
    identity = dict(zip(_IDENTITY_FIELDS, purpose[3]))
    if operation == "webauthn.registration.finalize":
        return factory(**common, evidence_public_key=key, expected_signer_identity=identity,
            expected_signer_spki_digest=purpose[4], expected_rp_id=purpose[5], expected_origin=purpose[6])
    if operation == "webauthn.trust.stage":
        return factory(**common, verifier_public_key=key, verifier_identity=identity,
            expected_candidate_signing_key_id=purpose[5], development_enabled=purpose[6],
            require_approval=purpose[7], require_approver_webauthn=purpose[8])
    return factory(**common, installer_public_key=key, expected_installer_identity=identity,
        expected_installer_spki_digest=purpose[4], installation_target_digest=purpose[5])


def _planner_from_configuration_on_work(*, operation, payload, configuration_digest,
        generation, runtime_role_identities, read_dsn, work):
    try:
        _operation(operation)
        owned, _launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        runtime = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime_role_identities, owned_payload=owned,
            configuration_digest=configuration_digest, launch=_launch, work=work)
        settings = _read_settings(owned, runtime, read_dsn)
        pins = _pins_from_owned_configuration_on_work(operation=operation, owned_payload=owned,
            owned_runtime_identities=runtime, configuration_digest=configuration_digest, work=work)
        return _read_owner(settings, pins)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnTransitionConfigurationError):
            raise
        raise WebAuthnTransitionConfigurationError("transition read planner configuration failed") from exc


def _producer_from_configuration_on_work(*, operation, payload, configuration_digest,
        generation, runtime_role_identities, read_dsn, planner_private_key, work):
    try:
        _operation(operation)
        if not isinstance(planner_private_key, Ed25519PrivateKey):
            raise WebAuthnTransitionConfigurationError("transition planner signer is not Ed25519")
        owned, _launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        runtime = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime_role_identities, owned_payload=owned,
            configuration_digest=configuration_digest, launch=_launch, work=work)
        settings = _read_settings(owned, runtime, read_dsn)
        pins = _pins_from_owned_configuration_on_work(operation=operation, owned_payload=owned,
            owned_runtime_identities=runtime, configuration_digest=configuration_digest, work=work)
        evidence.keys._pair_on_work(planner_private_key, pins[1], work)
        read_planner = _read_owner(settings, pins)
        from catchplate import authority_transition_registry as registry

        program = registry.successor_program(operation)
        return program.plan_factory(read_planner=read_planner, planner_private_key=planner_private_key,
            planner_public_key=pins[1], expected_planner_identity=dict(zip(_IDENTITY_FIELDS, pins[2])),
            expected_planner_spki_digest=pins[3], configuration_digest=pins[5], maximum_plan_age_ns=pins[6][2])
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnTransitionConfigurationError):
            raise
        raise WebAuthnTransitionConfigurationError("transition plan producer configuration failed") from exc


def _verifier_from_configuration_on_work(*, operation, payload, configuration_digest, generation,
        runtime_role_identities, work):
    try:
        _operation(operation)
        owned, _launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        runtime = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime_role_identities, owned_payload=owned,
            configuration_digest=configuration_digest, launch=_launch, work=work)
        pins = _pins_from_owned_configuration_on_work(operation=operation, owned_payload=owned,
            owned_runtime_identities=runtime, configuration_digest=configuration_digest, work=work)
        from catchplate import authority_webauthn_transition_plan_verifier as verifier

        return verifier.TransitionPlanVerifier(pins=pins)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnTransitionConfigurationError):
            raise
        raise WebAuthnTransitionConfigurationError("transition plan verifier configuration failed") from exc
