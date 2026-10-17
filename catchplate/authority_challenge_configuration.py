"""Bind maintenance producers/verifiers to admitted Service6 originals.

These fixed factories repeat the existing complete configuration, generation
and runtime-role joins. They do not enroll a supplied configuration or root.
The measured service supplies the admitted owner, actual launch, protected
read descriptor and (planner only) retained signer. The optional signed policy
is mandatory here; absent policy is disabled, never an environment fallback.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from catchplate import authority_challenge_plan as plan
from catchplate import authority_challenge_policy as policy
from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_webauthn_evidence_configuration as enabled
from catchplate import authority_webauthn_transition_configuration as role_mapping


_OPERATIONS = frozenset({"webauthn.challenge.create", "webauthn.challenge.maintain"})
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")


class ChallengeConfigurationError(ValueError):
    pass


def _require(value):
    if not value:
        raise ChallengeConfigurationError("challenge maintenance configuration is not independently selected")


def _capture(*, operation, payload, configuration_digest, generation, runtime_role_identities, work):
    _require(type(operation) is str and operation in _OPERATIONS)
    owned, launch = configuration._capture_configuration_on_work(payload=payload,
        configuration_digest=configuration_digest, generation=generation, work=work)
    runtime = configuration._capture_runtime_role_identities_on_work(
        runtime_role_identities=runtime_role_identities, owned_payload=owned,
        configuration_digest=configuration_digest, launch=launch, work=work)
    planner = role_mapping._role(owned, "planner")
    enabled._require_enabled_operation(planner, operation, work)
    configuration.capability.plan._same(owned["queryManifestDigest"],
        configuration.capability.plan._QUERY_MANIFEST_DIGEST, work,
        "challenge source query manifest differs from signed configuration")
    _require(policy.FIELD in owned)
    selected = policy.validate_policy(owned[policy.FIELD], work=work)
    encoded, spki, measurement, attestation = role_mapping._key_material(
        planner, runtime["roles"]["planner"], work)
    session = planner["plannerSessionIdentityDigest"]
    configuration.capability.shape._digest(session)
    maximum = planner["maximumInternalAgeNs"]
    _require(type(maximum) is int and 0 < maximum < 2**63)
    # The signed role's limit can narrow the existing source plan lifetime;
    # neither a request nor a mutable environment can enlarge either bound.
    maximum = min(maximum, plan.evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    key = configuration._key(encoded, work, expected_spki=spki)
    return owned, runtime, (operation, key, (session, measurement, attestation), spki,
        configuration_digest, selected, maximum, plan.evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS)


def _producer_from_configuration_on_work(*, operation, payload, configuration_digest,
        generation, runtime_role_identities, read_dsn, planner_private_key, work):
    """Select the genuine native read owner, without opening its connection."""
    _require(isinstance(planner_private_key, Ed25519PrivateKey))
    owned, runtime, pins = _capture(operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    settings = role_mapping._read_settings(owned, runtime, read_dsn)
    plan.evidence.keys._pair_on_work(planner_private_key, pins[1], work)
    from catchplate.authority_challenge_planning import MaintenancePlanner

    return MaintenancePlanner(operation=operation, read_dsn=settings[0],
        connect_timeout_seconds=settings[1], database_identity=settings[2],
        planner_private_key=planner_private_key, planner_public_key=pins[1],
        planner_identity=dict(zip(_IDENTITY_FIELDS, pins[2])), planner_spki_digest=pins[3],
        configuration_digest=pins[4], maintenance_policy=pins[5],
        maximum_plan_age_ns=pins[6], maximum_clock_skew_ns=pins[7])


@dataclass(frozen=True, slots=True, init=False)
class MaintenanceVerifier:
    """Configured public key/policy only; supplied roots still need admission."""

    _pins: tuple

    def __init__(self, *, pins):
        _require(type(pins) is tuple and len(pins) == 8
            and type(pins[0]) is str and pins[0] in _OPERATIONS
            and isinstance(pins[1], Ed25519PublicKey)
            and type(pins[2]) is tuple and len(pins[2]) == len(_IDENTITY_FIELDS))
        shape = plan.evidence.plan.contract
        for value in (*pins[2], pins[3], pins[4]):
            shape._digest(value)
        shape._integer(pins[6], plan.evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
        shape._integer(pins[7], plan.evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
        # Factory-owned policy is detached into immutable exact scalars.
        policy._shape(pins[5])
        object.__setattr__(self, "_pins", (*pins[:5], tuple(sorted(pins[5].items())), *pins[6:]))

    def _expectations(self, *, context, now_epoch_ns, deadline_epoch_ns, work):
        """One exact pin/policy/context join shared by both genuine replay paths."""
        _require(type(self) is MaintenanceVerifier)
        pins = self._pins
        owned = plan.manifests._context(context, work)
        work.prepare_copy(pins[5])
        selected = dict(pins[5])
        fixed = policy.maintenance_context(selected, work=work)
        plan._same({name: owned[name] for name in fixed}, fixed, work)
        plan._same((owned["operation"], owned["configurationDigest"]), (pins[0], pins[4]), work)
        expectations = {"context": owned, "plannerIdentity": dict(zip(_IDENTITY_FIELDS, pins[2])),
            "plannerSpkiDigest": pins[3], "policy": {"nowEpochNs": now_epoch_ns,
                "deadlineEpochNs": deadline_epoch_ns, "maximumPlanAgeNs": pins[6],
                "maximumClockSkewNs": pins[7]}}
        return pins, expectations

    def verify(self, *, envelope_bytes, request_bytes, manifest_bytes, context,
            now_epoch_ns, deadline_epoch_ns, read_original, check, work, apply_mutation=None,
            observe_effect=None):
        pins, expectations = MaintenanceVerifier._expectations(self, context=context, now_epoch_ns=now_epoch_ns,
            deadline_epoch_ns=deadline_epoch_ns, work=work)
        observed = plan.verify_maintenance_parent(envelope_bytes=envelope_bytes,
            request_bytes=request_bytes, manifest_bytes=manifest_bytes, expectations=expectations,
            planner_public_key=pins[1], read_original=read_original, check=check,
            apply_mutation=apply_mutation, observe_effect=observe_effect, work=work)
        _require(self._pins is pins)
        return observed

    def verify_vector(self, *, envelope_bytes, request_bytes, manifest_bytes, context,
            now_epoch_ns, deadline_epoch_ns, before_vector_bytes, read_original, check, work,
            apply_mutation=None, observe_effect=None):
        """Replay actual originals and lift only that computation's complete vector.

        The before vector and parent context still require independent current
        root admission. No supplied replay/result DTO is accepted by this API.
        """
        from catchplate import authority_challenge_current_root as current_root

        pins, expectations = MaintenanceVerifier._expectations(self, context=context, now_epoch_ns=now_epoch_ns,
            deadline_epoch_ns=deadline_epoch_ns, work=work)
        observed = current_root.replay_to_complete_vector(envelope_bytes=envelope_bytes,
            request_bytes=request_bytes, manifest_bytes=manifest_bytes, expectations=expectations,
            planner_public_key=pins[1], before_vector_bytes=before_vector_bytes,
            read_original=read_original, check=check, work=work,
            apply_mutation=apply_mutation, observe_effect=observe_effect)
        _require(self._pins is pins)
        return observed


def _verifier_from_configuration_on_work(*, operation, payload, configuration_digest,
        generation, runtime_role_identities, work):
    _owned, _runtime, pins = _capture(operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    return MaintenanceVerifier(pins=pins)
