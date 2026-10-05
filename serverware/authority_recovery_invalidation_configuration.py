"""Inert invalidation producer selection from admitted configuration originals.

The measured caller supplies the actual signed Service6, launch/cohort, protected
planner-read descriptor and local signer. These consistency joins do not admit
those originals, the request's witness, current roots or execution authority.
Only the explicitly signed recovery retention policy is selected. No ambient
fallback, challenge policy, new clock/work, connection, signing or route exists.
"""
from __future__ import annotations

from serverware import authority_recovery_configuration as recovery
from serverware import authority_recovery_invalidation_plan_owner as owner
from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_evidence_configuration as enabled
from serverware import authority_webauthn_transition_configuration as role_mapping


OPERATION = "webauthn.recovery.invalidate"
evidence, planning = owner.evidence, owner.planning


class RecoveryInvalidationConfigurationError(ValueError):
    pass


def _require(value):
    if not value:
        raise RecoveryInvalidationConfigurationError("invalidation producer configuration differs")


def _producer_from_configuration_on_work(*, payload, configuration_digest, generation,
        runtime_role_identities, read_dsn, planner_private_key, work):
    """Select the genuine inert owner; all invocation windows stay upstream.

    The owner accepts a held window only when its age/skew are no greater than
    these independently configured maxima; it never restores a shorter window.
    Full source/root/witness/native admission is still required by actual use.
    """
    try:
        evidence.capture._SharedLedger(work)
        limits = work.limits
        bounds = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
        previous = work.hash_work, work.input_bytes, work.json_nodes

        def local():
            nonlocal previous
            evidence.capture._SharedLedger(work)
            _require(work.limits is limits
                and (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes) == bounds)
            actual = work.hash_work, work.input_bytes, work.json_nodes
            _require(all(type(value) is int and before <= value <= maximum
                for before, value, maximum in zip(previous, actual, bounds, strict=True)))
            previous = actual

        # Fixed source scalar/tuple construction, apart from the measured
        # complete JSON, policy and descriptor copies on this same ledger.
        work.charge(input_bytes=16384, json_nodes=512)
        owned, launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        runtime = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime_role_identities, owned_payload=owned,
            configuration_digest=configuration_digest, launch=launch, work=work)
        planner = role_mapping._role(owned, "planner")
        verifier = role_mapping._role(owned, "verifier")
        enabled._require_enabled_operation(planner, OPERATION, work)
        configuration.capability.plan._same(owned["queryManifestDigest"],
            configuration.capability.plan._QUERY_MANIFEST_DIGEST, work,
            "invalidation query manifest differs from the source")
        selected = recovery.configuration(owned.get(recovery.FIELD), webauthn=owned["webauthn"])
        _require(selected is not None)
        policy = recovery.retention.capture_policy(selected[recovery.retention.FIELD], work=work)
        settings = role_mapping._read_settings(owned, runtime, read_dsn)
        work.prepare_copy(settings)
        encoded, spki, measurement, attestation = role_mapping._key_material(
            planner, runtime["roles"]["planner"], work)
        identity = {"sessionIdentityDigest": planner["plannerSessionIdentityDigest"],
            "measurementDigest": measurement, "attestationReceiptDigest": attestation}
        evidence._identity(identity)
        configuration.capability.plan._same(settings[2][4:],
            tuple(identity[name] for name in owner._IDENTITY_FIELDS), work,
            "invalidation read identity differs from the admitted planner")
        shape = configuration.capability.shape
        for role in (planner, verifier):
            shape._integer(role["maximumInternalAgeNs"], minimum=1)
        maximum_age = min(planner["maximumInternalAgeNs"], verifier["maximumInternalAgeNs"],
            evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
        skew = evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS
        _require(isinstance(planner_private_key, owner.plan.Ed25519PrivateKey))
        # All graph/scalar selections are detached before the first key/native
        # callback. Caller mutation can no longer choose policy, role or pins.
        reader = planning.RecoveryInvalidationReadPlanner(read_dsn=settings[0],
            connect_timeout_seconds=settings[1], database_identity=settings[2],
            terminal_retention_seconds=policy["terminalRetentionSeconds"],
            maximum_retained=policy["maximumRetained"])
        local()
        public = configuration._key(encoded, work, expected_spki=spki)
        local()
        evidence.keys._pair_on_work(planner_private_key, public, work)
        local()
        result = owner.RecoveryInvalidationPlanOwner(read_planner=reader,
            planner_private_key=planner_private_key, planner_public_key=public,
            expected_planner_identity=identity, expected_planner_spki_digest=spki,
            configuration_digest=configuration_digest, maximum_plan_age_ns=maximum_age,
            maximum_clock_skew_ns=skew)
        local()
        return result
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RecoveryInvalidationConfigurationError):
            raise
        raise RecoveryInvalidationConfigurationError("invalidation configuration capture failed") from exc
