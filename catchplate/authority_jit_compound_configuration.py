"""Inert JIT producer selection from admitted configuration originals.

The measured caller supplies actual Service6/cohort/launch originals, its
protected planner-read descriptor and the real page caller. This factory
repeats their consistency joins; it does not admit any of that provenance.
Only the page caller's retained planner key is available, and only its exact
original window can be used. No writer descriptor, policy override, clock
window, allowance, connection, signing, replay or operation route is created.
"""
from __future__ import annotations

from catchplate import authority_jit_compound_planning as planning
from catchplate import authority_jit_original_configuration as page_configuration
from catchplate import authority_jit_original_service as page_service
from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_webauthn_evidence_configuration as enabled
from catchplate import authority_webauthn_transition_configuration as role_mapping


OPERATION = "jit.assertion.issue"
_CALLER_FIELDS = ("_configured", "_check_owner", "_window", "_held", "_identity")
evidence, clock = page_service.evidence, page_service.clock


class JitCompoundConfigurationError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitCompoundConfigurationError("JIT producer differs from its original configured page owner")


def _same(left, right, work):
    configuration.capability.plan._same(left, right, work,
        "JIT producer selection differs from its original configuration")


def _caller_guard(page_caller, work):
    """Pin the exact original caller and allowance before native callbacks."""
    evidence.capture._SharedLedger(work)
    _require(type(page_caller) is page_service._PageCaller)
    held = tuple(getattr(page_caller, name) for name in _CALLER_FIELDS)
    selected = held[0]
    original = page_configuration._snapshot(selected)
    _require(selected.local_role == "planner")
    window = clock._validate(held[2])
    limits = work.limits
    bounds = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
    previous = work.hash_work, work.input_bytes, work.json_nodes

    def local():
        nonlocal previous
        evidence.capture._SharedLedger(work)
        _require(all(getattr(page_caller, name) is value
            for name, value in zip(_CALLER_FIELDS, held, strict=True))
            and page_configuration._snapshot(selected) is original
            and work.limits is limits
            and (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes) == bounds)
        actual = work.hash_work, work.input_bytes, work.json_nodes
        _require(all(type(value) is int and before <= value <= maximum
            for before, value, maximum in zip(previous, actual, bounds, strict=True)))
        previous = actual

    def check():
        local()
        _require(evidence.production._callback(work,
            lambda: page_service._PageCaller._live(page_caller, work)) is None)
        local()

    # No check callback runs here: full caller-supplied JSON/scalars are owned
    # and joined below before the first external owner/clock/key invocation.
    local()
    return selected, window, check


def _selection(*, payload, configuration_digest, generation, runtime_role_identities,
        read_dsn, page_caller, work):
    # Bound the source-owned scalar/tuple/construction scaffolding separately
    # from actual whole configuration, DSN and policy copies on this same work.
    work.charge(input_bytes=16384, json_nodes=256)
    selected, window, check = _caller_guard(page_caller, work)
    owned, launch = configuration._capture_configuration_on_work(payload=payload,
        configuration_digest=configuration_digest, generation=generation, work=work)
    runtime = configuration._capture_runtime_role_identities_on_work(
        runtime_role_identities=runtime_role_identities, owned_payload=owned,
        configuration_digest=configuration_digest, launch=launch, work=work)
    planner = role_mapping._role(owned, "planner")
    enabled._require_enabled_operation(planner, OPERATION, work)
    _same(owned["queryManifestDigest"], configuration.capability.plan._QUERY_MANIFEST_DIGEST, work)
    settings = role_mapping._read_settings(owned, runtime, read_dsn)
    encoded, spki, measurement, attestation = role_mapping._key_material(
        planner, runtime["roles"]["planner"], work)
    identity = (planner["plannerSessionIdentityDigest"], measurement, attestation)
    shape = configuration.capability.shape
    for value in identity:
        shape._digest(value)
    _same(settings[2][4:], identity, work)
    webauthn = owned["webauthn"]
    _require(type(webauthn) is dict)
    age_ns = webauthn["maximumChallengeAgeNs"]
    _require(type(age_ns) is int and age_ns > 0)
    assertion_policy = {"rp_id": webauthn["rpId"], "origin": webauthn["origin"],
        "maximum_assertion_age_seconds": min(30, age_ns // 1_000_000_000)}
    # The unchanged actual JIT source requires at least one complete second;
    # a signed sub-second policy refuses instead of acquiring a new default.
    planning.acquisition._policy(assertion_policy)
    maximum_ages = []
    for role in (planner, role_mapping._role(owned, "verifier"),
            role_mapping._role(owned, "planner-writer")):
        age = role["maximumInternalAgeNs"]
        shape._integer(age, minimum=1)
        maximum_ages.append(age)
    maximum = min(evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS, *maximum_ages)
    skew = evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS
    _same((selected.planner_identity, selected.planner_spki_digest,
            selected.configuration_digest, selected.generation_sequence, selected.generation_digest,
            selected.maximum_age_ns, selected.maximum_clock_skew_ns),
        (identity, spki, configuration_digest, launch["sequence"], launch["digest"], maximum, skew), work)
    _require(window[5] <= maximum and window[6] <= skew)
    work.prepare_copy((settings, assertion_policy))
    # Every field above is now detached. Native owner/key callbacks cannot
    # select a new DSN, role, policy, generation, signer or opening window.
    check()
    public = configuration._key(encoded, work, expected_spki=spki)
    check()
    evidence.keys._public_binding(selected.planner_public_key, spki, work)
    check()
    evidence.keys._pair_on_work(selected.private_key, public, work)
    check()
    return settings, assertion_policy, check


def _producer_from_configuration_on_work(*, payload, configuration_digest, generation,
        runtime_role_identities, read_dsn, page_caller, work):
    """Construct real inert owners only; no measured admission is fabricated.

    The producer must use the held window's original age/skew for parent
    expectations, never widen them back to the configured maxima. Its native
    pass and durable raw-page custody remain separate real operations.
    """
    try:
        evidence.capture._SharedLedger(work)
        settings, policy, check = _selection(payload=payload,
            configuration_digest=configuration_digest, generation=generation,
            runtime_role_identities=runtime_role_identities, read_dsn=read_dsn,
            page_caller=page_caller, work=work)
        reader = planning.JitCompoundReadPlanner(read_dsn=settings[0],
            connect_timeout_seconds=settings[1], database_identity=settings[2], assertion_policy=policy)
        check()
        # This is the actual configured producer, not a fallback observation or
        # successful custody DTO. Its source implementation is required.
        from catchplate.authority_jit_compound_production import _JitCompoundProducer

        result = _JitCompoundProducer(read_planner=reader, page_caller=page_caller)
        check()
        return result
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, JitCompoundConfigurationError):
            raise
        raise JitCompoundConfigurationError("JIT producer configuration capture failed") from exc
