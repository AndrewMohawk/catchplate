"""Private configured verification of original observed-planner handoff bytes.

Measured configuration and an active launch are upstream admission requirements,
not properties conferred by this mapper or its ordinary frozen return object.
The mapper owns the complete bounded configuration and launch bindings, checks
their independent commitment, and derives only the two public keys, identities
and historical policy used by the real handoff verifier. It neither reuses the
issuer factory nor accesses a DSN, samples clocks, signs or registers a route.

Caller request, nine-field historical context and full independent inventory
are copied before any invocation key callback. The existing handoff then owns
its boundary again and genuinely verifies the original bytes on the same work.
Configuration/key handles are snapshotted once, not accepted as a proof token.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_contract as authority
from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_handoff as handoff


_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_CONFIGURED_CONTEXT_FIELDS = frozenset({"expectedPlannerIdentity", "expectedVerifierIdentity",
    "maximumAssertionAgeNs", "maximumPlanAgeNs", "maximumClockSkewNs"})
_CALL_CONTEXT_FIELDS = handoff.retention.production._CONTEXT_FIELDS - _CONFIGURED_CONTEXT_FIELDS - {"expectedBefore"}


class RevocationVerifierError(ValueError):
    pass


def _validate_configuration(values):
    if type(values) is not tuple or len(values) != 10:
        raise RevocationVerifierError("revocation verifier configuration is not an exact ten-tuple")
    if any(not isinstance(key, Ed25519PublicKey) for key in values[:2]):
        raise RevocationVerifierError("revocation verifier requires Ed25519 public keys")
    for identity in values[2:4]:
        if type(identity) is not tuple or len(identity) != 3:
            raise RevocationVerifierError("revocation verifier identity is not an exact triple")
        for digest in identity:
            handoff.plan.contract._digest(digest)
    for index in (4, 5, 8):
        handoff.plan.contract._integer(values[index], minimum=1)
    handoff.plan.contract._integer(values[6])
    for index in (7, 9):
        handoff.plan.contract._digest(values[index])
    if (values[5] > authority.VERIFIER_RESPONSE_MAX_AGE_NS
            or values[6] != authority.VERIFIER_MAX_CLOCK_SKEW_NS):
        raise RevocationVerifierError("revocation verifier policy exceeds or differs from its source pins")


def _capture_handoff_inputs(*, envelope_bytes, evaluation_context_bytes, expected_request,
                            context, root_inventory, work):
    """Own only raw invocation data; no key, clock, launch or driver callback.

    The actual service uses this same helper before its launch/configuration
    callbacks. The configured owner deliberately repeats this boundary rather
    than admitting a reusable owned-input token. Immutable bytes need no copy.
    """
    handoff.plan.capture._SharedLedger(work)
    if (type(envelope_bytes) is not bytes
            or not 2 <= len(envelope_bytes) <= handoff.plan.contract.MAX_PAYLOAD_BYTES
            or type(evaluation_context_bytes) is not bytes
            or not 2 <= len(evaluation_context_bytes) <= handoff.retention.MAX_CONTEXT_BYTES
            or type(expected_request) is not dict):
        raise RevocationVerifierError("revocation verifier requires bounded original bytes and an exact request")
    handoff.plan.contract._object(context, _CALL_CONTEXT_FIELDS, "configured verifier context")
    owned = handoff.observed.reads._CopyBudget(work).copy(
        {"expectedRequest": expected_request, "context": context})
    inventory = handoff.observed._capture_root_inventory(root_inventory, work=work)
    request, context = owned["expectedRequest"], owned["context"]
    handoff.plan.contract._request(request)
    for name in ("expectedCapabilityId", "expectedPlannerTransactionId"):
        handoff.plan.contract._digest(context[name])
    if context["expectedApproverPolicyDigest"] is not None:
        handoff.plan.contract._digest(context["expectedApproverPolicyDigest"])
    for name in ("expectedFence", "reservedAtEpochNs", "deadlineEpochNs", "deadlineMonotonicNs",
                 "nowEpochNs", "nowMonotonicNs"):
        handoff.plan.contract._integer(context[name], minimum=1)
    return request, context, inventory


@dataclass(frozen=True, slots=True, init=False)
class RevocationPlanVerifier:
    """Constructor-owned settings, not admission or a successful plan token."""

    _configuration: tuple

    def __init__(self, *, planner_public_key, verifier_public_key,
                 expected_planner_identity, expected_verifier_identity,
                 maximum_assertion_age_ns, maximum_plan_age_ns, maximum_clock_skew_ns,
                 expected_configuration_digest, expected_generation_sequence, expected_generation_digest):
        handoff.plan.contract.validate_identity_shape(expected_planner_identity)
        handoff.plan.contract.validate_identity_shape(expected_verifier_identity)
        values = (planner_public_key, verifier_public_key,
            tuple(expected_planner_identity[name] for name in _IDENTITY_FIELDS),
            tuple(expected_verifier_identity[name] for name in _IDENTITY_FIELDS),
            maximum_assertion_age_ns, maximum_plan_age_ns, maximum_clock_skew_ns,
            expected_configuration_digest, expected_generation_sequence, expected_generation_digest)
        _validate_configuration(values)
        object.__setattr__(self, "_configuration", values)

    def _snapshot_configuration(self):
        if type(self) is not RevocationPlanVerifier:
            raise RevocationVerifierError("revocation verifier requires its exact configured owner")
        values = self._configuration
        _validate_configuration(values)
        return values

    def verify_handoff(self, *, envelope_bytes, evaluation_context_bytes, expected_request,
                       context, root_inventory, work):
        values = self._snapshot_configuration()
        request, owned, inventory = _capture_handoff_inputs(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, expected_request=expected_request,
            context=context, root_inventory=root_inventory, work=work)
        actual_context = {**owned,
            "expectedPlannerIdentity": dict(zip(_IDENTITY_FIELDS, values[2])),
            "expectedVerifierIdentity": dict(zip(_IDENTITY_FIELDS, values[3])),
            "maximumAssertionAgeNs": values[4], "maximumPlanAgeNs": values[5],
            "maximumClockSkewNs": values[6]}
        handoff.observed._validate_partial_context(actual_context, work)
        return handoff._verify_observed_plan_handoff_on_work(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, expected_request=request,
            context=actual_context, root_inventory=inventory,
            planner_public_key=values[0], verifier_public_key=values[1], work=work)


def _verifier_from_configuration_on_work(*, payload, configuration_digest, generation,
        runtime_role_identities, work):
    """Map root-admitted configuration without granting it admission here.

    Assertion age remains exactly the measured WebAuthn challenge policy,
    which may legitimately exceed thirty seconds. Plan age is the stricter of
    measured verifier internal age and the unchanged source thirty-second
    response policy; skew is the unchanged source five-second allowance.
    Native crypto internals are excluded from H/B/N. Actual capture, encodings,
    comparisons, SPKI hashes and identity framing use the supplied work.
    """
    try:
        owned, launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        runtime = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime_role_identities, owned_payload=owned,
            configuration_digest=configuration_digest, launch=launch, work=work)
        roles = owned["roles"]
        if type(roles) is not dict:
            raise RevocationVerifierError("revocation verifier roles are not an exact object")
        planner, verifier = roles["planner"], roles["verifier"]
        for name, role in (("planner", planner), ("verifier", verifier)):
            if type(role) is not dict:
                raise RevocationVerifierError("revocation verifier role is not an exact object")
            handoff.plan.contract._literal(role["processMode"], "policy-authority-" + name)
            for field in ("measurementDigest", "signingSpkiDigest"):
                handoff.plan.contract._digest(role[field])
            handoff.plan._same(role["responseSigningSpkiDigest"], role["signingSpkiDigest"], work,
                "revocation verifier key differs from its measured response pin")
        handoff.plan.contract._digest(planner["plannerSessionIdentityDigest"])
        handoff.plan._same(owned["queryManifestDigest"], handoff.plan._QUERY_MANIFEST_DIGEST, work,
            "revocation verifier configuration differs from the source query manifest")
        webauthn = owned["webauthn"]
        if type(webauthn) is not dict:
            raise RevocationVerifierError("revocation verifier WebAuthn policy is not an exact object")
        assertion_age = webauthn["maximumChallengeAgeNs"]
        handoff.plan.contract._integer(assertion_age, minimum=1)
        handoff.plan.contract._integer(verifier["maximumInternalAgeNs"], minimum=1)
        plan_age = min(verifier["maximumInternalAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS)
        skew = authority.VERIFIER_MAX_CLOCK_SKEW_NS
        handoff.plan.contract._integer(plan_age, minimum=1)
        handoff.plan.contract._integer(skew)

        planner_identity = {"sessionIdentityDigest": planner["plannerSessionIdentityDigest"],
            "measurementDigest": planner["measurementDigest"],
            "attestationReceiptDigest": runtime["roles"]["planner"]["attestationReceiptDigest"]}
        verifier_measurement = verifier["measurementDigest"]
        verifier_receipt = runtime["roles"]["verifier"]["attestationReceiptDigest"]
        planner_encoded, planner_spki = planner["signingPublicKeyBase64Url"], planner["signingSpkiDigest"]
        verifier_encoded, verifier_spki = verifier["signingPublicKeyBase64Url"], verifier["signingSpkiDigest"]
        generation_sequence, generation_digest = launch["sequence"], launch["digest"]
        # All graph inputs and scalar policy are owned before these real key
        # callbacks. Raw32, DER44 and their actual hash/comparison work are
        # charged by the existing guarded configuration helper.
        planner_key = configuration._key(planner_encoded, work, expected_spki=planner_spki)
        verifier_key = configuration._key(verifier_encoded, work, expected_spki=verifier_spki)
        verifier_session = configuration._frame_text(configuration._VERIFIER_SESSION,
            (configuration_digest, verifier_measurement, verifier_receipt), work)
        return RevocationPlanVerifier(planner_public_key=planner_key, verifier_public_key=verifier_key,
            expected_planner_identity=planner_identity,
            expected_verifier_identity={"sessionIdentityDigest": verifier_session,
                "measurementDigest": verifier_measurement, "attestationReceiptDigest": verifier_receipt},
            maximum_assertion_age_ns=assertion_age, maximum_plan_age_ns=plan_age, maximum_clock_skew_ns=skew,
            expected_configuration_digest=configuration_digest,
            expected_generation_sequence=generation_sequence, expected_generation_digest=generation_digest)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RevocationVerifierError):
            raise
        raise RevocationVerifierError("revocation verifier configuration failed") from exc
