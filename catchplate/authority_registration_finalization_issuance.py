"""Issue finalization authority from genuine signer originals BEFORE planning.

The caller must already authenticate the present actor and finalization purpose
and independently admit the caller key/configuration/root enrollment. Actual
raw8/raw2 replay derives the exact finalization request plus bounded sibling
hints; no posted request identity or successful replay object is accepted.

The signature issue is an actual current sample, never the old evidence/source
issue time. Original expiry and the caller's supplied live window/work cannot
be renewed. This module signs no plan, contacts no service, reserves no roots
and performs no SQL, custody write, retry or credential/session finalization.
"""
from __future__ import annotations

import base64
import secrets
import time

from catchplate import authority_registration_finalization_authorization as authorization
from catchplate import authority_webauthn_registration_signer_response as response


evidence, configuration, clock = response.evidence, response.configuration, authorization.clock
shape, keys = evidence.plan.contract, evidence.keys


class RegistrationFinalizationIssuanceError(ValueError):
    pass


def _produce_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, request_originals, response_originals, sibling_challenge_ids,
        authorization_enrollment_bytes, current_root_enrollment_bytes, grant_enrollment_bytes,
        root_public_key, caller_private_key, live_window, work, transport_deadline_ns=None):
    """Return only original signed authorization for a later matching live plan."""
    ledger = evidence.capture._SharedLedger(work)
    request_raw = response.wire._request_originals(request_originals)
    response_raw = response.wire._response_originals(response_originals)
    policy_raw, current_raw, grant_raw = (
        authorization_enrollment_bytes, current_root_enrollment_bytes, grant_enrollment_bytes)
    for raw, maximum in ((policy_raw, authorization.MAX_ENROLLMENT_BYTES),
            (current_raw, authorization.authorization.MAX_ENROLLMENT_BYTES),
            (grant_raw, authorization.grants.MAX_ENROLLMENT_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise RegistrationFinalizationIssuanceError("finalization issuer requires bounded enrollment originals")
    if sum(len(raw) for raw in (*request_raw, *response_raw,
            policy_raw, current_raw, grant_raw)) > response.authority.MAX_RESULT_BYTES:
        raise RegistrationFinalizationIssuanceError("finalization issuer originals exceed their aggregate bound")
    if (type(sibling_challenge_ids) is not list
            or len(sibling_challenge_ids) > response.production.registration.MAX_SIBLINGS
            or any(type(value) is not str or not 1 <= len(value) <= 4096
                for value in sibling_challenge_ids)):
        raise RegistrationFinalizationIssuanceError("finalization sibling hints exceed their source bound")
    siblings = evidence.capture._JSONCapture(ledger,
        maximum_bytes=response.authority.MAX_REQUEST_BYTES).visit(sibling_challenge_ids)
    digest, root, signer = configuration_digest, root_public_key, caller_private_key
    shape._digest(digest)
    authorization.authorization._public(root)
    authorization.authorization._private(signer)
    window = clock._validate(live_window)
    inherited = transport_deadline_ns
    if inherited is not None:
        shape._integer(inherited, minimum=1)
    bound = window[4] if inherited is None else min(window[4], inherited)
    if type(payload) is not dict or type(generation) is not dict:
        raise RegistrationFinalizationIssuanceError("finalization issuer configuration is not exact data")
    configuration.capability.shape._bounded_object(generation, 24, "finalization issuer generation")
    owned_payload = configuration._ConfigurationCapture(ledger,
        maximum_bytes=response.authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(generation)
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    last_epoch, last_monotonic = window[0], window[2]
    original_interval = interval = None
    policy_age = policy_skew = None

    def live():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise RegistrationFinalizationIssuanceError("finalization issuer original clocks expired or reversed")
        if original_interval is not None and not original_interval[0] <= now < original_interval[1]:
            raise RegistrationFinalizationIssuanceError("finalization signer originals are outside their original interval")
        if interval is not None:
            evidence._fresh(interval, now, policy_age, policy_skew)
        last_epoch, last_monotonic = now, monotonic
        return now

    live()
    replayed = response._verify_finalization_execution_request_on_configuration(
        payload=owned_payload, configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, request_originals=request_raw,
        response_originals=response_raw, sibling_challenge_ids=siblings, work=work)
    if replayed.last_epoch_ns < last_epoch:
        raise RegistrationFinalizationIssuanceError("finalization replay reversed the caller clock")
    last_epoch = replayed.last_epoch_ns
    original_interval = replayed.issued_at_epoch_ns, replayed.expires_at_epoch_ns
    bound = min(bound, replayed.deadline_ns)
    request = evidence.capture._JSONCapture(ledger,
        maximum_bytes=response.authority.MAX_REQUEST_BYTES).visit(replayed.request)
    actual_generation = replayed.generation_digest
    planner, operation_key = replayed.planner_public_key, replayed.evidence_public_key
    excluded = replayed.excluded_caller_spkis
    live()
    material = authorization._admit_enrollment_on_work(
        authorization_enrollment_bytes=policy_raw, current_root_enrollment_bytes=current_raw,
        grant_enrollment_bytes=grant_raw, root_public_key=root, configuration_digest=digest,
        planner_public_key=planner, evidence_public_key=operation_key, work=work)
    policy = material.payload
    evidence.plan._same(policy["generationDigest"], actual_generation, work,
        "finalization caller enrollment differs from actual configured generation")
    policy_pins = tuple(policy[name] for name in ("configurationDigest", "databaseId", "generationDigest",
        "currentRootEnrollmentDigest", "grantEnrollmentDigest", "callerId", "audienceSpkiDigest",
        "maximumAgeNs", "maximumClockSkewNs"))
    enrollment_digest, caller_key = material.enrollment_digest, material.caller_public_key
    caller_measurement = policy["callerKey"]["measurementDigest"]
    policy_age, policy_skew = policy_pins[7:]
    keys._pair_on_work(signer, caller_key, work)
    caller_spki = keys._spki_on_work(caller_key, work)
    work.prepare_scan(excluded)
    for pin in excluded:
        work.prepare_comparison(caller_spki, pin)
        if caller_spki == pin:
            raise RegistrationFinalizationIssuanceError("finalization caller key reuses an enrollment or runtime key")
    live()
    evidence.plan._same(request["operation"], authorization.OPERATION, work,
        "finalization request is not the fixed operation")
    request_digest = response.commitment._typed_request_digest(request, work=work)
    evidence.plan._same(request["requestDigest"], request_digest, work,
        "finalization request differs from its actual typed commitment")
    operation_size, request_size = work.prepare_utf8(authorization.OPERATION), work.prepare_utf8(request_digest)
    work.charge(hashes=1, input_bytes=len("catchplate.policyAuthorityOperation/v2") + 17
        + operation_size + request_size)
    operation_id = evidence.production._callback(work,
        lambda: response.commitment.operation_id(authorization.OPERATION, request_digest))
    evidence.plan._same(request["operationId"], operation_id, work,
        "finalization operation identity differs from the actual request")
    work.charge(input_bytes=32 + 43)
    nonce = evidence.production._callback(work, lambda: secrets.token_bytes(32))
    if type(nonce) is not bytes or len(nonce) != 32 or nonce == bytes(32):
        raise RegistrationFinalizationIssuanceError("finalization authorization ID generation failed")
    nonce_text = base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("=")
    # Unlike historical evidence admission, this authorization starts NOW,
    # before a future plan. Its old source/evidence deadline cannot be renewed.
    issued = live()
    expires = min(original_interval[1], window[3], issued + policy_age)
    if expires <= issued:
        raise RegistrationFinalizationIssuanceError("finalization authorization has no remaining original lifetime")
    interval = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    bound = min(bound, window[1] + expires - window[0])
    signed_payload = {"schema": authorization.REQUEST_PAYLOAD_SCHEMA,
        "sourceRevision": response.authority.SOURCE_REVISION,
        "purpose": authorization.PURPOSE, "operation": authorization.OPERATION,
        "configurationDigest": policy_pins[0], "databaseId": policy_pins[1], "generationDigest": policy_pins[2],
        "currentRootEnrollmentDigest": policy_pins[3], "grantEnrollmentDigest": policy_pins[4],
        "callerId": policy_pins[5], "audienceSpkiDigest": policy_pins[6],
        "authorizationEnrollmentDigest": enrollment_digest, "callerMeasurementDigest": caller_measurement,
        "requestDigest": request_digest, "operationId": operation_id, "authorizationId": nonce_text, **interval}
    live()
    original = authorization._sign_request_on_work(payload=signed_payload,
        private_key=signer, public_key=caller_key, work=work)
    live()
    checked = authorization._verify_on_work(authorization_bytes=original,
        authorization_enrollment_bytes=policy_raw, current_root_enrollment_bytes=current_raw,
        grant_enrollment_bytes=grant_raw, root_public_key=root, configuration_digest=digest,
        planner_public_key=planner, evidence_public_key=operation_key,
        live_window=window, work=work, transport_deadline_ns=bound)
    evidence.plan._same((checked.request_digest, checked.operation_id,
        checked.issued_at_epoch_ns, checked.expires_at_epoch_ns),
        (request_digest, operation_id, issued, expires), work,
        "finalization authorization changed actual request or current issue time")
    if checked.last_epoch_ns < last_epoch or checked.last_monotonic_ns < last_monotonic:
        raise RegistrationFinalizationIssuanceError("finalization verification reversed the caller clocks")
    last_epoch, last_monotonic = checked.last_epoch_ns, checked.last_monotonic_ns
    live()
    return original
