"""Issue dedicated request permission from actual registration signer originals.

The real authenticated control-plane owner must independently admit this new
execution-request purpose, its signing key and the caller's present permission.
Possession of old evidence-signing originals is not that authorization. This
private producer derives the request itself through genuine raw8/raw2 replay;
it accepts neither a posted request digest nor a successful replay carrier.

It creates no cold owner, network request, journal, reserve or database write.
One existing work allowance and one original clock bracket cover the operation.
The original grant/source/evidence lifetime intersection can only shrink; replay
or signing cannot renew it. Returned signed bytes authorize only the separately
enrolled authorizer's registration-evidence-admission request, not registration
finalization or direct SQL execution.
"""
from __future__ import annotations

import base64
import secrets
import time

from catchplate import authority_registration_execution_authorization as authorization
from catchplate import authority_current_root_authorization as current_root
from catchplate import authority_webauthn_registration_signer_response as response
from catchplate import authority_webauthn_evidence_plan_clock as clock


evidence, configuration = response.evidence, response.configuration
shape, keys = evidence.plan.contract, evidence.keys


class RegistrationExecutionIssuanceError(ValueError):
    pass


def _produce_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, request_originals, response_originals,
        authorization_enrollment_bytes, current_root_enrollment_bytes,
        grant_enrollment_bytes, root_public_key, caller_private_key,
        deadline_epoch_ns, work, transport_deadline_ns=None):
    """Return one original signed authorization, never request/plan permission DTOs."""
    ledger = evidence.capture._SharedLedger(work)
    request_raw = response.wire._request_originals(request_originals)
    response_raw = response.wire._response_originals(response_originals)
    policy_raw, current_raw, grant_raw = (
        authorization_enrollment_bytes, current_root_enrollment_bytes, grant_enrollment_bytes)
    for raw, maximum in ((policy_raw, authorization.MAX_ENROLLMENT_BYTES),
            (current_raw, current_root.MAX_ENROLLMENT_BYTES),
            (grant_raw, authorization.grants.MAX_ENROLLMENT_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise RegistrationExecutionIssuanceError("execution issuer requires bounded enrollment originals")
    if sum(len(raw) for raw in (*request_raw, *response_raw,
            policy_raw, current_raw, grant_raw)) > response.authority.MAX_RESULT_BYTES:
        raise RegistrationExecutionIssuanceError("execution issuer originals exceed the source aggregate")
    digest, root, signer = configuration_digest, root_public_key, caller_private_key
    shape._digest(digest)
    shape._integer(deadline_epoch_ns, minimum=1)
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    deadline, inherited = deadline_epoch_ns, transport_deadline_ns
    if type(payload) is not dict or type(generation) is not dict:
        raise RegistrationExecutionIssuanceError("execution issuer configuration is not exact data")
    configuration.capability.shape._bounded_object(generation, 24, "execution issuer generation")
    # Own every mutable caller graph before any actual clock/key callback. The
    # downstream replay receives these same owned values, never browser scope.
    owned_payload = configuration._ConfigurationCapture(ledger,
        maximum_bytes=response.authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(generation)
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    window = clock._open_on_work(deadline_epoch_ns=deadline,
        maximum_lifetime_ns=response.authority.VERIFIER_RESPONSE_MAX_AGE_NS,
        maximum_clock_skew_ns=response.authority.VERIFIER_MAX_CLOCK_SKEW_NS, work=work)
    bound = window[4] if inherited is None else min(window[4], inherited)
    last_epoch, last_monotonic = window[0], window[2]
    interval = None
    policy_age = policy_skew = None

    def live():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise RegistrationExecutionIssuanceError("execution issuer original clock window expired or reversed")
        if interval is not None:
            evidence._fresh(interval, now, policy_age, policy_skew)
        last_epoch, last_monotonic = now, monotonic
        return now

    live()
    replayed = response._verify_execution_request_on_configuration(
        payload=owned_payload, configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, request_originals=request_raw,
        response_originals=response_raw, work=work)
    last_epoch = max(last_epoch, replayed.last_epoch_ns)
    live()
    # All selected request identities, original intervals and configured key
    # pins are retained before root-delegation or signing callbacks can run.
    request = evidence.capture._JSONCapture(ledger,
        maximum_bytes=response.authority.MAX_REQUEST_BYTES).visit(replayed.request)
    actual_generation = replayed.generation_digest
    planner, operation_key = replayed.planner_public_key, replayed.evidence_public_key
    excluded = replayed.excluded_caller_spkis
    issued, expires = replayed.issued_at_epoch_ns, replayed.expires_at_epoch_ns
    bound = min(bound, replayed.deadline_ns)
    material = authorization._admit_enrollment_on_work(
        authorization_enrollment_bytes=policy_raw, current_root_enrollment_bytes=current_raw,
        grant_enrollment_bytes=grant_raw, root_public_key=root, configuration_digest=digest,
        planner_public_key=planner, evidence_public_key=operation_key, work=work)
    policy = material.payload
    # Root enrollment supplies all database/generation/audience choices. The
    # actual configured generation must agree; none is copied from the request.
    evidence.plan._same(policy["generationDigest"], actual_generation, work,
        "execution caller enrollment differs from the actual signer generation")
    policy_pins = tuple(policy[name] for name in (
        "configurationDigest", "databaseId", "generationDigest", "currentRootEnrollmentDigest",
        "grantEnrollmentDigest", "callerId", "audienceSpkiDigest", "maximumAgeNs", "maximumClockSkewNs"))
    enrollment_digest = material.enrollment_digest
    caller_measurement = policy["callerKey"]["measurementDigest"]
    caller_key = material.caller_public_key
    policy_age, policy_skew = policy_pins[7:]
    expires = min(expires, window[3], issued + policy_age, window[0] + policy_age, deadline)
    window = clock._validate((window[0], window[1], window[2], expires,
        window[1] + expires - window[0], policy_age, policy_skew))
    bound = min(bound, window[4])
    interval = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    live()
    keys._pair_on_work(signer, caller_key, work)
    caller_spki = keys._spki_on_work(caller_key, work)
    work.prepare_scan(excluded)
    for pin in excluded:
        work.prepare_comparison(caller_spki, pin)
        if caller_spki == pin:
            raise RegistrationExecutionIssuanceError("execution caller key reuses an enrollment, evidence or runtime key")
    live()

    evidence.plan._same(request["operation"], authorization.OPERATION, work,
        "execution request is not the fixed registration evidence admission")
    request_digest = response.commitment._typed_request_digest(request, work=work)
    evidence.plan._same(request["requestDigest"], request_digest, work,
        "execution request differs from its actual typed commitment")
    operation_size = work.prepare_utf8(authorization.OPERATION)
    request_size = work.prepare_utf8(request_digest)
    work.charge(hashes=1, input_bytes=len("catchplate.policyAuthorityOperation/v2") + 17
        + operation_size + request_size)
    operation_id = evidence.production._callback(work,
        lambda: response.commitment.operation_id(authorization.OPERATION, request_digest))
    evidence.plan._same(request["operationId"], operation_id, work,
        "execution operation identity differs from the actual request")
    work.charge(input_bytes=32 + 43)
    nonce = evidence.production._callback(work, lambda: secrets.token_bytes(32))
    if type(nonce) is not bytes or len(nonce) != 32 or nonce == bytes(32):
        raise RegistrationExecutionIssuanceError("execution authorization ID generation failed")
    nonce_text = base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("=")
    signed_payload = {
        "schema": authorization.REQUEST_PAYLOAD_SCHEMA,
        "sourceRevision": response.authority.SOURCE_REVISION,
        "purpose": authorization.PURPOSE, "operation": authorization.OPERATION,
        "configurationDigest": policy_pins[0], "databaseId": policy_pins[1],
        "generationDigest": policy_pins[2], "currentRootEnrollmentDigest": policy_pins[3],
        "grantEnrollmentDigest": policy_pins[4], "authorizationEnrollmentDigest": enrollment_digest,
        "callerId": policy_pins[5], "callerMeasurementDigest": caller_measurement,
        "audienceSpkiDigest": policy_pins[6], "requestDigest": request_digest,
        "operationId": operation_id, "authorizationId": nonce_text, **interval,
    }
    live()
    original = authorization._sign_request_on_work(payload=signed_payload,
        private_key=signer, public_key=caller_key, work=work)
    live()
    checked = authorization._verify_on_work(authorization_bytes=original,
        authorization_enrollment_bytes=policy_raw, current_root_enrollment_bytes=current_raw,
        grant_enrollment_bytes=grant_raw, root_public_key=root, configuration_digest=digest,
        planner_public_key=planner, evidence_public_key=operation_key,
        deadline_epoch_ns=expires, transport_deadline_ns=bound, work=work)
    evidence.plan._same((checked.request_digest, checked.operation_id,
        checked.issued_at_epoch_ns, checked.expires_at_epoch_ns),
        (request_digest, operation_id, issued, expires), work,
        "execution authorization changed the genuinely derived request or original interval")
    last_epoch = max(last_epoch, checked.last_epoch_ns)
    last_monotonic = max(last_monotonic, checked.last_monotonic_ns)
    live()
    return original
