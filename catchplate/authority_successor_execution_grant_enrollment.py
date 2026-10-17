"""Produce one fixed root delegation for a separate successor authorizer.

The caller must independently hold the actual root signing authority and admit
the new authorizer identity and policy. This producer derives database,
generation and enrollment identity only by genuinely admitting the original
current-root enrollment. It cannot adopt a caller's successful admission DTO.

Canonical authorizer PEM/SPKI and actual root/computation/completion/state key
separation are checked on the supplied work before signing. Planner and
operation-evidence key separation remains mandatory when an original grant is
verified with those independently admitted keys. This produces no grant,
capability, latest checkpoint, cold owner, key material or execution authority.
There is no I/O, clock, new allowance, key generation or provisioning here.
"""
from __future__ import annotations

from catchplate import authority_current_root_authorization as authorization
from catchplate import authority_successor_execution_grant as grants
from catchplate import authority_successor_execution_grant_signing as signing


class SuccessorExecutionGrantEnrollmentError(ValueError):
    pass


def _produce_on_work(*, current_root_enrollment_bytes, root_private_key,
        root_public_key, authorizer_public_key, authorizer_measurement_digest,
        maximum_grant_age_ns, maximum_clock_skew_ns, work):
    """Sign the exact seven-operation replay delegation from enrollment originals.

    Root/authorizer handles and policy inputs are independently supplied trust,
    not identities inferred from a database row, plan, scope or returned token.
    All incoming original bytes, exact immutable scalars and key references
    are held before the first native key callback.
    """
    original = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    private_key, root_key, authorizer_key = (
        root_private_key, root_public_key, authorizer_public_key)
    measurement, maximum_age, skew = (
        authorizer_measurement_digest, maximum_grant_age_ns, maximum_clock_skew_ns)
    authorization._private(private_key)
    authorization._public(root_key)
    authorization._public(authorizer_key)
    grants.shape._digest(measurement)
    grants.shape._integer(maximum_age, grants.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    grants.shape._integer(skew, grants.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    ledger = grants.capture._SharedLedger(work)

    current = authorization._admit_enrollment_on_work(enrollment_bytes=original,
        root_public_key=root_key, work=work)
    # Retain genuine scope/key observations before any further native exports.
    enrollment_digest, database_id, generation_digest = (
        current.enrollment_digest, current.payload["databaseId"], current.payload["generationDigest"])
    other_keys = (root_key, current.computation_public_key,
        current.completion_public_key, current.state_public_key)
    authorizer_spki = grants.keys._spki_on_work(authorizer_key, work)
    work.charge(input_bytes=authorization.MAX_PEM_BYTES)
    pem_bytes = authorization.production._callback(work, lambda: authorizer_key.public_bytes(
        authorization.Encoding.PEM, authorization.PublicFormat.SubjectPublicKeyInfo))
    if (type(pem_bytes) is not bytes or not 1 <= len(pem_bytes) <= authorization.MAX_PEM_BYTES
            or not pem_bytes.isascii()):
        raise SuccessorExecutionGrantEnrollmentError("authorizer did not export bounded canonical PEM")
    work.charge(input_bytes=len(pem_bytes))
    payload = {
        "schema": grants.ENROLLMENT_PAYLOAD_SCHEMA,
        "sourceRevision": grants.authority.SOURCE_REVISION,
        "currentRootEnrollmentDigest": enrollment_digest,
        "databaseId": database_id,
        "generationDigest": generation_digest,
        "operations": list(grants.OPERATIONS),
        "authorizer": {"publicKeyPem": pem_bytes.decode("ascii"),
            "spkiDigest": authorizer_spki, "measurementDigest": measurement},
        "maximumGrantAgeNs": maximum_age,
        "maximumClockSkewNs": skew,
    }
    grants._enrollment_shape(payload)
    owned = grants._Capture(ledger, maximum_bytes=grants.MAX_ENROLLMENT_BYTES).visit(payload)
    # The real parser rebinds exported PEM to the actual measured DER identity,
    # and rejects alternate encodings; serialization alone is not the join.
    authorization._role_key(owned["authorizer"], work)
    for key in other_keys:
        actual = grants.keys._spki_on_work(key, work)
        work.prepare_comparison(authorizer_spki, actual)
        if authorizer_spki == actual:
            raise SuccessorExecutionGrantEnrollmentError(
                "authorizer must be separate from root, computation, completion and state keys")
    return signing._sign_enrollment_on_work(payload=owned, private_key=private_key,
        public_key=root_key, work=work)
