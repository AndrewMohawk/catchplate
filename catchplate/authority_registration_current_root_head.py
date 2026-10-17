"""Two fixed registration nonce-head reads, never reservation authority.

The actual root provisioner retains the fresh nonce and original processing
window. Its V9 peer route can request only these independently domain-separated
observations from the enrolled, locked state owner. A signed response must still
match the independently held enrollment, context and complete-vector digest;
pending rejection and lifetime continuity remain the provisioner's duties.
No request-supplied operation, key, successful carrier or mutable state is used.
"""
from catchplate import authority_current_root_head as shared


MAX_QUERY_BYTES, MAX_BYTES = shared.MAX_QUERY_BYTES, shared.MAX_BYTES


def _operation(purpose):
    if type(purpose) is str and purpose == "execution":
        return shared.REGISTRATION_EXECUTION_OPERATION
    if type(purpose) is str and purpose == "finalization":
        return shared.REGISTRATION_FINALIZATION_OPERATION
    raise shared.CurrentRootHeadError("registration head purpose is not source fixed")


def _encode_query_on_work(*, enrollment_digest, context_digest, expected_vector_digest,
        challenge, work, purpose):
    return shared._encode_query_on_work(enrollment_digest=enrollment_digest,
        context_digest=context_digest, expected_vector_digest=expected_vector_digest,
        challenge=challenge, work=work, operation=_operation(purpose))


def _verify_on_work(*, observation_bytes, query_bytes, enrollment_bytes,
        root_public_key, now_epoch_ns, work, purpose):
    return shared._verify_on_work(observation_bytes=observation_bytes, query_bytes=query_bytes,
        enrollment_bytes=enrollment_bytes, root_public_key=root_public_key,
        now_epoch_ns=now_epoch_ns, work=work, operation=_operation(purpose))
