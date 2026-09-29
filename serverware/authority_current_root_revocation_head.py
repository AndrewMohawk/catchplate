"""Fixed public revocation head purpose; never an activation observation alias.

Only canonical, clock-independent shape and enrolled signature machinery is
shared. The schema, signature domain, query digest and operation all differ.
Historical admission authenticates this fixed original purpose only; it is not
a fresh observation, generic operation, execution or release authority.
"""
from serverware import authority_current_root_head as shared

authorization = shared.authorization
OPERATION = shared.REVOCATION_OPERATION
QUERY_SCHEMA, QUERY_IDENTITY_DOMAIN, OBSERVATION_SCHEMA, PAYLOAD_SCHEMA = shared._profile(OPERATION)
MAX_QUERY_BYTES, MAX_BYTES = shared.MAX_QUERY_BYTES, shared.MAX_BYTES
MAX_QUERY_NODES, MAX_NODES = shared.MAX_QUERY_NODES, shared.MAX_NODES


def _encode_query_on_work(*, enrollment_digest, context_digest, expected_vector_digest, challenge, work):
    return shared._encode_query_on_work(enrollment_digest=enrollment_digest,
        context_digest=context_digest, expected_vector_digest=expected_vector_digest,
        challenge=challenge, work=work, operation=OPERATION)


def _decode_query_on_work(raw, *, work):
    return shared._decode_query_on_work(raw, work=work, operation=OPERATION)


def _query_digest_on_work(raw, work):
    return shared._query_digest_on_work(raw, work, operation=OPERATION)


def _verify_on_work(*, observation_bytes, query_bytes, enrollment_bytes,
        root_public_key, now_epoch_ns, work):
    return shared._verify_on_work(observation_bytes=observation_bytes, query_bytes=query_bytes,
        enrollment_bytes=enrollment_bytes, root_public_key=root_public_key,
        now_epoch_ns=now_epoch_ns, work=work, operation=OPERATION)


def _sign_on_work(*, payload, enrollment_bytes, root_public_key,
        state_private_key, now_epoch_ns, work):
    return shared._sign_on_work(payload=payload, enrollment_bytes=enrollment_bytes,
        root_public_key=root_public_key, state_private_key=state_private_key,
        now_epoch_ns=now_epoch_ns, work=work, operation=OPERATION)


def _verify_historical_with_enrollment_on_work(*, observation_bytes, query_bytes,
        enrollment_bytes, root_public_key, live_window, transport_deadline_ns, work):
    return shared._historical_originals_on_work(observation_bytes=observation_bytes,
        query_bytes=query_bytes, enrollment_bytes=enrollment_bytes, root_public_key=root_public_key,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        work=work, operation=OPERATION)
