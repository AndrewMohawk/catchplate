"""Fixed maintenance factories on the real measured service role boundary.

These private methods do not dispatch requests or admit a current root. They
join the actual root-verified configuration, active generation, original role
descriptor and planner signer before constructing their specific source owner.
No incoming parent chooses keys, DSNs, policy, callbacks or role credentials.
"""
from __future__ import annotations

from serverware import authority_challenge_configuration as mapping
from serverware import authority_webauthn_transition_service as measured


def _producer_on_work(process, *, operation, work):
    mapping._require(type(operation) is str and operation in mapping._OPERATIONS)
    owned, digest, generation, dsn, private, runtime = measured._measured_context_on_work(
        process, role="planner", signing=True,
        read_descriptor="SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN", work=work)
    return mapping._producer_from_configuration_on_work(operation=operation,
        payload=owned, configuration_digest=digest, generation=generation,
        runtime_role_identities=runtime, read_dsn=dsn, planner_private_key=private, work=work)


def _verifier_on_work(process, *, operation, work):
    mapping._require(type(operation) is str and operation in mapping._OPERATIONS)
    owned, digest, generation, _dsn, _private, runtime = measured._measured_context_on_work(
        process, role="verifier", signing=False, read_descriptor=None, work=work)
    return mapping._verifier_from_configuration_on_work(operation=operation,
        payload=owned, configuration_digest=digest, generation=generation,
        runtime_role_identities=runtime, work=work)
