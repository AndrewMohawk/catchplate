"""Map admitted configuration to fixed successor-plan PostgreSQL custody.

The service owns root verification, active launch admission and the protected
planner-writer descriptor. One actual full capture binds their consistency.
The existing purpose-neutral database continuation holds writer connection
settings and joins exact planner aliases before the transition policy's native
key callbacks. It does not invoke evidence-admission policy or substitute a
generic role key for the operation's explicit transition policy.

The resulting owner is inert. Each fixed persist/read call still requires
independently admitted historical expectations; current configuration and
stored context do not manufacture that authority. No descriptor read, clock,
private signer, SQL, permission extension or replacement allowance exists here.
"""
from __future__ import annotations

from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_evidence_plan_writer_configuration as database_configuration
from serverware import authority_webauthn_transition_configuration as pins_configuration
from serverware import authority_webauthn_transition_persistence as persistence


class WebAuthnTransitionWriterConfigurationError(ValueError):
    pass


def _persistence_from_configuration_on_work(*, operation, payload, configuration_digest,
        generation, runtime_role_identities, writer_dsn, work):
    try:
        pins_configuration._operation(operation)
        owned, _launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        runtime = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime_role_identities, owned_payload=owned,
            configuration_digest=configuration_digest, launch=_launch, work=work)
        # This actual shared helper reads no purpose-policy slot and performs
        # no key callback. Its database3 is immutable before the next phase.
        dsn, timeout, database = database_configuration._database_from_owned_configuration_on_work(
            owned_payload=owned, writer_dsn=writer_dsn, work=work)
        pins = pins_configuration._pins_from_owned_configuration_on_work(operation=operation,
            owned_payload=owned, owned_runtime_identities=runtime,
            configuration_digest=configuration_digest, work=work)
        return persistence.TransitionPlanPersistence(writer_dsn=dsn,
            connect_timeout_seconds=timeout, database_identity=database, pins=pins)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnTransitionWriterConfigurationError):
            raise
        raise WebAuthnTransitionWriterConfigurationError("transition custody configuration failed") from exc
