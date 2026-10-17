"""Map admitted verifier configuration into the actual successor root reader.

One real full configuration/generation capture precedes all policy and key
callbacks. The verifier database identity, descriptor, timeout and source query
manifest are held independently of the returned purpose pins. The genuine
transition mapper enforces the fixed operation, measured roles, planner
allowlist and explicit signed policy without a second configuration capture.

The service remains responsible for root/launch/descriptor provenance. This
mapper opens no database, enrolls no root observations, changes no privilege
and creates no allowance, clock, signer, fallback policy or proof authority.
"""
from __future__ import annotations

import math

from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_revocation_plan as plan
from catchplate import authority_revocation_root_reader as reader
from catchplate import authority_webauthn_transition_configuration as pins_configuration


class WebAuthnTransitionRootConfigurationError(ValueError):
    pass


def _text_on_work(value, maximum, work):
    if type(value) is not str or not 1 <= len(value) <= maximum or "\x00" in value:
        raise WebAuthnTransitionRootConfigurationError("transition root configuration text is invalid")
    work.prepare_utf8(value)
    reader._bounded_text(value, maximum)


def _reader_from_configuration_on_work(*, operation, payload, configuration_digest,
        generation, runtime_role_identities, read_dsn, work):
    try:
        pins_configuration._operation(operation)
        owned, _launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        runtime = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime_role_identities, owned_payload=owned,
            configuration_digest=configuration_digest, launch=_launch, work=work)
        dsn = read_dsn
        _text_on_work(dsn, 65536, work)
        if "\r" in dsn or "\n" in dsn:
            raise WebAuthnTransitionRootConfigurationError("transition root DSN is not one protected descriptor value")
        role = pins_configuration._role(owned, "verifier")
        shape = configuration.capability.shape
        measurement = role["measurementDigest"]
        response_spki, signing_spki = role["responseSigningSpkiDigest"], role["signingSpkiDigest"]
        for digest in (measurement, response_spki, signing_spki):
            shape._digest(digest)
        plan._same(response_spki, signing_spki, work,
            "transition root verifier signing key differs from its measured response pin")
        timeout = role["databaseConnectTimeoutSeconds"]
        if (type(timeout) not in (int, float)
                or type(timeout) is float and not math.isfinite(timeout)
                or not 2 <= timeout <= 300):
            raise WebAuthnTransitionRootConfigurationError("transition root timeout is outside libpq's source interval")
        timeout = int(timeout)
        database_role, client_dn, client_serial, issuer_dn = (
            role["databaseRole"], role["tlsClientDn"], role["tlsClientSerial"], role["tlsIssuerDn"])
        query_manifest_digest = owned["queryManifestDigest"]
        _text_on_work(database_role, 63, work)
        for value in (client_dn, client_serial, issuer_dn):
            _text_on_work(value, 4096, work)
        shape._digest(query_manifest_digest)
        plan._same(query_manifest_digest, plan._QUERY_MANIFEST_DIGEST, work,
            "transition root query manifest differs from the source")
        # All database settings are now immutable held values. This actual
        # continuation owns policy graphs and reconstructs configured keys;
        # no returned policy/key data becomes a substitute root inventory.
        pins = pins_configuration._pins_from_owned_configuration_on_work(operation=operation,
            owned_payload=owned, owned_runtime_identities=runtime,
            configuration_digest=configuration_digest, work=work)
        if pins[0] != operation:
            raise WebAuthnTransitionRootConfigurationError("transition root configured operation changed")
        from catchplate import authority_webauthn_transition_root_reader as roots

        return roots.TransitionRootReader(operation=operation, dsn=dsn,
            connect_timeout_seconds=timeout, database_role=database_role,
            tls_client_dn=client_dn, tls_client_serial=client_serial,
            tls_issuer_dn=issuer_dn, query_manifest_digest=query_manifest_digest)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnTransitionRootConfigurationError):
            raise
        raise WebAuthnTransitionRootConfigurationError("transition root configuration failed") from exc
