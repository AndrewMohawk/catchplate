"""Map admitted verifier settings into the fixed evidence-root read owner.

The service supplies independently root-admitted measured configuration,
active launch generation and its protected verifier read DSN. This mapper
captures their genuine configuration commitment and launch consistency once;
it does not establish that upstream provenance or open a connection.

Every database setting is held before purpose-policy or key callbacks. The
selected evidence operation must be enabled and its explicit policy must pass
the real configured-pin mapper; no generic verifier key substitutes for that
policy. The root owner retains the exact signed verifier database role and
checks the actual source verifier privilege surface, not a new role literal.
No SQL, registry activation, policy expansion or replacement work is supplied.
"""
from __future__ import annotations

import math

from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_plan as plan
from serverware import authority_revocation_root_reader as reader
from serverware import authority_webauthn_evidence_plan_verifier_configuration as pins_configuration


class WebAuthnEvidenceRootConfigurationError(ValueError):
    pass


def _text_on_work(value, maximum, work):
    if type(value) is not str or not 1 <= len(value) <= maximum or "\x00" in value:
        raise WebAuthnEvidenceRootConfigurationError("evidence root configuration text is invalid")
    work.prepare_utf8(value)
    reader._bounded_text(value, maximum)


def _reader_from_configuration_on_work(*, purpose, payload, configuration_digest,
        generation, runtime_role_identities, read_dsn, work):
    try:
        if type(purpose) is not str or purpose not in ("registration", "installation"):
            raise WebAuthnEvidenceRootConfigurationError("evidence root purpose is not source fixed")
        operation = ("webauthn.registration.evidence.admit" if purpose == "registration"
            else "webauthn.trust.installation.admit")
        owned, _launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        runtime = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime_role_identities, owned_payload=owned,
            configuration_digest=configuration_digest, launch=_launch, work=work)
        dsn = read_dsn
        _text_on_work(dsn, 65536, work)
        if "\r" in dsn or "\n" in dsn:
            raise WebAuthnEvidenceRootConfigurationError("evidence root DSN is not one protected descriptor value")
        roles = owned["roles"]
        if type(roles) is not dict or type(roles.get("verifier")) is not dict:
            raise WebAuthnEvidenceRootConfigurationError("evidence root verifier role is absent")
        role = roles["verifier"]
        shape = configuration.capability.shape
        shape._literal(role["processMode"], "policy-authority-verifier")
        measurement = role["measurementDigest"]
        response_spki, signing_spki = role["responseSigningSpkiDigest"], role["signingSpkiDigest"]
        for digest in (measurement, response_spki, signing_spki):
            shape._digest(digest)
        plan._same(response_spki, signing_spki, work,
            "evidence root verifier signing key differs from its measured response pin")
        timeout = role["databaseConnectTimeoutSeconds"]
        if (type(timeout) not in (int, float)
                or type(timeout) is float and not math.isfinite(timeout)
                or not 2 <= timeout <= 300):
            raise WebAuthnEvidenceRootConfigurationError("evidence root timeout is outside libpq's source interval")
        timeout = int(timeout)
        database_role, client_dn, client_serial, issuer_dn = (
            role["databaseRole"], role["tlsClientDn"], role["tlsClientSerial"], role["tlsIssuerDn"])
        query_manifest_digest = owned["queryManifestDigest"]
        _text_on_work(database_role, 63, work)
        for value in (client_dn, client_serial, issuer_dn):
            _text_on_work(value, 4096, work)
        shape._digest(query_manifest_digest)
        plan._same(query_manifest_digest, plan._QUERY_MANIFEST_DIGEST, work,
            "evidence root query manifest differs from the source")
        # The full owned payload and all role/database scalars above precede
        # actual evidence-policy and planner-key callbacks. This real helper
        # enforces the selected operation's allowlist and explicit purpose
        # policy; its ordinary pins are not substituted for root observations.
        pins = pins_configuration._pins_from_owned_configuration_on_work(purpose=purpose,
            owned_payload=owned, owned_runtime_identities=runtime,
            configuration_digest=configuration_digest, work=work)
        if pins[0] != operation:
            raise WebAuthnEvidenceRootConfigurationError("evidence root purpose operation changed")
        from serverware import authority_webauthn_evidence_root_reader as roots

        return roots.EvidenceRootReader(operation=operation, dsn=dsn,
            connect_timeout_seconds=timeout, database_role=database_role,
            tls_client_dn=client_dn, tls_client_serial=client_serial,
            tls_issuer_dn=issuer_dn, query_manifest_digest=query_manifest_digest)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnEvidenceRootConfigurationError):
            raise
        raise WebAuthnEvidenceRootConfigurationError("evidence root configuration failed") from exc
