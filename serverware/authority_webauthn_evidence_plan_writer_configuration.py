"""Map admitted configuration to fixed evidence-plan PostgreSQL custody.

The service supplies genuinely root-verified configuration, active launch
bindings and the protected planner-writer DSN. This mapper owns those inputs
and checks their consistency; a constructed graph is not configuration or
launch authority. A missing, disabled or non-allowlisted evidence purpose denies.

Planner and writer role pins and the writer's planner aliases are joined before
native key callbacks. The actual planner key is reconstructed against its SPKI;
the evidence key comes only from the explicit signed purpose policy, never a
generic verifier role. All relevant scalar settings are held before either key
path. The returned owner opens no connection until its fixed persist/read call,
where independent historical expectations and original bytes remain required.

No private signer, clock, descriptor read, database call, policy extension,
registry activation or replacement work allowance is introduced here.
"""
from __future__ import annotations

import math

from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_plan as plan
from serverware import authority_revocation_writer_connection as writer
from serverware import authority_webauthn_evidence_configuration as read_configuration
from serverware import authority_webauthn_evidence_plan_persistence as persistence
from serverware import authority_webauthn_evidence_policy as policy


class WebAuthnEvidencePlanWriterConfigurationError(ValueError):
    pass


def _persistence_from_configuration_on_work(*, purpose, payload, configuration_digest,
        generation, writer_dsn, work):
    try:
        if type(purpose) is not str or purpose not in ("registration", "installation"):
            raise WebAuthnEvidencePlanWriterConfigurationError("evidence custody purpose is not source fixed")
        owned, _launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        writer.reader._bounded_text(writer_dsn, 65536)
        if "\n" in writer_dsn or "\r" in writer_dsn:
            raise WebAuthnEvidencePlanWriterConfigurationError("evidence custody DSN is not one descriptor value")
        roles = owned["roles"]
        if type(roles) is not dict:
            raise WebAuthnEvidencePlanWriterConfigurationError("evidence custody roles are not exact")
        planner, writer_role = roles["planner"], roles["planner-writer"]
        shape = configuration.capability.shape
        for name, role in (("planner", planner), ("planner-writer", writer_role)):
            if type(role) is not dict:
                raise WebAuthnEvidencePlanWriterConfigurationError("evidence custody role is not an exact object")
            shape._literal(role["processMode"], "policy-authority-" + name)
            for field in ("measurementDigest", "attestationReceiptDigest", "responseSigningSpkiDigest"):
                shape._digest(role[field])
        operation = ("webauthn.registration.evidence.admit" if purpose == "registration"
            else "webauthn.trust.installation.admit")
        read_configuration._require_enabled_operation(planner, operation, work)
        plan._same(owned["queryManifestDigest"], plan._QUERY_MANIFEST_DIGEST, work,
            "evidence custody query manifest differs from the source")

        planner_encoded = planner["signingPublicKeyBase64Url"]
        planner_spki = planner["signingSpkiDigest"]
        planner_identity = {"sessionIdentityDigest": planner["plannerSessionIdentityDigest"],
            "measurementDigest": planner["measurementDigest"],
            "attestationReceiptDigest": planner["attestationReceiptDigest"]}
        for digest in (*planner_identity.values(), planner_spki,
                writer_role["plannerSessionIdentityDigest"], writer_role["plannerSigningSpkiDigest"]):
            shape._digest(digest)
        for encoded in (planner_encoded, writer_role["plannerSigningPublicKeyBase64Url"]):
            shape._text(encoded, 43, minimum=43)
            shape._base64url(encoded)
        plan._same(planner["responseSigningSpkiDigest"], planner_spki, work,
            "evidence custody planner key differs from its response pin")
        plan._same((writer_role["plannerSessionIdentityDigest"], writer_role["plannerSigningSpkiDigest"],
                writer_role["plannerSigningPublicKeyBase64Url"]),
            (planner_identity["sessionIdentityDigest"], planner_spki, planner_encoded), work,
            "evidence custody writer aliases differ from the configured planner")

        timeout = writer_role["databaseConnectTimeoutSeconds"]
        if (type(timeout) not in (int, float)
                or type(timeout) is float and not math.isfinite(timeout)
                or not 2 <= timeout <= 300):
            raise WebAuthnEvidencePlanWriterConfigurationError("evidence custody timeout exceeds libpq's bounded interval")
        timeout = int(timeout)
        database_identity = (writer_role["databaseRole"], writer_role["tlsClientDn"],
            writer_role["tlsClientSerial"], writer_role["tlsIssuerDn"])
        writer._validate_database_identity(database_identity)
        if policy.FIELD not in owned:
            raise WebAuthnEvidencePlanWriterConfigurationError("evidence custody has no signed purpose policy")
        purpose_policy, webauthn = owned[policy.FIELD], owned["webauthn"]
        policy._shape(purpose_policy, webauthn=webauthn)
        selected = purpose_policy[purpose]
        if selected is None:
            raise WebAuthnEvidencePlanWriterConfigurationError("evidence custody purpose is disabled")
        # Hold every scalar and identity member before the actual validator
        # reconstructs either enabled purpose key. Do not reread these graphs
        # after a native callback or adopt a returned policy as new authority.
        evidence_identity = {name: selected["signerIdentity"][name] for name in (
            "sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")}
        evidence_spki = selected["signingSpkiDigest"]
        maximum_age_ns, maximum_clock_skew_ns = selected["maximumAgeNs"], selected["maximumClockSkewNs"]
        rp_id = selected["rpId"] if purpose == "registration" else None
        origin = selected["origin"] if purpose == "registration" else None
        target = selected["installationTargetDigest"] if purpose == "installation" else None
        _purposes, public_keys = policy._validate_policy_on_work(purpose_policy, webauthn=webauthn, work=work)
        evidence_key = public_keys[purpose]
        planner_key = configuration._key(planner_encoded, work, expected_spki=planner_spki)
        return persistence.EvidencePlanPersistence(writer_dsn=writer_dsn,
            connect_timeout_seconds=timeout, database_identity=database_identity, operation=operation,
            planner_public_key=planner_key, expected_planner_identity=planner_identity,
            expected_planner_spki_digest=planner_spki, evidence_public_key=evidence_key,
            expected_evidence_identity=evidence_identity, expected_evidence_spki_digest=evidence_spki,
            configuration_digest=configuration_digest, maximum_age_ns=maximum_age_ns,
            maximum_clock_skew_ns=maximum_clock_skew_ns, rp_id=rp_id, origin=origin,
            installation_target_digest=target)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnEvidencePlanWriterConfigurationError):
            raise
        raise WebAuthnEvidencePlanWriterConfigurationError("evidence custody configuration failed") from exc


def _registration_plan_persistence_from_configuration_on_work(*, payload, configuration_digest,
        generation, writer_dsn, work):
    return _persistence_from_configuration_on_work(purpose="registration", payload=payload,
        configuration_digest=configuration_digest, generation=generation, writer_dsn=writer_dsn, work=work)


def _installation_plan_persistence_from_configuration_on_work(*, payload, configuration_digest,
        generation, writer_dsn, work):
    return _persistence_from_configuration_on_work(purpose="installation", payload=payload,
        configuration_digest=configuration_digest, generation=generation, writer_dsn=writer_dsn, work=work)
