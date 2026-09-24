"""Map admitted purpose policy into the genuine configured evidence read owner.

The real service supplies root-verified configuration, active launch bindings
and its protected read descriptor. Full configuration ownership, its actual
commitment and generation membership are checked on the original work before
any key callback. This consistency check does not enroll a root or authenticate
a caller-created configuration dictionary. An absent/disabled purpose denies.

Neither generic role keys nor per-request signer/policy overrides are accepted.
The selected purpose's real public key, identity, age/skew and RP/origin or
installation target come from the same owned signed configuration. No signer,
database, registry entry, serving route or durable execution is opened here.
"""
from __future__ import annotations

import math

from serverware import authority_contract as authority
from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_plan as plan
from serverware import authority_revocation_root_reader as reader
from serverware import authority_webauthn_evidence_planning as planning
from serverware import authority_webauthn_evidence_policy as policy


class WebAuthnEvidenceConfigurationError(ValueError):
    pass


def _require_enabled_operation(planner, operation, work):
    """Check the owned signed allowlist on existing work, without activation."""
    enabled = planner["enabledOperations"]
    shape = configuration.capability.shape
    shape._array(enabled, len(authority.OPERATIONS), "evidence planner enabled operations")
    work.prepare_scan(enabled)
    previous, present = None, False
    for value in enabled:
        shape._text(value, 256)
        if value not in authority.OPERATIONS or previous is not None and previous >= value:
            raise WebAuthnEvidenceConfigurationError("evidence planner operations are not source-known, sorted and unique")
        if value == operation:
            present = True
        previous = value
    if not present:
        raise WebAuthnEvidenceConfigurationError("evidence operation is not enabled by the signed planner policy")


def _planner_from_configuration_on_work(*, purpose, payload, configuration_digest,
                                       generation, read_dsn, work):
    try:
        if type(purpose) is not str or purpose not in ("registration", "installation"):
            raise WebAuthnEvidenceConfigurationError("evidence configuration purpose is not source fixed")
        owned, _launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        reader._bounded_text(read_dsn, 65536)
        if "\n" in read_dsn or "\r" in read_dsn:
            raise WebAuthnEvidenceConfigurationError("evidence planner DSN is not one descriptor value")
        roles = owned["roles"]
        if type(roles) is not dict or type(roles.get("planner")) is not dict:
            raise WebAuthnEvidenceConfigurationError("evidence planner role configuration is absent")
        planner = roles["planner"]
        plan.contract._literal(planner["processMode"], "policy-authority-planner")
        operation = ("webauthn.registration.evidence.admit" if purpose == "registration"
            else "webauthn.trust.installation.admit")
        _require_enabled_operation(planner, operation, work)
        for name in ("plannerSessionIdentityDigest", "measurementDigest", "attestationReceiptDigest"):
            plan.contract._digest(planner[name])
        plan._same(owned["queryManifestDigest"], plan._QUERY_MANIFEST_DIGEST, work,
            "evidence planner query manifest differs from the source")
        timeout = planner["databaseConnectTimeoutSeconds"]
        if (type(timeout) not in (int, float)
                or type(timeout) is float and not math.isfinite(timeout)
                or not 2 <= timeout <= 300):
            raise WebAuthnEvidenceConfigurationError("evidence planner timeout is outside libpq's bounded interval")
        timeout = int(timeout)
        database_identity = (planner["databaseRole"], planner["tlsClientDn"], planner["tlsClientSerial"],
            planner["tlsIssuerDn"], planner["plannerSessionIdentityDigest"],
            planner["measurementDigest"], planner["attestationReceiptDigest"])
        reader._bounded_text(database_identity[0], 63)
        for value in database_identity[1:4]:
            reader._bounded_text(value, 4096)
        if policy.FIELD not in owned:
            raise WebAuthnEvidenceConfigurationError("evidence admission has no signed purpose policy")
        # Both policy slots and the WebAuthn graph are owned before the first
        # real raw-key constructor/SPKI callback. No role key is substituted.
        purposes, public_keys = policy._validate_policy_on_work(owned[policy.FIELD],
            webauthn=owned["webauthn"], work=work)
        selected = purposes[purpose]
        if selected is None:
            raise WebAuthnEvidenceConfigurationError("evidence admission purpose is disabled")
        return planning.EvidenceAdmissionPlanner(operation=selected["operation"],
            read_dsn=read_dsn, connect_timeout_seconds=timeout, database_identity=database_identity,
            evidence_public_key=public_keys[purpose], expected_evidence_identity=selected["signerIdentity"],
            expected_evidence_spki_digest=selected["signingSpkiDigest"],
            maximum_age_ns=selected["maximumAgeNs"], maximum_clock_skew_ns=selected["maximumClockSkewNs"],
            rp_id=selected["rpId"] if purpose == "registration" else None,
            origin=selected["origin"] if purpose == "registration" else None,
            installation_target_digest=selected["installationTargetDigest"] if purpose == "installation" else None)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnEvidenceConfigurationError):
            raise
        raise WebAuthnEvidenceConfigurationError("evidence planner configuration failed") from exc


def _registration_planner_from_configuration_on_work(*, payload, configuration_digest,
                                                     generation, read_dsn, work):
    return _planner_from_configuration_on_work(purpose="registration", payload=payload,
        configuration_digest=configuration_digest, generation=generation, read_dsn=read_dsn, work=work)


def _installation_planner_from_configuration_on_work(*, payload, configuration_digest,
                                                     generation, read_dsn, work):
    return _planner_from_configuration_on_work(purpose="installation", payload=payload,
        configuration_digest=configuration_digest, generation=generation, read_dsn=read_dsn, work=work)
