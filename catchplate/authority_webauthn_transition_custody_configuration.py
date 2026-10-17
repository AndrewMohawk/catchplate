"""Capture fixed successor custody policy, role pins and actual writer owner.

The service independently admits root-signed configuration, active generation
and the protected writer descriptor. This mapper captures their consistency
once, then uses the explicit transition policy for one of the three source
operations. Current configuration and received controls never enroll history.

All role, generation, endpoint and optional database scalars are held before
native key callbacks. Verifier/planner keys are actually pinned and distinct;
the selected operation keeps its explicit transition policy, never a generic
role-key substitute. When requested, the writer field is the actual inert
TransitionPlanPersistence owner, not a successful verification descriptor.
No socket, SQL, private signer, clock, ACL change or new allowance is provided.
"""
from __future__ import annotations

from dataclasses import dataclass
import math

from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_revocation_plan as plan
from catchplate import authority_webauthn_evidence_plan_writer_configuration as database_configuration
from catchplate import authority_webauthn_transition_configuration as pins_configuration
from catchplate import authority_webauthn_transition_custody_wire as wire
from catchplate import authority_webauthn_transition_persistence as persistence


class WebAuthnTransitionCustodyConfigurationError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _CustodyConfiguration:
    pins: tuple
    verifier_public_key: object
    generation_sequence: int
    generation_digest: str
    maximum_control_age_ns: int
    writer_configuration: persistence.TransitionPlanPersistence | None
    writer_endpoint: tuple
    planner_endpoint: tuple


def _endpoint(source, target, work):
    shape = configuration.capability.shape
    for field in ("peerUid", "peerGid"):
        shape._integer(target[field], 0xFFFFFFFF, minimum=1)
    plan._same((target["peerUid"], target["peerGid"]),
        (source["serviceUid"], source["serviceGid"]), work,
        "transition custody peer topology differs from the configured source")
    path = target["socketPath"]
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise WebAuthnTransitionCustodyConfigurationError("transition custody socket path is not bounded and absolute")
    if work.prepare_utf8(path) > 107 or len(path.encode("utf-8")) > 107:
        raise WebAuthnTransitionCustodyConfigurationError("transition custody socket path exceeds its UTF-8 bound")
    return (path, min(source["requestTimeoutSeconds"], target["requestTimeoutSeconds"]),
        target["serviceUid"], target["serviceGid"])


def _capture_on_work(*, operation, payload, configuration_digest, generation,
        runtime_role_identities, writer_dsn=None, work):
    """Own configuration once and derive fixed custody inputs on the same work."""
    try:
        pins_configuration._operation(operation)
        owned, launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        runtime = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime_role_identities, owned_payload=owned,
            configuration_digest=configuration_digest, launch=launch, work=work)
        verifier = pins_configuration._role(owned, "verifier")
        planner = pins_configuration._role(owned, "planner")
        writer = pins_configuration._role(owned, "planner-writer")
        shape = configuration.capability.shape
        for role in (verifier, planner, writer):
            for field in ("measurementDigest", "responseSigningSpkiDigest"):
                shape._digest(role[field])
            for field in ("serviceUid", "serviceGid"):
                shape._integer(role[field], 0xFFFFFFFF, minimum=1)
            shape._integer(role["maximumInternalAgeNs"], minimum=1)
            timeout = role["requestTimeoutSeconds"]
            if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                    or not 0.05 <= timeout <= 30):
                raise WebAuthnTransitionCustodyConfigurationError("transition custody request timeout exceeds its source interval")
        for role in (verifier, planner):
            shape._digest(role["signingSpkiDigest"])
            plan._same(role["responseSigningSpkiDigest"], role["signingSpkiDigest"], work,
                "transition custody signer differs from its measured response pin")
        verifier_encoded, verifier_spki = verifier["signingPublicKeyBase64Url"], verifier["signingSpkiDigest"]
        shape._text(verifier_encoded, 43, minimum=43)
        shape._base64url(verifier_encoded)
        sequence, digest = launch["sequence"], launch["digest"]
        maximum_age = min(wire.authority.VERIFIER_RESPONSE_MAX_AGE_NS,
            verifier["maximumInternalAgeNs"], planner["maximumInternalAgeNs"], writer["maximumInternalAgeNs"])
        planner_endpoint = _endpoint(verifier, planner, work)
        writer_endpoint = _endpoint(planner, writer, work)
        database = (None if writer_dsn is None else
            database_configuration._database_from_owned_configuration_on_work(
                owned_payload=owned, writer_dsn=writer_dsn, work=work))
        wire._pins(configuration_digest, sequence, digest, operation)
        # All subsequent custody scalars are held. The shared continuation
        # owns explicit transition policy and role pins before its callbacks;
        # it neither recaptures full configuration nor substitutes a role key.
        pins = pins_configuration._pins_from_owned_configuration_on_work(operation=operation,
            owned_payload=owned, owned_runtime_identities=runtime,
            configuration_digest=configuration_digest, work=work)
        verifier_key = configuration._key(verifier_encoded, work, expected_spki=verifier_spki)
        wire._distinct_keys(pins[1], verifier_key, work)
        configured_writer = (None if database is None else
            persistence.TransitionPlanPersistence(writer_dsn=database[0],
                connect_timeout_seconds=database[1], database_identity=database[2], pins=pins))
        return _CustodyConfiguration(pins=pins, verifier_public_key=verifier_key,
            generation_sequence=sequence, generation_digest=digest,
            maximum_control_age_ns=maximum_age, writer_configuration=configured_writer,
            writer_endpoint=writer_endpoint, planner_endpoint=planner_endpoint)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnTransitionCustodyConfigurationError):
            raise
        raise WebAuthnTransitionCustodyConfigurationError("transition custody configuration failed") from exc
