"""Capture fixed retain-only role, endpoint and purpose-policy configuration.

The actual service supplies root-admitted configuration, active launch values
and, for writer use only, the protected DSN. One full capture binds those
inputs. This mapper checks consistency, not root, launch or historical
authority. The optional purpose policy remains mandatory and cannot be
replaced by a generic verifier key or by a control's fields.

Every role, generation, endpoint and optional database scalar is held before
native key callbacks. The actual verifier/planner keys are independently pinned
and distinct. Returned immutable settings are ordinary configured inputs, not
successful proof tokens. No socket, database import, clock, private signer,
registry activation or replacement work allowance is introduced here.
"""
from __future__ import annotations

from dataclasses import dataclass
import math

from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_plan as plan
from serverware import authority_webauthn_evidence_custody_wire as wire
from serverware import authority_webauthn_evidence_plan_persistence as persistence
from serverware import authority_webauthn_evidence_plan_verifier_configuration as pins_configuration
from serverware import authority_webauthn_evidence_plan_writer_configuration as writer_configuration


class WebAuthnEvidenceCustodyConfigurationError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _CustodyConfiguration:
    pins: tuple
    verifier_public_key: object
    generation_sequence: int
    generation_digest: str
    maximum_control_age_ns: int
    writer_configuration: tuple | None
    writer_endpoint: tuple
    planner_endpoint: tuple


def _endpoint(source, target, work):
    """Bind one actual peer link and retain its fixed destination scalars."""
    shape = configuration.capability.shape
    for field in ("peerUid", "peerGid"):
        shape._integer(target[field], 0xFFFFFFFF, minimum=1)
    plan._same((target["peerUid"], target["peerGid"]),
        (source["serviceUid"], source["serviceGid"]), work,
        "evidence custody peer topology differs from the configured source")
    path = target["socketPath"]
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise WebAuthnEvidenceCustodyConfigurationError("evidence custody socket path is not bounded and absolute")
    if work.prepare_utf8(path) > 107:
        raise WebAuthnEvidenceCustodyConfigurationError("evidence custody socket path exceeds its UTF-8 bound")
    # The actual bytes are bounded before the endpoint is given to transport.
    if len(path.encode("utf-8")) > 107:
        raise WebAuthnEvidenceCustodyConfigurationError("evidence custody socket path changed after measurement")
    return (path, min(source["requestTimeoutSeconds"], target["requestTimeoutSeconds"]),
        target["serviceUid"], target["serviceGid"])


def _capture_on_work(*, purpose, payload, configuration_digest, generation,
        runtime_role_identities, writer_dsn=None, work):
    """Capture once and derive fixed custody settings on the original work."""
    try:
        if type(purpose) is not str or purpose not in ("registration", "installation"):
            raise WebAuthnEvidenceCustodyConfigurationError("evidence custody purpose is not source fixed")
        owned, launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        runtime = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime_role_identities, owned_payload=owned,
            configuration_digest=configuration_digest, launch=launch, work=work)
        roles = owned["roles"]
        if type(roles) is not dict:
            raise WebAuthnEvidenceCustodyConfigurationError("evidence custody roles are not an exact object")
        verifier, planner, writer = (roles[name] for name in ("verifier", "planner", "planner-writer"))
        shape = configuration.capability.shape
        for name, role in (("verifier", verifier), ("planner", planner), ("planner-writer", writer)):
            if type(role) is not dict:
                raise WebAuthnEvidenceCustodyConfigurationError("evidence custody role is not an exact object")
            shape._literal(role["processMode"], "policy-authority-" + name)
            for field in ("measurementDigest", "responseSigningSpkiDigest"):
                shape._digest(role[field])
            for field in ("serviceUid", "serviceGid"):
                shape._integer(role[field], 0xFFFFFFFF, minimum=1)
            shape._integer(role["maximumInternalAgeNs"], minimum=1)
            timeout = role["requestTimeoutSeconds"]
            if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                    or not 0.05 <= timeout <= 30):
                raise WebAuthnEvidenceCustodyConfigurationError("evidence custody request timeout is outside its source interval")
        for role in (verifier, planner):
            shape._digest(role["signingSpkiDigest"])
            plan._same(role["responseSigningSpkiDigest"], role["signingSpkiDigest"], work,
                "evidence custody signing key differs from its measured response pin")
        verifier_encoded = verifier["signingPublicKeyBase64Url"]
        verifier_spki = verifier["signingSpkiDigest"]
        shape._text(verifier_encoded, 43, minimum=43)
        shape._base64url(verifier_encoded)
        generation_sequence, generation_digest = launch["sequence"], launch["digest"]
        maximum_control_age_ns = min(wire.authority.VERIFIER_RESPONSE_MAX_AGE_NS,
            verifier["maximumInternalAgeNs"], planner["maximumInternalAgeNs"], writer["maximumInternalAgeNs"])
        planner_endpoint = _endpoint(verifier, planner, work)
        writer_endpoint = _endpoint(planner, writer, work)
        database = (None if writer_dsn is None else
            writer_configuration._database_from_owned_configuration_on_work(
                owned_payload=owned, writer_dsn=writer_dsn, work=work))
        # All custody-specific scalars are now held. This fixed continuation
        # captures the explicit evidence-purpose policy and planner pins before
        # its first key callback; it neither recaptures configuration nor adopts
        # a generic verifier key as the evidence-purpose key.
        pins = pins_configuration._pins_from_owned_configuration_on_work(purpose=purpose,
            owned_payload=owned, owned_runtime_identities=runtime,
            configuration_digest=configuration_digest, work=work)
        verifier_key = configuration._key(verifier_encoded, work, expected_spki=verifier_spki)
        wire._distinct_keys(pins[1], verifier_key, work)
        wire._pins(configuration_digest, generation_sequence, generation_digest, pins[0])
        configured_writer = (None if database is None else
            persistence._configuration(database + pins))
        return _CustodyConfiguration(pins=pins, verifier_public_key=verifier_key,
            generation_sequence=generation_sequence, generation_digest=generation_digest,
            maximum_control_age_ns=maximum_control_age_ns, writer_configuration=configured_writer,
            writer_endpoint=writer_endpoint, planner_endpoint=planner_endpoint)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnEvidenceCustodyConfigurationError):
            raise
        raise WebAuthnEvidenceCustodyConfigurationError("evidence custody configuration failed") from exc
