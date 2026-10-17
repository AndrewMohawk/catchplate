"""Fixed verifier-to-planner settings for live successor plan exchange.

The service independently admits configuration and active generation. This
mapper owns that full configuration once, joins the selected source operation
and explicit purpose policy, and retains all role/endpoint/generation scalars
before genuine key callbacks. It does not require a writer or admit history,
provide execution authority, open a socket, import a database or sample clocks.
"""
from __future__ import annotations

from dataclasses import dataclass
import math

from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_webauthn_transition_configuration as pins_configuration
from catchplate import authority_webauthn_transition_request as request


class WebAuthnTransitionExchangeConfigurationError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ExchangeConfiguration:
    pins: tuple
    verifier_public_key: object
    generation_sequence: int
    generation_digest: str
    maximum_control_age_ns: int
    planner_endpoint: tuple


def _endpoint(verifier, planner, work):
    shape = configuration.capability.shape
    for field in ("peerUid", "peerGid"):
        shape._integer(planner[field], 0xFFFFFFFF, minimum=1)
    request.evidence.plan._same((planner["peerUid"], planner["peerGid"]),
        (verifier["serviceUid"], verifier["serviceGid"]), work,
        "transition planner peer differs from the configured verifier")
    path = planner["socketPath"]
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise WebAuthnTransitionExchangeConfigurationError("transition planner socket path is not bounded and absolute")
    if work.prepare_utf8(path) > 107 or len(path.encode("utf-8")) > 107:
        raise WebAuthnTransitionExchangeConfigurationError("transition planner socket path exceeds its UTF-8 bound")
    return (path, min(verifier["requestTimeoutSeconds"], planner["requestTimeoutSeconds"]),
        planner["serviceUid"], planner["serviceGid"])


def _capture_on_work(*, operation, payload, configuration_digest, generation, runtime_role_identities, work):
    try:
        pins_configuration._operation(operation)
        owned, launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        runtime = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime_role_identities, owned_payload=owned,
            configuration_digest=configuration_digest, launch=launch, work=work)
        verifier = pins_configuration._role(owned, "verifier")
        planner = pins_configuration._role(owned, "planner")
        shape = configuration.capability.shape
        for role in (verifier, planner):
            for field in ("measurementDigest", "signingSpkiDigest",
                    "responseSigningSpkiDigest"):
                shape._digest(role[field])
            request.evidence.plan._same(role["responseSigningSpkiDigest"], role["signingSpkiDigest"],
                work, "transition role signer differs from its measured response pin")
            for field in ("serviceUid", "serviceGid"):
                shape._integer(role[field], 0xFFFFFFFF, minimum=1)
            shape._integer(role["maximumInternalAgeNs"], minimum=1)
            timeout = role["requestTimeoutSeconds"]
            if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                    or not 0.05 <= timeout <= 30):
                raise WebAuthnTransitionExchangeConfigurationError("transition exchange timeout is outside its source interval")
        encoded, spki = verifier["signingPublicKeyBase64Url"], verifier["signingSpkiDigest"]
        shape._text(encoded, 43, minimum=43)
        shape._base64url(encoded)
        sequence, digest = launch["sequence"], launch["digest"]
        maximum_age = min(request.authority.VERIFIER_RESPONSE_MAX_AGE_NS,
            verifier["maximumInternalAgeNs"], planner["maximumInternalAgeNs"])
        endpoint = _endpoint(verifier, planner, work)
        request._pins(configuration_digest, sequence, digest, operation)
        # The shared continuation holds all planner/explicit-purpose pins
        # before its native callbacks. Only immutable exchange scalars follow.
        pins = pins_configuration._pins_from_owned_configuration_on_work(operation=operation,
            owned_payload=owned, owned_runtime_identities=runtime,
            configuration_digest=configuration_digest, work=work)
        verifier_key = configuration._key(encoded, work, expected_spki=spki)
        request.wire._distinct_keys(pins[1], verifier_key, work)
        return _ExchangeConfiguration(pins=pins, verifier_public_key=verifier_key,
            generation_sequence=sequence, generation_digest=digest,
            maximum_control_age_ns=maximum_age, planner_endpoint=endpoint)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnTransitionExchangeConfigurationError):
            raise
        raise WebAuthnTransitionExchangeConfigurationError("transition exchange configuration failed") from exc
