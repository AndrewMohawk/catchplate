"""Private measured-configuration mapping for the read-only observed planner.

Root-signed configuration, active launch and the planner-only descriptor/signer
are service admission prerequisites, not properties created by this mapper.
It owns the full configuration and launch bindings on existing work, admits the
two measured public keys and pairs the actual local signer without signing.
It neither imports the active planner nor opens a database, persists a record,
samples a clock or enables a request purpose or registry entry.

Actual configuration capture, encoding, comparison, SPKI hashes and identity
framing retain the four-hash verifier-mapper schedule. Signer pairing adds two
raw32 serializations and one complete comparison (128 bytes, no hash/nodes).
Native key internals and bounded local descriptor/scalar admission are outside
H/B/N. This is not a whole-process cost or private-key provenance claim.
"""
from __future__ import annotations

import math

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from serverware import authority_contract as authority
from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_plan as plan
from serverware import authority_revocation_planning as planning


class RevocationPlannerConfigurationError(ValueError):
    pass


def _bind_signer(private_key, public_key, work):
    """Pair the real local signer with its admitted public pin, without signing."""
    work.charge(input_bytes=128)
    derived = configuration.production._callback(work, lambda: private_key.public_key())
    if not isinstance(derived, Ed25519PublicKey):
        raise RevocationPlannerConfigurationError("observed planner signer did not derive an Ed25519 key")
    actual = configuration.production._callback(work,
        lambda: derived.public_bytes(Encoding.Raw, PublicFormat.Raw))
    expected = configuration.production._callback(work,
        lambda: public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    if any(type(raw) is not bytes or len(raw) != 32 for raw in (actual, expected)):
        raise RevocationPlannerConfigurationError("observed planner signing keys are not exact raw32")
    if actual != expected:
        raise RevocationPlannerConfigurationError("observed planner signer differs from its measured public pin")


def _planner_from_configuration_on_work(*, payload, configuration_digest, generation,
                                       runtime_role_identities, read_dsn, planner_private_key, work):
    """Construct only from independently admitted local configuration inputs.

    The historical policy must equal the configured handoff receiver's policy:
    exact measured challenge age, min(verifier internal age, source thirty
    seconds), and source five-second skew. Planner internal request age belongs
    to a future authenticated request boundary, not these retained fields.
    Launch bindings are checked here but are not added as new signed plan fields.
    """
    try:
        owned, _launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        runtime = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime_role_identities, owned_payload=owned,
            configuration_digest=configuration_digest, launch=_launch, work=work)
        planning.reader._bounded_text(read_dsn, 65536)
        if "\n" in read_dsn or "\r" in read_dsn:
            raise RevocationPlannerConfigurationError("observed planner DSN is not one bounded descriptor value")
        if not isinstance(planner_private_key, Ed25519PrivateKey):
            raise RevocationPlannerConfigurationError("observed planner local signer is not Ed25519")
        roles = owned["roles"]
        if type(roles) is not dict:
            raise RevocationPlannerConfigurationError("observed planner roles are not an exact object")
        planner, verifier = roles["planner"], roles["verifier"]
        for name, role in (("planner", planner), ("verifier", verifier)):
            if type(role) is not dict:
                raise RevocationPlannerConfigurationError("observed planner role is not an exact object")
            plan.contract._literal(role["processMode"], "policy-authority-" + name)
            for field in ("measurementDigest", "signingSpkiDigest"):
                plan.contract._digest(role[field])
            plan._same(role["responseSigningSpkiDigest"], role["signingSpkiDigest"], work,
                "observed planner key differs from its measured response pin")
        plan.contract._digest(planner["plannerSessionIdentityDigest"])
        plan._same(owned["queryManifestDigest"], plan._QUERY_MANIFEST_DIGEST, work,
            "observed planner configuration differs from the source query manifest")

        timeout = planner["databaseConnectTimeoutSeconds"]
        if (type(timeout) not in (int, float)
                or (type(timeout) is float and not math.isfinite(timeout))
                or not 2 <= timeout <= 300):
            raise RevocationPlannerConfigurationError("observed planner timeout is outside libpq's bounded interval")
        timeout = int(timeout)
        database_identity = (planner["databaseRole"], planner["tlsClientDn"],
            planner["tlsClientSerial"], planner["tlsIssuerDn"], planner["plannerSessionIdentityDigest"],
            planner["measurementDigest"], runtime["roles"]["planner"]["attestationReceiptDigest"])
        planning._validate_read_configuration((read_dsn, timeout, database_identity, planner_private_key))
        webauthn = owned["webauthn"]
        if type(webauthn) is not dict:
            raise RevocationPlannerConfigurationError("observed planner WebAuthn policy is not an exact object")
        assertion_age = webauthn["maximumChallengeAgeNs"]
        plan.contract._integer(assertion_age, minimum=1)
        plan.contract._integer(verifier["maximumInternalAgeNs"], minimum=1)
        plan_age = min(verifier["maximumInternalAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS)
        skew = authority.VERIFIER_MAX_CLOCK_SKEW_NS
        plan.contract._integer(plan_age, minimum=1)
        plan.contract._integer(skew)

        planner_encoded, planner_spki = planner["signingPublicKeyBase64Url"], planner["signingSpkiDigest"]
        verifier_encoded, verifier_spki = verifier["signingPublicKeyBase64Url"], verifier["signingSpkiDigest"]
        verifier_measurement = verifier["measurementDigest"]
        verifier_receipt = runtime["roles"]["verifier"]["attestationReceiptDigest"]
        # Full graphs and scalar settings are owned before any key callback.
        # No issuer/verifier owner or caller-produced success token is reused.
        planner_key = configuration._key(planner_encoded, work, expected_spki=planner_spki)
        verifier_key = configuration._key(verifier_encoded, work, expected_spki=verifier_spki)
        verifier_session = configuration._frame_text(configuration._VERIFIER_SESSION,
            (configuration_digest, verifier_measurement, verifier_receipt), work)
        _bind_signer(planner_private_key, planner_key, work)
        # Resolve the actual successor only after owning and binding the same
        # configured inputs. Registry construction itself imports no planner.
        from serverware import authority_transition_registry as registry

        program = registry.successor_program("webauthn.credential.revoke")
        return program.factory(read_dsn=read_dsn, connect_timeout_seconds=timeout,
            database_identity=database_identity, planner_private_key=planner_private_key,
            planner_public_key=planner_key, verifier_public_key=verifier_key,
            expected_verifier_identity={"sessionIdentityDigest": verifier_session,
                "measurementDigest": verifier_measurement, "attestationReceiptDigest": verifier_receipt},
            maximum_assertion_age_ns=assertion_age, maximum_plan_age_ns=plan_age, maximum_clock_skew_ns=skew)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RevocationPlannerConfigurationError):
            raise
        raise RevocationPlannerConfigurationError("observed planner configuration failed") from exc
