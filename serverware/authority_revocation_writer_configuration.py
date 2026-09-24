"""Private measured-configuration mapping for original-byte planner custody.

Root-signed configuration, active launch and the writer-only DSN descriptor are
upstream service admission requirements. This mapper checks their supplied
bindings; neither its input dictionaries nor the returned persistence owner are
an admission or successful-verification token. Actual connection/TLS/privilege
admission and original-byte replay remain in the existing persistence path.
It opens no database, reads no descriptor, samples no clock and owns no signer.

Full configuration and selected launch bindings use the existing caller work.
The configuration commitment, two actual SPKI hashes and verifier-session frame
retain the four-hash schedule. Writer-to-planner alias comparisons add real B/N,
not another key decode or hash. Native key internals and bounded local scalar
admission are outside H/B/N. The owner's fifteen independent per-call inputs
are not derived here from configuration or retained context; a future action
adapter must own and authenticate those inputs before its callbacks.
"""
from __future__ import annotations

import math

from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_persistence as persistence
from serverware import authority_revocation_plan as plan
from serverware import authority_revocation_writer_connection as writer


class RevocationWriterConfigurationError(ValueError):
    pass


def _persistence_from_configuration_on_work(*, payload, configuration_digest,
                                           generation, persistence_dsn, work):
    """Construct the genuine owner from independently admitted local inputs.

    The writer's explicit planner aliases must agree with the actual planner
    role before any key callback. Its response-signing pin is a separate role
    field, not a planner-key alias or authority to sign a plan. This factory
    configures no historical clock, request/root expectations or age overrides.
    Launch consistency is checked without adding new signed plan fields.
    """
    try:
        owned, _launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        writer.reader._bounded_text(persistence_dsn, 65536)
        if "\n" in persistence_dsn or "\r" in persistence_dsn:
            raise RevocationWriterConfigurationError("revocation writer DSN is not one bounded descriptor value")
        roles = owned["roles"]
        if type(roles) is not dict:
            raise RevocationWriterConfigurationError("revocation writer roles are not an exact object")
        planner, verifier, writer_role = (roles[name] for name in ("planner", "verifier", "planner-writer"))
        for name, role in (("planner", planner), ("verifier", verifier), ("planner-writer", writer_role)):
            if type(role) is not dict:
                raise RevocationWriterConfigurationError("revocation writer role is not an exact object")
            plan.contract._literal(role["processMode"], "policy-authority-" + name)
            for field in ("measurementDigest", "attestationReceiptDigest", "responseSigningSpkiDigest"):
                plan.contract._digest(role[field])
        for role in (planner, verifier):
            plan.contract._digest(role["signingSpkiDigest"])
            plan._same(role["responseSigningSpkiDigest"], role["signingSpkiDigest"], work,
                "revocation writer key differs from its measured response pin")
        plan.contract._digest(planner["plannerSessionIdentityDigest"])
        plan.contract._digest(writer_role["plannerSessionIdentityDigest"])
        plan.contract._digest(writer_role["plannerSigningSpkiDigest"])
        plan._same(owned["queryManifestDigest"], plan._QUERY_MANIFEST_DIGEST, work,
            "revocation writer configuration differs from the source query manifest")
        plan._same((writer_role["plannerSessionIdentityDigest"], writer_role["plannerSigningSpkiDigest"],
            writer_role["plannerSigningPublicKeyBase64Url"]),
            (planner["plannerSessionIdentityDigest"], planner["signingSpkiDigest"],
             planner["signingPublicKeyBase64Url"]), work,
            "revocation writer planner aliases differ from the configured planner")

        timeout = writer_role["databaseConnectTimeoutSeconds"]
        if (type(timeout) not in (int, float)
                or (type(timeout) is float and not math.isfinite(timeout))
                or not 2 <= timeout <= 300):
            raise RevocationWriterConfigurationError("revocation writer timeout is outside libpq's bounded interval")
        timeout = int(timeout)
        database_identity = (writer_role["databaseRole"], writer_role["tlsClientDn"],
            writer_role["tlsClientSerial"], writer_role["tlsIssuerDn"])
        writer._validate_database_identity(database_identity)

        # All configuration graphs, alias joins and scalar settings above are
        # owned before these genuine, work-guarded key callbacks. Decode only
        # the actual planner/verifier keys; equality binds the writer alias to
        # that same canonical raw32 planner transport without a third decode.
        planner_key = configuration._key(planner["signingPublicKeyBase64Url"], work,
            expected_spki=planner["signingSpkiDigest"])
        verifier_key = configuration._key(verifier["signingPublicKeyBase64Url"], work,
            expected_spki=verifier["signingSpkiDigest"])
        verifier_session = configuration._frame_text(configuration._VERIFIER_SESSION,
            (configuration_digest, verifier["measurementDigest"], verifier["attestationReceiptDigest"]), work)
        return persistence.RevocationPlannerPersistence(
            persistence_dsn=persistence_dsn, connect_timeout_seconds=timeout,
            planner_public_key=planner_key, verifier_public_key=verifier_key,
            expected_planner_identity={"sessionIdentityDigest": planner["plannerSessionIdentityDigest"],
                "measurementDigest": planner["measurementDigest"], "attestationReceiptDigest": planner["attestationReceiptDigest"]},
            expected_verifier_identity={"sessionIdentityDigest": verifier_session,
                "measurementDigest": verifier["measurementDigest"], "attestationReceiptDigest": verifier["attestationReceiptDigest"]},
            writer_database_identity=database_identity)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RevocationWriterConfigurationError):
            raise
        raise RevocationWriterConfigurationError("revocation writer configuration failed") from exc
