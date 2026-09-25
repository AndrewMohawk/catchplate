"""Shared measured-configuration capture and private issuer construction.

The shared capture prefix owns configuration values and checks their consistency
with the separately supplied configuration digest and launch bindings for the
private issuer and handoff-verifier mappers. It does not enroll a root key,
verify a launch or turn arbitrary dictionaries into measured configuration.
The actual service supplies its root-admitted configuration and active launch
context. Database role/TLS admission remains in the real issuer connector. No
database import, clock, private key or public route exists here.
"""
from __future__ import annotations

import hashlib
import json
import math

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from serverware import authority_contract as authority
from serverware import authority_revocation_capability as capability
from serverware import authority_revocation_capability_production as production
from serverware import authority_revocation_invocation as invocation
from serverware import authority_revocation_issuance as configured


CONFIG_SCHEMA = "serverware.policyAuthorityServiceConfiguration/v4"
GENERATION_SCHEMA = "serverware.authorityGenerationLaunchContext/v4"
MAX_CONFIGURATION_DIGESTS = 4096
_GENERATION_FIELDS = ("schema", "sequence", "digest", "predecessorDigest",
    "minimumRollbackSequence", "operationManifestDigest", "configurationPayloadBindings",
    "configurationBindingDigest", "roleBindingDigests")
_ROLE_NAMES = ("verifier", "planner", "planner-writer", "issuer", "executor")
_ROLE_FIELDS = frozenset(_ROLE_NAMES)
_CONFIGURATION_BINDING_FIELDS = frozenset({"fileDigest", "payloadDigest", "payloadSchema", "role"})
_CONFIGURATION_PAYLOAD_SCHEMAS = {
    "authority-service": CONFIG_SCHEMA,
    "witness": "serverware.policyAuthorityReplayWitnessConfiguration/v4",
}
_VERIFIER_SESSION = "serverware.policyAuthorityVerifierSession/v2"
_ISSUER_SESSION = "serverware.policyAuthorityCapabilityIssuerSession/v1"


class RevocationConfigurationError(ValueError):
    pass


class _ConfigurationCapture(capability.capture._JSONCapture):
    """Service configuration alone permits finite fractional timeout values.

    Do not weaken retained proof JSON to accommodate configuration. Preserve
    each exact float and its service-canonical spelling, including negative
    zero. Scalar float encoding has a fixed native size bound, like the base
    capture's source-bounded integer sizing; its actual token is charged.
    """

    def visit(self, value, depth=0, ancestors=frozenset()):
        if type(value) is float:
            if depth > capability.capture.MAX_JSON_DEPTH or not math.isfinite(value):
                raise RevocationConfigurationError("issuer configuration float is not finite and bounded")
            self.ledger.charge(json_nodes=1)
            self.nodes += 1
            self._bytes(len(json.dumps(value, allow_nan=False)))
            return value if self.retain else None
        return super().visit(value, depth, ancestors)


def _configuration_wire(payload, ledger):
    # Same service canonical options, with a real bounded measurement pass
    # and reservation before the full encoder. No lossy float-to-int rewrite.
    measured = _ConfigurationCapture(ledger, maximum_bytes=authority.MAX_REQUEST_BYTES, retain=False)
    measured.visit(payload)
    ledger.charge(input_bytes=measured.bytes, json_nodes=measured.nodes)
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(encoded) != measured.bytes:
        raise RevocationConfigurationError("issuer configuration changed after measurement")
    return encoded


def _frame_text(domain, values, work):
    frames = []
    for value in values:
        if type(value) is not str or not value or "\x00" in value:
            raise RevocationConfigurationError("issuer identity frame is not exact nonempty text")
        size = work.prepare_utf8(value)
        if size > 4096:
            raise RevocationConfigurationError("issuer identity frame exceeds its source bound")
        frames.append(value.encode("utf-8"))
    return capability.plan._frame(domain, tuple(frames), work)


def _key(encoded, work, *, expected_spki=None):
    # Canonical raw32 key transport, not a key object from an incoming request.
    raw = invocation._decode(encoded, 32, 32, work)
    key = production._callback(work, lambda: Ed25519PublicKey.from_public_bytes(raw))
    if not isinstance(key, Ed25519PublicKey):
        raise RevocationConfigurationError("configured issuer key is not Ed25519")
    if expected_spki is not None:
        capability.shape._digest(expected_spki)
        # Ed25519 SubjectPublicKeyInfo is exactly 44 DER bytes. Reserve the
        # actual serialization before its callback, then charge its SHA input.
        work.charge(input_bytes=44)
        der = production._callback(work, lambda: key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
        if type(der) is not bytes or len(der) != 44:
            raise RevocationConfigurationError("configured issuer SPKI is not canonical Ed25519")
        work.charge(hashes=1, input_bytes=44)
        actual = "sha256:" + hashlib.sha256(der).hexdigest()
        capability.plan._same(actual, expected_spki, work, "configured issuer key differs from its SPKI pin")
    return key


def _generation_binding(payload, generation, configuration_digest, work):
    shape = capability.shape
    shape._literal(generation["schema"], GENERATION_SCHEMA)
    for value in (generation["sequence"], payload["generationSequence"]):
        shape._integer(value, minimum=1)
    for value in (generation["minimumRollbackSequence"], payload["generationMinimumRollbackSequence"]):
        shape._integer(value)
    for value in (generation["digest"], generation["configurationBindingDigest"],
                  generation["predecessorDigest"], generation["operationManifestDigest"],
                  payload["generationBindingDigest"], payload["generationPredecessorDigest"]):
        shape._digest(value)
    if generation["minimumRollbackSequence"] > generation["sequence"]:
        raise RevocationConfigurationError("issuer launch rollback floor exceeds its generation")
    # The launch supplies the final generation digest independently. The
    # configuration binds only the acyclic, predeclared generation metadata.
    capability.plan._same((generation["sequence"], generation["configurationBindingDigest"], generation["predecessorDigest"],
        generation["minimumRollbackSequence"], generation["operationManifestDigest"]),
        (payload["generationSequence"], payload["generationBindingDigest"], payload["generationPredecessorDigest"],
         payload["generationMinimumRollbackSequence"], authority.OPERATION_MANIFEST_DIGEST), work,
        "issuer configuration differs from the active launch generation")
    bindings = generation["configurationPayloadBindings"]
    shape._array(bindings, MAX_CONFIGURATION_DIGESTS, "launch configuration payload bindings")
    # One full bounded scan, with scalar references only: no set, sort or
    # additional variable graph is constructed during order/membership checks.
    work.prepare_scan(bindings)
    previous, present = None, False
    for binding in bindings:
        shape._object(binding, _CONFIGURATION_BINDING_FIELDS, "launch configuration payload binding")
        file_digest = binding["fileDigest"]
        payload_digest = binding["payloadDigest"]
        role = binding["role"]
        shape._digest(file_digest)
        shape._digest(payload_digest)
        if type(role) is not str or role not in _CONFIGURATION_PAYLOAD_SCHEMAS:
            raise RevocationConfigurationError("launch configuration payload role is not source-supported")
        shape._literal(binding["payloadSchema"], _CONFIGURATION_PAYLOAD_SCHEMAS[role])
        # fileDigest is the first ordering field and is independently unique.
        if previous is not None and previous >= file_digest:
            raise RevocationConfigurationError("launch configuration payload bindings are not sorted and unique")
        if role == "authority-service" and payload_digest == configuration_digest:
            present = True
        previous = file_digest
    if not present:
        raise RevocationConfigurationError("issuer configuration is not in the active launch generation")
    role_pins = payload["roleBindingDigests"]
    closure_pins = payload["roleRuntimeClosureDigests"]
    launch_pins = generation["roleBindingDigests"]
    shape._object(role_pins, _ROLE_FIELDS, "configured role bindings")
    shape._object(closure_pins, _ROLE_FIELDS, "configured role runtime closures")
    shape._bounded_object(launch_pins, 256, "launch role bindings")
    work.prepare_scan(launch_pins)
    for digest in launch_pins.values():
        shape._digest(digest)
    for role in _ROLE_NAMES:
        shape._digest(role_pins[role])
        shape._digest(closure_pins[role])
        if role not in launch_pins:
            raise RevocationConfigurationError("launch role binding is missing a configured authority role")
    # These are semantic pins derived by the independently admitted package
    # path, not final launch-manifest digests or hashes recomputed off-ledger.
    capability.plan._same(tuple(role_pins[role] for role in _ROLE_NAMES),
        tuple(launch_pins[role] for role in _ROLE_NAMES), work,
        "issuer role bindings differ from the active launch generation")


def _capture_configuration_on_work(*, payload, configuration_digest, generation, work):
    """Own the actual configuration and nine launch bindings on existing work.

    This shared consistency check is not root-key or launch admission. Its
    caller must supply the separately admitted configuration commitment and
    active launch values. Capturing them never manufactures that provenance.
    """
    ledger = capability.capture._SharedLedger(work)
    capability.shape._digest(configuration_digest)
    if type(payload) is not dict or type(generation) is not dict:
        raise RevocationConfigurationError("issuer configuration requires exact local JSON objects")
    # Validate exact keys before fixed lookups can encounter a foreign
    # string subclass. The real launch-context/v4 has twenty-four fields.
    capability.shape._bounded_object(generation, 24, "issuer launch context")
    owned = _ConfigurationCapture(ledger, maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
    launch = capability.capture._JSONCapture(ledger, maximum_bytes=authority.MAX_REQUEST_BYTES).visit(
        {name: generation[name] for name in _GENERATION_FIELDS})
    capability.shape._literal(owned["schema"], CONFIG_SCHEMA)
    capability.shape._literal(owned["sourceRevision"], authority.SOURCE_REVISION)
    encoded = _configuration_wire(owned, ledger)
    computed = capability.plan._frame(CONFIG_SCHEMA, (encoded,), work)
    capability.plan._same(computed, configuration_digest, work, "issuer configuration commitment changed")
    _generation_binding(owned, launch, configuration_digest, work)
    return owned, launch


def _issuer_from_configuration_on_work(*, payload, configuration_digest, generation, work):
    """Map an owned configuration on the existing remaining work allowance.

    Only the nine bindings used from the actual twenty-four-field launch context
    are captured; its signed statement and provisioning bodies are not new
    proof inputs. The service's measured load and active guard supply admission.
    The single issuer age policy is the minimum of its measured internal age
    and the existing source verifier-response maximum; clock skew stays pinned
    to that same source policy. A stricter measured age is never widened.
    """
    try:
        owned, launch = _capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)

        roles = owned["roles"]
        if type(roles) is not dict:
            raise RevocationConfigurationError("issuer configuration roles are not an exact object")
        planner, verifier, issuer = (roles[name] for name in ("planner", "verifier", "issuer"))
        for name, role in (("planner", planner), ("verifier", verifier), ("issuer", issuer)):
            if type(role) is not dict:
                raise RevocationConfigurationError("issuer configuration role is not an exact object")
            capability.shape._literal(role["processMode"], "policy-authority-" + name)
            for field in ("measurementDigest", "attestationReceiptDigest"):
                capability.shape._digest(role[field])
        witness = owned["replayWitness"]
        if type(witness) is not dict:
            raise RevocationConfigurationError("issuer witness configuration is not an exact object")
        for digest in (witness["identityDigest"], owned["issuerSessionIdentityDigest"],
                       owned["issuerCredentialIssuanceDigest"], planner["plannerSessionIdentityDigest"]):
            capability.shape._digest(digest)
        for role in (planner, verifier):
            capability.shape._digest(role["signingSpkiDigest"])
            capability.plan._same(role["responseSigningSpkiDigest"], role["signingSpkiDigest"], work,
                "issuer signer differs from its measured response signing pin")
        capability.shape._integer(issuer["maximumInternalAgeNs"], minimum=1)
        maximum_age_ns = min(issuer["maximumInternalAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS)
        maximum_clock_skew_ns = authority.VERIFIER_MAX_CLOCK_SKEW_NS
        capability.shape._integer(maximum_age_ns, minimum=1)
        capability.shape._integer(maximum_clock_skew_ns)

        # All graphs and scalar pins above are owned before the first key
        # constructor/serialization callback. Native crypto internals are not
        # counted as JSON/hash work; actual encodings and hashes are charged.
        planner_key = _key(planner["signingPublicKeyBase64Url"], work, expected_spki=planner["signingSpkiDigest"])
        verifier_key = _key(verifier["signingPublicKeyBase64Url"], work, expected_spki=verifier["signingSpkiDigest"])
        witness_key = _key(witness["signingPublicKeyBase64Url"], work)
        verifier_session = _frame_text(_VERIFIER_SESSION,
            (configuration_digest, verifier["measurementDigest"], verifier["attestationReceiptDigest"]), work)
        issuer_session = _frame_text(_ISSUER_SESSION,
            (issuer["databaseRole"], issuer["tlsClientDn"], issuer["tlsClientSerial"], issuer["tlsIssuerDn"],
             issuer["measurementDigest"], issuer["attestationReceiptDigest"], owned["issuerCredentialIssuanceDigest"]), work)
        capability.plan._same(issuer_session, owned["issuerSessionIdentityDigest"], work,
            "issuer session does not bind its configured role, TLS and issuance pins")
        return configured.RevocationCapabilityIssuer(
            planner_public_key=planner_key, verifier_public_key=verifier_key, witness_public_key=witness_key,
            expected_planner_identity={"sessionIdentityDigest": planner["plannerSessionIdentityDigest"],
                "measurementDigest": planner["measurementDigest"], "attestationReceiptDigest": planner["attestationReceiptDigest"]},
            expected_verifier_identity={"sessionIdentityDigest": verifier_session,
                "measurementDigest": verifier["measurementDigest"], "attestationReceiptDigest": verifier["attestationReceiptDigest"]},
            expected_issuer_session_identity_digest=issuer_session,
            issuer_pins={"measurementDigest": issuer["measurementDigest"], "attestationReceiptDigest": issuer["attestationReceiptDigest"],
                "credentialIssuanceDigest": owned["issuerCredentialIssuanceDigest"], "maximumAgeNs": maximum_age_ns,
                "maximumClockSkewNs": maximum_clock_skew_ns},
            expected_configuration_digest=configuration_digest, expected_witness_identity_digest=witness["identityDigest"],
            expected_generation_sequence=launch["sequence"], expected_generation_digest=launch["digest"])
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RevocationConfigurationError):
            raise
        raise RevocationConfigurationError("revocation issuer configuration failed") from exc
