"""Root-authenticated cold activation planning scope, not current-state authority.

The independent root signs the actual configuration/runtime originals, fixed
planner purpose and resource pins, policy, complete root-vector original and
independently enrolled current-state observation endpoint/key scope.
The original vector is a root assertion about a planning snapshot: it is not
an action-time latest-head witness, execution grant or permission to consume a
session/token. No caller-produced successful material is an admission input.

This module reads no descriptor/TLS file, creates no key, journal, DB connection
or work allowance, and does not renew the signed launch interval. Actual key
delivery and filesystem/connection identities are checked by their cold owners.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

from cryptography.exceptions import InvalidSignature

from serverware import authority_current_root_vector as vector
from serverware import authority_oidc_session_activation as assertion
from serverware import authority_oidc_session_activation_journal as journal
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware import authority_webauthn_evidence_configuration as enabled
from serverware import authority_webauthn_evidence_policy as evidence_policy
from serverware import authority_webauthn_transition_policy as transition_policy
from serverware import control_plane_enrollment_bootstrap as codec
from serverware import current_root_state_bootstrap as state
from serverware import oidc_session_activation_delivery as delivery
from serverware import registration_evidence_signer_bootstrap as signing
from serverware.registration_execution_sql_bootstrap import _database_shape


authority, configuration = codec.authority, codec.configuration
capability, capture, plan, keys = codec.capability, codec.capture, codec.plan, codec.keys
authorization, shape = state.authorization, codec.capability.shape
registration, clock = assertion.registration, assertion.clock
ROLE = PROCESS_MODE = "oidc-session-activation-planner"
OPERATION = "oidc.session.activate"
SERVICE_UID = SERVICE_GID = 65507
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, DELIVERY_KEY_FD, JOURNAL_KEY_FD, JOURNAL_FD = range(198, 205)
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, DELIVERY_KEY_FD, JOURNAL_KEY_FD, JOURNAL_FD)
LISTENER_PATH = "/run/serverware/oidc-session-activation/planner.sock"
JOURNAL_PATH = "/var/lib/serverware/oidc-session-activation-planner"
TLS_PATHS = {
    "ca": "/run/serverware/oidc-session-activation-planner-tls/ca.pem",
    "clientCertificate": "/run/serverware/oidc-session-activation-planner-tls/client.crt",
    "clientKey": "/run/serverware/oidc-session-activation-planner-tls/client.key",
}
TLS_LIMITS = {"ca": 64 * 1024, "clientCertificate": 64 * 1024, "clientKey": 16 * 1024}
MIN_TLS_BYTES = 2
KEY_BYTES = 32
MAX_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_AGE_NS = 300 * 1_000_000_000
SCHEMA = "serverware.signedOidcSessionActivationPlannerBootstrap/v2"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationPlannerBootstrap/v2"
LAUNCH_SCHEMA = "serverware.oidcSessionActivationPlannerLaunch/v2"
_FALSE_FIELDS = ("hardwareBacked", "nativeStageZero", "hsmBackedKeys", "teeVerified", "externalWitnessVerified")
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_PLANNER_FIELDS = frozenset({"publicKeyBase64Url", "spkiDigest", "identity"})
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount", "bytesDigest", "identityDigest"})
_READ_ROLE_FIELDS = frozenset({"databaseRole", "connectTimeoutSeconds", "clientDn", "clientSerial", "issuerDn"})
_STATE_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"})
_AUTHN_FIELDS = frozenset({"userVerification", "allowedAuthenticatorClasses", "requireHardwareAttestation"})
_TRUST_FIELDS = frozenset({"roots", "currentBundleDigest", "currentBundleSequence"})
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "role", "operation", "configurationPayload",
    "configurationDigest", "generation", "runtimeRoleIdentities", "runtimeClosureDigest", "planner",
    "rpId", "origin", "authenticationPolicy", "trustPolicy", "maximumPlanAgeNs", "maximumClockSkewNs",
    "deliveryTtlSeconds", "databaseEndpoint", "readRole", "queryManifestDigest", "tlsFiles",
    "deliveryKeyDigest", "journalKeyDigest", "completeRootVector", "databaseId", "stateEnrollment",
    "stateEndpoint", "issuedAtEpochNs", "expiresAtEpochNs",
    "trustMode", "launch", *_FALSE_FIELDS})
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid", "peerUid", "peerGid",
    "rootPublicKeyFd", "bootstrapFd", "listenerFd", "signingKeyFd", "deliveryKeyFd", "journalKeyFd",
    "journalDirectoryFd", "inheritedFileDescriptors", "listenerPath", "requestTimeoutSeconds",
    "journalDirectoryPath", "journalDirectoryDevice", "journalDirectoryInode", "journalMaximumRecords",
    "journalQuotaBytes", "listenerSocketDevice", "listenerSocketInode", "listenerPathDevice", "listenerPathInode"})
_ROLE_NAME = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z", re.ASCII)


class OidcSessionActivationPlannerBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _PlannerMaterial:
    """Same-call owned data; no public entrypoint accepts it as proof."""

    configuration_payload: dict
    generation: dict
    runtime_role_identities: dict
    configuration_digest: str
    runtime_closure_digest: str
    planner_public_key: object
    planner_identity: dict
    planner_spki_digest: str
    rp_id: str
    origin: str
    authn_policy: dict
    trust_policy: dict
    maximum_plan_age_ns: int
    maximum_clock_skew_ns: int
    delivery_ttl_seconds: int
    reader_configuration: tuple
    delivery_key_digest: str
    journal_key_digest: str
    complete_root_vector_bytes: bytes
    complete_root_vector_digest: str
    tls_files: dict
    attestation_interval: tuple
    opening_sample: tuple
    launch: dict
    bootstrap_bytes: bytes
    state_enrollment_bytes: bytes
    state_enrollment_digest: str
    state_endpoint: tuple


def _fail(message):
    raise OidcSessionActivationPlannerBootstrapError(message)


def _text(value, label, maximum, work):
    return registration._text(value, label, maximum, work)


def _state_endpoint(value):
    shape._object(value, _STATE_ENDPOINT_FIELDS, "activation state endpoint")
    shape._literal(value["socketPath"], state.LISTENER_PATH)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for field in ("listenerUid", "listenerGid"):
        shape._integer(value[field], 0)
    # The root socket-activation manager creates the listening kernel socket;
    # pathname ownership by the state UID is a separate filesystem check.
    return (value["socketPath"], value["requestTimeoutSeconds"], 0, 0)


def _launch_shape(value, work):
    shape._object(value, _LAUNCH_FIELDS, "activation planner launch")
    for field, expected in (("schema", LAUNCH_SCHEMA), ("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH), ("journalDirectoryPath", JOURNAL_PATH)):
        shape._literal(value[field], expected)
    for field, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), ("rootPublicKeyFd", ROOT_FD),
            ("bootstrapFd", BOOTSTRAP_FD), ("listenerFd", LISTENER_FD), ("signingKeyFd", KEY_FD),
            ("deliveryKeyFd", DELIVERY_KEY_FD), ("journalKeyFd", JOURNAL_KEY_FD),
            ("journalDirectoryFd", JOURNAL_FD)):
        shape._integer(value[field], 2**32 - 2, minimum=1)
        if value[field] != expected:
            _fail("activation planner fixed resource scalar differs")
    descriptors = value["inheritedFileDescriptors"]
    shape._array(descriptors, len(INHERITED_DESCRIPTORS), "activation inherited descriptors")
    for descriptor in descriptors:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(descriptors, list(INHERITED_DESCRIPTORS), work, "activation descriptor inventory differs")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for field in ("journalDirectoryDevice", "listenerSocketDevice", "listenerPathDevice"):
        shape._integer(value[field], 2**64 - 1)
    for field in ("journalDirectoryInode", "listenerSocketInode", "listenerPathInode"):
        shape._integer(value[field], 2**64 - 1, minimum=1)
    shape._integer(value["journalMaximumRecords"], journal.MAX_RECORDS, minimum=1)
    shape._integer(value["journalQuotaBytes"], journal.MAX_QUOTA_BYTES, minimum=1)


def _payload_shape(value, work):
    shape._object(value, _PAYLOAD_FIELDS, "activation planner bootstrap")
    for field, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("operation", OPERATION), ("trustMode", "trusted-host-local")):
        shape._literal(value[field], expected)
    for field in ("configurationDigest", "runtimeClosureDigest", "queryManifestDigest", "deliveryKeyDigest", "journalKeyDigest"):
        shape._digest(value[field])
    if value["deliveryKeyDigest"] == value["journalKeyDigest"]:
        _fail("activation delivery and journal key pins are not independent")
    authorization._token(value["databaseId"])
    shape._object(value["generation"], frozenset(configuration._GENERATION_FIELDS), "activation generation")
    if type(value["configurationPayload"]) is not dict or type(value["runtimeRoleIdentities"]) is not dict:
        _fail("activation configuration/runtime originals are not exact objects")
    selected = value["planner"]
    shape._object(selected, _PLANNER_FIELDS, "dedicated activation planner")
    shape._text(selected["publicKeyBase64Url"], 43, minimum=43)
    shape._base64url(selected["publicKeyBase64Url"])
    shape._digest(selected["spkiDigest"])
    shape.validate_identity_shape(selected["identity"])
    _text(value["rpId"], "activation RP ID", 4096, work)
    _text(value["origin"], "activation origin", 8192, work)
    shape._integer(value["maximumPlanAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(value["maximumClockSkewNs"], authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    shape._integer(value["deliveryTtlSeconds"], 60, minimum=5)
    shape._object(value["authenticationPolicy"], _AUTHN_FIELDS, "activation authentication policy")
    shape._object(value["trustPolicy"], _TRUST_FIELDS, "activation trust policy")
    _database_shape(value["databaseEndpoint"])
    read = value["readRole"]
    shape._object(read, _READ_ROLE_FIELDS, "activation verifier read role")
    if type(read["databaseRole"]) is not str or _ROLE_NAME.fullmatch(read["databaseRole"]) is None:
        _fail("activation database role is outside its closed identifier grammar")
    shape._integer(read["connectTimeoutSeconds"], 300, minimum=2)
    for field in ("clientDn", "clientSerial", "issuerDn"):
        _text(read[field], "activation SQL " + field, 4096, work)
    shape._object(value["tlsFiles"], frozenset(TLS_PATHS), "activation fixed TLS files")
    for field, maximum in TLS_LIMITS.items():
        record = value["tlsFiles"][field]
        shape._object(record, frozenset({"byteCount", "bytesDigest"}), "activation TLS original")
        shape._integer(record["byteCount"], maximum, minimum=MIN_TLS_BYTES)
        shape._digest(record["bytesDigest"])
    for field, maximum in (("completeRootVector", vector.MAX_BYTES),
            ("stateEnrollment", authorization.MAX_ENROLLMENT_BYTES)):
        original = value[field]
        shape._object(original, _ORIGINAL_FIELDS, "activation " + field + " original")
        authorization.transport._transport_shape(original["base64Url"], original["byteCount"], maximum)
        for digest_field in ("bytesDigest", "identityDigest"):
            shape._digest(original[digest_field])
    _state_endpoint(value["stateEndpoint"])
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(value[field], minimum=1)
    if not 0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= MAX_RECEIPT_AGE_NS:
        _fail("activation original launch lifetime exceeds its source bound")
    if any(value[field] is not False for field in _FALSE_FIELDS):
        _fail("activation launch claims unsupported hardware or witness assurance")
    _launch_shape(value["launch"], work)


def _fresh(interval, work, opening=None):
    """Check the same signed launch clock bracket without extending it."""
    try:
        return state._fresh(interval, work, opening=opening)
    except (TypeError, ValueError, OverflowError) as exc:
        raise OidcSessionActivationPlannerBootstrapError("activation original launch interval is not live") from exc


def _processing(live_window, transport_deadline_ns, work):
    """Preserve optional inherited request bounds; never open an allowance."""
    capture._SharedLedger(work)
    if live_window is not None:
        _window, current = delivery._window(live_window, transport_deadline_ns, work)
        return current
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    previous = None

    def current():
        nonlocal previous
        observed = clock._sample_on_work(work)
        if (transport_deadline_ns is not None and observed[2] >= transport_deadline_ns
                or previous is not None and (observed[0] < previous[2] or observed[1] < previous[1])):
            _fail("activation cold processing clock reversed or inherited deadline expired")
        previous = observed
        return observed[1]

    return current


def _policies(payload, configured, work):
    """Validate real root-descriptor grammar, never fabricate a credential."""
    webauthn = configured["webauthn"]
    shape._object(webauthn, evidence_policy._WEBAUTHN_FIELDS, "configured WebAuthn policy")
    plan._same((payload["rpId"], payload["origin"]), (webauthn["rpId"], webauthn["origin"]), work,
        "activation RP/origin differ from the actual configured ceremony")
    authn, roots = payload["authenticationPolicy"], payload["trustPolicy"]
    if authn["userVerification"] != "required" or type(authn["requireHardwareAttestation"]) is not bool:
        _fail("activation authentication policy is outside the fixed profile")
    classes, configured_classes = authn["allowedAuthenticatorClasses"], webauthn["allowedAuthenticatorClasses"]
    if (type(classes) is not list or not 1 <= len(classes) <= len(assertion._CLASSES)
            or any(type(item) is not str or item not in assertion._CLASSES for item in classes)
            or len(set(classes)) != len(classes)
            or type(configured_classes) is not list or not 1 <= len(configured_classes) <= 16
            or any(type(item) is not str or not 1 <= len(item) <= 128 for item in configured_classes)
            or len(set(configured_classes)) != len(configured_classes)
            or not set(classes).issubset(configured_classes)
            or type(webauthn["requireAttestationTrusted"]) is not bool
            or webauthn["requireAttestationTrusted"] and not authn["requireHardwareAttestation"]):
        _fail("activation authentication policy weakens configured class/attestation requirements")
    shape._digest(roots["currentBundleDigest"])
    shape._integer(roots["currentBundleSequence"], minimum=1)
    descriptors = roots["roots"]
    if type(descriptors) is not list or not 1 <= len(descriptors) <= assertion.trust.MAX_ROOTS:
        _fail("activation trust root inventory is not bounded")
    policies, identities, certificates = [], set(), set()
    for record in descriptors:
        shape._object(record, assertion._ROOT_FIELDS, "activation root descriptor")
        _text(record["id"], "activation trust root ID", 4096, work)
        shape._digest(record["certificate_sha256"])
        plan._same((record["bundle_digest"], record["bundle_sequence"]),
            (roots["currentBundleDigest"], roots["currentBundleSequence"]), work,
            "activation trust descriptor belongs to another root bundle")
        if record["id"] in identities or record["certificate_sha256"] in certificates:
            _fail("activation trust root descriptors are not unique")
        identities.add(record["id"])
        certificates.add(record["certificate_sha256"])
        if record["authenticator_class"] is not None and (
                type(record["authenticator_class"]) is not str or record["authenticator_class"] not in assertion._CLASSES):
            _fail("activation root class is unsupported")
        aaguids = record["aaguids"]
        if type(aaguids) is not list or len(aaguids) > assertion.trust.MAX_ROOT_AAGUIDS:
            _fail("activation root AAGUID list is not bounded")
        for aaguid in aaguids:
            _text(aaguid, "activation root AAGUID", 128, work)
        work.prepare_copy(record)
        policies.append(configuration.production._callback(work, lambda: assertion.trust.RootTrustPolicy(
            record["id"], record["certificate_sha256"], record["authenticator_class"], tuple(aaguids),
            record["bundle_digest"], record["bundle_sequence"])))
    # Actual neutral aggregate descriptor validation; no invented trust facts
    # or successful classify() result is used to authorize this profile.
    work.prepare_copy(roots)
    configuration.production._callback(work, lambda: assertion.trust.CredentialTrustContext(tuple(policies), False))


def _planner_key(payload, configured, root, work):
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "activation configured roles")
    forbidden = [keys._spki_on_work(root, work)]
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        shape._literal(role["processMode"], "policy-authority-" + name)
        for field, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID)):
            shape._integer(role[field], 2**32 - 2, minimum=1)
            if role[field] == expected:
                _fail("activation planner identity is shared with a generic role")
        for field in ("responseSigningSpkiDigest", "measurementDigest"):
            shape._digest(role[field])
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            shape._digest(role["signingSpkiDigest"])
            configuration._key(role["signingPublicKeyBase64Url"], work, expected_spki=role["signingSpkiDigest"])
            forbidden.append(role["signingSpkiDigest"])
    enabled._require_enabled_operation(roles["planner"], OPERATION, work)
    for name in ("verifier", "planner"):
        shape._integer(roles[name]["maximumInternalAgeNs"], minimum=1)
        if payload["maximumPlanAgeNs"] > roles[name]["maximumInternalAgeNs"]:
            _fail("activation plan age widens configured internal lifetime")
    # Existing configured purpose helpers genuinely validate explicit public
    # keys. Their absence is not fallback to any generic-purpose signing key.
    value = configured.get(evidence_policy.FIELD)
    if value is not None:
        policy, _public_keys = evidence_policy._validate_policy_on_work(value, webauthn=configured["webauthn"], work=work)
        forbidden.extend(policy[name]["signingSpkiDigest"] for name in ("registration", "installation") if policy[name] is not None)
    value = configured.get(transition_policy.FIELD)
    if value is not None:
        policy, _public_keys = transition_policy._validate_policy_on_work(value, webauthn=configured["webauthn"], work=work)
        forbidden.extend(policy[name]["signingSpkiDigest"] for name in ("registration", "stage", "completion") if policy[name] is not None)
    value = configured.get(enrollment_policy.FIELD)
    if value is not None:
        policy, _public_key = enrollment_policy._validate_policy_on_work(value, payload=configured, work=work)
        forbidden.append(policy["signingSpkiDigest"])
    selected = payload["planner"]
    work.prepare_scan(forbidden)
    if selected["spkiDigest"] in forbidden:
        _fail("activation dedicated planner key reuses another root or configured purpose")
    # Identity is an explicit independent root assertion, not a synthesized
    # generic runtime-role identity or a self-referential bootstrap digest.
    # Distinct purposes/keys may legitimately share measured release bytes.
    return configuration._key(selected["publicKeyBase64Url"], work, expected_spki=selected["spkiDigest"])


def _reader_configuration(payload, configured, work):
    endpoint, selected = payload["databaseEndpoint"], payload["readRole"]
    plan._same(selected["databaseRole"], configured["roles"]["verifier"]["databaseRole"], work,
        "activation read role differs from the actual configured verifier role")
    dsn = ("host=" + endpoint["host"] + " hostaddr=" + endpoint["hostaddr"]
        + " port=" + str(endpoint["port"]) + " dbname=" + endpoint["databaseName"]
        + " user=" + selected["databaseRole"] + " sslmode=verify-full sslrootcert=" + TLS_PATHS["ca"]
        + " sslcert=" + TLS_PATHS["clientCertificate"] + " sslkey=" + TLS_PATHS["clientKey"]
        + " passfile=/dev/null gssencmode=disable")
    identity = (selected["databaseRole"], selected["clientDn"], selected["clientSerial"], selected["issuerDn"],
        *(payload["planner"]["identity"][field] for field in _IDENTITY_FIELDS))
    return (dsn, selected["connectTimeoutSeconds"], identity, payload["maximumClockSkewNs"])


def _state_enrollment(payload, generation, root, work):
    record = payload["stateEnrollment"]
    original = authorization.transport._decode(record["base64Url"], record["byteCount"],
        authorization.MAX_ENROLLMENT_BYTES, work)
    work.charge(hashes=1, input_bytes=len(original))
    digest = configuration.production._callback(work, lambda: "sha256:" + hashlib.sha256(original).hexdigest())
    plan._same(digest, record["bytesDigest"], work, "activation state enrollment raw digest differs")
    admitted = authorization._admit_enrollment_on_work(enrollment_bytes=original,
        root_public_key=root, work=work)
    plan._same(admitted.enrollment_digest, record["identityDigest"], work,
        "activation state enrollment identity differs")
    plan._same(admitted.payload["generationDigest"], generation["digest"], work,
        "activation state enrollment differs from the genuine configured generation")
    # No source configuration field maps databaseId to a DSN. The independent
    # provisioner explicitly signs that association; do not equate it with the
    # unrelated databaseName spelling or claim a signature proves DB provenance.
    plan._same(admitted.payload["databaseId"], payload["databaseId"], work,
        "activation state enrollment differs from the root-pinned database identity")
    forbidden = tuple(admitted.payload[role]["spkiDigest"] for role in ("state", "computation", "completion"))
    work.prepare_scan(forbidden)
    if payload["planner"]["spkiDigest"] in forbidden:
        _fail("activation planner key reuses an enrolled state, computation or completion key")
    return original, admitted.enrollment_digest


def _material(payload, root, opening, original, work, current):
    configured, generation = configuration._capture_configuration_on_work(payload=payload["configurationPayload"],
        configuration_digest=payload["configurationDigest"], generation=payload["generation"], work=work)
    runtime = configuration._capture_runtime_role_identities_on_work(
        runtime_role_identities=payload["runtimeRoleIdentities"], owned_payload=configured,
        configuration_digest=payload["configurationDigest"], launch=generation, work=work)
    current()
    plan._same(payload["queryManifestDigest"], configured["queryManifestDigest"], work,
        "activation query manifest differs from root-authenticated configuration")
    plan._same(payload["queryManifestDigest"], plan._QUERY_MANIFEST_DIGEST, work,
        "activation query manifest differs from actual source")
    _policies(payload, configured, work)
    current()
    planner = _planner_key(payload, configured, root, work)
    current()
    state_original, state_digest = _state_enrollment(payload, generation, root, work)
    current()
    reader = _reader_configuration(payload, configured, work)
    record = payload["completeRootVector"]
    raw = authorization.transport._decode(record["base64Url"], record["byteCount"], vector.MAX_BYTES, work)
    work.charge(hashes=1, input_bytes=len(raw))
    digest = configuration.production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())
    plan._same(digest, record["bytesDigest"], work, "activation vector raw digest differs")
    current()
    # This invokes the actual canonical/full-inventory/source/count checks,
    # not a caller-selected vector or a successful verification carrier.
    identity = vector._digest_on_work(raw, work=work)
    plan._same(identity, record["identityDigest"], work, "activation complete vector identity differs")
    current()
    return _PlannerMaterial(configured, generation, runtime, payload["configurationDigest"],
        payload["runtimeClosureDigest"], planner, payload["planner"]["identity"], payload["planner"]["spkiDigest"],
        payload["rpId"], payload["origin"], payload["authenticationPolicy"], payload["trustPolicy"],
        payload["maximumPlanAgeNs"], payload["maximumClockSkewNs"], payload["deliveryTtlSeconds"], reader,
        payload["deliveryKeyDigest"], payload["journalKeyDigest"], raw, identity, payload["tlsFiles"],
        (payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]), opening, payload["launch"], original,
        state_original, state_digest, _state_endpoint(payload["stateEndpoint"]))


def _launch_guard(interval, opening, inherited, work):
    previous = opening

    def current():
        nonlocal previous
        inherited()
        sample = _fresh(interval, work, opening=opening)
        if sample[0] < previous[2] or sample[1] < previous[1]:
            _fail("activation original launch clock reversed between callbacks")
        previous = sample
        inherited()
        return sample[1]

    return current


def _verify_on_work(*, bootstrap_bytes, root_public_key, work, live_window=None, transport_deadline_ns=None):
    """Authenticate original root bytes before any private resource selection."""
    try:
        original, root = bootstrap_bytes, root_public_key
        if type(original) is not bytes or not 2 <= len(original) <= MAX_BYTES:
            _fail("activation bootstrap is not a bounded immutable original")
        authorization._public(root)
        inherited = _processing(live_window, transport_deadline_ns, work)
        inherited()
        envelope = codec._decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed activation bootstrap")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("activation bootstrap payload is not an exact object")
        codec._canonical(original, envelope, work)
        unsigned = configuration._configuration_wire(envelope["payload"], capture._SharedLedger(work))
        inherited()
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA, unsigned, capture._SharedLedger(work))
        inherited()
        codec._canonical(original, envelope, work)
        payload = envelope["payload"]
        _payload_shape(payload, work)
        interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        current = _launch_guard(interval, opening, inherited, work)
        current()
        material = _material(payload, root, opening, original, work, current)
        codec._canonical(original, envelope, work)
        current()
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationPlannerBootstrapError):
            raise
        raise OidcSessionActivationPlannerBootstrapError("activation planner bootstrap admission failed") from exc


def _produce_on_work(*, payload, root_private_key, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Sign independently established launch/snapshot claims, never invent them."""
    try:
        private, public = root_private_key, root_public_key
        authorization._private(private)
        authorization._public(public)
        owned = configuration._ConfigurationCapture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(payload)
        inherited = _processing(live_window, transport_deadline_ns, work)
        inherited()
        _payload_shape(owned, work)
        interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        current = _launch_guard(interval, opening, inherited, work)
        # The unreturned material only runs the genuine scope/key/vector gates;
        # no placeholder signed original is emitted or accepted as authority.
        _material(owned, public, opening, b"", work, current)
        unsigned = configuration._configuration_wire(owned, capture._SharedLedger(work))
        current()
        original = signing._sign(owned, SCHEMA, MAX_BYTES, private, public, work)
        current()
        codec._canonical(unsigned, owned, work)
        current()
        return original
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationPlannerBootstrapError):
            raise
        raise OidcSessionActivationPlannerBootstrapError("activation planner bootstrap production failed") from exc
