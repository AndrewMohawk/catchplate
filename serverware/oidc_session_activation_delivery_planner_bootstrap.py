"""Root-original consume-planner admission; no launch or execution capability.

This fixed profile independently binds the current consume request/configuration,
fresh history purpose, state snapshot, keys and resources. The closed v2 profile
also pins separate execution-export custody; it has no v1 fallback. This module
neither delivers descriptors nor opens a listener. No received material is
accepted as authority.

The separately named historical verifier authenticates the same original v2
scope as data for fresh completion custody. It returns a distinct result and
does not call the live launch guard or renew either original interval.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from cryptography.exceptions import InvalidSignature

from serverware import authority_oidc_session_activation_delivery_journal as journal
from serverware import authority_oidc_session_activation_delivery_state as delivery_state
from serverware import authority_oidc_session_activation_execution_expectations as expectations
from serverware import oidc_session_activation_history_custody_bootstrap as history
from serverware import oidc_session_activation_planner_bootstrap as shared


authority, configuration, capability = shared.authority, shared.configuration, shared.capability
capture, plan, keys, shape = shared.capture, shared.plan, shared.keys, shared.shape
registration, clock, authorization = shared.registration, shared.clock, shared.authorization
OPERATION = delivery_state.OPERATION
ROLE = PROCESS_MODE = "oidc-session-activation-delivery-planner"
SERVICE_UID = SERVICE_GID = 65501
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, HISTORY_FD, BUNDLE_KEY_FD, DELIVERY_KEY_FD, KEY_FD, JOURNAL_KEY_FD, JOURNAL_FD = range(198, 207)
EXECUTION_BUNDLE_KEY_FD, EXECUTION_STORE_FD = 207, 208
INHERITED_DESCRIPTORS = tuple(range(198, 209))
LISTENER_PATH = "/run/serverware/oidc-session-activation/delivery-planner.sock"
JOURNAL_PATH = "/var/lib/serverware/oidc-session-activation-delivery-planner"
EXECUTION_STORE_PATH = "/var/lib/serverware/oidc-session-activation-delivery-execution"
EXECUTION_BUNDLE_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-delivery-execution-bundle-key"
TLS_PATHS = {
    "ca": "/run/serverware/oidc-session-activation-delivery-planner-tls/ca.pem",
    "clientCertificate": "/run/serverware/oidc-session-activation-delivery-planner-tls/client.crt",
    "clientKey": "/run/serverware/oidc-session-activation-delivery-planner-tls/client.key",
}
TLS_LIMITS, MIN_TLS_BYTES = shared.TLS_LIMITS, shared.MIN_TLS_BYTES
MAX_BYTES = 4 * 1024 * 1024
_INTAKE_METADATA_BYTES = 128 * 1024
SCHEMA = "serverware.signedOidcSessionActivationDeliveryPlannerBootstrap/v2"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationDeliveryPlannerBootstrap/v2"
BRIDGE_SCHEMA = "serverware.signedOidcSessionActivationDeliveryPlannerBootstrap/v3"
BRIDGE_PAYLOAD_SCHEMA = "serverware.oidcSessionActivationDeliveryPlannerBootstrap/v3"
LAUNCH_SCHEMA = "serverware.oidcSessionActivationDeliveryPlannerLaunch/v2"
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "role", "operation", "configurationPayload",
    "configurationDigest", "generation", "runtimeRoleIdentities", "runtimeClosureDigest", "planner",
    "authenticationPolicy", "trustPolicy", "maximumPlanAgeNs", "maximumClockSkewNs", "consumeRequest",
    "activationExpectations", "activationScope", "historyCustody", "historyReceiverIdentity",
    "databaseEndpoint", "readRole", "queryManifestDigest", "tlsFiles", "journalKeyDigest", "executionBundleKeyDigest",
    "completeRootVector", "databaseId", "stateEnrollment", "stateEndpoint", "issuedAtEpochNs",
    "expiresAtEpochNs", "trustMode", "launch", *shared._FALSE_FIELDS})
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid", "peerUid", "peerGid",
    "rootPublicKeyFd", "bootstrapFd", "listenerFd", "historyCustodyFd", "bundleKeyFd", "deliveryKeyFd",
    "signingKeyFd", "journalKeyFd", "journalDirectoryFd", "inheritedFileDescriptors", "listenerPath",
    "requestTimeoutSeconds", "journalDirectoryPath", "journalDirectoryDevice", "journalDirectoryInode",
    "journalMaximumRecords", "journalQuotaBytes", "listenerSocketDevice", "listenerSocketInode",
    "listenerPathDevice", "listenerPathInode", "executionBundleKeyFd", "executionStoreDirectoryFd",
    "executionStoreDirectoryPath", "executionStoreDirectoryDevice", "executionStoreDirectoryInode",
    "executionStoreMaximumRecords", "executionStoreQuotaBytes"})
_SCOPE_FIELDS = frozenset({"authorizationDigest", "databaseId", "generationDigest", "pendingSequence",
    "pendingHeadDigest", "fence"})


class OidcSessionActivationDeliveryPlannerBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _PlannerMaterial:
    payload: dict
    bootstrap_bytes: bytes
    history_custody_bytes: bytes
    history_material: object
    consume_request_bytes: bytes
    planner_public_key: object
    reader_configuration: tuple
    state_enrollment_bytes: bytes
    state_enrollment_digest: str
    complete_root_vector_bytes: bytes
    complete_root_vector_digest: str
    state_endpoint: tuple
    attestation_interval: tuple
    opening_sample: tuple
    execution_bundle_key_digest: str


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalPlannerMaterial(_PlannerMaterial):
    """Original signed planning data, not a live constructor result."""


def _fail(message):
    raise OidcSessionActivationDeliveryPlannerBootstrapError(message)


def _intake_reservation(original_lengths):
    """Length-only cold, duplicate-admission and runtime-history captures.

    Actual nested v7 policy/current originals are contained by the original
    history length. This tightens the existing ceiling, never resets it.
    """
    limits = (16 * 1024, MAX_BYTES, history.MAX_BYTES)
    if (type(original_lengths) is not tuple or len(original_lengths) != 3
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(original_lengths, limits))):
        _fail("consume planner intake requires exact bounded cold lengths")
    reserved = 16 * sum(original_lengths) + _INTAKE_METADATA_BYTES
    if reserved >= authority.MAX_RESULT_BYTES:
        _fail("consume planner cold captures exhaust the existing original ceiling")
    return reserved


def _sha(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return configuration.production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())


def _same_bytes(left, right, work, label):
    work.charge(input_bytes=len(left) + len(right))
    if left != right:
        _fail(label)


def _launch(value, work):
    shape._object(value, _LAUNCH_FIELDS, "consume planner launch")
    for name, expected in (("schema", LAUNCH_SCHEMA), ("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH), ("journalDirectoryPath", JOURNAL_PATH),
            ("executionStoreDirectoryPath", EXECUTION_STORE_PATH)):
        shape._literal(value[name], expected)
    for name, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), ("rootPublicKeyFd", ROOT_FD),
            ("bootstrapFd", BOOTSTRAP_FD), ("listenerFd", LISTENER_FD), ("historyCustodyFd", HISTORY_FD),
            ("bundleKeyFd", BUNDLE_KEY_FD), ("deliveryKeyFd", DELIVERY_KEY_FD), ("signingKeyFd", KEY_FD),
            ("journalKeyFd", JOURNAL_KEY_FD), ("journalDirectoryFd", JOURNAL_FD),
            ("executionBundleKeyFd", EXECUTION_BUNDLE_KEY_FD), ("executionStoreDirectoryFd", EXECUTION_STORE_FD)):
        shape._integer(value[name], 2**32 - 2, minimum=1)
        if value[name] != expected:
            _fail("consume launch fixed resource differs")
    shape._array(value["inheritedFileDescriptors"], 11, "consume descriptor inventory")
    for descriptor in value["inheritedFileDescriptors"]:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(value["inheritedFileDescriptors"], list(INHERITED_DESCRIPTORS), work,
        "consume descriptor inventory differs")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("journalDirectoryDevice", "executionStoreDirectoryDevice", "listenerSocketDevice", "listenerPathDevice"):
        shape._integer(value[name], 2**64 - 1)
    for name in ("journalDirectoryInode", "executionStoreDirectoryInode", "listenerSocketInode", "listenerPathInode"):
        shape._integer(value[name], 2**64 - 1, minimum=1)
    shape._integer(value["journalMaximumRecords"], journal.MAX_RECORDS, minimum=1)
    shape._integer(value["journalQuotaBytes"], journal.MAX_QUOTA_BYTES, minimum=1)
    shape._integer(value["executionStoreMaximumRecords"], journal.MAX_RECORDS, minimum=1)
    shape._integer(value["executionStoreQuotaBytes"], journal.MAX_QUOTA_BYTES, minimum=1)


def _payload(value, work):
    shape._object(value, _PAYLOAD_FIELDS, "consume planner bootstrap")
    if value["schema"] not in (PAYLOAD_SCHEMA, BRIDGE_PAYLOAD_SCHEMA):
        _fail("consume planner payload has an unsupported fixed profile")
    for name, expected in (("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("operation", OPERATION), ("trustMode", "trusted-host-local")):
        shape._literal(value[name], expected)
    for name in ("configurationDigest", "runtimeClosureDigest", "queryManifestDigest", "journalKeyDigest", "executionBundleKeyDigest"):
        shape._digest(value[name])
    authorization._token(value["databaseId"])
    shape._object(value["generation"], frozenset(configuration._GENERATION_FIELDS), "consume generation")
    if type(value["configurationPayload"]) is not dict or type(value["runtimeRoleIdentities"]) is not dict:
        _fail("consume configuration/runtime originals are not exact objects")
    selected = value["planner"]
    shape._object(selected, shared._PLANNER_FIELDS, "dedicated consume planner")
    shape._text(selected["publicKeyBase64Url"], 43, minimum=43)
    shape._base64url(selected["publicKeyBase64Url"])
    shape._digest(selected["spkiDigest"])
    shape.validate_identity_shape(selected["identity"])
    shape.validate_identity_shape(value["historyReceiverIdentity"])
    shape._integer(value["maximumPlanAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(value["maximumClockSkewNs"], authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    shape._object(value["authenticationPolicy"], shared._AUTHN_FIELDS, "consume authentication policy")
    shape._object(value["trustPolicy"], shared._TRUST_FIELDS, "consume trust policy")
    shared._database_shape(value["databaseEndpoint"])
    read = value["readRole"]
    shape._object(read, shared._READ_ROLE_FIELDS, "consume read role")
    if type(read["databaseRole"]) is not str or shared._ROLE_NAME.fullmatch(read["databaseRole"]) is None:
        _fail("consume database role is outside the fixed grammar")
    shape._integer(read["connectTimeoutSeconds"], 300, minimum=2)
    for name in ("clientDn", "clientSerial", "issuerDn"):
        registration._text(read[name], "consume SQL " + name, 4096, work)
    shape._object(value["tlsFiles"], frozenset(TLS_PATHS), "consume TLS files")
    for name, maximum in TLS_LIMITS.items():
        record = value["tlsFiles"][name]
        shape._object(record, frozenset({"byteCount", "bytesDigest"}), "consume TLS pin")
        shape._integer(record["byteCount"], maximum, minimum=MIN_TLS_BYTES)
        shape._digest(record["bytesDigest"])
    shape._object(value["historyCustody"], frozenset({"byteCount", "bytesDigest"}), "consume history original")
    shape._integer(value["historyCustody"]["byteCount"], history.MAX_BYTES, minimum=2)
    shape._digest(value["historyCustody"]["bytesDigest"])
    for name, maximum in (("completeRootVector", shared.vector.MAX_BYTES),
            ("stateEnrollment", authorization.MAX_ENROLLMENT_BYTES)):
        record = value[name]
        shape._object(record, shared._ORIGINAL_FIELDS, "consume " + name)
        authorization.transport._transport_shape(record["base64Url"], record["byteCount"], maximum)
        shape._digest(record["bytesDigest"])
        shape._digest(record["identityDigest"])
    shape._object(value["activationScope"], _SCOPE_FIELDS, "independent activation scope")
    for name in ("authorizationDigest", "generationDigest", "pendingHeadDigest"):
        shape._digest(value["activationScope"][name])
    authorization._token(value["activationScope"]["databaseId"])
    for name in ("pendingSequence", "fence"):
        shape._integer(value["activationScope"][name], minimum=1)
    shared._state_endpoint(value["stateEndpoint"])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(value[name], minimum=1)
    if not 0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= shared.MAX_RECEIPT_AGE_NS:
        _fail("consume launch lifetime exceeds its source bound")
    if any(value[name] is not False for name in shared._FALSE_FIELDS):
        _fail("consume launch claims unsupported hardware or witness assurance")
    _launch(value["launch"], work)


def _planner_key(payload, configured, nested, root, work):
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "consume configured roles")
    forbidden = [keys._spki_on_work(root, work), nested.planner.planner_spki_digest]
    if nested.bridge_policy is not None:
        forbidden.extend((keys._spki_on_work(nested.historical_root_public_key, work),
            nested.bridge_policy.current_planner.planner_spki_digest))
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        shape._literal(role["processMode"], "policy-authority-" + name)
        for field in ("serviceUid", "serviceGid"):
            shape._integer(role[field], 2**32 - 2, minimum=1)
            if role[field] == SERVICE_UID:
                _fail("consume planner reuses a generic role identity")
        shape._digest(role["responseSigningSpkiDigest"])
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            configuration._key(role["signingPublicKeyBase64Url"], work, expected_spki=role["signingSpkiDigest"])
            forbidden.append(role["signingSpkiDigest"])
            shape._integer(role["maximumInternalAgeNs"], minimum=1)
            if payload["maximumPlanAgeNs"] > role["maximumInternalAgeNs"]:
                _fail("consume plan lifetime widens configured policy")
    shared.enabled._require_enabled_operation(roles["planner"], OPERATION, work)
    for module, names in ((shared.evidence_policy, ("registration", "installation")),
            (shared.transition_policy, ("registration", "stage", "completion"))):
        value = configured.get(module.FIELD)
        if value is not None:
            policy, _ = module._validate_policy_on_work(value, webauthn=configured["webauthn"], work=work)
            forbidden.extend(policy[name]["signingSpkiDigest"] for name in names if policy[name] is not None)
    value = configured.get(shared.enrollment_policy.FIELD)
    if value is not None:
        policy, _ = shared.enrollment_policy._validate_policy_on_work(value, payload=configured, work=work)
        forbidden.append(policy["signingSpkiDigest"])
    work.prepare_scan(forbidden)
    if payload["planner"]["spkiDigest"] in forbidden:
        _fail("consume planner key is not purpose-separated")
    return configuration._key(payload["planner"]["publicKeyBase64Url"], work,
        expected_spki=payload["planner"]["spkiDigest"])


def _material(payload, original, custody, root, window, bound, opening, current, work,
        *, historical=False, _continuity=None):
    if type(historical) is not bool:
        _fail("consume bootstrap internal history selector is not exact")
    configured, generation = configuration._capture_configuration_on_work(payload=payload["configurationPayload"],
        configuration_digest=payload["configurationDigest"], generation=payload["generation"], work=work)
    configuration._capture_runtime_role_identities_on_work(runtime_role_identities=payload["runtimeRoleIdentities"],
        owned_payload=configured, configuration_digest=payload["configurationDigest"], launch=generation, work=work)
    current()
    plan._same((payload["queryManifestDigest"], configured["queryManifestDigest"]),
        (plan._QUERY_MANIFEST_DIGEST, plan._QUERY_MANIFEST_DIGEST), work, "consume query manifest differs")
    # The neutral policy validator uses the actual configured RP/origin only
    # to validate policy grammar. Neither is a new consume permission field.
    shared._policies({"rpId": configured["webauthn"]["rpId"], "origin": configured["webauthn"]["origin"],
        "authenticationPolicy": payload["authenticationPolicy"], "trustPolicy": payload["trustPolicy"]}, configured, work)
    current()
    pin = payload["historyCustody"]
    if len(custody) != pin["byteCount"]:
        _fail("consume history original length differs")
    plan._same(_sha(custody, work), pin["bytesDigest"], work, "consume history original digest differs")
    bridged = payload["schema"] == BRIDGE_PAYLOAD_SCHEMA
    if bridged and historical:
        _fail("bridged consume planner has no implicit historical execution profile")
    verifier = (history._verify_bridge_consume_on_work if bridged else
        history._verify_historical_consume_on_work if historical else history._verify_consume_on_work)
    continuity_arguments = {}
    if _continuity is not None:
        continuity_arguments["_continuity"] = _continuity
    nested = verifier(custody_bytes=custody, root_public_key=root,
        work=work, live_window=window, transport_deadline_ns=bound, **continuity_arguments)
    current()
    if bridged and nested.bridge_policy is None:
        _fail("bridged consume planner lacks the genuine current-root policy original")
    output = nested.bridge_policy.current_planner if bridged else nested.planner
    plan._same((payload["configurationDigest"], generation["digest"], payload["runtimeClosureDigest"],
        payload["historyReceiverIdentity"]), (output.configuration_digest, output.generation["digest"],
        output.runtime_closure_digest, nested.receiver_identity), work, "consume independently authorized output cohort differs")
    plan._same(payload["runtimeRoleIdentities"], output.runtime_role_identities, work,
        "consume/history runtime identity cohort differs")
    if (payload["maximumPlanAgeNs"] > output.maximum_plan_age_ns
            or payload["maximumClockSkewNs"] > output.maximum_clock_skew_ns):
        _fail("consume processing policy widens nested historical custody")
    if bridged:
        policy = nested.bridge_policy
        expected_static = {**policy.consume_planner,
            "configurationPayload": output.configuration_payload,
            "authenticationPolicy": output.authn_policy, "trustPolicy": output.trust_policy,
            "maximumPlanAgeNs": output.maximum_plan_age_ns,
            "maximumClockSkewNs": output.maximum_clock_skew_ns}
        actual_bytes = configuration._configuration_wire(
            {name: payload[name] for name in expected_static}, capture._SharedLedger(work))
        expected_bytes = configuration._configuration_wire(expected_static, capture._SharedLedger(work))
        _same_bytes(actual_bytes, expected_bytes, work, "bridged consume independent current configuration")
        plan._same((payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]),
            nested.attestation_interval, work, "bridged consume paired fresh policy interval")
        policy.live()
        current()
    if payload["journalKeyDigest"] in (nested.bundle_key_digest, nested.delivery_key_digest,
            nested.planner.journal_key_digest):
        _fail("consume journal key reuses an activation custody purpose")
    for forbidden in (payload["journalKeyDigest"], nested.bundle_key_digest,
            nested.delivery_key_digest, nested.planner.journal_key_digest):
        work.prepare_comparison(payload["executionBundleKeyDigest"], forbidden)
        if payload["executionBundleKeyDigest"] == forbidden:
            _fail("consume execution-export key reuses a historical or journal purpose")
    launch, old_launch = payload["launch"], nested.planner.launch
    directory = (launch["journalDirectoryDevice"], launch["journalDirectoryInode"])
    if directory in ((old_launch["journalDirectoryDevice"], old_launch["journalDirectoryInode"]),
            (old_launch["executionStoreDirectoryDevice"], old_launch["executionStoreDirectoryInode"])):
        _fail("consume journal reuses an activation original or export directory")
    export_directory = (launch["executionStoreDirectoryDevice"], launch["executionStoreDirectoryInode"])
    if export_directory in (directory,
            (old_launch["journalDirectoryDevice"], old_launch["journalDirectoryInode"]),
            (old_launch["executionStoreDirectoryDevice"], old_launch["executionStoreDirectoryInode"])):
        _fail("consume execution store reuses a consume or historical originals directory")
    request = history._consume_request_on_work(payload["consumeRequest"], work)
    _same_bytes(request, nested.consume_request_bytes, work, "independent consume request differs from history purpose")
    old = expectations._capture_on_work(payload["activationExpectations"], work=work)
    plan._same((old["scope"]["configurationDigest"], old["scope"]["plannerSpkiDigest"], old["scope"]["plannerIdentity"]),
        (nested.planner.configuration_digest, nested.planner.planner_spki_digest, nested.planner.planner_identity),
        work, "activation expectations differ from historical planner")
    planner = _planner_key(payload, configured, nested, root, work)
    state_original, state_digest = shared._state_enrollment(payload, generation, root, work)
    _same_bytes(state_original, output.state_enrollment_bytes, work,
        "consume independently authorized current-root enrollment original differs")
    plan._same((payload["activationScope"]["databaseId"], payload["activationScope"]["generationDigest"]),
        (payload["databaseId"], generation["digest"]), work, "activation provenance database/generation differs")
    if bridged:
        # The bridge authenticates equal COMPLETE state payloads under their
        # separate roots. It authorizes key rotation, not state migration.
        plan._same(payload["activationScope"]["generationDigest"], nested.planner.generation["digest"],
            work, "bridged consume retains original activation generation")
    record = payload["completeRootVector"]
    vector = authorization.transport._decode(record["base64Url"], record["byteCount"], shared.vector.MAX_BYTES, work)
    plan._same(_sha(vector, work), record["bytesDigest"], work, "consume vector bytes differ")
    identity = shared.vector._digest_on_work(vector, work=work)
    plan._same(identity, record["identityDigest"], work, "consume complete vector identity differs")
    selected, endpoint = payload["readRole"], payload["databaseEndpoint"]
    plan._same(selected["databaseRole"], configured["roles"]["verifier"]["databaseRole"], work,
        "consume read role differs from configured verifier")
    dsn = ("host=" + endpoint["host"] + " hostaddr=" + endpoint["hostaddr"] + " port=" + str(endpoint["port"])
        + " dbname=" + endpoint["databaseName"] + " user=" + selected["databaseRole"]
        + " sslmode=verify-full sslrootcert=" + TLS_PATHS["ca"] + " sslcert=" + TLS_PATHS["clientCertificate"]
        + " sslkey=" + TLS_PATHS["clientKey"] + " passfile=/dev/null gssencmode=disable")
    read_identity = (selected["databaseRole"], selected["clientDn"], selected["clientSerial"], selected["issuerDn"],
        *(payload["planner"]["identity"][name] for name in shared._IDENTITY_FIELDS))
    current()
    material_type = _HistoricalPlannerMaterial if historical else _PlannerMaterial
    return material_type(payload, original, custody, nested, request, planner,
        (dsn, selected["connectTimeoutSeconds"], read_identity, payload["maximumClockSkewNs"]),
        state_original, state_digest, vector, identity, shared._state_endpoint(payload["stateEndpoint"]),
        (payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]), opening, payload["executionBundleKeyDigest"])


def _verify_on_work(*, bootstrap_bytes, history_custody_bytes, root_public_key,
        live_window, transport_deadline_ns, work, _continuity=None):
    try:
        original, custody, root = bootstrap_bytes, history_custody_bytes, root_public_key
        if (type(original) is not bytes or not 2 <= len(original) <= MAX_BYTES
                or type(custody) is not bytes or not 2 <= len(custody) <= history.MAX_BYTES):
            _fail("consume bootstrap/history requires bounded immutable originals")
        _intake_reservation((16 * 1024, len(original), len(custody)))
        authorization._public(root)
        window = clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        bound = min(window[4], transport_deadline_ns)
        inherited = shared._processing(window, bound, work, _continuity=_continuity)
        inherited()
        envelope = shared.codec._decode(original, work)
        shape._object(envelope, shared._ENVELOPE_FIELDS, "signed consume bootstrap")
        schema = envelope["schema"]
        if schema not in (SCHEMA, BRIDGE_SCHEMA):
            _fail("consume planner has an unsupported signed profile")
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("consume bootstrap payload is not an exact object")
        shared.codec._canonical(original, envelope, work)
        unsigned = configuration._configuration_wire(envelope["payload"], capture._SharedLedger(work))
        capability._signature(root, envelope["signatureBase64Url"], schema, unsigned, capture._SharedLedger(work))
        inherited()
        payload = envelope["payload"]
        _payload(payload, work)
        shape._literal(payload["schema"], BRIDGE_PAYLOAD_SCHEMA if schema == BRIDGE_SCHEMA else PAYLOAD_SCHEMA)
        interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        opening = shared._fresh(interval, work)
        current = shared._launch_guard(interval, opening, inherited, work, _continuity=_continuity)
        material = _material(payload, original, custody, root, window, bound, opening, current, work,
            _continuity=_continuity)
        shared.codec._canonical(original, envelope, work)
        current()
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationDeliveryPlannerBootstrapError):
            raise
        raise OidcSessionActivationDeliveryPlannerBootstrapError("consume planner bootstrap admission failed") from exc


def _verify_historical_on_work(*, bootstrap_bytes, history_custody_bytes, root_public_key,
        live_window, transport_deadline_ns, work, _continuity=None):
    """Original v2 planner/history data; never renew either old launch."""
    try:
        original, custody, root = bootstrap_bytes, history_custody_bytes, root_public_key
        if (type(original) is not bytes or not 2 <= len(original) <= MAX_BYTES
                or type(custody) is not bytes or not 2 <= len(custody) <= history.MAX_BYTES):
            _fail("historical consume planner requires bounded immutable originals")
        authorization._public(root)
        window = clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        bound = min(window[4], transport_deadline_ns)
        current = shared._processing(window, bound, work, _continuity=_continuity)
        current()
        envelope = shared.codec._decode(original, work)
        shape._object(envelope, shared._ENVELOPE_FIELDS, "historical signed consume bootstrap")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("historical consume bootstrap payload is not an exact object")
        shared.codec._canonical(original, envelope, work)
        unsigned = configuration._configuration_wire(envelope["payload"], capture._SharedLedger(work))
        current()
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA, unsigned, capture._SharedLedger(work))
        current()
        payload = envelope["payload"]
        _payload(payload, work)
        if payload["issuedAtEpochNs"] > current():
            _fail("historical consume planner is future-issued")
        opening = clock._sample_on_work(work)
        if _continuity is not None:
            current((opening[1], opening[2]))
        else:
            current()
        result = _material(payload, original, custody, root, window, bound, opening, current, work,
            historical=True, _continuity=_continuity)
        shared.codec._canonical(original, envelope, work)
        current()
        return result
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationDeliveryPlannerBootstrapError):
            raise
        raise OidcSessionActivationDeliveryPlannerBootstrapError("historical consume planner admission failed") from exc


def _produce_on_work(*, payload, history_custody_bytes, root_private_key, root_public_key,
        live_window, transport_deadline_ns, work, _continuity=None):
    private, root, custody = root_private_key, root_public_key, history_custody_bytes
    authorization._private(private)
    authorization._public(root)
    if type(custody) is not bytes or not 2 <= len(custody) <= history.MAX_BYTES:
        _fail("consume history requires bounded immutable originals")
    owned = configuration._ConfigurationCapture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(payload)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    inherited = shared._processing(window, bound, work, _continuity=_continuity)
    inherited()
    _payload(owned, work)
    schema = BRIDGE_SCHEMA if owned["schema"] == BRIDGE_PAYLOAD_SCHEMA else SCHEMA
    interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
    opening = shared._fresh(interval, work)
    current = shared._launch_guard(interval, opening, inherited, work, _continuity=_continuity)
    _material(owned, b"", custody, root, window, bound, opening, current, work, _continuity=_continuity)
    unsigned = configuration._configuration_wire(owned, capture._SharedLedger(work))
    current()
    original = shared.signing._sign(owned, schema, MAX_BYTES, private, root, work)
    shared.codec._canonical(unsigned, owned, work)
    current()
    return original
