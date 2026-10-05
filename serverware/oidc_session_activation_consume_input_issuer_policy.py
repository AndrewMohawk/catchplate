"""Fresh root-original policy for deriving one request's consume inputs.

The independently pinned activation planner is authenticated as historical
evidence, never renewed launch authority. Static pins belong to this signed
policy; completion controls and a typed consume request belong to the later
original-only producer. No resource observation, key custody or service is here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import time

from cryptography.exceptions import InvalidSignature

from serverware import authority_oidc_session_activation_reservation_records as reservation
from serverware import authority_successor_execution_window as processing
from serverware import oidc_session_activation_delivery_planner_bootstrap as consume
from serverware import oidc_session_activation_planner_bootstrap as activation
from serverware.authority_query_read_work import QueryReadWorkError


history = consume.history
authorization, shape, plan = activation.authorization, activation.shape, activation.plan
capture, clock, keys = activation.capture, activation.clock, activation.keys
authority, configuration, capability = activation.authority, activation.configuration, activation.capability
production = configuration.production
PURPOSE = "issue-oidc-session-activation-consume-inputs"
SCHEMA = "serverware.signedOidcSessionActivationConsumeInputIssuerPolicy/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationConsumeInputIssuerPolicy/v1"
V2_SCHEMA = "serverware.signedOidcSessionActivationConsumeInputIssuerPolicy/v2"
V2_PAYLOAD_SCHEMA = "serverware.oidcSessionActivationConsumeInputIssuerPolicy/v2"
V3_SCHEMA = "serverware.signedOidcSessionActivationConsumeInputIssuerPolicy/v3"
V3_PAYLOAD_SCHEMA = "serverware.oidcSessionActivationConsumeInputIssuerPolicy/v3"
SIGNATURE_DOMAIN = SCHEMA
IDENTITY_DOMAIN = "serverware.oidcSessionActivationConsumeInputIssuerPolicyIdentity/v1"
ACTIVATION_PLANNER_BOOTSTRAP_IDENTITY_DOMAIN = "serverware.oidcSessionActivationConsumeInputIssuerActivationPlannerBootstrapIdentity/v1"
V1_MAX_BYTES = 64 * 1024
V2_MAX_BYTES = 6 * 1024 * 1024
MAX_BYTES = V2_MAX_BYTES
MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES = activation.MAX_BYTES
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
MAX_NODES, MAX_DEPTH = 512, 6
MAX_RECEIPT_AGE_NS = activation.MAX_RECEIPT_AGE_NS
HISTORY_FIELDS = frozenset({"receiverIdentity", "bundleKeyDigest", "deliveryKeyDigest"})
CONSUME_PLANNER_FIELDS = frozenset({"planner", "databaseEndpoint", "readRole", "tlsFiles",
    "stateEndpoint", "journalKeyDigest", "executionBundleKeyDigest", "launch"})
PREDECESSOR_FIELDS = frozenset({"sequence", "headDigest", "fence"})
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "trustMode",
    "activationPlannerBootstrapDigest", "history", "consumePlanner", "activationPredecessor",
    "issuedAtEpochNs", "expiresAtEpochNs"})
V3_PAYLOAD_FIELDS = (PAYLOAD_FIELDS - frozenset({"activationPlannerBootstrapDigest", "activationPredecessor"})
    | frozenset({"activationIssuancePolicy"}))
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})


class OidcSessionActivationConsumeInputIssuerPolicyError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationConsumeInputIssuerPolicyError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _IssuerPolicyMaterial:
    """Same-call original-derived data; never accepted as authority input."""

    policy_bytes: bytes
    activation_planner_bootstrap_bytes: bytes
    policy_digest: str
    payload: dict
    activation_planner: activation._PlannerMaterial
    history: dict
    consume_planner: dict
    activation_predecessor: tuple
    consume_planner_public_key: object
    live_window: tuple
    deadline_ns: int
    live: object
    historical_root_public_key: object = None
    current_planner: object = None
    bridge: object = None
    request_bound: bool = False


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalIssuerPolicyMaterial(_IssuerPolicyMaterial):
    """Original signed bridge evidence, never current issuer permission."""


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("consume input issuer policy exceeds its structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("consume input issuer policy exceeds its node bound")
        return result


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    maximum = V1_MAX_BYTES if value.get("schema") in (SCHEMA, PAYLOAD_SCHEMA) else V2_MAX_BYTES
    return capability._wire(value, capture._SharedLedger(work), maximum, MAX_NODES)


def _canonical(original, value, work):
    maximum = V1_MAX_BYTES if value.get("schema") in (SCHEMA, PAYLOAD_SCHEMA) else V2_MAX_BYTES
    return capability._canonical(original, value, capture._SharedLedger(work), maximum, MAX_NODES)


def _payload_shape(payload, work):
    if type(payload) is dict and payload.get("schema") == V2_PAYLOAD_SCHEMA:
        from serverware import oidc_session_activation_consume_input_bridge_policy as bridge
        return bridge._payload_shape(payload, work)
    resource = type(payload) is dict and payload.get("schema") == V3_PAYLOAD_SCHEMA
    shape._object(payload, V3_PAYLOAD_FIELDS if resource else PAYLOAD_FIELDS, "consume input issuer policy")
    for name, expected in (("schema", V3_PAYLOAD_SCHEMA if resource else PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    if resource:
        from serverware import oidc_session_activation_request_issuance_policy as resources
        original = payload["activationIssuancePolicy"]
        shape._object(original, frozenset({"base64Url", "byteCount", "bytesDigest"}), "consume static issuance policy")
        authorization.transport._transport_shape(original["base64Url"], original["byteCount"], resources.MAX_BYTES)
        shape._digest(original["bytesDigest"])
    else:
        shape._digest(payload["activationPlannerBootstrapDigest"])
    selected_history = payload["history"]
    shape._object(selected_history, HISTORY_FIELDS, "consume input history pins")
    shape.validate_identity_shape(selected_history["receiverIdentity"])
    for name in ("bundleKeyDigest", "deliveryKeyDigest"):
        shape._digest(selected_history[name])
    if selected_history["bundleKeyDigest"] == selected_history["deliveryKeyDigest"]:
        _fail("consume input history bundle and delivery keys are not separate")
    if not resource:
        predecessor = payload["activationPredecessor"]
        shape._object(predecessor, PREDECESSOR_FIELDS, "independent activation predecessor")
        reservation._predecessor_scope(predecessor["sequence"], predecessor["headDigest"], predecessor["fence"])
    selected = payload["consumePlanner"]
    shape._object(selected, CONSUME_PLANNER_FIELDS, "consume input planner resources")
    planner = selected["planner"]
    shape._object(planner, activation._PLANNER_FIELDS, "dedicated consume planner")
    shape._text(planner["publicKeyBase64Url"], 43, minimum=43)
    shape._base64url(planner["publicKeyBase64Url"])
    shape._digest(planner["spkiDigest"])
    shape.validate_identity_shape(planner["identity"])
    activation._database_shape(selected["databaseEndpoint"])
    read = selected["readRole"]
    shape._object(read, activation._READ_ROLE_FIELDS, "consume read role")
    if type(read["databaseRole"]) is not str or activation._ROLE_NAME.fullmatch(read["databaseRole"]) is None:
        _fail("consume input database role is outside its fixed grammar")
    shape._integer(read["connectTimeoutSeconds"], 300, minimum=2)
    for name in ("clientDn", "clientSerial", "issuerDn"):
        activation.registration._text(read[name], "consume SQL " + name, 4096, work)
    shape._object(selected["tlsFiles"], frozenset(consume.TLS_PATHS), "consume TLS pins")
    for name, maximum in consume.TLS_LIMITS.items():
        pin = selected["tlsFiles"][name]
        shape._object(pin, frozenset({"byteCount", "bytesDigest"}), "consume TLS original pin")
        shape._integer(pin["byteCount"], maximum, minimum=consume.MIN_TLS_BYTES)
        shape._digest(pin["bytesDigest"])
    activation._state_endpoint(selected["stateEndpoint"])
    for name in ("journalKeyDigest", "executionBundleKeyDigest"):
        shape._digest(selected[name])
    consume._launch(selected["launch"], work)
    authorization._interval(payload, resources.MAX_POLICY_AGE_NS if resource else MAX_RECEIPT_AGE_NS)


def _read(original, work):
    """Own closed canonical data only; parsing is not root admission."""
    raw = authorization._original(original, MAX_BYTES, "consume input issuer policy")
    decoded = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(decoded, work)
    shape._object(owned, _ENVELOPE_FIELDS, "signed consume input issuer policy")
    if type(owned["schema"]) is not str or owned["schema"] not in (SCHEMA, V2_SCHEMA, V3_SCHEMA):
        _fail("consume input issuer policy schema is not supported")
    maximum = V1_MAX_BYTES if owned["schema"] == SCHEMA else V2_MAX_BYTES
    authorization._original(raw, maximum, "versioned consume input issuer policy")
    shape._base64url(owned["signatureBase64Url"], signature=True)
    shape._literal(owned["payload"]["schema"],
        V3_PAYLOAD_SCHEMA if owned["schema"] == V3_SCHEMA else V2_PAYLOAD_SCHEMA if owned["schema"] == V2_SCHEMA else PAYLOAD_SCHEMA)
    _payload_shape(owned["payload"], work)
    _canonical(raw, owned, work)
    return owned


def _digest_on_work(original, work):
    raw = authorization._original(original, MAX_BYTES, "consume input issuer policy")
    _read(raw, work)
    return plan._frame(IDENTITY_DOMAIN, (raw,), work)


def _activation_planner_bootstrap_digest_on_work(original, work):
    raw = authorization._original(original, MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES,
        "independent activation planner bootstrap")
    return plan._frame(ACTIVATION_PLANNER_BOOTSTRAP_IDENTITY_DOMAIN, (raw,), work)


def _inventory(policy_size, planner_original, work):
    total = policy_size + len(planner_original)
    if total > MAX_ORIGINAL_BYTES:
        _fail("consume input issuer original inventory exceeds 64 MiB")
    work.charge(input_bytes=total)


class _Lifetime:
    """Same-call ledger and clock floors, not an authority input carrier."""

    def __init__(self, window, bound, work, continuity):
        self.window, self.bound, self.work = window, bound, work
        self.epoch, self.monotonic = window[0], window[2]
        self.interval, self.continuation = None, continuity
        self.limits, self.metrics = work.limits, work.metrics
        self.ceilings = (self.limits.max_hashes, self.limits.max_input_bytes, self.limits.max_json_nodes)
        if continuity is not None and not callable(continuity):
            _fail("consume input issuer restrictive continuity is not callable")

    def _ledger(self):
        capture._SharedLedger(self.work)
        limits, observed = self.work.limits, self.work.metrics
        if (limits is not self.limits
                or self.ceilings != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                or observed.hash_work < self.metrics.hash_work
                or observed.input_bytes < self.metrics.input_bytes
                or observed.json_nodes < self.metrics.json_nodes):
            _fail("consume input issuer reset its original work allowance")
        self.metrics = observed

    def _floors(self, epoch, monotonic):
        if (type(epoch) is not int or type(monotonic) is not int
                or epoch < self.epoch or monotonic < self.monotonic
                or epoch >= self.window[3] or monotonic >= self.bound):
            _fail("consume input issuer clocks reversed or exceeded their original allowance")
        self.epoch, self.monotonic = epoch, monotonic

    def _owner(self):
        self._ledger()
        if self.continuation is not None:
            observed = self.continuation(self.epoch, self.monotonic)
            self._ledger()
            if type(observed) is not tuple or len(observed) != 2:
                _fail("consume input issuer continuity must return only two clock floors")
            self._floors(*observed)

    def current(self):
        self._owner()
        epoch = clock._check_on_work(self.window, work=self.work)
        monotonic = production._callback(self.work, time.monotonic_ns)
        self._floors(epoch, monotonic)
        self._owner()
        if self.interval is not None:
            issued, expires = self.interval
            if issued > self.epoch + self.window[6] or self.epoch >= expires:
                _fail("consume input issuer signed policy is not live")
        return self.epoch

    def continuity(self, epoch, monotonic):
        shape._integer(epoch, minimum=1)
        shape._integer(monotonic, minimum=1)
        self._floors(max(epoch, self.epoch), max(monotonic, self.monotonic))
        self.current()
        return self.epoch, self.monotonic

    def narrow(self, expires, age, skew):
        selected = processing._narrow(self.window, deadline_epoch_ns=expires,
            maximum_lifetime_ns=min(age, self.window[5]), maximum_clock_skew_ns=min(skew, self.window[6]))
        if (selected[:3] != self.window[:3]
                or any(value > old for value, old in zip(selected[3:], self.window[3:]))):
            _fail("consume input issuer widened the supplied processing window")
        self.current()
        self.window, self.bound = selected, min(self.bound, selected[4])
        self.current()


def _signature(envelope, root, work):
    unsigned = _wire(envelope["payload"], work)
    domain = V3_SCHEMA if envelope["schema"] == V3_SCHEMA else V2_SCHEMA if envelope["schema"] == V2_SCHEMA else SIGNATURE_DOMAIN
    try:
        capability._signature(root, envelope["signatureBase64Url"], domain,
            unsigned, capture._SharedLedger(work))
    except InvalidSignature as exc:
        raise OidcSessionActivationConsumeInputIssuerPolicyError(
            "consume input issuer policy root signature is invalid") from exc


def _consume_key(selected, planner, root, work, current):
    """Use actual configured purposes; no synthetic history result is passed."""
    return _consume_resource_key(selected, configured=planner.configuration_payload,
        planner_spki_digest=planner.planner_spki_digest, maximum_plan_age_ns=planner.maximum_plan_age_ns,
        state_enrollment_bytes=planner.state_enrollment_bytes,
        state_enrollment_digest=planner.state_enrollment_digest, root=root, work=work, current=current)


def _consume_resource_key(selected, *, configured, planner_spki_digest, maximum_plan_age_ns,
        state_enrollment_bytes, state_enrollment_digest, root, work, current):
    """Shared original resource checks; no successful planner DTO is invented."""
    chosen = selected["planner"]
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "consume configured roles")
    forbidden = [keys._spki_on_work(root, work), planner_spki_digest]
    current()
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        shape._literal(role["processMode"], "policy-authority-" + name)
        for field in ("serviceUid", "serviceGid"):
            shape._integer(role[field], 2**32 - 2, minimum=1)
            if role[field] == consume.SERVICE_UID:
                _fail("consume planner reuses a configured generic role identity")
        shape._digest(role["responseSigningSpkiDigest"])
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            configuration._key(role["signingPublicKeyBase64Url"], work, expected_spki=role["signingSpkiDigest"])
            forbidden.append(role["signingSpkiDigest"])
            shape._integer(role["maximumInternalAgeNs"], minimum=1)
            if maximum_plan_age_ns > role["maximumInternalAgeNs"]:
                _fail("consume planner lifetime widens configured policy")
        current()
    activation.enabled._require_enabled_operation(roles["planner"], consume.OPERATION, work)
    for module, names in ((activation.evidence_policy, ("registration", "installation")),
            (activation.transition_policy, ("registration", "stage", "completion"))):
        configured_policy = configured.get(module.FIELD)
        if configured_policy is not None:
            policy, _public = module._validate_policy_on_work(configured_policy,
                webauthn=configured["webauthn"], work=work)
            forbidden.extend(policy[name]["signingSpkiDigest"] for name in names if policy[name] is not None)
        current()
    configured_policy = configured.get(activation.enrollment_policy.FIELD)
    if configured_policy is not None:
        policy, _public = activation.enrollment_policy._validate_policy_on_work(
            configured_policy, payload=configured, work=work)
        forbidden.append(policy["signingSpkiDigest"])
    current()
    state = authorization._admit_enrollment_on_work(enrollment_bytes=state_enrollment_bytes,
        root_public_key=root, work=work)
    current()
    plan._same(state.enrollment_digest, state_enrollment_digest, work,
        "consume input state enrollment differs from genuinely admitted activation original")
    forbidden.extend(state.payload[name]["spkiDigest"] for name in ("state", "computation", "completion"))
    work.prepare_scan(forbidden)
    if chosen["spkiDigest"] in forbidden:
        _fail("consume planner key is not purpose-separated from actual root/configured/state keys")
    public = configuration._key(chosen["publicKeyBase64Url"], work, expected_spki=chosen["spkiDigest"])
    current()
    return public


def _join_planner(payload, original, root, lifetime, work):
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    lifetime.interval = interval
    lifetime.narrow(interval[1], lifetime.window[5], lifetime.window[6])
    current = lifetime.current
    identity = _activation_planner_bootstrap_digest_on_work(original, work)
    current()
    plan._same(identity, payload["activationPlannerBootstrapDigest"], work,
        "consume input issuer exact activation planner original")
    current()
    planner = activation._verify_historical_on_work(bootstrap_bytes=original, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    if type(planner) is not activation._PlannerMaterial:
        _fail("consume input issuer requires actual activation planner original admission")
    current()
    # The old launch is evidence only. Fresh policy lifetime never makes that
    # old interval live, and no old interval is substituted for current clocks.
    lifetime.narrow(interval[1], planner.maximum_plan_age_ns, planner.maximum_clock_skew_ns)
    selected_history, selected = payload["history"], payload["consumePlanner"]
    plan._same((selected_history["bundleKeyDigest"], selected_history["deliveryKeyDigest"]),
        (planner.bundle_key_digest, planner.delivery_key_digest), work,
        "consume history AES pins differ from genuine activation planner")
    plan._same(selected["readRole"]["databaseRole"],
        planner.configuration_payload["roles"]["verifier"]["databaseRole"], work,
        "consume read role differs from genuine configured verifier")
    current()
    public = _consume_key(selected, planner, root, work, current)
    forbidden = (planner.bundle_key_digest, planner.delivery_key_digest, planner.journal_key_digest)
    work.prepare_scan(forbidden)
    if selected["journalKeyDigest"] in forbidden:
        _fail("consume journal key reuses an activation custody purpose")
    work.prepare_scan((*forbidden, selected["journalKeyDigest"]))
    if selected["executionBundleKeyDigest"] in (*forbidden, selected["journalKeyDigest"]):
        _fail("consume execution-export key reuses a history or journal purpose")
    launch, old = selected["launch"], planner.launch
    old_directories = ((old["journalDirectoryDevice"], old["journalDirectoryInode"]),
        (old["executionStoreDirectoryDevice"], old["executionStoreDirectoryInode"]))
    journal = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
    export = launch["executionStoreDirectoryDevice"], launch["executionStoreDirectoryInode"]
    work.prepare_scan((*old_directories, journal, export))
    if journal in old_directories or export in (*old_directories, journal):
        _fail("consume directories reuse historical or consume original custody")
    lifetime.narrow(interval[1], min(planner.maximum_plan_age_ns,
        launch["requestTimeoutSeconds"] * 1_000_000_000), planner.maximum_clock_skew_ns)
    decoded_size = len(planner.state_enrollment_bytes) + len(planner.complete_root_vector_bytes)
    if V1_MAX_BYTES + len(original) + decoded_size > MAX_ORIGINAL_BYTES:
        _fail("consume input issuer decoded original inventory exceeds 64 MiB")
    current()
    return planner, public


def _verify_on_work(*, policy_bytes, activation_planner_bootstrap_bytes, root_public_key,
        live_window, transport_deadline_ns, work, _continuity=None):
    """Authenticate independent originals, not caller evidence or a template."""
    return _verify_original_on_work(policy_bytes=policy_bytes,
        activation_planner_bootstrap_bytes=activation_planner_bootstrap_bytes,
        root_public_key=root_public_key, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, _continuity=_continuity)


def _expected_policy_interval(value):
    if type(value) is not tuple or len(value) != 2:
        _fail("historical consume bridge needs its independently pinned original interval")
    for endpoint in value:
        shape._integer(endpoint, minimum=1)
    if not 0 < value[1] - value[0] <= MAX_RECEIPT_AGE_NS:
        _fail("historical consume bridge original interval exceeds its source bound")
    return value


def _verify_historical_on_work(*, policy_bytes, activation_planner_bootstrap_bytes,
        root_public_key, expected_policy_interval, live_window, transport_deadline_ns,
        work, _continuity=None):
    """Authenticate original v2 under explicit R1; current processing stays current.

    The composing fresh completion authority must independently supply R1 and
    the exact original interval. Neither is inferred from received evidence.
    """
    return _verify_original_on_work(policy_bytes=policy_bytes,
        activation_planner_bootstrap_bytes=activation_planner_bootstrap_bytes,
        root_public_key=root_public_key, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, _continuity=_continuity,
        expected_policy_interval=_expected_policy_interval(expected_policy_interval))


def _verify_original_on_work(*, policy_bytes, activation_planner_bootstrap_bytes,
        root_public_key, live_window, transport_deadline_ns, work, _continuity,
        expected_policy_interval=None):
    capture._SharedLedger(work)
    root = root_public_key
    raw = authorization._original(policy_bytes, MAX_BYTES, "consume input issuer policy")
    original = authorization._original(activation_planner_bootstrap_bytes,
        MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES, "independent activation planner bootstrap")
    _inventory(len(raw), original, work)
    if expected_policy_interval is not None:
        # Bound original/canonical graphs and the wrapped current planner before
        # decoding any policy body. Embedded raw bytes cannot exceed its envelope.
        reserved = (24 * len(raw) + 16 * len(original)
            + 8 * authorization.MAX_ENROLLMENT_BYTES + 8 * authorization.vector.MAX_BYTES + 64 * 1024)
        if reserved > MAX_ORIGINAL_BYTES:
            _fail("historical consume bridge captures exceed the original aggregate ceiling")
    authorization._public(root)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = _Lifetime(window, min(transport_deadline_ns, window[4]), work, _continuity)
    lifetime.current()
    envelope = _read(raw, work)
    lifetime.current()
    _signature(envelope, root, work)
    lifetime.current()
    payload = envelope["payload"]
    historical = expected_policy_interval is not None
    resource_live = None
    if historical:
        if envelope["schema"] != V2_SCHEMA:
            _fail("historical consume policy admission requires the explicit v2 bridge")
        from serverware import oidc_session_activation_consume_input_bridge_policy as bridge
        planner, public, historical_root, current_planner, bridge_material = bridge._join_historical_on_work(
            payload, original, root, lifetime, work, expected_policy_interval=expected_policy_interval)
    elif envelope["schema"] == V3_SCHEMA:
        from serverware import oidc_session_activation_consume_input_resources as resources
        planner, public, resource_live = resources._late_on_work(payload, original, root, lifetime, work)
        historical_root, current_planner, bridge_material = root, planner, None
    elif envelope["schema"] == V2_SCHEMA:
        from serverware import oidc_session_activation_consume_input_bridge_policy as bridge
        planner, public, historical_root, current_planner, bridge_material = bridge._join_on_work(
            payload, original, root, lifetime, work)
    else:
        planner, public = _join_planner(payload, original, root, lifetime, work)
        historical_root, current_planner, bridge_material = root, planner, None
    _canonical(raw, envelope, work)
    lifetime.current()
    identity = _digest_on_work(raw, work)
    lifetime.current()
    owned = _capture(payload, work)
    selected_history = _capture(owned["history"], work)
    selected = _capture(owned["consumePlanner"], work)
    predecessor = None
    if resource_live is None:
        predecessor = owned["activationPredecessor"]
        predecessor = reservation._predecessor_scope(predecessor["sequence"], predecessor["headDigest"], predecessor["fence"])
    lifetime.current()
    live = lifetime.current if resource_live is None else resource_live
    live()
    material_type = _HistoricalIssuerPolicyMaterial if historical else _IssuerPolicyMaterial
    return material_type(raw, original, identity, owned, planner, selected_history,
        selected, predecessor, public, lifetime.window, lifetime.bound, live,
        historical_root, current_planner, bridge_material, resource_live is not None)


def _produce_on_work(*, payload, activation_planner_bootstrap_bytes, root_private_key,
        root_public_key, live_window, transport_deadline_ns, work, _continuity=None):
    """Sign only after genuine historical admission and static purpose joins."""
    if type(payload) is dict and payload.get("schema") == V3_PAYLOAD_SCHEMA:
        from serverware import oidc_session_activation_consume_input_resources as resources
        if activation_planner_bootstrap_bytes is not None:
            _fail("static consume resources cannot select a future activation planner")
        return resources._produce_on_work(payload=payload, root_private_key=root_private_key,
            root_public_key=root_public_key, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work, _continuity=_continuity)
    capture._SharedLedger(work)
    private, root = root_private_key, root_public_key
    original = authorization._original(activation_planner_bootstrap_bytes,
        MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES, "independent activation planner bootstrap")
    owned = _capture(payload, work)
    authorization._private(private)
    authorization._public(root)
    _payload_shape(owned, work)
    is_bridge = owned["schema"] == V2_PAYLOAD_SCHEMA
    schema = V2_SCHEMA if is_bridge else SCHEMA
    maximum = V2_MAX_BYTES if is_bridge else V1_MAX_BYTES
    _inventory(maximum, original, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = _Lifetime(window, min(transport_deadline_ns, window[4]), work, _continuity)
    lifetime.current()
    if is_bridge:
        from serverware import oidc_session_activation_consume_input_bridge_policy as bridge
        bridge._join_on_work(owned, original, root, lifetime, work)
    else:
        _join_planner(owned, original, root, lifetime, work)
    live = lifetime.current
    live()
    keys._pair_on_work(private, root, work)
    live()
    envelope = {"schema": schema, "payload": owned, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > maximum or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        _fail("consume input issuer signature exceeds its output bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(schema) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("consume input issuer cannot reserve its signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("consume input issuer payload changed after measurement")
    message = plan._ascii(plan._frame(schema, (unsigned,), work), work)
    live()
    signature = production._sign_and_verify(private, root, message, work)
    live()
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        _fail("consume input issuer policy changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    raw = plan.core.canonical_bytes({"schema": schema, "payload": owned, "signatureBase64Url": encoded})
    if len(raw) != envelope_size:
        _fail("consume input issuer output differs from its reservation")
    live()
    readback = _read(raw, work)
    live()
    _signature(readback, root, work)
    live()
    plan._same(readback["payload"], owned, work, "consume input issuer signed policy differs")
    live()
    return raw
