"""Current-root authorization of old activation evidence for fresh consume.

The signed policy supplies both independent original identities. A historical
root is read only after the current-root signature on receiving; producing
requires the actual current root pair. No admitted material is an input API.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from serverware import oidc_session_activation_consume_input_issuer_policy as issuer


SCHEMA, PAYLOAD_SCHEMA = issuer.V2_SCHEMA, issuer.V2_PAYLOAD_SCHEMA
COMPATIBILITY = "same-generation-state-payload/v1"
MAX_BYTES = issuer.V2_MAX_BYTES
EVIDENCE_FIELDS = frozenset({"rootPublicKeyBase64Url", "rootSpkiDigest",
    "configurationDigest", "generationDigest", "plannerAttestationReceiptDigest",
    "validFromEpochNs", "validUntilEpochNs", "authorizationEnrollmentDigest",
    "grantEnrollmentDigest", "stateEnrollmentDigest"})
ORIGINAL_FIELDS = frozenset({"byteCount", "bytesDigest", "base64Url", "identityDigest"})
PAYLOAD_FIELDS = issuer.PAYLOAD_FIELDS | frozenset({"activationEvidence",
    "currentActivationPlanner", "compatibility"})
shape, plan, capture = issuer.shape, issuer.plan, issuer.capture


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _BridgeMaterial:
    historical_interval: tuple
    authorization_enrollment_digest: str
    grant_enrollment_digest: str
    state_enrollment_digest: str
    current_state_enrollment_digest: str


def _payload_shape(payload, work):
    shape._object(payload, PAYLOAD_FIELDS, "historical activation consume bridge policy")
    shape._literal(payload["schema"], PAYLOAD_SCHEMA)
    shape._literal(payload["compatibility"], COMPATIBILITY)
    # Preserve the exact v1 resource/purpose grammar. Only the two independently
    # signed evidence contexts below change; no free-form role or effect exists.
    prior = {name: payload[name] for name in issuer.PAYLOAD_FIELDS}
    prior["schema"] = issuer.PAYLOAD_SCHEMA
    issuer._payload_shape(prior, work)
    evidence = payload["activationEvidence"]
    shape._object(evidence, EVIDENCE_FIELDS, "independent historical activation evidence")
    shape._text(evidence["rootPublicKeyBase64Url"], 43, minimum=43)
    shape._base64url(evidence["rootPublicKeyBase64Url"])
    for name in EVIDENCE_FIELDS - {"rootPublicKeyBase64Url", "validFromEpochNs", "validUntilEpochNs"}:
        shape._digest(evidence[name])
    for name in ("validFromEpochNs", "validUntilEpochNs"):
        shape._integer(evidence[name], minimum=1)
    if evidence["validFromEpochNs"] >= evidence["validUntilEpochNs"]:
        issuer._fail("consume bridge historical original interval is empty")
    current = payload["currentActivationPlanner"]
    shape._object(current, ORIGINAL_FIELDS, "independent current planner original")
    shape._integer(current["byteCount"], issuer.MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES, minimum=2)
    for name in ("bytesDigest", "identityDigest"):
        shape._digest(current[name])
    shape._text(current["base64Url"],
        (4 * issuer.MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES + 2) // 3, minimum=2)
    shape._base64url(current["base64Url"])


def _join_on_work(payload, original, root, lifetime, work):
    """Called after actual root admission, or before signing by the root pair."""
    return _join_originals_on_work(payload, original, root, lifetime, work)


def _join_historical_on_work(payload, original, root, lifetime, work, *, expected_policy_interval):
    """Original evidence only; never install its expiry as the current clock."""
    return _join_originals_on_work(payload, original, root, lifetime, work,
        expected_policy_interval=issuer._expected_policy_interval(expected_policy_interval))


def _join_originals_on_work(payload, original, root, lifetime, work, *, expected_policy_interval=None):
    _payload_shape(payload, work)
    current = lifetime.current
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if expected_policy_interval is None:
        lifetime.interval = interval
        lifetime.narrow(interval[1], lifetime.window[5], lifetime.window[6])
    else:
        plan._same(interval, expected_policy_interval, work, "independent original consume policy interval")
        if interval[0] > current() + lifetime.window[6]:
            issuer._fail("historical consume policy is future-issued")
    evidence, wrapped = payload["activationEvidence"], payload["currentActivationPlanner"]
    # Charge the fixed decoded-original/canonical/nested-admission inventory
    # before decoding the embedded planner. This is not a Python heap bound.
    policy_size = work.measure(payload)[0]
    footprint = (8 * policy_size + 16 * (len(original) + wrapped["byteCount"])
        + 8 * issuer.authorization.MAX_ENROLLMENT_BYTES + 8 * issuer.authorization.vector.MAX_BYTES)
    if footprint > issuer.MAX_ORIGINAL_BYTES:
        issuer._fail("consume bridge originals exceed their aggregate admission reservation")
    work.charge(input_bytes=footprint)
    current()
    historical_root = issuer.configuration._key(evidence["rootPublicKeyBase64Url"], work,
        expected_spki=evidence["rootSpkiDigest"])
    current()
    plan._same(issuer._activation_planner_bootstrap_digest_on_work(original, work),
        payload["activationPlannerBootstrapDigest"], work, "consume bridge exact historical planner")
    old = issuer.activation._verify_historical_on_work(bootstrap_bytes=original,
        root_public_key=historical_root, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity)
    current()
    if type(old) is not issuer.activation._PlannerMaterial:
        issuer._fail("consume bridge has no genuine historical planner")
    for actual, expected, label in (
            (old.configuration_digest, evidence["configurationDigest"], "old configuration"),
            (old.generation["digest"], evidence["generationDigest"], "old generation"),
            (old.planner_identity["attestationReceiptDigest"],
                evidence["plannerAttestationReceiptDigest"], "old planner receipt"),
            (old.state_enrollment_digest, evidence["stateEnrollmentDigest"], "old state enrollment")):
        plan._same(actual, expected, work, "consume bridge " + label)
    old_interval = evidence["validFromEpochNs"], evidence["validUntilEpochNs"]
    if not old_interval[0] <= old.attestation_interval[0] < old.attestation_interval[1] <= old_interval[1]:
        issuer._fail("consume bridge historical planner escapes the independent original interval")
    current_original = issuer.authorization.transport._decode(wrapped["base64Url"], wrapped["byteCount"],
        issuer.MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES, work)
    work.charge(hashes=1, input_bytes=len(current_original))
    digest = issuer.production._callback(work,
        lambda: "sha256:" + hashlib.sha256(current_original).hexdigest())
    current()
    plan._same(digest, wrapped["bytesDigest"], work, "consume bridge current planner raw digest")
    plan._same(issuer._activation_planner_bootstrap_digest_on_work(current_original, work),
        wrapped["identityDigest"], work, "consume bridge current planner identity")
    # This current-root-pinned template provides genuine configuration/state
    # provenance only. The fresh policy authorizes the new consume launch; it
    # does not renew the template's activation launch or execute activation.
    chosen = issuer.activation._verify_historical_on_work(bootstrap_bytes=current_original,
        root_public_key=root, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity)
    current()
    if type(chosen) is not issuer.activation._PlannerMaterial:
        issuer._fail("consume bridge has no genuine current-root planner context")
    old_state = issuer.authorization._admit_enrollment_on_work(
        enrollment_bytes=old.state_enrollment_bytes, root_public_key=historical_root, work=work)
    current()
    new_state = issuer.authorization._admit_enrollment_on_work(
        enrollment_bytes=chosen.state_enrollment_bytes, root_public_key=root, work=work)
    current()
    plan._same(old_state.payload, new_state.payload, work,
        "consume bridge complete state enrollment payload compatibility")
    plan._same(old.generation["digest"], chosen.generation["digest"], work,
        "consume bridge unchanged state generation")
    for material, enrolled in ((old, old_state), (chosen, new_state)):
        plan._same(material.state_enrollment_digest, enrolled.enrollment_digest, work,
            "consume bridge genuine state enrollment identity")
    selected_history, selected = payload["history"], payload["consumePlanner"]
    plan._same((selected_history["bundleKeyDigest"], selected_history["deliveryKeyDigest"]),
        (old.bundle_key_digest, old.delivery_key_digest), work, "consume bridge historical custody keys")
    plan._same(selected["readRole"]["databaseRole"],
        chosen.configuration_payload["roles"]["verifier"]["databaseRole"], work,
        "consume bridge independently current read role")
    # The current configuration supplies enabled consumption and role pins.
    # Checking the old configuration too only excludes old purposes; it cannot
    # widen the current role or turn the old activation launch into permission.
    public = issuer._consume_key(selected, chosen, root, work, current)
    issuer._consume_key(selected, old, historical_root, work, current)
    forbidden = (old.bundle_key_digest, old.delivery_key_digest, old.journal_key_digest,
        chosen.bundle_key_digest, chosen.delivery_key_digest, chosen.journal_key_digest)
    work.prepare_scan(forbidden)
    if selected["journalKeyDigest"] in forbidden:
        issuer._fail("consume bridge journal key reuses an old or current custody purpose")
    work.prepare_scan((*forbidden, selected["journalKeyDigest"]))
    if selected["executionBundleKeyDigest"] in (*forbidden, selected["journalKeyDigest"]):
        issuer._fail("consume bridge export key reuses an old, current or journal purpose")
    occupied = tuple((material.launch[name + "Device"], material.launch[name + "Inode"])
        for material in (old, chosen) for name in ("journalDirectory", "executionStoreDirectory"))
    launch = selected["launch"]
    journal = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
    export = launch["executionStoreDirectoryDevice"], launch["executionStoreDirectoryInode"]
    work.prepare_scan((*occupied, journal, export))
    if journal in occupied or export in (*occupied, journal):
        issuer._fail("consume bridge directories reuse old or current original custody")
    deadline = interval[1] if expected_policy_interval is None else lifetime.window[3]
    lifetime.narrow(deadline, min(old.maximum_plan_age_ns, chosen.maximum_plan_age_ns,
        launch["requestTimeoutSeconds"] * 1_000_000_000),
        min(old.maximum_clock_skew_ns, chosen.maximum_clock_skew_ns))
    retained = sum(len(value) for material in (old, chosen) for value in
        (material.bootstrap_bytes, material.state_enrollment_bytes, material.complete_root_vector_bytes))
    if retained > footprint:
        issuer._fail("consume bridge decoded originals escaped their prior reservation")
    now = current()
    if expected_policy_interval is not None and interval[0] > now + lifetime.window[6]:
        issuer._fail("historical consume policy exceeds the narrowed current clock skew")
    bridge = _BridgeMaterial(old_interval, evidence["authorizationEnrollmentDigest"],
        evidence["grantEnrollmentDigest"], old_state.enrollment_digest, new_state.enrollment_digest)
    return old, public, historical_root, chosen, bridge


def _verify_on_work(*, policy_bytes, activation_planner_bootstrap_bytes, root_public_key,
        live_window, transport_deadline_ns, work, _continuity=None):
    """Require this exact current-root-signed profile through real issuer admission."""
    material = issuer._verify_on_work(policy_bytes=policy_bytes,
        activation_planner_bootstrap_bytes=activation_planner_bootstrap_bytes,
        root_public_key=root_public_key, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, _continuity=_continuity)
    if type(material.bridge) is not _BridgeMaterial:
        issuer._fail("consume bridge verifier requires the distinct v2 policy")
    return material


def _verify_historical_on_work(*, policy_bytes, activation_planner_bootstrap_bytes,
        root_public_key, expected_policy_interval, live_window, transport_deadline_ns,
        work, _continuity=None):
    """Genuine original v2 under separately pinned R1 and original interval."""
    material = issuer._verify_historical_on_work(policy_bytes=policy_bytes,
        activation_planner_bootstrap_bytes=activation_planner_bootstrap_bytes,
        root_public_key=root_public_key, expected_policy_interval=expected_policy_interval,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        work=work, _continuity=_continuity)
    if (type(material) is not issuer._HistoricalIssuerPolicyMaterial
            or type(material.bridge) is not _BridgeMaterial):
        issuer._fail("historical consume bridge requires its distinct original evidence material")
    return material


def _produce_on_work(*, payload, activation_planner_bootstrap_bytes, root_private_key,
        root_public_key, live_window, transport_deadline_ns, work, _continuity=None):
    _payload_shape(payload, work)
    return issuer._produce_on_work(payload=payload,
        activation_planner_bootstrap_bytes=activation_planner_bootstrap_bytes,
        root_private_key=root_private_key, root_public_key=root_public_key,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        work=work, _continuity=_continuity)
