"""Static consume resources and actual late same-request planner admission."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from serverware import oidc_session_activation_request_issuance_policy as resources
from serverware import oidc_session_activation_consume_input_issuer_policy as issuer


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Resources:
    issuance_policy_bytes: bytes
    policy: object
    consume_public_key: object
    live: object


def _same(actual, expected, work, label):
    ledger = issuer.capture._SharedLedger(work)
    left = resources.configuration._configuration_wire(actual, ledger)
    right = resources.configuration._configuration_wire(expected, ledger)
    work.charge(input_bytes=len(left) + len(right))
    if left != right:
        issuer._fail("consume resources changed " + label)


def _admit_on_work(*, payload, root_public_key, live_window=None,
        transport_deadline_ns=None, work, _continuity=None):
    owned = issuer._capture(payload, work)
    issuer._payload_shape(owned, work)
    issuer.shape._literal(owned["schema"], issuer.V3_PAYLOAD_SCHEMA)
    if (live_window is None) != (transport_deadline_ns is None):
        issuer._fail("consume resources need the complete original processing pair")
    current = resources._clock(owned, live_window, transport_deadline_ns, work, _continuity)
    wrapped = owned["activationIssuancePolicy"]
    current()
    raw = issuer.authorization.transport._decode(wrapped["base64Url"], wrapped["byteCount"],
        resources.MAX_BYTES, work)
    work.charge(hashes=1, input_bytes=len(raw))
    digest = issuer.production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())
    issuer.plan._same(digest, wrapped["bytesDigest"], work, "consume actual static issuance original")
    current()
    admitted = resources._verify_on_work(policy_bytes=raw, root_public_key=root_public_key,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work,
        _continuity=_continuity)
    if not (admitted.payload["issuedAtEpochNs"] <= owned["issuedAtEpochNs"]
            < owned["expiresAtEpochNs"] <= admitted.payload["expiresAtEpochNs"]):
        issuer._fail("consume resource policy escapes its original delegated interval")

    def live():
        first = current()
        observed = admitted.live()
        final = current()
        if not first <= observed <= final:
            issuer._fail("consume resource clock reversed across original delegation")
        return final

    configured, _generation, _runtime, _planner, state_raw, state_pin, _reader = admitted.resource_facts
    original = admitted.payload["plannerResources"]
    selected, history = owned["consumePlanner"], owned["history"]
    live()
    public = issuer._consume_resource_key(selected, configured=configured,
        planner_spki_digest=original["planner"]["spkiDigest"], maximum_plan_age_ns=original["maximumPlanAgeNs"],
        state_enrollment_bytes=state_raw, state_enrollment_digest=state_pin,
        root=root_public_key, work=work, current=live)
    issuer.plan._same((history["bundleKeyDigest"], history["deliveryKeyDigest"]),
        (original["bundleKeyDigest"], original["deliveryKeyDigest"]), work,
        "consume resource actual activation history cipher pins")
    issuer.plan._same(selected["readRole"]["databaseRole"], configured["roles"]["verifier"]["databaseRole"],
        work, "consume resource actual verifier read role")
    forbidden = (original["bundleKeyDigest"], original["deliveryKeyDigest"], original["journalKeyDigest"])
    work.prepare_scan((*forbidden, selected["journalKeyDigest"], selected["executionBundleKeyDigest"]))
    if (selected["journalKeyDigest"] in forbidden
            or selected["executionBundleKeyDigest"] in (*forbidden, selected["journalKeyDigest"])):
        issuer._fail("consume resources reuse an activation cipher purpose")
    old, new = original["launch"], selected["launch"]
    held = ((old["journalDirectoryDevice"], old["journalDirectoryInode"]),
        (old["executionStoreDirectoryDevice"], old["executionStoreDirectoryInode"]))
    journal = new["journalDirectoryDevice"], new["journalDirectoryInode"]
    export = new["executionStoreDirectoryDevice"], new["executionStoreDirectoryInode"]
    work.prepare_scan((*held, journal, export))
    if journal in held or export in (*held, journal):
        issuer._fail("consume resources reuse actual activation or consume directories")
    live()
    return _Resources(raw, admitted, public, live)


def _verify_on_work(*, policy_bytes, root_public_key, live_window=None,
        transport_deadline_ns=None, work, _continuity=None):
    raw = issuer.authorization._original(policy_bytes, issuer.MAX_BYTES, "consume resource policy")
    envelope = issuer._read(raw, work)
    issuer.shape._literal(envelope["schema"], issuer.V3_SCHEMA)
    issuer._signature(envelope, root_public_key, work)
    result = _admit_on_work(payload=envelope["payload"], root_public_key=root_public_key,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        work=work, _continuity=_continuity)
    issuer._canonical(raw, envelope, work)
    result.live()
    return result


def _late_on_work(payload, original, root, lifetime, work):
    static = _admit_on_work(payload=payload, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    lifetime.interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    lifetime.narrow(payload["expiresAtEpochNs"], lifetime.window[5], lifetime.window[6])
    planner = issuer.activation._verify_on_work(bootstrap_bytes=original, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work)
    work.charge(input_bytes=16384, json_nodes=256)
    document = issuer.activation.codec._decode(original, work)["payload"]
    projected = {name: document[name] for name in sorted(resources.RESOURCE_FIELDS)}
    _same(projected, static.policy.payload["plannerResources"], work, "the complete original planner resource projection")
    lifetime.narrow(min(payload["expiresAtEpochNs"], planner.attestation_interval[1]),
        min(planner.maximum_plan_age_ns, payload["consumePlanner"]["launch"]["requestTimeoutSeconds"] * 1_000_000_000),
        planner.maximum_clock_skew_ns)
    launch = issuer.activation._launch_guard(planner.attestation_interval,
        planner.opening_sample, lifetime.current, work, _continuity=lifetime.continuity)

    def live():
        first = static.live()
        observed = launch()
        final = lifetime.current()
        if not first <= observed <= final:
            issuer._fail("consume late original clocks reversed")
        return final

    live()
    return planner, static.consume_public_key, live


def _produce_on_work(*, payload, root_private_key, root_public_key,
        live_window, transport_deadline_ns, work, _continuity=None):
    owned = issuer._capture(payload, work)
    issuer._payload_shape(owned, work)
    static = _admit_on_work(payload=owned, root_public_key=root_public_key,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        work=work, _continuity=_continuity)
    static.live()
    raw = issuer.activation.signing._sign(owned, issuer.V3_SCHEMA, issuer.MAX_BYTES,
        root_private_key, root_public_key, work)
    static.live()
    envelope = issuer._read(raw, work)
    issuer._signature(envelope, root_public_key, work)
    issuer.plan._same(envelope["payload"], owned, work, "consume resource signature exact output")
    static.live()
    return raw
