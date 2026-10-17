"""Current custody's explicit independently pinned RI evidence association.

No archive discovery, retired signing, successful input DTO or release callback.
Only the outer current-root custody verifier calls this original-data admission.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib

from catchplate import oidc_session_activation_release_custody_bootstrap as custody
from catchplate import oidc_session_activation_release_intent_enrollment as intent_keys
from catchplate import oidc_session_activation_release_proof_enrollment as proof_keys


authorization, shape, plan = custody.authorization, custody.shape, custody.plan
planner, production = custody.planner_bootstrap, custody.production
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
_EXTRA_FIELDS = frozenset({"intentAuthorityRoot", "intentAuthorityInterval",
    "intentEnrollment", "proofEnrollment", "proofScope", "historicalReleaseCustody",
    "currentActivationPlanner"})
_LIMITS = (("plannerBootstrap", planner.MAX_BYTES),
    ("intentEnrollment", intent_keys.MAX_BYTES), ("proofEnrollment", proof_keys.MAX_BYTES),
    ("historicalReleaseCustody", custody.MAX_BYTES), ("currentActivationPlanner", planner.MAX_BYTES))


def _same_bytes(actual, expected, work, label):
    if type(actual) is not bytes or type(expected) is not bytes:
        custody._fail("retained release association lacks original bytes")
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        custody._fail("retained release original differs: " + label)


def unique_keys(values, work):
    selected, seen = [], []
    for key in values:
        pin = planner.keys._spki_on_work(key, work)
        work.prepare_scan(seen)
        if pin not in seen:
            seen.append(pin)
            selected.append(key)
    return tuple(selected)


def _shape(payload, work):
    shape._object(payload, custody._PAYLOAD_FIELDS | _EXTRA_FIELDS,
        "current custody over independently selected retained intent authority")
    shape._literal(payload["schema"], custody.V2_PAYLOAD_SCHEMA)
    # Reuse only the v1 scalar grammar; this projection is never signed,
    # returned, or admitted as an original or execution permission.
    common = {name: payload[name] for name in custody._PAYLOAD_FIELDS}
    common["schema"] = custody.PAYLOAD_SCHEMA
    custody._payload_shape(common, work)
    root = payload["intentAuthorityRoot"]
    shape._object(root, frozenset({"publicKeyPem", "spkiDigest"}), "independent RI root")
    pem = root["publicKeyPem"]
    if (type(pem) is not str or not 1 <= len(pem) <= authorization.MAX_PEM_BYTES
            or not pem.isascii() or "\0" in pem):
        custody._fail("independent RI root PEM is not bounded original text")
    shape._digest(root["spkiDigest"])
    interval = payload["intentAuthorityInterval"]
    shape._object(interval, frozenset({"issuedAtEpochNs", "expiresAtEpochNs"}), "RI archive interval")
    for value in interval.values():
        shape._integer(value, minimum=1)
    if interval["issuedAtEpochNs"] >= interval["expiresAtEpochNs"]:
        custody._fail("RI archive interval is empty")
    proof_keys._scope_shape(payload["proofScope"])
    for name, maximum in _LIMITS:
        record = payload[name]
        shape._object(record, custody._ORIGINAL_FIELDS, "retained release original")
        shape._integer(record["byteCount"], maximum, minimum=2)
        authorization.transport._transport_shape(record["base64Url"], record["byteCount"], maximum)
        shape._digest(record["bytesDigest"])


def _original(record, maximum, work, current):
    current()
    raw = authorization.transport._decode(record["base64Url"], record["byteCount"], maximum, work)
    work.charge(hashes=1, input_bytes=len(raw))
    digest = production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())
    current()
    plan._same(digest, record["bytesDigest"], work, "retained release independently pinned original")
    return raw


def _material(payload, original, root, window, deadline, opening, work, current, *, _current=None):
    declared = sum(payload[name]["byteCount"] for name, _ in _LIMITS)
    # Nested historical custody and both planners are decoded again by genuine
    # verifiers. Forecast before their first allocation; never reset work.
    if len(original) + 8 * declared + 8 * authorization.MAX_ENROLLMENT_BYTES + 64 * 1024 > MAX_ORIGINAL_BYTES:
        custody._fail("retained RI custody exceeds its unchanged original inventory")
    current()
    evidence_root = authorization._role_key(payload["intentAuthorityRoot"], work)
    current()
    raw = {name: _original(payload[name], maximum, work, current) for name, maximum in _LIMITS}
    old = custody._verify_historical_on_work(custody_bytes=raw["historicalReleaseCustody"],
        root_public_key=evidence_root, live_window=window, transport_deadline_ns=deadline,
        work=work, _current=current)
    current()
    _same_bytes(raw["plannerBootstrap"], old.planner.bootstrap_bytes, work, "RI planner/custody")
    old_payload = custody._decode(raw["historicalReleaseCustody"], work)["payload"]
    for name in custody._PAYLOAD_FIELDS - {"schema", "issuedAtEpochNs", "expiresAtEpochNs"}:
        plan._same(payload[name], old_payload[name], work, "current custody unchanged RI binding " + name)
    selected = payload["intentAuthorityInterval"]
    interval = selected["issuedAtEpochNs"], selected["expiresAtEpochNs"]
    if not interval[0] <= old.attestation_interval[0] < old.attestation_interval[1] <= interval[1]:
        custody._fail("original RI custody escapes independently selected archive interval")
    current_planner = planner._verify_historical_on_work(
        bootstrap_bytes=raw["currentActivationPlanner"], root_public_key=root,
        live_window=window, transport_deadline_ns=deadline, work=work,
        _continuity=custody._continuity(current, work))
    current()
    # The current template must preserve the dedicated delivery process's
    # isolation too; historical role separation alone is not current custody.
    roles = current_planner.configuration_payload["roles"]
    shape._object(roles, frozenset(planner.configuration._ROLE_NAMES), "current release configured roles")
    for name in planner.configuration._ROLE_NAMES:
        for field in ("serviceUid", "serviceGid"):
            shape._integer(roles[name][field], 2**32 - 2)
            if roles[name][field] == custody.SERVICE_UID:
                custody._fail("current release process shares a configured generic role")
    old_state = authorization._admit_enrollment_on_work(
        enrollment_bytes=old.planner.state_enrollment_bytes, root_public_key=evidence_root, work=work)
    current()
    new_state = authorization._admit_enrollment_on_work(
        enrollment_bytes=current_planner.state_enrollment_bytes, root_public_key=root, work=work)
    current()
    for actual, expected in ((old_state.payload, new_state.payload),
            (old_state.enrollment_digest, old.planner.state_enrollment_digest),
            (new_state.enrollment_digest, current_planner.state_enrollment_digest),
            (old.planner.generation["digest"], current_planner.generation["digest"]),
            (old.delivery_key_digest, current_planner.delivery_key_digest)):
        plan._same(actual, expected, work, "retained RI/current complete state and original delivery key")
    scope = payload["proofScope"]
    for name, expected in (("configurationDigest", old.planner.configuration_digest),
            ("databaseId", old_state.payload["databaseId"]),
            ("generationDigest", old.planner.generation["digest"]),
            ("runtimeClosureDigest", old.planner.runtime_closure_digest),
            ("receiverIdentity", old.receiver_identity)):
        plan._same(scope[name], expected, work, "retained RI proof scope " + name)
    # Caller identity is authenticated by the original enrollment, not guessed
    # from the fresh grant or recovered from a response record.
    enrollment = intent_keys._read(raw["intentEnrollment"], work)
    intent_scope = {name: scope[name] for name in intent_keys.SCOPE_FIELDS if name != "callerId"}
    intent_scope["callerId"] = enrollment["payload"]["callerId"]
    forbidden = unique_keys((old.planner.planner_public_key, current_planner.planner_public_key,
        old_state.computation_public_key, old_state.completion_public_key, old_state.state_public_key,
        root, evidence_root), work)
    admitted_intent = intent_keys._admit_on_work(enrollment_bytes=raw["intentEnrollment"],
        root_public_key=evidence_root, expected_scope=intent_scope, forbidden_public_keys=forbidden, work=work)
    current()
    proof_keys._admit_on_work(enrollment_bytes=raw["proofEnrollment"], root_public_key=evidence_root,
        expected_scope=scope, forbidden_public_keys=(*forbidden, admitted_intent.caller_public_key), work=work)
    current()
    return replace(old, custody_bytes=original,
        attestation_interval=(payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]),
        opening_sample=opening, intent_root_public_key=evidence_root,
        intent_authority_interval=interval, intent_enrollment_bytes=raw["intentEnrollment"],
        proof_enrollment_bytes=raw["proofEnrollment"], proof_scope=scope,
        historical_custody_bytes=raw["historicalReleaseCustody"], current_activation_planner=current_planner)


def root_for(material, current_root):
    if type(material) is not custody._ReleaseCustodyMaterial:
        custody._fail("retained release authority requires genuine custody-original admission")
    return current_root if material.intent_root_public_key is None else material.intent_root_public_key


def planner_for(material):
    return material.planner if material.current_activation_planner is None else material.current_activation_planner


def custody_for(material):
    return material.custody_bytes if material.historical_custody_bytes is None else material.historical_custody_bytes


def require_originals(material, intent_enrollment, proof_enrollment, work):
    if material.intent_root_public_key is not None:
        _same_bytes(intent_enrollment, material.intent_enrollment_bytes, work, "RI intent enrollment")
        _same_bytes(proof_enrollment, material.proof_enrollment_bytes, work, "RI proof enrollment")


def contain(material, payload):
    if material.intent_authority_interval is not None:
        before, after = material.intent_authority_interval
        if not before <= payload["issuedAtEpochNs"] < payload["expiresAtEpochNs"] <= after:
            custody._fail("retained RI signed original escapes selected archive interval")
