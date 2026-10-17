"""Bounded JIT parent commitments and independent original-byte replay.

The private signer commits bytes, not acquisition or custody authority. Only a
future configured producer may join it to a genuine native pass and actual
retention. Verification accepts raw originals and independent request, policy,
root, key and time pins; a signed result never replaces the complete replay.
No SQL, store, clock window, allowance, registry or execution grant is created.
This live verifier cannot renew an expired original for historical execution.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import os
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from catchplate import authority_jit_compound as compound
from catchplate import authority_webauthn_evidence as evidence
from catchplate import authority_webauthn_evidence_plan_clock as clock
from catchplate.authority_query_read_work import _ValidationWork


source = compound.source
SCHEMA = "catchplate.policyAuthorityJitCompoundPlan/v1"
ENVELOPE_SCHEMA = "catchplate.policyAuthorityJitCompoundPlanEnvelope/v1"
SIGNATURE_DOMAIN = "catchplate.policyAuthorityJitCompoundPlanSignature/v1"
IDENTITY_DOMAIN = "catchplate.policyAuthorityJitCompoundPlanIdentity/v1"
REQUEST_DOMAIN = "catchplate.policyAuthorityJitCompoundPlanRequestIdentity/v1"
MANIFEST_DOMAIN = "catchplate.policyAuthorityJitOriginalManifestIdentity/v1"
MAX_PARENT_BYTES, MAX_CONTEXT_BYTES, MAX_MANIFEST_BYTES = 32768, 65536, 131072
EXPECTATION_FIELDS = frozenset({"requestDigest", "operationId", "configurationDigest",
    "plannerIdentity", "plannerSpkiDigest", "assertionPolicy", "businessBeforeRoots",
    "authorizationBeforeRoots", "countedBeforeHeads", "databaseCutoffUs", "originalDeadlineNs",
    "maximumPlanAgeNs", "maximumClockSkewNs"})
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "operation", "operationId", "requestDigest",
    "configurationDigest", "plannerIdentity", "plannerSpkiDigest", "requestBytesDigest",
    "requestByteCount", "contextDigest", "contextByteCount", "manifestDigest", "manifestByteCount",
    "issuedAtEpochNs", "expiresAtEpochNs"})
MANIFEST_FIELDS = frozenset({"schema", "contextDigest", "originalChainDigest", "originalCount",
    "originalBytes", "originals", "businessAfterRoots", "authorizationAfterRoots", "countedAfterHeads", "result"})
DESCRIPTOR_FIELDS = frozenset({"kind", "ordinal", "byteLength", "digest"})
_ROOT_FIELDS = compound.original._ROOT
_HEAD_FIELDS = compound.original._HEAD


class JitCompoundPlanError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class VerifiedJitCompoundPlan:
    """Same-call outputs, never a successful proof/custody input."""

    envelope_bytes: bytes
    request_bytes: bytes
    context_bytes: bytes
    manifest_bytes: bytes
    plan_digest: str
    replay: compound.JitPassObservation


def _require(value):
    if not value:
        raise JitCompoundPlanError("JIT parent differs from its independent originals or live bounds")


def _object(value, fields):
    _require(type(value) is dict and len(value) == len(fields)
        and all(type(name) is str for name in value) and set(value) == fields)


def _same(left, right, work):
    first, second = work.wire(left), work.wire(right)
    work.charge(input_bytes=len(first) + len(second))
    _require(first == second)


def _same_bytes(left, right, work):
    _require(type(left) is bytes and type(right) is bytes)
    work.charge(input_bytes=len(left) + len(right))
    _require(left == right)


def _decode(raw, maximum, work, *, nodes=4096, depth=16):
    """Owned canonical ASCII object only; no embedded authority is adopted."""
    value = evidence.wire._decode_object(raw, work=work, maximum_bytes=maximum,
        maximum_nodes=nodes, maximum_depth=depth)
    _same_bytes(raw, work.wire(value), work)
    return value


def _root_documents(values, contracts, root_class, work):
    _require(type(values) is list and len(values) == 4)
    for value in values:
        _object(value, _ROOT_FIELDS)
    _require(tuple(value["table"] for value in values)
        == tuple(item.table for item in contracts if item.root_class == root_class))
    work.charge(hashes=(source.authority.TREE_DEPTH + 2) * len(values))
    return source.batch._roots(values)


def _expectations(value, work):
    _require(type(work) is _ValidationWork)
    _object(value, EXPECTATION_FIELDS)
    owned = source.reads._CopyBudget(work).copy(value)
    shape = source.shape
    for name in ("requestDigest", "operationId", "configurationDigest", "plannerSpkiDigest"):
        shape._digest(owned[name])
    evidence._identity(owned["plannerIdentity"])
    source._policy(owned["assertionPolicy"])
    shape._integer(owned["databaseCutoffUs"], (2**63 - 1) // 1000)
    shape._integer(owned["originalDeadlineNs"], minimum=1)
    shape._integer(owned["maximumPlanAgeNs"], source.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(owned["maximumClockSkewNs"], source.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    work.charge(input_bytes=32768, json_nodes=1024)
    contracts = source.primary_contract.primary_table_contracts(compound.OPERATION)
    _require(len(contracts) == 8)
    business = _root_documents(owned["businessBeforeRoots"], contracts, "business", work)
    authorization = _root_documents(owned["authorizationBeforeRoots"], contracts, "authorization", work)
    values = owned["countedBeforeHeads"]
    _require(type(values) is list and len(values) == 12)
    for value in values:
        _object(value, _HEAD_FIELDS)
        shape._digest(value["rootDigest"])
        shape._integer(value["indexRevision"])
        shape._integer(value["leafCount"])
    _require(tuple(value["indexId"] for value in values) == source.heads._jit_receipt_ids())
    work.prepare_copy(values)
    heads = tuple(source.read_write.CompleteReadWriteHead(value["indexId"], value["indexRevision"],
        compound.CountedNode(value["rootDigest"], value["leafCount"])) for value in values)
    return owned, business, authorization, heads


def _originals(request_raw, context_raw, manifest_raw, expectations, work):
    # Capture the entire independent graph before key/clock/read callbacks.
    expected, business, authorization, heads = _expectations(expectations, work)
    for raw, maximum in ((request_raw, source.authority.MAX_REQUEST_BYTES),
            (context_raw, MAX_CONTEXT_BYTES), (manifest_raw, MAX_MANIFEST_BYTES)):
        _require(type(raw) is bytes and 2 <= len(raw) <= maximum)
    request = _decode(request_raw, source.authority.MAX_REQUEST_BYTES, work,
        nodes=source.reads.MAX_JSON_NODES, depth=source.reads.MAX_JSON_DEPTH)
    for name in ("requestDigest", "operationId"):
        _same(request[name], expected[name], work)
    # The genuine source anchor helper also checks every profile's genesis,
    # count and parent-table join; embedded context is never its input.
    _anchors, business, authorization, _now = compound.original._anchors(request=request,
        assertion_policy=expected["assertionPolicy"], business_before_roots=business,
        authorization_before_roots=authorization, counted_before_heads=heads,
        database_cutoff_us=expected["databaseCutoffUs"], work=work)
    actual_context = compound._context(request, expected["assertionPolicy"], business, authorization,
        heads, expected["databaseCutoffUs"], expected["originalDeadlineNs"], work)
    _require(len(actual_context) <= MAX_CONTEXT_BYTES)
    _same_bytes(context_raw, actual_context, work)
    manifest = _decode(manifest_raw, MAX_MANIFEST_BYTES, work)
    _object(manifest, MANIFEST_FIELDS)
    _require(manifest["schema"] == compound.MANIFEST_SCHEMA and type(manifest["result"]) is dict)
    context_digest = evidence.plan._frame(compound.CONTEXT_DOMAIN, (context_raw,), work)
    _same(manifest["contextDigest"], context_digest, work)
    descriptors = manifest["originals"]
    _require(type(descriptors) is list and 1 <= len(descriptors) <= compound.MAX_ORIGINALS)
    source.shape._integer(manifest["originalCount"], compound.MAX_ORIGINALS, minimum=1)
    source.shape._integer(manifest["originalBytes"], compound.MAX_ORIGINAL_BYTES, minimum=2)
    _require(manifest["originalCount"] == len(descriptors))
    source.shape._digest(manifest["originalChainDigest"])
    chain = evidence.plan._frame(compound.SEED_DOMAIN,
        (evidence.plan._ascii(context_digest, work),), work)
    seen, total = set(), 0
    limits = {"primary-chunk": (7 * compound.rows.chunks.MAX_ROW_DATA_CHUNKS,
            compound.frames.MAX_CHUNK_BYTES),
        "primary-proof": (8, compound.frames.MAX_PROOF_BYTES),
        "index-frontier": (12, compound.frames.MAX_INDEX_BYTES)}
    for value in descriptors:
        _object(value, DESCRIPTOR_FIELDS)
        kind = value["kind"]
        _require(type(kind) is str and kind in limits)
        count, maximum = limits[kind]
        source.shape._integer(value["ordinal"], count - 1)
        source.shape._integer(value["byteLength"], maximum, minimum=2)
        source.shape._digest(value["digest"])
        address = kind, value["ordinal"]
        _require(address not in seen and value["byteLength"] <= compound.MAX_ORIGINAL_BYTES - total)
        work.charge(input_bytes=256, json_nodes=16)
        seen.add(address)
        total += value["byteLength"]
        chain = evidence.plan._frame(compound.STEP_DOMAIN,
            (evidence.plan._ascii(chain, work), work.wire(value)), work)
    _require(total == manifest["originalBytes"])
    _same(chain, manifest["originalChainDigest"], work)
    contracts = source.primary_contract.primary_table_contracts(compound.OPERATION)
    _root_documents(manifest["businessAfterRoots"], contracts, "business", work)
    _root_documents(manifest["authorizationAfterRoots"], contracts, "authorization", work)
    _same(manifest["authorizationAfterRoots"], expected["authorizationBeforeRoots"], work)
    after_heads = manifest["countedAfterHeads"]
    _require(type(after_heads) is list and len(after_heads) == 12)
    for value in after_heads:
        _object(value, _HEAD_FIELDS)
        source.shape._digest(value["rootDigest"])
        source.shape._integer(value["indexRevision"])
        source.shape._integer(value["leafCount"])
    _require(tuple(value["indexId"] for value in after_heads) == source.heads._jit_receipt_ids())
    return expected, request, business, authorization, heads


def _payload_shape(payload):
    _object(payload, PAYLOAD_FIELDS)
    _require(payload["schema"] == SCHEMA and payload["sourceRevision"] == source.authority.SOURCE_REVISION
        and type(payload["operation"]) is str and payload["operation"] == compound.OPERATION)
    evidence._identity(payload["plannerIdentity"])
    for name in ("operationId", "requestDigest", "configurationDigest", "plannerSpkiDigest",
            "requestBytesDigest", "contextDigest", "manifestDigest"):
        source.shape._digest(payload[name])
    for name, maximum in (("requestByteCount", source.authority.MAX_REQUEST_BYTES),
            ("contextByteCount", MAX_CONTEXT_BYTES), ("manifestByteCount", MAX_MANIFEST_BYTES)):
        source.shape._integer(payload[name], maximum, minimum=2)
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        source.shape._integer(payload[name], minimum=1)


def _bind(payload, expected, request_raw, context_raw, manifest_raw, work):
    _payload_shape(payload)
    for name in ("operationId", "requestDigest", "configurationDigest", "plannerIdentity", "plannerSpkiDigest"):
        _same(payload[name], expected[name], work)
    for raw, domain, digest, count in ((request_raw, REQUEST_DOMAIN, "requestBytesDigest", "requestByteCount"),
            (context_raw, compound.CONTEXT_DOMAIN, "contextDigest", "contextByteCount"),
            (manifest_raw, MANIFEST_DOMAIN, "manifestDigest", "manifestByteCount")):
        _same(payload[count], len(raw), work)
        _same(payload[digest], evidence.plan._frame(domain, (raw,), work), work)


class _Live:
    def __init__(self, expected, payload, window, work):
        self.window = clock._validate(window)
        _require(self.window[5:] == (expected["maximumPlanAgeNs"], expected["maximumClockSkewNs"]))
        self.work, self.limits = work, work.limits
        self.maximums = (self.limits.max_hashes, self.limits.max_input_bytes, self.limits.max_json_nodes)
        self.interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        self.cutoff = expected["databaseCutoffUs"] * 1000
        self.deadline = min(expected["originalDeadlineNs"], self.window[4])
        self.process, self.thread = os.getpid(), threading.get_ident()
        self.failed = self.busy = False
        self.suspended = self.owner = self.stage = None
        self.last = 0

    def live(self, work):
        _require(not self.failed and type(work) is _ValidationWork
            and (os.getpid(), threading.get_ident()) == (self.process, self.thread)
            and self.work.limits is self.limits
            and (self.limits.max_hashes, self.limits.max_input_bytes, self.limits.max_json_nodes) == self.maximums
            and (self.suspended is None or self.work.metrics == self.suspended))
        source.batch._SharedLedger(self.work)
        now = clock._check_on_work(self.window, work=work)
        issued, expires = self.interval
        maximum, skew = self.window[5:]
        _require(0 < issued < expires and expires - issued <= maximum
            and issued <= now + skew and now - issued <= maximum and now < expires
            and abs(self.cutoff - issued) <= skew and self.cutoff < expires)
        current = evidence.production._callback(work, time.monotonic_ns)
        _require(type(current) is int and self.last <= current < self.deadline)
        self.last = current

    def checked(self, stage, check):
        try:
            _require(not self.busy and type(stage) is compound._Stage and stage.work is not self.work
                and stage.acquisition is None and stage._owner._active is stage)
            if self.owner is None:
                self.owner = stage._owner
            _require(stage._owner is self.owner)
            self.stage = stage
            self.live(stage.work)
            self.busy = True
            _require(evidence.production._callback(stage.work, lambda: check(stage)) is None)
            self.live(stage.work)
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False

    def read(self, kind, ordinal, work, read_original):
        try:
            _require(not self.busy and self.stage is not None and work is self.stage.work
                and self.stage._owner is self.owner and self.owner._active is self.stage)
            self.live(work)
            self.busy = True
            # Actual raw transport may debit this genuine child. The enclosing
            # compound checks its exact limits/counter monotonicity and bytes.
            result = read_original(kind, ordinal, work)
            _require(type(result) is bytes)
            self.live(work)
            return result
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False


def _sign_payload(payload, private, public, work):
    ledger = evidence.capture._SharedLedger(work)
    encoded = evidence.capability._wire(payload, ledger, MAX_PARENT_BYTES, 2048)
    message = evidence.plan._ascii(evidence.plan._frame(SIGNATURE_DOMAIN, (encoded,), work), work)
    placeholder = {"schema": ENVELOPE_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
    size, nodes = work.measure(placeholder)
    payload_size, payload_nodes = work.measure(payload)
    _require(size <= MAX_PARENT_BYTES and nodes <= 2048)
    work.charge(input_bytes=3 * payload_size + size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=payload_nodes + nodes)
    _require(work.limits.max_input_bytes - work.input_bytes >= payload_size
        and work.limits.max_json_nodes - work.json_nodes >= payload_nodes)
    signature = evidence.production._sign_and_verify(private, public, message, work)
    _require(work.measure(payload) == (payload_size, payload_nodes)
        and evidence.plan.core.canonical_bytes(payload) == encoded)
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    source.shape._base64url(encoded_signature, signature=True)
    result = evidence.plan.core.canonical_bytes({"schema": ENVELOPE_SCHEMA,
        "payload": payload, "signatureBase64Url": encoded_signature})
    _require(len(result) == size)
    return result


def _sign_parent_on_work(*, request_bytes, context_bytes, manifest_bytes, expectations,
        planner_private_key, planner_public_key, issued_at_epoch_ns, expires_at_epoch_ns, live_window, work):
    """Private byte commitment only; no native/proof/custody success input."""
    _require(isinstance(planner_private_key, Ed25519PrivateKey)
        and isinstance(planner_public_key, Ed25519PublicKey))
    expected, _request, _business, _authorization, _heads = _originals(
        request_bytes, context_bytes, manifest_bytes, expectations, work)
    work.charge(input_bytes=8192, json_nodes=256)
    payload = {"schema": SCHEMA, "sourceRevision": source.authority.SOURCE_REVISION,
        "operation": compound.OPERATION,
        **{name: expected[name] for name in
            ("operationId", "requestDigest", "configurationDigest", "plannerIdentity", "plannerSpkiDigest")},
        "requestBytesDigest": evidence.plan._frame(REQUEST_DOMAIN, (request_bytes,), work),
        "requestByteCount": len(request_bytes),
        "contextDigest": evidence.plan._frame(compound.CONTEXT_DOMAIN, (context_bytes,), work),
        "contextByteCount": len(context_bytes),
        "manifestDigest": evidence.plan._frame(MANIFEST_DOMAIN, (manifest_bytes,), work),
        "manifestByteCount": len(manifest_bytes), "issuedAtEpochNs": issued_at_epoch_ns,
        "expiresAtEpochNs": expires_at_epoch_ns}
    _bind(payload, expected, request_bytes, context_bytes, manifest_bytes, work)
    live = _Live(expected, payload, live_window, work)
    try:
        live.live(work)
        evidence.keys._public_binding(planner_public_key, expected["plannerSpkiDigest"], work)
        evidence.keys._pair_on_work(planner_private_key, planner_public_key, work)
        live.live(work)
        result = _sign_payload(payload, planner_private_key, planner_public_key, work)
        live.live(work)
        return result
    except BaseException:
        live.failed = True
        raise


def verify_retained(*, envelope_bytes, request_bytes, context_bytes, manifest_bytes, expectations,
        planner_public_key, live_window, read_original, check, work) -> VerifiedJitCompoundPlan:
    """Authenticate original commitments, then replay every actual raw body.

    read_original(kind, ordinal, active_child_work) returns exact bytes only.
    check(actual_compound_stage) returns None and cannot spend its stage work.
    Both callbacks preserve this suspended parent's original allowance. Their
    configured caller must separately establish custody/currentness authority.
    """
    _require(isinstance(planner_public_key, Ed25519PublicKey) and callable(read_original) and callable(check))
    expected, request, business, authorization, heads = _originals(
        request_bytes, context_bytes, manifest_bytes, expectations, work)
    envelope = _decode(envelope_bytes, MAX_PARENT_BYTES, work, nodes=2048, depth=12)
    _object(envelope, frozenset({"schema", "payload", "signatureBase64Url"}))
    _require(envelope["schema"] == ENVELOPE_SCHEMA)
    payload = envelope["payload"]
    _bind(payload, expected, request_bytes, context_bytes, manifest_bytes, work)
    live = _Live(expected, payload, live_window, work)
    try:
        live.live(work)
        evidence.keys._public_binding(planner_public_key, expected["plannerSpkiDigest"], work)
        ledger = evidence.capture._SharedLedger(work)
        encoded = evidence.capability._wire(payload, ledger, MAX_PARENT_BYTES, 2048)
        evidence.capability._signature(planner_public_key, envelope["signatureBase64Url"],
            SIGNATURE_DOMAIN, encoded, ledger)
        digest = evidence.plan._frame(IDENTITY_DOMAIN, (envelope_bytes,), work)
        live.live(work)
        live.suspended = work.metrics
        actual = evidence.production._callback(work, lambda: compound.run_pass(request=request,
            assertion_policy=expected["assertionPolicy"], business_before_roots=business,
            authorization_before_roots=authorization, counted_before_heads=heads,
            database_cutoff_us=expected["databaseCutoffUs"], original_deadline_ns=expected["originalDeadlineNs"],
            cursor=None, trace=None, check=lambda stage: live.checked(stage, check),
            read_original=lambda kind, ordinal, child: live.read(kind, ordinal, child, read_original)))
        live.suspended = None
        live.live(work)
        _require(type(actual) is compound.JitPassObservation)
        _same_bytes(actual.context_bytes, context_bytes, work)
        _same_bytes(actual.original_manifest_bytes, manifest_bytes, work)
        live.live(work)
        return VerifiedJitCompoundPlan(envelope_bytes, request_bytes, context_bytes, manifest_bytes, digest, actual)
    except BaseException:
        live.failed = True
        raise
