"""Unregistered, explicit-input planning for trust publication completion.

The owning composer must independently admit the selected rows, committed
aggregate stage/root transition, installer key/measurement, target and time.
Neither an arbitrary KernelContext nor the supplied stage graph establishes
those facts. The genuine signature binds the complete expected installation,
including its original bytes; no unsigned local installer observation is used.

The business helper returns four ordinary (owned selected row, updated row)
pairs: publication, high-water, audit and exact v2 evidence consumption. The
private mutation adapter renders all four together as a KernelTransition;
neither helper registers a kernel or reinterprets a v1 evidence receipt. The
existing common finalizer must still plan the audit-capacity mutation before
after-roots, using the same original work allowance.
There is no database/file write, post-root side effect, signing, future witness
receipt, or claim that local rows establish root currentness. Exact execution
replay belongs to the execution envelope; a published row cannot be re-emitted.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_contract as authority
from catchplate import authority_transition_core as core
from catchplate import authority_webauthn_evidence as evidence
from catchplate import authority_webauthn_trust as trust
from catchplate import webauthn_trust_core as bundle_core


OPERATION = "webauthn.trust.complete"
CLAIMS_SCHEMA = "catchplate.policyAuthorityWebAuthnTrustInstallation/v2"
PUBLICATION_DOMAIN = "catchplate.policyAuthorityWebAuthnStagedPublication/v2"
EVIDENCE_TYPE = "webauthn-trust-installation/v2"
MAX_STAGED_WITHDRAWAL_IDS = 192
_ARGUMENT_FIELDS = frozenset({"publication_id", "verification_evidence_digest", "businessIntent"})
_PUBLICATION_FIELDS = frozenset({"id", "scope", "previous_bundle_digest", "bundle_digest",
    "sequence", "rollback_epoch", "signing_key_id", "bundle_json", "payload_digest",
    "actor_id", "withdrawn_credential_ids_json", "audit_event_json", "status", "attempts",
    "last_error", "created_at", "published_at"})
_PUBLICATION_MATERIAL = tuple(sorted(_PUBLICATION_FIELDS - {
    "status", "attempts", "last_error", "published_at"}))
_HIGH_WATER_FIELDS = frozenset({"authority_scope", "rollback_epoch", "publication_sequence",
    "publication_digest", "metadata_blob_digest", "revocation_set_digest",
    "witness_receipt_digest", "witness_sequence", "updated_at_epoch_ns"})
_STAGE_FIELDS = frozenset({"operationId", "requestDigest", "receiptDigest", "beforeRootsDigest",
    "afterRootsDigest", "fenceDigest", "witnessReceiptDigest", "witnessSequence",
    "publicationRowDigest", "previousHighWaterDigest"})
_STATE_FIELDS = frozenset({"version", "bundle_digest", "sequence", "rollback_epoch", "updated_at"})
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_I64_MAX = 2**63 - 1


class WebAuthnTrustCompletionError(ValueError):
    pass


def _object(value, fields, label):
    if (type(value) is not dict or len(value) != len(fields)
            or any(type(key) is not str for key in value) or set(value) != fields):
        raise WebAuthnTrustCompletionError(f"{label} is not source closed")


def _text(value, label, maximum=1024):
    if type(value) is not str or not 1 <= len(value) <= maximum or "\x00" in value:
        raise WebAuthnTrustCompletionError(f"{label} is not bounded exact text")
    if len(value.encode("utf-8")) > maximum:
        raise WebAuthnTrustCompletionError(f"{label} exceeds its UTF-8 bound")


def _integer(value, label, minimum=0):
    if type(value) is not int or not minimum <= value <= _I64_MAX:
        raise WebAuthnTrustCompletionError(f"{label} is not a bounded exact integer")


def _utc(value, label):
    _text(value, label, 64)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise WebAuthnTrustCompletionError(f"{label} is not an ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise WebAuthnTrustCompletionError(f"{label} is not UTC")
    return parsed


def _now(value):
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        raise WebAuthnTrustCompletionError("completion requires independently admitted exact UTC time")
    delta = value - _EPOCH
    result = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
    _integer(result, "completion time", 1)
    return result


def _digest(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _frame(domain, value, work):
    return evidence.plan._frame(domain, (work.wire(value),), work)


def _same(actual, expected, work, label):
    evidence.plan._same(actual, expected, work, label)


def _decode(raw, work, maximum):
    """Actual bounded duplicate-rejecting JSON parse, including list roots."""
    if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
        raise WebAuthnTrustCompletionError("completion JSON original exceeds its byte bound")
    nodes, hooks = evidence.wire._preflight(raw, work,
        maximum_nodes=evidence.plan.contract.MAX_JSON_NODES,
        maximum_depth=evidence.plan.contract.MAX_JSON_DEPTH)
    work.charge(input_bytes=3 * len(raw), json_nodes=nodes + hooks)
    try:
        return json.loads(raw.decode("ascii"), object_pairs_hook=evidence.wire._unique_object,
            parse_int=evidence.wire._parse_integer, parse_float=evidence.wire._reject_number,
            parse_constant=evidence.wire._reject_number)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise WebAuthnTrustCompletionError("completion JSON original is not bounded lossless ASCII") from exc


def _stored(value, work, maximum=2 * 1024 * 1024):
    if type(value) is not str or not 2 <= len(value) <= maximum:
        raise WebAuthnTrustCompletionError("completion stored JSON is not bounded text")
    work.prepare_utf8(value)
    return _decode(value.encode("utf-8"), work, maximum)


def _audit_id(request_digest, work):
    return core._deterministic_uuid(operation=OPERATION, request_digest=request_digest,
        purpose="webauthn-trust-publication-audit", work=work)


def completion_queries(*, publication_id, verification_evidence_digest, request_digest, work):
    """Close all four exact business queries; common capacity remains separate."""
    evidence.capture._SharedLedger(work)
    _text(publication_id, "publication ID")
    core.require_digest(request_digest, "completion request digest")
    core.require_digest(verification_evidence_digest, "completion evidence digest")
    values = ((trust.PUBLICATION_TABLE, "id", publication_id),
        (trust.HIGH_WATER_TABLE, "authority_scope", trust.AUTHORITY_SCOPE),
        ("metadata_audit_outbox", "id", _audit_id(request_digest, work)),
        ("policy_authority_external_evidence_receipts", "evidence_digest", verification_evidence_digest))
    queries = tuple(core.BoundedQuery(query_id=core.query_program_id(OPERATION, name, table),
        table=table, predicates=(core.QueryPredicate(column, "eq", value),),
        order_by=(core.QueryOrder(column),), maximum_rows=1, absent_key={column: value},
        require_absence=name == "audit")
        for name, (table, column, value) in zip(("publication", "high_water", "audit", "evidence"), values))
    spec = authority.operation_spec(OPERATION)
    if (sum(query.maximum_rows for query in queries) > spec["maximumBusinessQueryRows"]
            or sum(query.work_units for query in queries) > spec["maximumBusinessWorkUnits"]):
        raise WebAuthnTrustCompletionError("completion queries exceed their business allowance")
    return core.close_queries(OPERATION, queries)


def _business_count(context, work):
    if (type(context) is not core.KernelContext or type(context.operation) is not str
            or context.operation != OPERATION or type(context.selected_rows) is not tuple
            or len(context.selected_rows) > authority.operation_spec(OPERATION)["maximumQueryRows"]
            or any(type(selected) is not dict for selected in context.selected_rows)):
        raise WebAuthnTrustCompletionError("completion context is not source-bounded")
    work.prepare_scan(context.selected_rows)
    count = sum(not (selected.get("table") == capacity.AGGREGATE_TABLE
        and selected.get("key") == {"aggregate_id": capacity.AGGREGATE_ID})
        for selected in context.selected_rows)
    if count > authority.operation_spec(OPERATION)["maximumBusinessQueryRows"]:
        raise WebAuthnTrustCompletionError("completion selected business rows exceed their allowance")
    return count


def _installation_claims_on_work(*, installed_bundle_bytes, installed_state_bytes,
        publication_row, high_water_row, expected_committed_stage,
        installation_target_digest, observed_at, work):
    """Recompute installation claims from owned originals and admitted rows.

    Every caller runs the real semantic checks below. The returned claims and
    owned row ingredients are ordinary data; no API accepts this output as a
    successful-proof token. Admission of the committed stage, current rows,
    physical installation/readback, target and observation time belongs to the
    owning caller. Byte equality cannot establish fsync, runtime activation or
    filesystem ownership. No future completion receipt occurs in these claims.
    """
    ledger = evidence.capture._SharedLedger(work)
    core.require_digest(installation_target_digest, "independently configured installation target")
    now_ns = _now(observed_at)
    for raw, maximum in ((installed_bundle_bytes, bundle_core.MAX_INSTALLATION_BYTES),
                        (installed_state_bytes, bundle_core.MAX_STATE_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise WebAuthnTrustCompletionError("completion requires bounded immutable installation originals")
    owned = evidence.capture._JSONCapture(ledger).visit({"publication": publication_row,
        "highWater": high_water_row, "stage": expected_committed_stage})
    publication, high, stage = owned["publication"], owned["highWater"], owned["stage"]
    _object(stage, _STAGE_FIELDS, "independently admitted committed stage")
    for field in _STAGE_FIELDS - {"witnessSequence"}:
        core.require_digest(stage[field], "committed stage " + field)
    _integer(stage["witnessSequence"], "committed stage witness sequence", 1)
    _same(stage["operationId"], evidence.plan._frame("catchplate.policyAuthorityOperation/v2",
        (evidence.plan._ascii("webauthn.trust.stage", work),
         evidence.plan._ascii(stage["requestDigest"], work)), work), work, "committed stage operation changed")
    _object(publication, _PUBLICATION_FIELDS, "staged publication")
    _object(high, _HIGH_WATER_FIELDS, "trust high-water")
    _text(publication["id"], "publication ID")
    if (publication["scope"] != "global" or publication["status"] != "pending" or publication["published_at"] is not None
            or high["authority_scope"] != trust.AUTHORITY_SCOPE):
        raise WebAuthnTrustCompletionError("completion publication is not the pending global stage")
    for field in ("bundle_digest", "payload_digest", "signing_key_id", "previous_bundle_digest"):
        core.require_digest(publication[field], "publication " + field)
    for field in ("publication_digest", "metadata_blob_digest", "revocation_set_digest", "witness_receipt_digest"):
        core.require_digest(high[field], "high-water " + field)
    for row, fields in ((publication, ("sequence", "rollback_epoch")),
                       (high, ("publication_sequence", "witness_sequence"))):
        for field in fields:
            _integer(row[field], field, 1)
    _integer(publication["attempts"], "publication attempts")
    _integer(high["rollback_epoch"], "predecessor rollback epoch")
    _integer(high["updated_at_epoch_ns"], "predecessor update time")
    _text(publication["actor_id"], "publication actor")
    if publication["last_error"] is not None:
        _text(publication["last_error"], "publication last error", 2048)
    if (_utc(publication["created_at"], "stage creation") > observed_at
            or high["updated_at_epoch_ns"] > now_ns
            or publication["previous_bundle_digest"] != high["publication_digest"]
            or (publication["rollback_epoch"], publication["sequence"])
                <= (high["rollback_epoch"], high["publication_sequence"])
            or stage["witnessSequence"] <= high["witness_sequence"]):
        raise WebAuthnTrustCompletionError("completion predecessor, monotonicity or time changed")
    high_document = trust.high_water_document(rollback_epoch=high["rollback_epoch"],
        sequence=high["publication_sequence"], publication_digest=high["publication_digest"],
        metadata_blob_digest=high["metadata_blob_digest"], revocation_set_digest=high["revocation_set_digest"],
        witness_receipt_digest=high["witness_receipt_digest"], witness_sequence=high["witness_sequence"])
    previous_high_digest = trust.high_water_digest(high_document, work=work)
    work.prepare_copy(publication)
    publication_digest = _frame(PUBLICATION_DOMAIN,
        {field: publication[field] for field in _PUBLICATION_MATERIAL}, work)
    _same((stage["previousHighWaterDigest"], stage["publicationRowDigest"]),
        (previous_high_digest, publication_digest), work, "committed stage prestate changed")
    bundle = _stored(publication["bundle_json"], work)
    installed_bundle = _decode(installed_bundle_bytes, work, bundle_core.MAX_INSTALLATION_BYTES)
    _same(installed_bundle, bundle, work, "installed original bundle differs from committed stage")
    if type(bundle) is not dict or type(bundle.get("metadata")) is not dict:
        raise WebAuthnTrustCompletionError("staged bundle metadata is not an object")
    metadata = bundle["metadata"]
    _same((metadata.get("sequence"), metadata.get("rollbackEpoch"), metadata.get("signingKeyId")),
        (publication["sequence"], publication["rollback_epoch"], publication["signing_key_id"]),
        work, "staged bundle metadata changed")
    work.prepare_copy(bundle)
    work.prepare_copy(metadata)
    unsigned_bundle = {**bundle, "metadata": {key: value for key, value in metadata.items() if key != "signature"}}
    _same(_digest(work.wire(unsigned_bundle), work), publication["bundle_digest"], work,
        "staged unsigned bundle digest changed")
    state = _decode(installed_state_bytes, work, bundle_core.MAX_STATE_BYTES)
    _object(state, _STATE_FIELDS, "installed rollback state")
    _same((state["version"], state["bundle_digest"], state["sequence"], state["rollback_epoch"]),
        (1, publication["bundle_digest"], publication["sequence"], publication["rollback_epoch"]),
        work, "installed rollback state differs from committed stage")
    if _utc(state["updated_at"], "installed rollback timestamp") > observed_at:
        raise WebAuthnTrustCompletionError("installed rollback state is from the future")
    withdrawn = _stored(publication["withdrawn_credential_ids_json"], work)
    if type(withdrawn) is not list or len(withdrawn) > MAX_STAGED_WITHDRAWAL_IDS:
        raise WebAuthnTrustCompletionError("staged withdrawal set is not bounded")
    for item in withdrawn:
        _text(item, "withdrawn credential ID")
    work.prepare_copy(withdrawn)
    work.prepare_copy(withdrawn)
    _same(withdrawn, sorted(set(withdrawn)), work, "staged withdrawal set is not sorted and unique")
    event = _stored(publication["audit_event_json"], work)
    if type(event) is not dict:
        raise WebAuthnTrustCompletionError("stored completion audit is not an object")
    claims = {"schema": CLAIMS_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "publicationId": publication["id"], "publicationRowDigest": publication_digest,
        "previousBundleDigest": publication["previous_bundle_digest"], "previousHighWaterDigest": previous_high_digest,
        "bundleDigest": publication["bundle_digest"], "payloadDigest": publication["payload_digest"],
        "sequence": publication["sequence"], "rollbackEpoch": publication["rollback_epoch"],
        "signingKeyId": publication["signing_key_id"], "canonicalEnvelopeDigest": _digest(work.wire(bundle), work),
        "installedBundleBytesDigest": _digest(installed_bundle_bytes, work),
        "installedBundleByteCount": len(installed_bundle_bytes),
        "installedStateBytesDigest": _digest(installed_state_bytes, work),
        "installedStateByteCount": len(installed_state_bytes), "installationTargetDigest": installation_target_digest,
        "committedStageOperationId": stage["operationId"], "committedStageRequestDigest": stage["requestDigest"],
        "committedStageReceiptDigest": stage["receiptDigest"], "committedStageBeforeRootsDigest": stage["beforeRootsDigest"],
        "committedStageAfterRootsDigest": stage["afterRootsDigest"], "committedStageFenceDigest": stage["fenceDigest"],
        "witnessReceiptDigest": stage["witnessReceiptDigest"], "witnessSequence": stage["witnessSequence"]}
    return claims, publication, high, stage, withdrawn, event


def _complete_on_work(context, *, installation_envelope_bytes, installed_bundle_bytes,
        installed_state_bytes, installation_target_digest, expected_committed_stage,
        installer_public_key, expected_installer_identity, expected_installer_spki_digest,
        maximum_age_ns, maximum_clock_skew_ns, work):
    """Recompute the shared checks, consume exact evidence and plan four effects.

    Selected rows and identity are owned before key callbacks. The shared
    installation worker independently owns and checks the actual originals,
    stage and row material on every invocation; no cached success is accepted.
    PublicationRowDigest remains the immutable stage projection, excluding
    retry bookkeeping, not a substitute for the primary-tree row digest.
    """
    ledger = evidence.capture._SharedLedger(work)
    _business_count(context, work)
    request_digest, database_now = context.request_digest, context.database_now
    _object(context.arguments, _ARGUMENT_FIELDS, "completion arguments")
    _text(context.arguments["publication_id"], "publication ID")
    core.require_digest(request_digest, "completion request digest")
    core.require_digest(context.arguments["verification_evidence_digest"], "installation evidence digest")
    now_ns = _now(database_now)
    if (type(installation_envelope_bytes) is not bytes
            or not 2 <= len(installation_envelope_bytes) <= evidence.MAX_EVIDENCE_BYTES):
        raise WebAuthnTrustCompletionError("completion requires the bounded original evidence envelope")
    work.prepare_copy(context.selected_rows)
    selected_input = list(context.selected_rows)
    owned = evidence.capture._JSONCapture(ledger).visit({"arguments": context.arguments,
        "selected": selected_input, "identity": expected_installer_identity})
    work.prepare_copy(owned["selected"])
    arguments, selected = owned["arguments"], tuple(owned["selected"])
    owned_context = core.KernelContext(operation=OPERATION, arguments=arguments, selected_rows=selected,
        database_now=database_now, request_digest=request_digest)
    work.prepare_copy(arguments)
    semantic = {name: arguments[name] for name in _ARGUMENT_FIELDS - {"businessIntent"}}
    _same(arguments["businessIntent"], authority._synthesize_business_intent(OPERATION, semantic, work=work),
        work, "completion business intent changed")
    publication_selected = owned_context._exact(trust.PUBLICATION_TABLE,
        {"id": arguments["publication_id"]}, work=work)
    high_selected = owned_context._exact(trust.HIGH_WATER_TABLE,
        {"authority_scope": trust.AUTHORITY_SCOPE}, work=work)
    audit_selected = owned_context._exact("metadata_audit_outbox",
        {"id": _audit_id(request_digest, work)}, work=work)
    if (publication_selected.get("present") is not True or high_selected.get("present") is not True
            or audit_selected.get("present") is not False):
        raise WebAuthnTrustCompletionError("completion needs an existing predecessor and an unused audit identity")
    claims, publication, high, stage, withdrawn, event = _installation_claims_on_work(
        installed_bundle_bytes=installed_bundle_bytes, installed_state_bytes=installed_state_bytes,
        publication_row=publication_selected["row"], high_water_row=high_selected["row"],
        expected_committed_stage=expected_committed_stage, installation_target_digest=installation_target_digest,
        observed_at=database_now, work=work)
    _same(publication["id"], arguments["publication_id"], work, "completion publication identity changed")
    evidence_digest = evidence._evidence_digest_on_work(installation_envelope_bytes, work)
    _same(evidence_digest, arguments["verification_evidence_digest"], work, "completion original evidence identity changed")
    consumed_evidence = evidence._consume_on_work(owned_context,
        envelope_bytes=installation_envelope_bytes, purpose="trust-installation",
        expected_claims=claims, public_key=installer_public_key, expected_signer_identity=owned["identity"],
        expected_signer_spki_digest=expected_installer_spki_digest, now_epoch_ns=now_ns,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    now_iso = database_now.isoformat()
    work.prepare_copy(publication)
    updated_publication = {**publication, "status": "published", "published_at": now_iso, "last_error": None}
    updated_high = {"authority_scope": trust.AUTHORITY_SCOPE, "rollback_epoch": publication["rollback_epoch"],
        "publication_sequence": publication["sequence"], "publication_digest": publication["bundle_digest"],
        "metadata_blob_digest": publication["payload_digest"],
        "revocation_set_digest": _frame("catchplate.webauthnRevocationSet/v1", withdrawn, work),
        "witness_receipt_digest": stage["witnessReceiptDigest"], "witness_sequence": stage["witnessSequence"],
        "updated_at_epoch_ns": now_ns}
    event_bytes = work.wire(event)
    work.charge(input_bytes=len(event_bytes))
    audit = {"id": audit_selected["key"]["id"], "event_type": "webauthn.trust_bundle.published",
        "actor_type": "admin", "actor_id": publication["actor_id"], "event_json": event_bytes.decode("ascii"),
        "event_digest": evidence.plan._frame("catchplate.metadataAuditOutboxEvent/v1", (event_bytes,), work),
        "storage_format_version": 2, "status": "pending", "claim_id": None, "claimed_at": None,
        "attempts": 0, "audited_at": None, "audit_event_hash": None, "last_error": None, "created_at": now_iso}
    effects = ((publication_selected, updated_publication), (high_selected, updated_high),
        (audit_selected, audit), consumed_evidence)
    work.prepare_copy(updated_publication)
    return effects, dict(updated_publication)


def _kernel_transition_on_work(context, *, installation_envelope_bytes, installed_bundle_bytes,
        installed_state_bytes, installation_target_digest, expected_committed_stage,
        installer_public_key, expected_installer_identity, expected_installer_spki_digest,
        maximum_age_ns, maximum_clock_skew_ns, work):
    """Render the four actual business mutations; never finalize capacity here.

    The worker genuinely verifies and consumes the selected original v2
    evidence. Independent configured pins, committed-stage authority and
    selected-row/current-root admission remain required; no keyless default or
    evidence-success token is accepted. All final row copies, ordering and
    canonical result validation are charged on the same supplied work.
    """
    evidence.capture._SharedLedger(work)
    business_count = _business_count(context, work)
    spec = authority.operation_spec(OPERATION)
    effects, result = _complete_on_work(context,
        installation_envelope_bytes=installation_envelope_bytes,
        installed_bundle_bytes=installed_bundle_bytes, installed_state_bytes=installed_state_bytes,
        installation_target_digest=installation_target_digest, expected_committed_stage=expected_committed_stage,
        installer_public_key=installer_public_key, expected_installer_identity=expected_installer_identity,
        expected_installer_spki_digest=expected_installer_spki_digest,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    if len(effects) != 4 or len(effects) > spec["maximumBusinessMutations"]:
        raise WebAuthnTrustCompletionError("completion must render exactly four business effects")
    mutations, addresses = [], set()
    for selected, updated in effects:
        core.require_digest(selected["keyDigest"], "completion mutation key digest")
        address = selected["table"], selected["keyDigest"]
        if address in addresses:
            raise WebAuthnTrustCompletionError("completion produced duplicate row mutations")
        addresses.add(address)
        work.prepare_copy(selected["key"])
        if selected["present"] is True:
            work.prepare_copy(selected["row"])
        work.prepare_copy(updated)
        mutations.append(core.mutation(operation=OPERATION, selected=selected, row=updated))
    work.prepare_copy(mutations)
    ordered = sorted(mutations, key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
    work.prepare_copy(ordered)
    planned = tuple(ordered)
    business_work = 8 + business_count + 4 * len(planned)
    if business_work > spec["maximumBusinessWorkUnits"]:
        raise WebAuthnTrustCompletionError("completion exceeds its business work allowance")
    work.prepare_encoding(result)
    return core.KernelTransition(mutations=planned, result=result, work_units=business_work)
