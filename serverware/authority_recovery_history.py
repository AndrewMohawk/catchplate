"""Replay complete recovery history from retained, individually bounded pages.

This source-specific compound proof has one count phase, exactly one data phase
per authenticated credential, and one projection phase. Each phase retains the
ordinary work ceilings; the compound total is also bounded and recorded. No
full-row/proof collection or aggregate proof JSON document is constructed.

Roots, request/configuration selection, MVCC ownership and the absolute deadline
must be independently admitted by the actual caller. Its page reader must hold
that same original custody throughout. This module neither opens a transaction
nor obtains a clock or signing capability. A returned observation is not an
acceptable proof input: the independent executor must replay the raw originals.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Callable

from serverware import authority_complete_query_batch as batch
from serverware import authority_index_count_reader as count_reader
from serverware import authority_index_projection as projection
from serverware import authority_index_range as ranges
from serverware import authority_index_range_count as counts
from serverware import authority_index_reader as reader
from serverware import authority_radix_mutation as primary
from serverware import authority_revocation_wire as wire
from serverware import authority_transition_core as core
from serverware.authority_index_contract import (
    I64_MAX, KEY_NIBBLES, CountedNode, IndexLeaf, KeyInterval, OpaqueSubtree, empty_node,
)
from serverware.authority_index_heads import CapturedIndexHead
from serverware.authority_query_read_work import (
    MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES, QueryReadValidationLimits,
    QueryReadValidationMetrics, _ValidationWork,
)


SCHEMA = "serverware.policyAuthorityRecoveryHistory/v1"
COUNT_SCHEMA = "serverware.policyAuthorityRecoveryHistoryCount/v1"
PAGE_SCHEMA = "serverware.policyAuthorityRecoveryHistoryPage/v1"
CHAIN_SCHEMA = "serverware.policyAuthorityRecoveryHistoryChain/v1"
TABLE = "webauthn_credentials"
INDEX_ID = "webauthn_credential_user_history"
OPERATIONS = ("webauthn.recovery.create", "webauthn.recovery.candidate", "webauthn.recovery.finalize")
PAGE_ROWS = 1
MAX_COUNT = 10_000
MAX_PROJECTION_BYTES = 16 * 1024 * 1024
MAX_BODY_BYTES = 4 * 1024 * 1024
_ROOT_FIELDS = frozenset({"table", "rootRevision", "rootDigest", "leafCount"})
_HEAD_FIELDS = frozenset({"indexId", "table", "countedProfile", "projectionDigest",
    "projectionManifestDigest", "indexRevision", "rootDigest", "rootCount"})
_CONTEXT_FIELDS = frozenset({"operation", "userId", "cutoffUs", "maximumCount",
    "maximumBytes", "primaryRoot", "indexHead"})
_MANIFEST_FIELDS = _CONTEXT_FIELDS | {"schema", "countBody", "pages", "chainDigest"}
_PAGE_FIELDS = frozenset({"schema", "ordinal", "lower", "upper", "selectedRows",
    "beforeProofs", "frontier"})
_REQUIRED_TEXT = frozenset({"id", "credential_id", "user_id", "label", "public_key_cose",
    "authenticator_class", "attestation_trust_path", "transports", "created_at", "updated_at"})
_NULLABLE_TEXT = frozenset({"aaguid", "attestation_fmt", "attestation_leaf_sha256",
    "attestation_root_sha256", "attestation_trust_bundle_digest", "attestation_verified_at",
    "dev_private_key_pem", "last_used_at", "revoked_at", "revoked_by", "revocation_reason",
    "revocation_source"})
ROW_FIELDS = _REQUIRED_TEXT | _NULLABLE_TEXT | {
    "sign_count", "attestation_trusted", "attestation_trust_bundle_sequence"}


class RecoveryHistoryError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class HistoryMetrics:
    phases: tuple[QueryReadValidationMetrics, ...]
    total: QueryReadValidationMetrics
    raw_bytes: int
    projection_bytes: int


@dataclass(frozen=True, slots=True)
class HistoryObservation:
    digest: str
    count: int
    active_count: int
    chain_digest: str
    metrics: HistoryMetrics


def _integer(value, minimum=0, maximum=I64_MAX):
    if type(value) is not int or not minimum <= value <= maximum:
        raise RecoveryHistoryError("recovery history integer is not source bounded")
    return value


def _closed(value, fields):
    if type(value) is not dict or set(value) != fields:
        raise RecoveryHistoryError("recovery history record is not source closed")


def _own(value, work):
    return batch._JSONCapture(batch._SharedLedger(work)).visit(value)


def _sha(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def body_descriptor(raw: bytes, *, work: _ValidationWork) -> dict:
    if type(raw) is not bytes or not 2 <= len(raw) <= MAX_BODY_BYTES:
        raise RecoveryHistoryError("recovery history original body is not bounded bytes")
    return {"byteCount": len(raw), "digest": _sha(raw, work)}


def _descriptor(value):
    _closed(value, {"byteCount", "digest"})
    _integer(value["byteCount"], 2, MAX_BODY_BYTES)
    core.require_digest(value["digest"], "recovery history body digest")


def chain_seed(context: dict, count_body: dict, *, work: _ValidationWork) -> str:
    _closed(context, _CONTEXT_FIELDS)
    _descriptor(count_body)
    return _sha(work.wire({"schema": CHAIN_SCHEMA, "context": context,
                           "countBody": count_body}), work)


def chain_step(previous: str, ordinal: int, descriptor: dict, *, work: _ValidationWork) -> str:
    core.require_digest(previous, "recovery history predecessor")
    _integer(ordinal, 0, MAX_COUNT - 1)
    _descriptor(descriptor)
    return _sha(work.wire({"schema": CHAIN_SCHEMA, "previous": previous,
        "ordinal": ordinal, **descriptor}), work)


def head_wire(head: CapturedIndexHead) -> dict:
    if type(head) is not CapturedIndexHead or type(head.index_root) is not CountedNode:
        raise RecoveryHistoryError("recovery history head is not the exact observation")
    return {"indexId": head.index_id, "table": head.table, "countedProfile": head.counted_profile,
        "projectionDigest": head.projection_digest,
        "projectionManifestDigest": head.projection_manifest_digest,
        "indexRevision": head.index_revision, "rootDigest": head.index_root.digest,
        "rootCount": head.index_root.count}


def _context(*, operation, user_id, cutoff_us, maximum_count, maximum_bytes,
             primary_root, index_head, work):
    if type(operation) is not str or operation not in OPERATIONS:
        raise RecoveryHistoryError("recovery history operation is not source declared")
    reader._text(user_id, projection.MAX_TEXT_BYTES, work=work)
    _integer(cutoff_us)
    _integer(maximum_count, 1, MAX_COUNT)
    _integer(maximum_bytes, 65_536, MAX_PROJECTION_BYTES)
    value = _own({"operation": operation, "userId": user_id, "cutoffUs": cutoff_us,
        "maximumCount": maximum_count, "maximumBytes": maximum_bytes,
        "primaryRoot": primary_root, "indexHead": head_wire(index_head)}, work)
    raw_root, head = value["primaryRoot"], value["indexHead"]
    _closed(raw_root, _ROOT_FIELDS)
    _closed(head, _HEAD_FIELDS)
    if raw_root["table"] != TABLE:
        raise RecoveryHistoryError("recovery history primary root names another table")
    work.charge(hashes=65)
    root = primary.PrimaryRoot(TABLE, raw_root["rootRevision"], raw_root["rootDigest"], raw_root["leafCount"])
    reader._profile_work(INDEX_ID, work)
    profile = projection.profile_for(INDEX_ID)
    manifest = [definition.document() for definition in projection._DEFINITIONS]
    work.prepare_encoding(manifest, ensure_ascii=False)
    work.charge(hashes=1)
    if (head["indexId"] != INDEX_ID or head["table"] != TABLE
            or head["countedProfile"] != projection.COUNTED_PROFILE
            or head["projectionDigest"] != profile.projection_digest
            or head["projectionManifestDigest"] != projection.projection_manifest_digest()):
        raise RecoveryHistoryError("recovery history head differs from the source profile")
    _integer(head["indexRevision"])
    counted = CountedNode(head["rootDigest"], head["rootCount"])
    # Cold empty counted root and the source-selected user partition.
    work.charge(hashes=1)
    if (counted.count > root.leaf_count or (head["indexRevision"] == 0 and counted.count)
            or (counted.count == 0) != (counted.digest == empty_node(profile, "").digest)):
        raise RecoveryHistoryError("recovery history root population or genesis differs")
    selector = {"user_id": user_id}
    reader._interval_work(profile, profile, selector, work)
    interval = projection.query_interval(INDEX_ID, selector)
    return value, root, profile, counted, interval


def _body(raw, expected, work):
    _descriptor(expected)
    actual = body_descriptor(raw, work=work)
    if actual != expected:
        raise RecoveryHistoryError("recovery history retained body changed")
    # This parser reserves its lexical/decode/object-hook work before parsing.
    # Its result is already a private graph: do not copy/normalize it again.
    value = wire._decode_object(raw, work=work, maximum_bytes=MAX_BODY_BYTES)
    if work.wire(value) != raw:
        raise RecoveryHistoryError("recovery history original body is not canonical")
    return value


def _frontier(raw, *, count_only):
    if type(raw) is not list or len(raw) > count_reader.MAX_PREFIXES + int(not count_only):
        raise RecoveryHistoryError("recovery history frontier is not bounded")
    result, leaves, opaque = [], 0, 0
    for item in raw:
        if type(item) is not dict:
            raise RecoveryHistoryError("recovery history frontier entry is not closed")
        if (not count_only and set(item) == {"kind", "key", "primaryKeyDigest", "primaryRowDigest"}
                and item["kind"] == "leaf"):
            leaves += 1
            result.append(IndexLeaf(item["key"], item["primaryKeyDigest"], item["primaryRowDigest"]))
        elif set(item) == {"kind", "prefix", "digest", "count"} and item["kind"] == "opaque":
            opaque += 1
            result.append(OpaqueSubtree(item["prefix"], item["digest"], item["count"]))
        else:
            raise RecoveryHistoryError("recovery history frontier entry is not source declared")
    if leaves > PAGE_ROWS or opaque > count_reader.MAX_PREFIXES:
        raise RecoveryHistoryError("recovery history frontier exceeds its fixed phase inventory")
    return tuple(result)


def _next_key(key):
    following = int(key, 16) + 1
    return None if following == 1 << (4 * KEY_NIBBLES) else f"{following:0{KEY_NIBBLES}x}"


def _row_shape(row):
    _closed(row, ROW_FIELDS)
    if (any(type(row[name]) is not str for name in _REQUIRED_TEXT)
            or any(row[name] is not None and type(row[name]) is not str for name in _NULLABLE_TEXT)
            or type(row["sign_count"]) is not int or type(row["attestation_trusted"]) is not int
            or (row["attestation_trust_bundle_sequence"] is not None
                and type(row["attestation_trust_bundle_sequence"]) is not int)):
        raise RecoveryHistoryError("recovery history row differs from the scalar SQL schema")


def _json_field(value, work):
    if not value:
        return []  # Exactly db_common.loads(value, []).
    size = work.prepare_utf8(value)
    # These historical TEXT columns use ordinary json.loads, not the stricter
    # signed-proof wire language. Preserve literal Unicode, duplicate-member
    # last-value semantics and Python's legacy numeric handling. A lexical
    # count reserves the real parser graph without first allocating that graph.
    position = nodes = depth = 0
    while position < len(value):
        character = value[position]
        if character in " \r\n\t,:":
            position += 1
            continue
        if character in "]}":
            depth -= 1
            position += 1
            continue
        if not 0 <= depth <= 128:
            raise RecoveryHistoryError("recovery history legacy JSON exceeds its depth bound")
        nodes += 1
        if nodes > work.limits.max_json_nodes - work.json_nodes:
            raise RecoveryHistoryError("recovery history legacy JSON exceeds remaining node work")
        if character in "[{":
            depth += 1
            position += 1
        elif character == '"':
            position += 1
            while position < len(value):
                character = value[position]
                position += 1
                if character == "\\":
                    position += 1
                elif character == '"':
                    break
        else:
            # Valid primitive tokens contain none of these delimiters. Invalid
            # syntax still goes to the standard parser and cannot be success.
            while position < len(value) and value[position] not in " \r\n\t,:[]{}\"":
                position += 1
    work.charge(input_bytes=size, json_nodes=nodes)
    try:
        return json.loads(value)
    except (ValueError, RecursionError) as exc:
        raise RecoveryHistoryError("recovery history legacy JSON is invalid") from exc


def _legacy_bytes(value, work):
    """Meter the exact legacy ASCII serializer without changing its JSON domain.

    Unlike signed proof JSON, legacy metadata can contain parsed floats, NUL,
    or escaped surrogate code units. json.dumps safely escapes string values;
    these never become proof identities. No generic work/JSON codec is widened.
    """
    before_bytes, before_nodes = work.input_bytes, work.json_nodes
    def measure(item, depth=0):
        if depth > 128:
            raise RecoveryHistoryError("recovery history projection exceeds its depth bound")
        work.charge(json_nodes=1)
        kind = type(item)
        if item is None or kind in (bool, int, float):
            # Decoded integers already passed the standard parser's digit cap.
            work.charge(input_bytes=len(json.dumps(item)))
        elif kind is str:
            size = 2
            for character in item:
                point = ord(character)
                size += (2 if character in '"\\\b\f\n\r\t' else
                         12 if point > 0xFFFF else 6 if point < 32 or point >= 127 else 1)
                if size > work.limits.max_input_bytes - work.input_bytes:
                    raise RecoveryHistoryError("recovery history projection string exceeds work")
            work.charge(input_bytes=size)
        elif kind in (list, dict):
            work.charge(input_bytes=2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise RecoveryHistoryError("recovery history JSON key is not text")
                    measure(key, depth + 1)
                    measure(child, depth + 1)
            else:
                for child in item:
                    measure(child, depth + 1)
        else:
            raise RecoveryHistoryError("recovery history projection is not legacy JSON")
    measure(value)
    size, nodes = work.input_bytes - before_bytes, work.json_nodes - before_nodes
    work.charge(input_bytes=size, json_nodes=nodes)
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(raw) != size:
        raise RecoveryHistoryError("recovery history legacy encoding changed after measurement")
    return raw


def project_history_row(row: dict, *, work: _ValidationWork) -> bytes:
    """One exact legacy projection; this does not prove membership/completeness."""
    _row_shape(row)
    row = _own(row, work)
    def field_digest(name, encoding):
        work.prepare_utf8(row[name])
        try:
            raw = row[name].encode(encoding)
        except UnicodeError as exc:
            raise RecoveryHistoryError("recovery history encoded field is invalid") from exc
        return _sha(raw, work)
    value = {
        "record_id": row["id"], "credential_id_digest": field_digest("credential_id", "utf-8"),
        "public_key_cose_digest": field_digest("public_key_cose", "ascii"),
        "sign_count": row["sign_count"], "aaguid": row["aaguid"],
        "authenticator_class": row["authenticator_class"], "attestation_fmt": row["attestation_fmt"],
        "attestation_trusted": bool(row["attestation_trusted"]),
        "attestation_trust_path": _json_field(row["attestation_trust_path"], work),
        "attestation_leaf_sha256": row["attestation_leaf_sha256"],
        "attestation_root_sha256": row["attestation_root_sha256"],
        "attestation_trust_bundle_digest": row["attestation_trust_bundle_digest"],
        "attestation_trust_bundle_sequence": row["attestation_trust_bundle_sequence"],
        "attestation_verified_at": row["attestation_verified_at"],
        "transports": _json_field(row["transports"], work),
        "development_material_digest": (field_digest("dev_private_key_pem", "utf-8")
                                        if row["dev_private_key_pem"] is not None else None),
        "created_at": row["created_at"], "updated_at": row["updated_at"],
        "last_used_at": row["last_used_at"], "revoked_at": row["revoked_at"],
        "revoked_by": row["revoked_by"], "revocation_reason": row["revocation_reason"],
        "revocation_source": row["revocation_source"],
    }
    return _legacy_bytes(value, work)


def _page(value, *, ordinal, count, lower, whole, root, profile, counted, user_id, work):
    _closed(value, _PAGE_FIELDS)
    if (value["schema"] != PAGE_SCHEMA or type(value["ordinal"]) is not int
            or value["ordinal"] != ordinal or value["lower"] != lower
            or type(value["selectedRows"]) is not list or len(value["selectedRows"]) != PAGE_ROWS
            or type(value["beforeProofs"]) is not list or len(value["beforeProofs"]) != PAGE_ROWS):
        raise RecoveryHistoryError("recovery history page ordinal, lower edge or row inventory changed")
    ledger = batch._SharedLedger(work)
    hashes, input_bytes, nodes = ledger.remaining()
    memberships = primary.evaluate_primary_radix_memberships(
        table_contracts=(primary.PrimaryTableContract(TABLE, ("id",), False, "business"),),
        business_before_roots=(root,), authorization_before_roots=(),
        selected_rows=tuple(value["selectedRows"]), before_proofs=tuple(value["beforeProofs"]),
        limits=primary.PrimaryRadixLimits(1, 1, 64, 1024, min(136, hashes), input_bytes, 128, nodes))
    metrics = memberships.result.metrics
    work.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes, json_nodes=metrics.json_nodes)
    if memberships.result.business_after_roots != (root,) or memberships.result.authorization_after_roots:
        raise RecoveryHistoryError("recovery history read-only proof changed its original roots")
    selected, proof = memberships.selected_rows[0], memberships.before_proofs[0]
    row = selected["row"]
    if selected["present"] is not True or selected["contractSelector"] is not None:
        raise RecoveryHistoryError("recovery history needs a present full primary row")
    _row_shape(row)
    if row["user_id"] != user_id:
        raise RecoveryHistoryError("recovery history row belongs to another user")
    # Enforce the reader's actual canonical full-row ceiling during replay too.
    if len(work.wire(row)) > reader.MAX_PRIMARY_ROW_BYTES:
        raise RecoveryHistoryError("recovery history full row exceeds acquisition bounds")
    work.prepare_copy(row)
    work.charge(hashes=projection.ROW_HASH_WORK)
    leaf = projection.project_row(INDEX_ID, row, primary_key_digest=selected["keyDigest"],
                                  primary_row_digest=proof["rowDigest"])
    if leaf is None or leaf.key < lower or (whole.upper is not None and leaf.key >= whole.upper):
        raise RecoveryHistoryError("recovery history primary row escaped its user interval")
    upper = whole.upper if ordinal == count - 1 else _next_key(leaf.key)
    if upper != value["upper"] or (upper is None and ordinal != count - 1):
        raise RecoveryHistoryError("recovery history page upper edge is not source derived")
    frontier = _frontier(value["frontier"], count_only=False)
    opened = 1 + 3 * KEY_NIBBLES
    observed = ranges._reconstruct_complete_index_range(profile=profile, expected_root=counted,
        interval=KeyInterval(lower, upper), frontier=frontier,
        limits=ranges.IndexRangeLimits(max_entries=count_reader.MAX_PREFIXES + 1, max_leaves=1,
            max_opened_nodes=opened, max_hashes=16 * opened + 1), work=work)
    if observed.leaves != (leaf,):
        raise RecoveryHistoryError("recovery history range does not join its full primary row")
    projected = project_history_row(row, work=work)
    return upper, (row["created_at"], row["id"], projected), int(row["revoked_at"] is None)


def _replay_history(*, manifest, count_body, read_page, operation, user_id, cutoff_us,
                    maximum_count, maximum_bytes, primary_root, index_head):
    """One genuine engine shared by initial acquisition and independent replay."""
    work = _ValidationWork(QueryReadValidationLimits())
    context, root, profile, counted, whole = _context(operation=operation, user_id=user_id,
        cutoff_us=cutoff_us, maximum_count=maximum_count, maximum_bytes=maximum_bytes,
        primary_root=primary_root, index_head=index_head, work=work)
    producing = manifest is None
    if producing:
        owned = {"schema": SCHEMA, **context, "countBody": body_descriptor(count_body, work=work),
                 "pages": [], "chainDigest": None}
    else:
        _closed(manifest, _MANIFEST_FIELDS)
        if type(manifest["pages"]) is not list or len(manifest["pages"]) > maximum_count:
            raise RecoveryHistoryError("recovery history page inventory exceeds original configuration")
        owned = _own(manifest, work)
        manifest_context = {key: owned[key] for key in _CONTEXT_FIELDS}
        # Python mapping equality aliases True and 1. Original signed JSON
        # context is exact typed data, so compare actual canonical encodings.
        if owned["schema"] != SCHEMA or work.wire(manifest_context) != work.wire(context):
            raise RecoveryHistoryError("recovery history manifest differs from independent originals")
        core.require_digest(owned["chainDigest"], "recovery history final chain")
        for descriptor in owned["pages"]:
            _descriptor(descriptor)
    count_raw = _body(count_body, owned["countBody"], work)
    _closed(count_raw, {"schema", "frontier"})
    if count_raw["schema"] != COUNT_SCHEMA:
        raise RecoveryHistoryError("recovery history count schema changed")
    count = counts._reconstruct_index_range_count(profile=profile, expected_root=counted,
        interval=whole, frontier=_frontier(count_raw["frontier"], count_only=True),
        limits=ranges.IndexRangeLimits(max_entries=count_reader.MAX_PREFIXES, max_leaves=1,
            max_opened_nodes=count_reader.MAX_OPENED_NODES,
            max_hashes=16 * count_reader.MAX_OPENED_NODES), work=work).count
    if count > maximum_count or (not producing and count != len(owned["pages"])):
        raise RecoveryHistoryError("recovery history page count differs from authenticated population")
    chain = chain_seed(context, owned["countBody"], work=work)
    phases = [work.metrics]
    lower, projected, identities, active = whole.lower, [], set(), 0
    raw_bytes, projected_bytes = len(count_body), 2
    for ordinal in range(count):
        # One nonrenewable, source-fixed data-phase budget; no retry loop.
        work = _ValidationWork(QueryReadValidationLimits())
        raw = read_page(ordinal)
        descriptor = body_descriptor(raw, work=work) if producing else owned["pages"][ordinal]
        value = _body(raw, descriptor, work)
        lower, item, row_active = _page(value, ordinal=ordinal, count=count, lower=lower,
            whole=whole, root=root, profile=profile, counted=counted, user_id=user_id, work=work)
        if item[1] in identities:
            raise RecoveryHistoryError("recovery history repeats a credential identity")
        size = len(item[2]) + int(ordinal != 0)
        if size > maximum_bytes - projected_bytes:
            raise RecoveryHistoryError("recovery history exceeds original projection byte bound")
        projected_bytes += size
        projected.append(item)
        identities.add(item[1])
        active += row_active
        chain = chain_step(chain, ordinal, descriptor, work=work)
        if producing:
            # Only a bounded length/digest descriptor survives this raw page.
            work.prepare_copy(descriptor)
            owned["pages"].append(descriptor.copy())
        raw_bytes += len(raw)
        phases.append(work.metrics)
        del raw, value  # Retain only the bounded canonical legacy projection.
    if (count and lower != whole.upper) or (not producing and chain != owned["chainDigest"]):
        raise RecoveryHistoryError("recovery history coverage or final raw-page chain differs")
    if producing:
        owned["chainDigest"] = chain
    work = _ValidationWork(QueryReadValidationLimits())
    # Canonical array hashing without allocating/normalizing the full history.
    # Sorting and interpreter overhead are bounded by count, not JSON work units.
    work.charge(hashes=1, input_bytes=projected_bytes, json_nodes=count + 1)
    digest = hashlib.sha256()
    digest.update(b"[")
    for ordinal, item in enumerate(sorted(projected, key=lambda item: (item[0], item[1]))):
        if ordinal:
            digest.update(b",")
        digest.update(item[2])
    digest.update(b"]")
    phases.append(work.metrics)
    total = QueryReadValidationMetrics(sum(item.hash_work for item in phases),
        sum(item.input_bytes for item in phases), sum(item.json_nodes for item in phases))
    if (len(phases) != count + 2 or total.hash_work > (count + 2) * MAX_HASHES
            or total.input_bytes > (count + 2) * MAX_INPUT_BYTES
            or total.json_nodes > (count + 2) * MAX_JSON_NODES
            or raw_bytes > (count + 1) * MAX_BODY_BYTES):
        raise RecoveryHistoryError("recovery history exceeded its source compound schedule")
    return owned, HistoryObservation("sha256:" + digest.hexdigest(), count, active, chain,
        HistoryMetrics(tuple(phases), total, raw_bytes, projected_bytes))


def verify_history(*, manifest: dict, count_body: bytes, read_page: Callable[[int], bytes],
                   operation: str, user_id: str, cutoff_us: int, maximum_count: int,
                   maximum_bytes: int, primary_root: dict, index_head: CapturedIndexHead) -> HistoryObservation:
    """Replay every original against an independently admitted parent manifest.

    The fixed count/page/close schedule belongs to this successor, not generic
    v3 validation. No extra phases, metrics, verified pages or clocks are input.
    In particular a missing manifest cannot switch this API into production.
    """
    _closed(manifest, _MANIFEST_FIELDS)
    _, observation = _replay_history(manifest=manifest, count_body=count_body, read_page=read_page,
        operation=operation, user_id=user_id, cutoff_us=cutoff_us, maximum_count=maximum_count,
        maximum_bytes=maximum_bytes, primary_root=primary_root, index_head=index_head)
    return observation


def produce_history(*, count_body: bytes, read_page: Callable[[int], bytes], operation: str,
                    user_id: str, cutoff_us: int, maximum_count: int, maximum_bytes: int,
                    primary_root: dict, index_head: CapturedIndexHead) -> tuple[dict, HistoryObservation]:
    """Verify genuine first-pass originals while deriving their bounded manifest.

    The caller owns the original MVCC/cutoff and acquisition ledgers. After it
    derives/signs the parent, a second same-snapshot pass must match/persist the
    exact bodies. The executor then uses verify_history on retained originals.
    A returned manifest/observation is neither signed authority nor persistence.
    """
    return _replay_history(manifest=None, count_body=count_body, read_page=read_page,
        operation=operation, user_id=user_id, cutoff_us=cutoff_us, maximum_count=maximum_count,
        maximum_bytes=maximum_bytes, primary_root=primary_root, index_head=index_head)
