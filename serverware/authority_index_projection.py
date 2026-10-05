"""Source-fixed, unactivated WebAuthn secondary-index projection codecs.

These pure functions do not verify primary membership, root authority, SQL
population, currentness, or operation admission. A joined verifier must obtain
the full row and both commitments from the actual primary-proof evaluator.
``primary_key_digest`` is BusinessKey/v1, not the AuthenticatedKey tree path;
``primary_row_digest`` is the persisted SQL AuthenticatedRow/v1 commitment.

Exact Unicode equality, finite text bounds and canonical UTC expiry are a new
codec admission contract. Existing TEXT columns do not enforce that contract.
No historical values are rewritten or claimed to have equivalent SQL ordering.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from serverware import authority_challenge_id as challenge_ids

from serverware.authority_index_contract import (
    PROFILE as COUNTED_PROFILE,
    IndexLeaf,
    IndexProfile,
    IndexRangeError,
    KeyInterval,
)


PROJECTION_SCHEMA = "serverware.policyAuthorityIndexProjection/v1"
PROJECTION_DOMAIN = "serverware.policyAuthorityIndexProjectionDescriptor/v1"
PARTITION_DOMAIN = "serverware.policyAuthorityIndexPartition/v1"
MANIFEST_DOMAIN = "serverware.policyAuthorityIndexProjectionManifest/v1"
MAX_TEXT_BYTES = 4096
MAX_PARTITION_BYTES = 32768
PROFILE_HASH_WORK = 1
QUERY_HASH_WORK = 2
ROW_HASH_WORK = 2
I64_MIN = -(2**63)
I64_MAX = 2**63 - 1
_I32_MIN = -(2**31)
_I32_MAX = 2**31 - 1
_HEX_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UTC_TIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{6})?\+00:00\Z"
)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ZERO_ORDER = "0" * 32
_ZERO_SUFFIX = "0" * 64
_ENUM_CHOICES = (
    ("session-status", ("pending_webauthn", "active", "revoked")),
    ("live-session-status", ("pending_webauthn", "active")),
    ("publication-status", ("pending", "published")),
    ("global-scope", ("global",)),
)
_CHALLENGE_DIRECTION = ("at-or-before", "strictly-after", "all")
_CHALLENGE_ORDER_SUFFIX = "/generated-challenge-id-text-order"


class IndexProjectionError(IndexRangeError):
    pass


@dataclass(frozen=True, slots=True)
class _Definition:
    index_id: str
    table: str
    row_fields: tuple[tuple[str, str], ...]
    selector_fields: tuple[tuple[str, str], ...]
    membership: str
    partition_fields: tuple[str, ...]
    order_codec: str
    interval_rule: str

    def document(self) -> dict[str, Any]:
        result = {
            "schema": PROJECTION_SCHEMA,
            "countedProfile": COUNTED_PROFILE,
            "indexId": self.index_id,
            "table": self.table,
            "primaryKeyColumn": "id",
            "primaryKeyCommitment": "serverware.policyAuthorityBusinessKey/v1",
            "primaryRowCommitment": "serverware.policyAuthorityAuthenticatedRow/v1",
            "keyBytes": [32, 16, 32],
            "rowFields": [list(field) for field in self.row_fields],
            "selectorFields": [list(field) for field in self.selector_fields],
            "membership": self.membership,
            "partitionFields": list(self.partition_fields),
            "partitionDomain": PARTITION_DOMAIN,
            "partitionEncoding": "sorted-compact-UTF8-JSON/exact-typed-fields",
            "textEncoding": "exact-UTF8/no-NUL/no-normalization",
            "nullableTextEncoding": "null-or-exact-text/no-null-empty-alias",
            "maxTextBytes": MAX_TEXT_BYTES,
            "maxPartitionBytes": MAX_PARTITION_BYTES,
            "integerBounds": {"int32": [_I32_MIN, _I32_MAX], "int64": [I64_MIN, I64_MAX]},
            "textEnums": {name: list(choices) for name, choices in _ENUM_CHOICES},
            "selectorFieldsClosed": True,
            "referencedFieldsValidatedBeforeMembership": True,
            "orderCodec": self.order_codec,
            "intervalRule": self.interval_rule,
            "expiryEncoding": "UTC-isoformat-auto-fraction/signed64-microseconds",
            "expiryEpoch": "1970-01-01T00:00:00+00:00",
            "expiryFraction": "absent-if-zero/otherwise-exact-six-digits",
            "signedOrderEncoding": "signed64-plus-2^63/eight-byte-big-endian",
            "partitionFraming": "u64be-length/every-frame-including-domain",
            "keySuffix": "BusinessKey/v1-lowercase-SHA256-hex",
        }
        if self.order_codec.endswith(_CHALLENGE_ORDER_SUFFIX):
            # Keep every older descriptor byte-for-byte unchanged. Only the
            # fresh challenge family declares the stricter source ID domain.
            result["keyBytes"] = [32, 8, 1, 32, 7]
            result["keySuffix"] = "UUID36-class0-padded16-or-sha256-class1/zero7/exact-text-order"
            result["challengeIdAdmission"] = "fresh-only/canonical-lowercase-UUID36-or-sha256/no-legacy-adoption"
            if any(kind == "challenge-direction" for _, kind in self.selector_fields):
                result["textEnums"]["challenge-direction"] = list(_CHALLENGE_DIRECTION)
        return result


# These immutable definitions are source data, not a caller configuration
# language. Membership and interval implementations below are closed branches.
_DEFINITIONS = (
    _Definition(
        "webauthn_credential_id", "webauthn_credentials",
        (("id", "text"), ("credential_id", "text")),
        (("credential_id", "text"),), "all-rows-including-revoked", ("credential_id",),
        "zero16", "whole-equality-partition",
    ),
    _Definition(
        "webauthn_credential_user_history", "webauthn_credentials",
        (("id", "text"), ("user_id", "text")),
        (("user_id", "text"),), "all-rows-including-revoked", ("user_id",),
        "zero16", "whole-equality-partition",
    ),
    _Definition(
        "webauthn_credential_live_trust", "webauthn_credentials",
        (("id", "text"), ("revoked_at", "nullable-text"), ("attestation_trusted", "int32")),
        (), "revoked_at-is-null/attestation_trusted-nonzero", (),
        "zero16", "whole-equality-partition",
    ),
    _Definition(
        "webauthn_registration_unused_global", "webauthn_challenges",
        (("id", "text"), ("challenge_type", "text"), ("used_at", "nullable-text"),
         ("expires_at", "utc-expiry")),
        (("expires_after_us", "int64"),), "challenge_type-registration/used_at-is-null", (),
        "signed64-expiry-microseconds/zero8", "expiry-strictly-after-cutoff",
    ),
    _Definition(
        "webauthn_registration_unused_user", "webauthn_challenges",
        (("id", "text"), ("challenge_type", "text"), ("used_at", "nullable-text"),
         ("expires_at", "utc-expiry"), ("user_id", "text")),
        (("user_id", "text"), ("expires_after_us", "int64")),
        "challenge_type-registration/used_at-is-null/no-approval-request-filter", ("user_id",),
        "signed64-expiry-microseconds/zero8", "expiry-strictly-after-cutoff",
    ),
    _Definition(
        "webauthn_session_credential_status", "oidc_browser_sessions",
        (("id", "text"), ("bound_webauthn_credential_id", "nullable-text"),
         ("status", "session-status")),
        (("credential_record_id", "text"), ("status", "live-session-status")),
        "binding-nonnull/status-pending_webauthn-or-active/no-expiry-filter",
        ("credential_record_id", "status"), "zero16", "whole-equality-partition",
    ),
    _Definition(
        "webauthn_grant_approver_active", "approval_grants",
        (("id", "text"), ("approver_webauthn_credential_id", "nullable-text"), ("state", "text")),
        (("credential_record_id", "text"),),
        "binding-nonnull/state-active/no-expiry-uses-or-reservation-filter",
        ("credential_record_id",), "zero16", "whole-equality-partition",
    ),
    _Definition(
        "webauthn_control_approval_approved", "control_plane_approvals",
        (("id", "text"), ("approver_webauthn_credential_id", "nullable-text"), ("status", "text")),
        (("credential_record_id", "text"),), "binding-nonnull/status-approved/no-expiry-filter",
        ("credential_record_id",), "zero16", "whole-equality-partition",
    ),
    _Definition(
        "webauthn_publication_bundle_digest", "webauthn_trust_publications",
        (("id", "text"), ("scope", "global-scope"), ("status", "publication-status"),
         ("bundle_digest", "text")),
        (("bundle_digest", "text"),), "global/pending-or-published", ("bundle_digest",),
        "zero16", "whole-equality-partition",
    ),
    _Definition(
        "webauthn_publication_status", "webauthn_trust_publications",
        (("id", "text"), ("scope", "global-scope"), ("status", "publication-status")),
        (("status", "publication-status"),), "global/pending-or-published", ("status",),
        "zero16", "whole-equality-partition",
    ),
    _Definition(
        "webauthn_publication_generation", "webauthn_trust_publications",
        (("id", "text"), ("scope", "global-scope"), ("status", "publication-status"),
         ("rollback_epoch", "int64"), ("sequence", "int64")),
        (("minimum_rollback_epoch", "int64"), ("minimum_sequence", "int64")),
        "global/pending-or-published", (), "signed64-rollback-epoch/signed64-sequence",
        "generation-pair-inclusive-to-partition-end/not-a-maximum-claim",
    ),
    _Definition(
        "oidc_session_token_digest", "oidc_browser_sessions",
        (("id", "text"), ("token_digest", "text")),
        (("token_digest", "text"),), "all-rows-including-expired-or-revoked",
        ("token_digest",), "zero16", "whole-equality-partition",
    ),
    *tuple(
        _Definition(
            "oidc_activation_delivery_" + field, "oidc_session_activation_deliveries",
            (("id", "text"), (field, "text")), ((field, "text"),),
            "all-rows-including-expired-or-consumed", (field,),
            "zero16", "whole-equality-partition",
        )
        for field in ("session_id", "old_token_digest", "new_token_digest",
                      "assertion_digest", "challenge_id")
    ),
    *tuple(
        _Definition(
            "webauthn_challenge_" + kind + "_" + scope, "webauthn_challenges",
            (("id", "challenge-id"), (time_field, "utc-expiry"))
                + ((("used_at", "nullable-utc-expiry"),) if kind == "unused" else ())
                + ((("user_id", "text"),) if scope == "user" else ()),
            ((("user_id", "text"),) if scope == "user" else ())
                + (("cutoff_us", "int64"), ("direction", "challenge-direction")),
            "used_at-is-null" if kind == "unused" else "all-rows-including-terminal",
            ("user_id",) if scope == "user" else (),
            "signed64-" + time_field + _CHALLENGE_ORDER_SUFFIX,
            "source-direction-timestamp-cutoff",
        )
        for kind, time_field in (("unused", "expires_at"), ("created", "created_at"))
        for scope in ("global", "user")
    ),
    _Definition(
        "webauthn_challenge_terminal_unreferenced_global", "webauthn_challenges",
        (("id", "challenge-id"), ("used_at", "nullable-utc-expiry"),
         ("retention_reference_mask", "reference-mask")),
        (("cutoff_us", "int64"), ("direction", "challenge-direction")),
        "used_at-is-nonnull/authenticated-reference-mask-zero", (),
        "signed64-used_at" + _CHALLENGE_ORDER_SUFFIX, "source-direction-timestamp-cutoff",
    ),
    _Definition(
        "webauthn_challenge_scope_unused", "webauthn_challenges",
        (("id", "challenge-id"), ("challenge_type", "text"), ("user_id", "text"),
         ("scope_key", "nullable-text"), ("used_at", "nullable-utc-expiry")),
        (("challenge_type", "text"), ("user_id", "text"), ("scope_key", "nullable-text")),
        "used_at-is-null/no-expiry-filter", ("challenge_type", "user_id", "scope_key"),
        "zero8" + _CHALLENGE_ORDER_SUFFIX, "whole-equality-partition",
    ),
    _Definition(
        "webauthn_challenge_value", "webauthn_challenges",
        (("id", "challenge-id"), ("challenge", "text")), (("challenge", "text"),),
        "all-rows-including-terminal", ("challenge",),
        "zero8" + _CHALLENGE_ORDER_SUFFIX, "whole-equality-partition",
    ),
)
INDEX_IDS = tuple(definition.index_id for definition in _DEFINITIONS)


def index_ids_for_table(table: str) -> tuple[str, ...]:
    """All fixed profiles for a table, not a query-selected maintenance subset.

    A valid unindexed table has no profiles. This hashes nothing and grants no
    write permission, installed-schema admission or operation authority.
    """
    if (type(table) is not str or not 1 <= len(table) <= 128
            or re.fullmatch(r"[a-z][a-z0-9_]*", table) is None):
        raise IndexProjectionError("index source table is not an exact bounded identifier")
    return tuple(sorted(item.index_id for item in _DEFINITIONS if item.table == table))


def _definition(index_id: str) -> _Definition:
    if type(index_id) is not str:
        raise IndexProjectionError("index projection identity must be an exact string")
    for definition in _DEFINITIONS:
        if definition.index_id == index_id:
            return definition
    raise IndexProjectionError("index projection identity is not source admitted")


def _json_bytes(value: Any) -> bytes:
    # Only bounded source objects or already validated shallow primitive maps
    # reach this encoder. It is not a general untrusted JSON snapshot helper.
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _framed_hash(domain: str, *frames: bytes) -> str:
    digest = hashlib.sha256()
    for frame in (domain.encode("ascii"), *frames):
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def profile_for(index_id: str) -> IndexProfile:
    """Return a fresh source profile, spending exactly one descriptor hash."""
    definition = _definition(index_id)
    return IndexProfile(definition.index_id, definition.table,
                        _framed_hash(PROJECTION_DOMAIN, _json_bytes(definition.document())))


def projection_manifest_digest() -> str:
    """Explicitly hash the fixed source descriptors; no hidden registry IO.

    This one hash is not performed by profile/query/row calls and is not an
    installed operation manifest, checkpoint, or caller authorization.
    """
    return _framed_hash(MANIFEST_DOMAIN, _json_bytes([item.document() for item in _DEFINITIONS]))


def _text(value: Any) -> str:
    if type(value) is not str or len(value) > MAX_TEXT_BYTES or "\x00" in value:
        raise IndexProjectionError("index text is not an exact bounded NUL-free string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise IndexProjectionError("index text is not valid Unicode UTF-8") from exc
    if len(encoded) > MAX_TEXT_BYTES:
        raise IndexProjectionError("index text exceeds its UTF-8 byte bound")
    return value


def _integer(value: Any, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise IndexProjectionError("index integer is not an exact admitted signed value")
    return value


def _expiry_micros(value: Any) -> int:
    value = _text(value)
    if len(value) not in (25, 32) or _UTC_TIME.fullmatch(value) is None:
        raise IndexProjectionError("index expiry is not canonical UTC isoformat")
    try:
        instant = datetime.fromisoformat(value)
    except ValueError as exc:
        raise IndexProjectionError("index expiry is not a valid UTC date") from exc
    if instant.isoformat() != value:
        raise IndexProjectionError("index expiry is not canonical UTC isoformat")
    delta = instant - _EPOCH
    return _integer((delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds,
                    I64_MIN, I64_MAX)


def _primitive(value: Any, kind: str) -> Any:
    if kind in ("nullable-text", "nullable-utc-expiry") and value is None:
        return None
    if kind == "challenge-id":
        try:
            return challenge_ids.require_generated(value)
        except ValueError as exc:
            raise IndexProjectionError(str(exc)) from exc
    if kind == "reference-mask":
        return _integer(value, 0, 7)
    if kind == "challenge-direction":
        if type(value) is not str or value not in _CHALLENGE_DIRECTION:
            raise IndexProjectionError("challenge count direction is not source admitted")
        return value
    if kind == "int32":
        return _integer(value, _I32_MIN, _I32_MAX)
    if kind == "int64":
        return _integer(value, I64_MIN, I64_MAX)
    if kind in ("utc-expiry", "nullable-utc-expiry"):
        return _expiry_micros(value)
    value = _text(value)
    choices = dict(_ENUM_CHOICES)
    if kind in choices and value not in choices[kind]:
        raise IndexProjectionError("index text is outside its source enum")
    if kind not in ("text", "nullable-text", *choices):
        raise IndexProjectionError("index source field codec is unknown")
    return value


def _snapshot(value: Any, fields: tuple[tuple[str, str], ...], *, closed: bool) -> dict[str, Any]:
    if type(value) is not dict:
        raise IndexProjectionError("index fields require an exact dictionary")
    if closed and (len(value) != len(fields) or set(value) != {name for name, _ in fields}):
        raise IndexProjectionError("index selector fields are not closed")
    result = {}
    for name, kind in fields:
        if name not in value:
            raise IndexProjectionError("index referenced row field is missing")
        result[name] = _primitive(value[name], kind)
    return result


def snapshot_selector(index_id: str, selector: dict[str, Any]) -> dict[str, Any]:
    """Copy exact typed selector primitives without hashing or proving authority."""
    return _snapshot(selector, _definition(index_id).selector_fields, closed=True)


def _partition(profile: IndexProfile, fields: dict[str, Any]) -> str:
    encoded = _json_bytes(fields)
    if len(encoded) > MAX_PARTITION_BYTES:
        raise IndexProjectionError("index partition exceeds its canonical UTF-8 byte bound")
    return _framed_hash(
        PARTITION_DOMAIN, COUNTED_PROFILE.encode("ascii"), profile.index_id.encode("ascii"),
        profile.table.encode("ascii"), profile.projection_digest.encode("ascii"), encoded,
    )[7:]


def _signed_order(value: int) -> str:
    return (value + 2**63).to_bytes(8, "big").hex()


def _partition_end(prefix: str) -> str | None:
    successor = int(prefix, 16) + 1
    return None if successor == 2**256 else f"{successor:064x}" + "0" * 96


def query_interval(index_id: str, selector: dict[str, Any]) -> KeyInterval:
    """Derive one complete interval from a closed source selector, not bounds.

    The generation selector requests every pair >= its supplied minimum. It
    does not authenticate a maximum, predecessor, clock, or operation intent.
    """
    definition = _definition(index_id)
    owned = snapshot_selector(index_id, selector)
    profile = profile_for(index_id)
    prefix = _partition(profile, {name: owned[name] for name in definition.partition_fields})
    lower = prefix + "0" * 96
    upper = _partition_end(prefix)
    if definition.order_codec == "signed64-expiry-microseconds/zero8":
        cutoff = owned["expires_after_us"]
        if cutoff == I64_MAX:
            return KeyInterval(lower, lower)
        lower = prefix + _signed_order(cutoff + 1) + "0" * 16 + _ZERO_SUFFIX
    elif definition.order_codec == "signed64-rollback-epoch/signed64-sequence":
        lower = (prefix + _signed_order(owned["minimum_rollback_epoch"])
                 + _signed_order(owned["minimum_sequence"]) + _ZERO_SUFFIX)
    elif definition.interval_rule == "source-direction-timestamp-cutoff":
        cutoff, direction = owned["cutoff_us"], owned["direction"]
        following = upper if cutoff == I64_MAX else prefix + _signed_order(cutoff + 1) + "0" * 80
        if direction == "at-or-before":
            upper = following
        elif direction == "strictly-after":
            if cutoff == I64_MAX:
                return KeyInterval(lower, lower)
            lower = following
    return KeyInterval(lower, upper)


def project_row(
    index_id: str, row: dict[str, Any], *, primary_key_digest: str, primary_row_digest: str,
) -> IndexLeaf | None:
    """Project referenced fields; supplied commitments are only syntax checked.

    Unknown full-row fields are not copied or checked here. The actual primary
    evaluator must own and verify the complete row before this function is used
    in a join. Every referenced field is checked even for a nonmember row.
    """
    definition = _definition(index_id)
    for commitment in (primary_key_digest, primary_row_digest):
        if type(commitment) is not str or _HEX_DIGEST.fullmatch(commitment) is None:
            raise IndexProjectionError("index primary commitment is not canonical SHA-256")
    owned = _snapshot(row, definition.row_fields, closed=False)
    partition = {name: owned[name] for name in definition.partition_fields if name in owned}
    order = _ZERO_ORDER
    if definition.order_codec.endswith(_CHALLENGE_ORDER_SUFFIX):
        if index_id in ("webauthn_challenge_unused_global", "webauthn_challenge_unused_user",
                        "webauthn_challenge_scope_unused") and owned["used_at"] is not None:
            return None
        if index_id == "webauthn_challenge_terminal_unreferenced_global" and (
                owned["used_at"] is None or owned["retention_reference_mask"] != 0):
            return None
        time_key = "0" * 16
        if definition.order_codec.startswith("signed64-"):
            time_field = definition.order_codec.split("/", 1)[0][len("signed64-"):]
            time_key = _signed_order(owned[time_field])
        profile = profile_for(index_id)
        prefix = _partition(profile, partition)
        return IndexLeaf(prefix + time_key + challenge_ids.order_suffix(owned["id"]),
                         primary_key_digest, primary_row_digest)
    if index_id == "webauthn_credential_live_trust":
        if owned["revoked_at"] is not None or owned["attestation_trusted"] == 0:
            return None
    elif index_id in ("webauthn_registration_unused_global", "webauthn_registration_unused_user"):
        if owned["challenge_type"] != "registration" or owned["used_at"] is not None:
            return None
        order = _signed_order(owned["expires_at"]) + "0" * 16
    elif index_id == "webauthn_session_credential_status":
        binding = owned["bound_webauthn_credential_id"]
        if binding is None or owned["status"] not in ("pending_webauthn", "active"):
            return None
        partition = {"credential_record_id": binding, "status": owned["status"]}
    elif index_id in ("webauthn_grant_approver_active", "webauthn_control_approval_approved"):
        binding = owned["approver_webauthn_credential_id"]
        state, wanted = ((owned["state"], "active") if index_id == "webauthn_grant_approver_active"
                         else (owned["status"], "approved"))
        if binding is None or state != wanted:
            return None
        partition = {"credential_record_id": binding}
    elif index_id == "webauthn_publication_generation":
        order = _signed_order(owned["rollback_epoch"]) + _signed_order(owned["sequence"])
    profile = profile_for(index_id)
    prefix = _partition(profile, partition)
    return IndexLeaf(prefix + order + primary_key_digest[7:], primary_key_digest, primary_row_digest)
