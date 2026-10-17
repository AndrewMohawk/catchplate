"""Source-bound challenge counts from retained counted frontiers.

An input count is never accepted. Each interval is derived from the original
request subject and database cutoff, then its raw frontier reconstructs the
independently selected head. Results are relative observations, not root
currentness, request authorization, installed population or SQL effects.
"""
from __future__ import annotations

import json
from typing import Any

from catchplate import authority_index_count_reader as acquisition
from catchplate import authority_index_projection as projection
from catchplate import authority_index_range_count as reconstruction
from catchplate.authority_index_contract import CountedNode, OpaqueSubtree
from catchplate.authority_index_heads import CapturedIndexHead
from catchplate.authority_index_range import IndexRangeLimits
from catchplate.authority_query_read_work import _ValidationWork


SCHEMA = "catchplate.policyAuthorityChallengeCountEvidence/v1"
ADMISSION_ROLES = (
    "admission_global_live", "admission_user_live", "admission_global_rate",
    "admission_user_rate", "admission_terminal_count",
)
MAINTENANCE_ROLES = ("expired_remaining", "old_remaining", "overflow_skip_count")
SCOPE_ROLE = "scope_replacement_count"
ALL_ROLES = (*ADMISSION_ROLES, *MAINTENANCE_ROLES, SCOPE_ROLE)
_ROLES = {
    "admission_global_live": ("webauthn_challenge_unused_global", "strictly-after", "now"),
    "admission_user_live": ("webauthn_challenge_unused_user", "strictly-after", "now"),
    "admission_global_rate": ("webauthn_challenge_created_global", "strictly-after", "rate"),
    "admission_user_rate": ("webauthn_challenge_created_user", "strictly-after", "rate"),
    "admission_terminal_count": ("webauthn_challenge_terminal_unreferenced_global", "all", "zero"),
    "expired_remaining": ("webauthn_challenge_unused_global", "at-or-before", "now"),
    "old_remaining": ("webauthn_challenge_terminal_unreferenced_global", "at-or-before", "retention"),
}
_FIELDS = frozenset({"schema", "role", "indexId", "indexRevision", "rootDigest", "rootCount",
                     "lower", "upper", "frontier"})


class ChallengeCountError(ValueError):
    pass


def _integer(value, lower=0, upper=2**63 - 1):
    if type(value) is not int or not lower <= value <= upper:
        raise ChallengeCountError("challenge count parameter is not an exact bounded integer")
    return value


def source_interval(role: str, *, user_id: str, cutoff_us: int,
                    rate_window_us: int, retention_us: int, work: _ValidationWork):
    """Only semantic inputs enter this recipe, never a supplied raw interval."""
    if type(role) is not str or role not in _ROLES:
        raise ChallengeCountError("challenge count role is not source declared")
    if type(work) is not _ValidationWork:
        raise ChallengeCountError("challenge count recipe requires its original shared meter")
    _integer(cutoff_us)
    _integer(rate_window_us, 1)
    _integer(retention_us, 1)
    index_id, direction, which = _ROLES[role]
    value = (cutoff_us if which == "now" else cutoff_us - rate_window_us if which == "rate"
             else cutoff_us - retention_us if which == "retention" else 0)
    _integer(value, -(2**63))
    selector = {"cutoff_us": value, "direction": direction}
    if index_id.endswith("_user"):
        selector["user_id"] = user_id
    acquisition.reader._profile_work(index_id, work)
    profile = projection.profile_for(index_id)
    # The existing preparer consults only the declared index_id. An actual
    # IndexProfile supplies that identity; no fake CompleteIndexQuery is made.
    acquisition.reader._interval_work(profile, profile, selector, work)
    return profile, projection.query_interval(index_id, selector)


def _limits():
    # Same structural frontier bounds as the actual reader; no added allowance
    # per role when the common validation meter is supplied.
    return IndexRangeLimits(max_entries=acquisition.MAX_PREFIXES, max_leaves=1,
        max_opened_nodes=acquisition.MAX_OPENED_NODES,
        max_hashes=16 * acquisition.MAX_OPENED_NODES,
        max_input_bytes=acquisition.reader.MAX_TRANSPORT_BYTES)


def scope_interval(*, challenge_type, user_id, scope_key, work):
    """Exact legacy equality selector; NULL scope never starts replacement."""
    if type(work) is not _ValidationWork or type(scope_key) is not str:
        raise ChallengeCountError("challenge scope count needs the original non-null scope")
    index_id = "webauthn_challenge_scope_unused"
    selector = {"challenge_type": challenge_type, "user_id": user_id, "scope_key": scope_key}
    acquisition.reader._profile_work(index_id, work)
    profile = projection.profile_for(index_id)
    acquisition.reader._interval_work(profile, profile, selector, work)
    return profile, projection.query_interval(index_id, selector)


def evidence(role: str, observation: acquisition.AcquiredIndexCount, *, work: _ValidationWork):
    """Serialize actual raw observations; this conveys no successful verdict."""
    if type(work) is not _ValidationWork or type(observation) is not acquisition.AcquiredIndexCount:
        raise ChallengeCountError("challenge count acquisition is not the exact local observation")
    if role not in ALL_ROLES:
        raise ChallengeCountError("challenge count role is not source declared")
    raw = {"schema": SCHEMA, "role": role, "indexId": observation.profile.index_id,
        "indexRevision": observation.index_revision, "rootDigest": observation.root.digest,
        "rootCount": observation.root.count, "lower": observation.interval.lower,
        "upper": observation.interval.upper,
        "frontier": [{"prefix": entry.prefix, "digest": entry.digest, "count": entry.count}
                     for entry in observation.frontier]}
    work.prepare_normalization(raw)
    return json.loads(json.dumps(raw, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")))


def verify_evidence(raw: Any, *, role: str, expected_head: CapturedIndexHead,
                    user_id: str, cutoff_us: int, rate_window_us: int,
                    retention_us: int, work: _ValidationWork) -> int:
    """Replay the raw proof under a separately admitted exact counted head."""
    if type(work) is not _ValidationWork or type(expected_head) is not CapturedIndexHead:
        raise ChallengeCountError("challenge count verification lacks its original meter/head")
    # Own the source semantic selector before any proof callback. The head is
    # reconstructed below instead of relying on dataclass construction history.
    profile, interval = source_interval(role, user_id=user_id, cutoff_us=cutoff_us,
        rate_window_us=rate_window_us, retention_us=retention_us, work=work)
    return _verify_interval_evidence(raw, role=role, expected_head=expected_head,
        profile=profile, interval=interval, work=work)


def _verify_interval_evidence(raw, *, role, expected_head, profile, interval, work):
    """Private composition seam: the phase kernel derives the rank interval.

    In particular, overflow's exclusive lower bound is derived from its last
    genuinely joined candidate. It is not a request argument or a public
    caller-selected count predicate. The owning phase replays that derivation.
    """
    if (type(work) is not _ValidationWork or type(expected_head) is not CapturedIndexHead
            or role not in ALL_ROLES):
        raise ChallengeCountError("challenge count replay context is not source admitted")
    head_identity = (expected_head.index_id, expected_head.index_revision,
                     expected_head.index_root.digest, expected_head.index_root.count)
    root = CountedNode(head_identity[2], head_identity[3])
    _integer(head_identity[1])
    if head_identity[0] != profile.index_id:
        raise ChallengeCountError("challenge count role uses a different admitted index")
    if type(raw) is not dict or set(raw) != _FIELDS or type(raw.get("frontier")) is not list:
        raise ChallengeCountError("challenge count evidence is not source closed")
    if len(raw["frontier"]) > acquisition.MAX_PREFIXES:
        raise ChallengeCountError("challenge count evidence exceeds its source frontier bound")
    work.prepare_normalization(raw)
    raw = json.loads(json.dumps(raw, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")))
    if (raw["schema"] != SCHEMA or raw["role"] != role
            or type(raw["indexRevision"]) is not int or type(raw["rootCount"]) is not int
            or (raw["indexId"], raw["indexRevision"], raw["rootDigest"], raw["rootCount"]) != head_identity
            or (raw["lower"], raw["upper"]) != (interval.lower, interval.upper)):
        raise ChallengeCountError("challenge count evidence differs from its source selector/head")
    frontier = []
    for entry in raw["frontier"]:
        if type(entry) is not dict or set(entry) != {"prefix", "digest", "count"}:
            raise ChallengeCountError("challenge count frontier entry is not closed")
        frontier.append(OpaqueSubtree(entry["prefix"], entry["digest"], entry["count"]))
    result = reconstruction._reconstruct_index_range_count(profile=profile, expected_root=root,
        interval=interval, frontier=tuple(frontier), limits=_limits(), work=work)
    return result.count
