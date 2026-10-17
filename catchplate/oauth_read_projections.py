"""Bounded enrolled OAuth observations with SELECT-only database access.

Stored status is data, never current activation, retry or revocation authority.
The development readers remain separate because they perform lifecycle writes.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from datetime import datetime, timezone

from catchplate import db
from catchplate import oauth_application_owner as applications

MAX_PENDING = 64
MAX_WORK = 100
MAX_RESULT_BYTES = 1024 * 1024
_PENDING_COLUMNS = ("id", "requester_id", "name", "kind", "payload_digest", "metadata", "review_json",
    "target_credential_id", "target_credential_version", "status", "revocation_status", "revocation_error",
    "revocation_attempts", "revocation_next_attempt_at", "created_at", "expires_at", "updated_at")
_WORK_COLUMNS = ("id", "provider_id", "actor_id", "source", "status", "last_error", "created_at", "updated_at")
_ENROLLED_SOURCE = "enrolled-oauth-exchange/v1"
_MEASURED_SOURCE = "measured-oauth-exchange/v1"
_SETUP_SOURCE = "measured-oauth-setup-exchange/v1"


def _require(value):
    if not value:
        raise ValueError("enrolled OAuth observation unavailable")


def source_owner():
    """None means independently unconfigured development, never failed admission."""
    return applications.require_started()


def _text(value, maximum):
    _require(type(value) is str and value and value == value.strip()
        and len(value.encode("utf-8")) <= maximum
        and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value))
    return value


def _time(value):
    _text(value, 64)
    parsed = datetime.fromisoformat(value)
    _require(parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed))
    return parsed


def _status(value):
    _require(type(value) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", value) is not None)
    return value


def _integer(value, *, minimum=0):
    _require(type(value) is int and minimum <= value <= 2**63 - 1)
    return value


def _actor(value):
    _text(value, 2048)
    _require(len(value) <= 512)
    return value


def _mapping(original):
    _require(type(original) is str and 2 <= len(original.encode("utf-8")) <= 32 * 1024)
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result)
            result[key] = value
        return result
    value = json.loads(original, object_pairs_hook=pairs, parse_constant=lambda _: _require(False))
    _require(type(value) is dict and len(applications.canonical(value)) <= 32 * 1024)
    return value


class _Read:
    def __init__(self, owner):
        _require(type(owner) is applications.OAuthApplicationOwner)
        self.owner, self.identity = owner, (os.getpid(), threading.get_ident())
        self.epoch, self.mono = time.time_ns(), time.monotonic_ns()
        self.expires, self.deadline = self.epoch + 30_000_000_000, self.mono + 30_000_000_000
        self.check()

    def check(self):
        _require(self.identity == (os.getpid(), threading.get_ident()))
        epoch, mono = time.time_ns(), time.monotonic_ns()
        _require(self.epoch <= epoch < self.expires and self.mono <= mono < self.deadline
            and source_owner() is self.owner)
        self.owner.check()
        closing_epoch, closing_mono = time.time_ns(), time.monotonic_ns()
        _require(epoch <= closing_epoch < self.expires and mono <= closing_mono < self.deadline)
        self.epoch, self.mono = closing_epoch, closing_mono


def _pending(row):
    _require(set(row) == set(_PENDING_COLUMNS))
    for field, bound in (("id", 256), ("name", 256)):
        _text(row[field], bound)
    _actor(row["requester_id"])
    _require(row["kind"] == "oauth2" and type(row["payload_digest"]) is str
        and re.fullmatch(r"sha256:[0-9a-f]{64}", row["payload_digest"]) is not None)
    _status(row["status"])
    if row["revocation_status"] is not None:
        _status(row["revocation_status"])
    if row["revocation_error"] is not None:
        _text(row["revocation_error"], 2000)
    _integer(row["revocation_attempts"])
    if row["target_credential_id"] is None:
        _require(row["target_credential_version"] is None)
    else:
        _text(row["target_credential_id"], 256)
        _integer(row["target_credential_version"], minimum=1)
    created, expires, updated = (_time(row[key]) for key in ("created_at", "expires_at", "updated_at"))
    _require(created < expires and created <= updated)
    if row["revocation_next_attempt_at"] is not None:
        _time(row["revocation_next_attempt_at"])
    metadata, review = _mapping(row["metadata"]), _mapping(row["review_json"])
    provider, subject, _ = db.validate_managed_oauth_account_identity(metadata)
    db._validate_oauth_activation_review(review=review, metadata=metadata, name=row["name"], kind=row["kind"],
        provider_id=provider, provider_subject=subject, target_credential_id=row["target_credential_id"],
        target_credential_version=row["target_credential_version"])
    for field, bound in (("provider", 128), ("provider_subject", 4096), ("provider_account", 4096), ("credential_name", 256)):
        _text(review[field], bound)
    _require(type(review["scopes"]) is list and 1 <= len(review["scopes"]) <= 128
        and type(review["metadata_keys"]) is list and len(review["metadata_keys"]) <= 256)
    for value in review["scopes"]:
        _text(value, 1024)
    for value in review["metadata_keys"]:
        _require(type(value) is str and len(value.encode("utf-8")) <= 4096)
    if review.get("expires_at_epoch_ms") is not None:
        _integer(review["expires_at_epoch_ms"], minimum=1)
    # Preserve the original public sixteen fields without permissive str/int
    # coercion, malformed-JSON fallback, status promotion or expiry mutation.
    return {**{key: row[key] for key in _PENDING_COLUMNS if key not in {"metadata", "review_json"}}, "review": review}


def pending(owner, *, requester_id=None):
    read = _Read(owner)
    if requester_id is not None:
        _actor(requester_id)
    query = "SELECT " + ", ".join(_PENDING_COLUMNS) + " FROM pending_oauth_credentials"
    params = []
    if requester_id is not None:
        query += " WHERE requester_id = ?"
        params.append(requester_id)
    query += " ORDER BY created_at DESC, id DESC LIMIT ?"
    params.append(MAX_PENDING + 1)
    read.check()
    with db.connect() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    read.check()
    _require(len(rows) <= MAX_PENDING)
    result = []
    for original in rows:
        read.check()
        row = dict(original)
        _require(requester_id is None or row["requester_id"] == requester_id)
        result.append(_pending(row))
    _require(len(applications.canonical(result)) <= MAX_RESULT_BYTES)
    read.check()
    return result


def uncertainties(owner, *, actor_id=None):
    read = _Read(owner)
    if actor_id is not None:
        _actor(actor_id)
    # Include every retained enrolled state, including reserved, in-flight,
    # held and terminal cleanup observations. Do not run an expiry writer to
    # relabel an interrupted claim, or omit it as though it were clean.
    query = ("SELECT " + ", ".join(_WORK_COLUMNS) + " FROM oauth_revocation_work "
        "WHERE (source IN (?, ?, ?) OR status IN ('issuance_uncertain_unreported', 'issuance_uncertain'))")
    params = [_ENROLLED_SOURCE, _MEASURED_SOURCE, _SETUP_SOURCE]
    if actor_id is not None:
        query += " AND actor_id = ?"
        params.append(actor_id)
    query += " ORDER BY created_at DESC, id DESC LIMIT ?"
    params.append(MAX_WORK + 1)
    read.check()
    with db.connect() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    read.check()
    _require(len(rows) <= MAX_WORK)
    result = []
    for original in rows:
        read.check()
        row = dict(original)
        _require(set(row) == set(_WORK_COLUMNS) and (actor_id is None or row["actor_id"] == actor_id))
        for field, bound in (("id", 256), ("provider_id", 128), ("source", 256)):
            _text(row[field], bound)
        _actor(row["actor_id"])
        _status(row["status"])
        _require(row["source"] in {_ENROLLED_SOURCE, _MEASURED_SOURCE, _SETUP_SOURCE} or row["status"] in {"issuance_uncertain_unreported", "issuance_uncertain"})
        _require(_time(row["created_at"]) <= _time(row["updated_at"]))
        if row["last_error"] is not None:
            _text(row["last_error"], 2000)
        if row["source"] in {_ENROLLED_SOURCE, _MEASURED_SOURCE, _SETUP_SOURCE}:
            _require(row["last_error"] is None)
        result.append(row)
    _require(len(applications.canonical(result)) <= MAX_RESULT_BYTES)
    read.check()
    return result
