"""Explicitly pinned, scoped content measurements; never authorization.

The caller must obtain ``expected_sha256`` independently of the catalog being
read (for example from its protected assembly selection). Matching a digest
supplied by the same untrusted document is not authentication. Entries bind
flat content hashes to kernel fs-verity identities, not paths or permissions.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from types import MappingProxyType

from serverware import authority_artifact_spec as spec

SCHEMA = "serverware.sealedContentCatalog/v1"
MAX_BYTES = 8 * 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_STATE = threading.local()
_PID = os.getpid()


def _require(value):
    if not value:
        raise ValueError("pinned content catalog refused")


def _reset_after_fork():
    global _STATE, _PID
    _STATE, _PID = threading.local(), os.getpid()


os.register_at_fork(after_in_child=_reset_after_fork)


def _pairs(pairs):
    result = {}
    for name, value in pairs:
        _require(name not in result)
        result[name] = value
    return result


def _reject_number(_value):
    raise ValueError("pinned content catalog refused")


def _mapping(raw, expected_sha256):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES
             and type(expected_sha256) is str and _DIGEST.fullmatch(expected_sha256))
    _require("sha256:" + hashlib.sha256(raw).hexdigest() == expected_sha256)
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
        _require(type(value) is dict and set(value) == {"schema", "entries"}
                 and value["schema"] == SCHEMA and type(value["entries"]) is list
                 and 1 <= len(value["entries"]) <= spec.MAX_BUNDLE_FILES)
        result, previous = {}, None
        for row in value["entries"]:
            _require(type(row) is dict and set(row) == {"fsVerityDigest", "size", "sha256"}
                     and type(row["fsVerityDigest"]) is str and _DIGEST.fullmatch(row["fsVerityDigest"])
                     and type(row["sha256"]) is str and _DIGEST.fullmatch(row["sha256"])
                     and type(row["size"]) is int and 0 <= row["size"] <= spec.MAX_FILE_BYTES)
            order = (row["fsVerityDigest"], row["size"])
            _require(previous is None or previous < order)
            previous = order
            result[(bytes.fromhex(row["fsVerityDigest"][7:]), row["size"])] = row["sha256"][7:]
        _require(spec.canonical_json_bytes(value) == raw)
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise ValueError("pinned content catalog refused") from error
    return MappingProxyType(result)


def _current():
    if os.getpid() != _PID:
        _reset_after_fork()
    value = getattr(_STATE, "active", None)
    if value is not None:
        value._owner()
        _require(value._active and value._entries is not None)
    return value


class _PinnedContentCatalog:
    __slots__ = ("_pid", "_thread", "_entries", "_used", "_active")

    def __init__(self, raw, expected_sha256):
        self._pid, self._thread = os.getpid(), threading.current_thread()
        self._entries = _mapping(raw, expected_sha256)
        self._used = self._active = False

    def _owner(self):
        _require(os.getpid() == self._pid and threading.current_thread() is self._thread)

    def __enter__(self):
        self._owner()
        _require(not self._used)
        self._used = True
        _require(_current() is None)
        self._active = True
        _STATE.active = self
        return None

    def __exit__(self, error_type, error, traceback):
        self._owner()
        _require(_current() is self)
        _STATE.active = None
        self._active = False
        self._entries = None
        return False


def pinned_content_catalog(raw, expected_sha256):
    """Validate once; activate only in a single-use same-PID/thread scope.

    Other threads and forked children do not inherit activation. No file is
    retained or reread, and no catalog-derived value enters the observed LRU.
    """
    return _PinnedContentCatalog(raw, expected_sha256)


def _capture(key):
    token = _current()
    return token, None if token is None or key is None else token._entries.get(key)


def _check(token):
    _require(_current() is token)


def _require_inactive():
    _require(_current() is None)
