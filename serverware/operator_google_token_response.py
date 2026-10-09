"""Bounded operator-only Google refresh response classification.

A closed RFC 6749 section 5.2 denial is not an issued credential. Everything
else remains uncertain; parsed material is private custody input, never proof
of rejection. HTTP 200 keeps the existing JSON-object/token-validation contract.
This module does not retire work, mutate credentials, or implement native OAuth.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid

from serverware import operator_catalog_oauth_profile as profiles
from serverware.http_client import HttpClientError, _strict_json_loads


REJECTION_CODES_BY_STATUS = {
    400: frozenset({"invalid_request", "invalid_client", "invalid_grant",
                    "unauthorized_client", "unsupported_grant_type", "invalid_scope"}),
    401: frozenset({"invalid_client"}),
}
_TOKEN_URL = "https://oauth2.googleapis.com/token"
_MAX_BODY = 256 * 1024
_MAX_ERROR_BODY = 16 * 1024
_ERROR_FIELDS = frozenset({"error", "error_description", "error_uri", "error_subtype"})
_MEDIA_TYPE = re.compile(
    r'application/json(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*(?:utf-8|utf8|"utf-8"|"utf8"))?[ \t]*',
    re.IGNORECASE | re.ASCII,
)
_SEAL = object()
_REJECTED = "Operator Google refresh was rejected by the token endpoint"
_UNCERTAIN = "Operator Google refresh provider outcome is uncertain"
_FIELDS = ("work_id", "profile_binding_digest", "oauth_client_id", "http_status", "error_code")


@dataclass(frozen=True, slots=True)
class _Summary:
    work_id: str
    profile_binding_digest: str
    oauth_client_id: str
    http_status: int
    error_code: str


class RejectedRefresh(RuntimeError):
    """Response-produced proof; public binding is immutable, each handoff once."""
    __slots__ = ("_summary", "_consumed", "_claimed", "_lock")

    def __init__(self, *, work_id, profile_binding_digest, oauth_client_id,
                 http_status, error_code, _seal=None):
        if _seal is not _SEAL:
            raise ValueError("Google refresh rejection requires response provenance")
        super().__init__(_REJECTED)
        object.__setattr__(self, "_summary", _Summary(
            work_id, profile_binding_digest, oauth_client_id, http_status, error_code))
        object.__setattr__(self, "_consumed", False)
        object.__setattr__(self, "_claimed", False)
        object.__setattr__(self, "_lock", threading.Lock())

    def __setattr__(self, name, value):
        if name in self.__slots__ or name in _FIELDS:
            raise AttributeError("Google refresh rejection binding is immutable")
        super().__setattr__(name, value)

    def __delattr__(self, name):
        if name in self.__slots__ or name in _FIELDS:
            raise AttributeError("Google refresh rejection binding is immutable")
        super().__delattr__(name)

    def __str__(self):
        return _REJECTED

    def __repr__(self):
        return "RejectedRefresh(" + repr(_REJECTED) + ")"

    @property
    def work_id(self):
        return self._summary.work_id

    @property
    def profile_binding_digest(self):
        return self._summary.profile_binding_digest

    @property
    def oauth_client_id(self):
        return self._summary.oauth_client_id

    @property
    def http_status(self):
        return self._summary.http_status

    @property
    def error_code(self):
        return self._summary.error_code

    def matches(self, *, work_id, profile_binding_digest, oauth_client_id):
        return (self.work_id == work_id and self.profile_binding_digest == profile_binding_digest
                and self.oauth_client_id == oauth_client_id)

    def _public_summary(self):
        return {name: getattr(self._summary, name) for name in _FIELDS}

    def consume(self):
        with self._lock:
            if self._consumed:
                raise ValueError("Google refresh rejection already consumed")
            object.__setattr__(self, "_consumed", True)
            return self._public_summary()

    def claim_retirement(self):
        with self._lock:
            if not self._consumed or self._claimed:
                raise ValueError("Google refresh rejection retirement claim refused")
            # This burn deliberately survives a later SQLite rollback.
            object.__setattr__(self, "_claimed", True)
            return self._public_summary()


class UncertainRefreshResponse(RuntimeError):
    """Private parsed payload is for existing custody, never adoption/retirement."""
    def __init__(self, payload=None):
        super().__init__(_UNCERTAIN)
        self._payload = dict(payload) if isinstance(payload, dict) else None

    @property
    def payload(self):
        return None if self._payload is None else dict(self._payload)

    def __str__(self):
        return _UNCERTAIN

    def __repr__(self):
        return "UncertainRefreshResponse(" + repr(_UNCERTAIN) + ")"


def _require_binding(provider, body, headers, work_id, profile):
    try:
        admitted = profiles.require_profile()  # Also refuses native ownership.
        valid = (profile is admitted and profile.profile == "operator-google-v1"
                 and profile.provider_id == provider.id == "google"
                 and provider.token_url == _TOKEN_URL
                 and provider.token_auth == "client_secret_post"
                 and isinstance(work_id, str) and str(uuid.UUID(work_id)) == work_id
                 and isinstance(body, dict)
                 and set(body) == {"grant_type", "refresh_token", "client_id", "client_secret"}
                 and body["grant_type"] == "refresh_token"
                 and body["client_id"] == provider.client_id == profile.client_id
                 and isinstance(body["client_secret"], str) and bool(body["client_secret"])
                 and body["client_secret"] == provider.client_secret
                 and isinstance(body["refresh_token"], str) and bool(body["refresh_token"])
                 and len(body["refresh_token"].encode("utf-8")) <= 128 * 1024
                 and headers == {"Content-Type": "application/x-www-form-urlencoded",
                                 "Accept": "application/json"})
    except (AttributeError, TypeError, ValueError, RuntimeError):
        raise UncertainRefreshResponse() from None
    if not valid:
        raise UncertainRefreshResponse()


def _has_json_media_type(response):
    """Use physical capture, never the duplicate-collapsing header mapping."""
    raw = getattr(response, "raw_headers", ())
    if not isinstance(raw, (tuple, list)) or len(raw) > 100:
        return False
    values = []
    for pair in raw:
        if (not isinstance(pair, (tuple, list)) or len(pair) != 2
                or not all(isinstance(value, str) for value in pair)):
            return False
        if pair[0].lower() == "content-type":
            values.append(pair[1])
    return (len(values) == 1 and len(values[0]) <= 256
            and _MEDIA_TYPE.fullmatch(values[0]) is not None)


def request_refresh(provider, body, headers, *, work_id, profile, request) -> dict:
    """Return a success object; raise sealed denial or private uncertainty.

    The caller supplies its existing request_bytes binding. MIME is checked after
    capture for denials so a mixed/token-bearing object can reach existing custody.
    Unknown HTTPError streams are closed, never read through an unbounded fallback.
    """
    _require_binding(provider, body, headers, work_id, profile)
    outbound = urllib.request.Request(_TOKEN_URL,
        data=urllib.parse.urlencode(body).encode("utf-8"), headers=headers, method="POST")
    try:
        response = request(outbound, timeout=20, max_bytes=_MAX_BODY,
                           require_https=True, expected_statuses=(200, 400, 401))
    except urllib.error.HTTPError as error:
        try:
            error.close()
        finally:
            raise UncertainRefreshResponse() from None
    except (HttpClientError, urllib.error.URLError, TimeoutError, OSError):
        raise UncertainRefreshResponse() from None
    raw = getattr(response, "body", None)
    status = getattr(response, "status", None)
    if not isinstance(raw, bytes) or len(raw) > _MAX_BODY:
        raise UncertainRefreshResponse()
    try:
        # Preserve existing success parsing; rejection parsing is stricter.
        payload = json.loads(raw.decode("utf-8")) if type(status) is int and status == 200 else _strict_json_loads(raw)
    except (HttpClientError, UnicodeDecodeError, ValueError, OverflowError, RecursionError):
        raise UncertainRefreshResponse() from None
    if not isinstance(payload, dict):
        raise UncertainRefreshResponse()
    if type(status) is int and status == 200 and "error" not in payload:
        return payload
    if (type(status) is not int or status not in REJECTION_CODES_BY_STATUS
            or len(raw) > _MAX_ERROR_BODY or not _has_json_media_type(response)
            or not set(payload) <= _ERROR_FIELDS
            or not isinstance(payload.get("error"), str)
            or payload["error"] not in REJECTION_CODES_BY_STATUS[status]
            or not all(isinstance(value, str) for value in payload.values())):
        raise UncertainRefreshResponse(payload)
    raise RejectedRefresh(work_id=work_id, profile_binding_digest=profile.binding_digest,
        oauth_client_id=profile.client_id, http_status=status, error_code=payload["error"], _seal=_SEAL)
