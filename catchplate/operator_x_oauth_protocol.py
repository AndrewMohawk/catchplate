"""Pure X posting OAuth codecs; no contact, custody or lifecycle authority.

Requests are descriptions, not permission to send. Results describe supplied
response bytes, not authenticated transport, issuance/rejection proofs, account
admission, revocation propagation, or permission to retire work. A future owner
must supply those boundaries and retain uncertain material before any effects.
There is no retry policy. This conservative profile requires explicit scopes and
a returned refresh token on both grants; omission is uncertain, not rejection or
permission to reuse the prior token. No refresh rotation guarantee is assumed.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import json
import re
from urllib.parse import parse_qsl, quote_plus, unquote_plus, urlencode

from catchplate import operator_x_oauth_profile as profiles

AUTHORIZATION_URL = profiles.AUTHORIZATION_URL
TOKEN_URL = profiles.TOKEN_URL
REVOCATION_URL = profiles.REVOCATION_URL
IDENTITY_URL = profiles.IDENTITY_URL
SCOPES = profiles.SCOPES
MAX_TOKEN_BYTES = 128 * 1024
MAX_TOKEN_RESPONSE_BYTES = 256 * 1024
MAX_IDENTITY_RESPONSE_BYTES = 64 * 1024
MAX_REVOKE_RESPONSE_BYTES = 16 * 1024
MAX_LIFETIME_SECONDS = 366 * 24 * 60 * 60
_ERROR = "operator X OAuth protocol refused"
_MEDIA = re.compile(r'application/json(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*(?:utf-8|"utf-8"))?[ \t]*', re.I | re.ASCII)
_HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", re.ASCII)
_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}", re.ASCII)
_DENIALS = {400: frozenset({"invalid_request", "invalid_client", "invalid_grant",
    "unauthorized_client", "unsupported_grant_type", "invalid_scope"}),
    401: frozenset({"invalid_client"})}


class ProtocolError(ValueError):
    def __init__(self):
        super().__init__(_ERROR)


def _need(condition):
    if not condition:
        raise ProtocolError()


def _profile(value):
    try:
        return profiles.validate_profile(value)
    except (ValueError, TypeError, AttributeError):
        raise ProtocolError() from None


def _opaque(value, maximum=MAX_TOKEN_BYTES):
    _need(type(value) is str and 1 <= len(value) <= maximum
        and all(33 <= ord(char) <= 126 for char in value))
    return value


@dataclass(frozen=True, slots=True)
class Request:
    """Private HTTP description; deliberately not a transport/ownership proof."""
    profile: profiles.Profile = field(repr=False)
    phase: str
    method: str
    url: str
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    body: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class AcceptedToken:
    request: Request = field(repr=False)
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    expires_in: int
    scopes: tuple[str, ...]
    refresh_token_expires_in: int | None


@dataclass(frozen=True, slots=True)
class RejectedToken:
    """Closed response syntax only, never a consumable retirement proof."""
    request: Request = field(repr=False)
    http_status: int
    error_code: str


@dataclass(frozen=True, slots=True)
class UncertainResponse:
    request: Request = field(repr=False)
    http_status: int | None
    raw_body: bytes = field(repr=False)
    raw_complete: bool
    token_material: tuple[tuple[str, str], ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class AcceptedIdentity:
    """Numeric subject parsed from supplied bytes, not provider verification."""
    request: Request = field(repr=False)
    subject: str
    username: str = field(repr=False)  # Mutable display only.
    name: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class AcceptedRevocation:
    """Recognized HTTP 200 response, not durable/local/global revocation."""
    request: Request = field(repr=False)


def authorization_url(profile, *, state, code_verifier):
    profile = _profile(profile)
    _need(type(state) is str and re.fullmatch(r"[A-Za-z0-9_-]{43,128}", state))
    _need(type(code_verifier) is str and _VERIFIER.fullmatch(code_verifier))
    challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return AUTHORIZATION_URL + "?" + urlencode({"response_type": "code",
        "client_id": profile.client_id, "redirect_uri": profile.redirect_uri,
        "scope": " ".join(SCOPES), "state": state, "code_challenge": challenge,
        "code_challenge_method": "S256"})


def _form_request(profile, client_secret, phase, url, values):
    profile = _profile(profile)
    try:
        secret = profiles.validate_client_secret(client_secret)
        # RFC 6749 section 2.3.1 encodes BOTH components before adding ':';
        # valid client IDs/secrets may themselves contain ':', '+', '%' or UTF-8.
        basic = (quote_plus(profile.client_id, safe="") + ":" + quote_plus(secret, safe="")).encode("ascii")
    except (ValueError, TypeError, UnicodeError):
        raise ProtocolError() from None
    return Request(profile, phase, "POST", url, (("Authorization", "Basic " + base64.b64encode(basic).decode("ascii")),
        ("Content-Type", "application/x-www-form-urlencoded"), ("Accept", "application/json")),
        urlencode(values).encode("ascii"))


def code_exchange_request(profile, client_secret, code, code_verifier):
    profile = _profile(profile)
    _need(type(code_verifier) is str and _VERIFIER.fullmatch(code_verifier))
    return _form_request(profile, client_secret, "code", TOKEN_URL,
        {"grant_type": "authorization_code", "code": _opaque(code, 4096),
         "redirect_uri": profile.redirect_uri, "code_verifier": code_verifier})


def refresh_request(profile, client_secret, refresh_token):
    return _form_request(profile, client_secret, "refresh", TOKEN_URL,
        {"grant_type": "refresh_token", "refresh_token": _opaque(refresh_token)})


def revoke_request(profile, client_secret, token, token_type_hint):
    _need(type(token_type_hint) is str and token_type_hint in {"access_token", "refresh_token"})
    return _form_request(profile, client_secret, "revoke", REVOCATION_URL,
        {"token": _opaque(token), "token_type_hint": token_type_hint})


def identity_request(profile, access_token):
    return Request(_profile(profile), "identity", "GET", IDENTITY_URL,
        (("Authorization", "Bearer " + _opaque(access_token)), ("Accept", "application/json")), b"")


def _request(value, phases):
    # Reconstruct with the same builders: a publicly constructible description
    # must not mislabel arbitrary bytes as a request for the retained Profile.
    try:
        _need(type(value) is Request and type(value.phase) is str and value.phase in phases)
        profile = _profile(value.profile)
        _need(type(value.body) is bytes and len(value.body) <= 4 * MAX_TOKEN_BYTES
            and type(value.headers) is tuple)
        if value.phase == "identity":
            _need(len(value.headers) == 2 and type(value.headers[0]) is tuple
                and len(value.headers[0]) == 2 and value.headers[0][0] == "Authorization")
            bearer = value.headers[0][1]
            _need(type(bearer) is str and bearer.startswith("Bearer "))
            expected = identity_request(profile, bearer[7:])
        else:
            _need(len(value.headers) == 3 and type(value.headers[0]) is tuple
                and len(value.headers[0]) == 2 and value.headers[0][0] == "Authorization")
            basic = value.headers[0][1]
            _need(type(basic) is str and basic.startswith("Basic ") and len(basic) <= 32 * 1024)
            client, secret = base64.b64decode(basic[6:], validate=True).decode("ascii").split(":")
            _need(unquote_plus(client, errors="strict") == profile.client_id)
            secret = unquote_plus(secret, errors="strict")
            pairs = parse_qsl(value.body.decode("ascii"), keep_blank_values=True,
                strict_parsing=True, encoding="utf-8", errors="strict", max_num_fields=4)
            form = dict(pairs)
            _need(len(form) == len(pairs))
            if value.phase == "code":
                _need(set(form) == {"grant_type", "code", "redirect_uri", "code_verifier"})
                expected = code_exchange_request(profile, secret, form["code"], form["code_verifier"])
            elif value.phase == "refresh":
                _need(set(form) == {"grant_type", "refresh_token"})
                expected = refresh_request(profile, secret, form["refresh_token"])
            else:
                _need(set(form) == {"token", "token_type_hint"})
                expected = revoke_request(profile, secret, form["token"], form["token_type_hint"])
        _need(value == expected)
    except (ValueError, TypeError, AttributeError, UnicodeError):
        raise ProtocolError() from None


class _Pairs(list):
    """Keep duplicate values until private material has been retained."""


def _decoded(raw):
    # The bounded raw bytes survive any decoding/grammar failure. Decoding with
    # pairs first also preserves BOTH tokens in a duplicate-key response.
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_Pairs)
    except (ValueError, UnicodeError, RecursionError):
        return None


def _unique(value, depth=0, budget=None):
    if budget is None:
        budget = [4096]
    budget[0] -= 1
    _need(depth <= 16 and budget[0] >= 0)
    if type(value) is _Pairs:
        result = {}
        for key, item in value:
            _need(key not in result)
            _unique(key, depth + 1, budget)
            result[key] = _unique(item, depth + 1, budget)
        return result
    if type(value) is list:
        return [_unique(item, depth + 1, budget) for item in value]
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeError:
            raise ProtocolError() from None
        return value
    _need(value is None or type(value) is bool or (type(value) is int and -(2**53 - 1) <= value <= 2**53 - 1))
    return value


def _uncertain(request, status, body, maximum):
    complete = type(body) is bytes and len(body) <= maximum
    raw = body[:maximum] if type(body) is bytes else b""
    parsed = _decoded(raw) if complete else None
    material = tuple((key, value) for key, value in parsed
        if key in {"access_token", "refresh_token"} and type(value) is str) if type(parsed) is _Pairs else ()
    return UncertainResponse(request, status if type(status) is int else None,
        raw, complete, material), parsed


def _headers(headers, body, *, json_required):
    _need(type(headers) in {tuple, list} and len(headers) <= 64)
    selected = {}
    size = 0
    for pair in headers:
        _need(type(pair) in {tuple, list} and len(pair) == 2)
        name, value = pair
        _need(type(name) is str and type(value) is str and _HEADER.fullmatch(name)
            and all(32 <= ord(char) <= 126 or char == "\t" for char in value))
        size += len(name) + len(value)
        _need(size <= 16 * 1024)
        name = name.lower()
        if name in {"content-type", "content-length", "content-encoding", "transfer-encoding", "location"}:
            _need(name not in selected)
            selected[name] = value
    _need("location" not in selected
        and selected.get("content-encoding", "identity").lower() == "identity")
    length = selected.get("content-length")
    transfer = selected.get("transfer-encoding")
    # The transport has already framed/dechunked these bounded response bytes.
    _need(transfer is None or (transfer.lower() == "chunked" and length is None))
    _need(length is None or (re.fullmatch(r"0|[1-9][0-9]{0,8}", length) and int(length) == len(body)))
    media = selected.get("content-type")
    _need((not json_required and media is None) or
        (media is not None and len(media) <= 256 and _MEDIA.fullmatch(media)))


def _lifetime(value):
    _need(type(value) is int and 1 <= value <= MAX_LIFETIME_SECONDS)
    return value


def classify_token_response(request, *, status, headers, body):
    _request(request, {"code", "refresh"})
    uncertain, parsed = _uncertain(request, status, body, MAX_TOKEN_RESPONSE_BYTES)
    try:
        _need(uncertain.raw_complete and type(status) is int)
        _headers(headers, body, json_required=True)
        value = _unique(parsed)
        _need(type(value) is dict)
        if status in _DENIALS and not uncertain.token_material:
            _need(set(value) <= {"error", "error_description", "error_uri"}
                and type(value.get("error")) is str and value["error"] in _DENIALS[status]
                and len(body) <= MAX_REVOKE_RESPONSE_BYTES)
            _need(all(type(item) is str and len(item.encode("utf-8")) <= 4096
                and not any(ord(char) < 32 or ord(char) == 127 for char in item)
                for item in value.values()))
            return RejectedToken(request, status, value["error"])
        _need(status == 200 and set(value) in (
            {"access_token", "refresh_token", "token_type", "expires_in", "scope"},
            {"access_token", "refresh_token", "token_type", "expires_in", "scope", "refresh_token_expires_in"}))
        _need(type(value["token_type"]) is str and value["token_type"].lower() == "bearer")
        scope = value["scope"]
        _need(type(scope) is str and len(scope) <= 256)
        scopes = scope.split(" ")
        _need(len(scopes) == len(SCOPES) and tuple(sorted(scopes)) == SCOPES)
        return AcceptedToken(request, _opaque(value["access_token"]), _opaque(value["refresh_token"]),
            _lifetime(value["expires_in"]), SCOPES,
            _lifetime(value["refresh_token_expires_in"]) if "refresh_token_expires_in" in value else None)
    except (ProtocolError, UnicodeError, ValueError, TypeError):
        return uncertain


def classify_identity_response(request, *, status, headers, body):
    _request(request, {"identity"})
    uncertain, parsed = _uncertain(request, status, body, MAX_IDENTITY_RESPONSE_BYTES)
    try:
        _need(uncertain.raw_complete and type(status) is int and status == 200)
        _headers(headers, body, json_required=True)
        value = _unique(parsed)
        _need(type(value) is dict and set(value) == {"data"})
        data = value["data"]
        _need(type(data) is dict and set(data) == {"id", "name", "username"})
        subject, name, username = data["id"], data["name"], data["username"]
        _need(type(subject) is str and re.fullmatch(r"[1-9][0-9]{0,19}", subject)
            and int(subject) <= 2**64 - 1)
        _need(type(username) is str and re.fullmatch(r"[A-Za-z0-9_]{1,15}", username))
        _need(type(name) is str and 1 <= len(name.encode("utf-8")) <= 512
            and not any(ord(char) < 32 or ord(char) == 127 for char in name))
        return AcceptedIdentity(request, subject, username, name)
    except (ProtocolError, UnicodeError, ValueError, TypeError):
        return uncertain


def classify_revoke_response(request, *, status, headers, body):
    _request(request, {"revoke"})
    uncertain, parsed = _uncertain(request, status, body, MAX_REVOKE_RESPONSE_BYTES)
    try:
        _need(uncertain.raw_complete and type(status) is int and status == 200)
        _headers(headers, body, json_required=bool(body))
        if body:
            value = _unique(parsed)
            _need(type(value) is dict and set(value) == {"revoked"} and value["revoked"] is True)
        return AcceptedRevocation(request)
    except (ProtocolError, UnicodeError, ValueError, TypeError):
        return uncertain
