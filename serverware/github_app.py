"""Single-repository GitHub App installation-token protocol, not a custody service.

No environment credentials, redirects, ambient proxies, retries, background work
or persistence. The caller must retain verified numeric bindings for refresh.
After an uncertain mint, discard its candidate and impose bounded backoff before
a later separately authorized mint; do not replay this attempt. Python cannot
promise erasure of immutable PEM/JWT/token bytes. Never log requests or results.

Protocol: docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28 and
docs.github.com/en/rest/apps/installations?apiVersion=2022-11-28.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from email.message import Message
import hashlib
import json
import math
import re
import time
from typing import Callable
from urllib.request import Request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from serverware import github_issues, http_client

ORIGIN = "https://api.github.com"
# Explicitly supported through 2028-03-10 according to GitHub's API-version
# documentation; do not silently follow the newest version/default.
API_VERSION = "2022-11-28"
MAX_MINT_BYTES = 65536
MAX_READ_BYTES = 1048576
TOTAL_TIMEOUT = 20.0
REQUEST_TIMEOUT = 10.0
_MAX_ID = (1 << 53) - 1
_TOKEN = re.compile(r"(?=.{1,8192}\Z)[A-Za-z0-9._~+/-]+=*", re.ASCII)
_EXPIRY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", re.ASCII)


class GitHubAppError(ValueError):
    """Fixed safe message; private evidence is not safe to serialize or log.

    issuance_uncertain means POST may have issued a token, not that it did. A
    bounded mint_body and any parsed candidate_tokens are private, short-lived
    diagnostic evidence, never log/persistence inputs or permission proof. The
    caller discards them and applies backoff. Missing evidence is not proof of
    non-issuance; tokens expire naturally, not proven revoked by this module.
    """

    def __init__(self, phase: str, *, issuance_uncertain: bool = False,
                 mint_body: bytes = b"", candidate_tokens: tuple[str, ...] = ()):
        if phase not in {"configuration", "installation", "mint", "repository", "refresh"}:
            phase = "configuration"
        super().__init__("GitHub App " + phase + " refused")
        self.phase = phase
        self.issuance_uncertain = issuance_uncertain
        self.mint_body = mint_body[:MAX_MINT_BYTES]
        self.candidate_tokens = candidate_tokens


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("GitHub App protocol refused")


def _identifier(value: object) -> bool:
    return type(value) is int and 1 <= value <= _MAX_ID


def _epoch(value: object) -> int:
    _require(type(value) in {int, float} and math.isfinite(value)
             and 60 <= value <= 253402297199)
    return int(value)


@dataclass(frozen=True)
class AppConfig:
    app_id: int
    installation_id: int
    owner: str
    repository: str
    issues: str
    account_id: int | None = None
    repository_id: int | None = None

    def __post_init__(self):
        try:
            _require(_identifier(self.app_id) and _identifier(self.installation_id))
            github_issues.validate_repository({"owner": self.owner, "name": self.repository})
            _require(type(self.issues) is str and self.issues in {"read", "write"})
            _require((self.account_id is None and self.repository_id is None)
                     or (_identifier(self.account_id) and _identifier(self.repository_id)))
        except Exception:
            raise GitHubAppError("configuration") from None


@dataclass(frozen=True)
class SigningKey:
    private_key: rsa.RSAPrivateKey = field(repr=False)
    fingerprint: str


@dataclass(frozen=True)
class InstallationToken:
    config: AppConfig
    token: str = field(repr=False)
    issued_at: int
    expires_at: int
    key_fingerprint: str

    def __post_init__(self):
        try:
            _require(type(self.config) is AppConfig and self.config.repository_id is not None)
            _require(type(self.token) is str and _TOKEN.fullmatch(self.token) is not None)
            _require(type(self.issued_at) is int and type(self.expires_at) is int
                     and _epoch(self.issued_at) == self.issued_at
                     and self.issued_at < self.expires_at <= self.issued_at + 3660)
            _require(type(self.key_fingerprint) is str
                     and re.fullmatch(r"sha256:[0-9a-f]{64}", self.key_fingerprint) is not None)
        except Exception:
            raise GitHubAppError("configuration") from None


def _key_fingerprint(key: rsa.RSAPrivateKey) -> str:
    _require(isinstance(key, rsa.RSAPrivateKey) and 2048 <= key.key_size <= 8192)
    public = key.public_key().public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256:" + hashlib.sha256(public).hexdigest()


def load_private_key(pem: bytes) -> SigningKey:
    """Admit one unencrypted RSA PKCS#1/PKCS#8 PEM; no file or secret lookup."""
    try:
        _require(type(pem) is bytes and 1 <= len(pem) <= 16384)
        match = re.fullmatch(
            rb"-----BEGIN (RSA PRIVATE KEY|PRIVATE KEY)-----\r?\n"
            rb"[A-Za-z0-9+/=\r\n]+-----END \1-----\r?\n?", pem)
        _require(match is not None)
        key = serialization.load_pem_private_key(pem, password=None)
        return SigningKey(key, _key_fingerprint(key))
    except Exception:
        raise GitHubAppError("configuration") from None


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _b64(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def app_jwt(config: AppConfig, key: SigningKey, now_epoch: int) -> str:
    """RS256 App JWT, issued 60 seconds ago, expires nine minutes from now."""
    try:
        _require(type(config) is AppConfig and type(key) is SigningKey)
        _require(key.fingerprint == _key_fingerprint(key.private_key))
        now = _epoch(now_epoch)
        payload = _b64(_json({"alg": "RS256", "typ": "JWT"})) + b"." + _b64(
            _json({"iss": str(config.app_id), "iat": now - 60, "exp": now + 540}))
        signature = key.private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        return (payload + b"." + _b64(signature)).decode("ascii")
    except Exception:
        raise GitHubAppError("configuration") from None


def _headers(token: str, *, post: bool) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": API_VERSION, "User-Agent": "serverware-github-app/1",
        "Accept-Encoding": "identity"}
    if post:
        headers["Content-Type"] = "application/json"
    return headers


def _response(response: http_client.HttpResponse, status: int, maximum: int) -> dict:
    # Repeat response-shape checks at the injection boundary. Framing is handled
    # by request_bytes; strict parsing does not trust a transport-returned dict.
    _require(type(response) is http_client.HttpResponse and type(response.status) is int
             and response.status == status and type(response.body) is bytes
             and 1 <= len(response.body) <= maximum)
    headers = Message()
    _require(type(response.raw_headers) is tuple and len(response.raw_headers) <= 128)
    for name, value in response.raw_headers:
        _require(type(name) is str and type(value) is str and len(name) <= 256
                 and len(value) <= 8192 and not any(c in name + value for c in "\r\n\x00"))
        headers[name] = value
    http_client._response_media_type(headers, expected=("application/json",))
    http_client._validate_content_encoding(headers)
    length = http_client._content_length(headers, max_bytes=maximum)
    http_client._validate_transfer_encoding(headers, has_content_length=length is not None)
    _require(length is None or length == len(response.body))
    value = http_client._strict_json_loads(response.body)
    _require(type(value) is dict and "error" not in value and "errors" not in value)
    return value


def _installation(value: dict, config: AppConfig) -> int:
    _require(_identifier(value.get("id")) and value["id"] == config.installation_id
             and _identifier(value.get("app_id")) and value["app_id"] == config.app_id)
    account = value.get("account")
    _require(type(account) is dict and _identifier(account.get("id"))
             and type(account.get("login")) is str
             and account["login"].lower() == config.owner.lower()
             and account.get("type") in {"User", "Organization"})
    _require(_identifier(value.get("target_id")) and value["target_id"] == account["id"]
             and value.get("target_type") == account["type"])
    _require("suspended_at" in value and value["suspended_at"] is None
             and value.get("suspended_by") is None)
    permissions = value.get("permissions")
    _require(type(permissions) is dict and permissions.get("metadata") == "read"
             and permissions.get("issues") in ({"read", "write"} if config.issues == "read" else {"write"}))
    _require(config.account_id is None or config.account_id == account["id"])
    return account["id"]


def _repository(value: object, config: AppConfig, account_id: int) -> int:
    _require(type(value) is dict and _identifier(value.get("id"))
             and type(value.get("name")) is str and value["name"].lower() == config.repository.lower()
             and type(value.get("full_name")) is str
             and value["full_name"].lower() == (config.owner + "/" + config.repository).lower())
    owner = value.get("owner")
    _require(type(owner) is dict and _identifier(owner.get("id")) and owner["id"] == account_id
             and type(owner.get("login")) is str and owner["login"].lower() == config.owner.lower())
    _require(config.repository_id is None or config.repository_id == value["id"])
    return value["id"]


def _expiry(value: object, now: int) -> int:
    _require(type(value) is str and _EXPIRY.fullmatch(value) is not None)
    expires = int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    # GitHub tokens last one hour; allow only 60 seconds of provider clock skew.
    _require(now < expires <= now + 3660)
    return expires


def mint_installation_token(config: AppConfig, key: SigningKey, *,
                            transport: Callable | None = None,
                            clock: Callable[[], float] = time.time) -> InstallationToken:
    """Verify, mint once, and independently verify the token's one repository.

    Injection is an internal test seam, not a configurable URL/HTTP interface.
    A failed mint or any subsequent check is uncertain and MUST NOT be retried
    automatically. No identity is adopted from a renewal response.
    """
    phase, attempted, mint_body, candidates = "configuration", False, b"", ()
    try:
        _require(type(config) is AppConfig)
        started = _epoch(clock())
        jwt = app_jwt(config, key, started)
        deadline = http_client.HttpDeadline.after(TOTAL_TIMEOUT)
        send = http_client.request_bytes if transport is None else transport

        def exchange(method: str, path: str, token: str, body: object | None, limit: int):
            request = Request(ORIGIN + path, data=None if body is None else _json(body),
                headers=_headers(token, post=method == "POST"), method=method)
            return send(request, timeout=REQUEST_TIMEOUT, max_bytes=limit,
                require_https=True, deadline=deadline, expected_statuses=tuple(range(200, 600)))

        phase = "installation"
        installation = exchange("GET", "/repos/" + config.owner + "/" + config.repository
            + "/installation", jwt, None, MAX_READ_BYTES)
        account_id = _installation(_response(installation, 200, MAX_READ_BYTES), config)
        permissions = {"issues": config.issues, "metadata": "read"}
        body = {"permissions": permissions}
        body["repositories" if config.repository_id is None else "repository_ids"] = [
            config.repository if config.repository_id is None else config.repository_id]
        phase, attempted = "mint", True
        response = exchange("POST", "/app/installations/" + str(config.installation_id)
            + "/access_tokens", jwt, body, MAX_MINT_BYTES)
        if type(response) is http_client.HttpResponse and type(response.body) is bytes:
            mint_body = response.body[:MAX_MINT_BYTES]
        value = _response(response, 201, MAX_MINT_BYTES)
        token = value.get("token")
        if type(token) is str and _TOKEN.fullmatch(token):
            candidates = (token,)
        _require(bool(candidates) and value.get("permissions") == permissions
                 and value.get("repository_selection") == "selected")
        expires = _expiry(value.get("expires_at"), started)
        minted_repo = None
        if "repositories" in value:
            _require(type(value["repositories"]) is list and len(value["repositories"]) == 1)
            minted_repo = _repository(value["repositories"][0], config, account_id)
        phase = "repository"
        listing = _response(exchange("GET", "/installation/repositories?per_page=100&page=1",
            token, None, MAX_READ_BYTES), 200, MAX_READ_BYTES)
        _require(type(listing.get("total_count")) is int and listing["total_count"] == 1
                 and type(listing.get("repositories")) is list and len(listing["repositories"]) == 1)
        repository_id = _repository(listing["repositories"][0], config, account_id)
        _require(minted_repo is None or repository_id == minted_repo)
        finished = _epoch(clock())
        _require(started <= finished < expires)
        return InstallationToken(replace(config, account_id=account_id, repository_id=repository_id),
            token, started, expires, key.fingerprint)
    except Exception:
        raise GitHubAppError(phase, issuance_uncertain=attempted, mint_body=mint_body,
            candidate_tokens=candidates) from None


def needs_refresh(token: InstallationToken, now_epoch: int, margin_seconds: int = 60) -> bool:
    try:
        _require(type(token) is InstallationToken and type(margin_seconds) is int
                 and 0 <= margin_seconds <= 300)
        now = _epoch(now_epoch)
        return now < token.issued_at or now >= token.expires_at - margin_seconds
    except Exception:
        raise GitHubAppError("refresh") from None


def get_or_refresh(config: AppConfig, key: SigningKey, current: InstallationToken | None = None,
                   *, transport: Callable | None = None,
                   clock: Callable[[], float] = time.time) -> InstallationToken:
    """Caller-owned cache primitive. Never fall back to stale or mismatched tokens.

    No lock/thread/persistence is hidden here; a service must serialize refresh,
    commit the verified binding/token, and back off after uncertain mint failure.
    """
    try:
        _require(type(config) is AppConfig and type(key) is SigningKey
                 and key.fingerprint == _key_fingerprint(key.private_key))
        if current is not None:
            _require(type(current) is InstallationToken)
            effective = replace(config, account_id=current.config.account_id,
                repository_id=current.config.repository_id) if config.account_id is None else config
            _require(effective == current.config)
            config = effective
            if current.key_fingerprint == key.fingerprint and not needs_refresh(current, _epoch(clock())):
                return current
    except Exception:
        raise GitHubAppError("refresh") from None
    return mint_installation_token(config, key, transport=transport, clock=clock)
