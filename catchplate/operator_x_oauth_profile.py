"""Pure, closed X OAuth application configuration, not lifecycle authority.

These values do not configure or activate an application, prove its ownership,
verify an account, grant posting, or admit development/native execution. There
are no settings, environment, database, key-initialization or network effects.
The configuration and lifecycle owners must supply those independent admissions.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields
import hashlib
import json
import uuid

from pydantic import ConfigDict, Field, field_validator

from catchplate.operator_catalog_inputs import RevisionInput
from catchplate.operator_demo import origin

SCHEMA = "catchplate.operatorXOAuthProfile/v1"
PROFILE = "operator-x-oauth-v1"
PERMISSION_PRESET = "x_text_post_v1"
SCOPES = ("offline.access", "tweet.read", "tweet.write", "users.read")
API_ORIGINS = ("https://api.x.com",)
CALLBACK_PATH = "/api/oauth/callback/x"
CLIENT_AUTH_METHOD = "client_secret_basic"
AUTHORIZATION_URL = "https://x.com/i/oauth2/authorize"
TOKEN_URL = "https://api.x.com/2/oauth2/token"
REVOCATION_URL = "https://api.x.com/2/oauth2/revoke"
IDENTITY_URL = "https://api.x.com/2/users/me"
MAX_CLIENT_ID_BYTES = 256
MAX_SECRET_BYTES = 4096
MAX_PROFILE_BYTES = 4096
_ERROR = "operator X OAuth profile refused"


class ProfileError(ValueError):
    """Fixed, non-secret configuration failure."""


def _require(condition):
    if not condition:
        raise ProfileError(_ERROR)


def validate_client_id(value: str) -> str:
    _require(type(value) is str and 1 <= len(value) <= MAX_CLIENT_ID_BYTES
        and all(33 <= ord(char) <= 126 for char in value))
    return value


def validate_client_secret(value: str) -> str:
    try:
        _require(type(value) is str and value == value.strip()
            and not any(char in value for char in ("\x00", "\r", "\n"))
            and 1 <= len(value.encode("utf-8")) <= MAX_SECRET_BYTES)
        return value
    except (UnicodeError, TypeError, AttributeError):
        raise ProfileError(_ERROR) from None


def _public_origin(value: str) -> str:
    try:
        _require(type(value) is str)
        canonical, _ = origin(value)
        _require(value == canonical and canonical != "https://demo-upstream:8443")
        return canonical
    except (ValueError, TypeError, AttributeError):
        raise ProfileError(_ERROR) from None


def _record(client_id: str, redirect_uri: str) -> dict:
    return {"schema": SCHEMA, "profile": PROFILE, "provider_id": "x",
        "client_id": client_id, "redirect_uri": redirect_uri,
        "client_auth_method": CLIENT_AUTH_METHOD, "permission_preset": PERMISSION_PRESET,
        "scopes": list(SCOPES), "api_origins": list(API_ORIGINS),
        "authorization_url": AUTHORIZATION_URL, "token_url": TOKEN_URL,
        "revocation_url": REVOCATION_URL, "identity_url": IDENTITY_URL}


def _canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


@dataclass(frozen=True)
class Profile:
    """Validated public configuration only; callers still need actual admission."""
    client_id: str
    redirect_uri: str
    profile: str = field(init=False, default=PROFILE)
    provider_id: str = field(init=False, default="x")
    client_auth_method: str = field(init=False, default=CLIENT_AUTH_METHOD)
    permission_preset: str = field(init=False, default=PERMISSION_PRESET)
    scopes: tuple[str, ...] = field(init=False, default=SCOPES)
    api_origins: tuple[str, ...] = field(init=False, default=API_ORIGINS)
    authorization_url: str = field(init=False, default=AUTHORIZATION_URL)
    token_url: str = field(init=False, default=TOKEN_URL)
    revocation_url: str = field(init=False, default=REVOCATION_URL)
    identity_url: str = field(init=False, default=IDENTITY_URL)
    binding_digest: str = field(init=False)

    def __post_init__(self):
        validate_client_id(self.client_id)
        _require(type(self.redirect_uri) is str and self.redirect_uri.endswith(CALLBACK_PATH))
        _public_origin(self.redirect_uri[:-len(CALLBACK_PATH)])
        raw = _canonical(_record(self.client_id, self.redirect_uri))
        _require(len(raw) <= MAX_PROFILE_BYTES)
        object.__setattr__(self, "binding_digest", "sha256:" + hashlib.sha256(raw).hexdigest())


def build_profile(*, client_id: str, public_origin: str) -> Profile:
    return Profile(client_id, _public_origin(public_origin) + CALLBACK_PATH)


def validate_profile(value: Profile) -> Profile:
    try:
        _require(type(value) is Profile)
        expected = Profile(value.client_id, value.redirect_uri)
        _require(all(type(getattr(value, item.name)) is type(getattr(expected, item.name))
            and getattr(value, item.name) == getattr(expected, item.name) for item in fields(Profile)))
        return value
    except (AttributeError, TypeError, UnicodeError):
        raise ProfileError(_ERROR) from None


def public_record(value: Profile) -> dict:
    value = validate_profile(value)
    return _record(value.client_id, value.redirect_uri)


def parse_profile(record: dict) -> Profile:
    try:
        _require(type(record) is dict)
        value = Profile(record.get("client_id"), record.get("redirect_uri"))
        _require(record == _record(value.client_id, value.redirect_uri)
            and type(record.get("scopes")) is list and type(record.get("api_origins")) is list
            and all(type(item) is str for key in ("scopes", "api_origins") for item in record[key])
            and all(type(item) is str for item in record.values() if not isinstance(item, list)))
        return value
    except (ValueError, TypeError, AttributeError, RecursionError):
        raise ProfileError(_ERROR) from None


class XOAuthApplicationInput(RevisionInput):
    """Write-only configuration input; validation alone authorizes no mutation.

    Pydantic hides input in str/repr, not in raw ValidationError.errors()/json().
    The HTTP owner must return fixed errors, never those raw diagnostics;
    internal structured diagnostics must exclude both input and context.
    """
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    operation_id: str = Field(min_length=36, max_length=36)
    client_id: str = Field(min_length=1, max_length=MAX_CLIENT_ID_BYTES)
    client_secret: str = Field(min_length=1, max_length=MAX_SECRET_BYTES, repr=False, exclude=True)
    @field_validator("operation_id")
    @classmethod
    def operation_identifier(cls, value):
        try:
            _require(str(uuid.UUID(value)) == value)
            return value
        except (ValueError, TypeError, AttributeError):
            raise ProfileError(_ERROR) from None

    _client = field_validator("client_id")(validate_client_id)
    _secret = field_validator("client_secret")(validate_client_secret)
