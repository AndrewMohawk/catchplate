"""Strict, bounded operator workspace input; no implicit grants or renewals."""
from __future__ import annotations

from typing import Annotated, Literal
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MIN_TOKEN_LIFETIME_SECONDS = 3600
MAX_TOKEN_LIFETIME_SECONDS = 90 * 24 * 3600
DEFAULT_TOKEN_LIFETIME_SECONDS = 30 * 24 * 3600
_Item = Annotated[str, Field(min_length=1, max_length=256)]
_Lifetime = Annotated[int, Field(ge=MIN_TOKEN_LIFETIME_SECONDS, le=MAX_TOKEN_LIFETIME_SECONDS)]


def _identifier(value: str) -> str:
    if str(uuid.UUID(value)) != value:
        raise ValueError("identifier must be a canonical UUID")
    return value


class RevisionInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: int = Field(ge=1, lt=9_007_199_254_740_991)
    expected_policy_hash: str = Field(min_length=71, max_length=71, pattern=r"^sha256:[0-9a-f]{64}$")


class NamedInput(RevisionInput):
    name: str = Field(min_length=1, max_length=128)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        if value != value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("invalid resource name")
        return value


class CredentialInput(NamedInput):
    auth_type: Literal["bearer", "header"]
    header_name: str | None = Field(default=None, max_length=128)
    secret: str = Field(min_length=1, max_length=8192, repr=False)

    @model_validator(mode="after")
    def static_injection(self):
        from serverware.policy_bundle import _validate_credential_injection
        if any(ord(c) < 32 or ord(c) > 126 for c in self.secret):
            raise ValueError("credential requires printable ASCII")
        if self.auth_type == "bearer":
            if self.header_name not in {None, "Authorization"}:
                raise ValueError("bearer injection uses Authorization")
            injection = {"type": "bearer", "header": "Authorization"}
        else:
            injection = {"type": "header", "name": self.header_name, "prefix": ""}
        _validate_credential_injection("operator-catalog", injection)
        return self


class ApplicationInput(NamedInput):
    token_lifetime_seconds: _Lifetime


class TargetInput(RevisionInput):
    id: str = Field(min_length=36, max_length=36)
    _canonical_id = field_validator("id")(_identifier)


class ReplaceCredentialKeyInput(TargetInput):
    expected_credential_generation: int = Field(ge=1, lt=9_007_199_254_740_991)
    secret: str = Field(min_length=1, max_length=8192, repr=False)

    @field_validator("secret")
    @classmethod
    def printable_key(cls, value: str) -> str:
        if any(ord(char) < 32 or ord(char) > 126 for char in value):
            raise ValueError("credential requires printable ASCII")
        return value


class RotateApplicationInput(TargetInput):
    token_lifetime_seconds: _Lifetime


class RuleInput(NamedInput):
    application_id: str = Field(min_length=36, max_length=36)
    credential_id: str = Field(min_length=36, max_length=36)
    upstream_url: str = Field(min_length=1, max_length=2048)
    methods: list[Literal["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]] = Field(min_length=1, max_length=6)
    request_fields: list[_Item] = Field(default_factory=list, max_length=64)
    # Absence retains the legacy request_fields/no-body contract. Explicit null
    # is not an opt-out or an alias for another body mode.
    request_body_mode: Literal["preserve_json_v1"] | None = None
    response_fields: list[_Item] = Field(default_factory=list, max_length=64)
    query_keys: list[_Item] = Field(default_factory=list, max_length=64)
    allowed_headers: list[_Item] = Field(default_factory=lambda: ["accept", "user-agent"], max_length=32)
    response_mode: Literal["projected_json", "unfiltered_json", "unfiltered_json_or_empty_v1",
        "unfiltered_json_or_empty_v2"] = "projected_json"
    credential_input: Literal["insert", "replace_exact"] = "insert"
    placeholder: str | None = Field(default=None, min_length=1, max_length=1024, repr=False)
    _canonical_ids = field_validator("application_id", "credential_id")(_identifier)

    @field_validator("methods", "request_fields", "response_fields", "query_keys", "allowed_headers")
    @classmethod
    def bounded_unique_values(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values) or any(any(ord(c) < 33 or ord(c) > 126 for c in item) for item in values):
            raise ValueError("invalid input allowlist")
        return values

    @field_validator("request_fields", "response_fields")
    @classmethod
    def field_paths(cls, values: list[str]) -> list[str]:
        from serverware.policy_bundle import RESPONSE_FIELD_PATH_RE
        if any(RESPONSE_FIELD_PATH_RE.fullmatch(item) is None for item in values):
            raise ValueError("invalid field projection")
        return values

    @model_validator(mode="after")
    def response_mode_fields(self):
        if (self.response_mode == "projected_json") != bool(self.response_fields):
            raise ValueError("projected JSON requires fields; unfiltered JSON forbids them")
        return self

    @model_validator(mode="after")
    def request_body_mode_fields(self):
        if "request_body_mode" in self.model_fields_set:
            if self.request_body_mode != "preserve_json_v1" or self.request_fields:
                raise ValueError("explicit JSON preservation requires empty request fields")
        return self

    @model_validator(mode="after")
    def credential_input_placeholder(self):
        if self.credential_input == "insert":
            if "placeholder" in self.model_fields_set:
                raise ValueError("insertion does not accept a placeholder")
        else:
            from serverware.policy_bundle import validate_credential_header_replacement
            # Validate public placeholder grammar here. The actual stored
            # credential's target is independently checked inside publication.
            validate_credential_header_replacement(
                {"mode": "replaceExact", "expectedValue": self.placeholder},
                {"type": "bearer", "header": "Authorization"})
        return self


class GmailReadAgePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    mode: Literal["unrestricted"]


class GmailReadRuleInput(NamedInput):
    """A typed operation bundle, not caller-defined URL or content authority."""
    application_id: str = Field(min_length=36, max_length=36)
    credential_id: str = Field(min_length=36, max_length=36)
    operation_bundle: Literal["gmail_read_v1"]
    age_policy: GmailReadAgePolicy = Field(default_factory=lambda: GmailReadAgePolicy(mode="unrestricted"))
    credential_input: Literal["insert", "replace_exact"] = "insert"
    placeholder: str | None = Field(default=None, min_length=1, max_length=1024, repr=False)
    _canonical_ids = field_validator("application_id", "credential_id")(_identifier)

    @model_validator(mode="after")
    def credential_input_placeholder(self):
        if self.credential_input == "insert":
            if "placeholder" in self.model_fields_set:
                raise ValueError("insertion does not accept a placeholder")
        else:
            from serverware.policy_bundle import validate_credential_header_replacement
            validate_credential_header_replacement(
                {"mode": "replaceExact", "expectedValue": self.placeholder},
                {"type": "bearer", "header": "Authorization"})
        return self
