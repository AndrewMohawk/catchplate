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


class GithubTokenInput(NamedInput):
    secret: str = Field(min_length=1, max_length=8192, repr=False)

    @field_validator("secret")
    @classmethod
    def opaque_token(cls, value: str) -> str:
        from serverware.operator_catalog_github import validate_token
        return validate_token(value)


class XAppBearerInput(NamedInput):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    secret: str = Field(min_length=1, max_length=8192, repr=False)

    @field_validator("secret")
    @classmethod
    def opaque_token(cls, value: str) -> str:
        from serverware.operator_catalog_x import validate_token
        return validate_token(value)


class XUsernameRuleInput(NamedInput):
    application_id: str = Field(min_length=36, max_length=36)
    credential_id: str = Field(min_length=36, max_length=36)
    operation_bundle: Literal["x_username_read_v1"]
    username: str = Field(min_length=1, max_length=15)
    _canonical_ids = field_validator("application_id", "credential_id")(_identifier)

    @field_validator("username")
    @classmethod
    def exact_username(cls, value: str) -> str:
        from serverware.x_app_read import validate_username
        return validate_username(value)


class XPostRuleInput(NamedInput):
    """One fixed posting permission, optionally limited per verified account."""
    application_id: str = Field(min_length=36, max_length=36)
    credential_id: str = Field(min_length=36, max_length=36)
    operation_bundle: Literal["x_text_post_v1"]
    daily_post_attempt_limit: int | None = Field(default=None, ge=1, le=1_000_000_000)
    _canonical_ids = field_validator("application_id", "credential_id")(_identifier)

    @field_validator("daily_post_attempt_limit", mode="before")
    @classmethod
    def explicit_attempt_limit(cls, value):
        # Omission retains the old unbounded contract; null is not a limit.
        if type(value) is not int:
            raise ValueError("daily posting-attempt limit must be an integer")
        return value


class AlchemyKeyInput(NamedInput):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    secret: str = Field(min_length=1, max_length=8192, repr=False)

    @field_validator("secret")
    @classmethod
    def opaque_token(cls, value: str) -> str:
        from serverware.operator_catalog_alchemy import validate_token
        return validate_token(value)


class AlchemyChainStatusRuleInput(NamedInput):
    application_id: str = Field(min_length=36, max_length=36)
    credential_id: str = Field(min_length=36, max_length=36)
    operation_bundle: Literal["alchemy_chain_status_read_v1"]
    chain: Literal["eth-mainnet", "eth-sepolia"]
    _canonical_ids = field_validator("application_id", "credential_id")(_identifier)


class NpmTokenInput(NamedInput):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    secret: str = Field(min_length=1, max_length=8192, repr=False)

    @field_validator("secret")
    @classmethod
    def opaque_token(cls, value: str) -> str:
        from serverware.operator_catalog_npm import validate_token
        return validate_token(value)


class NpmMetadataRuleInput(NamedInput):
    application_id: str = Field(min_length=36, max_length=36)
    credential_id: str = Field(min_length=36, max_length=36)
    operation_bundle: Literal["npm_metadata_read_v1"]
    packages: list[Annotated[str, Field(min_length=1, max_length=214)]] = Field(min_length=1, max_length=64)
    _canonical_ids = field_validator("application_id", "credential_id")(_identifier)

    @field_validator("packages")
    @classmethod
    def exact_packages(cls, value: list[str]) -> list[str]:
        from serverware.npm_metadata import validate_packages
        return validate_packages(value)


class NpmInstallRuleInput(NpmMetadataRuleInput):
    operation_bundle: Literal["npm_install_v1"]


class NpmPublishingWindow(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    start: str = Field(min_length=5, max_length=5)
    end: str = Field(min_length=5, max_length=5)

    @model_validator(mode="after")
    def daily_utc_window(self):
        from serverware.npm_publish import validate_window
        validate_window({"timezone": "UTC", "start": self.start, "end": self.end})
        return self


class NpmPublishRuleInput(NamedInput):
    application_id: str = Field(min_length=36, max_length=36)
    credential_id: str = Field(min_length=36, max_length=36)
    operation_bundle: Literal["npm_publish_v1"]
    package: str = Field(min_length=1, max_length=214)
    tag: str = Field(default="latest", min_length=1, max_length=64)
    publishing_window: NpmPublishingWindow | None = None
    _canonical_ids = field_validator("application_id", "credential_id")(_identifier)

    @field_validator("package")
    @classmethod
    def exact_package(cls, value: str) -> str:
        from serverware.npm_publish import validate_package
        return validate_package(value)

    @field_validator("tag")
    @classmethod
    def exact_tag(cls, value: str) -> str:
        from serverware.npm_publish import validate_tag
        return validate_tag(value)


class GithubRepositoryInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    owner: str = Field(min_length=1, max_length=39)
    name: str = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def named_repository(self):
        from serverware.github_issues import validate_repository
        validate_repository(self.model_dump())
        return self


class GithubAppInput(NamedInput):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    app_id: str = Field(min_length=1, max_length=16)
    installation_id: str | None = Field(default=None, min_length=1, max_length=16)
    private_key_pem: str = Field(min_length=1, max_length=8192, repr=False)
    repository: GithubRepositoryInput
    issues_permission: Literal["read", "write"]

    @field_validator("app_id", "installation_id")
    @classmethod
    def numeric_identity(cls, value: str | None) -> str | None:
        from serverware.operator_github_app import identifier
        if value is not None:
            identifier(value)
        return value

    @field_validator("private_key_pem")
    @classmethod
    def rsa_key(cls, value: str) -> str:
        from serverware.github_app import load_private_key
        if len(value.encode("utf-8")) > 8192:
            raise ValueError("GitHub App key refused")
        load_private_key(value.encode("utf-8"))
        return value


class GithubRuleInput(NamedInput):
    application_id: str = Field(min_length=36, max_length=36)
    credential_id: str = Field(min_length=36, max_length=36)
    operation_bundle: Literal["github_issues_read_v1", "github_issues_write_v1"]
    repository: GithubRepositoryInput
    _canonical_ids = field_validator("application_id", "credential_id")(_identifier)


class ApplicationInput(NamedInput):
    token_lifetime_seconds: _Lifetime
    # Old callers retain Bearer; new clients must select the broader transport.
    proxy_authentication: Literal["bearer", "basic_and_bearer_v1"] = "bearer"


class TargetInput(RevisionInput):
    id: str = Field(min_length=36, max_length=36)
    _canonical_id = field_validator("id")(_identifier)


class ReplaceGithubAppKeyInput(TargetInput):
    """Write-only candidate key; no saved App/repository binding is editable."""
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    expected_credential_generation: int = Field(ge=1, lt=9_007_199_254_740_991)
    private_key_pem: str = Field(min_length=1, max_length=8192, repr=False, exclude=True)

    @field_validator("private_key_pem")
    @classmethod
    def rsa_key(cls, value: str) -> str:
        return GithubAppInput.rsa_key(value)


class _AwsSigV4TupleInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    credential_kind: Literal["long_term", "session"]
    access_key_id: str = Field(min_length=20, max_length=20, repr=False)
    secret_access_key: str = Field(min_length=40, max_length=40, repr=False)
    session_token: str | None = Field(min_length=1, max_length=8192, repr=False)
    expires_at: str | None = Field(min_length=20, max_length=20)

    @model_validator(mode="after")
    def complete_tuple(self):
        from serverware.operator_catalog_aws import TUPLE_FIELDS, validate_tuple
        validate_tuple({key: getattr(self, key) for key in TUPLE_FIELDS})
        return self


class AwsSigV4CredentialInput(NamedInput, _AwsSigV4TupleInput):
    """Explicit whole tuple, never a generic bearer/header secret."""


class ReplaceAwsSigV4CredentialInput(TargetInput, _AwsSigV4TupleInput):
    expected_credential_generation: int = Field(ge=1, lt=9_007_199_254_740_991)


class GoogleDisconnectInput(TargetInput):
    """Explicit review of local impact and Google's wider revocation boundary."""
    confirmed_affected_rule_ids: list[Annotated[str, Field(min_length=36, max_length=36)]] = Field(max_length=64)
    acknowledge_project_wide_revocation: bool

    @field_validator("confirmed_affected_rule_ids")
    @classmethod
    def exact_reviewed_rules(cls, values: list[str]) -> list[str]:
        if values != sorted(set(values)):
            raise ValueError("affected rules must be unique and sorted")
        for value in values:
            _identifier(value)
        return values

    @field_validator("acknowledge_project_wide_revocation")
    @classmethod
    def explicit_acknowledgement(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("Google project-wide revocation acknowledgement required")
        return value


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


class ApplicationProxyAuthenticationInput(TargetInput):
    proxy_authentication: Literal["bearer", "basic_and_bearer_v1"]


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
