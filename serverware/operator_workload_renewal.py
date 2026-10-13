"""Closed wire contract for explicitly enrolled, finite workload renewal.

This is ordinary operator-profile authority, not native/hardware authority.
The server receives a token verifier and an Ed25519 proof, never a token or
private key. Signature verification alone is not issuance: the transactional
owner must still check the current enrollment, generation and deadlines.
"""
from __future__ import annotations

import hashlib
import json
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from serverware.operator_catalog_inputs import RevisionInput, _identifier

SCHEMA = "serverware.workloadTokenRenewal/v1"
POLICY_SCHEMA = "serverware.proxyTokenRenewal/v1"
PUBLIC_PATH = "/v1/workload/renew"
INTERNAL_PATH = "/api/operator-demo/workloads/renew"
ENROLL_PATH = "/api/operator-demo/applications/renewal/enroll"
CANCEL_PATH = "/api/operator-demo/applications/renewal/cancel"
DOMAIN = b"serverware.workload-token-renewal/v1\x00POST /v1/workload/renew\x00"
MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 8192
REQUEST_LIFETIME_MS = 60_000
CLOCK_SKEW_MS = 5_000
OVERLAP_SECONDS = 300
MIN_TOKEN_LIFETIME_SECONDS = 3600
MAX_TOKEN_LIFETIME_SECONDS = 86400
DEFAULT_TOKEN_LIFETIME_SECONDS = 3600
MIN_ENROLLMENT_LIFETIME_SECONDS = 86400
MAX_ENROLLMENT_LIFETIME_SECONDS = 90 * 86400
DEFAULT_ENROLLMENT_LIFETIME_SECONDS = 30 * 86400
MAX_INTEGER = 9_007_199_254_740_991


def gate_descriptor() -> dict:
    return {"schema": POLICY_SCHEMA, "path": PUBLIC_PATH,
        "overlap_seconds": OVERLAP_SECONDS,
        "max_request_bytes": MAX_REQUEST_BYTES,
        "max_response_bytes": MAX_RESPONSE_BYTES}


def gate_descriptor_matches(value) -> bool:
    expected = gate_descriptor()
    return (type(value) is dict and value.keys() == expected.keys()
        and all(type(value[key]) is type(item) and value[key] == item
            for key, item in expected.items()))


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def key_fingerprint(public_key: str) -> str:
    return "sha256:" + hashlib.sha256(bytes.fromhex(public_key)).hexdigest()


class EnrollmentInput(RevisionInput):
    """Administrator-only opt-in; the client supplies only its public key."""
    id: str = Field(min_length=36, max_length=36)
    public_key: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    enrollment_lifetime_seconds: int = Field(default=DEFAULT_ENROLLMENT_LIFETIME_SECONDS,
        ge=MIN_ENROLLMENT_LIFETIME_SECONDS, le=MAX_ENROLLMENT_LIFETIME_SECONDS)
    token_lifetime_seconds: int = Field(default=DEFAULT_TOKEN_LIFETIME_SECONDS,
        ge=MIN_TOKEN_LIFETIME_SECONDS, le=MAX_TOKEN_LIFETIME_SECONDS)
    _canonical_id = field_validator("id")(_identifier)

    @model_validator(mode="after")
    def bounded_lifetime(self):
        if self.token_lifetime_seconds > self.enrollment_lifetime_seconds:
            raise ValueError("token lifetime exceeds enrollment lifetime")
        return self


class RenewalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True,
        serialize_by_alias=True)
    schema_: Literal["serverware.workloadTokenRenewal/v1"] = Field(alias="schema")
    audience: str = Field(min_length=1, max_length=512)
    application_id: str = Field(min_length=36, max_length=36)
    enrollment_id: str = Field(min_length=36, max_length=36)
    expected_token_generation: int = Field(ge=1, lt=MAX_INTEGER)
    operation_id: str = Field(min_length=36, max_length=36)
    issued_at_epoch_ms: int = Field(ge=1, le=MAX_INTEGER)
    expires_at_epoch_ms: int = Field(ge=1, le=MAX_INTEGER)
    token_sha256: str = Field(min_length=71, max_length=71, pattern=r"^sha256:[0-9a-f]{64}$")
    token_expires_at_epoch_ms: int = Field(ge=1, le=MAX_INTEGER)
    signature: str = Field(min_length=128, max_length=128, pattern=r"^[0-9a-f]{128}$", repr=False)
    _canonical_ids = field_validator("application_id", "enrollment_id", "operation_id")(_identifier)

    @model_validator(mode="after")
    def bounded_request(self):
        if not 0 < self.expires_at_epoch_ms - self.issued_at_epoch_ms <= REQUEST_LIFETIME_MS:
            raise ValueError("renewal request lifetime refused")
        if self.token_expires_at_epoch_ms <= self.issued_at_epoch_ms:
            raise ValueError("renewal token lifetime refused")
        return self

    def signed_fields(self) -> dict:
        return self.model_dump(exclude={"signature"}, by_alias=True)

    def signing_bytes(self) -> bytes:
        return DOMAIN + canonical(self.signed_fields())

    def request_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.signing_bytes()).hexdigest()

    def verify(self, public_key: str, audience: str) -> None:
        if self.audience != audience:
            raise ValueError("renewal proof refused")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(
                bytes.fromhex(self.signature), self.signing_bytes())
        except (InvalidSignature, ValueError, TypeError):
            raise ValueError("renewal proof refused") from None

    def check_fresh(self, now_epoch_ms: int) -> None:
        if self.issued_at_epoch_ms > now_epoch_ms + CLOCK_SKEW_MS or now_epoch_ms >= self.expires_at_epoch_ms:
            raise ValueError("renewal request expired or not yet valid")
