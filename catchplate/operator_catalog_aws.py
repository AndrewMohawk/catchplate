"""Storage-only AWS tuples: no signing, account verification, grants or renewal.

Only the encrypted credential envelope contains the complete tuple. Catalog and
core metadata retain a random local subject and nonsecret kind/expiry, never an
access key identifier. Expiration is observed, not repaired or extended.
"""
from __future__ import annotations

import json
import time
import uuid

from catchplate import aws_credential_boundary as boundary, aws_ecr_signing as signing
from catchplate.operator_catalog_schema import CatalogIntegrityError

CONNECTION = KIND = boundary.KIND
SECRET_CLASS = boundary.SECRET_CLASS
SECRET_SCHEMA = "catchplate.awsSigV4Credentials/v1"
TUPLE_FIELDS = ("credential_kind", "access_key_id", "secret_access_key", "session_token", "expires_at")
_METADATA_FIELDS = frozenset({"provider_id", "provider_subject", "secret_class",
    "connection_type", "credential_kind", "expires_at"})
_RECORD_FIELDS = frozenset({"id", "ordinal", "version", "name", "created_at", "status",
    "revoked_at", "key_replaced_at", "auth_type", "header_name", "connection_type",
    "provider_subject", "credential_kind", "expires_at"})


def selected(record: dict) -> bool:
    return boundary.selected(record.get("auth_type"), record)


def _canonical(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def validate_tuple(value: dict, *, require_future: bool = True) -> dict:
    """The signer's explicit syntax, with only a storage-time future check."""
    try:
        if type(value) is not dict or set(value) != set(TUPLE_FIELDS):
            raise ValueError()
        signing.Credentials(kind=value["credential_kind"], access_key_id=value["access_key_id"],
            secret_access_key=value["secret_access_key"], session_token=value["session_token"],
            expires_at=value["expires_at"])
        if require_future and value["credential_kind"] == "session":
            now = time.time_ns()
            if type(now) is not int or now < 0 or signing._expiry_seconds(value["expires_at"]) * 1_000_000_000 <= now:
                raise ValueError()
        return dict(value)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ValueError("AWS credential tuple refused") from None


def encode_secret(payload) -> str:
    value = validate_tuple({key: getattr(payload, key) for key in TUPLE_FIELDS})
    return _canonical({"schema": SECRET_SCHEMA, **value})


def validate_secret(secret: str, *, require_future: bool = True) -> dict:
    try:
        if type(secret) is not str or not 1 <= len(secret) <= 32768:
            raise ValueError()
        value = json.loads(secret)
        if (type(value) is not dict or set(value) != {"schema", *TUPLE_FIELDS}
                or value["schema"] != SECRET_SCHEMA or _canonical(value) != secret):
            raise ValueError()
        return validate_tuple({key: value[key] for key in TUPLE_FIELDS}, require_future=require_future)
    except (KeyError, TypeError, ValueError, RecursionError):
        raise ValueError("AWS credential tuple refused") from None


def metadata_from_secret(secret: str, subject: str) -> dict:
    value = validate_secret(secret)
    if type(subject) is not str or str(uuid.UUID(subject)) != subject:
        raise ValueError("AWS credential subject refused")
    return {"provider_id": "operator-demo", "provider_subject": subject,
        "secret_class": SECRET_CLASS, "connection_type": CONNECTION,
        "credential_kind": value["credential_kind"], "expires_at": value["expires_at"]}


def _public_expiry(kind, expiry) -> int | None:
    if kind == "long_term" and expiry is None:
        return None
    if kind == "session":
        return signing._expiry_seconds(expiry)
    raise ValueError()


def validate_credential(record: dict, metadata: dict | None = None) -> bool:
    try:
        if (type(record) is not dict or set(record) - _RECORD_FIELDS
                or record.get("auth_type") != KIND or record.get("connection_type") != CONNECTION
                or "header_name" not in record or record["header_name"] is not None
                or type(record.get("provider_subject")) is not str
                or str(uuid.UUID(record["provider_subject"])) != record["provider_subject"]):
            raise ValueError()
        _public_expiry(record["credential_kind"], record["expires_at"])
        if metadata is not None and (type(metadata) is not dict or set(metadata) != _METADATA_FIELDS
                or metadata["provider_id"] != "operator-demo" or metadata["secret_class"] != SECRET_CLASS
                or metadata["connection_type"] != CONNECTION
                or any(metadata[key] != record[key] for key in
                    ("provider_subject", "credential_kind", "expires_at"))):
            raise ValueError()
    except (KeyError, TypeError, ValueError, AttributeError):
        raise CatalogIntegrityError("catalog AWS credential binding refused") from None
    return True


def public_fields(record: dict, now_epoch_ms: int) -> dict:
    validate_credential(record)
    expiry = _public_expiry(record["credential_kind"], record["expires_at"])
    return {"credential_kind": record["credential_kind"], "expires_at": record["expires_at"],
        "expired": expiry is not None and now_epoch_ms >= expiry * 1000, "signing_available": False}


def capability() -> dict:
    return {"schema": "catchplate.operatorAwsCredentials/v1", "connection_type": CONNECTION,
        "create_path": "/api/operator-demo/credentials/aws-sigv4",
        "replace_path": "/api/operator-demo/credentials/aws-sigv4/replace",
        "revoke_path": "/api/operator-demo/credentials/revoke",
        "credential_kinds": ["long_term", "session"], "signing_available": False,
        "automatic_renewal": False}
