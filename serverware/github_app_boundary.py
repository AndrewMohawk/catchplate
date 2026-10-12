"""Exclude GitHub App private configuration from generic secret consumers.

Recognition is a refusal boundary, not validation or GitHub authority. Only the
dedicated operator owner may open App material and derive installation tokens.
This leaf deliberately has no configuration, protocol, database or network imports.
"""
from __future__ import annotations

import json
import re

CONNECTION = "github_app_v1"
SECRET_SCHEMA = "serverware.githubAppCredential/v1"
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
_JSON_STRING = re.compile(r'"(?:[^"\\\x00-\x1f]|\\.)*"')


def selected(kind, metadata=None) -> bool:
    # The reserved key denies even null, malformed or contradictory bindings.
    return kind == CONNECTION or isinstance(metadata, dict) and (
        metadata.get("connection_type") == CONNECTION or "github_app" in metadata
    )


def secret_selected(secret) -> bool:
    """Recognize reserved plaintext even when retained metadata was stripped.

    Inspect every JSON string literal independently so duplicate keys, escaped
    spellings and an otherwise malformed document cannot hide the discriminator.
    Ordinary JSON bearer/OAuth values are not refused merely for being JSON.
    """
    if isinstance(secret, bytes):
        try:
            secret = secret.decode("utf-8")
        except UnicodeDecodeError:
            return False
    if not isinstance(secret, str):
        return False
    if SECRET_SCHEMA in secret or _PRIVATE_KEY.search(secret):
        return True
    for match in _JSON_STRING.finditer(secret):
        try:
            value = json.loads(match.group())
        except (ValueError, RecursionError):
            continue
        if SECRET_SCHEMA in value or _PRIVATE_KEY.search(value):
            return True
    return False


def credential_selected(credential: dict) -> bool:
    return selected(credential.get("kind"), credential.get("metadata")) or secret_selected(
        credential.get("secret")
    )
