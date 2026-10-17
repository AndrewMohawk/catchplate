"""Recognize stored AWS tuples before generic credential handling.

This marker is not authority or validation. Any matching marker is enough to
exclude a record from legacy secret injection/release, including contradictory
records. The catalog owner separately validates the complete retained binding.
No AWS dispatch path is enabled by storing this credential type.
"""
from __future__ import annotations

KIND = "aws_sigv4_v1"
SECRET_CLASS = "awsSigV4"


def selected(kind, metadata=None) -> bool:
    return kind == KIND or isinstance(metadata, dict) and (
        metadata.get("connection_type") == KIND
        or metadata.get("secret_class") == SECRET_CLASS
    )


def credential_selected(credential: dict) -> bool:
    return selected(credential.get("kind"), credential.get("metadata"))
