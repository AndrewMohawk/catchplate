from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utcnow().isoformat()


def dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    return json.loads(value)


def audit_hash(
    *,
    event_id: str,
    event_type: str,
    actor_type: str,
    actor_id: str | None,
    event_json: str,
    prev_event_hash: str | None,
    created_at: str,
) -> str:
    """Existing audit-record commitment, independent of runtime configuration."""
    payload = dumps(
        {
            "id": event_id,
            "event_type": event_type,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "event_json": event_json,
            "prev_event_hash": prev_event_hash,
            "created_at": created_at,
        }
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


for _compatibility_export in (utcnow, iso_now, dumps, loads):
    _compatibility_export.__module__ = "serverware.db"
del _compatibility_export
