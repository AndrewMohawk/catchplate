from __future__ import annotations

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


for _compatibility_export in (utcnow, iso_now, dumps, loads):
    _compatibility_export.__module__ = "serverware.db"
del _compatibility_export
