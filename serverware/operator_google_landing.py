"""Fixed, token-free navigation after a trusted operator Google callback.

These helpers do not validate OAuth or confer account access. Callers supply
only server-owned records after state consumption or successful registration;
the workspace must still reconcile the actor's intent with its current catalog.
"""
from __future__ import annotations

import re


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_PREFIX = "/?operator_google_intent="
_SUFFIX = "#connect"
FALLBACK = "/#connect"


def intent_target(identifier: object) -> str:
    if isinstance(identifier, str) and _UUID.fullmatch(identifier):
        return _PREFIX + identifier + _SUFFIX
    return FALLBACK


def success_target(exchanged: dict, *, setup_session=None) -> str | None:
    """Use only the validated exchange claim, never callback query parameters."""
    if (exchanged.get("provider") != "google" or setup_session is not None
            or exchanged.get("setupSessionId") is not None):
        return None
    claim = exchanged.get("_operator_catalog_intent")
    if claim is None:
        return None
    return intent_target(claim.get("id") if isinstance(claim, dict) else None)


def denial_target(consumed_state: dict) -> str | None:
    """Use only the retained record returned by successful browser-bound consumption."""
    if consumed_state.get("provider") != "google" or consumed_state.get("setup_session_id") is not None:
        return None
    identifier = consumed_state.get("operator_catalog_intent_id")
    return None if identifier is None else intent_target(identifier)


def return_link(target: str | None) -> str:
    if target is None:
        return ""
    if target != FALLBACK:
        if (not target.startswith(_PREFIX) or not target.endswith(_SUFFIX)
                or intent_target(target[len(_PREFIX):-len(_SUFFIX)]) != target):
            raise ValueError("operator Google return target is invalid")
    # The closed relative-path grammar contains no HTML-significant characters.
    return '<p><a href="' + target + '">Return to Connect</a></p>'
