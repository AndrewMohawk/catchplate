"""Private Setup issuance data, not Setup ownership or execution permission.

Only scalar validation, fresh entropy and provider byte encodings are shared
with unbound issuance. No old signed statement, policy, receipt, encrypted
original or custody owner is converted into this purpose.
"""
from __future__ import annotations

from serverware import native_oauth_exchange as exchange
from serverware import native_oauth_refresh as material

INTENT_SCHEMA = "serverware.nativeOAuthExchangeIntent/v2"
STATE_SCHEMA = "serverware.nativeOAuthExchangeState/v2"
INTENT_FIELDS = exchange.INTENT_FIELDS | {"setupBinding"}
STATE_FIELDS = exchange.STATE_FIELDS | {"setupBinding"}
BINDING_FIELDS = frozenset({"sessionId", "revision", "rowSha256", "ownerId",
    "currentAssigneeId", "expiresAtEpochNs"})
# Three real transitions and the initial event sequence must fit SQL int8.
MAX_BINDING_REVISION = 9_223_372_036_854_775_803
RESERVED_METADATA = frozenset({"setup_session_id", "setupSessionId", "reconnect",
    "reconnect_credential_id", "reconnect_credential_version"})


def binding(value):
    material.require(type(value) is dict and set(value) == BINDING_FIELDS)
    exchange.identifier(value["sessionId"])
    material.digest(value["rowSha256"])
    material.integer(value["revision"], minimum=0, maximum=MAX_BINDING_REVISION)
    exchange.text(value["ownerId"], 512)
    if value["currentAssigneeId"] is not None:
        exchange.text(value["currentAssigneeId"], 512)
    material.integer(value["expiresAtEpochNs"])
    return dict(value)


def _requester(value, bound):
    material.require(type(value) is str and value.startswith("oidc:")
        and value == bound["ownerId"]
        and bound["currentAssigneeId"] in {None, value})


def intent(value):
    material.require(type(value) is dict and set(value) == INTENT_FIELDS
        and value["schema"] == INTENT_SCHEMA)
    # Validate a data projection only. The old public intent remains closed v1;
    # the actual Setup consent signs the unchanged v2 original and binding.
    scalar = {name: value[name] for name in exchange.INTENT_FIELDS}
    scalar["schema"] = exchange.INTENT_SCHEMA
    exchange.intent(scalar)
    bound = binding(value["setupBinding"])
    _requester(value["requesterId"], bound)
    material.require(not set(value["metadata"]) & RESERVED_METADATA)
    return value


def private_state(raw):
    state = material.document(raw, exchange.MAX_STATE)
    material.require(set(state) == STATE_FIELDS and state["schema"] == STATE_SCHEMA)
    bound = binding(state["setupBinding"])
    _requester(state["requesterId"], bound)
    scalar = {name: state[name] for name in exchange.STATE_FIELDS}
    scalar["schema"] = exchange.STATE_SCHEMA
    exchange.private_state(material.canonical(scalar))
    for name in ("issuedAtEpochNs", "contactExpiresAtEpochNs",
            "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs"):
        material.integer(state[name])
    material.require(state["issuedAtEpochNs"] < state["contactExpiresAtEpochNs"]
        <= state["retentionExpiresAtEpochNs"] <= state["pendingExpiresAtEpochNs"]
        <= bound["expiresAtEpochNs"]
        and type(state["metadata"]) is dict
        and not set(state["metadata"]) & RESERVED_METADATA)
    return state


def prepare(intent_value, *, enrollment_original, callback_origin, portal_origin,
        limits, issued_ns, contact_expires_ns, retention_expires_ns, pending_expires_ns):
    """Make a fresh private draft; only a later genuine receipt admits Setup."""
    value = intent(intent_value)
    bound = binding(value["setupBinding"])
    for epoch in (issued_ns, contact_expires_ns, retention_expires_ns, pending_expires_ns):
        material.integer(epoch)
    # The caller's original windows can only narrow; expiry is never renewed.
    end = bound["expiresAtEpochNs"]
    contact = min(contact_expires_ns, end)
    retention = min(retention_expires_ns, end)
    pending = min(pending_expires_ns, end)
    material.require(issued_ns < contact <= retention <= pending)
    scalar = {name: value[name] for name in exchange.INTENT_FIELDS}
    scalar["schema"] = exchange.INTENT_SCHEMA
    fresh, nonce = exchange.prepare(scalar, enrollment_original=enrollment_original,
        callback_origin=callback_origin, portal_origin=portal_origin, limits=limits,
        issued_ns=issued_ns, contact_expires_ns=contact,
        retention_expires_ns=retention, pending_expires_ns=pending)
    # This newly generated, not-yet-sealed data never had any signed authority.
    state = exchange.private_state(fresh)
    state["schema"], state["setupBinding"] = STATE_SCHEMA, bound
    raw = material.canonical(state)
    private_state(raw)
    return raw, nonce
