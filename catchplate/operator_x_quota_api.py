"""Ordinary, request-bound X posting leases and irreversible one-use claims.

This is not native request authority. The existing control-plane response signer
authenticates the entire response, and the existing recipient envelope encrypts
the secret. Neither a reservation nor a lease alone permits a provider send.
The Rust request owner must consume the signed claim once, without retrying an
unknown acknowledgement. This module performs no provider I/O or initialization.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
import uuid
from types import SimpleNamespace

from fastapi import HTTPException

REQUEST_VERSION = "catchplate.operatorXQuotaCredentialLeaseRequest/v1"
RESPONSE_VERSION = "catchplate.operatorXQuotaCredentialLeaseResponse/v1"
CLAIM_REQUEST_VERSION = "catchplate.operatorXQuotaClaimRequest/v1"
CLAIM_RESPONSE_VERSION = "catchplate.operatorXQuotaClaimResponse/v1"
CLAIM_PATH = "/api/data-plane/operator-x-quota/claim"
MAX_REQUEST_BYTES = 32 * 1024
WIRE_FIELDS = frozenset({"apiVersion", "purpose", "principalId", "routeId", "credentialId",
    "expectedCredentialVersion", "expectedMetadataSha256", "recipientPublicKey", "recipientKeyId",
    "recipientNonce", "policyHash", "dataPlaneBinaryDigest", "maxTtlSeconds", "operatorXQuota"})
QUOTA_FIELDS = frozenset({"canonicalRequest", "requestDigest", "operationDigest", "attemptNonce", "expiresAtEpochMs"})
UNCONTROLLED = {"controlled": False, "issuanceKind": None, "requestAuthority": None,
    "requestAuthoritySha256": None, "releaseAuthorization": None}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _need(value):
    if not value:
        raise ValueError("ordinary X quota request is unavailable")


def _sha(value):
    _need(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value))


def validate_wire(wire):
    """Closed, bounded original; current identity is joined separately in SQL."""
    _need(type(wire) is dict and set(wire) == WIRE_FIELDS
        and wire["apiVersion"] == REQUEST_VERSION and wire["purpose"] == "dispatchSecret")
    _need(len(canonical(wire)) <= MAX_REQUEST_BYTES)
    for field in ("principalId", "routeId", "credentialId"):
        value = wire[field]
        _need(type(value) is str and 0 < len(value.encode("utf-8")) <= 256
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    _need(type(wire["expectedCredentialVersion"]) is int and 1 <= wire["expectedCredentialVersion"] < 2**64
        and type(wire["maxTtlSeconds"]) is int and 1 <= wire["maxTtlSeconds"] <= 5)
    for field in ("expectedMetadataSha256", "recipientKeyId", "policyHash", "dataPlaneBinaryDigest"):
        _sha(wire[field])
    for field in ("recipientPublicKey", "recipientNonce"):
        _need(type(wire[field]) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", wire[field]))
    quota = wire["operatorXQuota"]
    _need(type(quota) is dict and set(quota) == QUOTA_FIELDS)
    for field in ("requestDigest", "operationDigest", "attemptNonce"):
        _sha(quota[field])
    _need(type(quota["expiresAtEpochMs"]) is int and 0 < quota["expiresAtEpochMs"] < 2**63)
    original = quota["canonicalRequest"]
    _need(type(original) is dict and set(original) == {"v", "principal", "client_ip", "route_id",
        "credential_ref", "credential_version", "policy_hash", "request", "operation"}
        and type(original["v"]) is int and original["v"] == 2
        and original["principal"] == wire["principalId"] and original["route_id"] == wire["routeId"]
        and original["credential_ref"] == wire["credentialId"]
        and original["credential_version"] == str(wire["expectedCredentialVersion"])
        and original["policy_hash"] == wire["policyHash"]
        and (original["client_ip"] is None or type(original["client_ip"]) is str and len(original["client_ip"]) <= 64))
    request, operation = original["request"], original["operation"]
    _need(type(request) is dict and set(request) == {"method", "scheme", "authority", "path", "query",
        "headers", "body_sha256", "discard_headers"}
        and request["method"] == "POST" and request["scheme"] == "https"
        and request["authority"] == "api.x.com" and request["path"] == "/2/tweets"
        and request["query"] == [] and request["discard_headers"] == ["accept-encoding"])
    _sha(request["body_sha256"])
    headers = request["headers"]
    _need(type(headers) is dict and len(headers) <= 16
        and all(type(k) is str and type(v) is str and k == k.lower()
            and len(k) <= 64 and len(v.encode("utf-8")) <= 8192
            and not any(c in v for c in "\r\n\0") for k, v in headers.items()))
    _need(type(operation) is dict and set(operation) == {"operation", "providerAccount"}
        and operation["operation"] == "tweets.write")
    _sha(operation["providerAccount"])
    _need(digest(original) == quota["requestDigest"]
        and digest({k: v for k, v in original.items() if k not in {"v", "client_ip"}}) == quota["operationDigest"])
    return wire


def binding(wire):
    validate_wire(wire)
    quota = wire["operatorXQuota"]
    return {"principal_id": wire["principalId"], "route_id": wire["routeId"], "credential_id": wire["credentialId"],
        "credential_version": wire["expectedCredentialVersion"], "credential_metadata_digest": wire["expectedMetadataSha256"],
        "policy_hash": wire["policyHash"], "request_digest": quota["requestDigest"],
        "operation_digest": quota["operationDigest"], "attempt_nonce": quota["attemptNonce"],
        "recipient_digest": digest({key: wire[key] for key in ("recipientKeyId", "recipientNonce")}),
        "request_binding_digest": digest(wire), "expires_at_epoch_ms": quota["expiresAtEpochMs"]}


def require_route(route):
    from catchplate import x_post
    x_post.validate_route(route)
    quotas = [row for row in route.constraints if row.get("type") == "rateLimit"]
    _need(len(quotas) == 1 and quotas[0] == x_post.quota_constraint(quotas[0].get("max"))
        and not route.jit)
    return dict(UNCONTROLLED)


def _payload(wire):
    # Only used after validate_wire; no public caller can supply an admitted
    # identity through this convenience projection.
    return SimpleNamespace(api_version=REQUEST_VERSION, principal_id=wire["principalId"],
        route_id=wire["routeId"], credential_id=wire["credentialId"], policy_hash=wire["policyHash"])


def _current(conn, wire):
    from catchplate import app, operator_x_account_store as accounts
    from catchplate import operator_catalog_x_oauth as catalog
    _need(app.EXPECTED_DATA_PLANE_BINARY_DIGEST == wire["dataPlaneBinaryDigest"])
    snapshot = app.get_policy_snapshot()
    _need(snapshot is not None and snapshot.hash == wire["policyHash"])
    payload = _payload(wire)
    policy = app._assert_credential_lease_route_binding(payload, snapshot)
    route = app._active_route_by_id(payload.route_id, snapshot=snapshot)
    require_route(route)
    core = accounts.current(conn, payload.credential_id)["credential"]
    _need(core["metadata"]["expires_at_epoch_ms"] >= wire["operatorXQuota"]["expiresAtEpochMs"])
    app._assert_credential_policy_binding(core, policy)
    app._assert_credential_injection_binding(core, policy)
    app._assert_route_credential_binding(route, core, policy)
    public = catalog.require_lease_binding(conn, principal_id=payload.principal_id,
        route_id=payload.route_id, credential_id=payload.credential_id, core_credential=core)
    account = "sha256:" + hashlib.sha256(b"x\0" + public["provider_subject"].encode("ascii")).hexdigest()
    _need(wire["operatorXQuota"]["canonicalRequest"]["operation"]["providerAccount"] == account)


def prepare_metadata(payload, route, *, original_deadline):
    """Refresh only before canonicalization on the existing metadata request.

    No quota is reserved here. The subsequent dispatch cannot repeat refresh
    or reconcile a newer generation. All old unbounded/native paths are inert.
    """
    from catchplate import db, operator_x_refresh as refresh
    if (payload.api_version != "catchplate.credentialLeaseRequest/v3"
            or payload.purpose != "generationMetadata" or route.adapter_type != "x.post.v1"
            or not any(row.get("type") == "rateLimit" for row in route.constraints)):
        return
    public = db.get_credential(payload.credential_id, include_secret=False)
    if public is None or not refresh.selected(public):
        return
    from catchplate import operator_publication as publication, operator_x_admission as admission
    from catchplate import operator_x_quota as store, operator_catalog_x_oauth as catalog
    require_route(route)
    _need(type(original_deadline) is float and time.monotonic() < original_deadline)
    directory = admission.require_runtime()
    with publication.exclusive(), db.metadata_connection() as conn:
        conn.execute("BEGIN")
        admission.check_connection(conn, directory)
        store.require_ready(conn)
        row = conn.execute("SELECT * FROM credentials WHERE id=?", (payload.credential_id,)).fetchone()
        _need(row is not None)
        core = db.row_to_credential(row)
        _need(refresh.selected(core))
        catalog.require_lease_binding(conn, principal_id=payload.principal_id, route_id=payload.route_id,
            credential_id=payload.credential_id, core_credential=core)
        current_policy = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()
        _need(current_policy is not None and current_policy[0] == payload.policy_hash)
        version = core["credential_version"]
    publication.assert_not_held()
    _need(time.monotonic() < original_deadline)
    refresh.prepare_for_lease(payload.credential_id, version, principal_id=payload.principal_id,
        route_id=payload.route_id, policy_hash=payload.policy_hash, deadline=original_deadline)
    _need(time.monotonic() < original_deadline)


def _transaction(wire, operation, *, reservation_id=None, deadline):
    from catchplate import db, operator_publication as publication
    from catchplate import operator_x_admission as admission, operator_x_quota as store
    try:
        pins = binding(wire)
        _need(math.isfinite(deadline) and time.monotonic() < deadline)
        directory = admission.require_runtime()
        publication.assert_not_held()
        with publication.exclusive(), db.metadata_connection() as conn:
            conn.execute("BEGIN IMMEDIATE" if operation != "check" else "BEGIN")
            admission.check_connection(conn, directory)
            _need(time.monotonic() < deadline)
            _current(conn, wire)
            store.validate_current(conn, pins)
            _need(time.monotonic() < deadline)
            if operation == "reserve":
                result = store.reserve(conn, pins)
            elif operation == "claim":
                result = store.claim(conn, pins, reservation_id)
            else:
                result = None
            admission.check_connection(conn, directory)
            _need(time.monotonic() < deadline)
            conn.commit()
        # A deadline crossing after commit loses the response; never undo the
        # durable claim or automatically attempt it again.
        _need(time.monotonic() < deadline)
        return result
    except store.QuotaExceeded:
        raise HTTPException(status_code=429, detail="X posting-attempt quota exhausted") from None
    except store.QuotaConflict:
        raise HTTPException(status_code=409, detail="X posting-attempt quota claim unavailable") from None
    except Exception:
        raise HTTPException(status_code=503, detail="X posting-attempt quota unavailable") from None


class Opening:
    """One actual lease request; never a deserialized dispatch permission."""
    def __init__(self, request, payload, *, original_deadline):
        from catchplate import app
        app._require_currentness_response_context(request, "/api/data-plane/credential-leases")
        original = app._original_data_plane_request(request, app._CREDENTIAL_LEASE_ORIGINAL_SCOPE_KEY, payload)
        self.wire = json.loads(canonical(validate_wire(original)))
        _need(request.headers.get("x-catchplate-response-nonce") == payload.recipient_nonce)
        now = time.time_ns() // 1_000_000
        remaining = self.wire["operatorXQuota"]["expiresAtEpochMs"] - now
        _need(type(original_deadline) is float and 0 < remaining <= min(payload.max_ttl_seconds * 1000,
            app.SECRET_LEASE_TTL_SECONDS * 1000, 5000))
        self.deadline = min(original_deadline, time.monotonic() + remaining / 1000)
        self.reservation = None
        _transaction(self.wire, "check", deadline=self.deadline)

    def reserve(self):
        _need(self.reservation is None)
        self.reservation = _transaction(self.wire, "reserve", deadline=self.deadline)
        return self.reservation["expires_at_epoch_ms"]

    def wrap(self, envelope):
        _need(self.reservation is not None and envelope["expiresAtEpochMs"] == self.reservation["expires_at_epoch_ms"])
        return {"apiVersion": RESPONSE_VERSION, "requestBindingSha256": digest(self.wire),
            "reservation": self.reservation, "credentialLease": envelope}

    def check(self):
        _need(self.reservation is not None)
        _transaction(self.wire, "check", deadline=self.deadline)


def claim(original):
    _need(type(original) is dict and set(original) == {"apiVersion", "leaseRequest", "reservationId"}
        and original["apiVersion"] == CLAIM_REQUEST_VERSION)
    reservation = original["reservationId"]
    _need(type(reservation) is str and str(uuid.UUID(reservation)) == reservation)
    wire = validate_wire(original["leaseRequest"])
    remaining = wire["operatorXQuota"]["expiresAtEpochMs"] - time.time_ns() // 1_000_000
    _need(0 < remaining <= min(wire["maxTtlSeconds"] * 1000, 5000))
    receipt = _transaction(wire, "claim", reservation_id=reservation,
        deadline=time.monotonic() + remaining / 1000)
    return {"apiVersion": CLAIM_RESPONSE_VERSION, "requestBindingSha256": digest(wire), "claim": receipt}
