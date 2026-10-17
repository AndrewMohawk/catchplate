"""One-shot ordinary X refresh under an exact retained account/application.

No global X configuration, Google intent, generic OAuth retirement, provider
retry, or secret lease is created here. The durable owner commits each contact
claim before HTTP and captures its private response before classification.
Only metadata is returned; the lease handler must perform its final locked
catalog/configuration and generation checks before opening a secret envelope.
"""
from __future__ import annotations

from contextlib import ExitStack
import math
import time
import uuid

from catchplate import operator_x_oauth_protocol as protocol
from catchplate.http_client import HttpDeadline, _strict_json_loads

_ERROR = "Operator X refresh is unavailable; inspect retained account status; no automatic retry"


class RefreshUnavailable(RuntimeError):
    def __init__(self):
        super().__init__(_ERROR)


def selected(credential) -> bool:
    """Marker detection only. Malformed marked rows must never use legacy OAuth."""
    return (isinstance(credential, dict) and isinstance(credential.get("metadata"), dict)
        and "operator_x_account" in credential["metadata"])


def _require(condition):
    if not condition:
        raise RefreshUnavailable()


def _remaining(deadline):
    now = time.monotonic()
    _require(type(deadline) is HttpDeadline and math.isfinite(deadline.expires_at)
        and math.isfinite(now) and deadline.expires_at > now)


def _write(function, *args, **kwargs):
    from catchplate import db, operator_publication as publication
    from catchplate import operator_x_admission as admission
    publication.assert_not_held()
    with publication.exclusive(), db.metadata_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        directory = admission.require_runtime()
        admission.check_connection(conn, directory)
        result = function(conn, *args, **kwargs)
        admission.check_connection(conn, directory)
        conn.commit()
        return result


def _hold(work_id):
    from catchplate import operator_x_account_store as store
    try:
        _write(store.hold, work_id, reason="refresh_failed")
    except Exception:
        # A failed disposition write leaves the original claimed work pending;
        # it never authorizes another refresh or a legacy cleanup fallback.
        pass


def _public(credential, profile):
    from catchplate import operator_catalog_x_oauth as catalog
    _require(isinstance(credential, dict) and selected(credential)
        and credential.get("kind") == "oauth2" and credential.get("lifecycle_status") == "active"
        and type(credential.get("credential_version")) is int and credential["credential_version"] >= 1
        and type(credential.get("id")) is str and str(uuid.UUID(credential["id"])) == credential["id"])
    metadata = catalog.validate_account_metadata(credential["metadata"], profile)
    return {"id": credential["id"], "kind": "oauth2", "credential_version": credential["credential_version"],
        "lifecycle_status": "active", "metadata": metadata}


def _contact(request, *, work_id, deadline, selection):
    from catchplate import operator_provider_key as keys
    from catchplate import operator_publication as publication
    from catchplate import operator_x_account_store as store
    from catchplate import operator_x_transport as transport
    _remaining(deadline)
    keys.check_pin(selection.key_pin)
    _write(store.claim_contact, work_id, request=request, deadline=deadline)
    _remaining(deadline)
    keys.check_pin(selection.key_pin)
    publication.assert_not_held()
    try:
        captured = transport.send(request, work_id=work_id, deadline=deadline)
    except transport.TransportInterrupted as error:
        # Retention intentionally precedes elapsed-clock or acceptance checks.
        transport.require_capture(error.capture, request=request, work_id=work_id, deadline=deadline)
        _write(store.capture, work_id, error.capture)
        raise RefreshUnavailable() from None
    transport.require_capture(captured, request=request, work_id=work_id, deadline=deadline)
    _write(store.capture, work_id, captured)
    _remaining(deadline)
    keys.check_pin(selection.key_pin)
    _require(captured.complete is True and captured.outcome == "complete")
    return captured


def prepare_for_lease(credential_id, expected_version, *, principal_id, route_id, policy_hash, deadline):
    """Return current/refreshed public core metadata, or a fixed held refusal.

    ``deadline`` is the lease caller's absolute monotonic deadline, not a fresh
    timeout. A stale generation returns current metadata without another token
    exchange; only the separate lease handler can issue a no-envelope proof.
    Caller pins come from the authenticated lease payload, never provider data.
    Current catalog and SQL policy binding is required even for metadata-only
    returns. The store retains these pins and rechecks them before each contact.
    """
    from catchplate import db, operator_publication as publication
    from catchplate.oauth import OAUTH_REFRESH_SKEW_SECONDS
    from catchplate import operator_provider_key as keys
    from catchplate import operator_x_admission as admission
    from catchplate import operator_x_configuration as configuration
    from catchplate import operator_x_oauth_profile as profiles
    from catchplate import operator_x_account_store as store
    from catchplate import operator_catalog_x_oauth as catalog
    work_id = None
    try:
        _require(type(credential_id) is str and str(uuid.UUID(credential_id)) == credential_id
            and type(expected_version) is int and expected_version >= 1
            and type(deadline) in (int, float) and math.isfinite(deadline)
            and all(type(value) is str and 1 <= len(value) <= 512 for value in (principal_id, route_id))
            and type(policy_hash) is str and policy_hash.startswith("sha256:")
            and len(policy_hash) == 71 and all(value in "0123456789abcdef" for value in policy_hash[7:]))
        lease_binding = {"principal_id": principal_id, "route_id": route_id,
            "credential_id": credential_id, "policy_hash": policy_hash}
        original_deadline = HttpDeadline(float(deadline))
        _remaining(original_deadline)
        publication.assert_not_held()
        directory = admission.require_runtime()
        with ExitStack() as retained:
            with publication.exclusive(), db.metadata_connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                admission.check_connection(conn, directory)
                binding = configuration.retained_public_binding(conn)
                _require(binding is not None)
                profile = profiles.parse_profile(binding["public_profile"])
                current = store.current(conn, credential_id)
                _require(current["selection"] == binding)
                public = _public(current["credential"], profile)
                _require(public["metadata"] == current["metadata"] and public["id"] == credential_id
                    and public["credential_version"] >= expected_version)
                catalog.require_lease_binding(conn, principal_id=principal_id, route_id=route_id,
                    credential_id=credential_id, core_credential=current["credential"], profile=profile)
                policy = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()
                _require(policy is not None and policy[0] == policy_hash)
                _remaining(original_deadline)
                # No secret read or provider I/O for a stale request or a token
                # with the same existing refresh margin as ordinary OAuth.
                if (public["credential_version"] != expected_version
                        or public["metadata"]["expires_at_epoch_ms"]
                            > time.time_ns() // 1_000_000 + OAUTH_REFRESH_SKEW_SECONDS * 1000):
                    admission.check_connection(conn, directory)
                    return public
                selection = retained.enter_context(configuration._retained_selection(conn, directory))
                _require(selection.record == binding)
                work = store.claim_refresh(conn, credential_id=credential_id, expected_version=expected_version,
                    lease_binding=lease_binding)
                _require(work["selection"] == selection.record and work["metadata"] == public["metadata"]
                    and work["credential_id"] == credential_id and work["generation"] == expected_version
                    and work["lease_binding"] == lease_binding)
                work_id = work["work_id"]
                admission.check_connection(conn, directory)
                conn.commit()
            _remaining(original_deadline)
            keys.check_pin(selection.key_pin)
            _require(type(work["secret"]) is str and len(work["secret"].encode("utf-8")) <= 1024 * 1024)
            secret = _strict_json_loads(work["secret"].encode("utf-8"))
            _require(type(secret) is dict and type(secret.get("token_type")) is str
                and secret["token_type"].lower() == "bearer")
            expiry = secret.get("refresh_token_expires_at_epoch_ms")
            _require(expiry is None or (type(expiry) is int and expiry > time.time_ns() // 1_000_000))
            request = protocol.refresh_request(selection.profile, selection.client_secret, secret.get("refresh_token"))
            captured = _contact(request, work_id=work_id, deadline=original_deadline, selection=selection)
            token = protocol.classify_token_response(request, status=captured.status,
                headers=captured.headers, body=captured.body)
            _require(type(token) is protocol.AcceptedToken)
            identity_request = protocol.identity_request(selection.profile, token.access_token)
            captured_identity = _contact(identity_request, work_id=work_id, deadline=original_deadline, selection=selection)
            identity = protocol.classify_identity_response(identity_request, status=captured_identity.status,
                headers=captured_identity.headers, body=captured_identity.body)
            _require(type(identity) is protocol.AcceptedIdentity
                and identity.subject == public["metadata"]["provider_subject"])
            _remaining(original_deadline)
            keys.check_pin(selection.key_pin)
            adopted = _write(store.adopt_refresh, work_id, token=token, identity=identity)
            result = _public(adopted, selection.profile)
            _require(result["id"] == credential_id and result["credential_version"] == expected_version + 1
                and result["metadata"]["operator_x_account"] == public["metadata"]["operator_x_account"]
                and result["metadata"]["provider_subject"] == public["metadata"]["provider_subject"])
            return result
    except BaseException as error:
        if work_id is not None:
            _hold(work_id)
        if not isinstance(error, Exception):
            raise
        raise RefreshUnavailable() from None
