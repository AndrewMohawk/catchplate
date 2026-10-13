"""Finite, opt-in workload renewal in the ordinary catalog transaction.

Only public keys, verifiers and one bounded operation receipt are retained.
Recovery never republishes policy or extends authority. Gate observation occurs
outside publication/SQLite ownership; a committed operation is not activation.
"""
from __future__ import annotations

from copy import deepcopy
import re
import time
import uuid

from serverware import operator_workload_renewal as wire
from serverware import operator_catalog_schema as schema

_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KEY = re.compile(r"[0-9a-f]{64}\Z")
_FIELDS = {"version", "enrollment_id", "public_key", "enrolled_at_epoch_ms",
    "expires_at_epoch_ms", "token_lifetime_seconds", "overlap_seconds", "previous_token", "last_operation"}
_PREVIOUS = {"token_sha256", "token_generation", "original_expires_at_epoch_ms", "accept_until_epoch_ms"}
_RECEIPT = {"operation_id", "request_sha256", "application_id", "enrollment_id",
    "previous_generation", "token_generation", "token_sha256", "issued_at_epoch_ms",
    "rotated_at_epoch_ms", "expires_at_epoch_ms", "previous_accept_until_epoch_ms"}
_CANCELLED = "client_renewal_cancelled_at_epoch_ms"


def _now():
    return time.time_ns() // 1_000_000


def _require(value):
    if not value:
        raise schema.CatalogIntegrityError("catalog workload renewal metadata refused")


def _integer(value, minimum=1):
    return type(value) is int and minimum <= value <= wire.MAX_INTEGER


def _uuid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _digest(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def validate(record: dict) -> None:
    """Closed retained metadata; absence alone preserves legacy behavior."""
    if _CANCELLED in record:
        _require(_integer(record[_CANCELLED], 0) and "client_renewal" not in record)
    if "client_renewal" not in record:
        return
    item = record["client_renewal"]
    _require(type(item) is dict and set(item) == _FIELDS)
    _require(type(item["version"]) is int and item["version"] == 1
        and _uuid(item["enrollment_id"]) and type(item["public_key"]) is str
        and _KEY.fullmatch(item["public_key"]) is not None
        and record.get("status") == "active" and _uuid(record.get("id"))
        and _integer(record.get("token_version")) and _digest(record.get("token_sha256")))
    start, end, lifetime = item["enrolled_at_epoch_ms"], item["expires_at_epoch_ms"], item["token_lifetime_seconds"]
    _require(_integer(start) and _integer(end)
        and wire.MIN_ENROLLMENT_LIFETIME_SECONDS * 1000 <= end - start <= wire.MAX_ENROLLMENT_LIFETIME_SECONDS * 1000
        and type(lifetime) is int and wire.MIN_TOKEN_LIFETIME_SECONDS <= lifetime <= wire.MAX_TOKEN_LIFETIME_SECONDS
        and type(item["overlap_seconds"]) is int and item["overlap_seconds"] == wire.OVERLAP_SECONDS
        and _integer(record.get("token_expires_at_epoch_ms")) and record["token_expires_at_epoch_ms"] <= end)
    previous, receipt = item["previous_token"], item["last_operation"]
    if receipt is None:
        _require(previous is None)
        return
    _require(type(receipt) is dict and set(receipt) == _RECEIPT)
    _require(_uuid(receipt["operation_id"]) and _digest(receipt["request_sha256"])
        and receipt["application_id"] == record["id"] and receipt["enrollment_id"] == item["enrollment_id"]
        and _integer(receipt["previous_generation"]) and _integer(receipt["token_generation"])
        and receipt["token_generation"] == receipt["previous_generation"] + 1 == record["token_version"]
        and receipt["token_sha256"] == record["token_sha256"]
        and _integer(receipt["issued_at_epoch_ms"]) and _integer(receipt["rotated_at_epoch_ms"])
        and start <= receipt["rotated_at_epoch_ms"] < end
        and receipt["issued_at_epoch_ms"] <= receipt["rotated_at_epoch_ms"] + wire.CLOCK_SKEW_MS
        and receipt["issued_at_epoch_ms"] > receipt["rotated_at_epoch_ms"] - wire.REQUEST_LIFETIME_MS
        and _integer(receipt["expires_at_epoch_ms"])
        and receipt["expires_at_epoch_ms"] == record["token_expires_at_epoch_ms"]
        == min(receipt["issued_at_epoch_ms"] + lifetime * 1000, end)
        and receipt["expires_at_epoch_ms"] > receipt["rotated_at_epoch_ms"])
    if previous is None:
        _require(receipt["previous_accept_until_epoch_ms"] is None)
        return
    _require(type(previous) is dict and set(previous) == _PREVIOUS)
    _require(_digest(previous["token_sha256"]) and previous["token_sha256"] != record["token_sha256"]
        and _integer(previous["token_generation"]) and previous["token_generation"] == receipt["previous_generation"]
        and _integer(previous["original_expires_at_epoch_ms"])
        and previous["original_expires_at_epoch_ms"] <= end
        and _integer(previous["accept_until_epoch_ms"])
        and previous["accept_until_epoch_ms"] == receipt["previous_accept_until_epoch_ms"]
        == min(previous["original_expires_at_epoch_ms"], receipt["rotated_at_epoch_ms"] + wire.OVERLAP_SECONDS * 1000)
        and previous["accept_until_epoch_ms"] > receipt["rotated_at_epoch_ms"])


def audience() -> str:
    from serverware import operator_demo
    return operator_demo.settings()["proxy_url"].rstrip("/") + wire.PUBLIC_PATH


def public_fields(record: dict, now: int) -> dict:
    validate(record)
    result = {"client_renewal": None}
    if _CANCELLED in record:
        result[_CANCELLED] = record[_CANCELLED]
    item = record.get("client_renewal")
    if item is not None:
        result["client_renewal"] = {"version": 1, "enrollment_id": item["enrollment_id"],
            "expires_at_epoch_ms": item["expires_at_epoch_ms"],
            "public_key_fingerprint": wire.key_fingerprint(item["public_key"]),
            "token_lifetime_seconds": item["token_lifetime_seconds"],
            "overlap_seconds": wire.OVERLAP_SECONDS, "audience": audience(),
            "status": "active" if now < item["expires_at_epoch_ms"] else "expired"}
    return result


def capability() -> dict:
    """Display descriptor only; caller must join actual gate and policy."""
    return {"schema": wire.SCHEMA, "enroll_path": wire.ENROLL_PATH, "cancel_path": wire.CANCEL_PATH,
        "path": wire.PUBLIC_PATH, "audience": audience(), "overlap_seconds": wire.OVERLAP_SECONDS,
        "token_lifetime_seconds": {"min": wire.MIN_TOKEN_LIFETIME_SECONDS,
            "max": wire.MAX_TOKEN_LIFETIME_SECONDS, "default": wire.DEFAULT_TOKEN_LIFETIME_SECONDS},
        "enrollment_lifetime_seconds": {"min": wire.MIN_ENROLLMENT_LIFETIME_SECONDS,
            "max": wire.MAX_ENROLLMENT_LIFETIME_SECONDS, "default": wire.DEFAULT_ENROLLMENT_LIFETIME_SECONDS},
        "single_writer": True}


def observe() -> dict:
    """Fresh bounded gate observation, using the managed source-pair join."""
    from serverware import operator_demo_store as store, operator_google_managed_config as managed
    store.operator_publication.assert_not_held()
    unavailable = {"ready": False, "policy_hash": None, "loaded_policy_hash": None}
    try:
        if managed.enabled():
            from serverware import operator_google_managed_readiness as readiness
            return readiness.observe_workload_renewal()
        health = store.loaded_gate_status()
        if (type(health) is not dict or health.get("ok") is not True
                or not _digest(health.get("policy_hash"))
                or not wire.gate_descriptor_matches(health.get("operator_workload_renewal"))):
            return unavailable
        with store._require().metadata_connection() as conn:
            row = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()
        current = row[0] if row else None
        return {"ready": current == health["policy_hash"], "policy_hash": current,
            "loaded_policy_hash": health["policy_hash"]}
    except Exception:
        return unavailable


def _admit_gate(expected):
    observed = observe()
    if not (observed.get("ready") is True
            and observed.get("policy_hash") == observed.get("loaded_policy_hash") == expected):
        raise schema.CatalogConflict("workload renewal gate unavailable")


def clear(record: dict, now: int) -> None:
    """Explicit lifecycle invalidation; no retained public key after cancel."""
    if "client_renewal" in record:
        record.pop("client_renewal")
        record[_CANCELLED] = now


def enroll(payload: wire.EnrollmentInput, actor_id: str) -> dict:
    from serverware import operator_catalog_mutations as mutations
    _admit_gate(payload.expected_policy_hash)

    def change(_db, conn, catalog):
        record = mutations._target(catalog, "applications", payload.id)
        now = _now()
        end = now + payload.enrollment_lifetime_seconds * 1000
        record.pop(_CANCELLED, None)
        record["client_renewal"] = {"version": 1, "enrollment_id": str(uuid.uuid4()),
            "public_key": payload.public_key, "enrolled_at_epoch_ms": now, "expires_at_epoch_ms": end,
            "token_lifetime_seconds": payload.token_lifetime_seconds, "overlap_seconds": wire.OVERLAP_SECONDS,
            "previous_token": None, "last_operation": None}
        record["token_expires_at_epoch_ms"] = min(record["token_expires_at_epoch_ms"], end)
        validate(record)
        return mutations._Change(schema.save_resource(conn, "applications", record),
            authority_changed=bool(mutations._active_rules(catalog, "application_id", payload.id)))
    return mutations._mutate(payload, actor_id, "applications", "application.renewal_enrolled", change)


def cancel(payload, actor_id: str) -> dict:
    from serverware import operator_catalog_mutations as mutations

    def change(_db, conn, catalog):
        record = mutations._target(catalog, "applications", payload.id)
        if "client_renewal" not in record:
            raise schema.CatalogConflict("workload renewal enrollment unavailable")
        clear(record, _now())
        return mutations._Change(schema.save_resource(conn, "applications", record),
            authority_changed=bool(mutations._active_rules(catalog, "application_id", payload.id)))
    return mutations._mutate(payload, actor_id, "applications", "application.renewal_cancelled", change)


def _authenticated(catalog, payload, now):
    from serverware import operator_catalog_mutations as mutations
    record = deepcopy(mutations._target(catalog, "applications", payload.application_id))
    item = record.get("client_renewal")
    if item is None or item["enrollment_id"] != payload.enrollment_id or now >= item["expires_at_epoch_ms"]:
        raise schema.CatalogConflict("workload renewal enrollment unavailable")
    payload.verify(item["public_key"], audience())
    last = item["last_operation"]
    replay = last is not None and last["operation_id"] == payload.operation_id
    if replay and last["request_sha256"] != payload.request_digest():
        raise schema.CatalogConflict("workload renewal operation conflict")
    return record, replay


def _result(identifier, operation):
    """Public receipt plus separately fenced current resource/policy status."""
    from serverware import operator_demo_store as store, operator_catalog_mutations as mutations
    with store._require().connect() as conn:
        conn.execute("BEGIN")
        catalog = schema.read_catalog(conn)
        schema.validate_bindings(conn, catalog)
        record = next(row for row in catalog["applications"] if row["id"] == identifier)
        state = mutations._state(conn)
    observed = observe()
    same = False
    try:
        with store._require().metadata_connection() as conn:
            conn.execute("BEGIN")
            current = schema.read_catalog(conn)
            current_record = next(row for row in current["applications"] if row["id"] == identifier)
            same = (current_record == record and current["revision"] == catalog["revision"]
                and mutations._state(conn) == state)
    except Exception:
        pass
    now = _now()
    enrollment = record.get("client_renewal")
    operation_current = (record["status"] == "active" and enrollment is not None
        and bool(mutations._active_rules(catalog, "application_id", identifier))
        and enrollment["enrollment_id"] == operation["enrollment_id"]
        and enrollment["expires_at_epoch_ms"] > now
        and enrollment["last_operation"] == operation
        and record["token_version"] == operation["token_generation"]
        and record["token_sha256"] == operation["token_sha256"]
        and record["token_expires_at_epoch_ms"] == operation["expires_at_epoch_ms"] > now)
    policy = {**state, "loaded_policy_hash": observed.get("loaded_policy_hash"),
        "activation": "active" if same and operation_current and observed.get("ready") is True
        and observed.get("policy_hash") == observed.get("loaded_policy_hash") == state["policy_hash"] else "pending"}
    return {"operation": deepcopy(operation), "application": mutations._public("applications", record,
        catalog, policy, now, {}), "revision": catalog["revision"], "policy": policy}


def _acknowledge(identifier, operation):
    try:
        return _result(identifier, operation)
    except Exception:
        # A postcommit observation/parser failure is never a proof rejection or
        # rollback. The caller may recover only its original signed operation.
        raise RuntimeError("workload renewal outcome observation unavailable") from None


def renew(payload: wire.RenewalRequest) -> dict:
    from serverware import operator_demo_store as store, operator_catalog_mutations as mutations
    from serverware import operator_catalog_policy as policy
    db = store._require()
    # Recover an authenticated committed receipt before freshness or issuance
    # capability checks. No HTTP crosses publication/database ownership.
    with store.operator_publication.exclusive():
        with db.connect() as conn:
            conn.execute("BEGIN")
            catalog = schema.read_catalog(conn)
            schema.validate_bindings(conn, catalog)
            record, replay = _authenticated(catalog, payload, _now())
            state = mutations._state(conn)
    if replay:
        return _acknowledge(payload.application_id, record["client_renewal"]["last_operation"])
    _admit_gate(state["policy_hash"])
    with store.operator_publication.exclusive():
        with db.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            catalog = schema.read_catalog(conn)
            schema.validate_bindings(conn, catalog)
            now = _now()
            record, replay = _authenticated(catalog, payload, now)
            item = record["client_renewal"]
            if replay:
                operation = deepcopy(item["last_operation"])
            else:
                if mutations._state(conn) != state:
                    raise schema.CatalogConflict("workload renewal policy changed")
                if (payload.expected_token_generation != record["token_version"]
                        or payload.token_sha256 == record["token_sha256"]
                        or item["previous_token"] is not None and (
                            now < item["previous_token"]["accept_until_epoch_ms"]
                            or payload.token_sha256 == item["previous_token"]["token_sha256"])):
                    raise schema.CatalogConflict("workload renewal generation or overlap conflict")
                payload.check_fresh(now)
                expiry = min(payload.issued_at_epoch_ms + item["token_lifetime_seconds"] * 1000, item["expires_at_epoch_ms"])
                if payload.token_expires_at_epoch_ms != expiry or expiry <= now:
                    raise ValueError("workload renewal token expiry refused")
                previous = None
                if record["token_expires_at_epoch_ms"] > now:
                    previous = {"token_sha256": record["token_sha256"], "token_generation": record["token_version"],
                        "original_expires_at_epoch_ms": record["token_expires_at_epoch_ms"],
                        "accept_until_epoch_ms": min(record["token_expires_at_epoch_ms"], now + wire.OVERLAP_SECONDS * 1000)}
                operation = {"operation_id": payload.operation_id, "request_sha256": payload.request_digest(),
                    "application_id": record["id"], "enrollment_id": item["enrollment_id"],
                    "previous_generation": record["token_version"], "token_generation": record["token_version"] + 1,
                    "token_sha256": payload.token_sha256, "issued_at_epoch_ms": payload.issued_at_epoch_ms,
                    "rotated_at_epoch_ms": now, "expires_at_epoch_ms": expiry,
                    "previous_accept_until_epoch_ms": previous["accept_until_epoch_ms"] if previous else None}
                record.update(token_sha256=payload.token_sha256, token_expires_at_epoch_ms=expiry,
                    token_version=operation["token_generation"], token_rotated_at=db.iso_now())
                item.update(previous_token=previous, last_operation=operation)
                validate(record)
                schema.save_resource(conn, "applications", record)
                publication = policy.publish(conn)
                revision = schema.advance_revision(conn, catalog["revision"])
                db.append_audit_event(conn, event_type="operator_catalog.application.token_renewed",
                    actor_type="agent", actor_id=record["principal_id"], event={
                        "resource_type": "application", "resource_id": record["id"],
                        "enrollment_id": item["enrollment_id"], "operation_id": payload.operation_id,
                        "token_generation": record["token_version"], "token_expires_at_epoch_ms": expiry,
                        "revision": revision, "policy_hash": publication["policy_hash"], "policy_sequence": publication["sequence"]})
                conn.commit()
                if publication["changed"]:
                    try:
                        store.materialize()
                    except Exception:
                        pass  # Durable result survives; no automatic reissuance.
    return _acknowledge(payload.application_id, operation)
