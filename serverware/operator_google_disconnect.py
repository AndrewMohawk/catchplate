"""Explicit operator Google disconnect: atomic local fence, retained cleanup.

No provider I/O occurs in this module. Provider acceptance retires only this
work item, never the quarantined account, family exclusion or revoked rules.
"""
from __future__ import annotations

from serverware import db, operator_catalog_schema as schema
from serverware import operator_google_disconnect_store as durable
from serverware.operator_publication import exclusive

DisconnectUnavailable = durable.DisconnectUnavailable


def capability_available(conn):
    return durable.available(conn)


def require_initial_admission(conn):
    durable.require_initial_admission(conn)


def _input(payload, actor_id):
    from serverware import operator_google_cleanup_store as cleanup
    identifiers = payload.confirmed_affected_rule_ids
    if (not durable.canonical_uuid(payload.id) or type(payload.expected_revision) is not int
            or not 0 < payload.expected_revision < 9_007_199_254_740_991
            or not isinstance(payload.expected_policy_hash, str) or not cleanup._SHA.fullmatch(payload.expected_policy_hash)
            or payload.acknowledge_project_wide_revocation is not True
            or not isinstance(identifiers, list) or len(identifiers) > 64
            or not all(durable.canonical_uuid(value) for value in identifiers)
            or identifiers != sorted(set(identifiers))
            or not isinstance(actor_id, str) or not 0 < len(actor_id) <= 512):
        raise ValueError("invalid operator Google disconnect confirmation")


def _family(conn, metadata, catalog):
    from serverware import operator_catalog_google as google, operator_google_cleanup_store as cleanup
    family = db._google_oauth_grant_family(metadata)
    durable._require(family is not None)
    cores = conn.execute("SELECT id,name,kind,metadata,lifecycle_status,credential_version FROM credentials LIMIT ?",
        (cleanup.MAX_FAMILY_SCAN + 1,)).fetchall()
    durable._require(len(cores) <= cleanup.MAX_FAMILY_SCAN)
    records = {row["id"]: row for row in catalog["credentials"]}
    identifiers = []
    for core in cores:
        other = db._google_oauth_grant_family(db.loads(core["metadata"], {}))
        if other is None or not db._google_oauth_grant_families_collide(family, other):
            continue
        record = records.get(core["id"])
        if record is None or record.get("status") != "active" or record.get("auth_type") != "google_oauth":
            raise schema.CatalogConflict()
        google.validate_record(record, core)
        identifiers.append(core["id"])
    durable._require(bool(identifiers))
    return sorted(identifiers)


def _validated_snapshot(conn, item):
    """Pure retained-state validation: no loaded-state or provider network I/O."""
    from serverware import operator_catalog_mutations as mutations, operator_google_cleanup_store as cleanup
    receipt = item["receipt"]
    catalog = schema.read_catalog(conn)
    schema.validate_bindings(conn, catalog)
    credentials = {row["id"]: row for row in catalog["credentials"]}
    for identifier in receipt["credential_ids"]:
        row = credentials.get(identifier, {})
        durable._require(row.get("status") == "quarantined"
            and row.get("disconnect_operation_id") == receipt["operation_id"]
            and row.get("quarantine_work_id") == receipt["operation_id"])
    durable._require(not any(row["status"] == "active" and row["credential_id"] in receipt["credential_ids"]
        for row in catalog["access_rules"]))
    work = cleanup.get_work(receipt["operation_id"], conn=conn)
    if item["status"] == "accepted":
        durable._require(work is None)
    else:
        durable._require(work is not None and work["source"] == durable.SOURCE and work["fence"] is not None
            and work["fence"]["credential_ids"] == receipt["credential_ids"]
            and work["fence"]["policy_hash"] == receipt["policy_hash"])
        durable.require_provider_work(conn, work)
    return catalog, mutations._state(conn)


def _observe(conn, item, *, publication_failed=False):
    from serverware import operator_catalog_mutations as mutations
    catalog, state = _validated_snapshot(conn, item)
    receipt = item["receipt"]
    policy = mutations._policy_observation(state, publication_failed=publication_failed)
    operation = {"schema": "serverware.operatorGoogleDisconnect/v1",
        "operation_id": receipt["operation_id"], "credential_id": receipt["credential_id"],
        "status": item["status"], "affected_rule_ids": receipt["affected_rule_ids"],
        "affected_application_ids": receipt["affected_application_ids"], "credential_ids": receipt["credential_ids"],
        "requested_at": receipt["requested_at"], "attempts": item["attempts"],
        "next_attempt_at": item["next_attempt_at"], "provider_accepted_at": item["provider_accepted_at"],
        "provider_revocation": "accepted" if item["status"] == "accepted" else "not_proven",
        "propagation": "not_proven", "reconnect": "blocked", "reason": item["reason"],
        "local_enforcement": "enforced" if policy["activation"] == "active" else "pending",
        "in_flight_requests": "not_recalled", "automatic_replay_allowed": False}
    return {"outcome": "committed", "disconnect": operation, "revision": catalog["revision"], "policy": policy}


def status_for_credential(credential_id, actor_id):
    from serverware import operator_demo_store as store
    if not durable.canonical_uuid(credential_id) or not isinstance(actor_id, str) or not actor_id:
        raise ValueError("invalid operator Google disconnect selector")
    store._require()
    with db.connect() as conn:
        conn.execute("BEGIN")
        durable._require(capability_available(conn))
        item = durable.get(conn, credential_id=credential_id)
        if item is None or item["receipt"]["actor_id"] != actor_id:
            return None
        return _observe(conn, item)


def _unknown(credential_id, operation_id):
    return {"outcome": "unknown", "disconnect": {"schema": "serverware.operatorGoogleDisconnect/v1",
        "operation_id": operation_id, "credential_id": credential_id, "status": "unknown",
        "provider_revocation": "not_proven", "propagation": "not_proven", "reconnect": "blocked",
        "local_enforcement": "pending", "automatic_replay_allowed": False}, "revision": None, "policy": None}


def disconnect(payload, actor_id):
    from serverware import operator_demo_store as store, operator_catalog_google as google
    from serverware import operator_google_cleanup as fencing, operator_google_cleanup_store as cleanup
    from serverware import operator_catalog_mutations as mutations
    _input(payload, actor_id)
    store._require()
    attempted_commit, did_commit, operation_id, result = False, False, None, None
    try:
        with exclusive():
            with db.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                durable._require(capability_available(conn))
                schema.require_revision(conn, payload.expected_revision)
                state = mutations._state(conn)
                if state["policy_hash"] != payload.expected_policy_hash:
                    raise schema.CatalogConflict()
                catalog = schema.read_catalog(conn)
                schema.validate_bindings(conn, catalog)
                target = mutations._target(catalog, "credentials", payload.id)
                if target.get("auth_type") != "google_oauth" or durable.get(conn, credential_id=payload.id) is not None:
                    raise schema.CatalogConflict()
                core = conn.execute("SELECT * FROM credentials WHERE id=?", (payload.id,)).fetchone()
                profile = google.validate_profile_binding(conn)
                metadata = google.validate_record(target, core, profile)
                durable.require_quiescent(conn, metadata)
                identifiers = _family(conn, metadata, catalog)
                rules = [row for row in catalog["access_rules"]
                    if row["status"] == "active" and row["credential_id"] in identifiers]
                affected = sorted(row["id"] for row in rules)
                if affected != payload.confirmed_affected_rule_ids:
                    raise schema.CatalogConflict()
                operation_id = cleanup._reserve(conn, operation="disconnect", actor_id=actor_id,
                    profile=profile, intent_id=metadata["oauth_intent_id"], credential={**dict(core), "metadata": metadata})
                cleanup._bind_identity(conn, operation_id, metadata)
                db.attach_oauth_revocation_material(operation_id, secret=db.decrypt_secret_envelope(core), _connection=conn)
                fence = fencing.fence_in_transaction(conn, operation_id, reason="explicit_disconnect")
                durable._require(fence["credential_ids"] == identifiers)
                # Independent custody marker prevents a missing durable table
                # becoming indistinguishable from a genuinely older profile.
                current = schema.read_catalog(conn)
                for row in current["credentials"]:
                    if row["id"] in identifiers:
                        schema.save_resource(conn, "credentials", {**row, "disconnect_operation_id": operation_id})
                state = mutations._state(conn)
                receipt = {"schema": "serverware.operatorGoogleDisconnectReceipt/v1", "operation_id": operation_id,
                    "credential_id": payload.id, "actor_id": actor_id, "requested_at": db.iso_now(),
                    "profile_binding_digest": profile.binding_digest, "oauth_client_id": profile.client_id,
                    "provider_subject": metadata["provider_subject"], "credential_ids": identifiers,
                    "affected_rule_ids": affected, "affected_application_ids": sorted({row["application_id"] for row in rules}),
                    "reviewed_revision": payload.expected_revision, "reviewed_policy_hash": payload.expected_policy_hash,
                    "revision": fence["catalog_revision"], "policy_hash": fence["policy_hash"],
                    "policy_sequence": state["sequence"], "project_wide_acknowledged": True}
                durable.insert(conn, receipt)
                schema.validate_bindings(conn)
                db.append_audit_event(conn, event_type="operator_catalog.oauth.disconnect_requested",
                    actor_type="admin", actor_id=actor_id, event=receipt)
                attempted_commit = True
                conn.commit()
                did_commit = True
            publication = fencing.materialize_committed(fence)
            with db.connect() as conn:
                conn.execute("BEGIN")
                result = _observe(conn, durable.get(conn, operation_id=operation_id),
                    publication_failed=publication.publication != "materialized")
        return result
    except Exception:
        if not attempted_commit:
            raise
        # A COMMIT exception or postcommit guard failure is never replayed and
        # never misclassified as a pre-admission409/422. Observe by saved ID.
        try:
            observed = status_for_credential(payload.id, actor_id)
            if observed is not None:
                return observed
        except Exception:
            pass
        if did_commit and result is not None:
            return result
        return _unknown(payload.id, operation_id)


def finish_work(work_id, *, worker_id, succeeded, error=None):
    """Only the existing claimed worker calls this after provider transport.

No provider details are persisted. Unknown/failed contact remains retryable
owned work. Provider acceptance and guarded retirement commit atomically.
"""
    from datetime import timedelta
    from serverware import operator_google_cleanup_store as cleanup, operator_demo_store as store
    if type(succeeded) is not bool or not isinstance(worker_id, str) or not 0 < len(worker_id) <= 128:
        raise ValueError("invalid operator Google disconnect completion")
    store._require()
    with exclusive(), db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        durable._require(capability_available(conn))
        item = durable.get(conn, operation_id=work_id)
        durable._require(item is not None and item["status"] != "accepted")
        work = conn.execute("SELECT * FROM oauth_revocation_work WHERE id=?", (work_id,)).fetchone()
        durable._require(work is not None and work["source"] == durable.SOURCE
            and work["status"] == "pending" and work["lease_owner"] == worker_id)
        cleanup.require_transition(conn, work_id, cleanup=True)
        _validated_snapshot(conn, item)
        now = db.utcnow()
        if succeeded:
            # The receipt update rolls back if exact guarded retirement or its
            # audit fails; a missing work row alone can never imply acceptance.
            conn.execute("UPDATE " + durable.TABLE + " SET status='accepted',provider_accepted_at=?,"
                "next_attempt_at=NULL,reason='provider_accepted' WHERE operation_id=?", (now.isoformat(), work_id))
            durable._require(cleanup.retire(conn, work_id, worker_id=worker_id))
            db.append_audit_event(conn, event_type="operator_catalog.oauth.disconnect_provider_accepted",
                actor_type="admin", actor_id=item["receipt"]["actor_id"], event={"operation_id": work_id,
                    "credential_id": item["receipt"]["credential_id"], "provider": "google",
                    "provider_outcome": "accepted", "propagation": "not_proven", "reconnect": "blocked"})
            conn.commit()
            return {"ok": True, "revocation_status": "accepted", "deleted": True, "reconnect": "blocked"}
        attempts = int(work["attempts"]) + 1
        next_at = (now + timedelta(seconds=db._oauth_revocation_backoff_seconds(attempts))).isoformat()
        conn.execute("UPDATE oauth_revocation_work SET attempts=?,last_error='provider_outcome_unconfirmed',"
            "next_attempt_at=?,lease_owner=NULL,lease_until=NULL,updated_at=? WHERE id=?",
            (attempts, next_at, now.isoformat(), work_id))
        conn.execute("UPDATE " + durable.TABLE + " SET status='retry',attempts=?,next_attempt_at=?,"
            "reason='provider_outcome_unconfirmed' WHERE operation_id=?", (attempts, next_at, work_id))
        db.append_audit_event(conn, event_type="operator_catalog.oauth.disconnect_retry_retained",
            actor_type="admin", actor_id=item["receipt"]["actor_id"], event={"operation_id": work_id,
                "credential_id": item["receipt"]["credential_id"], "attempts": attempts,
                "next_attempt_at": next_at, "provider_outcome": "not_proven"})
        conn.commit()
        return {"ok": False, "reason": "provider_revocation_failed", "retry_at": next_at}
