"""Explicit genesis successors: original signatures verified in the transaction.

The caller's key/head values only address expected prestate. Complete populations
are proved against current roots by the planner; this module never registers an
external verdict, signs an inclusion, or substitutes for WebAuthn admission.
Legacy genesis argument shapes retain their original, separate semantics.
"""
from serverware import authority_transition_core as core
from serverware import authority_transition_policy_candidate_context as originals
from serverware import authority_transition_policy_candidate_trust as trust
from serverware import authority_policy_candidate_evidence as signatures

PREPARE = "policy.genesis.prepare"
FINALIZE = "policy.genesis.finalize"
PREPARE_SCHEMA = "serverware.policyAuthorityGenesisPrepare/v2"
FINALIZE_SCHEMA = "serverware.policyAuthorityGenesisFinalize/v2"
FINALIZE_DELIVERY_SCHEMA = "serverware.policyAuthorityGenesisFinalize/v3"
FIELD = "policyGenesis"
MAX_ROWS = 16
TABLES = ("policy_authority_trusted_keys", "policy_authority_trusted_key_revocations",
    "policy_authority_evidence_verifications", "policy_runtime_role_keys")


def require(value, message="policy genesis v2 original is not exact"):
    if not value:
        raise core.TransitionKernelError(message)


def selected(operation, arguments):
    return (operation == PREPARE and arguments.get("schema") == PREPARE_SCHEMA
        or operation == FINALIZE and arguments.get("schema") in (FINALIZE_SCHEMA, FINALIZE_DELIVERY_SCHEMA))


def pending_outbox(outbox, expected):
    """The one untouched preparation event; no claimed/failed/adopted work."""
    require(set(outbox) == set(expected) and all(outbox[name] == expected[name]
        for name in expected if name != "created_at"), "genesis delivery requires the exact pending original outbox")
    core.require_text(outbox["created_at"], "genesis outbox timestamp", maximum_bytes=64)


def configuration(value, *, root_digest=None):
    """Optional signed configuration pin block; absence never enables v2."""
    if value is None:
        return None
    require(type(value) is dict and set(value) == {"auditStoreIdentityDigest", "auditSignerPublicKeyDigest"})
    for item in value.values():
        core.require_digest(item, "signed genesis configuration")
    if root_digest is not None:
        core.require_digest(root_digest, "admitted genesis root")
        require(value["auditSignerPublicKeyDigest"] != root_digest)
    return dict(value)


def parse_arguments(operation, value):
    from serverware import authority_transition_policy as legacy
    fields = {"schema", "record", "verificationInputs"} if operation == PREPARE else {
        "schema", "genesisPreparationDigest", "inclusionReceipt", "auditStoreIdentityDigest", "verificationInputs"}
    core.require_exact_arguments(value, fields)
    require(selected(operation, value))
    given = value["verificationInputs"]
    require(type(given) is dict and set(given) == {"key", "head", "revocationSequence"}
        and type(given["key"]) is dict and type(given["head"]) is dict)
    core.require_integer(given["revocationSequence"], "genesis revocation sequence", minimum=0, maximum=2**63-1)
    if operation == PREPARE:
        row = legacy._genesis_record(value["record"])
        core.require_text(row["prepared_by"], "genesis preparing actor", maximum_bytes=1024)
    else:
        from serverware import db
        core.require_digest(value["genesisPreparationDigest"], "genesis preparation")
        core.require_digest(value["auditStoreIdentityDigest"], "genesis audit store")
        row = legacy._mapping(value["inclusionReceipt"], "genesis inclusion",
            fields=frozenset(db._POLICY_AUTHORITY_AUDIT_INCLUSION_FIELDS))
        for field in ("inclusion_receipt_envelope_digest", "inclusion_receipt_payload_digest", "transition_digest",
                "outbox_event_digest", "audit_store_identity_digest", "audit_signer_public_key_digest",
                "audit_event_hash", "inclusion_root_digest", "signing_key_id", "signature_digest"):
            core.require_digest(row[field], "genesis inclusion " + field)
        core.require_text(row["outbox_id"], "genesis audit outbox", maximum_bytes=256)
        core.require_integer(row["audit_sequence"], "genesis audit sequence", minimum=1, maximum=2**63-1)
        if row["previous_audit_event_hash"] is not None:
            core.require_digest(row["previous_audit_event_hash"], "genesis previous audit event")
    return row, given


def evidence(operation, row):
    from serverware import db
    prefix = "genesis" if operation == PREPARE else "inclusion_receipt"
    return dict(evidence_kind="authority_genesis" if operation == PREPARE else "audit_inclusion_receipt",
        envelope_json=row[prefix + "_envelope_json"], envelope_digest=row[prefix + "_envelope_digest"],
        payload_json=row[prefix + "_payload_json"], payload_digest=row[prefix + "_payload_digest"],
        signature_algorithm=row["signature_algorithm"], signing_key_id=row["signing_key_id"],
        signature=row["signature"], signature_digest=row["signature_digest"],
        record_binding=db._candidate_authority_signed_record(row, current_prefix=prefix))


def stage(record, now):
    from serverware import authority_transition_policy as legacy
    return legacy._audit_stage(event_type="policy.authority.genesis.prepared", entity_kind="activation_genesis",
        entity_id=record["policy_hash"], entity_revision=1, state_digest=record["genesis_preparation_digest"],
        previous_state_digest=None, actor_id=record["prepared_by"],
        evidence={"highWaterDigest": record["high_water_digest"], "policyHash": record["policy_hash"]},
        created_at_epoch_ns=record["prepared_at_epoch_ns"], created_at=legacy._database_iso(now))


def queries(operation, *, arguments: dict, database_now, request_digest):
    from serverware import authority_transition_policy as legacy
    from serverware import authority_primary_contract as primary
    core.require_digest(request_digest, "genesis request")
    row, given = parse_arguments(operation, arguments)
    signed = evidence(operation, row)
    expected = signatures.verify_static_original(**signed, key=given["key"], key_head=given["head"],
        revocation=None, revocation_sequence=given["revocationSequence"],
        verified_at_epoch_ns=legacy._database_epoch_ns(database_now))
    result = [core.BoundedQuery(query_id=core.query_program_id(operation, "complete_population", table),
        table=table, predicates=(), order_by=tuple(core.QueryOrder(name) for name in primary.PRIMARY_KEY_COLUMNS[table]),
        maximum_rows=MAX_ROWS + 1, page_size=MAX_ROWS,
        proof_primitive="bounded-limit-plus-one", work_units=MAX_ROWS + 1) for table in TABLES]

    def exact(name, table, key):
        result.append(legacy._exact_query(operation=operation, name=name, table=table, key=key))

    digest = row["genesis_preparation_digest"] if operation == PREPARE else arguments["genesisPreparationDigest"]
    exact("genesis_preparation", "policy_authority_genesis_preparations", {"genesis_preparation_digest": digest})
    exact("genesis_finalization", "policy_authority_genesis_finalizations", {"genesis_preparation_digest": digest})
    exact("current_signature_head", "policy_authority_trusted_key_heads", {"evidence_kind": signed["evidence_kind"]})
    exact("current_signature_verification", "policy_authority_evidence_verifications",
        {"verification_receipt_digest": expected["verification_receipt_digest"]})
    exact("active_high_water", "policy_high_water", {"scope": "active"})
    result.append(legacy._exact_empty_page_query(operation=operation, name="active_publication_page",
        table="policy_publications", predicates={"scope": "active"}, order_by=("policy_hash",)))
    if operation == PREPARE:
        audit = stage(row, database_now)
        exact("genesis_outbox", "metadata_audit_outbox", {"id": audit["outbox"]["id"]})
        exact("genesis_transition", "policy_authority_transition_audits", {"transition_digest": audit["transition"]["transition_digest"]})
    else:
        exact("genesis_outbox", "metadata_audit_outbox", {"id": row["outbox_id"]})
        exact("genesis_transition", "policy_authority_transition_audits", {"transition_digest": row["transition_digest"]})
        exact("inclusion_receipt", "policy_authority_audit_inclusion_receipts",
            {"inclusion_receipt_envelope_digest": row["inclusion_receipt_envelope_digest"]})
        exact("inclusion_head", "policy_authority_audit_inclusion_heads",
            {"audit_store_identity_digest": arguments["auditStoreIdentityDigest"]})
        exact("genesis_publication", "policy_publications", {"policy_hash": core.SelectedRowFieldReference(
            table="policy_authority_genesis_preparations", key={"genesis_preparation_digest": digest}, column="policy_hash")})
    return tuple(result)


def _separate(context, kind, signing_key):
    core.require_digest(context.genesis_root_digest, "actual admitted genesis root")
    require(signing_key != context.genesis_root_digest, "genesis signer cannot be the admitted root")
    require(not any(row["public_key_digest"] == signing_key and row["evidence_kind"] != kind
        for row in originals.population(context, "policy_authority_trusted_keys")), "genesis signer is shared across authority purposes")
    require(not any(row["public_key_digest"] == signing_key and row["role"] in {"export", "custody"}
        for row in originals.population(context, "policy_runtime_role_keys")), "genesis signer is an export/custody key")


def transition(context):
    from serverware import authority_transition_policy as legacy
    require(configuration(context.genesis_policy, root_digest=context.genesis_root_digest) is not None,
        "genesis v2 requires independently signed audit pins")
    row, given = parse_arguments(context.operation, context.arguments)
    signed = evidence(context.operation, row)
    _separate(context, signed["evidence_kind"], row["signing_key_id"])
    verified, mutation = trust.current(context, expected_key=given["key"], expected_head=given["head"],
        expected_sequence=given["revocationSequence"], **signed)
    changes = () if mutation is None else (mutation,)
    if context.operation == PREPARE:
        return _prepare(context, row, verified, changes)
    return _finalize(context, row, verified, changes)


def _prepare(context, row, verified, changes):
    from serverware import authority_transition_policy as legacy
    digest = row["genesis_preparation_digest"]
    selected = context.exact("policy_authority_genesis_preparations", {"genesis_preparation_digest": digest})
    if selected["present"]:
        stored = legacy._row(selected)
        require(all(stored.get(key) == value for key, value in row.items())
            and stored["verification_receipt_digest"] == verified["verification_receipt_digest"], "genesis replay differs")
        return core.KernelTransition(mutations=(), result={"ok": True, "idempotent": True, **stored}, work_units=64)
    require(not context.exact("policy_authority_genesis_finalizations", {"genesis_preparation_digest": digest})["present"]
        and not context.exact("policy_high_water", {"scope": "active"})["present"]
        and not context.present_rows("policy_publications"), "genesis requires an empty authority")
    now = legacy._database_epoch_ns(context.database_now)
    require(row["prepared_at_epoch_ns"] <= now < row["expires_at_epoch_ns"] <= verified["expires_at_epoch_ns"]
        and verified["issued_at_epoch_ns"] <= row["prepared_at_epoch_ns"])
    audit = stage(row, context.database_now)
    stored = {**row, "evidence_kind": verified["evidence_kind"], "record_binding_digest": verified["record_binding_digest"],
        "verification_receipt_digest": verified["verification_receipt_digest"],
        "genesis_transition_digest": audit["transition"]["transition_digest"]}
    return core.KernelTransition(mutations=(*changes, *legacy._fresh_audit_mutations(context,
        operation_id=legacy._operation_id(PREPARE, context.request_digest), outbox_rows=(audit["outbox"],)),
        core.mutation(operation=PREPARE, selected=context.exact("policy_authority_transition_audits",
            {"transition_digest": stored["genesis_transition_digest"]}), row=audit["transition"]),
        core.mutation(operation=PREPARE, selected=selected, row=stored)),
        result={"ok": True, "idempotent": False, **stored, "audit_submission": audit["transition"]}, work_units=160)


def _finalize(context, row, verified, changes):
    from serverware import db
    from serverware import authority_transition_policy as legacy
    digest = context.arguments["genesisPreparationDigest"]
    preparation = legacy._row(context.exact("policy_authority_genesis_preparations", {"genesis_preparation_digest": digest}))
    # Project the exact originally signed fields, never post-signing DB columns.
    base = {key: preparation[key] for key in legacy._GENESIS_RECORD_FIELDS}
    legacy._genesis_record(base)
    _separate(context, "authority_genesis", base["signing_key_id"])
    historical = trust.historical(context, receipt_digest=preparation["verification_receipt_digest"], **evidence(PREPARE, base))
    require(preparation["evidence_kind"] == historical["evidence_kind"] == "authority_genesis"
        and preparation["record_binding_digest"] == historical["record_binding_digest"], "genesis preparation verification join changed")
    store = context.genesis_policy["auditStoreIdentityDigest"]
    signer = context.genesis_policy["auditSignerPublicKeyDigest"]
    require(context.arguments["auditStoreIdentityDigest"] == row["audit_store_identity_digest"] == store
        and row["audit_ledger_namespace"] == db._POLICY_AUTHORITY_AUDIT_LEDGER_NAMESPACE
        and row["signing_key_id"] == row["audit_signer_public_key_digest"] == signer
        and row["transition_digest"] == preparation["genesis_transition_digest"], "genesis inclusion purpose differs")
    audit = legacy._row(context.exact("policy_authority_transition_audits", {"transition_digest": row["transition_digest"]}))
    outbox_selected = context.exact("metadata_audit_outbox", {"id": row["outbox_id"]})
    outbox = legacy._row(outbox_selected)
    original_stage = stage(base, context.database_now)
    existing = context.exact("policy_authority_genesis_finalizations", {"genesis_preparation_digest": digest})
    delivery = context.arguments["schema"] == FINALIZE_DELIVERY_SCHEMA and not existing["present"]
    require(audit == original_stage["transition"]
        and audit["outbox_id"] == row["outbox_id"] and audit["outbox_event_digest"] == row["outbox_event_digest"]
        and audit["event_type"] == "policy.authority.genesis.prepared" and audit["entity_kind"] == "activation_genesis"
        and audit["entity_id"] == preparation["policy_hash"] and audit["state_digest"] == digest
        and outbox["event_digest"] == row["outbox_event_digest"]
        and (delivery or outbox["status"] == "audited" and outbox["audit_event_hash"] == row["audit_event_hash"]),
        "genesis requires the actual terminal audited outbox")
    if delivery:
        pending_outbox(outbox, original_stage["outbox"])
    receipt = {**row, "evidence_kind": verified["evidence_kind"], "record_binding_digest": verified["record_binding_digest"],
        "verification_receipt_digest": verified["verification_receipt_digest"],
        **{key: verified[key] for key in ("issued_at_epoch_ns", "expires_at_epoch_ns", "verified_at_epoch_ns")}}
    receipt_selected = context.exact("policy_authority_audit_inclusion_receipts",
        {"inclusion_receipt_envelope_digest": row["inclusion_receipt_envelope_digest"]})
    if existing["present"]:
        final = legacy._row(existing)
        require(legacy._row(receipt_selected) == receipt
            and final["inclusion_receipt_envelope_digest"] == row["inclusion_receipt_envelope_digest"], "genesis final replay differs")
        return core.KernelTransition(mutations=(), result={"ok": True, "idempotent": True, **final}, work_units=160)
    now = legacy._database_epoch_ns(context.database_now)
    require(preparation["prepared_at_epoch_ns"] <= now < preparation["expires_at_epoch_ns"]
        and not context.exact("policy_high_water", {"scope": "active"})["present"]
        and not context.present_rows("policy_publications") and not receipt_selected["present"], "genesis is no longer empty/current")
    head_selected = context.exact("policy_authority_audit_inclusion_heads", {"audit_store_identity_digest": store})
    head = legacy._row(head_selected) if head_selected["present"] else None
    require(row["audit_sequence"] == (head["audit_sequence"] + 1 if head else 1)
        and row["previous_audit_event_hash"] == (head["audit_event_hash"] if head else None), "genesis audit head changed")
    require(row["inclusion_root_digest"] == db._policy_authority_audit_inclusion_root(
        audit_store_identity_digest=store, audit_ledger_namespace=row["audit_ledger_namespace"], audit_signer_public_key_digest=signer,
        audit_sequence=row["audit_sequence"], previous_root_digest=head["inclusion_root_digest"] if head else None,
        audit_event_hash=row["audit_event_hash"], outbox_event_digest=row["outbox_event_digest"], transition_digest=row["transition_digest"]),
        "genesis signed inclusion root differs from actual chain")
    material = {"genesisPreparationDigest": digest, "highWaterDigest": preparation["high_water_digest"],
        "inclusionReceiptEnvelopeDigest": row["inclusion_receipt_envelope_digest"], "finalizedAtEpochNs": now}
    final = {key: preparation[key] for key in ("genesis_preparation_digest", "policy_id", "policy_sequence", "rollback_epoch",
        "policy_hash", "high_water_digest", "genesis_transition_digest")}
    final.update(inclusion_receipt_envelope_digest=row["inclusion_receipt_envelope_digest"], finalized_at_epoch_ns=now,
        finalization_digest=db._policy_authority_domain_digest(b"serverware.policyAuthorityGenesisFinalization/v1", db.dumps(material).encode("ascii")))
    now_iso = legacy._database_iso(context.database_now)
    if delivery:
        # Full-row CAS in the same v9 transaction as the inclusion, high-water
        # and finalization. The signature above binds the independent audit
        # event; neither an input status nor an append response is authority.
        changes = (*changes, core.mutation(operation=FINALIZE, selected=outbox_selected,
            row={**outbox, "status": "audited", "audited_at": now_iso,
                "audit_event_hash": row["audit_event_hash"]}))
    high = {"scope": "active", "policy_id": preparation["policy_id"], "sequence": preparation["policy_sequence"],
        "rollback_epoch": preparation["rollback_epoch"], "policy_hash": preparation["policy_hash"], "updated_at": now_iso}
    publication = {**high, "status": "committed", "previous_policy_hash": None, "created_at": now_iso, "committed_at": now_iso}
    next_head = {key: row[key] for key in ("audit_store_identity_digest", "audit_ledger_namespace", "audit_signer_public_key_digest",
        "signing_key_id", "audit_sequence", "audit_event_hash", "inclusion_root_digest", "inclusion_receipt_envelope_digest")}
    next_head["updated_at_epoch_ns"] = now
    return core.KernelTransition(mutations=(*changes,
        core.mutation(operation=FINALIZE, selected=receipt_selected, row=receipt),
        core.mutation(operation=FINALIZE, selected=head_selected, row=next_head),
        core.mutation(operation=FINALIZE, selected=context.exact("policy_publications", {"policy_hash": high["policy_hash"]}), row=publication),
        core.mutation(operation=FINALIZE, selected=context.exact("policy_high_water", {"scope": "active"}), row=high),
        core.mutation(operation=FINALIZE, selected=existing, row=final)),
        result={"ok": True, "idempotent": False, **final}, work_units=224)
