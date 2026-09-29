"""Pure ordered canary state overlay used before and inside one transaction.

The preflight overlay addresses queries only. It cannot commit or attest rows.
The kernel repeats this program over the authenticated complete before-state.
There is no SQL adapter, runtime connection, generic callback or DML fallback.
"""
from datetime import timezone

from serverware import authority_policy_canary as profile
from serverware import authority_policy_canary_tables as tables
from serverware import authority_policy_canary_evidence as runtime_signatures
from serverware import authority_policy_candidate_evidence as static_signatures
from serverware import authority_transition_policy as audit
from serverware import authority_transition_quota as shared


def exact(row, other, fields):
    profile.require(row is not None and other is not None and all(row[name] == other[name] for name in fields),
        "canary original predecessor association changed")


def evidence_inputs(item, prefix, binding):
    envelope = item[prefix + "_envelope_json"]
    return {"envelope_json": envelope,
        "envelope_digest": profile.sha256(envelope.encode("ascii")) if prefix == "state" else item[prefix + "_envelope_digest"],
        "payload_json": item[prefix + "_payload_json"],
        "payload_digest": item["state_digest"] if prefix == "state" else item[prefix + "_payload_digest"],
        **{name: item[name] for name in ("signature_algorithm", "signing_key_id", "signature", "signature_digest")},
        "record_binding": binding}


def apply_verification(item, verified, *, interval=False, verified_at=False):
    for name in ("evidence_kind", "record_binding_digest", "verification_receipt_digest"):
        item[name] = verified[name]
    if interval:
        item.update(issued_at_epoch_ns=verified["issued_at_epoch_ns"], expires_at_epoch_ns=verified["expires_at_epoch_ns"])
    if verified_at:
        item["verified_at_epoch_ns"] = verified["verified_at_epoch_ns"]


class State:
    def __init__(self, snapshot, events, database_now, statement):
        tables.snapshot(snapshot, events)
        self.database_now, self.now = database_now, shared._database_epoch_ns(database_now)
        self.statement = statement
        self.before = {table: {profile.canonical(tables.key(table, row)): dict(row) for row in snapshot[table]} for table in tables.TABLES}
        self.current = {table: {key: dict(row) for key, row in rows.items()} for table, rows in self.before.items()}
        self.current.update({table: {} for table in tables.AUDIT_TABLES})
        self.changed, self.work_units = {}, 1

    def charge(self, units):
        self.work_units += units
        profile.require(self.work_units <= profile.LIMITS["workUnits"], "canary batch exceeds its whole-transaction work bound")

    def rows(self, table):
        profile.require(table in self.current)
        rows = list(self.current[table].values())
        self.charge(len(rows) + 1)
        return rows

    def matching(self, table, **fields):
        return [row for row in self.rows(table) if all(row[name] == value for name, value in fields.items())]

    def one(self, table, *, optional=False, **fields):
        rows = self.matching(table, **fields)
        profile.require(len(rows) == 1 or (optional and not rows), "canary protected predecessor is missing or ambiguous: " + table)
        return rows[0] if rows else None

    def put(self, table, row, *, replace=False):
        profile.require(table in self.current and type(row) is dict)
        identity = profile.canonical(tables.key(table, row))
        prior = self.current[table].get(identity)
        if prior is not None and not replace:
            profile.require(prior == row, "canary immutable original identity was reused")
            return prior
        self.current[table][identity] = dict(row)
        if table in tables.TABLES:
            profile.require(len(self.current[table]) <= profile.MAX_ROWS, "canary retained population capacity is exhausted")
        if prior != row:
            self.changed[(table, identity)] = dict(row)
            profile.require(len(self.changed) <= profile.LIMITS["mutations"], "canary batch exceeds its atomic mutation bound")
        self.charge(1)
        return row

    def transition(self, **values):
        stage = audit._audit_stage(**values, created_at=self.database_now.astimezone(timezone.utc).isoformat())
        self.put("metadata_audit_outbox", stage["outbox"])
        self.put("policy_authority_transition_audits", stage["transition"])
        return stage["transition"]["transition_digest"]

    def static(self, kind, item, prefix, binding, *, historical=False, persist=True):
        inputs = evidence_inputs(item, prefix, binding)
        revoked = self.rows("policy_authority_trusted_key_revocations")
        profile.require(not any(row["evidence_kind"] == kind and row["signing_key_id"] == item["signing_key_id"] for row in revoked),
            "canary static signing authority is currently revoked")
        if historical:
            receipt = self.one("policy_authority_evidence_verifications", verification_receipt_digest=item["verification_receipt_digest"])
            verified = receipt["verified_at_epoch_ns"]
            profile.require(type(verified) is int and 0 < verified <= self.now and verified >= receipt["issued_at_epoch_ns"])
            keys = [row for row in self.rows("policy_authority_trusted_keys")
                if row["evidence_kind"] == kind and row["installed_at_epoch_ns"] <= verified]
            profile.require(bool(keys))
            key = max(keys, key=lambda row: row["key_revision"])
            head = {"evidence_kind": kind, "head_key_revision": key["key_revision"],
                "head_signing_key_id": key["signing_key_id"], "head_public_key_digest": key["public_key_digest"]}
            sequence = max((row["revocation_sequence"] for row in revoked if row["revoked_at_epoch_ns"] <= verified), default=0)
        else:
            verified = self.now
            head = self.one("policy_authority_trusted_key_heads", evidence_kind=kind)
            key = self.one("policy_authority_trusted_keys", evidence_kind=kind, key_revision=head["head_key_revision"])
            sequence = max((row["revocation_sequence"] for row in revoked), default=0)
        self.charge(32)
        computed = static_signatures.verify_static_original(evidence_kind=kind, **inputs, key=key, key_head=head,
            revocation=None, revocation_sequence=sequence, verified_at_epoch_ns=verified)
        if historical:
            profile.require(computed == receipt, "historical static signature/receipt changed")
            return receipt
        if not persist:
            return computed
        existing = self.matching("policy_authority_evidence_verifications", signature_digest=computed["signature_digest"],
            record_binding_digest=computed["record_binding_digest"])
        profile.require(len(existing) <= 1)
        if existing:
            profile.require(all(existing[0][name] == value for name, value in computed.items()
                if name not in {"verification_receipt_digest", "verified_at_epoch_ns"}))
            return existing[0]
        return self.put("policy_authority_evidence_verifications", computed)

    def runtime(self, kind, item, prefix, binding, *, historical=False, persist=True):
        from serverware import db
        role = db._POLICY_AUTHORITY_RUNTIME_EVIDENCE_DOMAINS[kind][0]
        key = self.one("policy_runtime_role_keys", assignment_envelope_digest=item["assignment_envelope_digest"],
            member_ordinal=item["member_ordinal"], role=role, signing_key_id=item["signing_key_id"])
        member = self.one("policy_canary_assignment_members", assignment_envelope_digest=item["assignment_envelope_digest"],
            member_ordinal=item["member_ordinal"])
        revocations = self.rows("policy_runtime_role_key_revocations")
        verified_at = self.now
        if historical:
            receipt = self.one("policy_runtime_evidence_verifications", verification_receipt_digest=item["verification_receipt_digest"])
            verified_at = receipt["verified_at_epoch_ns"]
            profile.require(type(verified_at) is int and receipt["issued_at_epoch_ns"] <= verified_at <= self.now)
            revocations = [row for row in revocations if row["revoked_at_epoch_ns"] <= verified_at]
            attestation = self.one("policy_runtime_attestations", attestation_receipt_envelope_digest=key["attestation_receipt_envelope_digest"])
            self.static("runtime_attestation", attestation, "attestation_receipt",
                db._candidate_authority_signed_record(attestation, current_prefix="attestation_receipt"), historical=True)
        self.charge(32)
        computed = runtime_signatures.verify_runtime_original(evidence_kind=kind, **evidence_inputs(item, prefix, binding),
            **{name: item[name] for name in ("assignment_envelope_digest", "member_ordinal", "canary_id", "fleet_id",
                "membership_revision", "instance_id", "boot_id")}, key=key, member=member, revocations=revocations,
            verified_at_epoch_ns=verified_at)
        if historical:
            profile.require(computed == receipt, "historical runtime signature/receipt changed")
            return receipt
        existing = self.matching("policy_runtime_evidence_verifications", signature_digest=computed["signature_digest"],
            record_binding_digest=computed["record_binding_digest"])
        profile.require(len(existing) <= 1)
        if existing:
            profile.require(all(existing[0][name] == value for name, value in computed.items() if name != "verified_at_epoch_ns"))
        elif persist:
            self.put("policy_runtime_evidence_verifications", computed)
        return computed

    def runtime_context(self, item, *, require_load=True):
        from serverware import db
        assignment = self.one("policy_canary_assignments", canary_id=item["canary_id"])
        member = self.one("policy_canary_assignment_members", assignment_envelope_digest=assignment["assignment_envelope_digest"],
            instance_id=item["instance_id"], boot_id=item["boot_id"])
        receipt = self.one("policy_canary_load_receipts", optional=not require_load,
            assignment_envelope_digest=assignment["assignment_envelope_digest"], member_ordinal=member["member_ordinal"],
            canary_id=item["canary_id"], instance_id=item["instance_id"], boot_id=item["boot_id"])
        context = {**assignment, **member}
        for field in ("load_receipt_envelope_digest", "load_receipt_payload_digest", "loaded_at_epoch_ns", "load_receipt_payload_json"):
            context[field] = None if receipt is None else receipt[field]
        policy_material = {"artifactEnvelopeDigest": context["artifact_envelope_digest"], "artifactPayloadDigest": context["artifact_payload_digest"],
            "candidatePolicyHash": context["candidate_policy_hash"], "compilerConfigurationSha256": context["compiler_config_digest"],
            "compilerSha256": context["compiler_digest"], "evaluatorAbiSha256": context["evaluator_abi_digest"],
            "policyBundleSha256": context["policy_bundle_digest"], "policySchemaSha256": context["policy_schema_digest"],
            "semanticModelSha256": context["semantic_model_digest"]}
        runtime_material = {"assignmentEnvelopeDigest": context["assignment_envelope_digest"], "assignmentRevision": context["assignment_revision"],
            "attestationReceiptEnvelopeDigest": context["attestation_receipt_envelope_digest"], "bootId": context["boot_id"],
            "canaryId": item["canary_id"], "fleetId": context["fleet_id"], "instanceId": context["instance_id"],
            "loadReceiptEnvelopeDigest": context["load_receipt_envelope_digest"], "memberId": context["member_id"],
            "memberOrdinal": context["member_ordinal"], "membershipRevision": context["membership_revision"],
            "membershipRootSha256": context["membership_root_digest"], "runtimeSha256": context["runtime_digest"],
            "teeMeasurementSha256": context["tee_measurement_digest"]}
        context["policy_identity_digest"] = db._policy_authority_domain_digest(b"serverware.policyShadowPolicyIdentity/v1", profile.canonical(policy_material))
        context["runtime_identity_digest"] = db._policy_authority_domain_digest(b"serverware.policyShadowRuntimeIdentity/v1", profile.canonical(runtime_material))
        return context

    def reverify_runtime_row(self, conn, *, evidence_kind, item, current_prefix, historical=False):
        from serverware import db
        from serverware import authority_transition_policy_canary_custody as custody
        profile.require(conn is None)
        signed = {name: value for name, value in item.items() if name not in {"issued_at_epoch_ns", "expires_at_epoch_ns"}}
        if evidence_kind == "generation_publication":
            signed.pop("management_request_json", None)
        fields = tuple(name for name in custody.RUNTIME + custody.INSTANCE if name in item)
        exact(item, self.runtime_context(item), fields)
        return self.runtime(evidence_kind, item, current_prefix, db._candidate_authority_signed_record(signed, current_prefix=current_prefix),
            historical=historical, persist=False)

    def reverify_custody_row(self, conn, item, *, require_current_head):
        from serverware import authority_transition_policy_canary_custody as custody
        profile.require(conn is None)
        return custody.reverify(self, item, current=require_current_head)
