"""Inactive, bounded aggregate trust-stage row semantics.

The composer must authenticate the original request/assertion, candidate bundle
and root policy, configured approval policy, cutoff and COMPLETE selected-row
union before calling this helper. Neither KernelContext nor candidate_roots is
a proof or authority token. In particular, enumerating the rows below does not
prove that an omitted credential, dependent or registration challenge is absent.

The private query adapter declares the actual complete populations and proved
selected-row joins. The mutation adapter renders the aggregate effects through
the source templates, but neither adapter registers a kernel or authenticates
its inputs. The owning composer must admit the complete query family and
finalize the one shared audit-capacity CAS before calculating after-roots.

All phases share the revocation source ceilings: 192 business selections, 136
FINAL business effects and 2048 semantic work units. There is no per-credential
allowance. The original H/B/N meter is also cumulative throughout. Overflow
rejects the entire calculation; nothing here commits a partial stage.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from catchplate import authority_contract as authority
from catchplate import authority_audit_capacity as capacity
from catchplate import authority_complete_query as complete
from catchplate import authority_complete_query_batch as capture
from catchplate import authority_transition_core as core
from catchplate import authority_transition_webauthn as revocation
from catchplate import authority_webauthn_trust as trust
from catchplate import webauthn_credential_trust as classifier
from catchplate.authority_query_read_work import _ValidationWork


OPERATION = "webauthn.trust.stage"
MAX_SELECTED_ROWS = 192
MAX_EFFECTS = 136
MAX_WORK_UNITS = 2048
MAX_JSON_BYTES = 2 * 1024 * 1024
_ARGUMENT_FIELDS = frozenset({"previous_bundle_digest", "bundle_digest", "sequence",
    "rollback_epoch", "signing_key_id", "bundle", "payload_digest", "actor_id",
    "reason", "approval_id", "audit_event", "withdrawn_credential_ids", "query_hints", "businessIntent"})
_SELECTED_FIELDS = frozenset({"table", "key", "keyDigest", "present", "row", "contractSelector"})
_TABLE_KEYS = {
    "webauthn_credentials": "id", "webauthn_challenges": "id",
    "oidc_browser_sessions": "id", "approval_grants": "id",
    "control_plane_approvals": "id", "metadata_audit_outbox": "id",
    "webauthn_trust_publications": "id", "rbac_role_bindings": "subject_id",
    "webauthn_trust_publication_high_water": "authority_scope",
}


class WebAuthnTrustStageError(ValueError):
    pass


def _same(left, right, work, label):
    work.prepare_comparison(left, right)
    if type(left) is not type(right) or left != right:
        raise WebAuthnTrustStageError(label)


def _text(value, label, maximum=1024):
    if type(value) is not str or not value or "\x00" in value:
        raise WebAuthnTrustStageError(label + " is not exact nonempty text")
    core.require_text(value, label, maximum_bytes=maximum)


def _integer(value, label, minimum=0):
    if type(value) is not int or not minimum <= value <= (1 << 63) - 1:
        raise WebAuthnTrustStageError(label + " is not a source-bounded integer")


def _json(value, work):
    size, _ = work.prepare_encoding(value)
    if size > MAX_JSON_BYTES:
        raise WebAuthnTrustStageError("stage JSON exceeds the existing 2 MiB bound")
    encoded = core.canonical_bytes(value)
    work.charge(input_bytes=len(encoded))
    return encoded.decode("ascii")


def _ids(values, label, work):
    if type(values) is not list or len(values) > MAX_SELECTED_ROWS:
        raise WebAuthnTrustStageError(label + " is not a bounded exact list")
    for value in values:
        complete._source_id(value, work=work)
    work.prepare_copy(values)
    ordered = sorted(values)
    _same(values, ordered, work, label + " is not sorted")
    work.prepare_copy(values)
    if len(set(values)) != len(values):
        raise WebAuthnTrustStageError(label + " repeats an identity")
    return values


def _arguments(values, work):
    if type(values) is not dict or set(values) != _ARGUMENT_FIELDS:
        raise WebAuthnTrustStageError("stage arguments are not closed")
    for name in ("bundle_digest", "payload_digest"):
        core.require_digest(values[name], name)
    if values["previous_bundle_digest"] is not None:
        core.require_digest(values["previous_bundle_digest"], "previous bundle digest")
    for name, minimum in (("sequence", 1), ("rollback_epoch", 0)):
        _integer(values[name], name, minimum)
    for name in ("signing_key_id", "actor_id"):
        _text(values[name], name)
    if values["approval_id"] is not None:
        _text(values["approval_id"], "stage approval ID")
    if values["reason"] is not None:
        _text(values["reason"], "stage reason", 16_384)
    if type(values["bundle"]) is not dict or type(values["audit_event"]) is not dict:
        raise WebAuthnTrustStageError("stage bundle and audit context must be exact objects")
    withdrawn = _ids(values["withdrawn_credential_ids"], "withdrawal hints", work)
    hints = values["query_hints"]
    if type(hints) is not dict or set(hints) != {
            "live_credential_ids", "registration_challenge_ids", "withdrawals"}:
        raise WebAuthnTrustStageError("stage complete query hints are not closed")
    live = _ids(hints["live_credential_ids"], "live trusted credential hints", work)
    registrations = _ids(hints["registration_challenge_ids"], "global registration hints", work)
    withdrawals = hints["withdrawals"]
    if type(withdrawals) is not list or len(withdrawals) != len(withdrawn):
        raise WebAuthnTrustStageError("stage dependent hints differ from withdrawal inventory")
    total = len(live) + len(registrations)
    for identifier, item in zip(withdrawn, withdrawals):
        if type(item) is not dict or set(item) != {"credential_record_id", "oidc_session_ids",
                "approval_grant_ids", "control_plane_approval_ids"}:
            raise WebAuthnTrustStageError("stage withdrawal dependency hints are not closed")
        _same(item["credential_record_id"], identifier, work, "stage withdrawal hint order changed")
        work.prepare_scan(live)
        if identifier not in live:
            raise WebAuthnTrustStageError("withdrawal is outside the hinted live trusted population")
        for name in ("oidc_session_ids", "approval_grant_ids", "control_plane_approval_ids"):
            total += len(_ids(item[name], name, work))
    if total > MAX_SELECTED_ROWS:
        raise WebAuthnTrustStageError("stage hinted union exceeds the single business bound")
    work.prepare_copy(values)
    semantic = {name: values[name] for name in _ARGUMENT_FIELDS - {"businessIntent"}}
    _same(values["businessIntent"], authority._synthesize_business_intent(OPERATION, semantic, work=work),
        work, "stage business intent changed")
    return values


def _assertion_scope(evidence, request_digest, work):
    """Bind mandatory independently verified evidence; do not authenticate it."""
    if type(evidence) is not dict:
        raise WebAuthnTrustStageError("stage requires actual independently verified assertion evidence")
    core.require_digest(request_digest, "stage request digest")
    for name in ("credentialRecordId", "challengeId"):
        _text(evidence.get(name), "stage assertion " + name)
    work.prepare_utf8(OPERATION)
    work.prepare_utf8(request_digest)
    work.charge(hashes=1)
    operation_id = core.framed_digest("catchplate.policyAuthorityOperation/v2",
        OPERATION.encode("ascii"), request_digest.encode("ascii"))
    for actual, expected in ((evidence.get("operation"), OPERATION),
            (evidence.get("requestDigest"), request_digest), (evidence.get("operationId"), operation_id)):
        _same(actual, expected, work, "stage assertion request identity changed")
    return evidence


def _query_recipe_on_work(*, arguments, database_now, request_digest,
        verified_webauthn_evidence, work):
    """Declare actual business queries; common capacity is appended by its owner.

    Evidence, clock and roots must be independently admitted. The supplied
    hints bound complete populations; they never authorize omission or an SQL
    page in place of a genuine counted/primary proof.
    """
    ledger = capture._SharedLedger(work)
    if type(database_now) is not datetime or database_now.tzinfo is not timezone.utc:
        raise WebAuthnTrustStageError("stage query cutoff is not exact UTC")
    owned = capture._JSONCapture(ledger).visit({"arguments": arguments,
        "evidence": verified_webauthn_evidence})
    values = _arguments(owned["arguments"], work)
    evidence = _assertion_scope(owned["evidence"], request_digest, work)
    cutoff = complete.cutoff_microseconds(database_now)
    result = []

    def exact(name, table, column, value, *, absent=False):
        result.append(core.BoundedQuery(query_id=core.query_program_id(OPERATION, name, table),
            table=table, predicates=(core.QueryPredicate(column, "eq", value),),
            order_by=(core.QueryOrder(column),), maximum_rows=1,
            absent_key={column: value}, require_absence=absent))

    def reference_query(name, table, column, approval_column):
        key = {"id": values["approval_id"]}
        work.prepare_encoding(key, shallow_copies=1)
        reference = core.SelectedRowFieldReference("control_plane_approvals", key, approval_column)
        # A null bound credential produces zero rows, not an invented PK
        # absence. The configured approval policy is checked by the kernel.
        result.append(core.BoundedQuery(query_id=core.query_program_id(OPERATION, name, table),
            table=table, predicates=(core.QueryPredicate(column, "eq", reference),),
            order_by=(core.QueryOrder(column),), maximum_rows=1))

    exact("stage_assertion_credential", "webauthn_credentials", "id", evidence["credentialRecordId"])
    exact("stage_assertion_challenge", "webauthn_challenges", "id", evidence["challengeId"])
    result.extend(revocation._trust_queries(OPERATION, work=work))
    exact("stage_actor_role", "rbac_role_bindings", "subject_id", values["actor_id"])
    candidate = core._deterministic_uuid(operation=OPERATION, request_digest=request_digest,
        purpose="trust-publication", work=work)
    exact("stage_new_publication", trust.PUBLICATION_TABLE, "id", candidate, absent=True)
    if values["approval_id"] is not None:
        exact("stage_consumed_approval", "control_plane_approvals", "id", values["approval_id"])
        reference_query("stage_approver_role", "rbac_role_bindings", "subject_id", "approved_by")
        reference_query("stage_approver_credential", "webauthn_credentials", "id", "approver_webauthn_credential_id")
        audit = core._deterministic_uuid(operation=OPERATION, request_digest=request_digest,
            purpose="trust-stage-approval-consumed:" + values["approval_id"], work=work)
        exact("stage_consumed_approval_audit", "metadata_audit_outbox", "id", audit, absent=True)
    invalidated = set()
    for item in values["query_hints"]["withdrawals"]:
        work.prepare_copy(item["control_plane_approval_ids"])
        invalidated.update(item["control_plane_approval_ids"])
    work.prepare_copy(values["query_hints"]["withdrawals"])
    for ordinal, identifier in enumerate(sorted(invalidated)):
        audit = core._deterministic_uuid(operation=OPERATION, request_digest=request_digest,
            purpose="trust-stage-approval-invalidated:" + identifier, work=work)
        exact("stage_invalidated_approval_audit_" + str(ordinal), "metadata_audit_outbox", "id", audit, absent=True)
    for role in complete.family_roles(OPERATION, arguments=values):
        result.append(complete._bind_query(OPERATION, role, arguments=values, cutoff_us=cutoff, work=work))
    queries = tuple(result)
    if (len(queries) > MAX_SELECTED_ROWS or sum(query.maximum_rows for query in queries) > MAX_SELECTED_ROWS
            or sum(query.work_units for query in queries) > MAX_WORK_UNITS):
        raise WebAuthnTrustStageError("stage query program exceeds its single business allowance")
    revocation._prepare_complete_copies(queries, work)
    return core.close_queries(OPERATION, queries)


class _Overlay:
    """One fixed table/key map; repeated updates retain the original CAS row."""

    def __init__(self, selected, work):
        self.work = work
        self.selected = selected
        self.original = {}
        self.current = {}
        self.changed = set()
        # Fixed authorization/publication scaffolding, then actual selection
        # visits, root-classification bound, effect writes and audit creations.
        self.units = 64
        for item in selected:
            self.tick(1)
            if (type(item) is not dict or set(item) != _SELECTED_FIELDS
                    or type(item["table"]) is not str or item["table"] not in _TABLE_KEYS
                    or type(item["key"]) is not dict
                    or set(item["key"]) != {_TABLE_KEYS[item["table"]]}
                    or type(item["present"]) is not bool
                    or (item["present"] and type(item["row"]) is not dict)
                    or (not item["present"] and item["row"] is not None)):
                raise WebAuthnTrustStageError("stage selection is not a closed business row")
            key_value = item["key"][_TABLE_KEYS[item["table"]]]
            _text(key_value, "stage primary key")
            address = item["table"], key_value
            if address in self.original:
                raise WebAuthnTrustStageError("stage selection repeats a primary key")
            core.require_digest(item["keyDigest"], "stage selected key digest")
            work.prepare_encoding(item["key"])
            work.prepare_utf8(item["table"])
            work.charge(hashes=1)
            digest = core.framed_digest("catchplate.policyAuthorityBusinessKey/v1",
                item["table"].encode("ascii"), core.canonical_bytes(item["key"]))
            _same(digest, item["keyDigest"], work, "stage primary-key commitment changed")
            if item["present"]:
                _same(item["row"].get(_TABLE_KEYS[item["table"]]), key_value,
                    work, "stage row escaped its selected primary key")
            self.original[address] = item
            self.current[address] = item["row"]

    def tick(self, count):
        if count > MAX_WORK_UNITS - self.units:
            raise WebAuthnTrustStageError("whole trust stage exceeds semantic work allowance")
        self.units += count

    def row(self, table, key, *, absent=False):
        self.tick(1)
        address = table, key
        if address not in self.original or (self.current[address] is None) != absent:
            raise WebAuthnTrustStageError("stage exact row is absent, present or unselected unexpectedly")
        return self.current[address]

    def put(self, table, key, row):
        self.tick(4)
        address = table, key
        if address not in self.original:
            raise WebAuthnTrustStageError("stage effect has no original selected row")
        _same(row.get(_TABLE_KEYS[table]), key, self.work, "stage effect changes its primary key")
        if address not in self.changed and len(self.changed) >= MAX_EFFECTS:
            raise WebAuthnTrustStageError("whole trust stage exceeds final business effect allowance")
        self.work.prepare_copy(row)
        self.current[address] = dict(row)
        self.changed.add(address)

    def update(self, table, key, changes):
        row = self.row(table, key)
        self.work.prepare_copy(row)
        self.work.prepare_copy(changes)
        self.put(table, key, {**row, **changes})

    def effects(self):
        # The whole owned selected graph conservatively prepays the address
        # list/sort, without first making an uncharged variable-sized list.
        self.work.prepare_copy(self.selected)
        ordered = sorted(self.changed)
        self.work.prepare_copy(ordered)
        return tuple((self.original[address], self.current[address]) for address in ordered)


def _admin(overlay, subject):
    row = overlay.row("rbac_role_bindings", subject)
    roles = revocation._stored_json(row.get("roles_json"), work=overlay.work)
    if (type(roles) is not list or len(roles) > 64
            or any(type(role) is not str for role in roles)
            or row.get("status") != "active" or "admin" not in roles):
        raise WebAuthnTrustStageError("trust publication requires current selected admin authority")
    _same(_json(roles, overlay.work), row["roles_json"], overlay.work,
        "stage RBAC roles are not canonical")
    overlay.tick(len(roles))


def _audit(overlay, context, *, purpose, event_type, actor_type, actor_id, event):
    overlay.tick(8)
    item_id = core._deterministic_uuid(operation=OPERATION,
        request_digest=context.request_digest, purpose=purpose, work=overlay.work)
    overlay.row("metadata_audit_outbox", item_id, absent=True)
    event_json = _json(event, overlay.work)
    overlay.work.prepare_utf8(event_json)
    overlay.work.charge(hashes=1)
    overlay.put("metadata_audit_outbox", item_id, {
        "id": item_id, "event_type": event_type, "actor_type": actor_type,
        "actor_id": actor_id, "event_json": event_json,
        "event_digest": core.framed_digest("catchplate.metadataAuditOutboxEvent/v1", event_json.encode("ascii")),
        "storage_format_version": 2, "status": "pending", "claim_id": None,
        "claimed_at": None, "attempts": 0, "audited_at": None,
        "audit_event_hash": None, "last_error": None, "created_at": context.database_now.isoformat()})


def _assertion(context, values, overlay):
    """Repeat actual revocation assertion row bindings without rendering writes.

    The genuine signature and evidence-schema admission belong to the owning
    verifier. These selected-row checks do not replace that cryptography.
    """
    work, evidence = overlay.work, context.verified_webauthn_evidence
    if type(evidence) is not dict:
        raise WebAuthnTrustStageError("stage requires independently verified assertion evidence")
    work.prepare_utf8(OPERATION)
    work.prepare_utf8(context.request_digest)
    work.charge(hashes=1)
    operation_id = core.framed_digest("catchplate.policyAuthorityOperation/v2",
        OPERATION.encode("ascii"), context.request_digest.encode("ascii"))
    credential = overlay.row("webauthn_credentials", evidence["credentialRecordId"])
    challenge = overlay.row("webauthn_challenges", evidence["challengeId"])
    if set(challenge) != revocation._CHALLENGE_FIELDS:
        raise WebAuthnTrustStageError("stage assertion challenge is not closed")
    payload = revocation._stored_json(challenge["payload_json"], work=work)
    if type(payload) is not dict:
        raise WebAuthnTrustStageError("stage assertion challenge payload is not an object")
    work.prepare_copy(payload)
    public = {**payload, "challengeId": challenge["id"], "challenge": challenge["challenge"],
        "challengeRowDigest": revocation._challenge_row_digest(challenge, work=work)}
    raw = revocation._challenge_bytes(challenge["challenge"], work=work)
    for actual, expected in (
        (evidence.get("operation"), OPERATION), (evidence.get("operationId"), operation_id),
        (evidence.get("requestDigest"), context.request_digest),
        (credential.get("user_id"), values["actor_id"]), (challenge.get("user_id"), values["actor_id"]),
        (credential.get("credential_id"), evidence.get("credentialId")),
        (credential.get("sign_count"), evidence.get("priorCounter")),
        (challenge.get("challenge_type"), "policy_authority"), (challenge.get("scope_key"), operation_id),
        (payload.get("operationId"), operation_id), (payload.get("credentialId"), evidence.get("credentialId")),
        (payload.get("rpId"), evidence.get("rpId")), (payload.get("origin"), evidence.get("origin")),
        (evidence.get("challengeDigest"), revocation._challenge_public_digest(public, work=work)),
        (evidence.get("clientChallengeDigest"), revocation._sha256_bytes(raw, work=work))):
        _same(actual, expected, work, "stage assertion row binding changed")
    if (credential.get("revoked_at") is not None or challenge.get("used_at") is not None
            or revocation._utc(challenge.get("expires_at"), "assertion expiry", work=work) <= context.database_now):
        raise WebAuthnTrustStageError("stage assertion is not live in the original state")
    revocation._assertion_trust(context, credential, evidence, work=work)
    for field in ("priorCounter", "counter"):
        if type(evidence.get(field)) is not int or not 0 <= evidence[field] <= 2_147_483_647:
            raise WebAuthnTrustStageError("stage assertion counter is invalid")
    if evidence["counter"] <= evidence["priorCounter"]:
        raise WebAuthnTrustStageError("stage assertion counter is not increasing")
    return credential, challenge, evidence["counter"]


def _approval(context, values, overlay, *, required, require_webauthn):
    identifier = values["approval_id"]
    if identifier is None:
        if required:
            raise WebAuthnTrustStageError("configured trust publication requires a second approver")
        return None
    approval = overlay.row("control_plane_approvals", identifier)
    for actual, expected in ((approval.get("action"), "webauthn.trust.publish"),
            (approval.get("resource_id"), "webauthn-trust-bundle"),
            (approval.get("payload_digest"), values["payload_digest"]),
            (approval.get("requester_id"), values["actor_id"]), (approval.get("status"), "approved")):
        _same(actual, expected, overlay.work, "stage approval binding changed")
    approver = approval.get("approved_by")
    _text(approver, "stage approver")
    if (approver == values["actor_id"]
            or revocation._utc(approval.get("expires_at"), "approval expiry", work=overlay.work) <= context.database_now):
        raise WebAuthnTrustStageError("stage approval is self-approved or expired")
    _admin(overlay, approver)
    credential_id = approval.get("approver_webauthn_credential_id")
    if require_webauthn and credential_id is None:
        raise WebAuthnTrustStageError("stage approval requires a bound authenticator")
    if credential_id is not None:
        _text(credential_id, "approval authenticator")
        credential = overlay.row("webauthn_credentials", credential_id)
        if credential.get("revoked_at") is not None or credential.get("user_id") != approver:
            raise WebAuthnTrustStageError("stage approver authenticator is not currently owned and live")
    return approval


def _candidate_content(values, policy, work):
    """Join owned content to the same unsigned digest as verify_bundle.

    This is a content join, not the upstream signature/schema/certificate
    verification. In particular, an omitted certificateSha256 still requires
    the admitted root producer's real certificate-DER hash.
    """
    bundle = values["bundle"]
    metadata, roots = bundle.get("metadata"), bundle.get("roots")
    if type(metadata) is not dict or type(roots) is not list or len(roots) != len(policy.roots):
        raise WebAuthnTrustStageError("candidate bundle metadata or root inventory changed")
    _text(metadata.get("signature"), "candidate original signature", 256)
    for field, expected in (("sequence", values["sequence"]),
            ("rollbackEpoch", values["rollback_epoch"]), ("signingKeyId", values["signing_key_id"])):
        _same(metadata.get(field), expected, work, "candidate signed metadata differs from stage")
    work.prepare_copy(bundle)
    work.prepare_copy(metadata)
    unsigned = {**bundle, "metadata": {key: value for key, value in metadata.items() if key != "signature"}}
    unsigned_bytes = work.wire(unsigned)
    work.charge(input_bytes=len(unsigned_bytes))
    _same(revocation._sha256_bytes(unsigned_bytes, work=work), values["bundle_digest"], work,
        "candidate original unsigned content differs from its bundle digest")
    for item, root in zip(roots, policy.roots):
        if type(item) is not dict:
            raise WebAuthnTrustStageError("candidate signed root is not an object")
        for field, expected in (("id", root.id), ("authenticatorClass", root.authenticator_class)):
            _same(item.get(field), expected, work, "candidate root policy differs from signed content")
        aaguids = item.get("aaguids", [])
        if (type(aaguids) is not list or len(aaguids) > classifier.MAX_ROOT_AAGUIDS
                or any(type(value) is not str for value in aaguids)):
            raise WebAuthnTrustStageError("candidate root AAGUID inventory changed")
        work.prepare_copy(aaguids)
        work.prepare_copy(aaguids)
        work.prepare_copy(root.aaguids)
        work.prepare_copy(root.aaguids)
        # The actual wrapper stores tuple(frozenset(...)), whose iteration
        # order is not canonical. Its classifier has set-membership semantics.
        _same(sorted(set(aaguids)), sorted(set(root.aaguids)), work,
            "candidate root AAGUID policy changed")
        if "certificateSha256" in item:
            _same(item["certificateSha256"], root.certificate_sha256, work,
                "candidate declared certificate digest differs from admitted root")


def _publication_baseline(values, overlay):
    """Selected predicates still require independently proved completeness."""
    for (table, _), row in overlay.current.items():
        if table != trust.PUBLICATION_TABLE or row is None:
            continue
        overlay.tick(1)
        overlay.work.prepare_scan(row)
        if row.get("scope") != "global" or row.get("status") not in {"pending", "published"}:
            raise WebAuthnTrustStageError("selected trust publication has an unknown scope or state")
        if row["status"] == "pending":
            raise WebAuthnTrustStageError("trust staging is blocked by an existing pending publication")
        if row.get("bundle_digest") == values["bundle_digest"]:
            # Unlike the legacy direct DB helper, this aggregate never repeats
            # consumed approvals or prior cascades. Exact replay is external.
            raise WebAuthnTrustStageError("candidate bundle already has publication custody")
        _integer(row.get("rollback_epoch"), "stored rollback epoch")
        _integer(row.get("sequence"), "stored publication sequence", 1)
        if (values["rollback_epoch"] < row["rollback_epoch"] or
                (values["rollback_epoch"] == row["rollback_epoch"] and values["sequence"] <= row["sequence"])):
            raise WebAuthnTrustStageError("candidate is not monotonic against selected publication history")


def _population_hints(context, values, overlay):
    """Join each hint to the observed complete prestate before overlay writes.

    The caller still must prove these exact ranges and their primary joins.
    An equal list computed from an incomplete caller-supplied union is not
    completeness authority. The source query program supplies those ranges.
    """
    work = overlay.work
    hints = values["query_hints"]
    work.prepare_copy(hints["withdrawals"])
    dependents = {item["credential_record_id"]: {"oidc_session_ids": [],
        "approval_grant_ids": [], "control_plane_approval_ids": []}
        for item in hints["withdrawals"]}
    live, registrations = [], []
    for (table, identifier), row in overlay.current.items():
        if row is None:
            continue
        overlay.tick(1)
        work.prepare_scan(row)
        if table == "webauthn_credentials" and row.get("revoked_at") is None:
            trusted = row.get("attestation_trusted")
            if type(trusted) is not int or not -(1 << 31) <= trusted < (1 << 31):
                raise WebAuthnTrustStageError("stage credential trust flag differs from its source integer")
            if trusted != 0:
                live.append(identifier)
        elif (table == "webauthn_challenges" and row.get("challenge_type") == "registration"
                and row.get("used_at") is None
                and revocation._utc(row.get("expires_at"), "registration expiry", work=work) > context.database_now):
            registrations.append(identifier)
        elif (table == "oidc_browser_sessions" and row.get("status") in {"pending_webauthn", "active"}
                and row.get("bound_webauthn_credential_id") in dependents):
            dependents[row["bound_webauthn_credential_id"]]["oidc_session_ids"].append(identifier)
        elif (table == "approval_grants" and row.get("state") == "active"
                and row.get("approver_webauthn_credential_id") in dependents):
            dependents[row["approver_webauthn_credential_id"]]["approval_grant_ids"].append(identifier)
        elif (table == "control_plane_approvals" and row.get("status") == "approved"
                and row.get("approver_webauthn_credential_id") in dependents):
            dependents[row["approver_webauthn_credential_id"]]["control_plane_approval_ids"].append(identifier)
    for observed, expected in ((live, hints["live_credential_ids"]),
            (registrations, hints["registration_challenge_ids"])):
        work.prepare_copy(observed)
        _same(sorted(observed), expected, work, "stage global hint differs from observed complete population")
    for item in hints["withdrawals"]:
        for name, observed in dependents[item["credential_record_id"]].items():
            work.prepare_copy(observed)
            _same(sorted(observed), item[name], work,
                "stage dependent hint differs from observed complete population")


def _business_rows(context, work):
    if (type(context) is not core.KernelContext or type(context.operation) is not str
            or context.operation != OPERATION or type(context.selected_rows) is not tuple
            or len(context.selected_rows) > authority.operation_spec(OPERATION)["maximumQueryRows"]
            or any(type(item) is not dict for item in context.selected_rows)):
        raise WebAuthnTrustStageError("stage context is not source bounded")
    work.prepare_copy(context.selected_rows)
    rows = tuple(item for item in context.selected_rows
        if not (item.get("table") == capacity.AGGREGATE_TABLE
            and item.get("key") == {"aggregate_id": capacity.AGGREGATE_ID}))
    if len(rows) > MAX_SELECTED_ROWS:
        raise WebAuthnTrustStageError("stage selected business union exceeds its single allowance")
    return rows


def _plan_stage(context, *, candidate_roots, development_enabled,
        require_approval, require_approver_webauthn, work):
    """Return (ordinary row effects, aggregate result, semantic work units).

    Approval booleans and candidate policy are independent configured inputs,
    not request fields. Fixed current admin roles are checked for both actors.
    All authorizations use the original state, before the first overlay write.
    """
    if (type(context) is not core.KernelContext or type(context.operation) is not str or context.operation != OPERATION
            or type(context.arguments) is not dict or set(context.arguments) != _ARGUMENT_FIELDS
            or type(context.database_now) is not datetime or context.database_now.tzinfo is not timezone.utc
            or type(work) is not _ValidationWork
            or any(type(value) is not bool for value in (development_enabled, require_approval, require_approver_webauthn))):
        raise WebAuthnTrustStageError("stage invocation is not closed and source bounded")
    capture._SharedLedger(work)
    core.require_digest(context.request_digest, "stage request digest")
    business_rows = _business_rows(context, work)
    database_now, request_digest = context.database_now, context.request_digest
    # One actual JSON normalization owns all variable row/request/evidence data.
    work.prepare_copy(business_rows)
    graph = {"arguments": context.arguments, "rows": list(business_rows),
        "evidence": context.verified_webauthn_evidence}
    work.prepare_normalization(graph)
    owned = json.loads(core.canonical_bytes(graph).decode("ascii"))
    work.prepare_copy(owned["rows"])
    context = core.KernelContext(OPERATION, owned["arguments"], tuple(owned["rows"]),
        database_now, request_digest, owned["evidence"])
    values, overlay = _arguments(context.arguments, work), _Overlay(context.selected_rows, work)
    _assertion_scope(context.verified_webauthn_evidence, context.request_digest, work)
    if type(candidate_roots) is not tuple or len(candidate_roots) > classifier.MAX_ROOTS:
        raise WebAuthnTrustStageError("candidate root policy is not a bounded exact tuple")
    root_graph = []
    for root in candidate_roots:
        if type(root) is not classifier.RootTrustPolicy:
            raise WebAuthnTrustStageError("candidate root is not the fixed policy type")
        root_graph.append({"id": root.id, "certificate_sha256": root.certificate_sha256,
            "authenticator_class": root.authenticator_class, "aaguids": root.aaguids,
            "bundle_digest": root.bundle_digest, "bundle_sequence": root.bundle_sequence})
    work.prepare_copy(root_graph)
    policy = classifier.CredentialTrustContext(candidate_roots, development_enabled)
    hints = values["withdrawn_credential_ids"]
    for root in policy.roots:
        _same(root.bundle_digest, values["bundle_digest"], work, "candidate root bundle changed")
        _same(root.bundle_sequence, values["sequence"], work, "candidate root sequence changed")
    overlay.tick(len(policy.roots))
    _candidate_content(values, policy, work)
    bundle_json = _json(values["bundle"], work)
    _publication_baseline(values, overlay)
    _population_hints(context, values, overlay)
    high = overlay.row(trust.HIGH_WATER_TABLE, trust.AUTHORITY_SCOPE)
    _same(high.get("publication_digest"), values["previous_bundle_digest"], work, "stage predecessor changed")
    if (values["rollback_epoch"] < high["rollback_epoch"] or
            (values["rollback_epoch"] == high["rollback_epoch"] and values["sequence"] <= high["publication_sequence"])):
        raise WebAuthnTrustStageError("candidate trust publication is not monotonic")
    _admin(overlay, values["actor_id"])
    signer, assertion, counter = _assertion(context, values, overlay)
    approval = _approval(context, values, overlay, required=require_approval,
        require_webauthn=require_approver_webauthn)
    # Classification uses ALL live rows in the independently proved population,
    # not IDs selected by the signed hint or merely removed certificate roots.
    affected = []
    affected_details = {}
    for (table, identifier), row in overlay.current.items():
        if table != "webauthn_credentials" or row is None or row.get("revoked_at") is not None:
            continue
        overlay.tick(2 + len(policy.roots))
        work.prepare_copy(root_graph)
        work.prepare_scan(row)
        status = classifier.classify(classifier.CredentialTrustFacts(
            bool(row.get("attestation_trusted")), str(row.get("authenticator_class") or "unknown"),
            bool(row.get("dev_private_key_pem")), row.get("attestation_root_sha256"),
            str(row.get("aaguid") or ""), row.get("attestation_trust_bundle_digest"),
            row.get("attestation_trust_bundle_sequence")), policy)
        if status.enrollment_trusted and not status.currently_trusted:
            affected.append(identifier)
            _text(row.get("credential_id"), "withdrawn credential identity", 4096)
            work.prepare_utf8(row["credential_id"])
            credential_digest = revocation._sha256_bytes(row["credential_id"].encode("utf-8"), work=work)[7:]
            affected_details[identifier] = {"credential_record_id": identifier,
                "credential_id_sha256": credential_digest, "user_id": row.get("user_id"),
                "reason": status.reason, "attestation_root_sha256": row.get("attestation_root_sha256")}
    work.prepare_copy(affected)
    affected.sort()
    _same(hints, affected, work, "stage withdrawal hints differ from complete candidate classification")
    work.prepare_copy(root_graph)
    root_digests = sorted(root.certificate_sha256 for root in policy.roots)
    mutation_payload = {"bundle_digest": values["bundle_digest"], "sequence": values["sequence"],
        "rollback_epoch": values["rollback_epoch"], "current_bundle_digest": values["previous_bundle_digest"],
        "root_certificate_sha256": root_digests, "withdrawn_credential_record_ids": affected,
        "reason": values["reason"]}
    work.prepare_encoding(mutation_payload)
    payload_bytes = core.canonical_bytes(mutation_payload)
    _same(values["payload_digest"], revocation._sha256_bytes(payload_bytes, work=work), work,
        "stage approval payload does not commit the actual aggregate transition")
    work.prepare_copy(affected)
    withdrawn = set(affected)
    work.prepare_copy(affected)
    per_credential = {identifier: {"revoked_grant_count": 0,
        "revoked_control_plane_approval_count": 0} for identifier in affected}
    now = context.database_now.isoformat()
    # No mutation precedes all baseline authorization and candidate checks.
    overlay.update("webauthn_credentials", signer["id"],
        {"sign_count": counter, "last_used_at": now, "updated_at": now})
    overlay.update("webauthn_challenges", assertion["id"], {"used_at": now})
    if approval is not None:
        overlay.update("control_plane_approvals", approval["id"],
            {"status": "consumed", "consumed_by": values["actor_id"], "consumed_at": now})
        work.prepare_copy(approval)
        _audit(overlay, context, purpose="trust-stage-approval-consumed:" + approval["id"],
            event_type="control_plane.approval.consumed", actor_type="admin", actor_id=values["actor_id"],
            event={name: approval.get(name) for name in ("action", "resource_id", "payload_digest", "requester_id",
                "approved_by", "approver_webauthn_credential_id")} | {"approval_id": approval["id"]})
    counts = {"revoked_credential_count": len(affected), "revoked_grant_count": 0,
        "revoked_control_plane_approval_count": 0, "revoked_oidc_browser_session_count": 0,
        "invalidated_registration_challenge_count": 0}
    reason = values["reason"] or "Attestation trust withdrawn by signed bundle " + values["bundle_digest"]
    # One source-order-independent pass over the working map. The consumed
    # approval is no longer approved; the signer counter is already updated.
    work.prepare_copy(context.selected_rows)
    for table, identifier in sorted(overlay.current):
        row = overlay.current[table, identifier]
        if row is None:
            continue
        overlay.tick(1)
        if table == "webauthn_credentials" and identifier in withdrawn:
            overlay.update(table, identifier, {"revoked_at": now, "revoked_by": values["actor_id"],
                "revocation_reason": reason, "revocation_source": "trust-root-withdrawal", "updated_at": now})
        elif (table == "oidc_browser_sessions" and row.get("bound_webauthn_credential_id") in withdrawn
                and row.get("status") in {"pending_webauthn", "active"}):
            overlay.update(table, identifier, {"status": "revoked", "revoked_at": now,
                "updated_at": now, "revocation_reason": "bound_webauthn_credential_revoked"})
            counts["revoked_oidc_browser_session_count"] += 1
        elif (table == "approval_grants" and row.get("approver_webauthn_credential_id") in withdrawn
                and row.get("state") == "active"):
            overlay.update(table, identifier, {"state": "revoked", "uses_remaining": 0,
                "reserved_attempt_id": None, "reserved_at_epoch_ms": None, "reservation_expires_at_epoch_ms": None})
            counts["revoked_grant_count"] += 1
            per_credential[row["approver_webauthn_credential_id"]]["revoked_grant_count"] += 1
        elif (table == "control_plane_approvals" and row.get("approver_webauthn_credential_id") in withdrawn
                and row.get("status") == "approved"):
            overlay.update(table, identifier, {"status": "invalidated"})
            work.prepare_copy(row)
            _audit(overlay, context, purpose="trust-stage-approval-invalidated:" + identifier,
                event_type="control_plane.approval.invalidated", actor_type="system", actor_id=None,
                event={name: row.get(name) for name in ("action", "resource_id", "payload_digest", "requester_id",
                    "approved_by", "approver_webauthn_credential_id")} | {"approval_id": identifier,
                    "reason": "approver_webauthn_credential_revoked"})
            counts["revoked_control_plane_approval_count"] += 1
            per_credential[row["approver_webauthn_credential_id"]]["revoked_control_plane_approval_count"] += 1
        elif (table == "webauthn_challenges" and row.get("challenge_type") == "registration"
                and row.get("used_at") is None
                and revocation._utc(row.get("expires_at"), "registration expiry", work=work) > context.database_now):
            overlay.update(table, identifier, {"used_at": now})
            counts["invalidated_registration_challenge_count"] += 1
    publication_id = core._deterministic_uuid(operation=OPERATION, request_digest=context.request_digest,
        purpose="trust-publication", work=work)
    overlay.row(trust.PUBLICATION_TABLE, publication_id, absent=True)
    work.prepare_copy(values["audit_event"])
    work.prepare_copy(affected_details)
    work.prepare_copy(per_credential)
    event = {**values["audit_event"], "bundle_digest": values["bundle_digest"],
        "sequence": values["sequence"], "rollback_epoch": values["rollback_epoch"],
        "signing_key_id": values["signing_key_id"], "withdrawn_credential_ids": affected,
        "root_certificate_sha256": root_digests,
        "withdrawn_credentials": [affected_details[identifier] for identifier in affected],
        "revoked_credentials": [{"credential_record_id": identifier,
            "credential_id_sha256": affected_details[identifier]["credential_id_sha256"],
            "user_id": affected_details[identifier]["user_id"], "revoked_at": now,
            "revocation_source": "trust-root-withdrawal", **per_credential[identifier]} for identifier in affected],
        "control_plane_mfa": {"operation": OPERATION, "request_digest": context.request_digest,
            "credential_record_id": signer["id"], "prior_counter": signer["sign_count"], "new_counter": counter},
        "control_plane_approval": None if approval is None else {"required": require_approval,
            "approval_id": approval["id"], "approved_by": approval["approved_by"],
            "approved_at": approval.get("approved_at"), "payload_digest": approval["payload_digest"]},
        "reason": values["reason"], "payload_digest": values["payload_digest"], **counts}
    publication = {"id": publication_id, "scope": "global",
        "previous_bundle_digest": values["previous_bundle_digest"], "bundle_digest": values["bundle_digest"],
        "sequence": values["sequence"], "rollback_epoch": values["rollback_epoch"],
        "signing_key_id": values["signing_key_id"], "bundle_json": bundle_json,
        "payload_digest": values["payload_digest"], "actor_id": values["actor_id"],
        "withdrawn_credential_ids_json": _json(affected, work), "audit_event_json": _json(event, work),
        "status": "pending", "attempts": 0, "last_error": None, "created_at": now, "published_at": None}
    overlay.put(trust.PUBLICATION_TABLE, publication_id, publication)
    effects = overlay.effects()
    result = {"publication_id": publication_id, "withdrawn_credential_ids": affected, **counts}
    work.prepare_copy(result)
    return effects, result, overlay.units


def _kernel_transition_on_work(context, *, candidate_roots, development_enabled,
        require_approval, require_approver_webauthn, work):
    """Render the single aggregate, not one fresh budget per withdrawal.

    Mandatory assertion evidence remains part of the independently admitted
    context; candidate roots and approval policy are separately admitted inputs.
    The common owner must still finalize audit capacity and prove all changed
    primary/counting roots. This private adapter is not a registered kernel.
    """
    if type(context) is not core.KernelContext:
        raise WebAuthnTrustStageError("stage mutation adapter requires the actual context")
    capture._SharedLedger(work)
    effects, result, units = _plan_stage(context, candidate_roots=candidate_roots,
        development_enabled=development_enabled, require_approval=require_approval,
        require_approver_webauthn=require_approver_webauthn, work=work)
    if not 1 <= len(effects) <= MAX_EFFECTS:
        raise WebAuthnTrustStageError("stage final effect inventory exceeds its business allowance")
    mutations, addresses = [], set()
    for selected, updated in effects:
        core.require_digest(selected["keyDigest"], "stage mutation key digest")
        address = selected["table"], selected["keyDigest"]
        if address in addresses:
            raise WebAuthnTrustStageError("stage produced duplicate final mutation addresses")
        addresses.add(address)
        work.prepare_copy(selected["key"])
        if selected["present"] is True:
            work.prepare_copy(selected["row"])
        work.prepare_copy(updated)
        mutations.append(core.mutation(operation=OPERATION, selected=selected, row=updated))
    work.prepare_copy(mutations)
    ordered = sorted(mutations, key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
    work.prepare_copy(ordered)
    planned = tuple(ordered)
    business_units = units + len(planned)
    if business_units > MAX_WORK_UNITS:
        raise WebAuthnTrustStageError("stage rendering exceeds its single semantic work allowance")
    work.prepare_encoding(result)
    return core.KernelTransition(mutations=planned, result=result, work_units=business_units)
