"""Closed durable records and fixed source lookups, not effect permission."""
from serverware import authority_oauth_retirement_succession as p
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_oauth_family_retirement as family
from serverware import authority_oauth_provider_retirement as provider
from serverware import authority_oauth_refresh_cleanup as refresh_cleanup
from serverware import authority_oauth_measured_pending_retirement as pending
from serverware import authority_oauth_measured_capture_retirement as capture
from serverware import authority_oauth_reconnect as reconnect

HEAD_FIELDS = frozenset({"id", "provider_id", "scope_kind", "provider_subject", "sequence", "scope_id", "scope_sha256", "created_at", "updated_at"})
SCOPE_FIELDS = frozenset({"id", "provider_id", "sequence", "authorization_sha256", "previous_head_json",
    "predecessors_json", "affected_originals_json", "inventory_original_json", "currentness_barriers_json",
    "fence_request_digest", "created_at", "expires_at"})
JOURNAL_FIELDS = frozenset({"id", "provider_id", "authorization_original", "authorization_sha256", "enrollment_original",
    "actor_id", "credential_policy_json", "authorize_arguments_json", "authorize_request_digest", "approval_id",
    "requester_credential_id", "requester_evidence_expires_at",
    "fence_arguments_json", "fence_request_digest", "scope_original_json", "status", "created_at",
    "admission_expires_at", "expires_at", "updated_at"})
MATERIAL_FIELDS = frozenset({"id", "material_id", "scope_id", "provider_id", "scope_json", "authorization_sha256", "material_original_json", "claim_arguments_json",
    "claim_request_digest", "owner_nonce_sha256", "status", "created_at", "updated_at"})
ATTEMPT_FIELDS = frozenset({"id", "material_id", "material_claim_id", "scope_id", "token_purpose", "contact_request_sha256", "contact_arguments_json",
    "contact_request_digest", "finish_arguments_json", "finish_request_digest", "transport_original", "prior_contact_json", "status", "created_at", "updated_at"})
ASSOCIATION_FIELDS = frozenset({"id", "credential_id", "credential_version", "scope_id", "scope_sha256", "provider_id", "provider_subject",
    "enrollment_sha256", "credential_sha256", "root_origin_request_digest", "previous_association_sha256", "created_at"})
CUSTODY_FIELDS = reconnect.ROW_FIELDS
CANDIDATE_FIELDS = reconnect.CANDIDATE_FIELDS | {"scopeSha256", "materialClosureSha256"}
ORIGINALS_FIELDS = frozenset({"journalOriginal", "scopeOriginal", "headOriginal", "materialOriginals", "attemptOriginals",
    "exchangeOriginal", "custodyOriginal", "candidateOriginal", "associationOriginal"})
RESULT_FIELDS = reconnect.RESULT_FIELDS | {"observation"}
OBSERVATION_FIELDS = frozenset({"status", "approval", "snapshotOriginal", "materialOriginal", "contactDisposition", "closureSha256"})

# These mappings are closed source profiles, not a caller-selected table name.
ORIGIN_TABLES = {"initial": "oauth_measured_exchange_custody", "setup": "oauth_measured_setup_custody",
    "reconnect": reconnect.TABLE, "succession": p.TABLE}
PREDECESSORS = {
    "refresh-family": (family.TABLE, refresh_cleanup.JOURNAL_TABLE, "work_id"),
    "pending-family": (pending.FAMILY_TABLE, pending.JOURNAL_TABLE, "pending_id"),
    "provider-capture": (provider.TABLE, capture.JOURNAL_TABLE, "exchange_id"),
    "reconnect-fence": (reconnect.JOURNAL_TABLE, reconnect.JOURNAL_TABLE, "id"),
    "succession": (p.SCOPE_TABLE, p.JOURNAL_TABLE, "id"),
}


def stored(value, maximum=p.MAX_ROW_BYTES):
    p.require(type(value) is str)
    return p.document(value.encode("ascii"), maximum)


def array(value, maximum=p.MAX_ROW_BYTES):
    p.require(type(value) is str and len(value.encode("ascii")) < maximum)
    item = p.document(b'{"items":' + value.encode("ascii") + b'}', maximum)["items"]
    p.require(type(item) is list)
    return item


def original(value, fields, *, integers=(), nullable=(), maximum=p.MAX_ROW_BYTES):
    row = dict(value); p.require(set(row) == fields)
    for name, item in row.items():
        if name in integers:
            p.common.integer(item)
        else:
            p.require(type(item) is str or item is None and name in nullable)
    if "id" in row:
        p.identifier(row["id"])
    raw = p.canonical(row); p.require(len(raw) <= maximum)
    return raw


def head_original(value):
    raw = original(value, HEAD_FIELDS, integers={"sequence"}, nullable={"provider_subject"}, maximum=8192)
    p.require(value["id"] == p.head_id(value["provider_id"]))
    p.require(value["scope_kind"] in {"family", "provider"}
        and (value["provider_subject"] is None) == (value["scope_kind"] == "provider"))
    p.identifier(value["scope_id"]); p.digest(value["scope_sha256"])
    return raw


def scope_original(value):
    raw = original(value, SCOPE_FIELDS, integers={"sequence"}, nullable={"previous_head_json"})
    p.require(value["provider_id"] in {"google", "x"}); p.digest(value["authorization_sha256"]); p.digest(value["fence_request_digest"])
    if value["previous_head_json"] is not None:
        head_original(stored(value["previous_head_json"], 8192))
    return raw


def journal_original(value):
    raw = original(value, JOURNAL_FIELDS, nullable={"fence_arguments_json", "fence_request_digest", "scope_original_json"})
    p.require(value["status"] in {"requested", "approved", "fenced", "committed"})
    p.digest(value["authorization_sha256"]); p.digest(value["authorize_request_digest"]); p.identifier(value["approval_id"])
    p.require(type(value["requester_credential_id"]) is str and 0 < len(value["requester_credential_id"]) <= 1024)
    p.require(all((value[name] is None) == (value["status"] in {"requested", "approved"})
        for name in ("fence_arguments_json", "fence_request_digest", "scope_original_json")))
    return raw


def material_original(value):
    raw = original(value, MATERIAL_FIELDS)
    p.require(value["status"] == "claimed" and value["provider_id"] in {"google", "x"}); p.identifier(value["scope_id"])
    p.require(value["id"] == p.material_claim_id(value["scope_id"], value["material_id"]))
    p.digest(value["authorization_sha256"]); p.digest(value["claim_request_digest"]); p.digest(value["owner_nonce_sha256"])
    return raw


def attempt_original(value):
    raw = original(value, ATTEMPT_FIELDS, nullable={"finish_arguments_json", "finish_request_digest", "transport_original", "prior_contact_json"}, maximum=512 * 1024)
    p.require(value["status"] in {"contact-claimed", "accepted", "accepted-existing", "rejected", "unknown"}
        and value["material_claim_id"] == p.material_claim_id(value["scope_id"], value["material_id"])
        and value["id"] == p.attempt_id(value["material_claim_id"], value["token_purpose"]))
    p.identifier(value["scope_id"]); p.digest(value["contact_request_sha256"]); p.digest(value["contact_request_digest"])
    p.require(all((value[name] is None) == (value["status"] in {"contact-claimed", "accepted-existing"})
        for name in ("finish_arguments_json", "finish_request_digest", "transport_original")))
    p.require((value["prior_contact_json"] is not None) == (value["status"] == "accepted-existing"))
    if value["prior_contact_json"] is not None:
        from serverware import authority_oauth_retirement_succession_contacts as contacts
        contacts.reference(records=stored(value["prior_contact_json"], 512 * 1024), request_sha256=value["contact_request_sha256"])
    if value["transport_original"] is not None:
        p.require(p.transport(value["transport_original"].encode("ascii"), value["contact_request_sha256"]) == value["status"])
    return raw


def association_original(value):
    raw = original(value, ASSOCIATION_FIELDS, integers={"credential_version"}, nullable={"previous_association_sha256"}, maximum=16384)
    p.require(value["id"] == p.association_id(value["credential_id"], value["credential_version"]))
    for name in ("scope_sha256", "enrollment_sha256", "credential_sha256", "root_origin_request_digest"):
        p.digest(value[name])
    if value["previous_association_sha256"] is not None:
        p.digest(value["previous_association_sha256"])
    return raw


def custody_original(value):
    # The scalar row has the same retained original slots; its source phase,
    # actions and signatures are exclusively the new succession purpose.
    return reconnect.row_original(value)


def candidate_original(value, grant):
    p.require(type(value) is dict and set(value) == CANDIDATE_FIELDS
        and value["apiVersion"] == "serverware.oauthRetiredScopeSuccessionCandidate/v1"
        and value["credentialId"] == grant["credentialId"] and value["previousVersion"] == grant["credentialVersion"]
        and value["exchangeId"] == grant["authorizationId"])
    for name in ("authorizationSha256", "scopeSha256", "materialClosureSha256", "tokenSecretSha256", "payloadDigest"):
        p.digest(value[name])
    p.refresh.envelope(value["tokenEnvelope"], grant["credentialVersion"] + 1)
    p.require(type(value["metadata"]) is dict and type(value["review"]) is dict
        and len(p.canonical(value["metadata"])) <= 32768 and len(p.canonical(value["review"])) <= 16384)
    p.common.integer(value["createdAtEpochNs"]); p.common.integer(value["expiresAtEpochNs"])
    p.require(grant["issuedAtEpochNs"] <= value["createdAtEpochNs"] < value["expiresAtEpochNs"] == grant["pendingExpiresAtEpochNs"])
    raw = p.canonical(value); p.require(len(raw) <= p.MAX_CANDIDATE_BYTES)
    return raw


def head_query(operation, provider_id):
    return shared._query(operation=operation, name="retirement_scope_head", table=p.HEAD_TABLE, key={"id": p.head_id(provider_id)})


def predecessor_queries(operation, pins):
    result, seen = [], set()
    for index, pin in enumerate(pins):
        table, journal, field = PREDECESSORS[pin["kind"]]
        key = {"id": pin["id"]}
        if (table, pin["id"]) not in seen:
            result.append(shared._query(operation=operation, name="succession_predecessor_" + str(index), table=table, key=key))
            seen.add((table, pin["id"]))
        if journal != table:
            result.append(shared._query(operation=operation, name="succession_predecessor_journal_" + str(index), table=journal,
                key={"id": pin["id"] if field == "id" else core.SelectedRowFieldReference(table, key, field)}))
    return tuple(result)


def predecessors(context, pins):
    result = []
    for pin in pins:
        table, journal_table, field = PREDECESSORS[pin["kind"]]
        row = shared._row(context.exact(table, {"id": pin["id"]}), "actual retained succession predecessor")
        journal = row if journal_table == table else shared._row(context.exact(journal_table, {"id": row[field]}), "actual predecessor claim")
        if pin["kind"] == "refresh-family":
            p.require(set(row) == family.FIELDS); refresh_cleanup.journal_original(journal)
            p.require(row["work_id"] == journal["id"] and row["authorization_sha256"] == journal["authorization_sha256"])
        elif pin["kind"] == "pending-family":
            p.require(set(row) == pending.FAMILY_FIELDS); pending.journal_original(journal)
            p.require(row["pending_id"] == journal["id"] and row["authorization_sha256"] == journal["authorization_sha256"]
                and row["claim_request_digest"] == journal["claim_request_digest"])
        elif pin["kind"] == "provider-capture":
            p.require(set(row) == provider.FIELDS); capture.journal_original(journal)
            p.require(row["exchange_id"] == journal["id"] and row["authorization_sha256"] == journal["authorization_sha256"]
                and row["claim_request_digest"] == journal["claim_request_digest"])
        elif pin["kind"] == "reconnect-fence":
            reconnect.journal_original(journal); p.require(journal["status"] == "fenced")
        else:
            scope_original(row); journal_original(journal)
            p.require(journal["status"] == "committed" and journal["scope_original_json"] == scope_original(row).decode("ascii"))
        p.require(p.sha256(p.canonical(row)) == pin["rowSha256"] and p.sha256(p.canonical(journal)) == pin["journalSha256"])
        result.append({"kind": pin["kind"], "rowOriginal": p.canonical(row).decode("ascii"), "journalOriginal": p.canonical(journal).decode("ascii")})
    return result
