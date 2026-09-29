"""Actual consumed token contacts: positive outcomes, never retry permission."""
from serverware import authority_oauth_retirement_succession as p
from serverware import authority_oauth_retirement_succession_records as rows
from serverware import authority_oauth_revocation as exchange
from serverware import authority_oauth_refresh_cleanup as refresh
from serverware import authority_oauth_measured_cleanup as measured_refresh
from serverware import authority_oauth_measured_pending_retirement as pending
from serverware import authority_oauth_measured_capture_retirement as capture
from serverware import authority_oauth_retirement_succession_inventory as inventory
from serverware import authority_oauth_activation as activation

PROFILES = {"exchange": exchange, "refresh": refresh, "measured-refresh": measured_refresh, "pending": pending, "capture": capture}
REFERENCE_FIELDS = frozenset({"profile", "attemptOriginal", "sourceOriginal"})


def reference(*, records, request_sha256):
    """Validate only retained outcome data; this function grants no effect."""
    p.require(type(records) is dict and set(records) == REFERENCE_FIELDS)
    attempt = rows.stored(records["attemptOriginal"], 512 * 1024)
    if records["profile"] == "succession":
        rows.attempt_original(attempt)
        p.require(attempt["status"] == "accepted" and attempt["prior_contact_json"] is None)
        material = rows.stored(records["sourceOriginal"])
        rows.material_original(material)
        p.require(attempt["material_claim_id"] == material["id"] and attempt["material_id"] == material["material_id"] and attempt["scope_id"] == material["scope_id"])
    else:
        p.require(records["profile"] in PROFILES)
        contract = PROFILES[records["profile"]]; contract.attempt_original(attempt)
        journal = rows.stored(records["sourceOriginal"])
        contract.journal_original(journal)
        key = "pending_id" if records["profile"] == "pending" else "exchange_id" if records["profile"] == "capture" else "work_id"
        p.require(attempt[key] == journal["id"] and attempt["id"] == contract.attempt_id(journal["id"], attempt["token_purpose"])
        p.require(attempt["transport_original"] is not None and attempt["transport_sha256"] == p.sha256(attempt["transport_original"].encode("ascii"))
            and contract.transport(attempt["transport_original"].encode("ascii"), request_sha256) == "accepted")
    p.require(attempt["status"] == "accepted" and attempt["contact_request_sha256"] == request_sha256)
    return records


def _selected(contract, kind, journal, expected):
    grant = contract.grant_document(contract.unb64(journal["authorization_original"], contract.MAX_GRANT_BYTES))["payload"]
    p.require(journal["authorization_sha256"] == p.sha256(contract.unb64(journal["authorization_original"], contract.MAX_GRANT_BYTES)))
    if grant["providerId"] != expected["providerId"]:
        return False
    if expected["scope"]["kind"] == "provider":
        return True
    p.require(kind not in {"exchange", "capture"}, "pre-subject predecessor effects require an independently authorized provider scope")
    return grant["familyScope"]["providerSubject"] == expected["providerSubject"]


def catalogue(graph, grant):
    """Complete authenticated prior contacts; unknown/rejected stay blocking."""
    result = []
    # Counters are not evidence of contact absence. Match each affected legacy
    # work/pending counter to the actual protected attempt population instead.
    for work in graph.rows("oauth_revocation_work"):
        if work["provider_id"] != grant["providerId"]:
            continue
        attempts = [attempt for table, field in ((exchange.ATTEMPT_TABLE, "work_id"), (refresh.ATTEMPT_TABLE, "work_id"),
            (capture.ATTEMPT_TABLE, "exchange_id")) for attempt in graph.rows(table) if attempt[field] == work["id"]]
        p.require(type(work["attempts"]) is int and work["attempts"] == len(attempts),
            "legacy work counter has no complete protected contact association")
    for row in graph.rows("pending_oauth_credentials"):
        if row["kind"] != "oauth2" or not inventory.in_scope(inventory.metadata(row), grant):
            continue
        attempts = [attempt for attempt in graph.rows(pending.ATTEMPT_TABLE) if attempt["pending_id"] == row["id"]]
        p.require(row["revocation_attempts"] == len(attempts), "pending legacy contact cannot be inferred from a missing journal")
        if attempts:
            journal = graph.row(pending.JOURNAL_TABLE, row["id"]); pending.journal_original(journal)
            before = rows.stored(journal["original_pending_json"], activation.MAX_PENDING_BYTES)
            p.require(row == {**before, "status": "family_retired", "revocation_status": "pending_retirement_" + journal["status"].replace("-", "_"),
                "revocation_attempts": len(attempts), "revocation_next_attempt_at": None, "revocation_error": None,
                "revocation_lease_owner": None, "revocation_lease_until": None, "updated_at": journal["updated_at"]})
    for kind, base in (("exchange", exchange), ("refresh", refresh), ("pending", pending), ("capture", capture)):
        for attempt in graph.rows(base.ATTEMPT_TABLE):
            base.attempt_original(attempt)
            key = "pending_id" if kind == "pending" else "exchange_id" if kind == "capture" else "work_id"
            journal = graph.row(base.JOURNAL_TABLE, attempt[key]); base.journal_original(journal)
            selected_kind, contract = kind, base
            if kind == "refresh" and graph.row(measured_refresh.TABLE, journal["id"], optional=True) is not None:
                selected_kind, contract = "measured-refresh", measured_refresh
            if not _selected(contract, selected_kind, journal, grant):
                continue
            p.require(attempt["status"] == "accepted", "an old consumed contact is not positively accepted; new authorization cannot settle or retry it")
            item = {"profile": selected_kind, "attemptOriginal": p.canonical(attempt).decode("ascii"), "sourceOriginal": p.canonical(journal).decode("ascii")}
            reference(records=item, request_sha256=attempt["contact_request_sha256"])
            result.append(item)
    for attempt in graph.rows(p.ATTEMPT_TABLE):
        rows.attempt_original(attempt)
        material = graph.row(p.MATERIAL_TABLE, attempt["material_claim_id"]); rows.material_original(material)
        if material["provider_id"] != grant["providerId"]:
            continue
        prior_scope = rows.stored(material["scope_json"], 8192)
        p.require(type(prior_scope) is dict and set(prior_scope) == {"kind", "providerId", "providerSubject", "externalImpactAuthorized"}
            and prior_scope["providerId"] == material["provider_id"] and prior_scope["externalImpactAuthorized"] is True)
        if grant["scope"]["kind"] == "family":
            p.require(prior_scope["kind"] == "family", "provider-wide predecessor cannot be narrowed into ordinary family reopening")
            if prior_scope["providerSubject"] != grant["providerSubject"]:
                continue
        p.require(attempt["status"] in {"accepted", "accepted-existing"}, "old succession contact remains consumed and unsettled")
        item = rows.stored(attempt["prior_contact_json"], 512 * 1024) if attempt["status"] == "accepted-existing" else {
            "profile": "succession", "attemptOriginal": p.canonical(attempt).decode("ascii"), "sourceOriginal": p.canonical(material).decode("ascii")}
        reference(records=item, request_sha256=attempt["contact_request_sha256"])
        if item not in result:
            result.append(item)
    p.require(len(result) <= p.MAX_HISTORY and len(p.canonical(result)) <= p.MAX_ROW_BYTES)
    return result


def prior_match(catalogue, request_sha256):
    p.digest(request_sha256)
    found = [item for item in catalogue if rows.stored(item["attemptOriginal"], 512 * 1024)["contact_request_sha256"] == request_sha256]
    # Multiple historical proven acknowledgements do not grant a new POST.
    # Return one exact retained accepted reference, deterministically.
    if not found:
        return None
    found.sort(key=lambda item: (item["profile"], rows.stored(item["attemptOriginal"], 512 * 1024)["id"]))
    return reference(records=found[0], request_sha256=request_sha256)


def complete(attempts, materials, authorization_id):
    expected = {p.attempt_id(p.material_claim_id(authorization_id, item["pin"]["materialId"]), purpose)
        for item in materials for purpose in item["pin"]["tokenPurposes"]}
    p.require({item["id"] for item in attempts} == expected, "every exact retained material purpose requires a definite terminal association")
    for row in attempts:
        rows.attempt_original(row)
        p.require(row["status"] in {"accepted", "accepted-existing"}, "unknown or rejected retirement cannot authorize a fresh scope")
    return p.sha256(p.canonical(sorted(attempts, key=lambda row: row["id"])))
