"""Source-fixed complete succession populations and exact material graph.

Every table has a separate authenticated before-root. A signed list is a pin
to compare with that actual complete population, never an absence proof.
"""
from catchplate import authority_oauth_retirement_succession as p
from catchplate import authority_oauth_retirement_succession_records as records
from catchplate import authority_oauth_activation as activation
from catchplate import authority_oauth_exchange as exchange
from catchplate import authority_oauth_refresh as refresh
from catchplate import authority_oauth_setup as setup
from catchplate import authority_oauth_measured_exchange as initial
from catchplate import authority_oauth_measured_setup as measured_setup
from catchplate import authority_oauth_reconnect as reconnect
from catchplate import authority_transition_quota as shared

TABLES = ("credentials", "pending_oauth_credentials", "setup_sessions", exchange.TABLE, refresh.TABLE, "oauth_revocation_work")
ORIGIN_CONTRACTS = {"initial": initial, "setup": measured_setup, "reconnect": reconnect}
PENDING_LIFECYCLE = frozenset({"status", "revocation_status", "revocation_error", "revocation_attempts",
    "revocation_next_attempt_at", "revocation_lease_owner", "revocation_lease_until", "updated_at"})


def metadata(row):
    value = shared._canonical_stored_mapping(row["metadata"], "actual complete OAuth metadata")
    p.require(value.get("provider_id") in {"google", "x"}, "unclassified OAuth metadata cannot establish complete scope")
    return value


def in_scope(value, grant):
    if value.get("provider_id") != grant["providerId"]:
        return False
    if grant["scope"]["kind"] == "provider":
        return True
    p.require(type(value.get("provider_subject")) is str, "unknown subject requires independently authorized provider scope")
    return value["provider_subject"] == grant["providerSubject"]


def _rows(graph, table):
    found = graph.rows(table)
    p.require(len(found) <= p.MAX_POPULATION, "succession population capacity exceeded; no truncation")
    p.require(len({row["id"] for row in found}) == len(found))
    return sorted(found, key=lambda row: row["id"])


def _origin(graph, history, pin):
    kind = pin["sourceKind"]
    row = graph.row(records.ORIGIN_TABLES[kind], history["id"])
    if kind == "succession":
        contract, raw = p, records.custody_original(row)
    else:
        contract = ORIGIN_CONTRACTS[kind]; raw = contract.row_original(row)
    p.require(p.sha256(raw) == pin["custodyRowSha256"] and row["id"] == history["id"])
    preparation = contract.arguments(contract.OP_PREPARE, records.stored(row["preparation_arguments_json"], p.MAX_ARGUMENT_BYTES))
    p.require(preparation["request"] == records.stored(history["consent_json"], p.MAX_ARGUMENT_BYTES)
        and preparation["resource_id"] == history["id"] and preparation["enrollment_original"] == history["enrollment_original"]
        and preparation["actor_id"] == history["requester_id"])
    if history["status"] == "claimed":
        p.require(False, "an unobserved old token contact cannot be settled by succession")
    p.require(history["status"] in {"prepared", "retained", "staged"})
    if history["status"] != "prepared":
        capture = contract.arguments(contract.OP_CAPTURE, records.stored(row["capture_arguments_json"], p.MAX_ARGUMENT_BYTES))
        claim = contract.arguments(contract.OP_CLAIM, records.stored(row["claim_arguments_json"], p.MAX_ARGUMENT_BYTES))
        request = capture["request"]
        p.require(capture["resource_id"] == claim["resource_id"] == history["id"]
            and capture["enrollment_original"] == claim["enrollment_original"] == history["enrollment_original"]
            and request["issuedMaterialEnvelope"] is not None
            and history["token_secret_sha256"] == request["issuedMaterialSha256"]
            and history["token_envelope_json"] == p.canonical(request["issuedMaterialEnvelope"]).decode("ascii")
            and history["raw_response_sha256"] == request["rawResponseSha256"]
            and history["raw_response_envelope_json"] == p.canonical(request["rawResponseEnvelope"]).decode("ascii")
            and history["contact_request_sha256"] == claim["request"]["contactRequestSha256"]
            and row["owner_nonce_sha256"] == claim["request"]["ownerNonceSha256"]
            == p.sha256(p.decoded(request["ownerNonce"], 32, 32)))
    return contract, row, preparation


def collect(graph, grant):
    """Pure analysis of the re-admitted complete protected snapshot graph."""
    from catchplate import authority_oauth_retirement_succession_materials as materials
    populations = {table: _rows(graph, table) for table in TABLES}
    actual_credentials, pending_rows, targets = [], {}, {}
    for row in populations["credentials"]:
        refresh.credential_original(row)
        if row["kind"] != "oauth2":
            continue
        value = metadata(row)
        if in_scope(value, grant):
            p.require(value.get("provider_identity_verified") is True)
            actual_credentials.append(row)
            targets[row["id"]] = row
    p.require([row["id"] for row in actual_credentials] == [entry["credentialId"] for entry in grant["affectedLineages"]],
        "grant does not cover the complete actual affected credential population")
    for row in populations["pending_oauth_credentials"]:
        activation.pending_original(row)
        if row["kind"] == "oauth2" and in_scope(metadata(row), grant):
            p.require(row["revocation_lease_owner"] is None and row["revocation_lease_until"] is None
                and type(row["revocation_attempts"]) is int and 0 <= row["revocation_attempts"] <= 2 and row["revocation_error"] is None,
                "unowned pending retirement contact cannot be reclassified")
            pending_rows[row["id"]] = row
    for row in populations["setup_sessions"]:
        setup.row_original(row)
        # Existing Setup associations are retained, not completed or adopted by
        # a credential replacement. A live credential-bound Setup must resolve
        # through its separate actual CAS owner first.
        p.require(not (row["status"] == "active" and row.get("credential_id") in targets),
            "active credential-bound Setup requires its own terminal transition")
    expected_origins = {item["exchangeId"]: item for item in grant["exchangeOrigins"]}
    history_rows = [row for row in populations[exchange.TABLE] if row["provider_id"] == grant["providerId"]]
    p.require([row["id"] for row in history_rows] == sorted(expected_origins),
        "exchange source pins must name the complete actual provider history")
    sources, represented_pending = [], set()
    for history in history_rows:
        exchange.row_original(history)
        pin = expected_origins[history["id"]]
        contract, custody, preparation = _origin(graph, history, pin)
        if history["status"] == "prepared":
            p.require(custody["status"] in {"prepared", "cancelled"}
                and history["claim_request_digest"] is None and history["token_envelope_json"] is None)
            sources.append({"exchangeId": history["id"], "sourceKind": pin["sourceKind"], "state": "never-contacted",
                "exchangeOriginal": exchange.row_original(history).decode("ascii"), "custodyOriginal": p.canonical(custody).decode("ascii")})
            continue
        # Pre-subject capture has no trustworthy family label. Even a caller's
        # expected account may not narrow the independent external effect scope.
        if history["status"] == "retained":
            if pin["sourceKind"] in {"initial", "setup"}:
                p.require(grant["scope"]["kind"] == "provider", "retained pre-subject material requires provider-wide authority")
            else:
                # A same-account reconnect's actual protected preparation pins
                # verified target metadata; an initial expected-subject hint
                # is deliberately not a substitute for that provenance.
                old = preparation["request"]["metadata"]
                p.require(old.get("provider_identity_verified") is True)
                if not in_scope(old, grant):
                    sources.append({"exchangeId": history["id"], "sourceKind": pin["sourceKind"], "state": "outside-scope",
                        "exchangeOriginal": exchange.row_original(history).decode("ascii"), "custodyOriginal": p.canonical(custody).decode("ascii")})
                    continue
        initial_pending, candidate, current_pending = None, None, None
        if history["status"] == "staged":
            stage = contract.arguments(contract.OP_STAGE, records.stored(custody["stage_arguments_json"], p.MAX_ARGUMENT_BYTES))
            p.require(stage["resource_id"] == history["id"] and stage["enrollment_original"] == history["enrollment_original"])
            p.require(stage["request"]["metadata"].get("provider_identity_verified") is True)
            if not in_scope(stage["request"]["metadata"], grant):
                sources.append({"exchangeId": history["id"], "sourceKind": pin["sourceKind"], "state": "outside-scope",
                    "exchangeOriginal": exchange.row_original(history).decode("ascii"), "custodyOriginal": p.canonical(custody).decode("ascii")})
                continue
            if pin["sourceKind"] in {"initial", "setup"}:
                initial_pending = records.stored(custody["pending_original_json"], activation.MAX_PENDING_BYTES)
                activation.pending_original(initial_pending)
                p.require(initial_pending["id"] == history["id"]
                    and all(initial_pending[name] == stage["request"]["tokenEnvelope"][name] for name in refresh.ENVELOPE_FIELDS))
                current_pending = pending_rows.get(history["id"])
                if current_pending is not None:
                    p.require(all(current_pending[name] == initial_pending[name] for name in activation.PENDING_FIELDS - PENDING_LIFECYCLE))
                    represented_pending.add(history["id"])
                else:
                    # Positive controlled activation publishes the same exact
                    # ciphertext into its actual credential; absence alone is
                    # never an activated-success assertion.
                    published = targets.get(history["id"])
                    p.require(published is not None, "staged material needs its actual current credential association")
                    materials.published_pending(graph, initial_pending, published)
            else:
                candidate = records.stored(custody["candidate_original_json"], p.MAX_CANDIDATE_BYTES)
                p.require(candidate["exchangeId"] == history["id"] and candidate["tokenEnvelope"] == stage["request"]["tokenEnvelope"]
                    and candidate["tokenSecretSha256"] == stage["request"]["tokenSecretSha256"])
                if custody["status"] == "committed":
                    committed = records.stored(custody["committed_credential_json"], 512 * 1024)
                    refresh.credential_original(committed)
                    p.require(committed["id"] == candidate["credentialId"]
                        and all(committed[name] == candidate["tokenEnvelope"][name] for name in refresh.ENVELOPE_FIELDS))
                    p.require(committed["id"] in targets)
                    materials.require_descendant(graph, committed, targets[committed["id"]])
        sources.append({"exchangeId": history["id"], "sourceKind": pin["sourceKind"], "state": history["status"],
            "exchangeOriginal": exchange.row_original(history).decode("ascii"), "custodyOriginal": p.canonical(custody).decode("ascii"),
            "initialPendingOriginal": None if initial_pending is None else p.canonical(initial_pending).decode("ascii"),
            "currentPendingOriginal": None if current_pending is None else p.canonical(current_pending).decode("ascii"),
            "candidateOriginal": None if candidate is None else p.canonical(candidate).decode("ascii")})
    p.require(represented_pending == set(pending_rows), "every affected pending row needs its positive measured source association")
    for row in populations[refresh.TABLE]:
        refresh.row_original(row)
        if row["provider_id"] == grant["providerId"] and in_scope(metadata(records.stored(row["credential_original_json"], 512 * 1024)), grant):
            p.require(row["status"] in {"retained", "committed"}, "unknown refresh contact blocks succession irrespective of timeout")
    # Material leaf selection is performed separately against these same held
    # source rows. It must account for every captured/pending/refresh/current
    # leaf, not count an ancestor ciphertext as another independent token.
    result = {"populations": {table: [p.canonical(row).decode("ascii") for row in values] for table, values in populations.items()},
        "exchangeSources": sources, "affectedCredentials": [refresh.credential_original(row).decode("ascii") for row in actual_credentials]}
    p.require(len(p.canonical(result)) <= p.MAX_ROW_BYTES)
    return result
