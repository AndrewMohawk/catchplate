"""Complete retained ciphertext graph and positive generation ancestry.

These functions inspect authenticated historical originals. They never decrypt,
invent provider acceptance, substitute a hash for family effect permission, or
create contact authority. The new measured helper must additionally check the
complete actual plaintext token-purpose set after its genuine material claim.
"""
from catchplate import authority_oauth_retirement_succession as p
from catchplate import authority_oauth_retirement_succession_records as records
from catchplate import authority_oauth_refresh as refresh
from catchplate import authority_oauth_measured_refresh as measured_refresh
from catchplate import authority_oauth_exchange as exchange
from catchplate import authority_oauth_activation as activation
from catchplate import authority_oauth_activation_policy as enrollment
from catchplate import authority_oauth_revocation as revocation
from catchplate import authority_oauth_measured_exchange as initial
from catchplate import authority_oauth_measured_setup as setup
from catchplate import authority_oauth_reconnect as reconnect

MATERIAL_FIELDS = frozenset({"apiVersion", "pin", "providerId", "enrollmentOriginal", "tokenEnvelope", "aadCredentialId",
    "aadCredentialVersion", "sourceOriginals"})
MATERIAL_SCHEMA = "catchplate.oauthRetiredScopeMaterial/v1"
_LIFECYCLE = frozenset({"lifecycle_status", "revocation_error", "revocation_requested_at", "updated_at"})


def _body(row):
    refresh.credential_original(row)
    return {name: value for name, value in row.items() if name not in _LIFECYCLE}


def _envelope(row):
    value = {name: row[name] for name in refresh.ENVELOPE_FIELDS}
    refresh.envelope(value, value["credential_version"])
    return value


def edges(graph, credential_id):
    result = []
    for history in graph.rows(refresh.TABLE):
        if history["credential_id"] != credential_id or history["status"] != "committed":
            continue
        refresh.row_original(history)
        custody = graph.row(measured_refresh.TABLE, history["id"])
        measured_refresh.row_original(custody)
        p.require(custody["status"] == "committed" and custody["credential_id"] == credential_id
            and custody["credential_version"] == history["credential_version"]
            and custody["enrollment_original"] == history["enrollment_original"])
        before = records.stored(history["credential_original_json"], 512 * 1024)
        request = measured_refresh.request(measured_refresh.OP_COMMIT, records.stored(custody["commit_request_json"], p.MAX_ARGUMENT_BYTES))
        p.require(request["expectedVersion"] == history["credential_version"] == before["credential_version"]
            and request["replacementSecretSha256"] == history["replacement_secret_sha256"]
            and request["supersededMaterialSha256"] == history["superseded_material_sha256"])
        after = {**before, **request["replacementEnvelope"], "metadata": p.canonical(request["replacementMetadata"]).decode("ascii"), "updated_at": history["updated_at"]}
        p.require(p.sha256(refresh.credential_original(after)) == history["replacement_credential_sha256"])
        result.append((before, after))
    for table, contract in ((reconnect.TABLE, reconnect), (p.TABLE, p)):
        for custody in graph.rows(table):
            if custody["status"] != "committed":
                continue
            (reconnect.row_original if contract is reconnect else records.custody_original)(custody)
            before = records.stored(custody["predecessor_original_json"], 512 * 1024)
            if before["id"] != credential_id:
                continue
            after = records.stored(custody["committed_credential_json"], 512 * 1024)
            stage = contract.arguments(contract.OP_STAGE, records.stored(custody["stage_arguments_json"], p.MAX_ARGUMENT_BYTES))
            candidate = records.stored(custody["candidate_original_json"], p.MAX_CANDIDATE_BYTES)
            p.require(after["id"] == before["id"] == candidate["credentialId"]
                and after["credential_version"] == before["credential_version"] + 1 == candidate["previousVersion"] + 1
                and _envelope(after) == stage["request"]["tokenEnvelope"] == candidate["tokenEnvelope"]
                and stage["request"]["tokenSecretSha256"] == candidate["tokenSecretSha256"]
                and records.stored(after["metadata"], 32768) == candidate["metadata"])
            p.digest(custody["commit_request_digest"])
            result.append((before, after))
    p.require(len(result) <= p.MAX_HISTORY)
    versions = [before["credential_version"] for before, _ in result]
    p.require(len(versions) == len(set(versions)), "multiple actual commits claim the same predecessor generation")
    return result


def require_descendant(graph, before, current):
    p.require(before["id"] == current["id"] and before["credential_version"] <= current["credential_version"])
    available = edges(graph, before["id"]); cursor = before
    p.require(current["credential_version"] - cursor["credential_version"] <= len(available))
    for _ in range(len(available) + 1):
        if cursor["credential_version"] == current["credential_version"]:
            p.require(_body(cursor) == _body(current), "historical token has no exact current-generation descendant")
            return
        matches = [(old, new) for old, new in available if old["credential_version"] == cursor["credential_version"]]
        p.require(len(matches) == 1 and _body(matches[0][0]) == _body(cursor))
        cursor = matches[0][1]
    p.require(False, "credential ancestry exceeded the complete retained graph")


def published_pending(graph, pending, current):
    candidates = [current]
    for before, after in edges(graph, current["id"]):
        candidates.extend((before, after))
    matches = [row for row in candidates if row["id"] == pending["id"]
        and _envelope(row) == _envelope(pending) and row["metadata"] == pending["metadata"]
        and row["name"] == pending["name"] and row["kind"] == pending["kind"]]
    p.require(matches, "pending absence has no positive published credential original")
    require_descendant(graph, matches[0], current)


def _material(kind, source, version, row, custody, token, secret_sha, enrollment_original, provider, originals):
    refresh.envelope(token, version)
    raw_enrollment = p.activation.enrollment_bytes(enrollment_original) if enrollment_original is not None else None
    if raw_enrollment is not None:
        application = enrollment.enrollment_document(raw_enrollment)["payload"]
        p.require(application["providerId"] == provider)
        enrollment_sha = p.sha256(raw_enrollment)
    else:
        association = records.stored(row["metadata"], 32768).get("oauth_application_owner")
        p.require(type(association) is dict); enrollment_sha = association["enrollmentSha256"]; p.digest(enrollment_sha)
    return {"apiVersion": MATERIAL_SCHEMA,
        "pin": {"materialId": p.material_id(kind, source, version), "sourceKind": kind, "sourceId": source,
            "sourceVersion": version, "sourceRowSha256": p.sha256(p.canonical(row)),
            "custodyRowSha256": None if custody is None else p.sha256(p.canonical(custody)),
            "tokenSecretSha256": secret_sha, "tokenEnvelopeSha256": p.sha256(p.canonical(token)),
            "enrollmentSha256": enrollment_sha, "tokenPurposes": None},
        "providerId": provider, "enrollmentOriginal": None if raw_enrollment is None else raw_enrollment.decode("ascii"),
        "tokenEnvelope": token, "aadCredentialId": source, "aadCredentialVersion": version, "sourceOriginals": originals}


def collect(graph, grant, analysis, target_enrollment_original):
    """Every affected leaf is compared with a grant pin, including settled ones."""
    from catchplate import authority_oauth_retirement_succession_inventory as inventory
    leaves, represented_work = [], set()
    by_id = {row["id"]: row for row in graph.rows("credentials")}
    for raw in analysis["affectedCredentials"]:
        row = records.stored(raw, 512 * 1024)
        original = target_enrollment_original if row["id"] == grant["credentialId"] else None
        leaves.append(_material("credential-current", row["id"], row["credential_version"], row, None, _envelope(row), None,
            original, grant["providerId"], {"credentialOriginal": raw}))
    for source in analysis["exchangeSources"]:
        history = records.stored(source["exchangeOriginal"], exchange.MAX_ROW_BYTES)
        custody = records.stored(source["custodyOriginal"]); kind = source["sourceKind"]
        if source["state"] == "never-contacted":
            work = graph.row("oauth_revocation_work", history["id"], optional=True)
            if kind in {"initial", "setup"}:
                contract = initial if kind == "initial" else setup
                preparation = contract.arguments(contract.OP_PREPARE, records.stored(custody["preparation_arguments_json"], p.MAX_ARGUMENT_BYTES))
                p.require(work is not None and work["source"] == contract.WORK_SOURCE and work["provider_id"] == grant["providerId"]
                    and work["actor_id"] == history["requester_id"] and work["attempts"] == 0
                    and work["status"] == ("cancelled_before_contact" if custody["status"] == "cancelled" else "reserved")
                    and _envelope(work) == preparation["request"]["reservedEnvelope"])
                represented_work.add(work["id"])
            else:
                p.require(work is None)
            continue
        if source["state"] == "outside-scope":
            p.require(graph.row("oauth_revocation_work", history["id"], optional=True) is None)
            continue
        if source["state"] == "retained":
            token = records.stored(history["token_envelope_json"], refresh.MAX_ENVELOPE_BYTES)
            work = graph.row("oauth_revocation_work", history["id"], optional=True)
            if kind in {"initial", "setup"}:
                contract = initial if kind == "initial" else setup
                p.require(work is not None and work["source"] == contract.WORK_SOURCE and work["provider_id"] == grant["providerId"]
                    and work["actor_id"] == history["requester_id"] and _envelope(work) == token)
                represented_work.add(work["id"])
            else:
                p.require(work is None, "reconnect/succession cannot borrow a fabricated revocation-work source")
            leaves.append(_material(kind + "-capture", history["id"], 1, history, custody, token,
                history["token_secret_sha256"], history["enrollment_original"], grant["providerId"], source))
        elif kind in {"initial", "setup"}:
            pending = source["currentPendingOriginal"]
            if pending is not None:
                row = records.stored(pending, activation.MAX_PENDING_BYTES)
                contract = initial if kind == "initial" else setup
                stage = contract.arguments(contract.OP_STAGE, records.stored(custody["stage_arguments_json"], p.MAX_ARGUMENT_BYTES))
                leaves.append(_material(kind + "-pending", row["id"], 1, row, custody, _envelope(row),
                    stage["request"]["tokenSecretSha256"], history["enrollment_original"], grant["providerId"], source))
        elif custody["status"] != "committed":
            p.require(custody["status"] == "staged")
            candidate = records.stored(source["candidateOriginal"], p.MAX_CANDIDATE_BYTES)
            material = _material(kind + "-candidate", history["id"], candidate["previousVersion"] + 1, candidate, custody,
                candidate["tokenEnvelope"], candidate["tokenSecretSha256"], history["enrollment_original"], grant["providerId"], source)
            material["aadCredentialId"] = candidate["credentialId"]
            leaves.append(material)
    for history in graph.rows(refresh.TABLE):
        if history["provider_id"] != grant["providerId"]:
            continue
        before = records.stored(history["credential_original_json"], 512 * 1024)
        if not inventory.in_scope(inventory.metadata(before), grant):
            for purpose in ("issued", "superseded"):
                item_id = history[purpose + "_work_id"]
                if item_id is not None and graph.row("oauth_revocation_work", item_id, optional=True) is not None:
                    represented_work.add(item_id)
            continue
        custody = graph.row(measured_refresh.TABLE, history["id"]); measured_refresh.row_original(custody)
        p.require(custody["credential_id"] == history["credential_id"] == before["id"]
            and custody["credential_version"] == history["credential_version"] == before["credential_version"]
            and custody["enrollment_original"] == history["enrollment_original"])
        capture = measured_refresh.request(measured_refresh.OP_CAPTURE, records.stored(custody["capture_request_json"], p.MAX_ARGUMENT_BYTES))
        p.require(capture["issuedMaterialSha256"] == history["issued_material_sha256"]
            and p.canonical(capture["issuedMaterialEnvelope"]).decode("ascii") == history["issued_material_envelope_json"]
            and capture["rawResponseSha256"] == history["raw_response_sha256"]
            and p.canonical(capture["rawResponseEnvelope"]).decode("ascii") == history["raw_response_envelope_json"])
        for purpose in ("issued", "superseded"):
            item_id = history[purpose + "_work_id"]
            work = None if item_id is None else graph.row("oauth_revocation_work", item_id, optional=True)
            required = history["status"] == "retained" if purpose == "issued" else history["status"] == "committed" and history["superseded_material_sha256"] is not None
            if not required:
                if purpose == "superseded" and history["status"] == "retained" and item_id is not None:
                    claim = measured_refresh.request(measured_refresh.OP_CLAIM, records.stored(custody["claim_request_json"], p.MAX_ARGUMENT_BYTES))
                    p.require(work is not None and work["status"] == "refresh_superseded_reserved" and work["attempts"] == 0
                        and work["source"] == measured_refresh.SUPERSEDED_SOURCE and work["actor_id"] == "oauth-refresh"
                        and item_id == refresh.artifact_id(history["id"], "superseded")
                        and _envelope(work) == claim["reservedSupersededEnvelope"])
                    represented_work.add(item_id)
                else:
                    p.require(work is None, "superseded/issued absence must follow its positive committed producer")
                continue
            p.require(work is not None and item_id == refresh.artifact_id(history["id"], purpose)
                and work["source"] == (measured_refresh.ISSUED_SOURCE if purpose == "issued" else measured_refresh.SUPERSEDED_SOURCE)
                and work["provider_id"] == grant["providerId"] and work["actor_id"] == "oauth-refresh"
                and work["created_at"] == history["created_at"])
            token = _envelope(work); revocation.work_original(work)
            if purpose == "issued":
                p.require(custody["status"] == "captured" and history["issued_material_envelope_json"] == p.canonical(token).decode("ascii"))
            else:
                commit = measured_refresh.request(measured_refresh.OP_COMMIT, records.stored(custody["commit_request_json"], p.MAX_ARGUMENT_BYTES))
                p.require(grant["providerId"] == "x" and custody["status"] == "committed"
                    and commit["supersededEnvelope"] == token and commit["supersededMaterialSha256"] == history["superseded_material_sha256"])
            represented_work.add(item_id)
            leaves.append(_material("refresh-" + purpose, item_id, 1, work, custody, token, history[purpose + "_material_sha256"],
                history["enrollment_original"], grant["providerId"], {"refreshOriginal": p.canonical(history).decode("ascii"),
                    "custodyOriginal": p.canonical(custody).decode("ascii"), "workOriginal": p.canonical(work).decode("ascii")}))
        if history["status"] == "committed":
            p.require(before["id"] in by_id)
            require_descendant(graph, before, by_id[before["id"]])
    for work in graph.rows("oauth_revocation_work"):
        if work["provider_id"] == grant["providerId"]:
            revocation.work_original(work)
            p.require(work["id"] in represented_work, "unclassified same-provider work requires an explicit complete retirement scope")
            p.require(work["lease_owner"] is None and work["lease_until"] is None and work["last_error"] is None)
    p.require(len(leaves) <= p.MAX_MATERIALS and len({value["pin"]["materialId"] for value in leaves}) == len(leaves))
    leaves.sort(key=lambda value: value["pin"]["materialId"])
    p.require([value["pin"]["materialId"] for value in leaves] == [pin["materialId"] for pin in grant["materials"]],
        "grant omitted or invented a leaf in the complete retained token graph")
    for value, pin in zip(leaves, grant["materials"]):
        value["pin"]["tokenPurposes"] = pin["tokenPurposes"]
        p.require(value["pin"] == pin)
        if grant["providerId"] == "x" and pin["sourceKind"] == "credential-current":
            p.require(pin["tokenPurposes"] == ["access", "refresh"])
        p.require(set(value) == MATERIAL_FIELDS and len(p.canonical(value)) <= p.MAX_ROW_BYTES)
    return leaves
