"""Exact predecessor/credential/currentness joins for the new independent scope."""
from serverware import authority_oauth_retirement_succession as p
from serverware import authority_oauth_retirement_succession_records as records
from serverware import authority_oauth_retirement_succession_inventory as inventory
from serverware import authority_oauth_refresh as refresh
from serverware import authority_oauth_activation_policy as enrollment
from serverware import authority_transition_credential_currentness as currentness
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_oauth_reconnect_rows as scalars

iso, epoch = scalars.iso, scalars.epoch
BARRIER_FIELDS = frozenset({"credentialId", "credentialVersion", "barrierSha256", "consumeRequestDigest"})


def grant(values):
    return p.grant_document(p.decoded(values["authorization_original"], p.MAX_GRANT_BYTES))["payload"]


def members(context, expected):
    result = []
    for pin in expected["affectedLineages"]:
        row = shared._row(context.exact("credentials", {"id": pin["credentialId"]}), "actual affected succession credential")
        head = shared._row(context.exact("credential_generations", {"credential_id": pin["credentialId"]}), "actual affected generation")
        metadata = inventory.metadata(row)
        p.require(row["kind"] == "oauth2" and metadata.get("provider_identity_verified") is True
            and inventory.in_scope(metadata, expected) and row["id"] == head["credential_id"] == pin["credentialId"]
            and row["credential_version"] == head["last_version"] == pin["credentialVersion"]
            and p.sha256(refresh.credential_original(row)) == pin["credentialRowSha256"]
            and p.sha256(refresh.generation_original(head)) == pin["generationRowSha256"])
        if pin["predecessorKind"] == "active":
            p.require(row["lifecycle_status"] == "active" and row["revocation_error"] is None and row["revocation_requested_at"] is None)
        if row["id"] == expected["credentialId"]:
            p.require(metadata["provider_subject"] == expected["providerSubject"] and metadata["provider_account"] == expected["providerAccount"]
                and p.sha256(p.canonical(metadata)) == expected["metadataSha256"])
        result.append((row, head))
    return result


def exact_application(values, expected, target):
    raw = p.activation.enrollment_bytes(values["enrollment_original"])
    payload = enrollment.enrollment_document(raw)["payload"]; metadata = inventory.metadata(target)
    p.require(metadata.get("oauth_application_owner") == enrollment.association(raw)
        and payload["providerId"] == metadata["provider_id"] == expected["providerId"]
        and payload["clientId"] == expected["clientId"]
        == metadata.get("oauth_client_id" if expected["providerId"] == "google" else "x_app_id"))


def journal(context, values, *, statuses):
    expected = grant(values)
    selected = context.exact(p.JOURNAL_TABLE, {"id": expected["authorizationId"]})
    row = shared._row(selected, "actual succession authorization")
    records.journal_original(row)
    p.require(row["authorization_original"] == p.decoded(values["authorization_original"], p.MAX_GRANT_BYTES).decode("ascii")
        and row["authorization_sha256"] == p.sha256(row["authorization_original"].encode("ascii"))
        and row["actor_id"] == expected["requesterId"] and row["provider_id"] == expected["providerId"]
        and row["credential_policy_json"] == p.canonical(values["credential_policy"]).decode("ascii")
        and row["admission_expires_at"] == iso(expected["admissionExpiresAtEpochNs"])
        and row["expires_at"] == iso(expected["expiresAtEpochNs"]) and row["status"] in statuses)
    original = p.arguments(p.OP_AUTHORIZE, records.stored(row["authorize_arguments_json"], p.MAX_ARGUMENT_BYTES))
    p.require(original["authorization_original"] == values["authorization_original"] and original["actor_id"] == expected["requesterId"]
        and original["enrollment_original"] == p.encoded(row["enrollment_original"].encode("ascii"))
        and original["credential_policy"] == values["credential_policy"])
    if context.operation not in p.MATERIAL_OPERATIONS | {p.OP_RECOVER} or values["request"].get("materialId") is None:
        p.require(row["enrollment_original"] == p.activation.enrollment_bytes(values["enrollment_original"]).decode("ascii"))
    return selected, row, expected


def _pair(journal, credential_id, name="original_affected_json"):
    values = records.array(journal[name])
    found = []
    for pair in values:
        p.require(type(pair) is dict and set(pair) == {"credentialOriginal", "generationOriginal"})
        row, head = records.stored(pair["credentialOriginal"], 512 * 1024), records.stored(pair["generationOriginal"], 8192)
        refresh.credential_original(row); refresh.generation_original(head)
        p.require(head["credential_id"] == row["id"] and head["last_version"] == row["credential_version"])
        if row["id"] == credential_id:
            found.append((row, head))
    p.require(len(found) == 1, "retired lineage is not associated with its actual predecessor")
    return found[0]


def _barrier(journal, credential_id, version):
    values = records.array(journal["currentness_barriers_json"], 65536)
    found = [value for value in values if value.get("credentialId") == credential_id and value.get("credentialVersion") == version]
    p.require(len(found) == 1); p.digest(found[0]["barrierSha256"])
    return found[0]


def predecessor_drain(context, graph, pin, before, head, predecessors):
    selected = [item for item in predecessors if item["kind"] == pin["predecessorKind"]
        and records.stored(item["rowOriginal"])["id"] == pin["predecessorId"]]
    p.require(len(selected) == 1)
    item = selected[0]; marker = records.stored(item["rowOriginal"]); journal = records.stored(item["journalOriginal"])
    p.require(p.sha256(item["rowOriginal"].encode("ascii")) == pin["predecessorSha256"])
    kind, identifier, version = pin["predecessorKind"], before["id"], before["credential_version"]
    if kind == "refresh-family":
        original = records.stored(journal["original_credential_json"], 512 * 1024)
        old_head = records.stored(journal["original_generation_json"], 8192)
        p.require(marker["credential_id"] == identifier and marker["credential_version"] == version)
        desired = {**original, "lifecycle_status": "revocation_pending", "revocation_requested_at": journal["created_at"], "updated_at": journal["created_at"]}
        digest, consumed = journal["currentness_barrier_sha256"], journal["claim_request_digest"]
        # The original N refresh barrier was consumed by the token POST claim,
        # not by its later cleanup claim. The protected cleanup grant pins it.
        from serverware import authority_oauth_refresh_cleanup as cleanup
        from serverware import authority_oauth_measured_cleanup as measured_cleanup
        if graph.row(measured_cleanup.TABLE, journal["id"], optional=True) is not None:
            cleanup = measured_cleanup
        old_grant = cleanup.grant_document(cleanup.unb64(journal["authorization_original"], cleanup.MAX_GRANT_BYTES))["payload"]
        if old_grant["credentialVersion"] == old_grant["refreshVersion"]:
            history = graph.row(refresh.TABLE, old_grant["refreshId"])
            p.require(history["credential_id"] == identifier and history["credential_version"] == version
                and refresh.row_digest(history) == old_grant["refreshRowSha256"] and digest == old_grant["historicalBarrierSha256"])
            consumed = history["claim_request_digest"]
    elif kind in {"pending-family", "provider-capture"}:
        original, old_head = _pair(journal, identifier)
        desired = {**original, "lifecycle_status": "revocation_pending", "revocation_requested_at": journal["created_at"], "updated_at": journal["created_at"]}
        digest = _barrier(journal, identifier, version)["barrierSha256"]; consumed = journal["claim_request_digest"]
    elif kind == "reconnect-fence":
        original, old_head = _pair(journal, identifier)
        old_grant = records.reconnect.grant_document(journal["authorization_original"].encode("ascii"))["payload"]
        desired = {**original, "lifecycle_status": "reconnect_pending" if identifier == old_grant["credentialId"] else "reconnect_fenced", "updated_at": journal["updated_at"]}
        digest = _barrier(journal, identifier, version)["barrierSha256"]; consumed = journal["fence_request_digest"]
    else:
        p.require(kind == "succession")
        original, old_head = _pair(marker, identifier, "affected_originals_json")
        desired = {**original, "lifecycle_status": "succession_fenced", "updated_at": marker["created_at"]}
        old_grant = p.grant_document(journal["authorization_original"].encode("ascii"))["payload"]
        p.require(identifier != old_grant["credentialId"], "an activated successor needs its actual new currentness association")
        barrier = _barrier(marker, identifier, version); digest, consumed = barrier["barrierSha256"], barrier["consumeRequestDigest"]
    p.require(before == desired and head == old_head and original["id"] == identifier
        and original["credential_version"] == version, "predecessor does not own this exact still-fenced generation")
    _, root = currentness.require_root(context, identifier, version)
    _, retained, _ = currentness._barrier(context, root, root["barrier_id"], digest)
    p.require(root["status"] == retained["status"] == "consumed" and retained["consume_request_digest"] == consumed)
    return {"credentialId": identifier, "credentialVersion": version, "barrierSha256": digest, "consumeRequestDigest": consumed}


def fence(context, graph, expected, before_members, predecessors, requested):
    p.require([item["credentialId"] for item in requested] == [pin["credentialId"] for pin in expected["affectedLineages"] if pin["predecessorKind"] == "active"])
    effects, drains = [], []
    for pin, (row, head) in zip(expected["affectedLineages"], before_members):
        if pin["predecessorKind"] == "active":
            found = next(item for item in requested if item["credentialId"] == row["id"])
            effects.extend(currentness.consume_barrier(context, row["id"], row["credential_version"], found["barrierSha256"]))
            drain = {"credentialId": row["id"], "credentialVersion": row["credential_version"],
                "barrierSha256": found["barrierSha256"], "consumeRequestDigest": context.request_digest}
        else:
            drain = predecessor_drain(context, graph, pin, row, head, predecessors)
        drains.append(drain)
        effects.append(core.mutation(operation=context.operation, selected=context.exact("credentials", {"id": row["id"]}),
            row={**row, "lifecycle_status": "succession_pending" if row["id"] == expected["credentialId"] else "succession_fenced", "updated_at": context.database_now.isoformat()}))
    return drains, effects


def retained(context, scope, expected, *, committed=None):
    values = records.array(scope["affected_originals_json"]); drains = records.array(scope["currentness_barriers_json"], 65536)
    p.require(len(values) == len(drains) == len(expected["affectedLineages"]))
    result = []
    for pair, drain, pin in zip(values, drains, expected["affectedLineages"]):
        p.require(type(drain) is dict and set(drain) == BARRIER_FIELDS)
        before, head = records.stored(pair["credentialOriginal"], 512 * 1024), records.stored(pair["generationOriginal"], 8192)
        p.require(p.sha256(refresh.credential_original(before)) == pin["credentialRowSha256"]
            and p.sha256(refresh.generation_original(head)) == pin["generationRowSha256"]
            and before["id"] == drain["credentialId"] == pin["credentialId"]
            and before["credential_version"] == drain["credentialVersion"] == pin["credentialVersion"])
        current = shared._row(context.exact("credentials", {"id": before["id"]}), "retained succession credential")
        current_head = shared._row(context.exact("credential_generations", {"credential_id": before["id"]}), "retained succession generation")
        replaced = committed is not None and before["id"] == expected["credentialId"]
        desired = committed if replaced else {**before, "lifecycle_status": "succession_pending" if before["id"] == expected["credentialId"] else "succession_fenced", "updated_at": scope["created_at"]}
        p.require(current == desired and current_head == ({**head, "last_version": head["last_version"] + 1, "updated_at": committed["updated_at"]} if replaced else head))
        _, root = currentness.require_root(context, before["id"], before["credential_version"])
        _, barrier, _ = currentness._barrier(context, root, root["barrier_id"], drain["barrierSha256"])
        p.require(root["status"] == barrier["status"] == "consumed" and barrier["consume_request_digest"] == drain["consumeRequestDigest"])
        result.append((before, head))
    return result
