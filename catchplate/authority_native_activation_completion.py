"""Finite native handoff producer bounds. No completion verdict is exported."""
from catchplate import authority_policy_canary as p
from catchplate import authority_policy_native_activation as profile
from catchplate import authority_native_activation_hold as hold


def _settlement_bound(signed_plan, native_upper):
    """Bound the real later controlled input, including duplicated intent.

    This is byte admission only. The later planner still independently acquires
    every current original/root; this local projection is never authority.
    """
    from catchplate import authority_contract as contract
    from catchplate import authority_policy_canary_tables as tables
    plan = signed_plan["payload"]
    values = profile.arguments(profile.PREFIX + "consume", plan["typedRequest"]["arguments"], typed=True)
    before = profile.canonical_original(values["before_original"], profile.MAX_BEFORE)
    for mutation in plan["mutationPlan"]:
        table = mutation["table"]
        if table not in tables.TABLES:
            continue
        p.require(mutation["operation"] in {"INSERT", "UPDATE"})
        before[table] = [row for row in before[table] if tables.key(table, row) != mutation["key"]] + [mutation["row"]]
        before[table].sort(key=lambda row: p.canonical(tables.key(table, row)))
    after_original = p.canonical(before).decode("ascii")
    p.require(len(after_original) <= profile.MAX_BEFORE)
    prepared = profile.prepared(profile.canonical_original(plan["expectedResult"]["preparedOriginal"]))
    approval = profile.canonical_original(prepared["approvalOriginal"])
    future = {**values, "approval_id": approval["id"], "approval_original": prepared["approvalOriginal"],
        "before_original": after_original, "native_request": {}, "publication_original": ""}
    # Actual typedRequest contains both arguments and businessIntent.arguments.
    # All originals are canonical ASCII: one string quoting adds at most 2x.
    # Additional room covers the fixed handler/runtime envelopes and the later
    # inclusion receipt retained inside the current preparation row.
    p.require(2 * (len(p.canonical(future)) + native_upper + 2 * 32768) + 16384 <= contract.MAX_REQUEST_BYTES,
        "native publication cannot fit its later complete protected settlement")


def planned_hold(signed_plan):
    plan = signed_plan["payload"]
    matches = [item for item in plan["mutationPlan"] if item["table"] == hold.TABLE]
    p.require(plan["typedRequest"]["operation"] == profile.PREFIX + "consume" and len(matches) == 1)
    selected = matches[0]
    row = hold.original(selected["row"])
    p.require(row["phase"] == "held" and selected["operation"] in {"INSERT", "UPDATE"}
        and selected["key"] == {"scope": hold.SCOPE}
        and (selected["expectedRow"] is None if selected["operation"] == "INSERT"
            else hold.original(selected["expectedRow"])["phase"] == "published"))
    result = plan["expectedResult"]
    prepared = profile.prepared(profile.canonical_original(result["preparedOriginal"]))
    p.require(row["prepared_sha256"] == result["preparedSha256"] == p.sha256(p.canonical(prepared))
        and row["activation_id"] == prepared["activationId"] and row["canary_id"] == prepared["canaryId"]
        and row["prepare_request_digest"] == result["requestDigest"]
        and row["configuration_digest"] == prepared["controlPlaneConfigurationSha256"]
        and row["issued_at_epoch_ns"] == prepared["issuedAtUnixNanos"] and row["expires_at_epoch_ns"] == prepared["expiresAtUnixNanos"])
    return p.canonical(row).decode("ascii")


def preflight(request_original, signed_plan, configuration_original, consumption_original):
    p.require(type(request_original) is bytes and type(configuration_original) is bytes and type(consumption_original) is bytes
        and len(request_original) <= profile.MAX_NATIVE and len(consumption_original) <= 8192)
    original = planned_hold(signed_plan)
    planned, result = p.canonical(signed_plan), p.canonical(signed_plan["payload"]["expectedResult"])
    # Scalar receipt/witness originals are independently bounded again at emit.
    response_upper = (16384 + len(consumption_original) + (len(configuration_original) * 4 + 2) // 3
        + len(p.canonical(planned.decode("ascii"))) + 2 * (len(result) + 8192) + len(result) + 4 * 8192
        + len(p.canonical(original)))
    native_upper = 1024 + 2 * len(request_original) + 2 * response_upper
    p.require(native_upper <= profile.MAX_NATIVE,
        "complete native request/proof cannot fit the unchanged 8 MiB frame")
    _settlement_bound(signed_plan, native_upper)


def emitted(request_original, response_original):
    response = profile.canonical_original(response_original.decode("ascii"), profile.MAX_NATIVE)
    proof = response["activationOriginals"]
    p.require(set(proof) == profile.PROOF_FIELDS and set(response["result"]) == profile.RESULT_FIELDS)
    plan = profile.canonical_original(proof["signedMeasuredPlanOriginal"], profile.MAX_NATIVE)
    p.require(proof["nativeEffectHoldOriginal"] == planned_hold(plan))
    for name in ("witnessRequestOriginal", "witnessResponseOriginal"):
        p.require(len(proof[name].encode("ascii")) <= 8192)
    execution = profile.canonical_original(proof["executorCompletionOriginal"], profile.MAX_NATIVE)
    p.require(len(p.canonical(execution["receipt"])) <= 8192 and len(p.canonical(response["attestationConsumptionReceipt"])) <= 8192)
    prepared = profile.canonical_original(response["result"]["preparedOriginal"])
    profile.native_request({"apiVersion": profile.NATIVE_REQUEST, "requestId": prepared["activationId"], "replayId": prepared["replayId"],
        "prepareRequestOriginal": request_original.decode("ascii"), "prepareResponseOriginal": response_original.decode("ascii")})
