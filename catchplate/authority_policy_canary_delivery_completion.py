"""Verify actual signed completion and persisted-row read originals.

Planner before-proofs are not post-write readback. Preparation is proven by
its complete after transition; a separate completed recover/read proves the
persisted slot/head/parts at that read's before-roots. Expired originals are
historical data, never renewed execution permission.
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import authority_policy_canary_delivery as profile

ORIGINAL_FIELDS = frozenset({"signedMeasuredPlanOriginal", "executorCompletionOriginal", "witnessRequestOriginal", "witnessResponseOriginal"})
RUNTIME_FIELDS = frozenset({"schema", "requestId", "operation", "configurationDigest", "requestDigest", "issuedAtEpochNs",
    "deadlineMonotonicNs", "fence", "result", "resultDigest", "commitReceiptDigest", "witnessCommitDigest",
    "attestationReceiptDigest", "attestationConsumptionReceipt", "attestationConsumptionReceiptDigest", "signature",
    "authorityConfigurationOriginal", "deliveryOriginals"})
PLAN_FIELDS = frozenset({"schema", "measuredPlan", "typedRequest", "selectedBusinessRows", "mutationPlan", "queryMultiproofs",
    "queryMultiproofsDigest", "plannerTrace", "plannerTraceDigest", "authorizationProjection", "webauthnEvidence",
    "expectedResult", "expectedResultDigest", "plannerIdentity", "rootTransition"})
MEASURED_FIELDS = frozenset({"schema", "plannerTransactionId", "operation", "operationId", "requestDigest", "capabilityId",
    "sourceRevision", "authoritySchemaVersion", "operationContractDigest", "operationManifestDigest", "handlerContractDigest",
    "queryManifestDigest", "selectedBusinessRowsDigest", "mutationPlanDigest", "workUnits", "authorityRootSetBeforeDigest",
    "authorizationProjectionDigest", "authoritySnapshotDigest", "rootTransitionDigest", "deadlineMonotonicNs", "deadlineEpochNs", "fence"})
WITNESS_REQUEST_FIELDS = frozenset({"schema", "envelopeId", "parentEnvelopeId", "phase", "operation", "requestDigest",
    "capabilityId", "resultDigest", "predecessorReceiptDigest", "deadlineMonotonicNs", "configurationDigest",
    "operationManifestDigest", "generationSequence", "generationDigest", "issuedAtEpochNs", "signature"})
WITNESS_RESPONSE_FIELDS = frozenset({"schema", "envelopeId", "parentEnvelopeId", "phase", "operation", "requestDigest",
    "capabilityId", "resultDigest", "witnessIdentityDigest", "sequence", "fence", "headDigest", "predecessorHeadDigest",
    "predecessorReceiptDigest", "logPredecessorHeadDigest", "deadlineMonotonicNs", "issuedAtEpochNs", "generationSequence",
    "generationDigest", "canonicalRequestDigest", "signature"})
COMMIT_FIELDS = frozenset({"schema", "capabilityId", "envelopeId", "plannerTransactionId", "authorizationProjectionDigest",
    "operation", "handlerName", "requestDigest", "resultDigest", "authorityRootSetBeforeDigest", "authorityRootSetAfterDigest",
    "authoritySnapshotDigest", "operationManifestDigest", "queryManifestDigest", "witnessReservationDigest", "witnessSequence",
    "deadlineMonotonicNs", "fence", "committedAtEpochNs", "sourceRevision"})


def preflight_bounds(operation, *, request_original, signed_plan, configuration_original, consumption_original):
    """Conservative byte arithmetic only; no synthetic receipt is emitted.

The actual signed plan already exists. The fixed scalar commit/witness
inventories fit their reserved 8 KiB originals, independently rechecked on
return. JSON quoting is bounded at two output bytes per original ASCII byte.
"""
    profile.require(operation in profile.OPERATIONS and type(request_original) is bytes
        and len(request_original) <= profile.MAX_ARGUMENT and type(configuration_original) is bytes
        and type(consumption_original) is bytes and len(consumption_original) <= 8192)
    planned = profile.canonical(signed_plan)
    expected = profile.canonical(signed_plan["payload"]["expectedResult"])
    profile.require(len(planned) <= profile.MAX_RESPONSE and len(expected) <= profile.MAX_ARGUMENT)
    # The full signed runtime envelope has the actual result plus its exact
    # executor-return result. Plan and receipt originals are JSON strings.
    response_upper = (16384 + len(consumption_original) + (len(configuration_original) * 4 + 2) // 3
        + len(profile.canonical(planned.decode("ascii"))) + 2 * (len(expected) + 8192) + len(expected) + 4 * 8192)
    http_upper = 1024 + (len(request_original) * 4 + 2) // 3 + (response_upper * 4 + 2) // 3
    profile.require(response_upper <= profile.MAX_RESPONSE and http_upper <= profile.MAX_RESPONSE,
        "complete delivery response cannot fit its existing whole-frame ceiling")
    if operation in {profile.OP_PREPARE, profile.OP_RECOVER}:
        completion_upper = 1024 + 2 * len(request_original) + 2 * response_upper
        profile.require(completion_upper <= profile.MAX_COMPLETION,
            "complete prepare/read proof cannot fit the unchanged future claim allowance")


def check_emitted_bounds(operation, request_original, response_original):
    profile.require(operation in profile.OPERATIONS and type(request_original) is bytes and type(response_original) is bytes
        and len(request_original) <= profile.MAX_ARGUMENT and len(response_original) <= profile.MAX_RESPONSE)
    response = profile.document(response_original, profile.MAX_RESPONSE)
    originals = response["deliveryOriginals"]
    profile.require(set(originals) == ORIGINAL_FIELDS)
    for field in ("witnessRequestOriginal", "witnessResponseOriginal"):
        profile.require(len(originals[field].encode("ascii")) <= 8192)
    executed = profile.document(originals["executorCompletionOriginal"].encode("ascii"), profile.MAX_RESPONSE)
    profile.require(len(profile.canonical(executed["receipt"])) <= 8192
        and len(profile.canonical(response["attestationConsumptionReceipt"])) <= 8192)
    if operation in {profile.OP_PREPARE, profile.OP_RECOVER}:
        completion_original = profile.canonical({"schema": profile.COMPLETION_SCHEMA,
            "requestOriginal": request_original.decode("ascii"), "responseOriginal": response_original.decode("ascii")})
        profile.require(len(completion_original) <= profile.MAX_COMPLETION)
    profile.require(1024 + (len(request_original) * 4 + 2) // 3 + (len(response_original) * 4 + 2) // 3 <= profile.MAX_RESPONSE)


def _key(value):
    return Ed25519PublicKey.from_public_bytes(profile.decoded(value, 32, length=32))


def _verify_signed(value, key, schema, field="signature"):
    from catchplate import authority_request_commitment as commitment
    profile.require(type(value) is dict and value.get("schema") == schema and field in value)
    unsigned = {name: item for name, item in value.items() if name != field}
    key.verify(profile.decoded(value[field], 64, length=64), commitment.framed_digest(schema, profile.canonical(unsigned)).encode("ascii"))


def _observe(plan, result, operation):
    """Tie the result to actual authenticated before/after rows, not a DTO."""
    observation = result["observation"]
    profile.require(result["status"] == "prepared")
    slot = profile.document(observation["slotOriginal"].encode("ascii"), 1024 * 1024)
    head = profile.document(observation["headOriginal"].encode("ascii"), 1024 * 1024)
    rows = plan["mutationPlan"] if operation == profile.OP_PREPARE else plan["selectedBusinessRows"]
    originals = {}
    for item in rows:
        if item["table"] not in profile.TABLES:
            continue
        if operation == profile.OP_PREPARE:
            profile.require(item["operation"] in {"INSERT", "UPDATE"})
            row = item["row"]
        else:
            if not item["present"]: continue
            row = item["row"]
        key = (item["table"], profile.canonical(item["key"]))
        profile.require(key not in originals)
        originals[key] = row
    profile.require(originals[(profile.SLOTS, profile.canonical({"id": slot["id"]}))] == slot
        and originals[(profile.HEADS, profile.canonical({"id": head["id"]}))] == head
        and head["slot_id"] == slot["id"] and head["status"] == slot["status"] == "prepared")
    parts = [originals[(profile.PARTS, profile.canonical({"slot_id": slot["id"], "ordinal": ordinal}))]
        for ordinal in range(slot["part_count"])]
    profile.require(profile.reassemble(slot, parts) == observation["httpOriginal"])
    if operation == profile.OP_RECOVER:
        profile.require(all(item["table"] not in profile.TABLES for item in plan["mutationPlan"]),
            "authenticated recovery read cannot mutate delivery authority")
    return observation


def verify(original, *, admission, allowed_operations, now):
    from catchplate import authority_contract as contract
    from catchplate import authority_planner as planner
    from catchplate import authority_primary_contract as primary
    from catchplate import authority_request_commitment as commitment
    from catchplate import authority_root_transition as roots
    from catchplate import authority_service as service
    from catchplate import authority_policy_canary_delivery_policy as policy
    profile.require(type(admission) is policy._Admission)
    admission.check()
    wrapper = profile.completion_original(original)
    request = profile.document(wrapper["requestOriginal"].encode("ascii"), profile.MAX_ARGUMENT)
    response = profile.document(wrapper["responseOriginal"].encode("ascii"), profile.MAX_RESPONSE)
    profile.require(set(request) == {"schema", "requestId", "operation", "input", "configurationDigest", "operationManifestDigest",
        "startedMonotonicNs", "deadlineMonotonicNs"} and request["schema"] == service.RUNTIME_REQUEST_SCHEMA
        and request["operation"] in allowed_operations and set(response) == RUNTIME_FIELDS
        and response["schema"] == profile.RESPONSE_SCHEMA and response["operation"] == request["operation"])
    config_original = profile.decoded(response["authorityConfigurationOriginal"], service.MAX_CONFIG_BYTES)
    configuration = profile.document(config_original, service.MAX_CONFIG_BYTES, exact=False)
    profile.require(set(configuration) == {"schema", "payload", "signature"} and configuration["schema"] == service.SIGNED_CONFIG_SCHEMA)
    payload = configuration["payload"]
    admission._configuration.root_key.verify(profile.decoded(configuration["signature"], 64, length=64),
        commitment.framed_digest(service.SIGNED_CONFIG_SCHEMA, profile.canonical(payload)).encode("ascii"))
    config_digest = commitment.framed_digest(service.CONFIG_SCHEMA, profile.canonical(payload))
    profile.require(payload["schema"] == service.CONFIG_SCHEMA and payload["sourceRevision"] == contract.SOURCE_REVISION
        and request["configurationDigest"] == response["configurationDigest"] == config_digest
        and request["operationManifestDigest"] == contract.OPERATION_MANIFEST_DIGEST
        and response["requestId"] == request["requestId"]
        and response["requestDigest"] == commitment.framed_digest(service.RUNTIME_REQUEST_SCHEMA, profile.canonical(request))
        and response["deadlineMonotonicNs"] == request["deadlineMonotonicNs"]
        and type(response["fence"]) is int and response["fence"] > 0
        and profile.epoch(response["issuedAtEpochNs"]) <= now)
    verifier = payload["roles"]["verifier"]
    _verify_signed(response, _key(verifier["signingPublicKeyBase64Url"]), profile.RESPONSE_SCHEMA)
    profile.require(response["attestationReceiptDigest"] == verifier["attestationReceiptDigest"]
        and response["attestationConsumptionReceiptDigest"] == commitment.framed_digest(
            response["attestationConsumptionReceipt"]["schema"], profile.canonical(response["attestationConsumptionReceipt"])))
    profile.require(set(request["input"]) == {"schema", "handler", "operationManifestDigest", "arguments"}
        and request["input"]["schema"] == "catchplate.policyAuthorityControlledWriterInput/v1"
        and request["input"]["operationManifestDigest"] == contract.OPERATION_MANIFEST_DIGEST
        and request["input"]["handler"] == contract.operation_spec(request["operation"])["handler"])
    arguments = profile.arguments(request["operation"], request["input"]["arguments"])
    policy.verify_original(request["operation"], arguments, configuration_payload=payload,
        root_key=admission._configuration.root_key, now_epoch_ns=response["issuedAtEpochNs"])
    result = profile.result(response["result"])
    profile.require(result["operation"] == request["operation"]
        and result["requestDigest"] == profile.request_digest(request["operation"], arguments))
    originals = response["deliveryOriginals"]
    profile.require(type(originals) is dict and set(originals) == ORIGINAL_FIELDS and all(type(value) is str for value in originals.values()))
    signed_plan = profile.document(originals["signedMeasuredPlanOriginal"].encode("ascii"), profile.MAX_RESPONSE)
    profile.require(set(signed_plan) == {"schema", "payload", "signatureBase64Url"}
        and signed_plan["schema"] == planner.SIGNED_MEASURED_PLAN_SCHEMA)
    planner_role = payload["roles"]["planner"]
    _key(planner_role["signingPublicKeyBase64Url"]).verify(profile.decoded(signed_plan["signatureBase64Url"], 64, length=64),
        planner.measured_plan_signature_message(signed_plan["payload"]))
    plan = signed_plan["payload"]
    profile.require(type(plan) is dict and set(plan) == PLAN_FIELDS and plan["schema"] == planner.PLANNER_RESPONSE_SCHEMA
        and plan["webauthnEvidence"] is None
        and plan["plannerIdentity"] == {"sessionIdentityDigest": planner_role["plannerSessionIdentityDigest"],
            "measurementDigest": planner_role["measurementDigest"], "attestationReceiptDigest": planner_role["attestationReceiptDigest"]})
    measured, typed = plan["measuredPlan"], plan["typedRequest"]
    spec = contract.operation_spec(request["operation"])
    profile.require(type(measured) is dict and set(measured) == MEASURED_FIELDS and measured["schema"] == planner.MEASURED_PLAN_SCHEMA
        and measured["authoritySchemaVersion"] == contract.SCHEMA_VERSION
        and type(measured["workUnits"]) is int and 1 <= measured["workUnits"] <= spec["maximumWorkUnits"]
        and type(typed) is dict and set(typed) == {"schema", "operation", "operationId", "requestDigest", "handler", "operationManifestDigest", "arguments"}
        and typed["schema"] == "catchplate.policyAuthorityV9Request/v1" and typed["handler"] == request["input"]["handler"]
        and typed["operationManifestDigest"] == contract.OPERATION_MANIFEST_DIGEST)
    # Recheck historic proof roots without invoking the live planner validator,
    # whose clock test must never be bypassed or renewed for old originals.
    transition = roots.verify_primary_root_transition(operation=request["operation"], value=plan["rootTransition"],
        selected_rows=plan["selectedBusinessRows"], before_proofs=plan["queryMultiproofs"], mutations=plan["mutationPlan"])
    expected_result_digest = commitment.framed_digest("catchplate.policyAuthorityControlledWriterResult/v2", profile.canonical(result))
    profile.require(plan["expectedResult"] == result and response["resultDigest"] == plan["expectedResultDigest"] == expected_result_digest
        and measured["operation"] == typed["operation"] == request["operation"]
        and measured["requestDigest"] == typed["requestDigest"] == result["requestDigest"] == planner.typed_request_digest(typed)
        and measured["operationId"] == typed["operationId"] == commitment.operation_id(request["operation"], result["requestDigest"])
        and profile.arguments(request["operation"], typed["arguments"], typed=True) == arguments
        and measured["sourceRevision"] == contract.SOURCE_REVISION and measured["operationManifestDigest"] == contract.OPERATION_MANIFEST_DIGEST
        and measured["operationContractDigest"] == contract.OPERATION_MANIFEST_DIGEST
        and measured["handlerContractDigest"] == contract.handler_contract_digest(request["operation"])
        and measured["queryManifestDigest"] == primary.source_query_manifest_digest()
        and measured["rootTransitionDigest"] == roots.primary_root_transition_digest(transition)
        and measured["fence"] == response["fence"] and measured["deadlineMonotonicNs"] == response["deadlineMonotonicNs"]
        and measured["selectedBusinessRowsDigest"] == commitment.framed_digest("catchplate.policyAuthoritySelectedBusinessRows/v1", profile.canonical(plan["selectedBusinessRows"]))
        and measured["mutationPlanDigest"] == commitment.framed_digest("catchplate.policyAuthorityMutationPlan/v3", profile.canonical(plan["mutationPlan"]))
        and plan["queryMultiproofsDigest"] == commitment.framed_digest("catchplate.policyAuthorityRadixMultiproofSet/v3", profile.canonical(plan["queryMultiproofs"])))
    projection = plan["authorizationProjection"]
    profile.require(type(projection) is dict
        and projection["sourceRows"] == roots.derive_authorization_sources(operation=request["operation"], selected_rows=plan["selectedBusinessRows"])
        and projection["sourceHighWaterDigest"] == commitment.framed_digest("catchplate.policyAuthorityAuthorizationRootSet/v1",
            profile.canonical(transition["authorizationBeforeRoots"]))
        and projection["authorizationReads"] == list(spec["authorizationReads"])
        and measured["authorizationProjectionDigest"] == commitment.framed_digest("catchplate.policyAuthorityAuthorizationProjection/v1", profile.canonical(projection))
        and measured["plannerTransactionId"] == commitment.framed_digest("catchplate.policyAuthorityPlannerTransaction/v1",
            measured["operationId"].encode("ascii"), measured["requestDigest"].encode("ascii"), measured["capabilityId"].encode("ascii"))
        and measured["authoritySnapshotDigest"] == commitment.framed_digest("catchplate.policyAuthoritySnapshot/v3",
            *[measured[name].encode("ascii") for name in ("operation", "operationId", "requestDigest", "queryManifestDigest",
                "authorityRootSetBeforeDigest", "authorizationProjectionDigest", "selectedBusinessRowsDigest", "mutationPlanDigest", "rootTransitionDigest")])
        and plan["plannerTraceDigest"] == commitment.framed_digest(planner.PLANNER_TRACE_SCHEMA, profile.canonical(plan["plannerTrace"])))
    executed = profile.document(originals["executorCompletionOriginal"].encode("ascii"), profile.MAX_RESPONSE)
    profile.require(set(executed) == {"receipt", "receiptDigest", "result", "resultDigest"}
        and executed["result"] == result and executed["resultDigest"] == expected_result_digest)
    receipt = executed["receipt"]
    profile.require(type(receipt) is dict and set(receipt) == COMMIT_FIELDS and receipt["schema"] == "catchplate.policyAuthorityWriterCommitReceipt/v2"
        and executed["receiptDigest"] == response["commitReceiptDigest"] == commitment.framed_digest(receipt["schema"], profile.canonical(receipt)))
    for field in ("operation", "requestDigest", "capabilityId", "plannerTransactionId", "authorizationProjectionDigest",
            "authoritySnapshotDigest", "authorityRootSetBeforeDigest", "operationManifestDigest", "queryManifestDigest", "deadlineMonotonicNs", "fence", "sourceRevision"):
        profile.require(receipt[field] == measured[field])
    profile.require(receipt["resultDigest"] == expected_result_digest and receipt["handlerName"] == request["input"]["handler"]
        and receipt["authorityRootSetBeforeDigest"] == commitment.framed_digest("catchplate.policyAuthorityRootSet/v1", profile.canonical(transition["businessBeforeRoots"]))
        and receipt["authorityRootSetAfterDigest"] == commitment.framed_digest("catchplate.policyAuthorityRootSet/v1", profile.canonical(transition["businessAfterRoots"]))
        and arguments["native_evidence"]["statement"]["issuedAtEpochNs"] <= receipt["committedAtEpochNs"]
            <= response["issuedAtEpochNs"] < arguments["native_evidence"]["statement"]["expiresAtEpochNs"]
        and receipt["committedAtEpochNs"] < measured["deadlineEpochNs"])
    witness_request_raw = originals["witnessRequestOriginal"].encode("ascii")
    witness_request = profile.document(witness_request_raw, 8192)
    witness = profile.document(originals["witnessResponseOriginal"].encode("ascii"), 8192)
    profile.require(set(witness_request) == WITNESS_REQUEST_FIELDS and set(witness) == WITNESS_RESPONSE_FIELDS)
    _verify_signed(witness_request, _key(verifier["signingPublicKeyBase64Url"]), service.WITNESS_REQUEST_SCHEMA_V2)
    _verify_signed(witness, _key(payload["replayWitness"]["signingPublicKeyBase64Url"]), service.WITNESS_RECEIPT_SCHEMA_V2)
    profile.require(witness["phase"] == witness_request["phase"] == "commit"
        and witness["witnessIdentityDigest"] == payload["replayWitness"]["identityDigest"]
        and response["witnessCommitDigest"] == commitment.framed_digest(service.WITNESS_RECEIPT_SCHEMA_V2, profile.canonical(witness))
        and witness["canonicalRequestDigest"] == commitment.framed_digest(service.WITNESS_REQUEST_SCHEMA_V2, witness_request_raw)
        and witness_request["configurationDigest"] == config_digest
        and witness_request["operationManifestDigest"] == contract.OPERATION_MANIFEST_DIGEST
        and witness["predecessorReceiptDigest"] == witness_request["predecessorReceiptDigest"] == receipt["witnessReservationDigest"])
    for field in ("operation", "requestDigest", "capabilityId", "resultDigest", "deadlineMonotonicNs"):
        profile.require(witness[field] == witness_request[field] == receipt[field])
    for field in ("envelopeId", "parentEnvelopeId", "generationSequence", "generationDigest"):
        profile.require(witness[field] == witness_request[field])
    head_material = {name: value for name, value in witness.items() if name != "signature"}
    head_material["headDigest"] = None
    profile.require(witness["fence"] == receipt["fence"] and type(witness["sequence"]) is int and witness["sequence"] > receipt["witnessSequence"]
        and witness["headDigest"] == commitment.framed_digest("catchplate.policyAuthorityReplayWitnessHead/v2", profile.canonical(head_material)))
    return _observe(plan, result, request["operation"]), arguments["native_evidence"]["statement"]


def verify_claim_originals(values, *, slot, head, http_original, admission, now):
    request, signed = values["request"], values["native_evidence"]["statement"]
    expected = {"slotOriginal": profile.row_original(profile.SLOTS, slot).decode("ascii"),
        "headOriginal": profile.row_original(profile.HEADS, head).decode("ascii"), "httpOriginal": http_original, "intakeOriginal": None}
    for field, allowed in (("prepareCompletionOriginal", {profile.OP_PREPARE, profile.OP_RECOVER}),
            ("readCompletionOriginal", {profile.OP_RECOVER})):
        observation, original_sender = verify(request[field], admission=admission, allowed_operations=allowed, now=now)
        profile.require(observation == expected)
        for name in ("deploymentId", "canaryId", "instanceId", "holderId", "bootId", "keyId", "purposeAssignmentSha256", "slotId", "httpSha256"):
            profile.require(original_sender[name] == signed[name], "completion cannot transfer original native ownership")
        profile.require(original_sender["originalExpiresAtEpochNs"] == signed["originalExpiresAtEpochNs"] == slot["expires_at_epoch_ns"]
            and slot["issued_at_epoch_ns"] <= now < slot["expires_at_epoch_ns"])
