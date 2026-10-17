"""Three fixed C9 decisions from admitted policy and actual retained requests.

Runtime markers and nonempty credential metadata are independently selected;
their exact bytes must match the authenticated recipe's closure-set role leaves.
Only original windows and actual endpoint resource observations enter the C9
payloads. Nothing signs, publishes, opens secrets, creates genesis, renews a
deadline or treats public-pin readback as native admission. Failed composition
consumes that actual request's attempt. Full-run coverage is the spine's gate.
"""
from __future__ import annotations

import copy

from catchplate import custody_generation_grants as generation
from catchplate import native_pilot_assignment as assignments
from catchplate import native_pilot_closure_set as closure_set
from catchplate import native_pilot_delivery_authority as c9
from catchplate import native_pilot_launch_publication as launch
from catchplate import native_pilot_precreation_install as precreation
from catchplate import native_pilot_publication as publication
from catchplate import native_pilot_scope_authority as scope
from catchplate import native_shadow_driver_bootstrap as driver
from catchplate import native_shadow_guest_delivery as delivery
from catchplate import native_shadow_proof_cohort_assignment as cohort
from catchplate import native_shadow_retrieval_artifacts as retrieval

p = delivery.p
ROLES = ("retrieval", "persistence", "trustedTime")
FIELDS = ("runtimeOriginal", "runtimeConfig", "credentials")
_RESOURCE_FIELDS = ("cohortObservationOriginal", "ordinaryParked", "ordinaryActivations",
    "ordinaryDirectories", "nativeActivations", "bridgeJournal")
_RECIPE_FIELDS = ("assignmentOriginal", "trustOriginal", "trustSha256", "closureSetOriginal")
_MEASURED_FIELDS = ("apiVersion", "recipeSha256", "configurationBindingOriginal",
    "configurationBindingSha256", "proofScopeOriginal", "production")
_ATTEMPTED = set()


def validate_policy(fragment, *, native_cold_originals) -> dict:
    """Pure closed three-role grammar; actual recipe membership is checked later."""
    p.fields(fragment, ROLES)
    p.fields(native_cold_originals, cohort.ENDPOINT_ROLES)
    for role in ROLES:
        selected = p.fields(fragment[role], FIELDS)
        cold_raw, _ = scope._original(native_cold_originals[role], 65536)
        cold = delivery.configuration(cold_raw, p.sha(cold_raw))
        runtime_raw, _ = scope._original(selected["runtimeOriginal"], 65536)
        purpose = "native-runtime-" + role
        launch.shape(purpose, runtime_raw)
        delivery._pin(selected["runtimeConfig"])
        c9._same(selected["runtimeConfig"],
            {"path": publication.DESTINATIONS[purpose], "sha256": p.sha(runtime_raw)})
        c9._credentials(selected["credentials"], cold["authority"])
    return copy.deepcopy(fragment)


def _owners(policy, process, request):
    from catchplate.native_pilot_supervisor_policy import SupervisorPolicy
    from catchplate.native_pilot_supervisor_process import AuthorityCoordinatorProcess, JobRequest

    p.require(type(policy) is SupervisorPolicy and type(process) is AuthorityCoordinatorProcess
        and type(request) is JobRequest)
    policy.check(process)
    process.check_request(request)


def _phase(process, name):
    value = p.fields(process.conductor_request(name),
        ("apiVersion", "sequence", "phase", "payload", "deadlineBoottimeNs"))
    p.require(value["apiVersion"] == "catchplate.nativePilotOperatorRequest/v1" and value["phase"] == name)
    p.ns(value["deadlineBoottimeNs"])
    return value


def _runtime_bindings(policy, process, request, fragment, endpoint_input):
    # These checked getters expose the actual prebound recipe's originals and
    # once-derived result, including its signature/currentness checks. Candidate
    # assignment fields or hashes alone cannot select this authority.
    originals = p.fields(policy.endpoint_recipe_originals(process=process, request=request), _RECIPE_FIELDS)
    measured = p.fields(policy.measured_configuration(process=process, request=request), _MEASURED_FIELDS)
    p.require(measured["apiVersion"] == "catchplate.nativePilotMeasuredConfiguration/v2")
    assignment_raw, envelope = scope._original(originals["assignmentOriginal"], assignments.MAX_BYTES)
    assignments.shape(envelope)
    p.require(assignments.version(envelope) == 2)
    trust_raw, _ = scope._original(originals["trustOriginal"], 1024 * 1024)
    p.require(p.sha(trust_raw) == p.digest(originals["trustSha256"]))
    set_text = originals["closureSetOriginal"]
    p.require(type(set_text) is str and set_text.isascii() and 0 < len(set_text) <= closure_set.MAX_BYTES)
    set_raw = set_text.encode("ascii")
    # The common-root helper also requires the signed legacy bridge anchors to
    # equal the actual bridge leaf. Endpoint runtime hashes are separate leaves.
    assignments.closure_binding(envelope, set_raw, "bridge")
    selected = closure_set.validate(set_raw)
    for role in ROLES:
        member = selected["members"][closure_set.ROLES.index(role)]
        p.require(member["role"] == role and member["manifest"]["runtimeConfigurationSha256"]
            == p.sha(fragment[role]["runtimeOriginal"].encode("ascii")))

    scope_raw, _ = scope._original(measured["proofScopeOriginal"], 16384)
    proof = retrieval.scope_original(scope_raw)
    retrieval.require_assignment_scope(proof, p.canonical(envelope["payload"]))
    manifest_raw = retrieval.fresh_ledger_manifest_original(scope_raw)
    for field, purpose, raw in (("proofScope", "endpoint-proof-scope", scope_raw),
            ("assignment", "endpoint-assignment", assignment_raw),
            ("retrievalManifest", "endpoint-retrieval-manifest", manifest_raw)):
        c9._same(endpoint_input[field], {"path": publication.DESTINATIONS[purpose], "sha256": p.sha(raw)})
    c9._same(endpoint_input["production"], measured["production"])
    return originals


def _context(policy, process, request):
    from catchplate.native_pilot_supervisor_endpoint_inputs import require_endpoint_inputs

    # This owner verifies its actual installed complete input and the reported
    # public-pin-open result, retaining files and original window. That result
    # alone is not endpoint allocation, a C9 signature or successful admission.
    endpoint_input = require_endpoint_inputs(policy, process=process, request=request)
    p.fields(endpoint_input, ("coldOriginals", "peer", "proofScope", "retrievalManifest",
        "objectDirectory", "assignment", "production"))
    p.fields(endpoint_input["coldOriginals"], ROLES)
    previous = _phase(process, "endpoint-inputs")
    p.fields(previous["payload"], _RESOURCE_FIELDS)
    current = _phase(process, "endpoint-deliveries")
    observed_fields = p.fields(current["payload"], _RESOURCE_FIELDS + ("driverGenerationRecipe",))
    p.require(type(observed_fields["driverGenerationRecipe"]) is dict)
    # Retain this owner-produced recipe as data for later generation decisions;
    # its mere presence never authorizes a generation or proves installation.
    for field in _RESOURCE_FIELDS:
        if field != "nativeActivations":
            c9._same(observed_fields[field], previous["payload"][field])
    earlier_activations = p.fields(previous["payload"]["nativeActivations"],
        tuple(role for role in cohort.ENDPOINT_ROLES if role not in ROLES))
    activations = p.fields(observed_fields["nativeActivations"], cohort.ENDPOINT_ROLES)
    for role, records in earlier_activations.items():
        c9._same(activations[role], records)

    installed_raw = process.approved_input_original("endpoint-precreation", "install-precreation")
    p.require(type(installed_raw) is bytes and p.sha(installed_raw)
        == process.approved_input_sha256("endpoint-precreation", "install-precreation"))
    installed = p.fields(p.document(installed_raw, precreation.MAX_INPUT), precreation.FIELDS)
    p.require(installed["apiVersion"] == "catchplate.nativePilotPrecreationBundle/v1")
    independent = policy.precreation()
    c9._same(installed["nativeColdOriginals"], independent["nativeColdOriginals"])
    fragment = validate_policy(policy.endpoint_deliveries(),
        native_cold_originals=independent["nativeColdOriginals"])
    recipe_originals = _runtime_bindings(policy, process, request, fragment, endpoint_input)
    configuration_raw, _ = scope._original(installed["cohortConfigurationOriginal"], cohort.MAX_BYTES)
    window_raw, signed_window = scope._original(installed["cohortPrecreationOriginal"], cohort.MAX_BYTES)
    observed_raw, observed = scope._original(observed_fields["cohortObservationOriginal"], cohort.MAX_BYTES)

    inputs, cold_values, window = {}, {}, None
    for role in ROLES:
        cold_raw, _ = scope._original(independent["nativeColdOriginals"][role], 65536)
        cold = delivery.configuration(cold_raw, p.sha(cold_raw))
        c9._same(endpoint_input["coldOriginals"][role],
            {"path": publication.DESTINATIONS["native-cold-" + role], "sha256": p.sha(cold_raw)})
        window = c9._endpoint_owner(role, cold, cold_raw, configuration_raw, window_raw, signed_window, observed)
        c9._activation(activations[role], c9.ENDPOINTS[role])
        selected = fragment[role]
        payload = {"configurationSha256": p.sha(cold_raw), "authorityKeyId": cold["authority"]["keyId"],
            **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
            **{name: window[name] for name in c9.WINDOW_FIELDS},
            "runtimeConfig": selected["runtimeConfig"], "credentials": selected["credentials"],
            "activation": activations[role]}
        p.fields(payload, delivery.FIELDS)
        payload_raw = p.canonical(payload)
        activation_raw = p.canonical(activations[role])
        p.require(len(payload_raw) <= delivery.MAX_DELIVERY and len(activation_raw) <= 32768)
        value = {"apiVersion": "catchplate.nativePilotDeliverySigningInput/v1", "role": role,
            "configurationOriginal": cold_raw.decode("ascii"),
            "ownerConfigurationOriginal": configuration_raw.decode("ascii"),
            "windowOriginal": window_raw.decode("ascii"), "observationOriginal": observed_raw.decode("ascii"),
            "runtimeOriginal": selected["runtimeOriginal"], "payloadOriginal": payload_raw.decode("ascii"),
            "activationOriginal": activation_raw.decode("ascii")}
        p.fields(value, c9.INPUT_FIELDS)
        inputs[role] = p.canonical(value)
        p.require(len(inputs[role]) <= c9.MAX_INPUT)
        cold_values[role] = cold
    p.require(window is not None and previous["deadlineBoottimeNs"] == current["deadlineBoottimeNs"]
        == window["startupDeadlineBoottimeNs"] and request.deadline_boottime_ns == p.ns(window["startupDeadlineBoottimeNs"]))
    pending = _phase(process, request.phase)
    p.require(p.sha(p.canonical(pending)) == request.value["conductorRequestSha256"]
        and pending["deadlineBoottimeNs"] == window["startupDeadlineBoottimeNs"])
    return inputs, cold_values, window, recipe_originals


def _result(process, role, input_raw, cold):
    job = "native-delivery-" + role
    p.require(process.approved_input_original("endpoint-deliveries", job) == input_raw
        and process.approved_input_sha256("endpoint-deliveries", job) == p.sha(input_raw))
    result = p.fields(process.prior_result("endpoint-deliveries", job), ("original", "sha256", "pin"))
    raw, signed = scope._original(result["original"], delivery.MAX_DELIVERY)
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    c9._same(result["pin"], {"path": publication.DESTINATIONS[job], "sha256": p.sha(raw)})
    p.fields(signed, ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "catchplate.policyCustodyGuestDelivery/v1")
    approved = p.document(input_raw, c9.MAX_INPUT)
    p.require(p.canonical(signed["payload"]).decode("ascii") == approved["payloadOriginal"])
    driver._key(cold["authority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
        delivery.DOMAIN + p.canonical(signed["payload"]))
    return raw, delivery._delivery_guest(signed["payload"], raw)


def _recheck(policy, process, request, window, before, recipe_originals):
    c9._same(policy.endpoint_recipe_originals(process=process, request=request), recipe_originals)
    c9._live(window, before)
    _owners(policy, process, request)


def compose(policy, *, process, request) -> bytes:
    """One role's complete input, never an approval, signature or secret read."""
    _owners(policy, process, request)
    p.require(request.phase == "endpoint-deliveries" and 1 <= request.job_index <= len(ROLES))
    role = ROLES[request.job_index - 1]
    p.require(request.job == "native-delivery-" + role)
    # Retain the actual process identity, not a reusable numeric object ID.
    attempt = (process, request.sequence)
    p.require(attempt not in _ATTEMPTED and len(_ATTEMPTED) < len(ROLES))
    _ATTEMPTED.add(attempt)
    inputs, cold, window, recipe_originals = _context(policy, process, request)
    before = c9._live(window)
    for earlier in ROLES[:request.job_index - 1]:
        _result(process, earlier, inputs[earlier], cold[earlier])
    _recheck(policy, process, request, window, before, recipe_originals)
    return inputs[role]


def require_deliveries(policy, *, process, request) -> dict:
    """Verify all three actual results for initial ceremony / first C9 input.

    Returns exactly deliveryOriginals and endpointDeliveryResult as checked data
    from the same process's retained originals/request. It grants no service or
    native admission and does not calculate or synthesize a genesis. The actual
    next request must have arrived; no future signature is assumed successful.
    """
    _owners(policy, process, request)
    from catchplate.native_pilot_supervisor_endpoint_inputs import _service_boundary
    p.require(_service_boundary(request))
    inputs, cold, window, recipe_originals = _context(policy, process, request)
    before = c9._live(window)
    originals, guests = {}, {}
    for role in ROLES:
        originals[role], guests[role] = _result(process, role, inputs[role], cold[role])
    current = p.fields(_phase(process, "service-originals")["payload"],
        _RESOURCE_FIELDS + ("driverGenerationRecipe", "endpointDeliveries", "endpointDeliveryResult",
            "ordinaryPreparationOriginal", "ordinaryInitialResourcesOriginal"))
    _ordinary_preparation(process, current, now=before)
    previous = _phase(process, "endpoint-deliveries")["payload"]
    for field in _RESOURCE_FIELDS + ("driverGenerationRecipe",):
        c9._same(current[field], previous[field])
    pins = p.fields(current["endpointDeliveries"], ROLES)
    for role in ROLES:
        c9._same(pins[role], {"path": publication.DESTINATIONS["native-delivery-" + role],
            "sha256": p.sha(originals[role])})
    observed = p.fields(current["endpointDeliveryResult"], ("guests", "spoolJournal"))
    p.fields(observed["guests"], ROLES)
    c9._same(observed["guests"], guests)
    journal = p.fields(observed["spoolJournal"], ("genesisSha256", "sequence", "headSha256"))
    p.integer(journal["sequence"], minimum=0, maximum=0)
    p.require(p.digest(journal["genesisSha256"]) != p.sha(b"")
        and p.digest(journal["headSha256"]) == journal["genesisSha256"])
    _recheck(policy, process, request, window, before, recipe_originals)
    return {"deliveryOriginals": originals, "endpointDeliveryResult": copy.deepcopy(observed)}


def _ordinary_preparation(process, current, *, now):
    """Join the explicit parked-pre-exec observation, never a live identity."""
    from catchplate import native_pilot_ordinary_key_profile as ordinary

    raw, _ = scope._original(current["ordinaryPreparationOriginal"], ordinary.MAX_PREPARATION)
    measured = ordinary.preparation(raw)
    from catchplate import native_pilot_ordinary_initial_profile as initial
    resources_raw, _ = scope._original(current["ordinaryInitialResourcesOriginal"], initial.MAX_STATE)
    resources = initial.resources(resources_raw)
    p.require(resources["preparationSha256"] == p.sha(raw)
        and p.ns(measured["issuedAtBoottimeNs"]) <= p.ns(resources["issuedAtBoottimeNs"]) <= now)
    p.fields(current["ordinaryDirectories"], generation.ROLES)
    installed_raw = process.approved_input_original("endpoint-precreation", "install-precreation")
    p.require(p.sha(installed_raw) == process.approved_input_sha256("endpoint-precreation", "install-precreation"))
    installed = p.document(installed_raw, precreation.MAX_INPUT)
    launch_raw, launch = scope._original(installed["ordinaryLaunchOriginal"], 65536)
    p.require(measured["configurationSha256"] == p.sha(launch_raw))
    for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
                 "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId"):
        c9._same(measured[name], launch[name])
    p.require(p.ns(measured["issuedAtBoottimeNs"]) <= now
        < p.ns(measured["startupDeadlineBoottimeNs"]))
    parked = p.fields(current["ordinaryParked"], generation.ROLES)
    for role in generation.ROLES:
        row = measured["services"][role]
        cold_raw, _ = scope._original(installed["ordinaryColdOriginals"][role], 65536)
        cold = generation.configuration(cold_raw, p.sha(cold_raw), role)
        p.require(row["configurationSha256"] == p.sha(cold_raw)
            == launch["services"][role]["deliveryConfiguration"]["sha256"]
            and row["plannedUid"] == cold["uid"] and row["plannedGid"] == cold["gid"])
        actual = p.fields(parked[role], ("processId", "startTimeTicks", "pidfdInode", "executable"))
        p.require(row["processId"] == actual["processId"] and row["startTimeTicks"] == actual["startTimeTicks"]
            and row["pidfdStat"]["inode"] == actual["pidfdInode"])
        c9._same({name: row["targetExecutable"][name] for name in ("device", "inode", "length", "sha256")},
            actual["executable"])
        p.require(row["targetExecutable"]["sha256"] == launch["services"][role]["executableSha256"])
        directories = resources["services"][role]["directories"]
        c9._same({name: item["identity"] for name, item in directories.items()},
            current["ordinaryDirectories"][role])
        for item in directories.values():
            p.require(item["identity"]["uid"] == cold["uid"] and item["identity"]["gid"] == cold["gid"])
