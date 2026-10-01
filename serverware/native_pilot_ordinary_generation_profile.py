"""Pure first-install generation inputs from retained commissioning originals.

Only the two original UNIX installation bounds are independently selected here.
All identity/receipt/assignment fields derive from authenticated originals and
the actual source-owned driver recipe. These public helpers cannot establish
kernel provenance, approve their own inputs, write grants or renew any clock.
"""
from __future__ import annotations

import copy

from serverware import custody_generation_grants as g
from serverware import native_pilot_assignment as assignments
from serverware import native_pilot_driver_authority as driver_authority
from serverware import native_pilot_measured_configuration as measured_profile
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_runtime_profile as runtime_profile
from serverware import native_pilot_publication as publication
from serverware import native_pilot_scope_authority as driver_scope
from serverware import native_pilot_service_authority as service
from serverware import native_pilot_window_authority as window_authority
from serverware import native_shadow_constructed_driver as driver_admission
from serverware import native_shadow_retrieval_artifacts as retrieval

p = g.p
API = "serverware.nativePilotOrdinaryGenerationPolicy/v1"
MAX_POLICY = 4096
POLICY_FIELDS = ("apiVersion", "installationIssuedAtUnixNanos", "installationExpiresAtUnixNanos")
INPUT_FIELDS = ("apiVersion", "operation", "serviceRole", "launchOriginal", "payloadOriginal", "services")
SERVICE_FIELDS = ("configurationOriginal", "configurationSha256", "deliveryOriginal", "runtimeOriginal", "historyOriginal")
MEASURED_FIELDS = ("apiVersion", "recipeSha256", "configurationBindingOriginal", "configurationBindingSha256",
    "proofScopeOriginal", "production")
ORIGINAL_FIELDS = ("assignmentOriginal", "trustOriginal", "trustSha256", "closureSetOriginal")
RECIPE_FIELDS = ("dispatchManifestSha256", "driverGenerationReceiptSha256", "kernelDriverIdentitySha256",
    "retainedDescriptorSetSha256", "operationCoverageRootSha256", "stableReaperIdentity")


def _same(first, second):
    p.require(g.canonical(first) == g.canonical(second))


def validate_policy(fragment):
    p.fields(fragment, POLICY_FIELDS)
    p.require(fragment["apiVersion"] == API)
    issued = p.integer(fragment["installationIssuedAtUnixNanos"])
    expires = p.integer(fragment["installationExpiresAtUnixNanos"])
    p.require(issued < expires and len(p.canonical(fragment)) <= MAX_POLICY)
    return copy.deepcopy(fragment)


def _recipe(bootstrap_raw, configuration_raw, observation_raw, binding, production, assignment, now):
    """Recompute the existing generation_manifest recipe without an owner DTO."""
    config = window_authority.validate_configuration(configuration_raw)
    envelope = p.fields(p.document(bootstrap_raw, 8192), ("payload", "signature"))
    early = p.fields(envelope["payload"], driver_scope.BOOTSTRAP_FIELDS)
    selected = config["lifecycle"]["constructedAdmissionAuthority"]
    public = driver_admission.authority(selected)
    p.require(early["apiVersion"] == "serverware.nativeShadowBootstrapDriverAdmission/v1"
        and early["purpose"] == "native-driver-bootstrap-admission"
        and early["configurationSha256"] == p.sha(configuration_raw)
        and early["signingKeyId"] == selected["keyId"] and early["signingKeySpkiSha256"] == selected["keySpkiSha256"]
        and early["bootstrapObservationOriginal"] == observation_raw.decode("ascii"))
    public.verify(p.decoded(envelope["signature"], size=64), p.preimage(driver_admission.BOOTSTRAP_DOMAIN, early))
    p.freshness(early["issuedAtUnixNanos"], early["expiresAtUnixNanos"], now, 30_000_000_000)
    observed = p.fields(p.document(observation_raw, 65536), driver_authority.OBSERVATION_FIELDS)
    driver = p.fields(observed["driver"], driver_scope.DRIVER_FIELDS)
    parent = early["parent"]
    driver_authority._process(parent)
    p.require(observed["apiVersion"] == "serverware.nativeShadowDriverObservation/v1"
        and observed["configurationSha256"] == early["configurationSha256"]
        and observed["windowSha256"] == early["windowSha256"]
        and (observed["uid"], observed["gid"]) == (config["uid"], config["gid"]))
    instance = p.sha(observed["invocationId"].encode("ascii"))
    p.require(driver["identitySha256"] == p.framed(b"serverware.policyShadowCustodyKernelDriverIdentity/v1",
        (p.canonical([driver[name] for name in driver_scope.DRIVER_FIELDS[:-1]]),))
        and driver["driverExecutableSha256"] == config["image"]["executableSha256"]
        and driver["retainedDescriptorManifestSha256"] == p.sha(p.canonical(observed["descriptors"]))
        and driver["identitySha256"] == binding["kernelRetainedDriverIdentitySha256"]
        and instance == binding["supervisorInstanceSha256"]
        and driver["supervisorBootIdSha256"] == binding["supervisorBootIdSha256"])
    reaper = {"reaperInstanceSha256": p.framed(b"serverware.nativeShadowStableParentInstance/v1",
        (p.canonical([parent, instance]),)), "reaperExecutableSha256": early["parentExecutableSha256"],
        "supervisorInstanceSha256": instance, "supervisorBootIdSha256": driver["supervisorBootIdSha256"],
        "kernelDriverIdentitySha256": driver["identitySha256"], "subreaperProcessStartTimeTicks": parent["startTimeTicks"],
        "pidfdNamespaceSha256": early["pidNamespaceSha256"], "retainedDescriptorSetSha256": driver["retainedDescriptorManifestSha256"],
        "ownershipEpoch": parent["startTimeTicks"], "independentRestartForbidden": True}
    reaper["identitySha256"] = p.framed(b"serverware.policyShadowCustodyStableReaper/v1", (p.canonical(list(reaper.values())),))
    coverage = p.framed(b"serverware.policyShadowCustodyOperationCoverage/v1", (p.canonical(measured_profile.OPERATIONS),))
    keys = [row for row in assignment["authorityKeyIndependence"]["bindings"]
        if row["role"] == "custody-result-envelope" and row["scopeSha256"] == assignment["assignmentId"]]
    p.require(len(keys) == 1 and binding["operationCoverageRootSha256"] == coverage)
    key = keys[0]
    manifest = p.framed(b"serverware.policyShadowCustodyDispatchManifest/v1", (p.canonical([
        "serverware.policyShadowCustodyDispatch/v2", coverage, production["dispatcherProtocolSetSha256"],
        driver["identitySha256"], reaper["identitySha256"], driver["driverExecutableSha256"], production["signerBackendSha256"],
        production["persistenceBackendSha256"], production["retrievalBackendSha256"], 8 * 1024 * 1024, 8 * 1024 * 1024,
        production["maximumAsyncDurabilityNanos"], key["keyId"], key["keySpkiSha256"]]),))
    return {"dispatchManifestSha256": manifest, "driverGenerationReceiptSha256": p.sha(bootstrap_raw),
        "kernelDriverIdentitySha256": driver["identitySha256"], "retainedDescriptorSetSha256": driver["retainedDescriptorManifestSha256"],
        "operationCoverageRootSha256": coverage, "stableReaperIdentity": reaper}, key


def derive_scope(fragment, *, measured, recipe_originals, driver_generation_recipe, bootstrap_original,
                 bootstrap_configuration_original, driver_observation_original, now_unix_ns):
    """Authenticate exact earlier originals; no conversion between clock domains."""
    fragment = validate_policy(fragment)
    p.fields(measured, MEASURED_FIELDS); p.fields(recipe_originals, ORIGINAL_FIELDS)
    p.fields(driver_generation_recipe, RECIPE_FIELDS)
    p.require(measured["apiVersion"] == "serverware.nativePilotMeasuredConfiguration/v2")
    p.digest(measured["recipeSha256"]); p.integer(now_unix_ns)
    value = {"apiVersion": "serverware.nativePilotMeasuredConfigurationRecipe/v2", **recipe_originals}
    envelope, _, key_root = measured_profile._assignment(value, now_unix_ns)
    assignment = envelope["payload"]
    trust_raw = service._original(recipe_originals["trustOriginal"], 1024 * 1024)
    trust = p.document(trust_raw, 1024 * 1024)
    checkpoint = trust["checkpoint"]
    closure_raw = recipe_originals["closureSetOriginal"].encode("ascii")
    bridge = assignments.closure_binding(envelope, closure_raw, "bridge")
    binding_raw = service._original(measured["configurationBindingOriginal"], 65536)
    binding = p.document(binding_raw, 65536)
    p.require(p.framed(b"serverware.policyShadowProductionCustodyConfiguration/v2", (binding_raw,))
        == measured["configurationBindingSha256"])
    proof_raw = service._original(measured["proofScopeOriginal"], 16384)
    proof = retrieval.scope_original(proof_raw)
    p.require(proof.get("api_version") == retrieval.SCOPE_SET_API)
    retrieval.require_assignment_scope(proof, p.canonical(assignment))
    p.require(proof["production_configuration_binding_sha256"] == measured["configurationBindingSha256"]
        and binding["assignmentId"] == assignment["assignmentId"] and binding["assignmentPayloadSha256"] == envelope["payloadSha256"]
        and binding["assignmentRevision"] == assignment["assignmentRevision"]
        and binding["assertedCustodyKeySetRootSha256"] == key_root
        and binding["executionClosureManifestSha256"] == bridge["manifestSha256"]
        and binding["structurallyVerifiedSeccompPolicySha256"] == bridge["structurallyVerifiedPolicySha256"]
        and binding["nativeClosureSet"] == assignment["nativeClosureSet"])
    production = p.fields(measured["production"], driver_scope.PRODUCTION_FIELDS)
    measured_profile._production({name: production[name] for name in measured_profile.PRODUCTION_FIELDS})
    p.require(production["expectedConfigurationBindingSha256"] == measured["configurationBindingSha256"])
    for name in measured_profile.PRODUCTION_FIELDS:
        p.require(binding[name] == production[name])
    expected, authority = _recipe(bootstrap_original, bootstrap_configuration_original, driver_observation_original,
        binding, production, assignment, now_unix_ns)
    _same(driver_generation_recipe, expected)
    issued, expires = (fragment[name] for name in POLICY_FIELDS[1:])
    maximum_age = p.integer(assignment["observationWindow"]["maximumEvidenceAgeNanos"])
    p.require(issued <= now_unix_ns < expires and expires - issued <= maximum_age
        and assignment["issuedAtUnixNanos"] <= issued < expires <= assignment["expiresAtUnixNanos"]
        and trust["issuedAtUnixNanos"] <= issued < expires <= trust["expiresAtUnixNanos"]
        and checkpoint["asOfUnixNanos"] <= issued < expires <= checkpoint["asOfUnixNanos"] + 300_000_000_000)
    for key in [trust["assignmentKey"], trust["timeKey"], *(row["key"] for row in trust["roleKeys"])]:
        p.require(key["notBeforeUnixNanos"] <= issued < expires <= key["notAfterUnixNanos"])
    p.integer(checkpoint["revocationGeneration"], maximum=p.MAX_U64)
    result = {"previousConfigurationBindingSha256": None,
        "successorConfigurationBindingSha256": measured["configurationBindingSha256"],
        **{name: expected[name] for name in RECIPE_FIELDS[:-1]}, "assignmentId": assignment["assignmentId"],
        "assignmentPayloadSha256": envelope["payloadSha256"], "assignmentRevision": assignment["assignmentRevision"],
        "fiveServiceProtocolSetSha256": production["dispatcherProtocolSetSha256"],
        "envelopeAuthorityKeyId": authority["keyId"], "envelopeAuthorityKeySpkiSha256": authority["keySpkiSha256"],
        "trustedTimeCheckpointSha256": checkpoint["checkpointId"], "trustedTimeRevocationGeneration": checkpoint["revocationGeneration"],
        "trustedTimeRevocationRootSha256": checkpoint["revocationRootSha256"],
        **{name: fragment[name] for name in POLICY_FIELDS[1:]}}
    p.fields(result, g.SCOPE)
    return result


def _input(role, input_raw, root_pin, *, adopted=False):
    p.require(role in g.ROLES)
    value = p.fields(p.document(input_raw, service.MAX_INPUT_BYTES), INPUT_FIELDS)
    p.require(value["apiVersion"] == (service.ADOPTED_INPUT_API if adopted else "serverware.nativePilotServiceAuthorityInput/v1")
        and value["operation"] == "generation" and value["serviceRole"] == role)
    selected = p.fields(p.fields(value["services"], (role,))[role], SERVICE_FIELDS)
    launch_raw = service._original(value["launchOriginal"], 65536)
    launch = g.document(launch_raw, 65536)
    payload_raw = service._original(value["payloadOriginal"], 65536)
    payload = p.fields(g.document(payload_raw, 65536), g.GRANT)
    issued = p.integer(payload["issuedAtBoottimeNanos"], maximum=p.MAX_U64)
    boot = tuple(launch[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"))
    launch, startup, lifetime = service._launch(launch_raw, boot, issued, adopted=adopted)
    item = service._service(selected, role, launch, boot, startup, lifetime, issued, granted=False, adopted=adopted)
    runtime_profile.validate_runtime(role, item["runtime_raw"], adopted=adopted)
    header = item["header"]
    p.fields(root_pin, ("keyId", "keySpkiSha256"))
    p.require(root_pin == {"keyId": header["authorityHistoryRootKeyId"],
        "keySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]})
    initial.manifest(item["history_raw"], role=role, root_pin=root_pin, adopted=adopted)
    p.require(payload["scope"]["previousConfigurationBindingSha256"] is None)
    g._grant_values(payload_raw=payload_raw, guest=item["guest"], runtime_raw=item["runtime_raw"],
        history_raw=item["history_raw"], delivery_raw=item["delivery_raw"], now=issued, **service._flags(role, adopted=adopted))
    return value, payload, item, issued


def build(role, *, launch_raw, configuration_raw, delivery_raw, runtime_raw, history_raw, scope,
          issued_boottime_ns, expires_boottime_ns, adopted=False):
    p.require(role in g.ROLES)
    p.fields(scope, g.SCOPE); p.require(scope["previousConfigurationBindingSha256"] is None)
    launch = g.document(launch_raw, 65536)
    selected = {"configurationOriginal": configuration_raw.decode("ascii"), "configurationSha256": p.sha(configuration_raw),
        "deliveryOriginal": delivery_raw.decode("ascii"), "runtimeOriginal": runtime_raw.decode("ascii"),
        "historyOriginal": history_raw.decode("ascii")}
    boot = tuple(launch[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"))
    launch, startup, lifetime = service._launch(launch_raw, boot, issued_boottime_ns, adopted=adopted)
    item = service._service(selected, role, launch, boot, startup, lifetime, issued_boottime_ns, granted=False, adopted=adopted)
    header = item["header"]
    payload = {"apiVersion": "serverware.custodyServiceGenerationGrant/v1", "purpose": "cold-service-generation-admission",
        "serviceRole": role, "guest": item["guest"], "runtimeConfigurationSha256": p.sha(runtime_raw),
        "authorityHistoryManifestSha256": header["authorityHistoryManifestSha256"], "scope": copy.deepcopy(scope),
        "issuedAtBoottimeNanos": issued_boottime_ns, "expiresAtBoottimeNanos": expires_boottime_ns}
    value = {"apiVersion": service.ADOPTED_INPUT_API if adopted else "serverware.nativePilotServiceAuthorityInput/v1", "operation": "generation", "serviceRole": role,
        "launchOriginal": launch_raw.decode("ascii"), "payloadOriginal": g.canonical(payload).decode("ascii"), "services": {role: selected}}
    raw = p.canonical(value)
    p.require(len(raw) <= service.MAX_INPUT_BYTES)
    _input(role, raw, {"keyId": header["authorityHistoryRootKeyId"], "keySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]}, adopted=adopted)
    return raw


def checked_result(role, input_raw, result, *, root_pin, adopted=False):
    """Verify the fixed result with independently pinned history-root authority."""
    _, payload, item, issued = _input(role, input_raw, root_pin, adopted=adopted)
    p.fields(result, ("original", "sha256", "pin"))
    raw = service._original(result["original"], 65536)
    signed = p.fields(g.document(raw, 65536), ("payload", "signatureBase64url"))
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    _same(result["pin"], {"path": publication.DESTINATIONS["ordinary-generation-" + role], "sha256": p.sha(raw)})
    _same(signed["payload"], payload)
    g._admit_grant(signed_raw=raw, guest=item["guest"], runtime_raw=item["runtime_raw"], history_raw=item["history_raw"],
        delivery_raw=item["delivery_raw"], now=issued, **service._flags(role, adopted=adopted))
    return raw
