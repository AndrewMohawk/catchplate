"""Fixed cold commissioning producers and literal predecessor associations.

This is not an executor, installer, approval authority or process owner. The
separate retained cold executor supplies actual observations and completed
input/result originals. Every signing dispatch authenticates that complete
public input before invoking its fixed private-key loader. Hot jobs are never
selected here. Static configurations, measured images, transport ciphertext,
trust and private credentials remain independently provisioned prerequisites.
"""
from __future__ import annotations

import os
import time
from typing import NamedTuple

from serverware import custody_generation_grants as g
from serverware import native_pilot_assignment as assignment
from serverware import native_pilot_closure_set as sets
from serverware import native_pilot_genesis_closure_authority as closure
from serverware import native_pilot_genesis_delivery_authority as delivery
from serverware import native_pilot_genesis_encrypted_authority as encrypted
from serverware import native_pilot_genesis_endpoint_release_authority as endpoint_release
from serverware import native_pilot_genesis_key_authority as keys
from serverware import native_pilot_genesis_launch_profile as launch
from serverware import native_pilot_genesis_native_service_authority as service
from serverware import native_pilot_genesis_ordinary_authority as ordinary
from serverware import native_pilot_genesis_ordinary_initial_authority as initial
from serverware import native_pilot_genesis_ordinary_runtime as runtime
from serverware import native_pilot_genesis_parent_authority as parent
from serverware import native_pilot_genesis_verifier_authority as verifier
from serverware import native_pilot_publication_cold_binding as binding
from serverware import native_shadow_nitro_originals as originals

p = g.p
API = "serverware.nativePilotGenesisJobs/v1"
OWNER_ACTION_API = "serverware.nativePilotGenesisOwnerAction/v1"
ORDINARY = initial.profile.ROLES
NATIVE = delivery.ROLES
COORDINATOR = NATIVE[-1]
AUTHORIZATIONS = ("role-keys", "admission", "closure", "encrypted-delivery", "verifier-transport")
MAX_OUTPUT = 32 * 1024 * 1024


class Job(NamedTuple):
    name: str
    family: str
    role: str | None
    operation: str | None
    key: str | None
    maximum: int


def _producer(name, family, maximum, role=None, operation=None, *, signed=True):
    return Job(name, family, role, operation, name if signed else None, maximum)


def _owner(name, maximum=65536, role=None):
    return Job(name, "owner", role, None, None, maximum)


def _native(role):
    return tuple(_producer("native-" + operation + "-" + role, operation,
        keys.MAX_INPUT if operation in ("role-keys", "admission") else closure.MAX_INPUT if operation == "closure"
        else encrypted.MAX_INPUT if operation == "encrypted-delivery" else verifier.MAX_INPUT,
        role, operation) for operation in AUTHORIZATIONS)


# No input-supplied operation list. Both native grants require authentic
# endpoint pairs; Retrieval additionally needs the prior publication original.
JOBS = (
    _producer("closure-set", "closure-set", sets.MAX_BYTES, signed=False),
    _producer("assignment", "assignment", assignment.MAX_INPUT),
    _producer("cold-binding", "cold-binding", binding.MAX_INPUT, signed=False),
    _producer("parent-precreation", "parent", parent.MAX_INPUT, operation="precreation"),
    _owner("install-precreation"), _owner("parent-start"),
    _owner("ordinary-prepare"), _owner("endpoints-prepare"),
    *(_producer("initial-" + operation + "-" + role, "initial", initial.MAX_INPUT, role, operation,
        signed=operation != "assemble") for role in ORDINARY for operation in initial.OPERATIONS),
    *(_producer("ordinary-runtime-" + role, "ordinary-runtime", ordinary.MAX_INPUT, role, "delivery", signed=False)
        for role in ORDINARY),
    *(_producer("ordinary-delivery-" + role, "ordinary", ordinary.MAX_INPUT, role, "delivery") for role in ORDINARY),
    _producer("native-delivery-" + NATIVE[0], "delivery", delivery.MAX_INPUT, NATIVE[0]),
    _owner("admit-delivery-" + NATIVE[0], role=NATIVE[0]), _owner("initialize-retrieval-store"),
    _producer("native-delivery-" + NATIVE[1], "delivery", delivery.MAX_INPUT, NATIVE[1]),
    _owner("admit-delivery-" + NATIVE[1], role=NATIVE[1]),
    *(_job for role in NATIVE[:2] for _job in _native(role)),
    *(_producer("native-" + operation + "-grant", "service", service.MAX_INPUT, operation=operation)
        for operation in service.OPERATIONS),
    *(_producer("ordinary-grant-" + role, "ordinary", ordinary.MAX_INPUT, role, "grant") for role in ORDINARY),
    *(_owner("install-ordinary-" + role, role=role) for role in ORDINARY),
    *(_job for role in NATIVE[:2] for _job in (
        _producer("native-launch-" + role, "launch", launch.MAX_INPUT, role, signed=False),
        _owner("install-launch-" + role, 32 * 1024 * 1024, role))),
    _producer("endpoint-release", "endpoint-release", endpoint_release.MAX_INPUT),
    _owner("endpoints-release"), _owner("ordinary-release"),
    _owner("coordinator-prepare"), _owner("coordinator-assemble"),
    _producer("native-delivery-" + COORDINATOR, "delivery", delivery.MAX_INPUT, COORDINATOR),
    *_native(COORDINATOR),
    _producer("native-launch-" + COORDINATOR, "launch", launch.MAX_INPUT, COORDINATOR, signed=False),
    _owner("install-launch-" + COORDINATOR, 32 * 1024 * 1024, COORDINATOR),
    _producer("parent-release", "parent", parent.MAX_INPUT, operation="release"),
    _owner("coordinator-release"), _owner("coordinator-finish"), _owner("cleanup"),
)
BY_NAME = {job.name: job for job in JOBS}
KEY_PURPOSES = tuple(job.key for job in JOBS if job.key is not None)
# Explicit successor: acquisition while endpoints still live, then actual
# cleanup, then acknowledged descriptor custody. Legacy JOBS remains closed.
HANDOFF_JOBS = JOBS[:-1] + (_owner("acquire-cold-core"), JOBS[-1], _owner("handoff-cold-core"))
HANDOFF_BY_NAME = {item.name: item for item in HANDOFF_JOBS}
PARENTS = dict(zip(delivery.PARENTS, ("parent.configuration", "parent.cold", "parent.precreation", "parent.observation"), strict=True))
OBSERVATIONS = (*PARENTS.values(), "parent.peer", "ordinary.configuration", "ordinary.preparation", "ordinary.resources",
    *("ordinary.activation." + role for role in ORDINARY), *("ordinary.runtime-inputs." + role for role in ORDINARY),
    "endpoints.configuration", "endpoints.preparation", "endpoints.resources",
    *("endpoints.activation." + role for role in NATIVE[:2]), "endpoints.store",
    "coordinator.observation", "coordinator.runtime", "coordinator.activation")


def catalogue(*, handoff=False):
    p.require(type(handoff) is bool)
    return HANDOFF_JOBS if handoff else JOBS


def job(name, *, handoff=False):
    p.require(type(handoff) is bool)
    selected = HANDOFF_BY_NAME if handoff else BY_NAME
    p.require(type(name) is str and name in selected)
    return selected[name]


def _raw(value):
    p.require(type(value) is str and value.isascii())
    return value.encode("ascii")


def _same(left, right):
    p.require(g.canonical(left) == g.canonical(right))


def _record(prior, name, field="result"):
    row = p.fields(prior[name], ("input", "result"))
    p.require(all(type(raw) is bytes and 0 < len(raw) <= MAX_OUTPUT for raw in row.values()))
    return row[field]


def _observed(observations, name):
    raw = observations[name]
    p.require(name in OBSERVATIONS and type(raw) is bytes and 0 < len(raw) <= MAX_OUTPUT)
    return raw


def _parents(value, observations):
    for field, observed in PARENTS.items():
        p.require(_raw(value[field]) == _observed(observations, observed))


def _ordinary_source(value, observations):
    _parents(value, observations)
    for field, name in (("launchOriginal", "ordinary.configuration"), ("preparationOriginal", "ordinary.preparation"),
            ("resourcesOriginal", "ordinary.resources")):
        p.require(_raw(value[field]) == _observed(observations, name))


def _histories(value, prior):
    for role, original in p.fields(value, ORDINARY).items():
        p.require(_raw(original) == _record(prior, "initial-assemble-" + role))


def _binding(value, prior):
    p.require(_raw(value["coldBindingInputOriginal"]) == _record(prior, "cold-binding", "input")
        and value["coldBindingInputSha256"] == p.sha(_record(prior, "cold-binding", "input")))


def _pair(value, role, prior):
    for operation, prefix in (("role-keys", "roleKey"), ("admission", "admission")):
        name = "native-" + operation + "-" + role
        p.require(_raw(value[prefix + "InputOriginal"]) == _record(prior, name, "input")
            and _raw(value[prefix + "Original"]) == _record(prior, name))


def associate(selected, value, *, prior, observations):
    """Exact fixed-field joins only; the producer separately authenticates data."""
    family, role, operation = selected.family, selected.role, selected.operation
    if family == "assignment":
        p.require(_raw(value["closureSetOriginal"]) == _record(prior, "closure-set"))
    elif family == "cold-binding":
        p.require(_raw(value["closureSetOriginal"]) == _record(prior, "closure-set")
            and _raw(value["assignmentOriginal"]) == _record(prior, "assignment"))
    elif family == "parent" and operation == "release":
        for field, observation in (("configurationOriginal", "parent.configuration"), ("deliveryConfigurationOriginal", "parent.cold"),
                ("precreationOriginal", "parent.precreation"), ("observationOriginal", "parent.observation")):
            p.require(_raw(value[field]) == _observed(observations, observation))
        launched = p.document(_record(prior, "native-launch-" + COORDINATOR), launch.MAX_OUTPUT)
        p.require(value["launchOriginal"] == launched["launchOriginal"]
            and _raw(value["closureOriginal"]) == _record(prior, "native-closure-" + COORDINATOR))
    elif family == "initial":
        p.require(value["serviceRole"] == role and value["operation"] == operation)
        _ordinary_source(value, observations)
        if operation != "checkpoint":
            checkpoint_name = "initial-checkpoint-" + role
            checkpoint_input = initial.input_document(_record(prior, checkpoint_name, "input"))
            for field in initial.COMMON_FIELDS:
                if field != "operation":
                    _same(value[field], checkpoint_input[field])
            p.require(_raw(value["initialCheckpointOriginal"]) == _record(prior, checkpoint_name))
        if operation == "assemble":
            for signer, literal in p.fields(value["anchorSignatures"], initial.KEY_NAMES).items():
                p.require(_raw(literal) == _record(prior, "initial-" + signer + "-anchor-" + role))
    elif family in ("ordinary", "ordinary-runtime"):
        p.require(value["serviceRole"] == role and value["operation"] == operation)
        _ordinary_source(value["source"], observations); _histories(value["historyOriginals"], prior)
        p.require(_raw(value["coordinatorPeerPreparationOriginal"]) == _observed(observations, "parent.peer"))
        reference = ("ordinary-runtime-" + ORDINARY[0] if family == "ordinary-runtime" and role != ORDINARY[0]
            else "ordinary-delivery-" + role if operation == "grant" else None)
        if reference is not None:
            original = ordinary.input_document(_record(prior, reference, "input"))
            for field in ordinary.COMMON:
                if field not in ("operation", "serviceRole"):
                    _same(value[field], original[field])
        if operation == "delivery":
            p.require(g.canonical(value["activation"]) == _observed(observations, "ordinary.activation." + role))
            if family == "ordinary":
                p.require(g.canonical(value) == _record(prior, "ordinary-runtime-" + role, "input"))
                payload = g.document(_raw(value["payloadOriginal"]), ordinary.MAX_DELIVERY)
                p.require(payload["runtimeConfig"]["sha256"] == p.sha(_record(prior, "ordinary-runtime-" + role)))
        else:
            _binding(value, prior)
            for selected_role in ORDINARY:
                p.require(_raw(value["deliveryOriginals"][selected_role]) == _record(prior, "ordinary-delivery-" + selected_role)
                    and g.canonical(value["activation"][selected_role]) == _observed(observations, "ordinary.activation." + selected_role))
            for field, kind in (("nativePublicationOriginal", "publication"), ("nativeRetrievalOriginal", "retrieval")):
                p.require(_raw(value[field]) == _record(prior, "native-" + kind + "-grant"))
    elif family == "delivery":
        p.require(value["role"] == role); _parents(value["parentOriginals"], observations)
        if role == COORDINATOR:
            p.require(_raw(value["runtimeOriginal"]) == _observed(observations, "coordinator.runtime")
                and _raw(value["activationOriginal"]) == _observed(observations, "coordinator.activation"))
        else:
            for field, observed in (("ownerConfigurationOriginal", "endpoints.configuration"),
                    ("preparationOriginal", "endpoints.preparation"), ("resourcesOriginal", "endpoints.resources")):
                p.require(_raw(value[field]) == _observed(observations, observed))
            p.require(_raw(value["activationOriginal"]) == _observed(observations, "endpoints.activation." + role))
    elif family in ("role-keys", "admission", "closure"):
        p.require(value["role"] == role); _binding(value, prior)
        p.require(_raw(value["deliveryInputOriginal"]) == _record(prior, "native-delivery-" + role, "input")
            and _raw(value["deliveryOriginal"]) == _record(prior, "native-delivery-" + role))
        if family == "admission":
            first = keys.input_document(_record(prior, "native-role-keys-" + role, "input"))
            for field in (*keys.profile.SOURCE_FIELDS, "policy"):
                _same(value[field], first[field])
            p.require(_raw(value["roleKeyOriginal"]) == _record(prior, "native-role-keys-" + role))
    elif family in ("encrypted-delivery", "verifier-transport"):
        p.require(value["role"] == role); _pair(value, role, prior)
    elif family == "service":
        p.require(value["operation"] == operation); _binding(value, prior)
        _ordinary_source(value["ordinary"]["source"], observations)
        _histories(value["ordinary"]["historyOriginals"], prior)
        p.require(_raw(value["coordinatorPeerPreparationOriginal"]) == _observed(observations, "parent.peer"))
        current = ordinary.input_document(_record(prior, "ordinary-runtime-" + ORDINARY[0], "input"))
        for field in ("runtimePolicy", "source", "historyOriginals"):
            _same(value["ordinary"][field], current[field])
        for field in ("expectedPeer", "coordinatorPeerPreparationOriginal"):
            _same(value[field], current[field])
        for endpoint, pair in p.fields(value["endpointPairs"], service.ENDPOINTS).items():
            _pair(pair, endpoint, prior)
        if operation == "retrieval":
            p.require(_raw(value["nativePublicationOriginal"]) == _record(prior, "native-publication-grant")
                and _raw(value["retrievalStoreObservationOriginal"]) == _observed(observations, "endpoints.store"))
    elif family == "launch":
        p.require(value["role"] == role); _pair(value["pairContext"], role, prior)
        for name, row in value["authorizations"].items():
            p.require(_raw(row["inputOriginal"]) == _record(prior, "native-" + name + "-" + role, "input")
                and _raw(row["authorizationOriginal"]) == _record(prior, "native-" + name + "-" + role))
        for name, row in value["serviceContexts"].items():
            p.require(_raw(row["inputOriginal"]) == _record(prior, "native-" + name + "-grant", "input")
                and _raw(row["grantOriginal"]) == _record(prior, "native-" + name + "-grant"))
    elif family == "endpoint-release":
        _parents(value["parentOriginals"], observations)
        for field, observed in (("configurationOriginal", "endpoints.configuration"),
                ("preparationOriginal", "endpoints.preparation"), ("resourcesOriginal", "endpoints.resources")):
            p.require(_raw(value[field]) == _observed(observations, observed))
        for endpoint, row in value["services"].items():
            bundle = p.document(_record(prior, "native-launch-" + endpoint), launch.MAX_OUTPUT)
            _same(row["launch"], bundle["launchPin"])
            p.require(row["launchOriginal"] == bundle["launchOriginal"]
                and _raw(row["closureInputOriginal"]) == _record(prior, "native-closure-" + endpoint, "input")
                and _raw(row["closureOriginal"]) == _record(prior, "native-closure-" + endpoint))


def _runtime(value, *, boot, now_boottime_ns):
    return runtime.build(value["serviceRole"], fragment=value["runtimePolicy"],
        history_originals={role: _raw(raw) for role, raw in value["historyOriginals"].items()}, source=value["source"],
        peer_preparation_raw=_raw(value["coordinatorPeerPreparationOriginal"]), approved_peer=value["expectedPeer"],
        boot=boot, now_boottime_ns=now_boottime_ns)


def prepare_input(name, raw, *, prior, observations, boot, now_boottime_ns, now_unix_ns):
    selected = job(name)
    p.require(selected.family != "owner" and type(raw) is bytes and 0 < len(raw) <= selected.maximum)
    index = JOBS.index(selected)
    p.require(type(prior) is dict and set(prior) == {item.name for item in JOBS[:index]}
        and type(observations) is dict and set(observations).issubset(OBSERVATIONS))
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    mono = dict(boot=boot, now_boottime_ns=now_boottime_ns)
    family, role, operation = selected.family, selected.role, selected.operation
    if family == "closure-set":
        from scripts.authority import prepare_native_pilot_closure_set as preparation
        value = p.document(raw, selected.maximum)
        p.require(value["apiVersion"] == preparation.GENESIS_BOOTSTRAP_INPUT_API
            and value["setApiVersion"] == sets.GENESIS_BOOTSTRAP_API)
        prepared = {"outputOriginal": preparation.prepare(raw, p.sha(raw))}
    elif family == "assignment":
        value, selected_set = assignment.input_document(raw)
        p.require(selected_set == sets.GENESIS_BOOTSTRAP_API)
        prepared = assignment.prepare_input(raw, now_unix_ns=now_unix_ns)
    elif family == "cold-binding":
        value = binding.input_document(raw)
        result = binding.prepare(input_original=raw, expected_input_sha256=p.sha(raw), **clocks)
        parsed = binding.result_document(result)
        trust = g.document(_raw(value["trustOriginal"]), g.MAX_BYTES)
        assigned = g.document(_raw(value["assignmentOriginal"]), g.MAX_BYTES)["payload"]
        prepared = {"outputOriginal": result, "deadline": p.ns(parsed["deadlineBoottimeNs"]),
            "epochLimit": min(parsed["expiresAtUnixNanos"], trust["issuedAtUnixNanos"] + binding.MAX_AGE + 1,
                assigned["issuedAtUnixNanos"] + binding.MAX_AGE + 1)}
    elif family == "parent":
        value = parent.input_document(raw); p.require(value["operation"] == operation)
        prepared = parent.prepare_input(raw, **mono)
    elif family == "initial":
        value = initial.input_document(raw); prepared = initial.prepare_input(operation, raw, **mono)
    elif family in ("ordinary", "ordinary-runtime"):
        value = ordinary.input_document(raw); prepared = ordinary.prepare_input(operation, raw, **clocks)
        if family == "ordinary-runtime":
            prepared["outputOriginal"] = _runtime(value, **mono)
    elif family == "delivery":
        value = delivery.input_document(raw); prepared = delivery.prepare_input(role, raw, **mono)
    elif family in ("role-keys", "admission"):
        value = keys.input_document(raw); prepared = keys.prepare_input(operation, role, raw, **clocks)
    elif family in ("closure", "encrypted-delivery", "verifier-transport", "launch"):
        module = {"closure": closure, "encrypted-delivery": encrypted, "verifier-transport": verifier, "launch": launch}[family]
        value = module.input_document(raw); prepared = module.prepare_input(role, raw, **clocks)
    elif family == "service":
        value = service.input_document(raw); prepared = service.prepare_input(operation, raw, **clocks)
    else:
        p.require(family == "endpoint-release")
        value = endpoint_release.input_document(raw); prepared = endpoint_release.prepare_input(raw, **clocks)
    associate(selected, value, prior=prior, observations=observations)
    return {"nativeContext": prepared, "deadline": prepared.get("deadline"), "epochLimit": prepared.get("epochLimit")}


def run(name, *, input_original, prior, observations, key_loader):
    """Fixed producer dispatch. Key loader is the retained executor's method."""
    selected = job(name)
    owner = os.getpid(), originals._start(), originals._boot()
    before, wall = originals._clock(), time.time_ns()
    prepared = prepare_input(name, input_original, prior=prior, observations=observations,
        boot=owner[2], now_boottime_ns=before, now_unix_ns=wall)
    p.require((os.getpid(), originals._start(), originals._boot()) == owner)
    current_boot, current_wall = originals._clock(), time.time_ns()
    p.require(before <= current_boot and wall <= current_wall
        and (prepared["deadline"] is None or current_boot < prepared["deadline"])
        and (prepared["epochLimit"] is None or current_wall < prepared["epochLimit"]))
    key = key_loader(selected.key) if selected.key is not None else None
    family, role, operation = selected.family, selected.role, selected.operation
    if family in ("closure-set", "cold-binding", "ordinary-runtime"):
        result = prepared["nativeContext"]["outputOriginal"]
    elif family == "initial" and operation == "assemble":
        result, deadline = initial.assemble(input_original=input_original)
        p.require(deadline == prepared["deadline"])
    elif family == "launch":
        result, deadline = launch.assemble(role, input_original=input_original)
        p.require(deadline == prepared["deadline"] and result == prepared["nativeContext"]["bundleOriginal"])
    elif family == "assignment":
        result = assignment.sign(input_original=input_original, signing_key=key)
    elif family in ("parent", "endpoint-release"):
        module = parent if family == "parent" else endpoint_release
        result, deadline = module.sign(input_original=input_original, signing_key=key)
        p.require(deadline == prepared["deadline"])
    elif family == "initial":
        result, deadline = initial.sign(operation, input_original=input_original, signing_key=key)
        p.require(deadline == prepared["deadline"])
    elif family in ("ordinary", "service"):
        module = ordinary if family == "ordinary" else service
        result = module.sign(operation, input_original=input_original, signing_key=key)
    elif family in ("role-keys", "admission"):
        result, deadline = keys.sign(operation, role, input_original=input_original, signing_key=key)
        p.require(deadline == prepared["deadline"])
    else:
        module = {"delivery": delivery, "closure": closure, "encrypted-delivery": encrypted, "verifier-transport": verifier}[family]
        result, deadline = module.sign(role, input_original=input_original, signing_key=key)
        p.require(deadline == prepared["deadline"])
    p.require((os.getpid(), originals._start(), originals._boot()) == owner)
    now, epoch = originals._clock(), time.time_ns()
    p.require(current_boot <= now and current_wall <= epoch and type(result) is bytes and 0 < len(result) <= MAX_OUTPUT
        and (prepared["deadline"] is None or now < prepared["deadline"])
        and (prepared["epochLimit"] is None or epoch < prepared["epochLimit"]))
    return {"result": result, "deadline": prepared["deadline"], "epochLimit": prepared["epochLimit"]}


def publication_plan(name, prior, observations, *, boot, now_boottime_ns, now_unix_ns):
    from serverware import native_pilot_genesis_job_publication as publication
    return publication.publication_plan(name, prior=prior, observations=observations, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
