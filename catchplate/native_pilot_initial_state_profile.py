"""Explicit initial-current-state delegation, never inferred freshness.

This pure projection authenticates the base fifteen-file installation input.
Only a real first-installation owner may use its result to initialize the
independently delegated empty registry. Active/current authority, scope,
authorities, counters, revocation facts and original bounds are supplied by the
delegation; signatures only authenticate matching installed-history facts.
No file owner, signature, approval, clock renewal or later-state update is made.
"""
from __future__ import annotations

import copy

from catchplate import native_pilot_current_head_worker_profile as worker
from catchplate import native_pilot_lifecycle_inputs as lifecycle
from catchplate import native_pilot_ordinary_initial_profile as initial
from catchplate import native_pilot_ordinary_runtime_profile as runtime

p, g = worker.p, initial.g
API = "catchplate.nativePilotInitialCurrentStateDelegation/v1"
PURPOSE = "authorize-generation-one-current-state-at-first-adopted-installation"
MAX_INPUT = 32 * 1024 * 1024
MAX_DELEGATION = 65536
POLICY_NAME = "worker-policy.json"
INVENTORY_NAME = "worker-supervisor-inventory.json"
STATE_DIRECTORY = worker.STATE_DIRECTORY
FIELDS = ("apiVersion", "purpose", "supervisorInventorySha256", "stateDirectory", "decisionDirectory",
    *worker.STATE_SCOPE, *worker.CLOCKS, "targets")
TARGET_FIELDS = ("serviceRole", "endpointRole", "rootAuthority", "checkpointAuthority",
    *worker.COUNTERS, "revocationRootSha256", "status")
DERIVED_PINS = ("initialHistorySha256", "endpointProcessIdentitySha256", "deploymentGenerationSha256", "checkpointSha256")
BASE_API = "catchplate.nativePilotAdoptedOrdinaryInstallationInput/v1"
BASE_FIELDS = ("apiVersion", "launchOriginal", "preparationOriginal", "resourcesOriginal",
    "driverConfigurationOriginal", "driverWindowOriginal", "coldOriginals", "historyOriginals", "runtimeOriginals")


def delegation(raw, *, boot, now_boottime_ns, now_unix_ns):
    """Closed independent permission; this function does not prove its custody."""
    value = p.fields(p.document(raw, MAX_DELEGATION), FIELDS)
    p.require(value["apiVersion"] == API and value["purpose"] == PURPOSE)
    p.digest(value["supervisorInventorySha256"])
    worker._directory(value["stateDirectory"]); worker._directory(value["decisionDirectory"])
    p.require(value["stateDirectory"] != value["decisionDirectory"])
    worker._interval(value); worker._live(value, boot, now_boottime_ns, now_unix_ns)
    worker.head.key._invocation(value["invocationId"])
    for name in worker.STATE_SCOPE[4:]: p.digest(value[name])
    p.fields(value["targets"], worker.JOB_NAMES)
    for name in worker.JOB_NAMES:
        row = p.fields(value["targets"][name], TARGET_FIELDS)
        role, endpoint = worker.phase.legacy.CURRENT_HEAD_JOB_INFO[name]
        p.require(row["serviceRole"] == role and row["endpointRole"] in worker.head.key.ENDPOINT_ROLES
            and (endpoint is None or row["endpointRole"] == endpoint) and row["status"] == "active")
        worker._pin(row["rootAuthority"]); worker._pin(row["checkpointAuthority"])
        for field in worker.COUNTERS: p.integer(row[field])
        p.require(row["checkpointSequence"] == 1)
        p.digest(row["revocationRootSha256"])
    p.require(len({(row["serviceRole"], row["endpointRole"]) for row in value["targets"].values()}) == len(worker.JOB_NAMES))
    return copy.deepcopy(value)


def _targets(value, installed):
    helper_runtime = runtime.validate_runtime(g.ROLES[-1], installed["runtimeOriginals"][g.ROLES[-1]].encode("ascii"), adopted=True)
    helpers = initial.helper_endpoint_histories(installed["historyOriginals"][g.ROLES[-1]].encode("ascii"), runtime=helper_runtime)
    targets, checkpoint_deadlines = {}, []
    for name in worker.JOB_NAMES:
        selected = value["targets"][name]
        role, endpoint = worker.phase.legacy.CURRENT_HEAD_JOB_INFO[name]
        raw = installed["historyOriginals"][role].encode("ascii") if endpoint is None else helpers[endpoint]["original"]
        # Independently pin the root, rather than trusting the root named by
        # the installation's runtime alone. This authenticates each of eight.
        history = initial.manifest(raw, role=role, root_pin=selected["rootAuthority"], adopted=True)
        wrapper = p.fields(g.document(raw, g.MAX_BYTES), initial.WRAPPER_FIELDS)
        state, checkpoint = wrapper["initialState"], wrapper["initialCheckpoint"]
        payload = checkpoint["payload"]
        epoch = history["firstRetainedEpoch"]["retainedEpoch"]
        p.require(payload["endpointRole"] == selected["endpointRole"]
            and payload["revocationStatus"] == "authorized-and-not-revoked"
            and {field: epoch["checkpointAuthority"][field] for field in ("keyId", "keySpkiSha256")} == selected["checkpointAuthority"]
            and payload["checkpointSequence"] == selected["checkpointSequence"]
            and payload["revocationGenerationHighWater"] == selected["revocationGenerationHighWater"]
            and payload["revocationRootSha256"] == selected["revocationRootSha256"])
        for field in ("endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch"):
            p.require(state[field] == selected[field])
        for field in (*worker.BOOT, "invocationId"):
            p.require(state[field] == value[field])
        checkpoint_deadlines.append(payload["validUntilBoottime"]["absoluteBoottimeNanos"])
        targets[name] = copy.deepcopy(selected) | dict(initialHistorySha256=p.sha(raw),
            endpointProcessIdentitySha256=state["endpointProcessIdentitySha256"],
            deploymentGenerationSha256=state["deploymentGenerationSha256"], checkpointSha256=checkpoint["checkpointSha256"])
    return targets, min(checkpoint_deadlines)


def prepare(delegation_raw, installation_original, supervisor_inventory_original, *,
            boot, now_boottime_ns, now_unix_ns):
    """Return existing State1/Update1/WorkerPolicy1, not installation success.

    The actual owner must commit these only after the same literal base input
    was successfully installed. The installation wrapper calls this function
    with base Input1; the local import avoids recursion through its Input2.
    """
    from catchplate import native_pilot_adopted_ordinary_install as installation

    p.require(all(type(raw) is bytes and raw for raw in (delegation_raw, installation_original, supervisor_inventory_original))
        and sum(map(len, (delegation_raw, installation_original, supervisor_inventory_original))) <= MAX_INPUT)
    value = delegation(delegation_raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.require(p.sha(supervisor_inventory_original) == value["supervisorInventorySha256"])
    lifecycle._inventory(supervisor_inventory_original, "supervisor")
    installed = p.fields(p.document(installation_original, MAX_INPUT), BASE_FIELDS)
    p.require(installed["apiVersion"] == BASE_API)
    admitted = installation.prepare_input(installation_original, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    for field, source in (("driverConfigurationSha256", "driverConfigurationOriginal"),
            ("driverWindowSha256", "driverWindowOriginal"), ("launchSha256", "launchOriginal")):
        p.require(value[field] == p.sha(installed[source].encode("ascii")))
    window = p.document(installed["driverWindowOriginal"].encode("ascii"), 32768)["payload"]
    p.require(all(window[field] == value[field] for field in (*worker.BOOT, "invocationId"))
        and p.ns(window["issuedAtBoottimeNs"]) <= p.ns(value["issuedAtBoottimeNs"])
        and p.ns(value["deadlineBoottimeNs"]) <= p.ns(window["lifetimeDeadlineBoottimeNs"]))
    targets, checkpoint_deadline = _targets(value, installed)
    p.require(p.ns(value["deadlineBoottimeNs"]) <= checkpoint_deadline)
    state_raw = p.canonical(dict(apiVersion=worker.STATE_API, generation=1,
        **{field: value[field] for field in (*worker.STATE_SCOPE, *worker.CLOCKS)}, targets=targets))
    worker.state(state_raw)
    update_raw = p.canonical(dict(apiVersion=worker.UPDATE_API, directory=copy.deepcopy(value["stateDirectory"]),
        expectedStateSha256=None, expectedGeneration=0, nextStateOriginal=state_raw.decode("ascii")))
    p.require(worker.update(update_raw, None) == state_raw)
    policy_raw = p.canonical(dict(apiVersion=worker.API, purpose=worker.PURPOSE,
        **{field: copy.deepcopy(value[field]) for field in ("supervisorInventorySha256", "stateDirectory", "decisionDirectory",
            *worker.BOOT, *worker.CLOCKS)}, initialStateSha256=p.sha(state_raw), initialStateGeneration=1))
    worker.prepare(policy_raw, inventory_sha256=value["supervisorInventorySha256"], boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    deadline = min(admitted["deadline"], p.ns(value["deadlineBoottimeNs"]))
    epoch_limit = value["expiresAtUnixNanos"]
    if admitted["epochLimit"] is not None: epoch_limit = min(epoch_limit, admitted["epochLimit"])
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch_limit)
    return dict(stateOriginal=state_raw, updateOriginal=update_raw, workerPolicyOriginal=policy_raw,
        deadline=deadline, epochLimit=epoch_limit)
