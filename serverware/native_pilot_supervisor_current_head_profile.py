"""Fixed late current-head intake over authenticated, retained public sources.

No helper here observes a process, owns a pending request, constructs a
currentness decision or approves an input. The caller must establish that the
literal sources are the actual completed conductor inputs/results. In
particular, generation rows must match their complete approved input and
result, and all eight initial wrappers must match the actual assembly outputs.
Historical signatures establish source associations, never currentness.
"""
from __future__ import annotations

import copy

from serverware import custody_generation_grants as g
from serverware import native_pilot_current_head_profile as head
from serverware import native_pilot_initial_requests_profile as requests
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_key_authority as history
from serverware import native_pilot_ordinary_key_profile as key
from serverware import native_pilot_ordinary_runtime_profile as runtime
from serverware import native_pilot_service_authority as service
from serverware import native_pilot_window_authority as windows
from serverware import native_shadow_driver_bootstrap as driver

p = g.p
API = "serverware.nativePilotSupervisorCurrentHeadPolicy/v1"
OBSERVED_API = "serverware.nativePilotCurrentHeadObservedRequest/v1"
MAX_POLICY = 4096
MAX_INPUT = head.MAX_INPUT
MAX_OUTPUT = head.MAX_OUTPUT
MAX_OBSERVED = 32 * 1024 * 1024
MAX_RETAINED_BYTES = 128 * 1024 * 1024
TARGETS = tuple((role, None) for role in g.ROLES[:4]) + tuple(
    (g.ROLES[-1], endpoint_role) for endpoint_role in initial.HELPER_ENDPOINT_ROLES)
JOB_NAMES = tuple("current-head-" + role + ("-" + endpoint if endpoint else "")
    for role, endpoint in TARGETS)
_POLICY_FIELDS = ("authorities", "endpointRole", "endpointGeneration", "serviceGeneration",
    "operationGeneration", "durableEpoch", "deploymentGenerationSha256",
    "revocationGenerationHighWater", "revocationRootSha256", "validity")
_STATE_GENERATIONS = ("endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch")
_SOURCE_FIELDS = ("fragment", "bridge_preparation_raw", "driver_configuration_raw", "driver_window_raw",
    "launch_raw", "preparation_raw", "resources_raw", "ordinary_context", "initial_policy")
_CONTEXT_FIELDS = ("sources", "window", "deadline", "targets", "validatedAtBoottimeNanos")


def validate_policy(fragment):
    """Select exactly the eight independent late intakes, never future facts."""
    p.fields(fragment, ("apiVersion", "targets"))
    p.require(fragment["apiVersion"] == API and type(fragment["targets"]) is list
        and fragment["targets"] == list(JOB_NAMES) and len(p.canonical(fragment)) <= MAX_POLICY)
    return copy.deepcopy(fragment)


def _same(first, second):
    p.require(g.canonical(first) == g.canonical(second))


def _text(raw, bound):
    p.require(type(raw) is bytes and 0 < len(raw) <= bound)
    return raw.decode("ascii")


def _approved_history(role, row, item):
    """Bind authenticated history keys/state to independently selected policy."""
    p.fields(row, _POLICY_FIELDS)
    p.require(row["validity"] == "observed-initial-resources-through-original-lifetime")
    authorities = p.fields(row["authorities"], ("root", "checkpoint", "service"))
    for public in authorities.values():
        history._key(public)
    root = {name: authorities["root"][name] for name in ("keyId", "keySpkiSha256")}
    p.require(root == {"keyId": item["header"]["authorityHistoryRootKeyId"],
        "keySpkiSha256": item["header"]["authorityHistoryRootKeySpkiSha256"]})
    wrapper = p.fields(g.document(item["history_raw"], g.MAX_BYTES), initial.WRAPPER_FIELDS)
    p.require(wrapper["apiVersion"] == initial.WRAPPER_API)
    manifest = initial.manifest(item["history_raw"], role=role, root_pin=root)
    epoch = manifest["firstRetainedEpoch"]["retainedEpoch"]
    _same(authorities, {"root": manifest["rootAuthority"], "checkpoint": epoch["checkpointAuthority"],
        "service": epoch["serviceSigningKey"]})
    p.require(row["endpointRole"] == epoch["endpointProcessIdentity"]["endpointRole"])
    state, payload = wrapper["initialState"], wrapper["initialCheckpoint"]["payload"]
    for name in _STATE_GENERATIONS:
        p.require(key._uint(row[name]) == state[name])
    p.require(p.digest(row["deploymentGenerationSha256"]) == state["deploymentGenerationSha256"]
        and key._uint(row["revocationGenerationHighWater"]) == payload["revocationGenerationHighWater"]
        and p.digest(row["revocationRootSha256"]) == payload["revocationRootSha256"])
    return root, wrapper, epoch


def prepare_context(*, fragment, bridge_preparation_raw, driver_configuration_raw, driver_window_raw,
                    launch_raw, preparation_raw, resources_raw, ordinary_context, initial_policy,
                    boot, now_boottime_ns):
    """Authenticate public source joins; the caller establishes their provenance.

    The five row6 values are literal originals from actual generation inputs
    plus their actual signed generation outputs. No source is synthesized from
    a digest. This returns checked data, not a live owner or signing approval.
    """
    from serverware import native_pilot_bridge_preparation as bridge

    fragment = validate_policy(fragment)
    now = key._uint(now_boottime_ns)
    config = windows.validate_configuration(driver_configuration_raw)
    signed_window = p.fields(p.document(driver_window_raw, windows.MAX_WINDOW),
        ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed_window["apiVersion"] == "serverware.nativeShadowDriverBootstrapWindow/v1")
    window = signed_window["payload"]
    driver._key(config["bootstrapAuthority"]).verify(p.decoded(signed_window["signatureBase64url"], size=64),
        driver.WINDOW_DOMAIN + p.canonical(window))
    windows.validate_window(window, driver_configuration_raw, config, boot=boot, now=now)
    launch, startup, lifetime = service._launch(launch_raw, boot, now)
    p.require(startup == p.ns(window["startupDeadlineBoottimeNs"])
        and lifetime == p.ns(window["lifetimeDeadlineBoottimeNs"])
        and launch["invocationId"] == window["invocationId"])
    measured = key.preparation(preparation_raw)
    initial.resources(resources_raw)
    observed = bridge.shape(bridge_preparation_raw)
    p.require(observed["apiVersion"] == bridge.HELPER_API)
    exported, peers = bridge._parts(observed)
    p.require(exported["apiVersion"] == requests.HELPER_API
        and exported["launchSha256"] == p.sha(launch_raw)
        and exported["preparationSha256"] == p.sha(preparation_raw)
        and exported["resourcesSha256"] == p.sha(resources_raw))
    ordinary_peers = peers["ordinary-services"]
    p.require(tuple(ordinary_peers[name] for name in bridge.WINDOW)
        == tuple(window[name] for name in bridge.WINDOW))
    p.require(all(p.ns(peer["observedAtBoottimeNs"]) <= now for peer in peers.values()))
    for role in g.ROLES:
        actual, peer = measured["services"][role], ordinary_peers["peers"][role]
        p.require(actual["processId"] == peer["processId"] and actual["startTimeTicks"] == peer["startTimeTicks"]
            and peer["pidfd"] == {name: actual["pidfdStat"][name] for name in ("device", "inode")}
            and peer["targetExecutable"] == {name: actual["targetExecutable"][name]
                for name in ("device", "inode", "length", "sha256")})
    p.fields(initial_policy, ("apiVersion", "services"))
    p.require(initial_policy["apiVersion"] == "serverware.nativePilotSupervisorOrdinaryInitialPolicy/v1")
    policy_rows = p.fields(initial_policy["services"], g.ROLES)
    rows = p.fields(ordinary_context, g.ROLES)
    contexts, items, pinned = {}, {}, {}
    deadline, issued_floor, common_scope, total = startup, 0, None, sum(map(len, (bridge_preparation_raw,
        driver_configuration_raw, driver_window_raw, launch_raw, preparation_raw, resources_raw)))
    total += len(g.canonical(initial_policy))
    for role in g.ROLES:
        row = p.fields(rows[role], service._SERVICE + ("generationGrantOriginal",))
        total += sum(len(value.encode("ascii")) for value in row.values() if type(value) is str)
        p.require(total <= MAX_RETAINED_BYTES)
        item = service._service(row, role, launch, boot, startup, lifetime, now, granted=True)
        runtime.validate_runtime(role, item["runtime_raw"])
        root, wrapper, epoch = _approved_history(role, policy_rows[role], item)
        generation = item["generation"]
        p.require(generation["scope"]["previousConfigurationBindingSha256"] is None)
        if common_scope is None:
            common_scope = generation["scope"]
        else:
            _same(common_scope, generation["scope"])
        deadline = min(deadline, generation["expiresAtBoottimeNanos"])
        issued_floor = max(issued_floor, generation["issuedAtBoottimeNanos"])
        contexts[role] = dict(configurationOriginal=row["configurationOriginal"].encode("ascii"),
            runtimeOriginal=item["runtime_raw"], historyOriginal=item["history_raw"], guest=item["guest"])
        items[role] = item
        pinned[role] = root, wrapper, epoch
    p.require(items[g.ROLES[-1]]["header"]["apiVersion"] == initial.HELPER_RUNTIME_API)
    selection = requests.select(contexts, preparation_original=preparation_raw, resources_original=resources_raw,
        launch_original=launch_raw, window=window, boot=boot, now_boottime_ns=now)
    selected = {(role, endpoint): row for role, endpoint, row in requests.iter_selection(selection)}
    members = initial.helper_endpoint_histories(items[g.ROLES[-1]]["history_raw"],
        runtime=runtime.validate_runtime(g.ROLES[-1], items[g.ROLES[-1]]["runtime_raw"]))
    targets = {}
    for job_name, (role, endpoint) in zip(JOB_NAMES, TARGETS, strict=True):
        row = exported["requests"][role] if endpoint is None else exported["requests"][role][endpoint]
        endpoint = row["endpointRole"]
        expected = selected[role, endpoint]
        for name in ("endpointRole", "runtimeConfigurationSha256", "initialHistorySha256", "checkpointSha256"):
            p.require(row[name] == expected[name])
        pending = head.request(row["requestOriginal"].encode("ascii"))
        _same(pending["operation"]["body"]["accepted_floor"], expected["floor"])
        p.require(pending["deadline"]["domain"] == expected["domain"]
            and pending["deadline"]["absoluteBoottimeNanos"] == min(expected["deadline"], deadline)
            and issued_floor <= pending["requestedAtBoottimeNanos"] <= now)
        root, wrapper, epoch = pinned[role]
        selected_history = items[role]["history_raw"]
        if role == g.ROLES[-1]:
            wrapper, epoch, selected_history = (members[endpoint][name] for name in ("wrapper", "epoch", "original"))
        checkpoint = wrapper["initialCheckpoint"]
        p.require(p.ns(wrapper["initialState"]["issuedAtBoottimeNs"]) <= pending["requestedAtBoottimeNanos"]
            and checkpoint["payload"]["validFromBoottime"]["absoluteBoottimeNanos"]
                <= pending["requestedAtBoottimeNanos"])
        target_deadline = pending["deadline"]["absoluteBoottimeNanos"]
        targets[job_name] = dict(serviceRole=role, endpointRole=endpoint, request=copy.deepcopy(row),
            rootAuthority=copy.deepcopy(root), checkpointAuthority=copy.deepcopy(epoch["checkpointAuthority"]),
            selectedHistoryOriginal=selected_history.decode("ascii"), deadline=target_deadline)
        total += len(p.canonical(targets[job_name]))
        p.require(total <= MAX_RETAINED_BYTES)
    deadline = min(deadline, *(row["deadline"] for row in targets.values()))
    p.require(now < deadline)
    sources = dict(fragment=fragment, bridge_preparation_raw=bridge_preparation_raw,
        driver_configuration_raw=driver_configuration_raw, driver_window_raw=driver_window_raw,
        launch_raw=launch_raw, preparation_raw=preparation_raw, resources_raw=resources_raw,
        ordinary_context=copy.deepcopy(ordinary_context), initial_policy=copy.deepcopy(initial_policy))
    return dict(sources=sources, window=copy.deepcopy(window), deadline=deadline, targets=targets,
        validatedAtBoottimeNanos=now)


def _refresh(context, *, boot, now_boottime_ns):
    p.fields(context, _CONTEXT_FIELDS)
    p.fields(context["sources"], _SOURCE_FIELDS)
    p.require(key._uint(context["validatedAtBoottimeNanos"]) <= key._uint(now_boottime_ns))
    checked = prepare_context(**context["sources"], boot=boot, now_boottime_ns=now_boottime_ns)
    p.require(checked["window"] == context["window"] and checked["deadline"] == context["deadline"]
        and checked["targets"] == context["targets"])
    return checked


def observed_original(job_name, context):
    """Export existing evidence only: no currentness, approval or input template."""
    p.require(job_name in JOB_NAMES)
    context = _refresh(context, boot=tuple(context["window"][name] for name in
        ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")),
        now_boottime_ns=context["validatedAtBoottimeNanos"])
    sources, target = context["sources"], context["targets"][job_name]
    row = sources["ordinary_context"][target["serviceRole"]]
    # These are evidence originals, not the current-head input schema. The
    # independently authorized checkpoint decision is deliberately absent.
    originals = {name: _text(sources[source], bound) for name, source, bound in (
        ("bridgePreparation", "bridge_preparation_raw", 1024 * 1024),
        ("driverConfiguration", "driver_configuration_raw", 65536),
        ("driverWindow", "driver_window_raw", 32768), ("launch", "launch_raw", 65536),
        ("preparation", "preparation_raw", key.MAX_PREPARATION),
        ("resources", "resources_raw", initial.MAX_STATE))}
    originals.update({"configuration": row["configurationOriginal"], "runtime": row["runtimeOriginal"],
        "primaryInitialHistory": row["historyOriginal"], "selectedInitialHistory": target["selectedHistoryOriginal"],
        "generationGrant": row["generationGrantOriginal"], "request": target["request"]["requestOriginal"]})
    pending = head.request(originals["request"].encode("ascii"))
    result = dict(apiVersion=OBSERVED_API, jobName=job_name, serviceRole=target["serviceRole"],
        endpointRole=target["endpointRole"], originals=originals, rootAuthority=target["rootAuthority"],
        checkpointAuthority=target["checkpointAuthority"], checkpointSha256=target["request"]["checkpointSha256"],
        requestSha256=target["request"]["requestSha256"], requestNonceSha256=pending["requestNonceSha256"],
        deadlineBoottimeNanos=target["deadline"])
    raw = p.canonical(result)
    p.require(len(raw) <= MAX_OBSERVED)
    return raw


def prepare_input(job_name, input_raw, *, context, boot, now_boottime_ns):
    """Bind an independently supplied COMPLETE input, without constructing it."""
    p.require(job_name in JOB_NAMES)
    context = _refresh(context, boot=boot, now_boottime_ns=now_boottime_ns)
    sources, target = context["sources"], context["targets"][job_name]
    helper = target["serviceRole"] == g.ROLES[-1]
    value = p.fields(p.document(input_raw, MAX_INPUT), head.INPUT_FIELDS
        + (("endpointRole", "runtimeOriginal") if helper else ()))
    p.require(value["apiVersion"] == (head.HELPER_API if helper else head.API)
        and value["serviceRole"] == target["serviceRole"])
    for name, source in (("driverConfigurationOriginal", "driver_configuration_raw"),
            ("driverWindowOriginal", "driver_window_raw"), ("launchOriginal", "launch_raw"),
            ("preparationOriginal", "preparation_raw"), ("resourcesOriginal", "resources_raw")):
        p.require(type(value[name]) is str and value[name].encode("ascii") == sources[source])
    row = sources["ordinary_context"][target["serviceRole"]]
    p.require(value["configurationOriginal"] == row["configurationOriginal"]
        and value["initialHistoryOriginal"] == row["historyOriginal"]
        and value["rootAuthority"] == target["rootAuthority"]
        and value["requestOriginal"] == target["request"]["requestOriginal"])
    if helper:
        p.require(value["endpointRole"] == target["endpointRole"] and value["runtimeOriginal"] == row["runtimeOriginal"])
    prepared = head.prepare_input(input_raw, boot=boot, now_boottime_ns=now_boottime_ns)
    _same(prepared["authority"], target["checkpointAuthority"])
    p.require(prepared["deadline"] == target["deadline"] and now_boottime_ns < context["deadline"])
    return prepared


def checked_result(job_name, input_raw, result, *, context, boot, now_boottime_ns):
    prepare_input(job_name, input_raw, context=context, boot=boot, now_boottime_ns=now_boottime_ns)
    return head.checked_result(input_raw, result, boot=boot, now_boottime_ns=now_boottime_ns)
