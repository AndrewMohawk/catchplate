"""Fixed candidate inputs for the existing cold owner actions; no ownership.

Only public bytes are composed. Real control constructors, exclusive writes,
store admission, process progress, descriptor transfer and cleanup remain in
GenesisExecution. A fixed action requests that existing operation; it is never
a fabricated result or permission inferred from successful validation.
"""
from __future__ import annotations

import copy

from catchplate import native_pilot_genesis_jobs as jobs
from catchplate import native_pilot_genesis_execution_protocol as wire
from catchplate import native_pilot_genesis_parent_control as parent_control
from catchplate import native_pilot_genesis_ordinary_control as ordinary_control
from catchplate import native_pilot_genesis_endpoint_control as endpoint_control
from catchplate import native_pilot_genesis_coordinator_assembly as assembly
from catchplate import native_pilot_genesis_launch_install as launch_install

p, g = jobs.p, jobs.g
LABEL_FIELDS = ("securityLabelSha256", "configurationGenerationSha256")
NAMES = tuple(row.name for row in jobs.HANDOFF_JOBS if row.family == "owner")


def selection_fields(selected):
    _selected(selected)
    return {"parent-start": ("controllerExecutableSha256",), "ordinary-prepare": ("launchOriginal",),
        "endpoints-prepare": ("configurationOriginal",), "coordinator-assemble": ("peers",)}.get(selected.name, ())


def _selected(selected):
    p.require(type(selected) is jobs.Job and selected.family == "owner"
        and jobs.HANDOFF_BY_NAME.get(selected.name) == selected and selected.name in NAMES)


def _record(prior, name, field="result"):
    return jobs._record(prior, name, field)


def _original(text, maximum):
    return jobs.delivery.original(text, maximum)


def _same_window(context, configuration):
    p.require(configuration["apiVersion"] == wire.HANDOFF_CONFIGURATION_API)
    wire.require_window(context["window"], configuration["window"])


def _parent(prior, observations, configuration, clocks, *, before_start=False):
    original_input = jobs.parent.input_document(_record(prior, "parent-precreation", "input"))
    config_raw = _original(original_input["configurationOriginal"], jobs.parent.MAX_WIRE)
    cold_raw = _original(original_input["deliveryConfigurationOriginal"], jobs.parent.MAX_COLD)
    signed_raw = _record(prior, "parent-precreation")
    p.require(original_input["operation"] == "precreation")
    checked = jobs.parent.prepare_input(_record(prior, "parent-precreation", "input"), **clocks)
    context = jobs.parent.validate_precreation(signed_raw, configuration_raw=config_raw,
        delivery_configuration_raw=cold_raw, **clocks)
    signed = g.document(signed_raw, jobs.parent.MAX_OUTPUT)
    p.require(g.canonical(signed["payload"]) == g.canonical(checked["payload"]))
    _same_window(context, configuration)
    result = dict(context=context, configuration_raw=config_raw, cold_raw=cold_raw, precreation_raw=signed_raw)
    if not before_start:
        for name, raw in (("configuration", config_raw), ("cold", cold_raw), ("precreation", signed_raw)):
            p.require(jobs._observed(observations, "parent." + name) == raw)
        observed_raw = jobs._observed(observations, "parent.observation")
        result["observed"] = jobs.parent.validate_observation(observed_raw,
            configuration_raw=config_raw, precreation_raw=signed_raw, context=context)
    return result


def _peer(measured, ids, labels, *, root):
    p.fields(labels, LABEL_FIELDS)
    for digest in labels.values(): p.digest(digest)
    result = {**ids, "pid": measured["processId"], "startTimeTicks": measured["startTimeTicks"],
        **{"executable" + name[0].upper() + name[1:]: measured["targetExecutable"][name]
            for name in ("device", "inode", "length", "sha256")},
        **{name: measured["cgroup"][source] for name, source in (
            ("cgroupPathSha256", "pathSha256"), ("cgroupMountId", "mountId"), ("cgroupInode", "inode"))},
        **copy.deepcopy(labels)}
    # The native v4 digest permits UID/GID zero only for this result-peer
    # branch. Do not route root through the legacy positive-UID hot helper.
    parts = [p.integer(result[name], minimum=0 if name in ("uid", "gid") else 1,
        maximum=(1 << (width * 8)) - 1).to_bytes(width, "big") for name, width in (
            ("uid", 4), ("gid", 4), ("pid", 4), ("startTimeTicks", 8),
            ("executableDevice", 8), ("executableInode", 8), ("executableLength", 8))]
    parts += [bytes.fromhex(p.digest(result["executableSha256"])[7:]), p.digest(result["cgroupPathSha256"]).encode("ascii")]
    parts += [p.integer(result[name], maximum=p.MAX_U64).to_bytes(8, "big") for name in ("cgroupMountId", "cgroupInode")]
    parts += [p.digest(result[name]).encode("ascii") for name in LABEL_FIELDS]
    result["processIdentitySha256"] = p.framed(b"catchplate.policyCustodyPeerProcessIdentity/v4", parts)
    assembly.runtime.peer(result, root=root)
    return result


def _assemble(selection, prior, observations, configuration, clocks):
    observed_raw = jobs._observed(observations, "coordinator.observation")
    observed = assembly.observation(observed_raw)
    wire.require_window(observed["window"], configuration["window"])
    p.require(g.canonical(observed["activation"]) == jobs._observed(observations, "coordinator.activation"))
    parent = _parent(prior, observations, configuration, {name: clocks[name] for name in ("boot", "now_boottime_ns")})
    for field, observation in (("parentConfigurationSha256", "parent.configuration"),
            ("parentPrecreationSha256", "parent.precreation"), ("ordinaryConfigurationSha256", "ordinary.configuration"),
            ("endpointConfigurationSha256", "endpoints.configuration")):
        p.require(observed[field] == p.sha(jobs._observed(observations, observation)))
    p.fields(selection["peers"], assembly.ROLES)
    ordinary_records, native_records, ids, bounds = {}, {}, {}, []
    for role in jobs.ORDINARY:
        name = "ordinary-grant-" + role
        raw, input_raw = _record(prior, name), _record(prior, name, "input")
        prepared = jobs.ordinary.prepare_input("grant", input_raw, **clocks)
        jobs.ordinary.checked_result("grant", input_raw, {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **clocks)
        # The exact grant input is already authenticated; join it again to
        # this transcript's actual sources and earlier issued originals.
        jobs.associate(jobs.job(name), jobs.ordinary.input_document(input_raw), prior=prior, observations=observations)
        guest = prepared["payload"]["guest"]
        ordinary_records[role] = {"runtimeOriginal": _record(prior, "ordinary-runtime-" + role).decode("ascii"),
            "historyOriginal": _record(prior, "initial-assemble-" + role).decode("ascii"),
            "grantOriginal": raw.decode("ascii"), "guest": guest}
        ids[role] = {name: guest[name] for name in ("uid", "gid")}
        bounds.append(prepared)
    for operation, role in zip(jobs.service.OPERATIONS, jobs.service.ENDPOINTS, strict=True):
        name = "native-" + operation + "-grant"
        raw, input_raw = _record(prior, name), _record(prior, name, "input")
        prepared = jobs.service.prepare_input(operation, input_raw, **clocks)
        jobs.service.checked_result(operation, input_raw, {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **clocks)
        jobs.associate(jobs.job(name), jobs.service.input_document(input_raw), prior=prior, observations=observations)
        guest = prepared["payload"]["authorization"]["guest"]
        native_records[role] = {"grantOriginal": raw.decode("ascii"), "guest": guest}
        ids[role] = {name: guest[name] for name in ("uid", "gid")}
        bounds.append(prepared)
    ids["resultPeer"] = {"uid": 0, "gid": 0}
    value = {"apiVersion": assembly.API, **{field: observed[field] for field in assembly.PINS},
        "peers": {role: _peer(observed["peers"][role], ids[role], selection["peers"][role], root=role == "resultPeer")
            for role in assembly.ROLES}}
    raw = g.canonical(value)
    result = assembly.build(approval_raw=raw, observation_raw=observed_raw,
        ordinary_records=ordinary_records, native_records=native_records,
        cold=parent["context"]["cold"], coordinator=parent["observed"], **clocks)
    bounds.append(result)
    return raw, {"deadline": min(item["deadline"] for item in bounds),
        "epochLimit": min(item["epochLimit"] for item in bounds if item.get("epochLimit") is not None)}


def compose(selected, selection, *, prior, observations, execution_configuration,
            boot, now_boottime_ns, now_unix_ns):
    """Return only an unsigned candidate, with any narrower existing limits."""
    _selected(selected)
    p.fields(selection, selection_fields(selected))
    p.require(type(prior) is dict and type(observations) is dict
        and execution_configuration["apiVersion"] == wire.HANDOFF_CONFIGURATION_API)
    name = selected.name
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    mono = dict(boot=boot, now_boottime_ns=now_boottime_ns)
    context = {"deadline": None, "epochLimit": None}
    if name in ("parent-start", "ordinary-prepare", "endpoints-prepare"):
        parent = _parent(prior, observations, execution_configuration, mono, before_start=name == "parent-start")
        context = {"deadline": parent["context"]["deadline"], "epochLimit": None}
        pins = {"parentConfigurationSha256": p.sha(parent["configuration_raw"]),
            "parentPrecreationSha256": p.sha(parent["precreation_raw"])}
        if name == "parent-start":
            raw = g.canonical({"apiVersion": parent_control.CONTROL_API,
                "controllerExecutableSha256": p.digest(selection["controllerExecutableSha256"]),
                "configurationSha256": pins["parentConfigurationSha256"],
                "precreationSha256": pins["parentPrecreationSha256"]})
            parent_control._control(raw)
        elif name == "ordinary-prepare":
            launch_raw = _original(selection["launchOriginal"], 65536)
            ordinary_control._launch(launch_raw, parent["context"]["window"])
            raw = g.canonical({"apiVersion": ordinary_control.CONTROL_API,
                "launchConfigurationSha256": p.sha(launch_raw), **pins})
            ordinary_control._control(raw)
        else:
            configuration_raw = _original(selection["configurationOriginal"], jobs.delivery.endpoints.MAX_WIRE)
            configured = jobs.delivery.endpoints.configuration(configuration_raw)
            p.require(all(configured[field] == digest for field, digest in pins.items()))
            control = parent_control._control(_record(prior, "parent-start", "input"))
            p.require(control["configurationSha256"] == pins["parentConfigurationSha256"]
                and control["precreationSha256"] == pins["parentPrecreationSha256"])
            raw = g.canonical({"apiVersion": jobs.delivery.endpoints.CONTROL_API,
                "configurationSha256": p.sha(configuration_raw),
                "controllerExecutableSha256": control["controllerExecutableSha256"]})
            endpoint_control.control(raw)
    elif name == "initialize-retrieval-store":
        binding_input = _record(prior, "cold-binding", "input")
        result = jobs.binding.prepare(binding_input, expected_input_sha256=p.sha(binding_input), **clocks)
        p.require(result == _record(prior, "cold-binding"))
        value = jobs.binding.result_document(result)
        raw = _original(value["proofScopeOriginal"], 16384)
        context = {"deadline": p.ns(value["deadlineBoottimeNs"]), "epochLimit": value["expiresAtUnixNanos"]}
    elif name.startswith("install-launch-"):
        raw = p.canonical({"apiVersion": launch_install.API, "role": selected.role,
            "launchInputOriginal": _record(prior, "native-launch-" + selected.role, "input").decode("ascii"),
            "bundleOriginal": _record(prior, "native-launch-" + selected.role).decode("ascii")})
        wire.native_install(raw, selected.role, prior)
        context = launch_install.prepare_input(selected.role, raw, **clocks)
    elif name == "coordinator-assemble":
        raw, context = _assemble(selection, prior, observations, execution_configuration, clocks)
    else:
        if name == "install-precreation" or name.startswith("install-ordinary-"):
            context = jobs.publication_plan(name, prior, observations, **clocks)
        raw = g.canonical({"apiVersion": wire.ACTION_API, "action": name})
        wire.owner_action(raw, name)
    deadline, expiry = context.get("deadline"), context.get("epochLimit")
    p.require(0 < len(raw) <= selected.maximum and (deadline is None or now_boottime_ns < deadline)
        and (expiry is None or now_unix_ns < expiry))
    return {"inputOriginal": raw, "deadline": deadline, "epochLimit": expiry}
