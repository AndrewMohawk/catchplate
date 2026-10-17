"""Closed foundation/parent candidate inputs for the existing cold catalogue.

Selected trust, assignment policy and cold window remain independent decisions.
Only literal predecessor roots, observed originals and the original execution
window are filled in here. The dispatcher performs the existing public producer
validation; this module neither signs nor supplies an approval or live owner.
"""
from __future__ import annotations

import copy

from catchplate import native_pilot_genesis_jobs as jobs

p, g = jobs.p, jobs.g
FAMILIES = ("closure-set", "assignment", "cold-binding", "parent")


def selection_fields(selected):
    p.require(type(selected) is jobs.Job and jobs.BY_NAME.get(selected.name) == selected
        and selected.family in FAMILIES)
    if selected.family == "parent":
        return ("configurationOriginal", "deliveryConfigurationOriginal") if selected.operation == "precreation" else ()
    return {"closure-set": ("members",), "assignment": ("trustOriginal", "payload"),
        "cold-binding": ("commissioningIdSha256", "initialPublicationRevision", "window")}[selected.family]


def _text(raw):
    p.require(type(raw) is bytes and 0 < len(raw) <= jobs.MAX_OUTPUT)
    return raw.decode("ascii")


def _parent(selected, selection, prior, observations, configuration):
    if selected.operation == "precreation":
        original = jobs._raw(selection["configurationOriginal"])
        delivery = jobs._raw(selection["deliveryConfigurationOriginal"])
        config, _ = jobs.parent.validate_configuration(original, delivery)
        payload = {"configurationSha256": p.sha(original),
            "authorityKeyId": config["precreationAuthority"]["keyId"], **copy.deepcopy(configuration["window"])}
        return {"apiVersion": jobs.parent.INPUT_API, "operation": "precreation", **selection,
            "payloadOriginal": _text(g.canonical(payload))}
    p.require(selected.operation == "release")
    originals = {field: _text(jobs._observed(observations, name)) for field, name in (
        ("configurationOriginal", "parent.configuration"), ("deliveryConfigurationOriginal", "parent.cold"),
        ("precreationOriginal", "parent.precreation"), ("observationOriginal", "parent.observation"))}
    config = g.document(jobs._raw(originals["configurationOriginal"]), jobs.parent.MAX_WIRE)
    launch = p.document(jobs._record(prior, "native-launch-" + jobs.COORDINATOR), jobs.launch.MAX_OUTPUT)
    delivery = jobs.delivery.input_document(jobs._record(prior, "native-delivery-" + jobs.COORDINATOR, "input"))
    payload = {"configurationSha256": p.sha(jobs._raw(originals["configurationOriginal"])),
        "precreationSha256": p.sha(jobs._raw(originals["precreationOriginal"])),
        "observationSha256": p.sha(jobs._raw(originals["observationOriginal"])),
        "invocationId": configuration["window"]["invocationId"],
        "launch": copy.deepcopy(launch["launchPin"]), "image": copy.deepcopy(delivery["image"]),
        "signingKeyId": config["releaseAuthority"]["keyId"]}
    return {"apiVersion": jobs.parent.INPUT_API, "operation": "release", **originals,
        "payloadOriginal": _text(g.canonical(payload)), "launchOriginal": launch["launchOriginal"],
        "closureOriginal": _text(jobs._record(prior, "native-closure-" + jobs.COORDINATOR))}


def compose(selected, selection, *, prior, observations, execution_configuration):
    """Compose only source-owned fields; never overwrite selected policy pins."""
    p.fields(selection, selection_fields(selected))
    if selected.family == "closure-set":
        value = {"apiVersion": "catchplate.nativePilotClosureSetPreparation/v3",
            "setApiVersion": jobs.sets.GENESIS_BOOTSTRAP_API, "members": copy.deepcopy(selection["members"])}
    elif selected.family == "assignment":
        payload = copy.deepcopy(p.fields(selection["payload"], jobs.assignment.NATIVE_FIELDS))
        closure_raw = jobs._record(prior, "closure-set")
        closure = jobs.sets.validate(closure_raw, api_version=jobs.sets.GENESIS_BOOTSTRAP_API)
        payload["nativeClosureSet"] = {name: closure[name] for name in ("setRootSha256", "seccompSetRootSha256")}
        trust_raw = jobs._raw(selection["trustOriginal"])
        value = {"apiVersion": jobs.assignment.GENESIS_BOOTSTRAP_INPUT_API,
            "setApiVersion": jobs.sets.GENESIS_BOOTSTRAP_API, "trustOriginal": _text(trust_raw),
            "trustSha256": p.sha(trust_raw), "payloadOriginal": _text(g.canonical(payload)),
            "closureSetOriginal": _text(closure_raw)}
    elif selected.family == "cold-binding":
        assigned, selected_set = jobs.assignment.input_document(jobs._record(prior, "assignment", "input"))
        p.require(selected_set == jobs.sets.GENESIS_BOOTSTRAP_API)
        value = {"apiVersion": jobs.binding.API, **copy.deepcopy(selection),
            **{name: assigned[name] for name in ("trustOriginal", "trustSha256")},
            "assignmentOriginal": _text(jobs._record(prior, "assignment")),
            "closureSetOriginal": _text(jobs._record(prior, "closure-set"))}
    else:
        value = _parent(selected, selection, prior, observations, execution_configuration)
    return g.canonical(value)
