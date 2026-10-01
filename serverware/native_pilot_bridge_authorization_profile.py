"""Pure fixed bridge authorizations from complete retained public originals.

Independent policy selects validity, local roles, challenge and verifier port.
Actual C9, assignment, trust and closure originals supply every other field.
These checks establish signatures and byte associations, not live ownership,
independent approval, provisioned ciphertext, a verifier or native readiness.
"""
from __future__ import annotations

from serverware import native_pilot_assignment as assignment
from serverware import native_pilot_bridge_authority as authority
from serverware import native_pilot_bridge_commissioning_policy as policy
from serverware import native_pilot_bridge_key_profile as keys
from serverware import native_pilot_bridge_runtime as runtime
from serverware import native_pilot_closure_authority as closure

p = keys.p
OPERATIONS = ("role-keys", "admission", "closure", "encrypted-delivery", "verifier-transport")
PAIR_FIELDS = authority.PAIR_FIELDS
MAX_INPUT = keys.MAX_INPUT
MAX_OUTPUT = closure.MAX_BYTES
_SETTINGS = {"closure": "closure", "encrypted-delivery": "encryptedDelivery", "verifier-transport": "verifierTransport"}


def _bytes(value, maximum):
    p.require(type(value) is bytes and 0 < len(value) <= maximum)
    return value


def _result(raw):
    return {"original": raw.decode("ascii"), "sha256": p.sha(raw)}


def _selection(fragment, delivery_input_raw):
    source = keys.c9.input_document(_bytes(delivery_input_raw, keys.c9.MAX_BRIDGE_INPUT))
    p.require(source["role"] == "bridge")
    _, config = keys.c9._original(source["ownerConfigurationOriginal"], 65536)
    cold_raw, _ = keys.c9._original(source["configurationOriginal"], 65536)
    _, operational = runtime.original(source["runtimeOriginal"])
    p.require(runtime.version(operational) == 11)
    selected = policy.validate_policy(fragment, bootstrap_configuration=config, cold_original=cold_raw)
    _, payload = keys.c9._original(source["payloadOriginal"], keys.delivery.MAX_DELIVERY)
    keys.c9._same(payload["credentials"], selected["deliveryCredentials"])
    return selected, source


def _pair_context(records):
    return {"roleKeyInputOriginal": records["role-keys"]["inputOriginal"].decode("ascii"),
        "roleKeyOriginal": records["role-keys"]["authorizationOriginal"].decode("ascii"),
        "admissionInputOriginal": records["admission"]["inputOriginal"].decode("ascii"),
        "admissionOriginal": records["admission"]["authorizationOriginal"].decode("ascii")}


def _closure_input(selected, source, common, records, contexts):
    prepared = contexts["admission"]
    role = contexts["role-keys"]["payload"]
    recipe = common["recipe_originals"]
    set_raw, _ = keys.c9._original(recipe["closureSetOriginal"], closure.MAX_BYTES)
    _, envelope = keys.c9._original(recipe["assignmentOriginal"], 4 * 1024 * 1024)
    leaf = assignment.closure_binding(envelope, set_raw, "bridge")
    checkpoint, supervisor = prepared["trustCheckpoint"], prepared["authorityKeys"][-1]
    payload = {"apiVersion": "serverware.nativeCustodyClosureAssignment/v3",
        "purpose": "shadow-custody-closure-set-member", "profile": closure.SET_PROFILE,
        **{name: role[name] for name in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision", "guest")},
        "manifestSha256": prepared["manifest"]["manifestSha256"],
        "trustCheckpointId": checkpoint["checkpointId"], "revocationGeneration": checkpoint["revocationGeneration"],
        "revocationRootSha256": checkpoint["revocationRootSha256"], **selected["launchAuthorizations"]["closure"],
        "signingKeyId": supervisor["keyId"], "signingKeySpkiSha256": supervisor["keySpkiSha256"],
        "guestRole": "bridge", **{name: leaf[name] for name in ("setRootSha256", "seccompSetRootSha256", "leafSha256")}}
    return {"apiVersion": "serverware.nativePilotClosureAuthorityInput/v2", "guestRole": "bridge",
        "controlOriginal": common["control_original"].decode("ascii"),
        "configurationOriginal": source["ownerConfigurationOriginal"], "windowOriginal": source["windowOriginal"],
        "observationOriginal": source["observationOriginal"], "deliveryConfigurationOriginal": source["configurationOriginal"],
        "deliveryOriginal": common["delivery_raw"].decode("ascii"), "runtimeOriginal": source["runtimeOriginal"],
        **recipe, "manifestOriginal": p.canonical(prepared["manifest"]).decode("ascii"),
        "payloadOriginal": p.canonical(payload).decode("ascii")}


def _input(operation, selected, source, common, records, contexts):
    if operation in keys.OPERATIONS:
        value = {"apiVersion": keys.API, "operation": operation,
            "controlOriginal": _bytes(common["control_original"], 4096).decode("ascii"),
            "deliveryInputOriginal": common["delivery_input_raw"].decode("ascii"),
            "deliveryOriginal": _bytes(common["delivery_raw"], keys.delivery.MAX_DELIVERY).decode("ascii"),
            "recipeOriginals": common["recipe_originals"], "measured": common["measured"],
            "policy": selected["keyAuthorization"]}
        if operation == "admission":
            value["roleKeyOriginal"] = records["role-keys"]["authorizationOriginal"].decode("ascii")
    elif operation == "closure":
        value = _closure_input(selected, source, common, records, contexts)
    else:
        value = {"apiVersion": authority.API, "operation": operation, **_pair_context(records),
            **selected["launchAuthorizations"][_SETTINGS[operation]]}
    raw = p.canonical(value)
    _bytes(raw, closure.MAX_BRIDGE_INPUT if operation == "closure" else MAX_INPUT)
    return raw


def prepare_input(operation, input_raw, *, boot, now_boottime_ns, now_unix_ns):
    """Use the actual existing producer validation, including original clocks."""
    p.require(type(operation) is str and operation in OPERATIONS)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    if operation == "closure":
        prepared = closure.prepare_input(input_raw, **clocks)
        p.require(prepared["payload"].get("guestRole") == "bridge")
    else:
        prepared = authority.prepare_input(operation, input_raw, **clocks)
    # Closure's producer ceiling may exceed this particular signed decision.
    # Retained consumers must keep the smaller original payload expiry too.
    prepared["epochLimit"] = min(prepared["epochLimit"], prepared["payload"]["expiresAtUnixNanos"])
    p.require(now_boottime_ns < prepared["deadline"] and now_unix_ns < prepared["epochLimit"])
    return prepared


def checked_result(operation, input_raw, result, *, boot, now_boottime_ns, now_unix_ns):
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    prepare_input(operation, input_raw, **clocks)
    return (closure.checked_result(input_raw, result, **clocks) if operation == "closure"
        else authority.checked_result(operation, input_raw, result, **clocks))


def _chain(names, records, *, common, clocks):
    p.fields(records, names)
    selected, source = _selection(common["fragment"], common["delivery_input_raw"])
    checked, contexts = {}, {}
    for operation in names:
        row = p.fields(records[operation], ("inputOriginal", "authorizationOriginal"))
        raw = _input(operation, selected, source, common, checked, contexts)
        p.require(_bytes(row["inputOriginal"], MAX_INPUT) == raw)
        maximum = closure.MAX_BYTES if operation == "closure" else keys.MAX_OUTPUT
        output = _bytes(row["authorizationOriginal"], maximum)
        contexts[operation] = prepare_input(operation, raw, **clocks)
        checked_result(operation, raw, _result(output), **clocks)
        checked[operation] = {"inputOriginal": raw, "authorizationOriginal": output}
    return selected, source, checked, contexts


def _bounds(contexts, clocks):
    values = tuple(contexts.values())
    p.require(values)
    window = values[0]["window"]
    for value in values[1:]:
        keys.c9._same(value["window"], window)
    deadline = min(value["deadline"] for value in values)
    epoch = min(value["epochLimit"] for value in values)
    p.require(clocks["now_boottime_ns"] < deadline and clocks["now_unix_ns"] < epoch)
    return window, deadline, epoch


def prepare(operation, *, fragment, control_original, delivery_input_raw, delivery_raw, recipe_originals,
            measured, prior_authorizations, boot, now_boottime_ns, now_unix_ns):
    p.require(type(operation) is str and operation in OPERATIONS)
    common = dict(fragment=fragment, control_original=control_original, delivery_input_raw=delivery_input_raw,
        delivery_raw=delivery_raw, recipe_originals=recipe_originals, measured=measured)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    selected, source, records, contexts = _chain(OPERATIONS[:OPERATIONS.index(operation)],
        prior_authorizations, common=common, clocks=clocks)
    raw = _input(operation, selected, source, common, records, contexts)
    contexts[operation] = prepare_input(operation, raw, **clocks)
    window, deadline, epoch = _bounds(contexts, clocks)
    return {"inputOriginal": raw, "window": window, "deadline": deadline, "epochLimit": epoch}


def build(operation, **kwargs):
    return prepare(operation, **kwargs)["inputOriginal"]
