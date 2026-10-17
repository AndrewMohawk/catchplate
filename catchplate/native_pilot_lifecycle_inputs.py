"""Compile candidate lifecycle inputs from selected originals and observations.

These pure functions neither approve their output nor establish provenance for
the caller's policy/key selections. The independent provider must authorize the
exact returned bytes before transferring protected originals with ApprovalPeer.
The authenticated transport and retained lifecycle perform the actual process,
installed-runtime and descriptor checks. No owner, approval, signature, key or
file is created here, and no ambient clock can renew a supplied original limit.
"""
from __future__ import annotations

import copy
import json

from scripts import native_pilot_runtime_artifacts as artifacts
from catchplate import native_pilot_adopted_intake as intake
from catchplate import native_pilot_adopted_supervisor_policy as policy
from catchplate import native_pilot_genesis_rendezvous_profile as rendezvous_profile
from catchplate import native_pilot_interactive as interactive
from catchplate import native_pilot_measured_configuration as measured
from catchplate import native_pilot_window_authority as window_authority
from catchplate import native_shadow_driver_bootstrap as driver

p = policy.p
ORIGINALS = ("policy", "recipe", "intake_configuration", "conductor_inventory", "authority_inventory")
_INVENTORY_FIELDS = ("apiVersion", "source", "target", "command", "records", "recordsSha256", "counts", "limits",
    "intendedInstalledOwnership", "exportOwnership", "releaseAuthority", "liveReady", "launchPrepared",
    "dynamicLoaderClosureVerified", "boundary")
_BOOTSTRAP_FIELDS = ("control", "configuration", "window", "deliveryConfiguration")


def _document(raw, maximum, fields=None):
    p.require(type(raw) is bytes)
    value = p.document(raw, maximum)
    p.require(p.canonical(value) == raw)
    return value if fields is None else p.fields(value, fields)


def _original(text, maximum):
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= maximum)
    return text.encode("ascii")


def _clocks(boot, now_boottime_ns, now_unix_ns):
    p.require(type(boot) is tuple and len(boot) == 3)
    p.require(p.decoded(boot[0], size=16) != bytes(16))
    p.integer(boot[1], minimum=0, maximum=p.MAX_I64)
    p.integer(boot[2], maximum=p.MAX_I64)
    p.integer(now_boottime_ns, maximum=p.MAX_U64)
    p.integer(now_unix_ns, maximum=p.MAX_I64)


def _inventory(raw, role):
    """Public package association only; never installed-runtime admission."""
    fields = _INVENTORY_FIELDS + (() if role == "conductor" else ("requiredArguments",))
    # Real package inventories have thousands of records. Use their existing
    # bounded artifact codec, not the signed-envelope 16,384-node codec.
    p.require(type(raw) is bytes and 0 < len(raw) <= artifacts.MAX_MANIFEST_BYTES)
    value = p.fields(json.loads(raw.decode("ascii"), object_pairs_hook=p._pairs,
        parse_float=p._reject, parse_constant=p._reject), fields)
    p.require(artifacts._canonical(value) == raw)
    api, target, command = {
        "conductor": (artifacts.API_VERSION, "native-pilot-conductor-artifact", artifacts.COMMAND),
        "authority": (artifacts.AUTHORITY_API_VERSION, artifacts.AUTHORITY_TARGET, artifacts.AUTHORITY_COMMAND),
        "supervisor": (artifacts.SUPERVISOR_API_VERSION, artifacts.SUPERVISOR_TARGET, artifacts.SUPERVISOR_COMMAND),
    }[role]
    p.require(value["apiVersion"] == api and value["target"] == target and value["command"] == command)
    source = artifacts._source(p.fields(value["source"], artifacts.SOURCE_FIELDS))
    p.require(all(value[name] is False for name in
        ("releaseAuthority", "liveReady", "launchPrepared", "dynamicLoaderClosureVerified")))
    p.require(type(value["records"]) is list and 0 < len(value["records"]) <= artifacts.MAX_ENTRIES
        and p.sha(artifacts._canonical(value["records"])) == p.digest(value["recordsSha256"]))
    if role == "supervisor":
        p.require(p.canonical(value["requiredArguments"]) == p.canonical(artifacts.SUPERVISOR_REQUIRED_ARGUMENTS))
    elif role == "authority":
        p.require(value["requiredArguments"] == {
            "runtimeInventory": ["--runtime-inventory-fd", "--runtime-inventory-sha256"],
            "authorityKeys": "--authority-key PURPOSE=FD repeated for the exact source-selected KEY_PURPOSES",
            "inventoryKind": artifacts.API_VERSION, "conductorInventoryDerived": False})
    return source


def _driver_bootstrap(supplied, *, boot, now):
    p.fields(supplied, _BOOTSTRAP_FIELDS)
    limits = {"control": 4096, "configuration": 65536, "window": 32768, "deliveryConfiguration": 65536}
    raw = {name: _original(supplied[name], limits[name]) for name in _BOOTSTRAP_FIELDS}
    config = window_authority.validate_configuration(raw["configuration"])
    window_authority.validate_delivery(config, raw["deliveryConfiguration"])
    control = _document(raw["control"], limits["control"],
        ("apiVersion", "supervisorExecutableSha256", "configurationSha256", "windowSha256"))
    p.require(control["apiVersion"] == "catchplate.nativeShadowDriverBootstrapControl/v1"
        and control["configurationSha256"] == p.sha(raw["configuration"])
        and control["windowSha256"] == p.sha(raw["window"]))
    p.digest(control["supervisorExecutableSha256"])
    signed = _document(raw["window"], limits["window"], ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "catchplate.nativeShadowDriverBootstrapWindow/v1")
    window_authority.validate_window(signed["payload"], raw["configuration"], config, boot=boot, now=now)
    driver._key(config["bootstrapAuthority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
        driver.WINDOW_DOMAIN + p.canonical(signed["payload"]))
    return config, signed["payload"]


def _sender(pending):
    p.fields(pending, ("senderRequestOriginal", "listenerConfigurationOriginal"))
    sender_raw = _original(pending["senderRequestOriginal"], rendezvous_profile.MAX_SENDER)
    listener_raw = _original(pending["listenerConfigurationOriginal"], rendezvous_profile.MAX_CONFIGURATION)
    listener = rendezvous_profile._configuration(listener_raw)
    sender = rendezvous_profile._document(sender_raw, rendezvous_profile.MAX_SENDER,
        rendezvous_profile.SENDER_REQUEST_FIELDS)
    observed_raw = _original(sender["listenerOriginal"], rendezvous_profile.MAX_SENDER)
    observed = rendezvous_profile._document(observed_raw, rendezvous_profile.MAX_SENDER,
        rendezvous_profile.SENDER_FIELDS)
    p.require(sender["apiVersion"] == rendezvous_profile.SENDER_REQUEST_API
        and type(sender["sequence"]) is int and sender["sequence"] == 0
        and sender["configurationSha256"] == p.sha(listener_raw)
        and sender["listenerSha256"] == p.sha(observed_raw)
        and sender["deadlineBoottimeNs"] == listener["window"]["startupDeadlineBoottimeNs"]
        and type(sender["expiresAtUnixNanos"]) is int
        and sender["expiresAtUnixNanos"] == listener["expiresAtUnixNanos"]
        and observed["apiVersion"] == rendezvous_profile.SENDER_API
        and observed["configurationSha256"] == sender["configurationSha256"]
        and observed["endpoint"] == rendezvous_profile.ENDPOINT)
    for name in rendezvous_profile.wire.endpoints.WINDOW[:3]:
        p.require(type(observed[name]) is type(listener["window"][name])
            and observed[name] == listener["window"][name])
    rendezvous_profile._socket(observed["socket"], named=True)
    identity = {"pid": p.integer(observed["processId"], minimum=2, maximum=(1 << 31) - 1),
        "uid": 0, "gid": 0, "startTimeTicks": p.integer(observed["processStartTimeTicks"], maximum=p.MAX_I64)}
    return listener, identity


def bootstrap(pending, *, recipe_original, recipe_sha256, supervisor_inventory_original,
              supervisor_inventory_sha256, conductor_inventory_original, authority_inventory_original,
              key_bindings, policy_selection, issued_at_unix_ns, expires_at_unix_ns,
              boot, now_boottime_ns, now_unix_ns):
    """Return five candidate literal originals, their pins and original bounds.

    ``pending`` is the bootstrap value returned by ApprovalPeer. Recipe and
    supervisor pins, key bindings, policy selection and absolute UNIX bounds
    must be independently selected by the provider; this function cannot attest
    to that provenance. The policy selector is exact existing v1 or v2, never an
    implicit promotion to interactive operation. Runtime inventories and recipe
    are returned byte-for-byte; only intake and its containing policy are built.
    """
    _clocks(boot, now_boottime_ns, now_unix_ns)
    p.require(p.sha(recipe_original) == p.digest(recipe_sha256)
        and p.sha(supervisor_inventory_original) == p.digest(supervisor_inventory_sha256))
    recipe = _document(recipe_original, measured.MAX_RECIPE, measured.SET_FIELDS)
    p.require(recipe["apiVersion"] == measured.ADOPTED_API)
    source = artifacts._source(p.fields(recipe["source"], artifacts.SOURCE_FIELDS))
    for role, raw in (("supervisor", supervisor_inventory_original),
            ("conductor", conductor_inventory_original), ("authority", authority_inventory_original)):
        p.require(_inventory(raw, role) == source)
        if role != "supervisor":
            p.require(recipe[role + "InventorySha256"] == p.sha(raw))
    config, window = _driver_bootstrap(recipe["bootstrapOriginals"], boot=boot, now=now_boottime_ns)
    measured._production(recipe["production"])
    assignment, _, _ = measured._assignment(recipe, now_unix_ns)
    manifest_raw = _original(recipe["closureManifestOriginal"], measured.closure.MAX_BYTES)
    manifest = _document(manifest_raw, measured.closure.MAX_BYTES, measured.closure.MANIFEST_FIELDS)
    p.require(manifest["apiVersion"] == "catchplate.nativeCustodyExecutionClosure/v2"
        and manifest["profile"] == measured.closure.PROFILE)
    measured._closure_set(recipe, assignment, manifest)
    listener, sender = _sender(pending)
    cold_window = listener["window"]
    p.require(tuple(cold_window[name] for name in rendezvous_profile.wire.endpoints.WINDOW[:3]) == boot)
    issued = max(p.ns(value["issuedAtBoottimeNs"]) for value in (window, cold_window))
    startup = min(p.ns(value["startupDeadlineBoottimeNs"]) for value in (window, cold_window))
    lifetime = min(p.ns(value["lifetimeDeadlineBoottimeNs"]) for value in (window, cold_window))
    reserve = max(config["lifecycle"]["cleanupReserveNanos"], rendezvous_profile.wire.RESERVE)
    trust = measured.launch.shape("native-bridge-trust", _original(recipe["trustOriginal"], 1024 * 1024))
    epoch_issue = max(p.integer(issued_at_unix_ns), trust["issuedAtUnixNanos"], assignment["payload"]["issuedAtUnixNanos"])
    expiry = min(p.integer(expires_at_unix_ns), listener["expiresAtUnixNanos"], trust["expiresAtUnixNanos"],
        assignment["payload"]["expiresAtUnixNanos"], trust["checkpoint"]["asOfUnixNanos"] + 300_000_000_000,
        trust["assignmentKey"]["notAfterUnixNanos"], trust["timeKey"]["notAfterUnixNanos"],
        *(row["key"]["notAfterUnixNanos"] for row in trust["roleKeys"]))
    deadline = min(startup, lifetime - reserve)
    p.require(issued <= now_boottime_ns < deadline and epoch_issue <= now_unix_ns < expiry)
    intake_value = {"apiVersion": intake.API, "purpose": intake.PURPOSE, "sender": sender,
        **{name: cold_window[name] for name in rendezvous_profile.wire.endpoints.WINDOW[:3]},
        "issuedAtBoottimeNs": str(issued), "startupDeadlineBoottimeNs": str(startup),
        "lifetimeDeadlineBoottimeNs": str(lifetime), "issuedAtUnixNanos": epoch_issue, "expiresAtUnixNanos": expiry}
    intake_raw = p.canonical(intake_value)
    intake.validate_configuration(intake_raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(key_bindings, policy.profile.KEY_PURPOSES)
    for digest in key_bindings.values():
        p.digest(digest)
    selected_key = config["lifecycle"]["constructedAdmissionAuthority"]
    p.require(key_bindings["driver-bootstrap"] == key_bindings["driver-constructed"]
        == p.sha(p.decoded(selected_key["publicKeyBase64url"], size=32))
        and key_bindings["driver-scope"] == config["phaseTwoAuthority"]["keyId"])
    p.require(type(policy_selection) is dict)
    interactive_selected = policy_selection.get("apiVersion") == policy.INTERACTIVE_API
    p.fields(policy_selection, ("apiVersion", "purpose") + (("interactive",) if interactive_selected else ()))
    p.require(policy_selection["apiVersion"] == (policy.INTERACTIVE_API if interactive_selected else policy.API)
        and policy_selection["purpose"] == (policy.INTERACTIVE_PURPOSE if interactive_selected else policy.PURPOSE))
    if interactive_selected:
        interval = interactive.validate_policy(policy_selection["interactive"])
        p.require(now_boottime_ns < interval["stopAtBoottimeNanos"] < lifetime - reserve
            and now_unix_ns < interval["expiresAtUnixNanos"] <= expiry
            and interval["stopAtBoottimeNanos"] - now_boottime_ns
                < interval["expiresAtUnixNanos"] - now_unix_ns)
    policy_raw = p.canonical({**copy.deepcopy(policy_selection), "source": source,
        **{name: recipe[name] for name in ("conductorInventorySha256", "authorityInventorySha256", "bootstrapOriginals")},
        "catalogueSha256": p.sha(policy.catalogue_original()), "keyBindings": copy.deepcopy(key_bindings),
        "measuredRecipeSha256": recipe_sha256, "intakeConfigurationOriginal": intake_raw.decode("ascii"),
        "intakeConfigurationSha256": p.sha(intake_raw)})
    policy.shape(policy_raw)
    originals = dict(zip(ORIGINALS, (policy_raw, recipe_original, intake_raw,
        conductor_inventory_original, authority_inventory_original), strict=True))
    return {"originals": originals, "pins": {name: p.sha(raw) for name, raw in originals.items()},
        "deadline": deadline, "epochLimit": expiry}


def rendezvous(request_original, *, expected_request_sha256, expected_receiver,
               boot, now_boottime_ns, now_unix_ns):
    """Compile Execution/v2 for an independently selected exact receiver.

    The independent decision must pin the entire request and its PID/start/
    credentials. This is not an approval output or proof of process ownership;
    the later listener promotes only its actual already-observed socket.
    """
    _clocks(boot, now_boottime_ns, now_unix_ns)
    p.require(p.sha(request_original) == p.digest(expected_request_sha256))
    ticket = rendezvous_profile.verify_request(request_original)
    p.fields(expected_receiver, ("pid", "uid", "gid", "startTimeTicks"))
    receiver = _document(_original(ticket["receiverOriginal"], rendezvous_profile.MAX_RECEIVER),
        rendezvous_profile.MAX_RECEIVER)["receiver"]
    p.require(p.canonical(expected_receiver) == p.canonical(receiver))
    configuration = rendezvous_profile._configuration(ticket["configurationOriginal"].encode("ascii"))
    raw = p.canonical({**configuration, "apiVersion": rendezvous_profile.wire.HANDOFF_CONFIGURATION_API,
        "coreHandoff": {"peerPid": receiver["pid"], "peerUid": receiver["uid"], "peerGid": receiver["gid"]}})
    rendezvous_profile.execution(raw, request_original, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    deadline = min(p.ns(configuration["window"]["startupDeadlineBoottimeNs"]),
        p.ns(configuration["window"]["lifetimeDeadlineBoottimeNs"]) - rendezvous_profile.wire.RESERVE)
    return {"input_original": raw, "input_sha256": p.sha(raw),
        "deadline": deadline, "epochLimit": configuration["expiresAtUnixNanos"]}
