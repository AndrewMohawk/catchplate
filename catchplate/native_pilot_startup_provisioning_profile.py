"""Explicit delegation for three late startup peer projections, not ownership.

The real provisioner retains separately approved protected originals and the
actual parent's observation. Only the three named peer fields and consequent
source/admission hashes are derived. All selections, source bytes and original
clock fields remain independent inputs. No private key, currentness decision,
registry initialization, arbitrary template or command is supplied here.
"""
from __future__ import annotations

import copy
import json

from catchplate import native_pilot_startup_profile as startup

p, policy, decisions = startup.p, startup.policy, startup.decisions
API = "catchplate.nativePilotStartupProvisioningDelegation/v1"
PURPOSE = "project-observed-startup-peers-into-fixed-public-inputs"
# The protected public-input reader accepts at most 32 MiB. Wrapper metadata
# consumes this new delegation's budget; the provider's own cap is unchanged.
MAX_DELEGATION = policy.MAX_POLICY
PROVIDER_FIELDS = tuple(name for name in policy.FIELDS if name not in ("lifecyclePeer", "currentHeadPeer"))
DECISION_FIELDS = tuple(name for name in decisions.FIELDS if name != "providerPeer")
FIELDS = ("apiVersion", "purpose", "configurationSha256", "supervisorInventorySha256",
    "measuredRecipeSha256", "conductorInventorySha256", "authorityInventorySha256",
    "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos",
    "providerPolicy", "decisionConfiguration")
FIXED = ("configuration", "supervisor-inventory", "recipe", "conductor-inventory", "authority-inventory")
PINS = dict(zip(FIXED, ("configurationSha256", "supervisorInventorySha256", "measuredRecipeSha256",
    "conductorInventorySha256", "authorityInventorySha256"), strict=True))
LIMITS = {"configuration": startup.MAX_CONFIGURATION,
    "supervisor-inventory": policy.lifecycle.artifacts.MAX_MANIFEST_BYTES,
    **{name: startup.SOURCE_LIMITS[name] for name in FIXED[2:]}}
CONTEXT_FIELDS = ("value", "delegationOriginal", "fixedOriginals", "deadline", "epochLimit")


def canonical(value):
    """Count wrapper metadata in the fixed bound; keep the provider codec."""
    p.fields(value, FIELDS)
    p.fields(value["providerPolicy"], PROVIDER_FIELDS)
    p.fields(value["decisionConfiguration"], DECISION_FIELDS)
    policy.canonical(value["providerPolicy"])
    remainder = {name: value[name] for name in FIELDS if name != "providerPolicy"}
    p.require(len(p.canonical(remainder)) <= decisions.MAX_CONFIGURATION + 4096)
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")
    p.require(0 < len(raw) <= MAX_DELEGATION)
    return raw


def _delegation(raw):
    p.require(type(raw) is bytes and 0 < len(raw) <= MAX_DELEGATION)
    value = p.fields(json.loads(raw.decode("ascii"), object_pairs_hook=p._pairs,
        parse_float=p._reject, parse_constant=p._reject), FIELDS)
    p.require(canonical(value) == raw and value["apiVersion"] == API and value["purpose"] == PURPOSE)
    for name in PINS.values(): p.digest(value[name])
    p.require(p.ns(value["issuedAtBoottimeNs"]) < p.ns(value["deadlineBoottimeNs"])
        and p.integer(value["issuedAtUnixNanos"]) < p.integer(value["expiresAtUnixNanos"]))
    return value


def _source_limits(value, fixed, *, boot, now_boottime_ns, now_unix_ns):
    """Original waiting limits only; full policy admission follows observation.

    Existing source validators authenticate driver-window and assignment bounds
    without inventing placeholder peer identities for policy.prepare().
    """
    selected = value["providerPolicy"]
    p.require(selected["apiVersion"] == policy.API and selected["purpose"] == policy.PURPOSE
        and selected["catalogueSha256"] == p.sha(policy.catalogue_original()))
    for name in ("supervisorInventorySha256", "measuredRecipeSha256", "conductorInventorySha256",
            "authorityInventorySha256"):
        p.require(selected[name] == value[name])
    lifecycle = policy.lifecycle
    recipe = lifecycle._document(fixed["recipe"], lifecycle.measured.MAX_RECIPE, lifecycle.measured.SET_FIELDS)
    p.require(recipe["apiVersion"] == lifecycle.measured.ADOPTED_API and recipe["source"] == selected["source"])
    for role in ("supervisor", "conductor", "authority"):
        p.require(lifecycle._inventory(fixed[role + "-inventory"], role) == selected["source"])
        if role != "supervisor": p.require(recipe[role + "InventorySha256"] == selected[role + "InventorySha256"])
    listener_raw = lifecycle._original(selected["listenerConfigurationOriginal"], startup.SOURCE_LIMITS["listener-configuration"])
    p.require(p.sha(listener_raw) == p.digest(selected["listenerConfigurationSha256"]))
    listener = lifecycle.rendezvous_profile._configuration(listener_raw)
    window = listener["window"]
    p.require(tuple(window[name] for name in startup.BOOT_FIELDS) == boot)
    config, driver_window = lifecycle._driver_bootstrap(recipe["bootstrapOriginals"], boot=boot, now=now_boottime_ns)
    assignment, _, _ = lifecycle.measured._assignment(recipe, now_unix_ns)
    trust = lifecycle.measured.launch.shape("native-bridge-trust", lifecycle._original(recipe["trustOriginal"], 1024 * 1024))
    lifetime = min(p.ns(item["lifetimeDeadlineBoottimeNs"]) for item in (window, driver_window))
    reserve = max(config["lifecycle"]["cleanupReserveNanos"], lifecycle.interactive.COHORT_REAP_RESERVE_NS)
    startup_limit = min(*(p.ns(item["startupDeadlineBoottimeNs"]) for item in (window, driver_window)), lifetime - reserve)
    issue = max(p.ns(item["issuedAtBoottimeNs"]) for item in (window, driver_window))
    p.require(p.integer(selected["issuedAtUnixNanos"]) < p.integer(selected["expiresAtUnixNanos"])
        <= listener["expiresAtUnixNanos"])
    epoch_issue = max(selected["issuedAtUnixNanos"], trust["issuedAtUnixNanos"], assignment["payload"]["issuedAtUnixNanos"])
    expiry = min(selected["expiresAtUnixNanos"], trust["expiresAtUnixNanos"], assignment["payload"]["expiresAtUnixNanos"],
        trust["checkpoint"]["asOfUnixNanos"] + 300_000_000_000, trust["assignmentKey"]["notAfterUnixNanos"],
        trust["timeKey"]["notAfterUnixNanos"], *(row["key"]["notAfterUnixNanos"] for row in trust["roleKeys"]))
    p.require(issue <= now_boottime_ns < startup_limit and epoch_issue <= now_unix_ns < expiry)
    return listener, lifetime, startup_limit, expiry


def prepare(delegation_raw, *, configuration_original, recipe_original, conductor_inventory_original,
            authority_inventory_original, supervisor_inventory_original, boot, now_boottime_ns, now_unix_ns):
    """Check independent pins and pre-observation wait bounds; no decision yet."""
    value = _delegation(delegation_raw)
    fixed = dict(zip(FIXED, (configuration_original, supervisor_inventory_original, recipe_original,
        conductor_inventory_original, authority_inventory_original), strict=True))
    for name, original in fixed.items():
        p.require(type(original) is bytes and 0 < len(original) <= LIMITS[name]
            and p.sha(original) == value[PINS[name]])
    configured = startup.configuration(configuration_original, inventory_sha256=value["supervisorInventorySha256"],
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    config = configured["value"]
    p.require(p.ns(config["issuedAtBoottimeNs"]) <= p.ns(value["issuedAtBoottimeNs"]) <= now_boottime_ns
        < p.ns(value["deadlineBoottimeNs"]) <= configured["deadline"]
        and config["issuedAtUnixNanos"] <= value["issuedAtUnixNanos"] <= now_unix_ns
        < value["expiresAtUnixNanos"] <= configured["epochLimit"])
    decision = value["decisionConfiguration"]
    p.require(decision["apiVersion"] == decisions.API and decision["purpose"] == decisions.PURPOSE
        and decision["supervisorInventorySha256"] == value["supervisorInventorySha256"]
        and tuple(decision[name] for name in startup.BOOT_FIELDS) == boot)
    startup.socket_identity(decision["directory"])
    p.require(decision["directory"] != config["directory"]
        and p.ns(decision["issuedAtBoottimeNs"]) <= now_boottime_ns < p.ns(decision["deadlineBoottimeNs"])
        and p.integer(decision["issuedAtUnixNanos"]) <= now_unix_ns < p.integer(decision["expiresAtUnixNanos"]))
    listener, lifetime, startup_limit, expiry = _source_limits(value, fixed, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    # Resumed roles see their original limits, not the provisioner's wait cap.
    p.require(max(p.ns(listener["window"]["lifetimeDeadlineBoottimeNs"]), lifetime,
        p.ns(decision["deadlineBoottimeNs"])) <= p.ns(value["deadlineBoottimeNs"])
        and max(listener["expiresAtUnixNanos"], expiry, decision["expiresAtUnixNanos"]) <= value["expiresAtUnixNanos"])
    deadline = min(startup_limit, p.ns(value["deadlineBoottimeNs"]), p.ns(decision["deadlineBoottimeNs"]))
    epoch_limit = min(expiry, value["expiresAtUnixNanos"], decision["expiresAtUnixNanos"])
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch_limit)
    return dict(value=copy.deepcopy(value), delegationOriginal=delegation_raw, fixedOriginals=fixed,
        deadline=deadline, epochLimit=epoch_limit)


def compose(context, observation_original, *, boot, now_boottime_ns, now_unix_ns):
    """Produce existing six originals and Admission1 after complete admission."""
    p.fields(context, CONTEXT_FIELDS)
    fixed = p.fields(context["fixedOriginals"], FIXED)
    checked = prepare(context["delegationOriginal"], configuration_original=fixed["configuration"],
        recipe_original=fixed["recipe"], conductor_inventory_original=fixed["conductor-inventory"],
        authority_inventory_original=fixed["authority-inventory"], supervisor_inventory_original=fixed["supervisor-inventory"],
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.require(checked == context)
    observed = startup.observation_value(observation_original, configuration_raw=fixed["configuration"])
    value = checked["value"]
    peer = lambda role: {name: observed["processes"][role][name] for name in policy.PEER_FIELDS}
    provider = copy.deepcopy(value["providerPolicy"])
    provider.update(lifecyclePeer=peer("lifecycle"), currentHeadPeer=peer("decisions"))
    decision = copy.deepcopy(value["decisionConfiguration"])
    decision["providerPeer"] = peer("provider")
    originals = {"listener-configuration": provider["listenerConfigurationOriginal"].encode("ascii"),
        "provider-policy": policy.canonical(provider), "recipe": fixed["recipe"],
        "conductor-inventory": fixed["conductor-inventory"], "authority-inventory": fixed["authority-inventory"],
        "decision-configuration": p.canonical(decision)}
    admission_raw = p.canonical(dict(apiVersion=startup.ADMISSION_API, configurationSha256=p.sha(fixed["configuration"]),
        observationSha256=p.sha(observation_original), sources={name: p.sha(originals[name]) for name in startup.SOURCE_NAMES},
        deadlineBoottimeNs=value["deadlineBoottimeNs"], expiresAtUnixNanos=value["expiresAtUnixNanos"]))
    admitted = startup.admission(admission_raw, configuration_raw=fixed["configuration"], observation_raw=observation_original,
        source_originals=originals, supervisor_inventory_original=fixed["supervisor-inventory"],
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    return dict(originals=originals, admissionOriginal=admission_raw,
        deadline=min(checked["deadline"], admitted["startupDeadline"]), epochLimit=min(checked["epochLimit"], admitted["epochLimit"]))
