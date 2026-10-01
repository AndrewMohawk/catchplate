"""Explicit independent delegation for fixed lifecycle input derivations.

This is a pure decision layer, not a policy file owner or an approval issuer.
The provider must retain an independently provisioned, externally pinned
protected original, authenticate both actual channels and preserve its ordered
transcript. Compiler success alone grants no authority. Eight current-head
decisions are never delegated; their complete protected input and Approval2
must arrive from the separately pinned decision peer for the actual request.
The adopted key bindings become actual bootstrap policy bindings. Cold signer
identities instead remain bound by the authorized complete selections and their
existing producer checks; this policy declares no unobserved cold key custody.

The receiver rule explicitly delegates the observed root receiver to the named
lifecycle peer for this original invocation. It does not prove process lineage:
the genuine lifecycle/listener retain that responsibility and their PIDFDs.
The transcript must additionally join the rendezvous sender to its accepted
bootstrap literal. No templates, arbitrary callbacks or ambient clocks exist.
"""
from __future__ import annotations

import copy
import json

from serverware import native_pilot_adopted_inputs as adopted
from serverware import native_pilot_genesis_inputs as cold
from serverware import native_pilot_lifecycle_inputs as lifecycle

p = lifecycle.p
API = "serverware.nativePilotApprovalDelegationPolicy/v1"
PURPOSE = "independent-fixed-cold-and-adopted-input-derivation"
MAX_POLICY = 32 * 1024 * 1024
MAX_NODES = 524288
DERIVE = "derive-exact-candidate-from-pinned-selection-and-authenticated-transcript"
BOOTSTRAP = "derive-bootstrap-from-pinned-recipe-and-observed-sender"
RENDEZVOUS = "delegate-observed-root-receiver-to-pinned-lifecycle-peer-for-original-invocation"
EXTERNAL_HEAD = "require-fresh-protected-current-head-input-and-approval"
INTERACTIVE_STOP = "derive-selected-interactive-stop-from-observed-origin-handoff"
FIELDS = ("apiVersion", "purpose", "source", "catalogueSha256", "supervisorInventorySha256",
    "conductorInventorySha256", "authorityInventorySha256", "measuredRecipeSha256",
    "listenerConfigurationOriginal", "listenerConfigurationSha256", "issuedAtUnixNanos",
    "expiresAtUnixNanos", "lifecyclePeer", "currentHeadPeer", "keyBindings", "bootstrap",
    "rendezvous", "cold", "adopted")
PEER_FIELDS = ("pid", "uid", "gid", "startTimeTicks")
COLD = cold.CATALOGUE
ADOPTED = adopted.context.CATALOGUE
HEADS = tuple(job.name for _, job in ADOPTED if job.family == "current-head")


def canonical(value):
    """Bounded policy-only codec; unsigned counters never widen signed grants."""
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop(); count += 1
        p.require(depth <= 40 and count <= MAX_NODES)
        if type(item) is dict:
            p.require(all(type(key) is str and key.isascii() for key in item))
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            p.require(item.isascii())
        elif type(item) is int:
            p.require(-(1 << 63) <= item <= p.MAX_U64)
        else:
            p.require(item is None or type(item) is bool)
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")
    p.require(0 < len(raw) <= MAX_POLICY)
    return raw


def catalogue_original():
    """Pin executable source metadata and its exact compiler selection fields."""
    return canonical({"cold": [{"name": job.name, "family": job.family, "role": job.role,
        "operation": job.operation, "key": job.key, "maximum": job.maximum,
        "selectionFields": list(cold.selection_fields(job.name))} for job in COLD],
        "adopted": [{"phase": phase, "name": job.name, "family": job.family, "role": job.role,
            "purpose": job.purpose, "key": job.key, "maximum": job.maximum,
            "selectionFields": list(adopted.selection_fields(job.name))} for phase, job in ADOPTED]})


def _peer(value, *, root):
    p.fields(value, PEER_FIELDS)
    p.integer(value["pid"], minimum=2, maximum=(1 << 31) - 1)
    p.integer(value["startTimeTicks"], maximum=p.MAX_U64)
    for name in ("uid", "gid"):
        p.integer(value[name], minimum=0, maximum=(1 << 32) - 2)
        if root: p.require(value[name] == 0)
    return value


def _policy_selection(value):
    p.require(type(value) is dict)
    interactive = value.get("apiVersion") == lifecycle.policy.INTERACTIVE_API
    p.fields(value, ("apiVersion", "purpose") + (("interactive",) if interactive else ()))
    p.require(value["apiVersion"] == (lifecycle.policy.INTERACTIVE_API if interactive else lifecycle.policy.API)
        and value["purpose"] == (lifecycle.policy.INTERACTIVE_PURPOSE if interactive else lifecycle.policy.PURPOSE))
    if interactive: lifecycle.interactive.validate_policy(value["interactive"])
    return interactive


def shape(raw):
    """Closed static delegation, not proof that a file or peer is independent."""
    p.require(type(raw) is bytes and 0 < len(raw) <= MAX_POLICY)
    value = p.fields(json.loads(raw.decode("ascii"), object_pairs_hook=p._pairs,
        parse_float=p._reject, parse_constant=p._reject), FIELDS)
    p.require(canonical(value) == raw and value["apiVersion"] == API and value["purpose"] == PURPOSE
        and value["catalogueSha256"] == p.sha(catalogue_original()))
    lifecycle.artifacts._source(p.fields(value["source"], lifecycle.artifacts.SOURCE_FIELDS))
    for name in ("supervisorInventorySha256", "conductorInventorySha256", "authorityInventorySha256",
            "measuredRecipeSha256", "listenerConfigurationSha256"):
        p.digest(value[name])
    listener_raw = lifecycle._original(value["listenerConfigurationOriginal"], lifecycle.rendezvous_profile.MAX_CONFIGURATION)
    p.require(p.sha(listener_raw) == value["listenerConfigurationSha256"])
    listener = lifecycle.rendezvous_profile._configuration(listener_raw)
    p.require(p.integer(value["issuedAtUnixNanos"]) < p.integer(value["expiresAtUnixNanos"])
        <= listener["expiresAtUnixNanos"])
    _peer(value["lifecyclePeer"], root=True)
    _peer(value["currentHeadPeer"], root=False)
    p.require(value["lifecyclePeer"]["pid"] != value["currentHeadPeer"]["pid"])
    p.fields(value["keyBindings"], adopted.profile.KEY_PURPOSES)
    for digest in value["keyBindings"].values(): p.digest(digest)
    p.fields(value["bootstrap"], ("rule", "policySelection"))
    p.require(value["bootstrap"]["rule"] == BOOTSTRAP)
    interactive = _policy_selection(value["bootstrap"]["policySelection"])
    p.fields(value["rendezvous"], ("rule",)); p.require(value["rendezvous"]["rule"] == RENDEZVOUS)
    p.require(len(COLD) == 66 and len(ADOPTED) == 176 and len(HEADS) == 8)
    for stage, order, compiler in (("cold", COLD, cold), ("adopted", tuple(job for _, job in ADOPTED), adopted)):
        p.fields(value[stage], tuple(job.name for job in order))
        for job in order:
            row = value[stage][job.name]
            if stage == "adopted" and job.name in HEADS:
                p.fields(row, ("rule",)); p.require(row["rule"] == EXTERNAL_HEAD)
                continue
            p.fields(row, ("rule", "selection"))
            fragment = p.fields(row["selection"], compiler.selection_fields(job.name))
            p.require(len(canonical(fragment)) <= job.maximum)
            if stage == "adopted" and job.family == "stop" and row["rule"] == INTERACTIVE_STOP:
                p.require(interactive)
                action = p.fields(fragment["action"], ("action", "stopAtBoottimeNanos", "expiresAtUnixNanos"))
                p.require(action["action"] == "run-interactive")
                interval = value["bootstrap"]["policySelection"]["interactive"]
                p.require(all(type(action[name]) is int and action[name] == interval[name]
                    for name in lifecycle.interactive.FIELDS[1:]))
            else:
                p.require(row["rule"] == DERIVE)
                if stage == "adopted" and job.family == "stop":
                    p.fields(fragment["action"], ("action",)); p.require(fragment["action"]["action"] == "stop")
    return copy.deepcopy(value)


def prepare(raw, *, recipe_original, supervisor_inventory_original, conductor_inventory_original,
            authority_inventory_original, boot, now_boottime_ns, now_unix_ns):
    """Authenticate public static associations before any delegated decision.

    Returned data is not a retained capability. The provider owns the protected
    policy and these public originals and must check them around every use.
    """
    lifecycle._clocks(boot, now_boottime_ns, now_unix_ns)
    value = shape(raw)
    for field, original in (("measuredRecipeSha256", recipe_original),
            ("supervisorInventorySha256", supervisor_inventory_original),
            ("conductorInventorySha256", conductor_inventory_original),
            ("authorityInventorySha256", authority_inventory_original)):
        p.require(type(original) is bytes and p.sha(original) == value[field])
    recipe = lifecycle._document(recipe_original, lifecycle.measured.MAX_RECIPE, lifecycle.measured.SET_FIELDS)
    p.require(recipe["apiVersion"] == lifecycle.measured.ADOPTED_API and recipe["source"] == value["source"])
    for role, original in (("supervisor", supervisor_inventory_original), ("conductor", conductor_inventory_original),
            ("authority", authority_inventory_original)):
        p.require(lifecycle._inventory(original, role) == value["source"])
        if role != "supervisor": p.require(recipe[role + "InventorySha256"] == value[role + "InventorySha256"])
    config, driver_window = lifecycle._driver_bootstrap(recipe["bootstrapOriginals"], boot=boot, now=now_boottime_ns)
    lifecycle.measured._production(recipe["production"])
    assignment, _, _ = lifecycle.measured._assignment(recipe, now_unix_ns)
    manifest = lifecycle._document(lifecycle._original(recipe["closureManifestOriginal"], lifecycle.measured.closure.MAX_BYTES),
        lifecycle.measured.closure.MAX_BYTES, lifecycle.measured.closure.MANIFEST_FIELDS)
    p.require(manifest["apiVersion"] == "serverware.nativeCustodyExecutionClosure/v2"
        and manifest["profile"] == lifecycle.measured.closure.PROFILE)
    lifecycle.measured._closure_set(recipe, assignment, manifest)
    trust = lifecycle.measured.launch.shape("native-bridge-trust", lifecycle._original(recipe["trustOriginal"], 1024 * 1024))
    listener = lifecycle.rendezvous_profile._configuration(value["listenerConfigurationOriginal"].encode("ascii"))
    window = listener["window"]
    p.require(tuple(window[name] for name in lifecycle.rendezvous_profile.wire.endpoints.WINDOW[:3]) == boot)
    issue = max(p.ns(item["issuedAtBoottimeNs"]) for item in (window, driver_window))
    lifetime = min(p.ns(item["lifetimeDeadlineBoottimeNs"]) for item in (window, driver_window))
    reserve = max(config["lifecycle"]["cleanupReserveNanos"], lifecycle.interactive.COHORT_REAP_RESERVE_NS)
    startup = min(*(p.ns(item["startupDeadlineBoottimeNs"]) for item in (window, driver_window)), lifetime - reserve)
    epoch_issue = max(value["issuedAtUnixNanos"], trust["issuedAtUnixNanos"], assignment["payload"]["issuedAtUnixNanos"])
    expiry = min(value["expiresAtUnixNanos"], trust["expiresAtUnixNanos"], assignment["payload"]["expiresAtUnixNanos"],
        trust["checkpoint"]["asOfUnixNanos"] + 300_000_000_000, trust["assignmentKey"]["notAfterUnixNanos"],
        trust["timeKey"]["notAfterUnixNanos"], *(row["key"]["notAfterUnixNanos"] for row in trust["roleKeys"]))
    p.require(issue <= now_boottime_ns < startup and epoch_issue <= now_unix_ns < expiry)
    bindings = value["keyBindings"]
    p.require(bindings["driver-bootstrap"] == bindings["driver-constructed"] == p.sha(p.decoded(
        config["lifecycle"]["constructedAdmissionAuthority"]["publicKeyBase64url"], size=32))
        and bindings["driver-scope"] == config["phaseTwoAuthority"]["keyId"])
    selected = value["bootstrap"]["policySelection"]
    if selected["apiVersion"] == lifecycle.policy.INTERACTIVE_API:
        interval = selected["interactive"]
        p.require(now_boottime_ns < interval["stopAtBoottimeNanos"] < lifetime - reserve
            and now_unix_ns < interval["expiresAtUnixNanos"] <= expiry
            and interval["stopAtBoottimeNanos"] - now_boottime_ns < interval["expiresAtUnixNanos"] - now_unix_ns)
    return {"value": value, "deadline": lifetime, "epochLimit": expiry, "startupDeadline": startup,
        "peer": copy.deepcopy(value["lifecyclePeer"]), "currentHeadPeer": copy.deepcopy(value["currentHeadPeer"]),
        "bootstrap_configuration": dict(recipe_original=recipe_original, recipe_sha256=value["measuredRecipeSha256"],
            supervisor_inventory_original=supervisor_inventory_original,
            supervisor_inventory_sha256=value["supervisorInventorySha256"],
            conductor_inventory_original=conductor_inventory_original, authority_inventory_original=authority_inventory_original,
            key_bindings=copy.deepcopy(bindings), policy_selection=copy.deepcopy(selected),
            issued_at_unix_ns=value["issuedAtUnixNanos"], expires_at_unix_ns=value["expiresAtUnixNanos"]),
        "_original": raw, "_boot": boot, "_issued": issue, "_epoch_issued": epoch_issue,
        "_reserve": reserve, "_listener": listener}


def _value(prepared):
    p.require(type(prepared) is dict and canonical(prepared["value"]) == prepared["_original"])
    return prepared["value"]


def _adopted_pending(pending):
    p.require(type(pending) is dict)
    index = p.integer(pending["sequence"], maximum=len(ADOPTED)) - 1
    _, raws, _ = adopted.context.channel._pending_adopted(pending, index)
    ticket = p.document(raws["request"], adopted.profile.MAX_FRAME)
    p.require(p.canonical(ticket) == raws["request"]
        and all(type(ticket[name]) is int for name in ("sequence", "conductorSequence", "jobIndex")))
    phase, job = ADOPTED[index]
    p.require(ticket["conductorSequence"] == tuple(adopted.profile.JOBS).index(phase) + 1)
    observed = p.document(raws["observation"], adopted.profile.MAX_FRAME)
    conductor = p.document(observed["conductorRequestOriginal"].encode("ascii"), adopted.profile.MAX_FRAME)
    p.require(type(conductor["sequence"]) is int and type(conductor["payload"]) is dict)
    return ticket, job, conductor


def _selection(prepared, stage, job=None, pending=None):
    """Return only the explicitly delegated fragment; heads always refuse."""
    value = _value(prepared)
    if stage == "bootstrap":
        p.require(job is None and value["bootstrap"]["rule"] == BOOTSTRAP)
        return {}
    if stage == "rendezvous":
        p.require(job is None and value["rendezvous"]["rule"] == RENDEZVOUS)
        ticket = lifecycle.rendezvous_profile.verify_request(pending)
        p.require(ticket["configurationOriginal"] == value["listenerConfigurationOriginal"])
        receiver = p.document(ticket["receiverOriginal"].encode("ascii"), lifecycle.rendezvous_profile.MAX_RECEIVER)["receiver"]
        return {"expected_request_sha256": p.sha(pending), "expected_receiver": copy.deepcopy(receiver)}
    p.require(stage in ("cold", "adopted") and type(job) is str and job in value[stage])
    row = value[stage][job]
    p.require(row["rule"] != EXTERNAL_HEAD)
    fragment = copy.deepcopy(row["selection"])
    if row["rule"] == INTERACTIVE_STOP:
        p.require(stage == "adopted" and job == "stop")
        ticket, selected, conductor = _adopted_pending(pending)
        p.require(selected.name == job and ticket["phase"] == "shutdown")
        fragment["action"]["originHandoffSha256"] = p.sha(lifecycle.interactive._handoff(conductor["payload"]["originHandoff"]))
    else:
        p.require(row["rule"] == DERIVE)
    return fragment


def selection(prepared, stage, job=None, pending=None):
    return _selection(prepared, stage, job, pending)


def _scope(prepared, peer, boot, now_boottime_ns, now_unix_ns):
    value = _value(prepared)
    lifecycle._clocks(boot, now_boottime_ns, now_unix_ns)
    p.require(_peer(peer, root=True) == value["lifecyclePeer"] and boot == prepared["_boot"]
        and prepared["_issued"] <= now_boottime_ns < prepared["deadline"]
        and prepared["_epoch_issued"] <= now_unix_ns < prepared["epochLimit"])
    return value


def _caps(prepared, deadline, expiry, now_boottime_ns, now_unix_ns):
    deadline, expiry = min(deadline, prepared["deadline"]), min(expiry, prepared["epochLimit"])
    p.require(now_boottime_ns < deadline and now_unix_ns < expiry)
    return {"deadline": deadline, "epochLimit": expiry}


def _adopted_caps(prepared, ticket, now_boottime_ns, now_unix_ns):
    ceiling = prepared["deadline"] - prepared["_reserve"]
    if ticket["phase"] not in ("generation-origin", "shutdown"):
        ceiling = min(ceiling, prepared["startupDeadline"])
    deadline, expiry = p.ns(ticket["deadlineBoottimeNs"]), p.ns(ticket["expiresAtUnixNanos"])
    p.require(deadline <= ceiling and expiry <= prepared["epochLimit"])
    return _caps(prepared, deadline, expiry, now_boottime_ns, now_unix_ns)


def authorize(prepared, stage, pending, *, selection, peer, boot, now_boottime_ns, now_unix_ns):
    """Authorize one fixed derivation under the separately retained policy.

    Call before composition and again before sealing approvals. This does not
    authenticate a transcript or candidate, mint an approval, advance order or
    observe a peer; the real caller supplies those independent boundaries.
    """
    value = _scope(prepared, peer, boot, now_boottime_ns, now_unix_ns)
    expiry = prepared["epochLimit"]
    if stage == "bootstrap":
        listener, _ = lifecycle._sender(pending)
        p.require(pending["listenerConfigurationOriginal"] == value["listenerConfigurationOriginal"]
            and listener == prepared["_listener"] and selection == {} and value["bootstrap"]["rule"] == BOOTSTRAP)
        deadline = prepared["startupDeadline"]
    elif stage == "rendezvous":
        p.require(value["rendezvous"]["rule"] == RENDEZVOUS)
        expected = _selection(prepared, stage, pending=pending)
        p.require(canonical(selection) == canonical(expected))
        ticket = lifecycle.rendezvous_profile.verify_request(pending)
        deadline = min(p.ns(ticket["deadlineBoottimeNs"]), prepared["startupDeadline"])
        expiry = min(expiry, ticket["expiresAtUnixNanos"])
    elif stage == "cold":
        ticket, job, deadline = cold.installation.request(pending, prepared["_listener"], now_boottime_ns=now_boottime_ns)
        p.require(p.canonical(ticket) == pending
            and canonical(selection) == canonical(_selection(prepared, stage, job.name)))
        if job.name not in ("coordinator-finish", "acquire-cold-core", "cleanup", "handoff-cold-core"):
            deadline = min(deadline, prepared["startupDeadline"])
    else:
        p.require(stage == "adopted")
        ticket, job, conductor = _adopted_pending(pending)
        p.require(job.name not in HEADS
            and canonical(selection) == canonical(_selection(prepared, stage, job.name, pending)))
        caps = _adopted_caps(prepared, ticket, now_boottime_ns, now_unix_ns)
        if job.family == "stop":
            selected_policy = value["bootstrap"]["policySelection"]
            lifecycle.policy.require_shutdown(selected_policy, selection["action"],
                origin_handoff=conductor["payload"]["originHandoff"], deadline_boottime_ns=caps["deadline"],
                expires_at_unix_ns=caps["epochLimit"], now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
            if selection["action"]["action"] == "run-interactive":
                caps["epochLimit"] = min(caps["epochLimit"], selection["action"]["expiresAtUnixNanos"])
        return caps
    return _caps(prepared, deadline, expiry, now_boottime_ns, now_unix_ns)


def admit_external(prepared, pending, *, peer, boot, now_boottime_ns, now_unix_ns):
    """Permit only the exact head ingress, never decide currentness or approve."""
    value = _scope(prepared, peer, boot, now_boottime_ns, now_unix_ns)
    ticket, job, _ = _adopted_pending(pending)
    p.require(job.name in HEADS and value["adopted"][job.name] == {"rule": EXTERNAL_HEAD})
    return _adopted_caps(prepared, ticket, now_boottime_ns, now_unix_ns)
