"""Pure initial-only request selection and existing native wire composition.

Public dictionaries here are data, never live owners or approval. The actual
acquisition owner supplies already admitted C9/runtime/history originals. A
zero-consumed cursor is an independently selected start anchor, not a receipt,
signed consume head, currentness decision, readiness or legacy startup floor.
"""
from __future__ import annotations

import copy

from serverware import custody_generation_grants as g
from serverware import native_pilot_current_head_profile as head
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_key_profile as key
from serverware import native_pilot_ordinary_runtime_profile as runtime
from serverware import native_pilot_ordinary_runtime_recipe as recipe

p = g.p
API = "serverware.nativePilotInitialTrustRequests/v1"
MAX_BYTES = 65536
FIELDS = ("apiVersion", "launchSha256", "preparationSha256", "resourcesSha256",
    "requestedAtBoottimeNanos", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "requests")
ROW_FIELDS = ("endpointRole", "runtimeConfigurationSha256", "initialHistorySha256",
    "checkpointSha256", "requestOriginal", "requestSha256")
CONTEXT_FIELDS = ("configurationOriginal", "runtimeOriginal", "historyOriginal", "guest")


def select(contexts, *, preparation_original, resources_original, launch_original,
           window, boot, now_boottime_ns):
    """Authenticate all five initial wrappers and select only actual pin cursors.

This pure check establishes byte/signature joins, not the provenance of a
caller dictionary, an empty-directory observation or permission to sign.
Missing/conflicting coverage refuses before the owner samples request entropy.
"""
    p.fields(contexts, g.ROLES)
    p.require(type(boot) is tuple and len(boot) == 3
        and tuple(window[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")) == boot)
    now = key._uint(now_boottime_ns)
    observed = initial.resources(resources_original)
    p.require(observed["preparationSha256"] == p.sha(preparation_original))
    values, checked = {}, {}
    for role in g.ROLES:
        row = p.fields(contexts[role], CONTEXT_FIELDS)
        value = runtime.validate_runtime(role, row["runtimeOriginal"])
        header, guest = value["runtime"], row["guest"]
        p.guest(guest)
        p.require(guest["serviceRole"] == role
            and guest["runtimeConfigurationSha256"] == p.sha(row["runtimeOriginal"]))
        wrapper = p.fields(g.document(row["historyOriginal"], g.MAX_BYTES), initial.WRAPPER_FIELDS)
        p.require(wrapper["apiVersion"] == initial.WRAPPER_API)
        history = initial.runtime_manifest(row["historyOriginal"], runtime=header, guest=guest)
        state, checkpoint = wrapper["initialState"], wrapper["initialCheckpoint"]
        epoch = history["firstRetainedEpoch"]["retainedEpoch"]
        cold = g.configuration(row["configurationOriginal"], guest["configurationSha256"], role)
        identity = initial.prepared_state(state, preparation_raw=preparation_original,
            resources_raw=resources_original, launch_raw=launch_original, configuration=cold,
            window=window, endpoint_role=checkpoint["payload"]["endpointRole"], now=now)
        p.require(identity == epoch["endpointProcessIdentity"]
            and (guest["uid"], guest["gid"]) == (cold["uid"], cold["gid"]))
        key.validate_payload(checkpoint["payload"], identity=identity, window=window, now=now)
        deadline = min(p.ns(window["startupDeadlineBoottimeNs"]),
            checkpoint["payload"]["validUntilBoottime"]["absoluteBoottimeNanos"])
        p.require(now < deadline)
        checked[role] = dict(endpointRole=identity["endpointRole"], identity=identity,
            checkpoint=checkpoint, state=state, deadline=deadline,
            runtimeConfigurationSha256=p.sha(row["runtimeOriginal"]),
            initialHistorySha256=p.sha(row["historyOriginal"]))
        values[role] = value
    forbidden = {digest for row in checked.values() for digest in initial.commitments(row["state"]).values()}
    selected = {}

    def accept(pin, expected_role=None, subject=None):
        runtime._pin_shape(pin)
        matches = [role for role in g.ROLES if pin["endpointProcessIdentity"] == checked[role]["identity"]]
        p.require(len(matches) == 1)
        target = matches[0]
        p.require(expected_role is None or expected_role == target)
        item = checked[target]
        p.require(pin["signedCurrentKeyAuthorization"] == item["checkpoint"]
            and pin["declaredSocketPath"] == runtime.listener(target)
            and pin["consumeHeadObservedAtBoottimeNanos"] == p.ns(item["state"]["issuedAtBoottimeNs"]))
        if subject is not None:
            p.require(recipe.subject(subject) == item["endpointRole"])
        cursor = pin["consumeCursor"]
        recipe.cursor(cursor)
        p.require(cursor["expectedPredecessorReceiptSha256"] not in forbidden)
        if target in selected:
            p.require(selected[target] == cursor)
        else:
            selected[target] = copy.deepcopy(cursor)

    accept(values[g.ROLES[2]]["serviceSigningPin"], g.ROLES[2])
    accept(values[g.ROLES[3]]["serviceSigningPin"], g.ROLES[3])
    for subject in values[g.ROLES[3]]["currentSubjects"]:
        accept(subject["pin"], subject=subject["subject"])
    p.fields(selected, g.ROLES)
    return {role: {"endpointRole": checked[role]["endpointRole"],
        "runtimeConfigurationSha256": checked[role]["runtimeConfigurationSha256"],
        "initialHistorySha256": checked[role]["initialHistorySha256"],
        "checkpointSha256": checked[role]["checkpoint"]["checkpointSha256"],
        "floor": {"checkpointSequence": checked[role]["checkpoint"]["payload"]["checkpointSequence"],
            "checkpointSha256": checked[role]["checkpoint"]["checkpointSha256"], "consumeCursor": selected[role]},
        "domain": copy.deepcopy(key._boot(window)), "deadline": checked[role]["deadline"]}
        for role in g.ROLES}


def request_original(selection, *, entropy, issued_at_boottime_ns):
    """Existing native request bytes; caller data alone establishes no owner."""
    p.require(type(entropy) is bytes and len(entropy) == 32)
    issued = key._uint(issued_at_boottime_ns)
    p.require(issued < selection["deadline"])
    value = {"apiVersion": head.PROTOCOL_API, "endpointRole": selection["endpointRole"],
        "requestEntropyBase64": p.encoded(entropy), "requestedAtBoottimeNanos": issued,
        "deadline": {"domain": copy.deepcopy(selection["domain"]), "absoluteBoottimeNanos": selection["deadline"]},
        "operation": {"operation": "current-endpoint-trust", "body": {"accepted_floor": copy.deepcopy(selection["floor"])}}}
    value["requestNonceSha256"] = p.sha(p.canonical([value[name] for name in (
        "apiVersion", "endpointRole", "requestEntropyBase64", "requestedAtBoottimeNanos", "deadline", "operation")]))
    raw = p.canonical(value)
    head.request(raw)
    return raw


def shape(raw):
    """Closed public export grammar, never request provenance or currentness."""
    value = p.fields(p.document(raw, MAX_BYTES), FIELDS)
    p.require(value["apiVersion"] == API)
    for name in FIELDS[1:4]:
        recipe.digest(value[name])
    issued = key._uint(value["requestedAtBoottimeNanos"])
    startup, lifetime = (p.ns(value[name]) for name in ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued < startup <= lifetime and startup - issued <= 30_000_000_000)
    rows = p.fields(value["requests"], g.ROLES)
    domain, nonces = None, set()
    for role in g.ROLES:
        row = p.fields(rows[role], ROW_FIELDS)
        for name in ROW_FIELDS[1:4]:
            recipe.digest(row[name])
        p.require(type(row["requestOriginal"]) is str and row["requestOriginal"].isascii())
        request_raw = row["requestOriginal"].encode("ascii")
        request = head.request(request_raw)
        floor = request["operation"]["body"]["accepted_floor"]
        recipe.cursor(floor["consumeCursor"])
        p.require(request["endpointRole"] == row["endpointRole"]
            and request["requestedAtBoottimeNanos"] == issued
            and floor["checkpointSequence"] == 1 and floor["checkpointSha256"] == row["checkpointSha256"]
            and request["deadline"]["absoluteBoottimeNanos"] <= startup
            and row["requestSha256"] == head.request_sha256(request_raw)
            and request["requestNonceSha256"] not in nonces)
        nonces.add(request["requestNonceSha256"])
        if domain is None:
            domain = request["deadline"]["domain"]
        else:
            p.require(domain == request["deadline"]["domain"])
    return copy.deepcopy(value)
