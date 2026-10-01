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
HELPER_API = "serverware.nativePilotInitialTrustRequests/v2"
MAX_BYTES = 65536
FIELDS = ("apiVersion", "launchSha256", "preparationSha256", "resourcesSha256",
    "requestedAtBoottimeNanos", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "requests")
ROW_FIELDS = ("endpointRole", "runtimeConfigurationSha256", "initialHistorySha256",
    "checkpointSha256", "requestOriginal", "requestSha256")
CONTEXT_FIELDS = ("configurationOriginal", "runtimeOriginal", "historyOriginal", "guest")


def select(contexts, *, preparation_original, resources_original, launch_original,
           window, boot, now_boottime_ns, adopted=False):
    """Authenticate five service contexts and every role-specific initial wrapper.

This pure check establishes byte/signature joins, not the provenance of a
caller dictionary, an empty-directory observation or permission to sign.
Missing/conflicting coverage refuses before the owner samples request entropy.
"""
    p.fields(contexts, g.ROLES)
    p.require(type(adopted) is bool and type(boot) is tuple and len(boot) == 3
        and tuple(window[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")) == boot)
    now = key._uint(now_boottime_ns)
    observed = initial.resources(resources_original, adopted=adopted)
    p.require(observed["preparationSha256"] == p.sha(preparation_original))
    values, checked = {}, {}
    for role in g.ROLES:
        row = p.fields(contexts[role], CONTEXT_FIELDS)
        value = runtime.validate_runtime(role, row["runtimeOriginal"], adopted=adopted)
        header, guest = value["runtime"], row["guest"]
        p.guest(guest)
        p.require(guest["serviceRole"] == role
            and guest["runtimeConfigurationSha256"] == p.sha(row["runtimeOriginal"]))
        wrapper = p.fields(g.document(row["historyOriginal"], g.MAX_BYTES), initial.WRAPPER_FIELDS)
        p.require(wrapper["apiVersion"] == (initial.ADOPTED_WRAPPER_API if adopted and role in initial.ADOPTED_ROLES else initial.WRAPPER_API))
        history = initial.runtime_manifest(row["historyOriginal"], runtime=header, guest=guest)
        state, checkpoint = wrapper["initialState"], wrapper["initialCheckpoint"]
        epoch = history["firstRetainedEpoch"]["retainedEpoch"]
        cold = g.configuration(row["configurationOriginal"], guest["configurationSha256"], role)
        identity = initial.prepared_state(state, preparation_raw=preparation_original,
            resources_raw=resources_original, launch_raw=launch_original, configuration=cold,
            window=window, endpoint_role=checkpoint["payload"]["endpointRole"], now=now, adopted=adopted)
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
    helper = values[g.ROLES[-1]]["runtime"]["apiVersion"] == initial.HELPER_RUNTIME_API
    targets = {(role, row["endpointRole"]): row for role, row in checked.items() if not helper or role != g.ROLES[-1]}
    if helper:
        members = initial.helper_endpoint_histories(contexts[g.ROLES[-1]]["historyOriginal"], runtime=values[g.ROLES[-1]])
        for endpoint_role, item in members.items():
            state, checkpoint, identity = item["state"], item["checkpoint"], item["identity"]
            selected_identity = initial.prepared_state(state, preparation_raw=preparation_original,
                resources_raw=resources_original, launch_raw=launch_original,
                configuration=g.configuration(contexts[g.ROLES[-1]]["configurationOriginal"],
                    contexts[g.ROLES[-1]]["guest"]["configurationSha256"], g.ROLES[-1]),
                window=window, endpoint_role=endpoint_role, now=now, adopted=adopted)
            p.require(identity == selected_identity)
            key.validate_payload(checkpoint["payload"], identity=identity, window=window, now=now)
            targets[g.ROLES[-1], endpoint_role] = dict(endpointRole=endpoint_role, identity=identity,
                checkpoint=checkpoint, state=state, deadline=min(p.ns(window["startupDeadlineBoottimeNs"]),
                    checkpoint["payload"]["validUntilBoottime"]["absoluteBoottimeNanos"]),
                runtimeConfigurationSha256=p.sha(contexts[g.ROLES[-1]]["runtimeOriginal"]),
                initialHistorySha256=p.sha(item["original"]))
    forbidden = {digest for row in targets.values() for digest in initial.commitments(row["state"], adopted=adopted).values()}
    selected = {}

    def accept(pin, expected_role=None, subject=None):
        runtime._pin_shape(pin)
        matches = [target for target, row in targets.items() if pin["endpointProcessIdentity"] == row["identity"]]
        p.require(len(matches) == 1)
        target = matches[0]
        p.require(expected_role is None or expected_role == target[0])
        item = targets[target]
        p.require(pin["signedCurrentKeyAuthorization"] == item["checkpoint"]
            and pin["declaredSocketPath"] == runtime.listener(target[0])
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
    if helper:
        for pin in values[g.ROLES[-1]]["initialEndpointPins"].values():
            accept(pin, g.ROLES[-1])
    for subject in values[g.ROLES[3]]["currentSubjects"]:
        accept(subject["pin"], subject=subject["subject"])
    p.require(set(selected) == set(targets))
    result = {}
    for role in g.ROLES:
        entries = {}
        for (target, endpoint_role), row in targets.items():
            if target != role:
                continue
            entries[endpoint_role] = {"endpointRole": endpoint_role,
                "runtimeConfigurationSha256": row["runtimeConfigurationSha256"],
                "initialHistorySha256": row["initialHistorySha256"],
                "checkpointSha256": row["checkpoint"]["checkpointSha256"],
                "floor": {"checkpointSequence": row["checkpoint"]["payload"]["checkpointSequence"],
                    "checkpointSha256": row["checkpoint"]["checkpointSha256"], "consumeCursor": selected[target, endpoint_role]},
                "domain": copy.deepcopy(key._boot(window)), "deadline": row["deadline"]}
        result[role] = entries if helper and role == g.ROLES[-1] else next(iter(entries.values()))
    return result


def iter_selection(selection):
    """Source-ordered selections; callers still must authenticate their source."""
    p.fields(selection, g.ROLES)
    for role in g.ROLES:
        row = selection[role]
        if role == g.ROLES[-1] and "endpointRole" not in row:
            p.fields(row, initial.HELPER_ENDPOINT_ROLES)
            for endpoint_role in initial.HELPER_ENDPOINT_ROLES:
                yield role, endpoint_role, row[endpoint_role]
        else:
            yield role, row["endpointRole"], row


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
    p.require(value["apiVersion"] in (API, HELPER_API))
    for name in FIELDS[1:4]:
        recipe.digest(value[name])
    issued = key._uint(value["requestedAtBoottimeNanos"])
    startup, lifetime = (p.ns(value[name]) for name in ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued < startup <= lifetime and startup - issued <= 30_000_000_000)
    rows = p.fields(value["requests"], g.ROLES)
    domain, nonces = None, set()
    expanded = []
    for role in g.ROLES:
        if role == g.ROLES[-1] and value["apiVersion"] == HELPER_API:
            members = p.fields(rows[role], initial.HELPER_ENDPOINT_ROLES)
            expanded.extend((role, endpoint_role, members[endpoint_role]) for endpoint_role in initial.HELPER_ENDPOINT_ROLES)
        else:
            expanded.append((role, None, rows[role]))
    helper_runtime = set()
    for role, endpoint_role, supplied in expanded:
        row = p.fields(supplied, ROW_FIELDS)
        p.require(endpoint_role is None or endpoint_role == row["endpointRole"])
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
        if role == g.ROLES[-1]:
            helper_runtime.add(row["runtimeConfigurationSha256"])
    p.require(len(helper_runtime) == 1)
    return copy.deepcopy(value)


def iter_requests(export):
    """Checked source order: (service role, protocol role, copied request row)."""
    value = shape(p.canonical(export))
    return tuple(iter_selection(value["requests"]))
