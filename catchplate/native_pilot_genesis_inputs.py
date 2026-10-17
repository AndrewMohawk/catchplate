"""Compose a candidate for one genuine, ordered cold66 request.

The independent provider retains its earlier input/result originals and the
observation snapshot returned by the preceding call. The executor sends only a
delta and its immediately preceding result, not a complete reusable transcript.
This pure compiler binds those bytes and original clocks; it does not establish
their provenance, approve a job, install files, sign, or reconstruct owners.
The authenticated channel and actual executor remain authoritative, including
their retained narrower limits. No alternative approval or job wire is added.
"""
from __future__ import annotations

from catchplate import native_pilot_genesis_foundation_inputs as foundation
from catchplate import native_pilot_genesis_job_install as installation
from catchplate import native_pilot_genesis_jobs as jobs
from catchplate import native_pilot_genesis_native_inputs as native
from catchplate import native_pilot_genesis_ordinary_inputs as ordinary
from catchplate import native_pilot_genesis_owner_inputs as owners

p, g, wire = jobs.p, jobs.g, installation.wire
CATALOGUE = jobs.catalogue(handoff=True)
MAX_TRANSCRIPT = 128 * 1024 * 1024  # Executor separately counts approvals and public-result copies too.
OBSERVATION_OUTPUTS = {
    "parent-start": (*jobs.PARENTS.values(), "parent.peer"),
    "ordinary-prepare": ("ordinary.configuration", "ordinary.preparation", "ordinary.resources",
        *("ordinary.activation." + role for role in jobs.ORDINARY),
        *("ordinary.runtime-inputs." + role for role in jobs.ORDINARY)),
    "endpoints-prepare": ("endpoints.configuration", "endpoints.preparation", "endpoints.resources",
        *("endpoints.activation." + role for role in jobs.NATIVE[:2])),
    "initialize-retrieval-store": ("endpoints.store",),
    "coordinator-prepare": ("coordinator.observation", "coordinator.activation"),
    "coordinator-assemble": ("coordinator.runtime",),
    "acquire-cold-core": ("core.observation",),
}


def selection_fields(name):
    """Closed fragment fields for a source-selected job, never an action list."""
    selected = jobs.job(name, handoff=True)
    module = owners if selected.family == "owner" else ordinary if selected.family in (
        "initial", "ordinary-runtime", "ordinary") else native if selected.family in native.FAMILIES else foundation
    return module.selection_fields(selected)


def _pinned(raw, maximum, digest):
    p.require(type(raw) is bytes and 0 < len(raw) <= maximum and p.sha(raw) == p.digest(digest))


def _transcript(ticket, prior, observations):
    prefix = CATALOGUE[:ticket["sequence"] - 1]
    p.require(type(prior) is dict and set(prior) == {item.name for item in prefix})
    retained = 0
    for item in prefix:
        row = p.fields(prior[item.name], ("input", "result"))
        for field, maximum in (("input", item.maximum), ("result", jobs.MAX_OUTPUT)):
            raw = row[field]
            p.require(type(raw) is bytes and 0 < len(raw) <= maximum and raw.isascii())
            retained += len(raw)
            p.require(retained <= MAX_TRANSCRIPT)
    if prefix:
        previous = ticket["previousResult"]
        p.require(previous["resultOriginal"].encode("ascii") == prior[prefix[-1].name]["result"])
    # No caller-preloaded future observations and no dropped earlier originals.
    expected = {name for item in prefix[:-1] for name in OBSERVATION_OUTPUTS.get(item.name, ())}
    p.require(type(observations) is dict and set(observations) == expected)
    merged = dict(observations)
    delta = ticket["observation"]
    p.require(set(delta) == set(OBSERVATION_OUTPUTS.get(prefix[-1].name, ())) if prefix else not delta)
    for name, original in delta.items():
        p.require(name not in merged)
        merged[name] = original.encode("ascii")
    for raw in merged.values():
        p.require(type(raw) is bytes and 0 < len(raw) <= wire.MAX_REQUEST and raw.isascii())
        retained += len(raw)
        p.require(retained <= MAX_TRANSCRIPT)
    for item in prefix:
        names = OBSERVATION_OUTPUTS.get(item.name, ())
        if not names:
            continue
        result = prior[item.name]["result"]
        if item.name in ("initialize-retrieval-store", "coordinator-assemble", "acquire-cold-core"):
            p.require(result == merged[names[0]])
        else:
            receipt = p.fields(g.document(result, 65536), ("apiVersion", "action", "observationSha256"))
            p.require(receipt["apiVersion"] == "catchplate.nativePilotGenesisOwnerResult/v1"
                and receipt["action"] == item.name
                and receipt["observationSha256"] == {name: p.sha(merged[name]) for name in names})
    return merged


def compose(request_original, selection, *, configuration_original, configuration_sha256,
            request_sha256, prior, observations, boot, now_boottime_ns, now_unix_ns):
    """Return candidate bytes, current caps, and the accumulated observations.

    `prior` includes the immediate previous result received in this request,
    paired with the exact input the provider previously delivered. `observations`
    is the snapshot BEFORE this frame. Persist the returned snapshot only as part
    of the provider's retained transcript; a repeated call is not retry authority.
    Returned caps intersect the original execution, request and current producer;
    they do not replace the live executor's narrower historical limits.
    """
    _pinned(configuration_original, installation.MAX_CONFIGURATION, configuration_sha256)
    _pinned(request_original, installation.MAX_REQUEST, request_sha256)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    configuration = installation.context(configuration_original, **clocks)
    ticket, selected, deadline = installation.request(request_original, configuration,
        now_boottime_ns=now_boottime_ns)
    observed = _transcript(ticket, prior, observations)
    p.fields(selection, selection_fields(selected.name))
    if selected.family == "owner":
        prepared = owners.compose(selected, selection, prior=prior, observations=observed,
            execution_configuration=configuration, **clocks)
        raw = prepared["inputOriginal"]
    else:
        if selected.family in ("initial", "ordinary-runtime", "ordinary"):
            raw = ordinary.compose(selected, selection, prior=prior, observations=observed, **clocks)
        elif selected.family in native.FAMILIES:
            raw = native.compose(selected, selection, prior=prior, observations=observed, **clocks)
        else:
            raw = foundation.compose(selected, selection, prior=prior, observations=observed,
                execution_configuration=configuration)
        prepared = jobs.prepare_input(selected.name, raw, prior=prior, observations=observed, **clocks)
        if selected.name == "parent-precreation":
            wire.require_window(prepared["nativeContext"]["window"], configuration["window"])
    p.require(type(raw) is bytes and 0 < len(raw) <= selected.maximum and raw.isascii())
    if prepared["deadline"] is not None:
        deadline = min(deadline, p.integer(prepared["deadline"], maximum=p.MAX_U64))
    epoch_limit = configuration["expiresAtUnixNanos"]
    if prepared["epochLimit"] is not None:
        epoch_limit = min(epoch_limit, p.integer(prepared["epochLimit"], maximum=p.MAX_I64))
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch_limit)
    return dict(inputOriginal=raw, inputSha256=p.sha(raw), deadline=deadline, epochLimit=epoch_limit,
        observations=observed)
