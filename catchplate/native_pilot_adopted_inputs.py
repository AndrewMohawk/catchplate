"""Compose candidate inputs for the source-fixed adopted176 catalogue.

Candidates are not independent approvals. The authentic channel, independently
operated decision service, protected publishers, native validator and actual
owners remain required. No signing, filesystem or process IO occurs here.
"""
from __future__ import annotations

from catchplate import native_pilot_adopted_bridge_inputs as bridge
from catchplate import native_pilot_adopted_constructed_inputs as constructed
from catchplate import native_pilot_adopted_foundation_inputs as foundation
from catchplate import native_pilot_adopted_handoff_inputs as handoff
from catchplate import native_pilot_adopted_input_context as context
from catchplate import native_pilot_adopted_native_inputs as native
from catchplate import native_pilot_adopted_ordinary_inputs as ordinary

p, profile, policy = context.p, context.profile, context.policy


def _module(selected):
    if selected.family == "driver" and selected.role == "constructed":
        return constructed
    if selected.family in foundation.FAMILIES:
        return foundation
    if selected.family in handoff.FAMILIES:
        return handoff
    if selected.family in ("ordinary-initial", "helper-initial", "ordinary-installation") or selected.family.startswith("ordinary-"):
        return ordinary
    if selected.family in ("delivery", "launch"):
        return bridge if selected.role == "bridge" else native
    return native if selected.family in ("native-key", "native", "generation-install", "native-launch-authorization", "service-material") else bridge


def selection_fields(name):
    p.require(type(name) is str and name in profile.BY_NAME)
    selected = profile.BY_NAME[name][1]
    return _module(selected).selection_fields(selected)


def compose(pending, selection, *, policy_original, policy_sha256, recipe_original, recipe_sha256,
            prior, observations, cold_prior, boot, now_boottime_ns, now_unix_ns):
    """Return exact candidate bytes, original caps and retained phase snapshot.

    `prior` is the completed job prefix, including the current frame's previous
    result: {name: {input: bytes, result: dict}}. `observations` is the snapshot
    BEFORE this call, mapping phase to literal supervisor observation bytes.
    Persist the returned snapshot. `cold_prior` retains all actual cold66 inputs
    and result bytes; adoption cannot be reconstructed from a receipt alone.
    Returned caps do not replace narrower limits retained by the live executor.
    """
    context.lifecycle._clocks(boot, now_boottime_ns, now_unix_ns)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    selected_policy, recipe, control, config, window, intake = context.configuration(
        policy_original, policy_sha256, recipe_original, recipe_sha256, clocks)
    ticket, selected, observed, payloads, snapshot = context.transcript(
        pending, prior, observations, selected_policy, policy_sha256, clocks)
    reserve = max(policy.interactive.COHORT_REAP_RESERVE_NS, config["lifecycle"]["cleanupReserveNanos"])
    lifetime = min(p.ns(window["lifetimeDeadlineBoottimeNs"]), p.ns(intake["lifetimeDeadlineBoottimeNs"])) - reserve
    ceiling = lifetime if ticket["phase"] in ("generation-origin", "shutdown") else min(lifetime,
        p.ns(window["startupDeadlineBoottimeNs"]), p.ns(intake["startupDeadlineBoottimeNs"]))
    deadline, epoch_limit = p.ns(ticket["deadlineBoottimeNs"]), p.ns(ticket["expiresAtUnixNanos"])
    p.require(now_boottime_ns < deadline <= ceiling and now_unix_ns < epoch_limit <= intake["expiresAtUnixNanos"])
    if "driver-bootstrap" in prior:
        bootstrap_job = profile.BY_NAME["driver-bootstrap"][1]
        expected = foundation.compose(bootstrap_job, {}, prior={}, observations=payloads,
            bootstrap_originals=selected_policy["bootstrapOriginals"])
        p.require(prior["driver-bootstrap"]["input"] == expected)
    if "endpoint-precreation" in payloads:
        p.require(payloads["endpoint-precreation"]["bootstrapAdmissionOriginal"]
            == profile._result(prior, "driver-bootstrap")["original"])
    context.measured_originals(observed, recipe, control, config, window, payloads, clocks)
    module = _module(selected)
    p.fields(selection, module.selection_fields(selected))
    if module is foundation:
        raw = module.compose(selected, selection, prior=prior, observations=payloads,
            bootstrap_originals=selected_policy["bootstrapOriginals"])
    elif module is handoff:
        raw = module.compose(selected, selection, prior=prior, observations=payloads,
            supervisor_observation=observed, cold_prior=cold_prior, boot=boot)
    else:
        raw = module.compose(selected, selection, prior=prior, observations=payloads,
            supervisor_observation=observed, **clocks)
    context.original(raw, selected.maximum)
    if selected.family == "stop":
        policy.require_shutdown(selected_policy, p.document(raw, selected.maximum),
            origin_handoff=payloads["shutdown"]["originHandoff"], deadline_boottime_ns=deadline,
            expires_at_unix_ns=epoch_limit, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    prepared = profile.prepare_input(selected.name, raw, phase=ticket["phase"], prior=prior,
        observations=payloads, **clocks)
    if prepared["deadline"] is not None:
        deadline = min(deadline, p.integer(prepared["deadline"], maximum=p.MAX_U64))
    if prepared["epochLimit"] is not None:
        epoch_limit = min(epoch_limit, p.integer(prepared["epochLimit"], maximum=p.MAX_I64))
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch_limit)
    return dict(inputOriginal=raw, inputSha256=p.sha(raw), deadline=deadline, epochLimit=epoch_limit,
        observations=snapshot)
