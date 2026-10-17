"""One explicitly approved interval on the actual, already running pilot.

This is not a workload launcher, heartbeat generator, readiness assertion or
request result. Native parent owners continue their existing inspection and
lifecycle loops; this owner retains and checks the same live graph until the
approved absolute stop time. Any cancellation or uncertainty raises into the
conductor's existing one-shot cleanup path.
"""
from __future__ import annotations

import copy
import select
import time

from catchplate import custody_generation_originals as originals
from catchplate import native_shadow_nitro_profile as p

API = "catchplate.nativePilotInteractivePolicy/v1"
RESULT_API = "catchplate.nativePilotInteractiveResult/v1"
FIELDS = ("apiVersion", "stopAtBoottimeNanos", "expiresAtUnixNanos")
ACTION_FIELDS = ("action", "originHandoffSha256", "stopAtBoottimeNanos", "expiresAtUnixNanos")
RESULT_FIELDS = ("apiVersion", "actionSha256", "originHandoffSha256", "startedAtBoottimeNanos",
    "endedAtBoottimeNanos", "endedAtUnixNanos", "reason")
MAX_POLICY = 1024
# The already selected native proof-cohort parent begins reaping at this
# fixed offset (native_guest/parent.rs), independent of the driver reserve.
COHORT_REAP_RESERVE_NS = 250_000_000


def validate_policy(fragment):
    """Closed static selection, not an approval or a clock observation."""
    p.fields(fragment, FIELDS)
    p.require(fragment["apiVersion"] == API)
    p.integer(fragment["stopAtBoottimeNanos"])
    p.integer(fragment["expiresAtUnixNanos"])
    p.require(len(p.canonical(fragment)) <= MAX_POLICY)
    return copy.deepcopy(fragment)


def _handoff(value):
    p.fields(value, ("apiVersion", "okForAction", "automaticRetryAllowed", "originSha256"))
    p.require(value["apiVersion"] == "catchplate.nativeGenerationOriginHandoff/v1"
        and value["okForAction"] is False and value["automaticRetryAllowed"] is False)
    p.digest(value["originSha256"])
    return p.canonical(value)


def validate_action(action, *, origin_handoff):
    """Check the approved action's exact observation association, not authority."""
    p.fields(action, ACTION_FIELDS)
    p.require(action["action"] == "run-interactive"
        and p.digest(action["originHandoffSha256"]) == p.sha(_handoff(origin_handoff)))
    validate_policy({"apiVersion": API, **{name: action[name] for name in FIELDS[1:]}})
    return copy.deepcopy(action)


def check_result(result, *, action, origin_handoff):
    """Validate factual interval fields; they certify no workload outcome."""
    selected = validate_action(action, origin_handoff=origin_handoff)
    p.fields(result, RESULT_FIELDS)
    p.require(result["apiVersion"] == RESULT_API and result["reason"] == "approved-interval-ended"
        and p.digest(result["actionSha256"]) == p.sha(p.canonical(selected))
        and result["originHandoffSha256"] == selected["originHandoffSha256"])
    started = p.integer(result["startedAtBoottimeNanos"])
    ended = p.integer(result["endedAtBoottimeNanos"])
    p.require(started < selected["stopAtBoottimeNanos"] <= ended
        and p.integer(result["endedAtUnixNanos"]) < selected["expiresAtUnixNanos"])
    return copy.deepcopy(result)


def check_terminal(result, *, action, origin_handoff, deadline_boottime_ns,
        now_boottime_ns, now_unix_ns):
    """Require interval evidence only for the selected successful terminal path.

    The calling process owner separately authenticates its child, exact result
    envelope, exit status and reap. This checker never proves those events.
    """
    fields = ("apiVersion", "status", "phase", "pilotAcceptanceVerified", "productionReleaseEligible")
    expected = action is not None and result.get("status") == "stopped-cleanup-complete"
    p.fields(result, fields + (("interactiveResult",) if expected else ()))
    if expected:
        checked = check_result(result["interactiveResult"], action=action, origin_handoff=origin_handoff)
        p.require(checked["endedAtBoottimeNanos"] < p.integer(deadline_boottime_ns, maximum=p.MAX_U64)
            and checked["endedAtBoottimeNanos"] <= p.integer(now_boottime_ns, maximum=p.MAX_U64)
            and checked["endedAtUnixNanos"] <= p.integer(now_unix_ns))
    return copy.deepcopy(result)


def wait_for_child(process, *, action, origin_handoff, deadline_boottime_ns):
    """Wait before cleanup on one of the two actual retained process owners.

    Signals remain enabled in the caller. A failed/cancelled wait requires its
    one-shot ``close(cancel=True)``; it is not another cleanup attempt or timer.
    """
    from catchplate.native_pilot_coordinator_process import ConductorProcess
    from catchplate.native_pilot_supervisor_process import AuthorityCoordinatorProcess
    p.require(type(process) in (ConductorProcess, AuthorityCoordinatorProcess))
    selected = validate_action(action, origin_handoff=origin_handoff)
    deadline = p.integer(deadline_boottime_ns, maximum=p.MAX_U64)
    p.require(not process._interval_wait_attempted and not process._close_attempted
        and selected["stopAtBoottimeNanos"] < deadline <= process._lifetime - process._reserve)
    process._interval_wait_attempted = True
    last_wall = time.time_ns()
    while True:
        # Actual class-specific immutable original/runtime admission is kept
        # separate from child terminal state, which may occur at any iteration.
        if type(process) is ConductorProcess:
            process._boundary()
        else:
            process._capabilities()
            for runtime in process._runtimes:
                runtime.check()
        process._io_check(deadline, allow_terminal=True)
        process._read_stderr()
        now, wall = originals.clock(), time.time_ns()
        p.require(last_wall <= wall < selected["expiresAtUnixNanos"] and now < deadline)
        last_wall = wall
        if select.select([process._pidfd], [], [], 0)[0] or now >= selected["stopAtBoottimeNanos"]:
            process._interval_wait_done = True
            return
        remaining = min(selected["stopAtBoottimeNanos"] - now, selected["expiresAtUnixNanos"] - wall)
        try:
            select.select([process._pidfd, process._child.stderr.fileno()], [], [],
                min(0.05, remaining / 1_000_000_000))
        except InterruptedError:
            continue


def run(pilot, action, *, origin_handoff, deadline_boottime_ns):
    """Retain actual owners, with no callbacks, supplied FDs or new deadlines."""
    from catchplate.native_pilot_launch import NativePilotLaunch
    p.require(type(pilot) is NativePilotLaunch)
    pilot.check_running()
    p.require(not pilot._interactive_attempted and pilot._origin_handoff is not None
        and _handoff(origin_handoff) == pilot._origin_handoff)
    selected = validate_action(action, origin_handoff=origin_handoff)
    deadline = p.integer(deadline_boottime_ns, maximum=p.MAX_U64)
    p.require(selected["stopAtBoottimeNanos"] < deadline <= pilot.running_deadline_boottime_ns())
    started, last_wall = originals.clock(), time.time_ns()
    p.require(started < selected["stopAtBoottimeNanos"] and last_wall < selected["expiresAtUnixNanos"]
        and selected["stopAtBoottimeNanos"] - started < selected["expiresAtUnixNanos"] - last_wall)
    pilot._interactive_attempted = True
    last_boot = started
    try:
        # These are retained actual owner PIDFDs, never identifiers supplied in
        # the action. Readability is terminal failure, not a success signal.
        descriptors = pilot.running_pidfds()
        while True:
            pilot.check_running()
            now, wall = originals.clock(), time.time_ns()
            p.require(last_boot <= now < deadline and last_wall <= wall < selected["expiresAtUnixNanos"])
            last_boot, last_wall = now, wall
            if now >= selected["stopAtBoottimeNanos"]:
                result = check_result({"apiVersion": RESULT_API, "actionSha256": p.sha(p.canonical(selected)),
                    "originHandoffSha256": selected["originHandoffSha256"],
                    "startedAtBoottimeNanos": started, "endedAtBoottimeNanos": now,
                    "endedAtUnixNanos": wall, "reason": "approved-interval-ended"},
                    action=selected, origin_handoff=origin_handoff)
                pilot._interactive_result = copy.deepcopy(result)
                return result
            remaining = min(selected["stopAtBoottimeNanos"] - now, selected["expiresAtUnixNanos"] - wall)
            try:
                terminal, _, _ = select.select(descriptors, [], [], min(0.01, remaining / 1_000_000_000))
            except InterruptedError:
                continue  # Same original interval; KeyboardInterrupt still cancels it.
            p.require(not terminal)
    except BaseException:
        pilot._interactive_failed = True
        raise
