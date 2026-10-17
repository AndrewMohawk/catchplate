"""Retained candidate DATA for the fixed bootstrap/rendezvous/cold66/adopted176.

This is not a live owner, decision authority, approval or evidence of execution.
The caller supplies authenticated observations and separately approves each
candidate. ``accept`` records only the exact input the caller says was accepted
by its transport. Results come exclusively from later literal requests or the
explicit terminal successors; a descriptor receipt is never a job result.

No filesystem, process, signing, key or ambient-clock operation occurs here.
The existing compilers and terminal codecs retain their own admission boundary.
In particular, public cold owner receipts cannot establish actual ownership.
"""
from __future__ import annotations

import copy

from catchplate import native_pilot_adopted_inputs as adopted
from catchplate import native_pilot_genesis_inputs as cold
from catchplate import native_pilot_genesis_process as cold_process
from catchplate import native_pilot_lifecycle_inputs as lifecycle
from catchplate import native_pilot_supervisor_process as adopted_process

p = lifecycle.p
BOOTSTRAP_FIELDS = ("recipe_original", "recipe_sha256", "supervisor_inventory_original",
    "supervisor_inventory_sha256", "conductor_inventory_original", "authority_inventory_original",
    "key_bindings", "policy_selection", "issued_at_unix_ns", "expires_at_unix_ns")
COLD_END = 2 + len(cold.CATALOGUE)
END = COLD_END + len(adopted.context.CATALOGUE)
# Existing family limits remain 128 MiB each. The aggregate additionally holds
# static inventories, recipe/policy, last requests, terminal originals and one
# unaccepted candidate. This is a literal-data bound, not a Python heap claim.
MAX_RETAINED_BYTES = 512 * 1024 * 1024


def _retained(total):
    p.integer(total, minimum=0, maximum=MAX_RETAINED_BYTES)


def _budget(*values):
    seen, total = set(), 0
    def visit(value, depth=0):
        nonlocal total
        p.require(depth <= 64)
        kind = type(value)
        if kind in (bytes, str, dict, list, tuple):
            identity = id(value)
            if identity in seen: return
            seen.add(identity)
        if kind is bytes:
            total += len(value)
        elif kind is str:
            p.require(value.isascii()); total += len(value) + 2
        elif kind is dict:
            total += 2
            for key, item in value.items():
                p.require(type(key) is str); visit(key, depth + 1); visit(item, depth + 1)
        elif kind in (list, tuple):
            total += 2
            for item in value: visit(item, depth + 1)
        else:
            p.require(value is None or kind in (bool, int))
            total += len(str(value))
        _retained(total)
    for value in values: visit(value)


def _configuration(value):
    p.fields(value, BOOTSTRAP_FIELDS)
    for name, maximum in (("recipe", lifecycle.measured.MAX_RECIPE),
            ("supervisor_inventory", lifecycle.artifacts.MAX_MANIFEST_BYTES),
            ("conductor_inventory", lifecycle.artifacts.MAX_MANIFEST_BYTES),
            ("authority_inventory", lifecycle.artifacts.MAX_MANIFEST_BYTES)):
        raw = value[name + "_original"]
        p.require(type(raw) is bytes and 0 < len(raw) <= maximum and raw.isascii())
        if name + "_sha256" in value:
            p.require(p.sha(raw) == p.digest(value[name + "_sha256"]))
    p.fields(value["key_bindings"], lifecycle.policy.profile.KEY_PURPOSES)
    for digest in value["key_bindings"].values(): p.digest(digest)
    selection = value["policy_selection"]
    p.require(type(selection) is dict)
    selected = selection.get("apiVersion") == lifecycle.policy.INTERACTIVE_API
    p.fields(selection, ("apiVersion", "purpose") + (("interactive",) if selected else ()))
    p.require(selection["apiVersion"] == (lifecycle.policy.INTERACTIVE_API if selected else lifecycle.policy.API)
        and selection["purpose"] == (lifecycle.policy.INTERACTIVE_PURPOSE if selected else lifecycle.policy.PURPOSE))
    if selected: lifecycle.interactive.validate_policy(selection["interactive"])
    p.require(p.integer(value["issued_at_unix_ns"]) < p.integer(value["expires_at_unix_ns"]))
    _budget(value)
    return copy.deepcopy(value)


def _originals(value, expected):
    p.fields(value, expected)
    p.require(all(type(raw) is bytes and raw == expected[name] for name, raw in value.items()))


def _family_budget(prior, observations, *, selected):
    maximum = cold.MAX_TRANSCRIPT if selected == "cold" else adopted.profile.MAX_RETAINED_BYTES
    total = sum(len(row["input"]) + len(row["result"] if selected == "cold"
        else p.canonical(row["result"])) for row in prior.values())
    p.require(total + sum(map(len, observations.values())) <= maximum)


def _current_head_context(prior, payloads, *, boot, now_boottime_ns):
    """Project authenticated retained sources, never a fresh decision.

    The caller first authenticates the complete adopted transcript. This
    separately testable projection makes no claim that a supplied dictionary
    was accepted or that its processes exist; the lower context authenticates
    the complete literal history/runtime/grant and observed request joins.
    """
    profile, ordinary, heads = adopted.profile, adopted.ordinary, adopted.bridge.current_heads
    bootstrap = profile._input(prior, "driver-bootstrap")
    initial_policy = {"apiVersion": ordinary.initial_policy.POLICY_API, "services": {
        role: ordinary._checkpoint_policy(profile._input(prior, "ordinary-initial-checkpoint-" + role))
        for role in profile.g.ROLES}}
    launch = profile._input(prior, "ordinary-generation-" + profile.g.ROLES[0])["launchOriginal"]
    for role in profile.g.ROLES:
        p.require(profile._input(prior, "ordinary-generation-" + role)["launchOriginal"] == launch)
    early = payloads["endpoint-inputs"]
    return heads.prepare_context(
        fragment={"apiVersion": heads.API, "targets": list(heads.JOB_NAMES)},
        bridge_preparation_raw=profile._raw(payloads["bridge-runtime"]["bridgePreparationOriginal"]),
        driver_configuration_raw=profile._raw(bootstrap["configurationOriginal"]),
        driver_window_raw=profile._raw(bootstrap["windowOriginal"]),
        launch_raw=profile._raw(launch),
        preparation_raw=profile._raw(early["ordinaryPreparationOriginal"]),
        resources_raw=profile._raw(early["ordinaryInitialResourcesOriginal"]),
        ordinary_context=adopted.bridge._ordinary(prior), initial_policy=initial_policy,
        boot=boot, now_boottime_ns=now_boottime_ns)


class CandidateTranscript:
    """Mutable public transcript data; never an opaque authority capability."""
    def __init__(self, bootstrap_configuration):
        self._data = dict(configuration=_configuration(bootstrap_configuration), index=0,
            boot=None, now=None, wall=None, bootstrap=None, sender=None, execution=None,
            coldPrior={}, coldObservations={}, adoptedPrior={}, adoptedObservations={},
            accepted=None, coldTerminal=None, adoptedTerminal=None,
            lifetime=None, expiry=None, coldExpiry=None)
        self._candidate = None

    @property
    def next_stage(self):
        """Next data operation; a completion marker is not an approval job."""
        state, index = self._data, self._data["index"]
        if index == 0: return "bootstrap"
        if index == 1: return "rendezvous"
        if index < COLD_END: return "cold"
        if state["coldTerminal"] is None: return "cold-completion"
        if index < END: return "adopted"
        return "adopted-completion" if state["adoptedTerminal"] is None else "done"

    @property
    def done(self):
        """Only the complete public transcript, not successful commissioning."""
        return self.next_stage == "done"

    def _clocks(self, boot, now_boottime_ns, now_unix_ns):
        lifecycle._clocks(boot, now_boottime_ns, now_unix_ns)
        state = self._data
        if state["boot"] is not None:
            p.require(boot == state["boot"] and state["now"] <= now_boottime_ns and state["wall"] <= now_unix_ns)
        if state["lifetime"] is not None:
            p.require(now_boottime_ns < state["lifetime"] and now_unix_ns < state["expiry"])
        return dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)

    def _adopted_pending(self, pending):
        """Splice only the actual next frame's result of the accepted input."""
        state = self._data
        index = state["index"] - COLD_END
        p.require(0 <= index < len(adopted.context.CATALOGUE) and type(pending) is dict
            and type(pending["sequence"]) is int and pending["sequence"] == index + 1)
        request_raw = lifecycle._original(pending["requestOriginal"], adopted.profile.MAX_FRAME)
        ticket = p.document(request_raw, adopted.profile.MAX_FRAME)
        prior = dict(state["adoptedPrior"])
        if index:
            previous = p.fields(ticket["previousResult"], ("phase", "job", "result"))
            phase, selected = adopted.context.CATALOGUE[index - 1]
            last = state["accepted"]
            p.require(previous["phase"] == phase and previous["job"] == last["job"] == selected.name
                and type(previous["result"]) is dict)
            prior[last["job"]] = dict(input=last["input"], result=copy.deepcopy(previous["result"]))
        _budget(state, pending, prior)
        return index, request_raw, prior

    def current_head_evidence(self, pending, *, boot, now_boottime_ns, now_unix_ns):
        """Existing public evidence for the exact next one of eight head jobs.

        No currentness decision is required or inferred. Nothing is accepted,
        committed or advanced: a later independently supplied decision still
        passes through ordinary ``prepare`` and byte-exact ``accept``.
        """
        p.require(self._candidate is None and self.next_stage == "adopted")
        clocks = self._clocks(boot, now_boottime_ns, now_unix_ns)
        index, _, prior = self._adopted_pending(pending)
        phase, selected = adopted.context.CATALOGUE[index]
        heads = adopted.bridge.current_heads
        p.require(phase == "bridge-runtime" and selected.family == "current-head"
            and selected.name in heads.JOB_NAMES)
        state, originals = self._data, self._data["bootstrap"]
        policy_sha = p.sha(originals["policy"])
        policy, recipe, control, config, window, intake = adopted.context.configuration(
            originals["policy"], policy_sha, originals["recipe"], p.sha(originals["recipe"]), clocks)
        ticket, checked, observed, payloads, snapshot = adopted.context.transcript(
            pending, prior, state["adoptedObservations"], policy, policy_sha, clocks)
        p.require(checked is selected)
        reserve = max(adopted.policy.interactive.COHORT_REAP_RESERVE_NS, config["lifecycle"]["cleanupReserveNanos"])
        ceiling = min(p.ns(window["startupDeadlineBoottimeNs"]), p.ns(intake["startupDeadlineBoottimeNs"]),
            min(p.ns(window["lifetimeDeadlineBoottimeNs"]), p.ns(intake["lifetimeDeadlineBoottimeNs"])) - reserve)
        deadline, expiry = p.ns(ticket["deadlineBoottimeNs"]), p.ns(ticket["expiresAtUnixNanos"])
        p.require(now_boottime_ns < deadline <= ceiling and now_unix_ns < expiry <= intake["expiresAtUnixNanos"])
        expected = adopted.foundation.compose(adopted.profile.BY_NAME["driver-bootstrap"][1], {},
            prior={}, observations=payloads, bootstrap_originals=policy["bootstrapOriginals"])
        p.require(prior["driver-bootstrap"]["input"] == expected
            and payloads["endpoint-precreation"]["bootstrapAdmissionOriginal"]
                == adopted.profile._result(prior, "driver-bootstrap")["original"])
        adopted.context.measured_originals(observed, recipe, control, config, window, payloads, clocks)
        context = _current_head_context(prior, payloads, boot=boot, now_boottime_ns=now_boottime_ns)
        p.require(heads.adoption_selected(context)
            and now_boottime_ns < min(deadline, context["deadline"], state["lifetime"])
            and now_unix_ns < min(expiry, state["expiry"]))
        raw = heads.observed_original(selected.name, context)
        _family_budget(prior, snapshot, selected="adopted")
        _budget(state, pending, prior, snapshot, raw)
        return raw

    def prepare(self, stage, pending, selection, *, boot, now_boottime_ns, now_unix_ns):
        """Compose once; no caller-supplied prior rows or future observations."""
        p.require(self._candidate is None and stage == self.next_stage
            and stage in ("bootstrap", "rendezvous", "cold", "adopted"))
        clocks = self._clocks(boot, now_boottime_ns, now_unix_ns)
        state = self._data
        next_state = dict(state, boot=boot, now=now_boottime_ns, wall=now_unix_ns, index=state["index"] + 1)
        if stage == "bootstrap":
            p.fields(selection, ())
            result = lifecycle.bootstrap(pending, **state["configuration"], **clocks)
            supplied = result["originals"]
            intake = lifecycle.intake.validate_configuration(supplied["intake_configuration"], **clocks)
            next_state.update(bootstrap=dict(supplied), sender=copy.deepcopy(pending),
                lifetime=p.ns(intake["lifetimeDeadlineBoottimeNs"]), expiry=intake["expiresAtUnixNanos"])
            accepted = None
        elif stage == "rendezvous":
            p.fields(selection, ("expected_request_sha256", "expected_receiver"))
            ticket = lifecycle.rendezvous_profile.verify_request(pending)
            p.require(ticket["senderRequestOriginal"] == state["sender"]["senderRequestOriginal"]
                and ticket["configurationOriginal"] == state["sender"]["listenerConfigurationOriginal"])
            result = lifecycle.rendezvous(pending, **selection, **clocks)
            supplied = {"input": result["input_original"]}
            next_state.update(execution=supplied["input"], coldExpiry=min(state["expiry"], result["epochLimit"]))
            accepted = None
        elif stage == "cold":
            index = state["index"] - 2
            ticket = p.document(pending, cold.installation.MAX_REQUEST)
            p.require(type(ticket["sequence"]) is int and ticket["sequence"] == index + 1)
            prior = dict(state["coldPrior"])
            if index:
                previous = p.fields(ticket["previousResult"], ("job", "resultOriginal", "resultSha256"))
                last = state["accepted"]
                p.require(previous["job"] == last["job"] == cold.CATALOGUE[index - 1].name)
                result_raw = lifecycle._original(previous["resultOriginal"], cold.jobs.MAX_OUTPUT)
                p.require(p.sha(result_raw) == p.digest(previous["resultSha256"]))
                prior[last["job"]] = dict(input=last["input"], result=result_raw)
            result = cold.compose(pending, selection, configuration_original=state["execution"],
                configuration_sha256=p.sha(state["execution"]), request_sha256=p.sha(pending),
                prior=prior, observations=state["coldObservations"], **clocks)
            supplied = {"input": result["inputOriginal"]}
            result["epochLimit"] = min(result["epochLimit"], state["coldExpiry"])
            next_state.update(coldPrior=prior, coldObservations=result["observations"], coldExpiry=result["epochLimit"])
            accepted = dict(job=cold.CATALOGUE[index].name, input=supplied["input"], request=pending)
        else:
            index, request_raw, prior = self._adopted_pending(pending)
            originals = state["bootstrap"]
            result = adopted.compose(pending, selection, policy_original=originals["policy"],
                policy_sha256=p.sha(originals["policy"]), recipe_original=originals["recipe"],
                recipe_sha256=p.sha(originals["recipe"]), prior=prior,
                observations=state["adoptedObservations"], cold_prior=state["coldPrior"], **clocks)
            supplied = {"input": result["inputOriginal"]}
            next_state.update(adoptedPrior=prior, adoptedObservations=result["observations"])
            accepted = dict(job=adopted.context.CATALOGUE[index][1].name, input=supplied["input"], request=request_raw)
        deadline, expiry = result["deadline"], result["epochLimit"]
        if next_state["lifetime"] is not None:
            deadline, expiry = min(deadline, next_state["lifetime"]), min(expiry, next_state["expiry"])
        p.require(now_boottime_ns < deadline and now_unix_ns < expiry)
        if accepted is not None: accepted.update(deadline=deadline, expiry=expiry)
        next_state["accepted"] = accepted
        candidate = dict(originals=dict(supplied), pins={name: p.sha(raw) for name, raw in supplied.items()},
            deadline=deadline, epochLimit=expiry)
        _budget(state, next_state, candidate)
        self._candidate = dict(state=next_state, value=candidate)
        return copy.deepcopy(candidate)

    def accept(self, originals):
        """Record exact candidate custody reported by the caller, not approval."""
        p.require(self._candidate is not None)
        _originals(originals, self._candidate["value"]["originals"])
        self._data, self._candidate = self._candidate["state"], None

    def complete(self, stage, terminal_raw, *, boot, now_boottime_ns, now_unix_ns):
        """Consume a literal terminal only after the final input was accepted.

        The actual process owner proves EOF, exit0, cleanup and consuming reap.
        These pure associations cannot establish any of those runtime facts.
        """
        p.require(self._candidate is None and stage in ("cold", "adopted")
            and self.next_stage == stage + "-completion")
        clocks = self._clocks(boot, now_boottime_ns, now_unix_ns)
        state, last = self._data, self._data["accepted"]
        p.require(now_boottime_ns < last["deadline"] and now_unix_ns < last["expiry"])
        next_state = dict(state, now=now_boottime_ns, wall=now_unix_ns)
        if stage == "cold":
            value, bundle = cold_process.completion_value(terminal_raw,
                observation_raw=state["coldObservations"]["core.observation"], final_input_raw=last["input"],
                configuration_raw=state["execution"], **clocks)
            p.require(bundle == state["coldPrior"]["coordinator-finish"]["result"]
                and p.ns(value["deadlineBoottimeNs"]) <= p.ns(
                    p.document(last["request"], cold.installation.MAX_REQUEST)["deadlineBoottimeNs"]))
            observed = cold_process.core.observation(state["coldObservations"]["core.observation"], bundle)
            prior = dict(state["coldPrior"])
            prior[last["job"]] = dict(input=last["input"], result=value["finalResult"]["resultOriginal"].encode("ascii"))
            _family_budget(prior, state["coldObservations"], selected="cold")
            # Terminal transport/reap caps must not replace the genuine core's
            # operational lifetime carried into the subsequent adopted jobs.
            next_state.update(coldPrior=prior, coldTerminal=terminal_raw,
                lifetime=min(state["lifetime"], p.ns(observed["deadlineBoottimeNs"])),
                expiry=min(state["expiry"], observed["expiresAtUnixNanos"]))
        else:
            value = adopted_process.completion_value(terminal_raw, request_raw=last["request"],
                input_raw=last["input"], input_sha256=p.sha(last["input"]),
                now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
            result_raw = value["finalResult"]["resultOriginal"].encode("ascii")
            prior = dict(state["adoptedPrior"])
            prior[last["job"]] = dict(input=last["input"], result=p.document(result_raw, 4096))
            _family_budget(prior, state["adoptedObservations"], selected="adopted")
            next_state.update(adoptedPrior=prior, adoptedTerminal=terminal_raw)
        _budget(next_state)
        self._data = next_state
