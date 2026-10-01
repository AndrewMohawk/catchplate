"""Pure retained-transcript checks for adopted candidate composition.

Only the authenticated supervisor channel establishes observation provenance.
These checks preserve its literal phase frames, independently selected policy
and recipe, fixed job order, and original clocks. No owner is reconstructed.
"""
from __future__ import annotations

from serverware import native_pilot_adopted_phase_profile as profile
from serverware import native_pilot_adopted_supervisor_policy as policy
from serverware import native_pilot_lifecycle_inputs as lifecycle
from serverware import native_pilot_measured_configuration as measured
from serverware import native_pilot_supervisor_approval_channel as channel

p = profile.p
CATALOGUE = tuple((phase, job) for phase, jobs in profile.JOBS.items() for job in jobs)
OBSERVATION_FIELDS = ("apiVersion", "policySha256", "catalogueSha256", "intakeConfigurationSha256",
    "conductorRequestOriginal", "measuredConfiguration", "recipeOriginals")


def original(raw, maximum, digest=None):
    p.require(type(raw) is bytes and 0 < len(raw) <= maximum and raw.isascii())
    if digest is not None:
        p.require(p.sha(raw) == p.digest(digest))
    return raw


def observation(raw, selected_policy):
    value = p.fields(p.document(original(raw, profile.MAX_FRAME), profile.MAX_FRAME), OBSERVATION_FIELDS)
    p.require(value["apiVersion"] == "serverware.nativePilotAdoptedSupervisorObservation/v1")
    for field in ("catalogueSha256", "intakeConfigurationSha256"):
        p.require(value[field] == selected_policy[field])
    return value


def transcript(pending, prior, observations, selected_policy, policy_sha256, clocks):
    """Snapshot values are exact supervisor observation bytes, not payloads."""
    p.require(type(prior) is dict and len(prior) < len(CATALOGUE))
    index = len(prior)
    _, raw, _ = channel._pending_adopted(pending, index)
    ticket = p.document(raw["request"], profile.MAX_FRAME)
    p.require(all(type(ticket[name]) is int for name in ("sequence", "conductorSequence", "jobIndex")))
    phase, job = CATALOGUE[index]
    prefix = CATALOGUE[:index]
    p.require(set(prior) == {previous.name for _, previous in prefix}
        and type(observations) is dict and set(observations) == {stage for stage, _ in prefix})
    retained = 0
    for _, previous in prefix:
        row = p.fields(prior[previous.name], ("input", "result"))
        original(row["input"], previous.maximum)
        p.require(type(row["result"]) is dict)
        result_raw = p.canonical(row["result"])
        original(result_raw, profile.MAX_FRAME)
        retained += len(row["input"]) + len(result_raw)
        p.require(retained <= profile.MAX_RETAINED_BYTES)
    payloads, snapshot = {}, dict(observations)
    first_expiry = first_deadline = None
    for stage in observations:
        observed = observation(observations[stage], selected_policy)
        p.require(observed["policySha256"] == policy_sha256)
        conductor = p.document(observed["conductorRequestOriginal"].encode("ascii"), profile.MAX_FRAME)
        p.require(conductor["phase"] == stage)
        payloads[stage] = conductor["payload"]
        retained += len(observations[stage])
        p.require(retained <= profile.MAX_RETAINED_BYTES)
        if stage == "bootstrap-admission":
            first_expiry = conductor["expiresAtUnixNanos"]
            first_deadline = p.ns(conductor["deadlineBoottimeNs"])
    previous = ticket["previousResult"]
    if prefix:
        previous_phase, previous_job = prefix[-1]
        p.require(p.canonical(previous) == p.canonical({"phase": previous_phase,
            "job": previous_job.name, "result": prior[previous_job.name]["result"]}))
        profile.checked_result(previous_job.name, prior[previous_job.name]["input"],
            prior[previous_job.name]["result"], phase=previous_phase,
            prior={name: row for name, row in prior.items() if name != previous_job.name},
            observations=payloads, **clocks)
    else:
        p.require(previous is None)
    observed = observation(raw["observation"], selected_policy)
    p.require(observed["policySha256"] == policy_sha256)
    conductor = p.document(observed["conductorRequestOriginal"].encode("ascii"), profile.MAX_FRAME)
    p.require(type(conductor["sequence"]) is int and type(conductor["payload"]) is dict)
    p.require(type(ticket["conductorSequence"]) is int
        and ticket["conductorSequence"] == tuple(profile.JOBS).index(phase) + 1)
    if phase in snapshot:
        p.require(ticket["conductorRequest"] is None and snapshot[phase] == raw["observation"])
    else:
        p.require(ticket["jobIndex"] == 1 and p.canonical(ticket["conductorRequest"]) == p.canonical(conductor))
        snapshot[phase] = raw["observation"]
        p.require(retained + len(raw["observation"]) <= profile.MAX_RETAINED_BYTES)
    if first_expiry is not None:
        p.require(ticket["expiresAtUnixNanos"] == first_expiry)
        if phase not in ("generation-origin", "shutdown"):
            p.require(p.ns(ticket["deadlineBoottimeNs"]) <= first_deadline)
        if phase == "endpoint-precreation":
            p.require(p.ns(ticket["deadlineBoottimeNs"]) == first_deadline)
    payloads[phase] = conductor["payload"]
    return ticket, job, observed, payloads, snapshot


def configuration(policy_original, policy_sha256, recipe_original, recipe_sha256, clocks):
    original(policy_original, policy.MAX_POLICY, policy_sha256)
    selected = policy.shape(policy_original)
    original(recipe_original, measured.MAX_RECIPE, recipe_sha256)
    recipe = lifecycle._document(recipe_original, measured.MAX_RECIPE, measured.SET_FIELDS)
    p.require(recipe["apiVersion"] == measured.ADOPTED_API and selected["measuredRecipeSha256"] == recipe_sha256)
    for field in ("source", "conductorInventorySha256", "authorityInventorySha256", "bootstrapOriginals"):
        p.require(p.canonical(recipe[field]) == p.canonical(selected[field]))
    bootstrap = {name + "Original": text for name, text in selected["bootstrapOriginals"].items()}
    control, config, cold, window, _, _ = profile.legacy.driver_authority._common(bootstrap)
    intake = policy.intake.validate_configuration(selected["intakeConfigurationOriginal"].encode("ascii"), **clocks)
    p.require(tuple(window[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")) == clocks["boot"])
    p.require(p.ns(window["issuedAtBoottimeNs"]) <= clocks["now_boottime_ns"])
    key = config["lifecycle"]["constructedAdmissionAuthority"]
    p.require(selected["keyBindings"]["driver-bootstrap"] == selected["keyBindings"]["driver-constructed"]
        == p.sha(p.decoded(key["publicKeyBase64url"], size=32))
        and selected["keyBindings"]["driver-scope"] == config["phaseTwoAuthority"]["keyId"])
    return selected, recipe, control, config, window, intake


def measured_originals(observed, recipe, control, config, window, payloads, clocks):
    phase = p.document(observed["conductorRequestOriginal"].encode("ascii"), profile.MAX_FRAME)["phase"]
    if phase not in measured.RESULT_PHASES:
        p.require(observed["measuredConfiguration"] is None and observed["recipeOriginals"] is None)
        return
    expected = {field: recipe[field] for field in ("assignmentOriginal", "trustOriginal", "trustSha256", "closureSetOriginal")}
    p.require(observed["recipeOriginals"] == expected)
    early = payloads["bootstrap-admission"]
    current = payloads["endpoint-precreation"]
    p.require(early["bootstrapObservationOriginal"] == current["bootstrapObservationOriginal"])
    driver_observed = profile.legacy.driver_authority._observation(
        early["bootstrapObservationOriginal"].encode("ascii"), control, config, window, clocks["now_boottime_ns"])
    envelope, keys, key_root = measured._assignment(recipe, clocks["now_unix_ns"])
    manifest = measured.closure._manifest({"manifestOriginal": recipe["closureManifestOriginal"]},
        config, driver_observed, envelope["payload"])
    measured._closure_set(recipe, envelope, manifest)
    expected_measured = measured.derive_configuration(envelope=envelope, keys=keys, key_root=key_root,
        manifest=manifest, observed=driver_observed, production=recipe["production"], window=window,
        recipe_sha=p.sha(p.canonical(recipe)), successor=True)
    p.require(p.canonical(observed["measuredConfiguration"]) == p.canonical(expected_measured))
