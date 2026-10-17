"""Fixed public driver/cohort candidate projections for adopted commissioning.

No owners, signatures, approvals, filesystem publications or ambient clocks.
The facade sends the result through the existing job validators before use.
"""
from __future__ import annotations

import copy

from catchplate import native_pilot_adopted_phase_profile as profile
from catchplate import native_pilot_adopted_publication as published

p, legacy, g = profile.p, profile.legacy, profile.g
FAMILIES = ("driver", "cohort", "precreation")


def selection_fields(selected):
    p.require(profile.BY_NAME.get(selected.name, (None, None))[1] == selected and selected.family in FAMILIES)
    p.require(selected.family != "driver" or selected.role == "bootstrap")
    if selected.family == "cohort" and selected.role == "precreation":
        return ("authority", "endpointExecutableSha256", "cleanup", "nativeColdOriginals")
    if selected.family == "cohort" and selected.role == "release":
        return ("endpointImages",)
    if selected.family == "precreation":
        return ("cohortExecutableSha256", "ordinaryColdOriginals", "ordinaryExecutableSha256")
    return ()


def _driver(selected, observations, prior, bootstrap):
    phase = profile.BY_NAME[selected.name][0]
    value = {"apiVersion": "catchplate.nativePilotDriverAuthorityInput/v1", "operation": selected.role,
        **{name + "Original": text for name, text in bootstrap.items()}}
    if selected.role == "bootstrap":
        value.update(observationOriginal=observations[phase]["bootstrapObservationOriginal"],
            payloadOriginal=observations[phase]["admissionPayloadOriginal"])
    else:
        value.update(copy.deepcopy(observations[phase]))
        value["bootstrapAdmissionOriginal"] = profile._result(prior, "driver-bootstrap")["original"]
    return value


def _cohort(selected, selection, observations, prior, bootstrap):
    if selected.role == "release":
        first = profile._input(prior, "cohort-precreation")
        config = legacy.cohort.configuration(first["configurationOriginal"].encode("ascii"))
        observed_raw = observations["service-originals"]["cohortObservationOriginal"].encode("ascii")
        observed = p.document(observed_raw, legacy.cohort.MAX_BYTES)
        precreated = profile._result(prior, "cohort-precreation")["original"]
        payload = {"apiVersion": legacy.cohort.release_api(config), "configurationSha256": first["configurationSha256"],
            "precreationSha256": p.sha(precreated.encode("ascii")), "observationSha256": p.sha(observed_raw),
            "invocationId": observed["invocationId"], "signingKeyId": config["authority"]["keyId"],
            "externalDriverSha256": legacy.cohort.external_driver_sha256(config, observed)}
        images = p.fields(selection["endpointImages"], profile.cohort_authority.ROLES)
        for role in profile.cohort_authority.ROLES:
            launch = profile._result(prior, "install-launch-" + role)
            image = images[role]
            legacy.delivery_authority.delivery._pin(image)
            closure = p.document(profile._output(prior, "native-closure-" + role), legacy.closure_authority.MAX_BYTES)
            p.require(image["sha256"] == closure["manifest"]["imageSha256"])
            payload[role] = {"launch": copy.deepcopy(launch["launch"]), "image": copy.deepcopy(image)}
        return {**copy.deepcopy(first), "operation": "release", "payloadOriginal": p.canonical(payload).decode("ascii"),
            "precreationOriginal": precreated, "observationsOriginal": observed_raw.decode("ascii")}
    control = p.document(bootstrap["control"].encode("ascii"), 4096)
    window = p.document(bootstrap["window"].encode("ascii"), 32768)["payload"]
    cold = p.fields(selection["nativeColdOriginals"], profile.cohort_authority.ROLES)
    p.digest(selection["endpointExecutableSha256"])
    config = {"apiVersion": legacy.cohort.ADOPTED_CONFIGURATION_API,
        "authority": copy.deepcopy(selection["authority"]), "executableSha256": selection["endpointExecutableSha256"],
        "cleanup": copy.deepcopy(selection["cleanup"]), "externalDriver": {
            **{name: control[name] for name in ("configurationSha256", "windowSha256", "supervisorExecutableSha256")},
            "observationSha256": p.sha(observations["endpoint-precreation"]["bootstrapObservationOriginal"].encode("ascii"))}}
    for role in profile.cohort_authority.ROLES:
        raw = profile._raw(cold[role], 65536)
        config[role + "Configuration"] = {"path": legacy.launch_install.ADOPTED_DESTINATIONS["native-cold-" + role],
            "sha256": p.sha(raw)}
    raw = p.canonical(config)
    legacy.cohort.configuration(raw)
    payload = {"configurationSha256": p.sha(raw), "authorityKeyId": config["authority"]["keyId"],
        **{name: window[name] for name in legacy.delivery_authority.WINDOW_FIELDS}}
    return {"apiVersion": profile.cohort_authority.API, "operation": "precreation",
        "configurationOriginal": raw.decode("ascii"), "configurationSha256": p.sha(raw),
        "coldOriginals": copy.deepcopy(cold), "payloadOriginal": p.canonical(payload).decode("ascii")}


def _precreation(selection, observations, prior, bootstrap):
    cohort = profile._input(prior, "cohort-precreation")
    precreated = profile._result(prior, "cohort-precreation")["original"]
    window = p.document(bootstrap["window"].encode("ascii"), 32768)["payload"]
    p.digest(selection["cohortExecutableSha256"])
    cold = p.fields(selection["ordinaryColdOriginals"], g.ROLES)
    executables = p.fields(selection["ordinaryExecutableSha256"], g.ROLES)
    control = {"apiVersion": "catchplate.nativeShadowProofCohortControl/v1",
        "cohortExecutableSha256": selection["cohortExecutableSha256"],
        "configurationSha256": cohort["configurationSha256"], "precreationSha256": p.sha(precreated.encode("ascii"))}
    launch = {"apiVersion": "catchplate.custodyFiveServiceLaunch/v7",
        **{name: window[name] for name in legacy.delivery_authority.WINDOW_FIELDS if name != "issuedAtBoottimeNs"}, "services": {}}
    for role in g.ROLES:
        raw = profile._raw(cold[role], 65536)
        g.configuration(raw, p.sha(raw), role)
        p.digest(executables[role])
        launch["services"][role] = {"executableSha256": executables[role], "deliveryConfiguration": {
            "path": legacy.launch_install.publication.DESTINATIONS["ordinary-cold-" + role], "sha256": p.sha(raw)}}
    launch_raw = p.canonical(launch)
    published.shape("ordinary-launch", launch_raw)
    return {"apiVersion": "catchplate.nativePilotPrecreationBundle/v2",
        "driverConfigurationOriginal": bootstrap["configuration"], "driverWindowOriginal": bootstrap["window"],
        "driverObservationOriginal": observations["endpoint-precreation"]["bootstrapObservationOriginal"],
        "cohortConfigurationOriginal": cohort["configurationOriginal"], "cohortPrecreationOriginal": precreated,
        "cohortControlOriginal": p.canonical(control).decode("ascii"), "ordinaryLaunchOriginal": launch_raw.decode("ascii"),
        "nativeColdOriginals": copy.deepcopy(cohort["coldOriginals"]), "ordinaryColdOriginals": copy.deepcopy(cold)}


def compose(selected, selection, *, prior, observations, bootstrap_originals):
    p.fields(selection, selection_fields(selected))
    if selected.family == "driver":
        value = _driver(selected, observations, prior, bootstrap_originals)
    elif selected.family == "cohort":
        value = _cohort(selected, selection, observations, prior, bootstrap_originals)
    else:
        value = _precreation(selection, observations, prior, bootstrap_originals)
    return p.canonical(value)
