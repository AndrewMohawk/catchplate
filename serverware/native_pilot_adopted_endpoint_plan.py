"""Four fixed public originals for the explicitly adopted endpoint phase.

This is pure byte/signature association, not an observation, publication,
native adoption validation or core custody capability. ``prepare`` evaluates
the retained original interval; ``prepare_current`` additionally admits the
caller's actual clocks. The executor owns all source and descriptor provenance.
The fresh auxiliary manifest deliberately contains no cold core or receipts.
"""
from __future__ import annotations

from serverware import native_pilot_adopted_phase_profile as profile
from serverware import native_pilot_adopted_publication as adopted_publication
from serverware import native_pilot_measured_configuration as measured
from serverware import native_pilot_publication as publication
from serverware import native_pilot_supervisor_endpoint_policy as policy
from serverware import native_shadow_endpoint_driver as external_driver
from serverware import native_shadow_retrieval_artifacts as retrieval

p, g = profile.p, profile.g
PURPOSES = ("endpoint-peer", "endpoint-proof-scope", "endpoint-retrieval-manifest", "endpoint-assignment")
FIELDS = ("coldOriginals", "peer", "proofScope", "retrievalManifest", "objectDirectory", "assignment",
    "production", "adoptionAuthorization")
PIN_FIELDS = ("peer", "proofScope", "retrievalManifest", "assignment")


def _same(left, right):
    p.require(g.canonical(left) == g.canonical(right))


def _pin(value, purpose, raw):
    _same(value, {"path": publication.DESTINATIONS[purpose], "sha256": p.sha(raw)})


def _peer(prior, observations, driver_context, bootstrap):
    """Join independent labels in installed runtimes to actual retained identities."""
    first = profile._input(prior, "driver-bootstrap")
    bundle = profile._input(prior, "install-precreation")
    early = observations["bootstrap-admission"]
    current = observations["endpoint-inputs"]
    p.require(first["observationOriginal"] == early["bootstrapObservationOriginal"]
        == bundle["driverObservationOriginal"])
    for target, source in (("driverConfigurationOriginal", "configurationOriginal"),
            ("driverWindowOriginal", "windowOriginal")):
        p.require(bundle[target] == first[source])
    driver_authority = profile.legacy.driver_authority
    control, config, _, window, _, _ = driver_authority._common(first)
    observed = driver_authority._observation(first["observationOriginal"].encode("ascii"),
        control, config, window, driver_context["now"])
    cohort = profile.cohort_authority.cohort
    selected = profile._input(prior, "cohort-precreation")
    p.require(selected["configurationOriginal"] == bundle["cohortConfigurationOriginal"])
    _same(selected["coldOriginals"], bundle["nativeColdOriginals"])
    prepared = profile.cohort_authority.prepare_input("precreation", prior["cohort-precreation"]["input"],
        boot=driver_context["boot"], now_boottime_ns=driver_context["now"], now_unix_ns=driver_context["wall"])
    cohort_config = cohort.configuration(bundle["cohortConfigurationOriginal"].encode("ascii"))
    signed_raw = profile._output(prior, "cohort-precreation")
    p.require(signed_raw == bundle["cohortPrecreationOriginal"].encode("ascii"))
    signed = p.fields(p.document(signed_raw, cohort.MAX_BYTES), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "serverware.nativeShadowProofCohortPrecreation/v1")
    _same(signed["payload"], prepared["window"])
    driver_authority.driver._key(cohort_config["authority"]).verify(
        p.decoded(signed["signatureBase64url"], size=64), cohort.PRECREATE_DOMAIN + p.canonical(signed["payload"]))
    for name in external_driver.WINDOW_JOIN:
        _same(prepared["window"][name], window[name])
    cohort_observed = p.fields(p.document(current["cohortObservationOriginal"].encode("ascii"), cohort.MAX_BYTES),
        cohort.originals_fields(cohort_config))
    p.require(cohort_observed["apiVersion"] == cohort.originals_api(cohort_config)
        and cohort_observed["configurationSha256"] == p.sha(bundle["cohortConfigurationOriginal"].encode("ascii"))
        and cohort_observed["precreationSha256"] == p.sha(signed_raw)
        and cohort_observed["invocationId"] == window["invocationId"])
    processes, executables = set(), set()
    for role in cohort.roles(cohort_config):
        row = p.fields(cohort_observed[role], ("processId", "startTimeTicks", "executable"))
        pid = p.integer(row["processId"], minimum=2, maximum=(1 << 31) - 1)
        p.integer(row["startTimeTicks"], maximum=p.MAX_U64)
        exe = p.fields(row["executable"], external_driver.EXE_FIELDS)
        identity = (p.integer(exe["device"], minimum=0, maximum=p.MAX_U64),
            p.integer(exe["inode"], maximum=p.MAX_U64))
        p.integer(exe["length"], maximum=64 * 1024 * 1024)
        p.require(exe["sha256"] == cohort_config["executableSha256"] and pid not in processes
            and identity not in executables)
        processes.add(pid); executables.add(identity)
    source = {"configurationSha256": p.sha(first["configurationOriginal"].encode("ascii")),
        "windowSha256": p.sha(first["windowOriginal"].encode("ascii")),
        "observationSha256": p.sha(first["observationOriginal"].encode("ascii")),
        "supervisorExecutableSha256": control["supervisorExecutableSha256"]}
    _same(cohort_config["externalDriver"], source)
    external = external_driver.original(cohort_observed["externalDriver"], source)
    packet = {"apiVersion": "serverware.nativeShadowEndpointDriverBinding/v1",
        "configurationOriginal": first["configurationOriginal"], "windowOriginal": first["windowOriginal"],
        "observationOriginal": first["observationOriginal"]}
    p.require(external["bindingSha256"] == p.sha(p.canonical(packet)))
    _same(external["supervisor"], {name: bootstrap["parent"][name] for name in external_driver.PROCESS_FIELDS})
    kernel, child, exe = observed["driver"], external["driver"], external["executable"]
    pidfd, executable = observed["descriptors"][:2]
    p.require(child["processId"] == observed["processId"] and child["processId"] not in processes
        and child["startTimeTicks"] == kernel["processStartTimeTicks"]
        and (child["pidfdDevice"], child["pidfdInode"]) == (pidfd["device"], pidfd["inode"])
        and (exe["device"], exe["inode"]) == (executable["device"], executable["inode"])
        and exe["sha256"] == kernel["driverExecutableSha256"])
    installed = profile._input(prior, "install-ordinary-runtime")
    peers = [g.canonical(profile.legacy.service_authority._runtime(
        installed["runtimeOriginals"][role].encode("ascii"), role, adopted=True)["expectedPeer"]) for role in g.ROLES]
    p.require(all(raw == peers[0] for raw in peers))
    peer = retrieval._peer(peers[0])
    expected = {"uid": observed["uid"], "gid": observed["gid"], "pid": child["processId"],
        "startTimeTicks": child["startTimeTicks"], "executableDevice": exe["device"], "executableInode": exe["inode"],
        "executableLength": exe["length"], "executableSha256": exe["sha256"],
        "cgroupMountId": kernel["cgroupMountId"], "cgroupInode": kernel["cgroupInode"]}
    _same({name: peer[name] for name in expected}, expected)
    return peers[0], observed, config, window, prepared, cohort_config


def _prepare(value, *, prior, observations, boot, now_boottime_ns, now_unix_ns):
    p.fields(value, FIELDS)
    p.integer(now_boottime_ns, maximum=p.MAX_U64); p.integer(now_unix_ns)
    first_raw = prior["driver-bootstrap"]["input"]
    driver_authority = profile.legacy.driver_authority
    first = driver_authority.prepare_input("bootstrap", first_raw, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns, adopted=True)
    result = profile._result(prior, "driver-bootstrap")
    driver_authority._checked_result("bootstrap", first_raw,
        {name: result[name] for name in ("original", "sha256")}, first)
    peer_raw, observed, config, window, cohort_context, cohort_config = _peer(prior, observations,
        dict(boot=boot, now=now_boottime_ns, wall=now_unix_ns), first["payload"])
    adoption = profile.adoption_input(prior["publication-adoption"]["input"], observations=observations,
        prior=prior, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    adoption_raw = profile._output(prior, "publication-adoption")
    profile._adoption_result(adoption_raw, adoption)
    native = p.document(profile._input(prior, "publication-adoption")["validationInputOriginal"].encode("ascii"),
        profile.adoption.MAX_INPUT)
    recipe = {"apiVersion": measured.ADOPTED_API, **{name: native["current" + name[0].upper() + name[1:]]
        for name in ("assignmentOriginal", "trustOriginal", "trustSha256", "closureSetOriginal")}}
    assignment, keys, root = measured._assignment(recipe, now_unix_ns)
    selected_set = measured.closure_set.validate(recipe["closureSetOriginal"].encode("ascii"),
        api_version=measured.closure_set.PUBLICATION_API)
    manifest = selected_set["members"][-1]["manifest"]
    measured.closure._manifest({"manifestOriginal": p.canonical(manifest).decode("ascii")},
        config, observed, assignment["payload"])
    measured._closure_set(recipe, assignment, manifest)
    p.fields(value["production"], measured.scope.PRODUCTION_FIELDS)
    derived = measured.derive_configuration(envelope=assignment, keys=keys, key_root=root,
        manifest=manifest, observed=observed, production={name: value["production"][name]
            for name in measured.PRODUCTION_FIELDS}, window=window,
        recipe_sha=p.sha(p.canonical(recipe)), successor=True)
    p.require(derived["configurationBindingSha256"] == native["currentConfigurationBindingSha256"]
        and derived["proofScopeOriginal"] == native["currentProofScopeOriginal"])
    _same(derived["production"], value["production"])
    trust = p.document(recipe["trustOriginal"].encode("ascii"), 1024 * 1024)
    authority = [row["key"] for row in trust["roleKeys"] if row["role"] == "custody-supervisor-capability"]
    p.require(len(authority) == 1)
    _same(adoption["payload"]["authority"], {name: authority[0][name]
        for name in ("keyId", "keySpkiSha256", "publicKeyBase64url")})
    payload, checkpoint = adoption["payload"], trust["checkpoint"]
    p.require(payload["assignmentPayloadSha256"] == assignment["payloadSha256"]
        and payload["assignmentRevision"] == assignment["payload"]["assignmentRevision"])
    for name in ("revocationGeneration", "revocationRootSha256"):
        _same(payload[name], checkpoint[name])
    p.require(payload["trustCheckpointId"] == checkpoint["checkpointId"])
    proof_raw = derived["proofScopeOriginal"].encode("ascii")
    assignment_raw = recipe["assignmentOriginal"].encode("ascii")
    retrieval.require_assignment_scope(retrieval.scope_original(proof_raw), p.canonical(assignment["payload"]))
    manifest_raw = retrieval.fresh_ledger_manifest_original(proof_raw)
    plan = tuple(zip(PURPOSES, (peer_raw, proof_raw, manifest_raw, assignment_raw), strict=True))
    p.require(sum(len(raw) for _, raw in plan) <= publication.MAX_PUBLIC_BYTES)
    for field, (purpose, raw) in zip(PIN_FIELDS, plan, strict=True):
        p.require(len(raw) <= publication.LIMITS[purpose])
        publication._shape(purpose, raw); _pin(value[field], purpose, raw)
    policy.validate_policy({"apiVersion": policy.API, "initialization": retrieval.FRESH_INITIALIZATION,
        "objectDirectory": value["objectDirectory"], "peerExpectations": {name: retrieval._peer(peer_raw)[name]
            for name in policy.PEER_FIELDS}})
    p.fields(value["coldOriginals"], profile.COMPOSITE)
    cold = profile._input(prior, "install-precreation")["nativeColdOriginals"]
    for role in profile.COMPOSITE:
        purpose = "native-cold-" + role
        _same(value["coldOriginals"][role], {"path": profile.legacy.launch_install.ADOPTED_DESTINATIONS[purpose],
            "sha256": p.sha(cold[role].encode("ascii"))})
        _same(value["coldOriginals"][role], cohort_config[role + "Configuration"])
    _same(value["adoptionAuthorization"], {"path": adopted_publication.DESTINATIONS["publication-adoption"],
        "sha256": p.sha(adoption_raw)})
    _same(value["adoptionAuthorization"], profile._result(prior, "publication-adoption")["pin"])
    all_keys = [trust["assignmentKey"], trust["timeKey"], *(row["key"] for row in trust["roleKeys"])]
    epoch = min(adoption["epochLimit"], first["epochLimit"], trust["expiresAtUnixNanos"],
        trust["issuedAtUnixNanos"] + p.DAY_NS + 1, assignment["payload"]["expiresAtUnixNanos"],
        assignment["payload"]["issuedAtUnixNanos"] + p.DAY_NS + 1,
        checkpoint["asOfUnixNanos"] + 300_000_000_000, *(key["notAfterUnixNanos"] for key in all_keys))
    deadline = min(adoption["deadline"], first["deadline"], cohort_context["deadline"])
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch)
    return {"plan": plan, "deadline": deadline, "epochLimit": epoch}


def prepare_current(value, *, prior, observations, boot, now_boottime_ns, now_unix_ns):
    """Authenticate originals and their nonrenewed caps at explicit current clocks."""
    return _prepare(value, prior=prior, observations=observations, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)


def prepare(value, *, prior, observations):
    """Pure original-interval plan; never a claim of present freshness or ownership."""
    source = profile._input(prior, "publication-adoption")
    native = p.document(source["validationInputOriginal"].encode("ascii"), profile.adoption.MAX_INPUT)
    payload = p.document(native["payloadOriginal"].encode("ascii"), profile.adoption.MAX_AUTHORIZATION)
    first = profile._input(prior, "driver-bootstrap")
    window = p.document(first["windowOriginal"].encode("ascii"), 65536)["payload"]
    return _prepare(value, prior=prior, observations=observations,
        boot=tuple(window[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")),
        now_boottime_ns=payload["issuedAtBoottimeNanos"], now_unix_ns=payload["issuedAtUnixNanos"])["plan"]
