#!/usr/bin/env python3
"""Typed adopted candidates over synthetic signed originals, never owners.

The 40-history, installation, C9 and generation positives exercise real public
validators with independently framed test signatures. Unconsumed catalogue
positions are labelled padding, not successful jobs. Later native transitions
and publication have selection/missing-evidence controls only: no complete
native adoption ceremony, installed files or live identity is fabricated.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))

from serverware import native_pilot_adopted_ordinary_inputs as compiler
from serverware import native_pilot_adopted_publication as adopted_paths
from serverware import native_pilot_closure_set as sets
from serverware import native_pilot_ordinary_install as public_install
from serverware import native_pilot_publication as paths
from test_native_pilot_adopted_current_head import fixture as ordinary_fixture
from test_native_pilot_adopted_cohort_authority import release_fixture
from test_native_pilot_closure_set import EXPECTED_SCOPE_VALUES, EXPECTED_SCOPE_ROOTS, manifest_fixture, scope_fixture
from test_native_pilot_generation_scope import fixture as scope_source, key_fixture, NOW, ASSIGNMENT_DOMAIN, signed_message
from test_native_pilot_ordinary_generations import result as generation_result
from test_native_pilot_ordinary_initial import ANCHOR_FIELDS, SIGNATURE_FIELDS
from test_native_pilot_ordinary_keys import canonical, encoded, framed, labelled, sha

profile, g, p = compiler.profile, compiler.g, compiler.p
FAILURES = (ValueError, KeyError, TypeError, InvalidSignature)
SUPPORTED = tuple(job for _, job in profile.BY_NAME.values() if job.family in compiler.FAMILIES)


def record(name, raw, output):
    job = profile.BY_NAME[name][1]
    result = dict(original=output.decode("ascii"), sha256=sha(output))
    if job.purpose is not None:
        selected = adopted_paths.DESTINATIONS if job.purpose in adopted_paths.DESTINATIONS else paths.DESTINATIONS
        result["pin"] = dict(path=selected[job.purpose], sha256=sha(output))
    return dict(input=raw, result=result)


def scope_arguments():
    """Independently re-sign the old scope fixture's exact hot12 successor."""
    policy, args, _ = scope_source()
    selected = json.loads(args["recipe_originals"]["closureSetOriginal"])
    selected["members"].insert(-1, dict(role="publicationReconciliation", manifest=manifest_fixture("publicationReconciliation")))
    selected_raw = sets.set_original(selected["members"], api_version=sets.PUBLICATION_API)
    selected = json.loads(selected_raw)
    envelope = json.loads(args["recipe_originals"]["assignmentOriginal"])
    envelope["payload"]["nativeClosureSet"] = {name: selected[name] for name in ("setRootSha256", "seccompSetRootSha256")}
    envelope["payloadSha256"] = sha(canonical(envelope["payload"]))
    envelope["signature"] = encoded(key_fixture("assignment")[0].sign(signed_message(ASSIGNMENT_DOMAIN, envelope["payload"])))
    args["recipe_originals"].update(assignmentOriginal=canonical(envelope).decode("ascii"), closureSetOriginal=selected_raw.decode("ascii"))
    binding = json.loads(args["measured"]["configurationBindingOriginal"])
    binding.update(assignmentPayloadSha256=envelope["payloadSha256"], nativeClosureSet=copy.deepcopy(envelope["payload"]["nativeClosureSet"]))
    # The ordinary fixture independently selected this exact protocol set.
    # Recompute the measured binding and derived dispatch receipt, not a tag.
    binding["dispatcherProtocolSetSha256"] = labelled("protocol-set")
    args["measured"]["production"]["dispatcherProtocolSetSha256"] = labelled("protocol-set")
    binding_sha = framed(b"serverware.policyShadowProductionCustodyConfiguration/v2", (canonical(binding),))
    proof = scope_fixture(envelope)
    proof["production_configuration_binding_sha256"] = binding_sha
    proof["binding_sha256"] = framed(b"serverware.policyShadowProductionCustodyProofScope/v2",
        (canonical([proof[name] for name in EXPECTED_SCOPE_VALUES + EXPECTED_SCOPE_ROOTS]),))
    args["measured"].update(configurationBindingOriginal=canonical(binding).decode("ascii"),
        configurationBindingSha256=binding_sha, proofScopeOriginal=canonical(proof).decode("ascii"))
    args["measured"]["production"]["expectedConfigurationBindingSha256"] = binding_sha
    recipe = args["driver_generation_recipe"]
    production = args["measured"]["production"]
    authority = key_fixture("custody-result-envelope")[1]
    recipe["dispatchManifestSha256"] = framed(b"serverware.policyShadowCustodyDispatchManifest/v1", (canonical([
        "serverware.policyShadowCustodyDispatch/v2", recipe["operationCoverageRootSha256"],
        production["dispatcherProtocolSetSha256"], recipe["kernelDriverIdentitySha256"],
        recipe["stableReaperIdentity"]["identitySha256"], binding["workerExecutableSha256"],
        production["signerBackendSha256"], production["persistenceBackendSha256"], production["retrievalBackendSha256"],
        8 * 1024 * 1024, 8 * 1024 * 1024, production["maximumAsyncDurabilityNanos"],
        authority["keyId"], authority["keySpkiSha256"]]),))
    return policy, args


def fixture():
    source = ordinary_fixture()
    f, args = source["fixture"], source["args"]
    # Inert unconsumed slots supply only prefix shape; they never claim approval
    # or kernel ownership and cannot pass their own family validators.
    records = {name: dict(input=canonical({"syntheticUnconsumedJob": name}), result={}) for name in profile.BY_NAME}
    selections = {job.name: {} for job in SUPPORTED}
    peer = json.loads(f["runtimes"][g.ROLES[0]])["runtime"]["expectedPeer"]
    _, cohort_input, _ = release_fixture()
    config = json.loads(cohort_input["configurationOriginal"])
    observed = json.loads(cohort_input["observationsOriginal"])
    # This early public source is structurally complete synthetic observation
    # data, not the later independently signed generation fixture's admission.
    bootstrap = json.loads(scope_source()[1]["driver_observation_original"])
    bootstrap.update(uid=peer["uid"], gid=peer["gid"])
    bootstrap["driver"]["driverExecutableSha256"] = peer["executableSha256"]
    config["externalDriver"].update(configurationSha256=sha(args["driver_configuration_raw"]),
        windowSha256=sha(args["driver_window_raw"]), observationSha256=sha(canonical(bootstrap)))
    external = observed["externalDriver"]
    external.update({name: config["externalDriver"][name] for name in compiler.endpoint_driver.CONFIG_FIELDS[:3]})
    external["driver"].update(processId=peer["pid"], startTimeTicks=peer["startTimeTicks"])
    external["executable"] = {target: peer[name] for target, name in (("device", "executableDevice"),
        ("inode", "executableInode"), ("length", "executableLength"), ("sha256", "executableSha256"))}
    observed["configurationSha256"] = sha(canonical(config))
    precreation = dict(ordinaryLaunchOriginal=canonical(f["launch"]).decode("ascii"),
        ordinaryColdOriginals={role: canonical(f["cold"][role]).decode("ascii") for role in g.ROLES},
        driverConfigurationOriginal=args["driver_configuration_raw"].decode("ascii"),
        driverWindowOriginal=args["driver_window_raw"].decode("ascii"),
        cohortConfigurationOriginal=canonical(config).decode("ascii"),
        cohortPrecreationOriginal=cohort_input["precreationOriginal"])
    records["install-precreation"]["input"] = canonical(precreation)
    payload = dict(ordinaryPreparationOriginal=canonical(f["preparation"]).decode("ascii"),
        ordinaryInitialResourcesOriginal=canonical(f["resources"]).decode("ascii"),
        cohortObservationOriginal=canonical(observed).decode("ascii"), ordinaryActivations={role:
            json.loads(args["ordinary_context"][role]["deliveryOriginal"])["payload"]["activation"] for role in g.ROLES})
    observations = {phase: {} for phase in profile.JOBS}
    observations["bootstrap-admission"] = dict(bootstrapObservationOriginal=canonical(bootstrap).decode("ascii"))
    observations["endpoint-inputs"] = payload
    clocks = dict(boot=args["boot"], now_boottime_ns=1400, now_unix_ns=NOW)
    supervisor = dict(apiVersion="serverware.nativePilotAdoptedSupervisorObservation/v1")
    remaining = tuple(role for role in compiler.initial.HELPER_ENDPOINT_ROLES
        if role != json.loads(f["histories"][g.ROLES[-1]])["initialCheckpoint"]["payload"]["endpointRole"])
    wrappers = [(role, None, json.loads(f["histories"][role])) for role in g.ROLES]
    wrappers.extend((g.ROLES[-1], slot, json.loads(f["helper_histories"][endpoint])) for slot, endpoint in enumerate(remaining, 1))
    for role, slot, wrapper in wrappers:
        state, checkpoint = wrapper["initialState"], wrapper["initialCheckpoint"]
        anchor = wrapper["history"]["firstRetainedEpoch"]
        authorities = f["initial_policy"]["services"][role]["authorities"]
        anchor_raw = canonical([anchor[name] for name in ANCHOR_FIELDS])
        signatures = {name: dict(apiVersion=compiler.initial_authority.SIGNATURE_API, signer=name,
            anchorPayloadSha256=sha(anchor_raw), keyId=authorities[name]["keyId"],
            keySpkiSha256=authorities[name]["keySpkiSha256"], signatureBase64=anchor[field])
            for name, field in zip(compiler.initial_authority.KEY_NAMES, SIGNATURE_FIELDS, strict=True)}
        stem, suffix = ("ordinary-initial-", "-" + role) if slot is None else ("ordinary-helper-initial-", "-slot" + str(slot))
        base = dict(apiVersion=compiler.initial_authority.ADOPTED_INPUT_API,
            driverConfigurationOriginal=precreation["driverConfigurationOriginal"], driverWindowOriginal=precreation["driverWindowOriginal"],
            launchOriginal=precreation["ordinaryLaunchOriginal"], configurationOriginal=precreation["ordinaryColdOriginals"][role],
            preparationOriginal=payload["ordinaryPreparationOriginal"], resourcesOriginal=payload["ordinaryInitialResourcesOriginal"],
            initialStateOriginal=canonical(state).decode("ascii"), authorities=authorities,
            payloadOriginal=canonical(checkpoint["payload"]).decode("ascii"))
        if slot is None:
            selections[stem + "checkpoint" + suffix] = copy.deepcopy(f["initial_policy"]["services"][role])
        for operation in compiler.initial_authority.OPERATIONS:
            value = base | dict(operation=operation)
            if operation != "checkpoint": value["initialCheckpointOriginal"] = canonical(checkpoint).decode("ascii")
            if operation == "assemble":
                value["anchorSignatures"] = {name: canonical(item).decode("ascii") for name, item in signatures.items()}
                output = canonical(wrapper)
            elif operation == "checkpoint": output = canonical(checkpoint)
            else: output = canonical(signatures[operation.removesuffix("-anchor")])
            name = stem + operation + suffix
            records[name] = record(name, canonical(value), output)
    installed = dict(apiVersion=compiler.installation.API, launchOriginal=precreation["ordinaryLaunchOriginal"],
        preparationOriginal=payload["ordinaryPreparationOriginal"], resourcesOriginal=payload["ordinaryInitialResourcesOriginal"],
        **{name: precreation[name] for name in ("driverConfigurationOriginal", "driverWindowOriginal")},
        coldOriginals=precreation["ordinaryColdOriginals"], historyOriginals={role: raw.decode("ascii") for role, raw in f["histories"].items()},
        runtimeOriginals={role: raw.decode("ascii") for role, raw in f["runtimes"].items()})
    planned = public_install.plan(runtime_originals=f["runtimes"], history_originals=f["histories"],
        cold_originals={role: canonical(f["cold"][role]) for role in g.ROLES}, launch_original=canonical(f["launch"]), adopted=True)
    metadata = {role: {} for role in g.ROLES}
    pins = {}
    for row in planned:
        pin = dict(path=row["path"], sha256=sha(row["raw"])); pins[row["path"]] = pin
        if row["kind"] == "runtime": metadata[row["role"]]["runtimeConfig"] = pin
        else: metadata[row["role"]][row["kind"] + "Credential"] = dict(
            name="authority-history" if row["kind"] == "history" else "peer-inspection-policy",
            original=pin, length=len(row["raw"]), signing=None)
    records["install-ordinary-runtime"] = dict(input=canonical(installed), result=dict(
        apiVersion=compiler.installation.RESULT_API, inputSha256=sha(canonical(installed)), pins=pins, services=metadata))
    selections["install-ordinary-runtime"] = dict(runtimePolicy=copy.deepcopy(f["fragment"]),
        peerOriginal=canonical(peer).decode("ascii"), peerSha256=sha(canonical(peer)))
    for role in g.ROLES:
        delivery_raw = args["ordinary_context"][role]["deliveryOriginal"].encode("ascii")
        envelope = json.loads(delivery_raw)
        c9 = envelope["payload"]
        c9["issuedAtBoottimeNs"] = f["resources"]["issuedAtBoottimeNs"]
        envelope["signatureBase64url"] = encoded(f["delivery_keys"][role].sign(g.c9.DOMAIN + canonical(c9)))
        delivery_raw = canonical(envelope)
        value = dict(apiVersion=compiler.service.ADOPTED_INPUT_API, operation="delivery", serviceRole=role,
            launchOriginal=installed["launchOriginal"], configurationOriginal=installed["coldOriginals"][role],
            configurationSha256=sha(canonical(f["cold"][role])), runtimeOriginal=installed["runtimeOriginals"][role],
            payloadOriginal=canonical(c9).decode("ascii"), activation=c9["activation"])
        name = "ordinary-delivery-" + role
        records[name] = record(name, canonical(value), delivery_raw)
        selections[name] = dict(credentials=copy.deepcopy(f["fragment"]["services"][role]["credentials"]))
    generation_policy, scope_args = scope_arguments()
    scope = compiler.generation.derive_scope(generation_policy, **scope_args, adopted=True)
    supervisor.update(measuredConfiguration=scope_args["measured"], recipeOriginals=scope_args["recipe_originals"])
    observations["service-originals"] = payload | dict(driverGenerationRecipe=scope_args["driver_generation_recipe"])
    records["driver-bootstrap"] = record("driver-bootstrap", canonical(dict(
        configurationOriginal=scope_args["bootstrap_configuration_original"].decode("ascii"),
        windowOriginal=precreation["driverWindowOriginal"],
        observationOriginal=scope_args["driver_observation_original"].decode("ascii"))), scope_args["bootstrap_original"])
    records["endpoint-inputs"]["input"] = canonical(dict(peer=dict(path=paths.DESTINATIONS["endpoint-peer"], sha256=sha(canonical(peer)))))
    for role in g.ROLES:
        value = compiler.generation.build(role, launch_raw=canonical(f["launch"]), configuration_raw=canonical(f["cold"][role]),
            delivery_raw=records["ordinary-delivery-" + role]["result"]["original"].encode("ascii"),
            runtime_raw=f["runtimes"][role], history_raw=f["histories"][role], scope=scope,
            issued_boottime_ns=1200, expires_boottime_ns=int(f["launch"]["lifetimeDeadlineBoottimeNs"]), adopted=True)
        raw = generation_result(role, json.loads(json.loads(value)["payloadOriginal"]))["original"].encode("ascii")
        records["ordinary-generation-" + role] = record("ordinary-generation-" + role, value, raw)
    selections["ordinary-generation-" + g.ROLES[0]] = dict(generationPolicy=generation_policy,
        window=dict(issuedAtBoottimeNanos=1200, expiresAtBoottimeNanos=int(f["launch"]["lifetimeDeadlineBoottimeNs"])))
    transition_policy = dict(apiVersion=compiler.transition.API, regularAppendCapacity=1,
        dispatch={role: dict(initialHeadSha256=labelled("SYNTHETIC dispatch / " + role)) for role in (g.ROLES[0], g.ROLES[3])},
        spool={role: dict(initialTransitionHeadSha256=labelled("SYNTHETIC spool / " + role)) for role in (g.ROLES[0], g.ROLES[1], g.ROLES[3])})
    for job in SUPPORTED:
        if job.family in ("ordinary-dispatch", "ordinary-head", "ordinary-cleanup", "ordinary-current"):
            selections[job.name] = dict(transitionPolicy=copy.deepcopy(transition_policy))
        elif job.family == "ordinary-publication":
            selections[job.name] = dict(initialTransitionHeadSha256=labelled("SYNTHETIC publication / " + job.role))
    return dict(source=source, records=records, observations=observations, selections=selections,
        supervisor_observation=supervisor, clocks=clocks, scope_args=scope_args, generation_policy=generation_policy)


def prefix(name, records):
    names = tuple(profile.BY_NAME)
    return {entry: records[entry] for entry in names[:names.index(name)]}


def compose(f, name, *, selection=None, records=None, observations=None, clocks=None):
    phase, selected = profile.BY_NAME[name]
    values = f["observations"] if observations is None else observations
    phases = tuple(profile.JOBS)
    return compiler.compose(selected, f["selections"][name] if selection is None else selection,
        prior=prefix(name, f["records"] if records is None else records),
        observations={item: values[item] for item in phases[:phases.index(phase) + 1]},
        supervisor_observation=f["supervisor_observation"], **(f["clocks"] if clocks is None else clocks))


class AdoptedOrdinaryInputControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.value = fixture()

    def test_all_forty_initial_candidates_use_actual_signed_predecessors(self):
        jobs = [job for job in SUPPORTED if job.family in ("ordinary-initial", "helper-initial")]
        self.assertEqual(len(jobs), 40)
        for job in jobs:
            with self.subTest(job=job.name):
                self.assertEqual(compose(self.value, job.name), self.value["records"][job.name]["input"])

    def test_installation_and_five_deliveries_equal_complete_adopted_inputs(self):
        for name in ("install-ordinary-runtime", *("ordinary-delivery-" + role for role in g.ROLES)):
            with self.subTest(job=name):
                self.assertEqual(compose(self.value, name), self.value["records"][name]["input"])
        value = json.loads(compose(self.value, "install-ordinary-runtime"))
        self.assertEqual(len(json.loads(value["runtimeOriginals"][g.ROLES[-1]])["initialEndpointHistories"]), 4)
        self.assertEqual(sum(len(row["directories"]) for row in json.loads(value["resourcesOriginal"])["services"].values()), 17)

    def test_all_five_generation_candidates_derive_the_current_hot12_scope(self):
        for role in g.ROLES:
            name = "ordinary-generation-" + role
            with self.subTest(role=role):
                self.assertEqual(compose(self.value, name), self.value["records"][name]["input"])

    def test_old_and_hot12_scope_selectors_remain_disjoint(self):
        f = self.value
        with self.assertRaises(FAILURES): compiler.generation.derive_scope(f["generation_policy"], **f["scope_args"])
        old_policy, old_args, expected = scope_source()
        self.assertEqual(compiler.generation.derive_scope(old_policy, **old_args), expected)
        with self.assertRaises(FAILURES): compiler.generation.derive_scope(old_policy, **old_args, adopted=True)

    def test_static_selections_are_closed_and_cannot_override_sources(self):
        for job in SUPPORTED:
            with self.subTest(job=job.name):
                self.assertEqual(set(compiler.selection_fields(job)), set(self.value["selections"][job.name]))
                with self.assertRaises(FAILURES): compose(self.value, job.name,
                    selection=self.value["selections"][job.name] | {"payloadOriginal": "caller override"})
        with self.assertRaises(FAILURES): compiler.selection_fields(profile.BY_NAME["driver-bootstrap"][1])

    def test_no_resampled_initial_or_delivery_issue_and_original_expiry(self):
        f = self.value
        for name in ("ordinary-initial-checkpoint-" + g.ROLES[0], "ordinary-delivery-" + g.ROLES[0]):
            with self.subTest(job=name):
                self.assertEqual(compose(f, name), compose(f, name, clocks=f["clocks"] | {"now_boottime_ns": 1500}))
                with self.assertRaises(FAILURES): compose(f, name, clocks=f["clocks"] | {"now_boottime_ns": 5000})
                with self.assertRaises(FAILURES): compose(f, name, clocks=f["clocks"] | {"boot": ("wrong", 1, 2)})

    def test_checkpoint_compiler_explicitly_refuses_legacy_launch_six(self):
        f = self.value
        records, observations = copy.deepcopy(f["records"]), copy.deepcopy(f["observations"])
        first = json.loads(records["install-precreation"]["input"])
        launch = json.loads(first["ordinaryLaunchOriginal"])
        launch["apiVersion"] = "serverware.custodyFiveServiceLaunch/v6"
        first["ordinaryLaunchOriginal"] = canonical(launch).decode("ascii")
        records["install-precreation"]["input"] = canonical(first)
        # Rejoin the public source hashes so this is not merely a stale hash.
        early = observations["endpoint-inputs"]
        prepared = json.loads(early["ordinaryPreparationOriginal"])
        prepared["configurationSha256"] = sha(canonical(launch))
        early["ordinaryPreparationOriginal"] = canonical(prepared).decode("ascii")
        resources = json.loads(early["ordinaryInitialResourcesOriginal"])
        resources["preparationSha256"] = sha(canonical(prepared))
        early["ordinaryInitialResourcesOriginal"] = canonical(resources).decode("ascii")
        with self.assertRaises(FAILURES): compose(f, "ordinary-initial-checkpoint-" + g.ROLES[0],
            records=records, observations=observations)

    def test_history_signatures_and_resource_identity_cannot_be_replaced(self):
        f = self.value; name = "ordinary-initial-root-anchor-" + g.ROLES[0]
        records = copy.deepcopy(f["records"])
        prior = "ordinary-initial-checkpoint-" + g.ROLES[0]
        value = json.loads(records[prior]["result"]["original"])
        value["authoritySignatureBase64"] = encoded(bytes(64))
        records[prior]["result"].update(original=canonical(value).decode("ascii"), sha256=sha(canonical(value)))
        with self.assertRaises(FAILURES): compose(f, name, records=records)
        observations = copy.deepcopy(f["observations"])
        value = json.loads(observations["endpoint-inputs"]["ordinaryInitialResourcesOriginal"])
        value["services"][g.ROLES[0]]["directories"]["publication-journal"]["entryCount"] = 1
        observations["endpoint-inputs"]["ordinaryInitialResourcesOriginal"] = canonical(value).decode("ascii")
        with self.assertRaises(FAILURES): compose(f, "ordinary-initial-checkpoint-" + g.ROLES[0], observations=observations)

    def test_peer_requires_independent_pin_actual_driver_join_and_later_literal_pin(self):
        f = self.value; selection = copy.deepcopy(f["selections"]["install-ordinary-runtime"])
        selection["peerSha256"] = labelled("wrong peer pin")
        with self.assertRaises(FAILURES): compose(f, "install-ordinary-runtime", selection=selection)
        observed = copy.deepcopy(f["observations"])
        value = json.loads(observed["endpoint-inputs"]["cohortObservationOriginal"])
        value["externalDriver"]["driver"]["processId"] += 1
        observed["endpoint-inputs"]["cohortObservationOriginal"] = canonical(value).decode("ascii")
        with self.assertRaises(FAILURES): compose(f, "install-ordinary-runtime", observations=observed)
        records = copy.deepcopy(f["records"])
        records["endpoint-inputs"]["input"] = canonical(dict(peer=dict(path=paths.DESTINATIONS["endpoint-peer"], sha256=labelled("another peer"))))
        with self.assertRaises(FAILURES): compose(f, "ordinary-generation-" + g.ROLES[0], records=records)

    def test_activation_is_literal_list_and_installed_credentials_are_not_selected(self):
        f = self.value; name = "ordinary-delivery-" + g.ROLES[0]
        observed = copy.deepcopy(f["observations"])
        observed["endpoint-inputs"]["ordinaryActivations"][g.ROLES[0]].pop()
        with self.assertRaises(FAILURES): compose(f, name, observations=observed)
        selection = copy.deepcopy(f["selections"][name]); selection["issuedAtBoottimeNs"] = "1500"
        with self.assertRaises(FAILURES): compose(f, name, selection=selection)

    def test_later_generation_cannot_choose_a_new_window_or_recipe(self):
        f = self.value; name = "ordinary-generation-" + g.ROLES[1]
        with self.assertRaises(FAILURES): compose(f, name, selection=f["selections"]["ordinary-generation-" + g.ROLES[0]])
        observed = copy.deepcopy(f["observations"])
        observed["service-originals"]["driverGenerationRecipe"]["driverGenerationReceiptSha256"] = labelled("wrong retained receipt")
        with self.assertRaises(FAILURES): compose(f, name, observations=observed)
        with self.assertRaises(FAILURES): compose(f, name, clocks=f["clocks"] | {"now_unix_ns": NOW + 1_000_000_000})

    def test_generation_cannot_extend_original_bootstrap_authority_windows(self):
        f = self.value
        policy = copy.deepcopy(f["generation_policy"])
        policy["installationExpiresAtUnixNanos"] = NOW + 21_000_000_000
        with self.assertRaises(FAILURES): compiler.generation.derive_scope(policy, **f["scope_args"], adopted=True)
        name = "ordinary-generation-" + g.ROLES[0]
        selection = copy.deepcopy(f["selections"][name])
        selection["window"]["expiresAtBoottimeNanos"] += 1
        with self.assertRaises(FAILURES): compose(f, name, selection=selection)

    def test_transition_and_publication_families_refuse_absent_native_evidence(self):
        for job in SUPPORTED:
            if job.family in ("ordinary-dispatch", "ordinary-head", "ordinary-cleanup", "ordinary-current", "ordinary-publication"):
                with self.subTest(job=job.name), self.assertRaises(FAILURES): compose(self.value, job.name)


if __name__ == "__main__": unittest.main()
