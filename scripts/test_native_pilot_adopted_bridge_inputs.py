#!/usr/bin/env python3
"""Pure adopted bridge candidates, not a completed commissioning transcript.

The existing fixtures supply real deterministic C9/key/closure/TrustedTime and
current-head signatures. Unexamined prior slots are explicitly labelled, and
public installation results/descriptors are synthetic data, never owners.
Runtime14 business histories/grants in the bridge chain remain structural
fixtures. These tests do not claim complete Runtime14 composition or native
business admission. No successful validator, signer loader or owner is mocked.
"""
from __future__ import annotations

import copy
from functools import lru_cache
import json
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))

from serverware import native_pilot_adopted_bridge_inputs as compiler
from serverware import native_pilot_driver_authority as driver_authority
from serverware import native_pilot_scope_authority as scope
from test_native_pilot_adopted_bridge_chain import fixture as bridge_fixture, delivery_options
from test_native_pilot_adopted_current_head import fixture as head_fixture
from test_native_pilot_adopted_interactive import fixture as interval_fixture, window_fixture, literal_rows, SECOND, BOOT
from test_native_pilot_generation_scope import fixture as generation_fixture, key_fixture, encoded, signed_message, NOW

profile, p, g = compiler.profile, compiler.p, compiler.g
ERRORS = (ValueError, KeyError, TypeError, InvalidSignature)
PADDING = p.canonical({"unexaminedSyntheticPrefixSlot": True})


def output(raw):
    return {"original": raw.decode("ascii"), "sha256": p.sha(raw)}


def record(raw, result=None):
    return {"input": raw, "result": {"unexaminedSyntheticPrefixSlot": True} if result is None else result}


def observed(*, measured=None, recipe=None):
    # Only the facade authenticates this envelope's actual transport provenance.
    return {"apiVersion": compiler.OBSERVATION_API, "policySha256": p.sha(b"synthetic-policy"),
        "catalogueSha256": p.sha(b"synthetic-catalogue"), "intakeConfigurationSha256": p.sha(b"synthetic-intake"),
        "conductorRequestOriginal": "{}", "measuredConfiguration": measured, "recipeOriginals": recipe}


def case(name, records, observations, clocks, supervisor=None):
    selected_phase, selected = profile.BY_NAME[name]
    names, phases = tuple(profile.BY_NAME), tuple(profile.JOBS)
    return dict(prior={key: copy.deepcopy(records.get(key, record(PADDING))) for key in names[:names.index(name)]},
        observations={phase: copy.deepcopy(observations.get(phase, {}))
            for phase in phases[:phases.index(selected_phase) + 1]},
        supervisor_observation=copy.deepcopy(observed() if supervisor is None else supervisor), **clocks)


def compose(name, selection, options):
    return compiler.compose(profile.BY_NAME[name][1], selection, **options)


def head_case(name):
    f = head_fixture(); args = f["args"]
    # These are the literal authenticated source projections consumed by the
    # head job. They do not purport to be complete earlier generation jobs.
    records = {"driver-bootstrap": record(p.canonical({
        "configurationOriginal": args["driver_configuration_raw"].decode("ascii"),
        "windowOriginal": args["driver_window_raw"].decode("ascii")}))}
    for role, row in args["ordinary_context"].items():
        records["ordinary-generation-" + role] = record(p.canonical({
            "launchOriginal": args["launch_raw"].decode("ascii"),
            "services": {role: {field: value for field, value in row.items() if field != "generationGrantOriginal"}}}),
            output(row["generationGrantOriginal"].encode("ascii")))
    observations = {"endpoint-inputs": {
        "ordinaryPreparationOriginal": args["preparation_raw"].decode("ascii"),
        "ordinaryInitialResourcesOriginal": args["resources_raw"].decode("ascii")},
        "bridge-runtime": {"bridgePreparationOriginal": args["bridge_preparation_raw"].decode("ascii")}}
    clocks = {**f["clocks"], "now_unix_ns": NOW}
    return f, case(name, records, observations, clocks)


def bridge_records(f):
    options = delivery_options(f)
    source = f["source"]
    records = {"driver-bootstrap": record(p.canonical({name + "Original": raw.decode("ascii")
        for name, raw in options["bootstrap_originals"].items()})),
        "install-bridge-runtime": record(options["runtime_bundle_raw"], options["runtime_result"]),
        "native-delivery-bridge": record(f["common"]["delivery_input_raw"], output(f["common"]["delivery_raw"])),
        # The equality join consumes these exact shared measured/recipe objects;
        # this projection is not represented as a signed Retrieval key input.
        "native-role-keys-retrieval": record(p.canonical({"measured": f["common"]["measured"],
            "recipeOriginals": f["common"]["recipe_originals"]})),
        "native-service-trustedTime": record(f["value"]["serviceContext"]["inputOriginal"].encode("ascii"),
            output(f["value"]["serviceContext"]["grantOriginal"].encode("ascii")))}
    for role, raw in f["histories"].items():
        records["ordinary-generation-" + role] = record(p.canonical({"services": {role: {
            "historyOriginal": raw.decode("ascii")}}}))
    for operation, name in compiler._authorization_names().items():
        row = f["records"][operation]
        records[name] = record(row["inputOriginal"], output(row["authorizationOriginal"]))
    observations = {"bootstrap-admission": {"bootstrapObservationOriginal": source["observationOriginal"]},
        "bridge-delivery": {"activation": options["activation"]}}
    supervisor = observed(measured=f["common"]["measured"], recipe=f["common"]["recipe_originals"])
    return records, observations, supervisor


def bridge_case(name):
    f = bridge_fixture()
    records, observations, supervisor = bridge_records(f)
    return f, case(name, records, observations, f["clocks"], supervisor)


@lru_cache(maxsize=1)
def _scope_case():
    f = bridge_fixture()
    source, common = f["source"], f["common"]
    runtime = json.loads(source["runtimeOriginal"])
    # Real signed ordinary test originals support the public publication shape;
    # this separate fixture is not asserted to share the bridge's live window
    # or to establish the complete Runtime14 business/history relationships.
    grants = {role: row["generationGrantOriginal"]
        for role, row in head_fixture()["args"]["ordinary_context"].items()}
    for role, text in grants.items():
        runtime["ordinaryInitialHistories"][role]["generationGrantOriginal"] = text
    runtime["generationAdmission"]["grants"] = {role: p.sha(text.encode("ascii")) for role, text in grants.items()}
    source["runtimeOriginal"] = p.canonical(runtime).decode("ascii")
    c9 = json.loads(common["delivery_raw"])
    c9["payload"]["runtimeConfig"]["sha256"] = p.sha(source["runtimeOriginal"].encode("ascii"))
    source["payloadOriginal"] = p.canonical(c9["payload"]).decode("ascii")
    c9["signatureBase64url"] = encoded(key_fixture("bridge-c9")[0].sign(
        compiler.delivery.delivery.DOMAIN + p.canonical(c9["payload"])))
    common.update(delivery_input_raw=p.canonical(source), delivery_raw=p.canonical(c9))
    records = {}
    for operation in compiler.authorizations.OPERATIONS:
        raw = compiler.authorizations.build(operation, prior_authorizations=records, **common)
        prepared = compiler.authorizations.prepare_adopted_input(operation, raw, **f["clocks"])
        result = copy.deepcopy(prepared["result"])
        signed = result["authorization"] if "authorization" in result else result
        signed["signature"] = encoded(key_fixture("custody-supervisor-capability")[0].sign(
            signed_message(prepared["domain"], prepared["payload"])))
        records[operation] = {"inputOriginal": raw, "authorizationOriginal": p.canonical(result)}
    f["records"] = records
    f["value"].update(deliveryInputOriginal=common["delivery_input_raw"].decode("ascii"),
        deliveryOriginal=common["delivery_raw"].decode("ascii"), authorizations={operation: {
            name: raw.decode("ascii") for name, raw in row.items()} for operation, row in records.items()})
    prior, observations, supervisor = bridge_records(f)
    launch_raw = p.canonical(f["value"])
    selected = compiler.launch.prepare_input(launch_raw, **f["clocks"])
    installed = compiler.launch_publication.launch._installation_result("bridge",
        p.sha(selected["bundleOriginal"]), selected["window"], selected["pins"])
    installed["apiVersion"] = "serverware.nativePilotLaunchInstallation/v3"
    prior["install-launch-bridge"] = record(launch_raw, installed)
    for role, text in grants.items():
        prior["ordinary-generation-" + role]["result"] = output(text.encode("ascii"))
    _, previous, _ = generation_fixture()
    early = json.loads(previous["bootstrap_original"])["payload"]
    window = json.loads(source["windowOriginal"])["payload"]
    early.update(configurationSha256=p.sha(source["ownerConfigurationOriginal"].encode("ascii")),
        windowSha256=p.sha(source["windowOriginal"].encode("ascii")),
        bootstrapObservationOriginal=source["observationOriginal"],
        **{name: window[name] for name in ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs")})
    early_raw = p.canonical({"payload": early, "signature": encoded(key_fixture("custody-supervisor-capability")[0].sign(
        p.preimage(scope.admission.BOOTSTRAP_DOMAIN, early)))})
    prior["driver-bootstrap"]["result"] = output(early_raw)
    native_launch = selected["prepared"]["native-launch-bridge"]
    bundle = json.loads(selected["bundleOriginal"])
    files = {"launch": native_launch, "c9-configuration": source["configurationOriginal"].encode("ascii"),
        "c9-delivery": common["delivery_raw"], "c9-runtime": source["runtimeOriginal"].encode("ascii"),
        "time-grant": f["value"]["serviceContext"]["grantOriginal"].encode("ascii")}
    for name, field in (("trust", "trust"), ("time", "timeBootstrap"), ("assignment", "assignment"),
            ("closure", "closure"), ("keys", "keys"), ("encrypted", "encryptedKeys"),
            ("admission", "admission"), ("verifier", "verifierTransport")):
        files[name] = bundle["originals"][field].encode("ascii")
    descriptors = [{"name": name, "device": 19, "inode": 20000 + index,
        "mode": stat.S_IFREG | 0o400, "uid": 0, "gid": 0, "length": len(raw)}
        for index, (name, raw) in enumerate(files.items())]
    for index, row in enumerate(c9["payload"]["credentials"]):
        descriptors.append({"name": "credential:" + row["name"], "device": 23, "inode": 30000 + index,
            "mode": stat.S_IFREG | 0o400, "uid": c9["payload"]["uid"], "gid": c9["payload"]["gid"], "length": row["length"]})
    descriptors.extend({"name": "activation:" + row["name"], "length": 0,
        **{name: row[name] for name in ("device", "inode", "mode", "uid", "gid")}} for row in c9["payload"]["activation"])
    operation = {"apiVersion": "serverware.nativeShadowDriverOperation/v1", "launch": installed["launch"],
        "descriptors": sorted(descriptors, key=lambda row: row["name"]), "production": common["measured"]["production"]}
    observations["release"] = {"operationOriginal": p.canonical(operation).decode("ascii")}
    return prior, observations, supervisor, f["clocks"]


def scope_case():
    records, observations, supervisor, clocks = copy.deepcopy(_scope_case())
    return case("driver-scope", records, observations, clocks, supervisor)


class AdoptedBridgeInputControls(unittest.TestCase):
    def test_exact_selected_inventory_and_no_lookalike_jobs(self):
        names = [name for name, (_, job) in profile.BY_NAME.items() if job.family in compiler._FIELDS
            or job.family in ("delivery", "launch") and job.role == "bridge"]
        self.assertEqual(len(names), 20)
        for name in names:
            self.assertIsInstance(compiler.selection_fields(profile.BY_NAME[name][1]), tuple)
        selected = profile.BY_NAME["driver-scope"][1]
        with self.assertRaises(ERRORS): compiler.selection_fields(type(selected)(*selected))
        with self.assertRaises(ERRORS): compiler.selection_fields(profile.BY_NAME["native-delivery-retrieval"][1])

    def test_all_eight_current_head_candidates_keep_exact_independent_decisions(self):
        for name in compiler.current_heads.JOB_NAMES:
            f, options = head_case(name)
            selected = {"currentness": json.loads(f["inputs"][name])["currentness"]}
            with self.subTest(name=name): self.assertEqual(compose(name, selected, options), f["inputs"][name])

    def test_currentness_missing_changed_or_wrong_request_refuses(self):
        name = compiler.current_heads.JOB_NAMES[0]
        f, options = head_case(name)
        currentness = json.loads(f["inputs"][name])["currentness"]
        for selection in ({}, {"currentness": {**currentness, "requestSha256": p.sha(b"different-request")}},
                {"currentness": currentness, "automaticCurrent": True}):
            with self.subTest(selection=tuple(selection)), self.assertRaises(ERRORS): compose(name, selection, options)
        with self.assertRaises(ERRORS):
            compose(name, {"currentness": currentness}, options | {"now_boottime_ns": f["context"]["deadline"]})

    def test_delivery_uses_actual_runtime_install_and_forty_one_activation_rows(self):
        name = "native-delivery-bridge"; f, options = bridge_case(name)
        self.assertEqual(compose(name, {"commissioningPolicy": f["common"]["fragment"]}, options),
            f["common"]["delivery_input_raw"])
        for mutation in ("activation", "installation"):
            changed = copy.deepcopy(options)
            if mutation == "activation": changed["observations"]["bridge-delivery"]["activation"].pop()
            else: changed["prior"]["install-bridge-runtime"]["result"]["bundleSha256"] = p.sha(b"different-install")
            with self.subTest(mutation=mutation), self.assertRaises(ERRORS):
                compose(name, {"commissioningPolicy": f["common"]["fragment"]}, changed)

    def test_all_five_authorization_candidates_preserve_signed_predecessors(self):
        for operation, name in compiler._authorization_names().items():
            f, options = bridge_case(name)
            with self.subTest(operation=operation):
                self.assertEqual(compose(name, {"commissioningPolicy": f["common"]["fragment"]}, options),
                    f["records"][operation]["inputOriginal"])

    def test_authorization_rebind_or_changed_signature_refuses(self):
        name = "native-key-admission-bridge"; f, options = bridge_case(name)
        for mutation in ("measured", "signature"):
            changed = copy.deepcopy(options)
            if mutation == "measured": changed["supervisor_observation"]["measuredConfiguration"]["configurationBindingSha256"] = p.sha(b"rebind")
            else:
                row = changed["prior"]["native-role-keys-bridge"]["result"]
                value = json.loads(row["original"]); value["signature"] = encoded(bytes(64))
                changed["prior"]["native-role-keys-bridge"]["result"] = output(p.canonical(value))
            with self.subTest(mutation=mutation), self.assertRaises(ERRORS):
                compose(name, {"commissioningPolicy": f["common"]["fragment"]}, changed)

    def test_launch_keeps_complete_authorizations_and_actual_time_grant(self):
        name = "install-launch-bridge"; f, options = bridge_case(name)
        selection = {"commissioningPolicy": f["common"]["fragment"]}
        self.assertEqual(compose(name, selection, options), p.canonical(f["value"]))
        changed = copy.deepcopy(options)
        row = changed["prior"]["native-service-trustedTime"]["result"]
        value = json.loads(row["original"]); value["signature"] = encoded(bytes(64))
        changed["prior"]["native-service-trustedTime"]["result"] = output(p.canonical(value))
        with self.assertRaises(ERRORS): compose(name, selection, changed)

    def test_scope_candidate_uses_verified_launch_and_selected_runtime_fourteen(self):
        options = scope_case(); raw = compose("driver-scope", {}, options)
        value = json.loads(raw)
        checked = scope.prepare_input(raw, **{name: options[name] for name in ("boot", "now_boottime_ns", "now_unix_ns")}, adopted=True)
        self.assertEqual(checked["payload"]["apiVersion"], "serverware.nativeShadowDriverScope/v4")
        self.assertEqual(json.loads(value["launchOriginal"])["apiVersion"], "serverware.nativeProofBridgeLaunch/v10")
        self.assertEqual(checked["payload"]["operation"], json.loads(options["observations"]["release"]["operationOriginal"]))
        with self.assertRaises(ERRORS):
            scope.prepare_input(raw, **{name: options[name] for name in ("boot", "now_boottime_ns", "now_unix_ns")})

    def test_scope_generation_substitution_or_installation_rebind_refuses(self):
        for mutation in ("grant", "launch"):
            options = scope_case()
            if mutation == "grant":
                role = g.ROLES[0]
                options["prior"]["ordinary-generation-" + role]["result"] = output(b"{}")
            else: options["prior"]["install-launch-bridge"]["result"]["launch"]["sha256"] = p.sha(b"other-launch")
            with self.subTest(mutation=mutation), self.assertRaises(ERRORS): compose("driver-scope", {}, options)

    def test_phase_two_reuses_exact_scope_bundle_without_new_configuration(self):
        options = scope_case(); raw = compose("driver-scope", {}, options)
        records = options["prior"] | {"driver-scope": record(raw)}
        names = [name for name, (_, job) in profile.BY_NAME.items() if job.family == "phase-two-public"]
        self.assertEqual(len(names), 1)
        next_options = case(names[0], records, options["observations"],
            {name: options[name] for name in ("boot", "now_boottime_ns", "now_unix_ns")}, options["supervisor_observation"])
        candidate = json.loads(compose(names[0], {}, next_options))
        self.assertEqual(candidate["publicBundleOriginal"], json.loads(raw)["publicBundleOriginal"])
        with self.assertRaises(ERRORS): compiler.phase_two.build(candidate["publicBundleOriginal"].encode("ascii"))
        with self.assertRaises(ERRORS): compose(names[0], {"replacementRuntime": "{}"}, next_options)

    def test_constructed_phase_projection_checks_signed_adopted_scope_without_relabel(self):
        # Exercise the real selected phase helper, not complete constructed
        # admission: no Nitro verifier/census result is fabricated here.
        options = scope_case(); raw = compose("driver-scope", {}, options); value = json.loads(raw)
        clocks = {name: options[name] for name in ("boot", "now_boottime_ns", "now_unix_ns")}
        prepared = scope.prepare_input(raw, **clocks, adopted=True)
        signed_scope = p.canonical({"payload": prepared["payload"], "signatureBase64url": encoded(
            key_fixture("phase")[0].sign(prepared["message"]))})
        launch_input = json.loads(options["prior"]["install-launch-bridge"]["input"])
        selected = compiler.launch.prepare_input(options["prior"]["install-launch-bridge"]["input"], **clocks)
        bundle = json.loads(selected["bundleOriginal"])
        exported = {"phaseScopeOriginal": signed_scope.decode("ascii"),
            "phaseBundleOriginal": value["publicBundleOriginal"], "bootstrapObservationOriginal": value["observationOriginal"],
            **{target: bundle["originals"][source] for target, source in (("closureOriginal", "closure"),
                ("assignmentOriginal", "assignment"), ("keyConfigurationOriginal", "keys"),
                ("admissionAuthorizationOriginal", "admission"))}}
        args = (value, exported, json.loads(launch_input["controlOriginal"]),
            json.loads(value["configurationOriginal"]), json.loads(value["deliveryConfigurationOriginal"]),
            prepared["window"], json.loads(value["observationOriginal"]))
        result, guest = driver_authority._phase(*args, adopted=True)
        self.assertEqual(result, signed_scope)
        self.assertEqual(guest["deliverySha256"], p.sha(json.loads(value["publicBundleOriginal"])["deliveryOriginal"].encode("ascii")))
        with self.assertRaises(ERRORS): driver_authority._phase(*args)
        bad = json.loads(signed_scope); bad["signatureBase64url"] = encoded(bytes(64))
        exported["phaseScopeOriginal"] = p.canonical(bad).decode("ascii")
        with self.assertRaises(ERRORS): driver_authority._phase(*args, adopted=True)

    def test_constructed_closure_uses_actual_v5_domain_and_hot12_assignment_leaf(self):
        f = bridge_fixture(); records = f["records"]
        pair = compiler.authorizations.keys.admitted_adopted_pair(
            records["role-keys"]["inputOriginal"], records["role-keys"]["authorizationOriginal"],
            records["admission"]["inputOriginal"], records["admission"]["authorizationOriginal"], **f["clocks"])
        exported = {"closureOriginal": records["closure"]["authorizationOriginal"].decode("ascii")}
        args = (exported, json.loads(f["source"]["ownerConfigurationOriginal"]),
            {"authorization": pair["authorization"]}, pair["expectedScope"],
            p.public_key(pair["authorityKeys"][-1]), f["clocks"]["now_unix_ns"],
            json.loads(f["common"]["recipe_originals"]["assignmentOriginal"]))
        expiry = driver_authority._closure(*args, adopted=True)
        self.assertGreater(expiry, f["clocks"]["now_unix_ns"])
        with self.assertRaises(ERRORS): driver_authority._closure(*args)
        bad = json.loads(exported["closureOriginal"]); bad["authorization"]["signature"] = encoded(bytes(64))
        exported["closureOriginal"] = p.canonical(bad).decode("ascii")
        with self.assertRaises(ERRORS): driver_authority._closure(*args, adopted=True)

    def test_origin_and_stop_are_exact_actions_not_success_or_permission(self):
        clocks = dict(boot=BOOT, now_boottime_ns=SECOND, now_unix_ns=100 * SECOND)
        origin = next(name for name, (_, job) in profile.BY_NAME.items() if job.family == "origin")
        self.assertEqual(compose(origin, {}, case(origin, {}, {}, clocks)), b'{"action":"observe-installed-generation"}')
        self.assertEqual(compose("stop", {"action": {"action": "stop"}}, case("stop", {}, {}, clocks)), b'{"action":"stop"}')
        with self.assertRaises(ERRORS): compose("stop", {}, case("stop", {}, {}, clocks))
        with self.assertRaises(ERRORS): compose("stop", {"action": {"action": "stop", "approved": True}}, case("stop", {}, {}, clocks))

    def test_interactive_action_is_copied_and_all_original_caps_remain(self):
        originals, production = window_fixture(); _, action, interval = interval_fixture()
        records = {"install-precreation": record(p.canonical(literal_rows(originals))),
            "endpoint-inputs": record(p.canonical({"production": production}))}
        # Explicit shape-only prior projections for the action reducer. These
        # placeholder signatures are never passed to a signature validator.
        common = {"issuedAtUnixNanos": 99 * SECOND, "expiresAtUnixNanos": 110 * SECOND}
        for name, payload in {"publication-adoption": {**common, "issuedAtBoottimeNanos": SECOND,
                "expiresAtBoottimeNanos": 8 * SECOND}, "driver-bootstrap": common, "driver-constructed": common}.items():
            records[name] = record(PADDING, output(p.canonical({"payload": payload, "signature": encoded(bytes(64))})))
        for role in g.ROLES:
            payload = {"serviceRole": role, "issuedAtBoottimeNanos": SECOND, "expiresAtBoottimeNanos": 7 * SECOND,
                "scope": {"installationIssuedAtUnixNanos": 99 * SECOND, "installationExpiresAtUnixNanos": 109 * SECOND}}
            records["ordinary-generation-" + role] = record(PADDING,
                output(p.canonical({"payload": payload, "signatureBase64url": encoded(bytes(64))})))
        options = case("stop", records, {"shutdown": {"originHandoff": interval["origin_handoff"]}},
            dict(boot=BOOT, now_boottime_ns=SECOND, now_unix_ns=100 * SECOND))
        self.assertEqual(compose("stop", {"action": action}, options), p.canonical(action))
        for change in ({"stopAtBoottimeNanos": 7 * SECOND}, {"expiresAtUnixNanos": 110 * SECOND},
                {"originHandoffSha256": p.sha(b"different-origin")}):
            with self.subTest(change=change), self.assertRaises(ERRORS):
                compose("stop", {"action": action | change}, options)

    def test_prefix_and_supervisor_source_are_required_not_inferred(self):
        name = "native-role-keys-bridge"; f, options = bridge_case(name)
        selection = {"commissioningPolicy": f["common"]["fragment"]}
        for mutation in ("prefix", "measured", "observation-api"):
            changed = copy.deepcopy(options)
            if mutation == "prefix": changed["prior"].pop(next(iter(changed["prior"])))
            elif mutation == "measured": changed["supervisor_observation"]["measuredConfiguration"] = None
            else: changed["supervisor_observation"]["apiVersion"] = "serverware.nativePilotSupervisorObservation/v1"
            with self.subTest(mutation=mutation), self.assertRaises(ERRORS): compose(name, selection, changed)


if __name__ == "__main__":
    unittest.main()
