#!/usr/bin/env python3
"""Cold owner-action candidate controls, never owner or installation receipts.

The consumed authority originals carry the existing fixtures' real-format
synthetic signatures. Measured process/FD/cgroup facts are labelled synthetic
public observations. No constructor, protected writer, native process, private
key loader, or successful validator is mocked or invoked. Unexamined prior
positions remain explicit padding, not an asserted completed ceremony.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from catchplate import native_pilot_genesis_owner_inputs as compiler
from catchplate import native_pilot_genesis_jobs as jobs
from catchplate import native_pilot_genesis_execution_protocol as wire
import test_native_pilot_genesis_jobs as job_tests
import test_native_pilot_genesis_native_inputs as native_tests
import test_native_pilot_genesis_ordinary_inputs as ordinary_inputs
import test_native_pilot_genesis_ordinary_runtime as ordinary_tests
import test_native_pilot_genesis_coordinator_assembly as assembly_tests

p, g = jobs.p, jobs.g
ERRORS = (ValueError, KeyError, TypeError, InvalidSignature)
CATALOGUE = jobs.catalogue(handoff=True)


def prefix(name, records):
    before = CATALOGUE[:CATALOGUE.index(jobs.job(name, handoff=True))]
    return {row.name: records.get(row.name, job_tests.record(job_tests.PADDING, job_tests.PADDING)) for row in before}


def configuration(parent, clocks):
    payload = g.document(parent["precreation_raw"], jobs.parent.MAX_OUTPUT)["payload"]
    raw = g.canonical({"apiVersion": wire.HANDOFF_CONFIGURATION_API,
        "window": {name: payload[name] for name in wire.endpoints.WINDOW},
        "expiresAtUnixNanos": clocks["now_unix_ns"] + 1_000_000_000,
        "coreHandoff": {"peerPid": 123, "peerUid": 0, "peerGid": 0}})
    return wire.configuration(raw, handoff=True, **clocks)


def fixture():
    """Authentic synthetic source chain and measured-public assembly facts."""
    native = native_tests.fixture()
    prior, observations, clocks = native["prior"], native["observations"], native["clocks"]
    ordinary = ordinary_tests.fixture()
    parent = ordinary["f"]["parent"]
    assert observations["parent.precreation"] == parent["precreation_raw"]
    prior.update(job_tests.static_records(native["base"]["coldBindingInputOriginal"], clocks))
    prior["parent-precreation"] = job_tests.record(g.canonical(parent["pre_input"]), parent["precreation_raw"])
    configured = configuration(parent, clocks)
    runtime = g.document(observations["coordinator.runtime"], g.MAX_BYTES)
    for role, field in zip(jobs.ORDINARY, ("durableGrantOriginal", "currentGrantOriginal"), strict=True):
        delivery_input = g.canonical(ordinary["delivery_inputs"][role])
        prior["ordinary-runtime-" + role] = job_tests.record(delivery_input, ordinary["runtimes"][role])
        prior["ordinary-delivery-" + role] = job_tests.record(delivery_input, ordinary["deliveries"][role])
        observations["ordinary.activation." + role] = g.canonical(ordinary["delivery_inputs"][role]["activation"])
        grant = copy.deepcopy(ordinary["grants"][role])
        grant.update(coldBindingInputOriginal=native["base"]["coldBindingInputOriginal"].decode("ascii"),
            coldBindingInputSha256=native["base"]["coldBindingInputSha256"],
            nativePublicationOriginal=prior["native-publication-grant"]["result"].decode("ascii"),
            nativeRetrievalOriginal=prior["native-retrieval-grant"]["result"].decode("ascii"))
        raw, signed = g.canonical(grant), runtime[field].encode("ascii")
        jobs.ordinary.checked_result("grant", raw, {"original": signed.decode("ascii"), "sha256": p.sha(signed)}, **clocks)
        prior["ordinary-grant-" + role] = job_tests.record(raw, signed)
    peers = {row["serviceRole"]: row["expectedPeer"] for row in runtime["serviceSessions"]}
    peers.update({role: row["expectedPeer"] for role, row in zip(jobs.service.ENDPOINTS, runtime["nativeEndpoints"], strict=True)})
    peers["resultPeer"] = runtime["resultPeer"]
    pins = {field: p.sha(observations[name]) for field, name in (
        ("parentConfigurationSha256", "parent.configuration"), ("parentPrecreationSha256", "parent.precreation"),
        ("ordinaryConfigurationSha256", "ordinary.configuration"), ("endpointConfigurationSha256", "endpoints.configuration"))}
    observed = {"apiVersion": compiler.assembly.OBSERVATION, **pins, "window": configured["window"],
        "observedAtBoottimeNs": str(clocks["now_boottime_ns"]),
        "peers": {role: assembly_tests.measured(peers[role], index) for index, role in enumerate(compiler.assembly.ROLES)},
        "activation": jobs.delivery._activation(observations["coordinator.activation"])}
    observations["coordinator.observation"] = g.canonical(observed)
    selections = {name: {} for name in compiler.NAMES}
    selections["parent-start"] = {"controllerExecutableSha256": p.sha(b"SYNTHETIC selected controller executable")}
    selections["ordinary-prepare"] = {"launchOriginal": observations["ordinary.configuration"].decode("ascii")}
    selections["endpoints-prepare"] = {"configurationOriginal": observations["endpoints.configuration"].decode("ascii")}
    selections["coordinator-assemble"] = {"peers": {role: {name: peers[role][name] for name in compiler.LABEL_FIELDS}
        for role in compiler.assembly.ROLES}}
    parent_control = compiler.compose(jobs.job("parent-start"), selections["parent-start"],
        prior=prefix("parent-start", prior), observations=observations, execution_configuration=configured, **clocks)
    prior["parent-start"] = job_tests.record(parent_control["inputOriginal"], job_tests.PADDING)
    return dict(prior=prior, observations=observations, clocks=clocks, configuration=configured,
        selections=selections, expected_peers=peers, native=native)


class GenesisOwnerInputControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = fixture()
        cls.public = ordinary_inputs.fixture()

    def compose(self, name, *, selection=None, prior=None, observations=None, configured=None, clocks=None):
        return compiler.compose(jobs.job(name, handoff=True), self.f["selections"][name] if selection is None else selection,
            prior=prefix(name, self.f["prior"] if prior is None else prior),
            observations=self.f["observations"] if observations is None else observations,
            execution_configuration=self.f["configuration"] if configured is None else configured,
            **(self.f["clocks"] if clocks is None else clocks))

    def refused(self, name, **changes):
        with self.assertRaises(ERRORS): self.compose(name, **changes)

    def test_exact_owner_inventory_and_closed_static_fragments(self):
        self.assertEqual(len(compiler.NAMES), 21)
        self.assertEqual(compiler.NAMES, tuple(row.name for row in CATALOGUE if row.family == "owner"))
        selected = {name: compiler.selection_fields(jobs.job(name, handoff=True)) for name in compiler.NAMES}
        self.assertEqual({name for name, fields in selected.items() if fields},
            {"parent-start", "ordinary-prepare", "endpoints-prepare", "coordinator-assemble"})
        for name in compiler.NAMES:
            extra = copy.deepcopy(self.f["selections"][name]); extra["ready"] = True
            with self.subTest(job=name): self.refused(name, selection=extra)
        with self.assertRaises(ValueError): compiler.selection_fields(jobs.job("parent-precreation"))

    def test_three_preparation_candidates_pin_actual_literals_and_controller(self):
        parent = g.document(self.compose("parent-start")["inputOriginal"], 4096)
        ordinary = g.document(self.compose("ordinary-prepare")["inputOriginal"], 4096)
        endpoints = g.document(self.compose("endpoints-prepare")["inputOriginal"], 4096)
        self.assertEqual(parent["configurationSha256"], p.sha(self.f["observations"]["parent.configuration"]))
        self.assertEqual(parent["precreationSha256"], p.sha(self.f["prior"]["parent-precreation"]["result"]))
        self.assertEqual(ordinary["launchConfigurationSha256"], p.sha(self.f["observations"]["ordinary.configuration"]))
        self.assertEqual(ordinary["parentPrecreationSha256"], parent["precreationSha256"])
        self.assertEqual(endpoints["configurationSha256"], p.sha(self.f["observations"]["endpoints.configuration"]))
        self.assertEqual(endpoints["controllerExecutableSha256"], parent["controllerExecutableSha256"])
        for name in ("parent-start", "ordinary-prepare", "endpoints-prepare"):
            self.assertEqual(set(self.compose(name)), {"inputOriginal", "deadline", "epochLimit"})

    def test_preparation_rejects_window_extension_signature_and_controller_pin_drift(self):
        changed = copy.deepcopy(self.f["configuration"])
        changed["window"]["startupDeadlineBoottimeNs"] = str(int(changed["window"]["startupDeadlineBoottimeNs"]) + 1)
        for name in ("parent-start", "ordinary-prepare", "endpoints-prepare"):
            with self.subTest(job=name): self.refused(name, configured=changed)
        prior = copy.deepcopy(self.f["prior"])
        signed = g.document(prior["parent-precreation"]["result"], jobs.parent.MAX_OUTPUT)
        signed["signatureBase64url"] = p.encoded(bytes(64))
        prior["parent-precreation"]["result"] = g.canonical(signed)
        self.refused("parent-start", prior=prior)
        prior = copy.deepcopy(self.f["prior"])
        control = g.document(prior["parent-start"]["input"], 4096)
        control["precreationSha256"] = p.sha(b"another parent")
        prior["parent-start"]["input"] = g.canonical(control)
        self.refused("endpoints-prepare", prior=prior)

    def test_store_initialization_uses_exact_authenticated_proof_scope_not_a_head(self):
        result = self.compose("initialize-retrieval-store")
        bound = jobs.binding.result_document(self.f["prior"]["cold-binding"]["result"])
        self.assertEqual(result["inputOriginal"], bound["proofScopeOriginal"].encode("ascii"))
        self.assertEqual(result["deadline"], p.ns(bound["deadlineBoottimeNs"]))
        self.assertEqual(result["epochLimit"], bound["expiresAtUnixNanos"])
        prior = copy.deepcopy(self.f["prior"])
        prior["cold-binding"]["result"] += b" "
        self.refused("initialize-retrieval-store", prior=prior)

    def test_all_three_native_installations_consume_exact_predecessor_pairs(self):
        for role in jobs.NATIVE:
            name = "install-launch-" + role
            with self.subTest(role=role):
                result = self.compose(name)
                selected = wire.native_install(result["inputOriginal"], role, self.f["prior"])
                prior = self.f["prior"]["native-launch-" + role]
                self.assertEqual(selected["launchInputOriginal"].encode("ascii"), prior["input"])
                self.assertEqual(selected["bundleOriginal"].encode("ascii"), prior["result"])
                self.assertLess(self.f["clocks"]["now_boottime_ns"], result["deadline"])
                tampered = copy.deepcopy(self.f["prior"])
                tampered["native-launch-" + role]["result"] += b" "
                self.refused(name, prior=tampered)

    def test_public_install_actions_require_authenticated_fixed_plans(self):
        # This separate public-path fixture re-signs the actual C9/grants;
        # it is not silently merged with another successful native ceremony.
        for name in ("install-precreation", *("install-ordinary-" + role for role in jobs.ORDINARY)):
            with self.subTest(job=name):
                result = self.compose(name, prior=self.public["records"], observations=self.public["observations"],
                    clocks=self.public["clocks"])
                self.assertEqual(wire.owner_action(result["inputOriginal"], name)["action"], name)
                self.assertIsNotNone(result["deadline"]); self.assertIsNotNone(result["epochLimit"])
        changed = copy.deepcopy(self.public["records"])
        changed["ordinary-grant-" + jobs.ORDINARY[0]]["result"] = job_tests.PADDING
        self.refused("install-ordinary-" + jobs.ORDINARY[0], prior=changed, observations=self.public["observations"])

    def test_coordinator_candidate_derives_all_measured_peers_and_root_result(self):
        result = self.compose("coordinator-assemble")
        approved = compiler.assembly.approval(result["inputOriginal"])
        self.assertEqual(approved["peers"], self.f["expected_peers"])
        self.assertEqual((approved["peers"]["resultPeer"]["uid"], approved["peers"]["resultPeer"]["gid"]), (0, 0))
        self.assertTrue(all(approved["peers"][role]["uid"] > 0 for role in compiler.assembly.ROLES[:-1]))
        self.assertLessEqual(result["deadline"], p.ns(self.f["configuration"]["window"]["startupDeadlineBoottimeNs"]))
        self.assertNotIn("runtimeOriginal", result)  # The genuine owner produces the runtime observation.
        self.assertNotIn("approved", result)

    def test_coordinator_requires_both_signatures_exact_activation_and_source_pins(self):
        for name in ("ordinary-grant-" + jobs.ORDINARY[0], "native-publication-grant"):
            prior = copy.deepcopy(self.f["prior"])
            signed = g.document(prior[name]["result"], g.MAX_BYTES)
            field = "signatureBase64url" if name.startswith("ordinary") else "signature"
            signed[field] = p.encoded(bytes(64)); prior[name]["result"] = g.canonical(signed)
            with self.subTest(job=name): self.refused("coordinator-assemble", prior=prior)
        for field in ("parentConfigurationSha256", "activation"):
            observed = copy.deepcopy(self.f["observations"])
            value = compiler.assembly.observation(observed["coordinator.observation"])
            if field == "activation": value[field][0]["inode"] += 1
            else: value[field] = p.sha(b"another parent")
            observed["coordinator.observation"] = g.canonical(value)
            with self.subTest(field=field): self.refused("coordinator-assemble", observations=observed)

    def test_coordinator_selection_cannot_override_measured_identity_or_add_role(self):
        for role in compiler.assembly.ROLES:
            selection = copy.deepcopy(self.f["selections"]["coordinator-assemble"])
            selection["peers"][role]["pid"] = 456
            with self.subTest(role=role): self.refused("coordinator-assemble", selection=selection)
        selection = copy.deepcopy(self.f["selections"]["coordinator-assemble"])
        selection["peers"]["caller-chosen-service"] = selection["peers"]["resultPeer"]
        self.refused("coordinator-assemble", selection=selection)

    def test_remaining_actions_are_only_exact_requests_not_owner_results(self):
        special = {"parent-start", "ordinary-prepare", "endpoints-prepare", "initialize-retrieval-store", "coordinator-assemble",
            "install-precreation", *("install-ordinary-" + role for role in jobs.ORDINARY),
            *("install-launch-" + role for role in jobs.NATIVE)}
        for name in set(compiler.NAMES) - special:
            with self.subTest(job=name):
                result = self.compose(name)
                self.assertEqual(result, {"inputOriginal": g.canonical({"apiVersion": wire.ACTION_API, "action": name}),
                    "deadline": None, "epochLimit": None})
        self.assertIn("acquire-cold-core", compiler.NAMES)
        self.assertIn("handoff-cold-core", compiler.NAMES)

    def test_derived_startup_and_native_epoch_limits_are_not_renewed(self):
        clocks = {**self.f["clocks"], "now_boottime_ns": p.ns(self.f["configuration"]["window"]["startupDeadlineBoottimeNs"])}
        for name in ("parent-start", "ordinary-prepare", "endpoints-prepare", "coordinator-assemble"):
            with self.subTest(job=name): self.refused(name, clocks=clocks)
        result = self.compose("install-launch-" + jobs.NATIVE[0])
        self.refused("install-launch-" + jobs.NATIVE[0], clocks={**self.f["clocks"], "now_unix_ns": result["epochLimit"]})


if __name__ == "__main__":
    unittest.main()
