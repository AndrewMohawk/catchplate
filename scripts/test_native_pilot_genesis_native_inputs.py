#!/usr/bin/env python3
"""Pure candidate controls over authentic, explicitly synthetic signed sources.

No owner, filesystem resource, ciphertext decryption, installed package or
approval is manufactured. Existing fixture keys sign only synthetic public
transcripts. Unexamined catalogue records are labelled padding, never evidence
of successful preparation. No validator is mocked or replaced.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from serverware import native_pilot_genesis_native_inputs as compiler
from serverware import native_pilot_genesis_jobs as jobs
from serverware import native_pilot_genesis_launch_install as installation
import test_native_pilot_genesis_key_authority as key_tests
import test_native_pilot_genesis_launch as launch_tests
import test_native_pilot_genesis_ordinary_runtime as ordinary_tests
import test_native_pilot_genesis_transport_authority as transport_tests

p, g = jobs.p, jobs.g
ERRORS = (ValueError, KeyError, TypeError, InvalidSignature)
PADDING = b'{"testOnly":"unexamined catalogue position, not an owner receipt"}'


def record(raw, result):
    return {"input": raw, "result": result}


def prefix(name, prior):
    before = jobs.JOBS[:jobs.JOBS.index(jobs.job(name))]
    return {row.name: prior.get(row.name, record(PADDING, PADDING)) for row in before}


def fixed_row(base, role, runtime_raw=None):
    """Re-sign exact synthetic C9 after choosing actual installer destinations."""
    row = transport_tests.attach_ciphertext(base, role, runtime_raw=runtime_raw)
    payload = g.document(row["delivery"]["raw"], 65536)["payload"]
    payload["runtimeConfig"]["path"] = installation.DESTINATIONS[role]["runtime"]
    payload["credentials"][0]["original"]["path"] = installation.DESTINATIONS[role]["encryptedInventory"]
    delivery = transport_tests.replace_c9(row["delivery"], payload)
    pair = transport_tests.rebind_pair(base, role, delivery)
    row.update(delivery=delivery, pair=pair)
    clocks = transport_tests.clocks_for(base)
    for kind, module, api, domain in (
            ("encrypted", jobs.encrypted, "serverware.nativeShadowEncryptedKeyDelivery/v1", transport_tests.ENCRYPTED_DOMAIN),
            ("verifier", jobs.verifier, "serverware.nativeShadowVerifierTransport/v1", transport_tests.VERIFIER_DOMAIN)):
        value = module.input_document(row[kind + "_input_raw"])
        value.update({name: raw.decode("ascii") for name, raw in pair.items()})
        raw = p.canonical(value)
        prepared = module.prepare_input(role, raw, **clocks)
        row[kind + "_input_raw"] = raw
        row[kind + "_raw"] = transport_tests.independent_signed(api, domain, prepared["payload"], base["supervisor_key"])
    return row


def fixture():
    base = key_tests.fixture()
    clocks = transport_tests.clocks_for(base)
    rows = {role: fixed_row(base, role) for role in jobs.NATIVE[:2]}
    services = launch_tests._native_grants(base, rows, clocks)
    runtime = launch_tests._coordinator_runtime(base, rows, services, clocks)
    rows[jobs.COORDINATOR] = fixed_row(base, jobs.COORDINATOR, runtime)
    prior, observations, selections, expected = {}, {}, {}, {}
    binding = base["coldBindingInputOriginal"]
    prior["cold-binding"] = record(binding, jobs.binding.prepare(binding,
        expected_input_sha256=p.sha(binding), **clocks))
    for role, row in rows.items():
        source = row["delivery"]
        input_value = source["input"]
        for field, name in jobs.PARENTS.items():
            raw = input_value["parentOriginals"][field].encode("ascii")
            assert observations.get(name, raw) == raw
            observations[name] = raw
        if role != jobs.COORDINATOR:
            for field, name in (("ownerConfigurationOriginal", "endpoints.configuration"),
                    ("preparationOriginal", "endpoints.preparation"), ("resourcesOriginal", "endpoints.resources")):
                raw = input_value[field].encode("ascii")
                assert observations.get(name, raw) == raw
                observations[name] = raw
            observations["endpoints.activation." + role] = input_value["activationOriginal"].encode("ascii")
        else:
            observations["coordinator.runtime"] = input_value["runtimeOriginal"].encode("ascii")
            observations["coordinator.activation"] = input_value["activationOriginal"].encode("ascii")
        delivery_name = "native-delivery-" + role
        payload = g.document(input_value["payloadOriginal"].encode("ascii"), 65536)
        selection = {"credentials": payload["credentials"]}
        selection.update({"image": input_value["image"]} if role == jobs.COORDINATOR else
            {"configurationOriginal": input_value["configurationOriginal"]})
        selections[delivery_name] = selection
        expected[delivery_name] = p.canonical(input_value)
        prior[delivery_name] = record(expected[delivery_name], source["raw"])
        for operation, prefix_name in (("role-keys", "roleKey"), ("admission", "admission")):
            name = "native-" + operation + "-" + role
            raw = row["pair"][prefix_name + "InputOriginal"]
            value = jobs.keys.input_document(raw)
            selections[name] = value["policy"] if operation == "role-keys" else {}
            expected[name] = raw
            prior[name] = record(raw, row["pair"][prefix_name + "Original"])
        value, old_launch = launch_tests._input(base, role, row, services, clocks)
        for kind in jobs.launch.AUTHORIZATIONS:
            name = "native-" + kind + "-" + role
            raw = value["authorizations"][kind]["inputOriginal"].encode("ascii")
            original = value["authorizations"][kind]["authorizationOriginal"].encode("ascii")
            parsed = p.document(raw, jobs.job(name).maximum)
            selections[name] = (parsed["policy"] if kind == "closure" else
                {field: parsed[field] for field in compiler.selection_fields(jobs.job(name))})
            expected[name] = raw
            prior[name] = record(raw, original)
        # Independent expected launch construction changes only fixed public
        # destination paths; the full issuer then authenticates every original.
        for component, pin in value["pins"].items():
            if component not in installation.PREREQUISITES:
                pin["path"] = installation.DESTINATIONS[role][component]
        native = g.document(old_launch, 32768)
        native["keyAdmission"].update({name: value["pins"][name] for name in jobs.launch.INNER})
        operation = jobs.launch.SELECTORS[role][1]
        if operation: native[operation] = value["pins"]["serviceGrant"]
        value["pins"]["launch"]["sha256"] = p.sha(g.canonical(native))
        raw = p.canonical(value)
        bundle = jobs.launch.prepare_input(role, raw, **clocks)["bundleOriginal"]
        name = "native-launch-" + role
        selections[name] = {"timeBootstrap": value["timeBootstrap"], "trustPath": value["pins"]["trust"]["path"]}
        expected[name] = raw
        prior[name] = record(raw, bundle)
    ordinary = ordinary_tests.fixture()
    current = ordinary["delivery_inputs"][jobs.ORDINARY[0]]
    publication_input = jobs.service.input_document(services["publication"]["inputOriginal"].encode("ascii"))
    for field in ("runtimePolicy", "source", "historyOriginals"):
        assert current[field] == publication_input["ordinary"][field]
    for field in ("expectedPeer", "coordinatorPeerPreparationOriginal"):
        assert current[field] == publication_input[field]
    for role in jobs.ORDINARY:
        prior["initial-assemble-" + role] = record(PADDING, current["historyOriginals"][role].encode("ascii"))
    prior["ordinary-runtime-" + jobs.ORDINARY[0]] = record(g.canonical(current), ordinary["runtimes"][jobs.ORDINARY[0]])
    for field, name in (("launchOriginal", "ordinary.configuration"), ("preparationOriginal", "ordinary.preparation"),
            ("resourcesOriginal", "ordinary.resources")):
        observations[name] = current["source"][field].encode("ascii")
    observations["parent.peer"] = current["coordinatorPeerPreparationOriginal"].encode("ascii")
    for operation, row in services.items():
        raw = row["inputOriginal"].encode("ascii")
        value = jobs.service.input_document(raw)
        name = "native-" + operation + "-grant"
        selections[name] = value["window"]
        expected[name] = raw
        prior[name] = record(raw, row["grantOriginal"].encode("ascii"))
        if operation == "retrieval":
            observations["endpoints.store"] = value["retrievalStoreObservationOriginal"].encode("ascii")
    selections["endpoint-release"] = {}
    return dict(base=base, rows=rows, prior=prior, observations=observations,
        selections=selections, expected=expected, clocks=clocks)


class GenesisNativeInputControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = fixture()

    def compose(self, name, *, selection=None, prior=None, observations=None, clocks=None):
        return compiler.compose(jobs.job(name), self.f["selections"][name] if selection is None else selection,
            prior=self.f["prior"] if prior is None else prior,
            observations=self.f["observations"] if observations is None else observations,
            **(self.f["clocks"] if clocks is None else clocks))

    def same(self, names):
        for name in names:
            with self.subTest(job=name):
                raw = self.compose(name)
                self.assertEqual(raw, self.f["expected"][name])
                jobs.prepare_input(name, raw, prior=prefix(name, self.f["prior"]),
                    observations=self.f["observations"], **self.f["clocks"])

    def test_all_native_families_have_closed_selection_fields(self):
        selected = [job for job in jobs.JOBS if job.family in compiler.FAMILIES]
        self.assertEqual(set(row.family for row in selected), set(compiler.FAMILIES))
        self.assertEqual(set(self.f["selections"]), {row.name for row in selected})
        for row in selected:
            self.assertEqual(set(compiler.selection_fields(row)), set(self.f["selections"][row.name]))

    def test_c9_all_three_uses_exact_observations_and_fixed_runtime_paths(self):
        self.same("native-delivery-" + role for role in jobs.NATIVE)

    def test_role_keys_and_admission_preserve_prior_policy_and_actual_signatures(self):
        self.same("native-" + operation + "-" + role for role in jobs.NATIVE for operation in ("role-keys", "admission"))

    def test_closure_all_three_preserves_exact_delivery_and_binding(self):
        self.same("native-closure-" + role for role in jobs.NATIVE)

    def test_encrypted_and_verifier_require_provisioned_ciphertext_and_prior_pair(self):
        self.same("native-" + operation + "-" + role for role in jobs.NATIVE
            for operation in ("encrypted-delivery", "verifier-transport"))

    def test_native_grants_use_actual_first_runtime_and_observed_store(self):
        self.same("native-" + operation + "-grant" for operation in jobs.service.OPERATIONS)

    def test_launch_all_three_is_accepted_by_actual_installation_input_checker(self):
        for role in jobs.NATIVE:
            name = "native-launch-" + role
            raw = self.compose(name)
            self.assertEqual(raw, self.f["expected"][name])
            installation.prepare_input(role, p.canonical({"apiVersion": installation.API, "role": role,
                "launchInputOriginal": raw.decode("ascii"),
                "bundleOriginal": self.f["prior"][name]["result"].decode("ascii")}), **self.f["clocks"])

    def test_endpoint_release_has_only_literal_authenticated_launch_sources(self):
        raw = self.compose("endpoint-release")
        prepared = jobs.prepare_input("endpoint-release", raw, prior=prefix("endpoint-release", self.f["prior"]),
            observations=self.f["observations"], **self.f["clocks"])
        self.assertGreater(prepared["deadline"], self.f["clocks"]["now_boottime_ns"])
        value = jobs.endpoint_release.input_document(raw)
        for role in jobs.NATIVE[:2]:
            bundle = p.document(self.f["prior"]["native-launch-" + role]["result"], jobs.launch.MAX_OUTPUT)
            self.assertEqual(value["services"][role]["launchOriginal"], bundle["launchOriginal"])

    def test_unknown_selection_cannot_override_observed_runtime_or_payload(self):
        name = "native-delivery-" + jobs.COORDINATOR
        for field in ("runtimeOriginal", "payloadOriginal", "activationOriginal", "role"):
            with self.subTest(field=field), self.assertRaises(ERRORS):
                self.compose(name, selection={**self.f["selections"][name], field: "unapproved override"})
        with self.assertRaises(ERRORS):
            compiler.compose(jobs.job("parent-precreation"), {}, prior={}, observations={}, **self.f["clocks"])

    def test_missing_or_modified_retrieval_store_is_not_synthesized(self):
        for remove in (True, False):
            observed = dict(self.f["observations"])
            if remove: del observed["endpoints.store"]
            else:
                value = g.document(observed["endpoints.store"], 65536)
                value["store"]["headSha256"] = p.sha(b"another synthetic head")
                observed["endpoints.store"] = g.canonical(value)
            with self.subTest(remove=remove), self.assertRaises(ERRORS):
                self.compose("native-retrieval-grant", observations=observed)

    def test_modified_actual_activation_or_prior_signature_is_refused(self):
        role = jobs.NATIVE[0]
        observed = dict(self.f["observations"])
        activation = jobs.delivery._activation(observed["endpoints.activation." + role])
        activation[0]["inode"] += 1
        observed["endpoints.activation." + role] = g.canonical(activation)
        with self.assertRaises(ERRORS): self.compose("native-delivery-" + role, observations=observed)
        prior = copy.deepcopy(self.f["prior"])
        name = "native-role-keys-" + role
        signed = g.document(prior[name]["result"], jobs.keys.MAX_OUTPUT)
        signed["signature"] = p.encoded(bytes(64))
        prior[name]["result"] = g.canonical(signed)
        with self.assertRaises(ERRORS): self.compose("native-admission-" + role, prior=prior)

    def test_original_clock_expiry_and_static_policy_renewal_are_refused(self):
        name = "native-closure-" + jobs.NATIVE[0]
        selection = dict(self.f["selections"][name])
        selection["expiresAtUnixNanos"] += 300_000_000_000
        with self.assertRaises(ERRORS): self.compose(name, selection=selection)
        clocks = dict(self.f["clocks"], now_boottime_ns=1 << 62)
        with self.assertRaises(ERRORS): self.compose(name, clocks=clocks)
        with self.assertRaises(ERRORS):
            self.compose("native-admission-" + jobs.NATIVE[0], selection={"policy": self.f["selections"][name]})


if __name__ == "__main__":
    unittest.main()
