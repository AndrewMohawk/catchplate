#!/usr/bin/env python3
"""Pure compiler framing with signed synthetic bootstrap and recipe originals.

No deployed supervisor, approvals or successful native adoption is simulated.
Late catalogue coverage below checks selectors, not a complete 176-job run.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
from scripts import test_native_pilot_lifecycle_inputs as fixture_source
from scripts.test_native_pilot_generation_scope import key_fixture
from scripts.test_native_pilot_adopted_cohort_authority import fixture as cohort_fixture, release_fixture
from serverware import native_pilot_adopted_inputs as compiler

p, profile, context = compiler.p, compiler.profile, compiler.context
ERRORS = (ValueError, InvalidSignature)


def fixture(parent):
    source = fixture_source.fixture(parent)
    lifecycle = fixture_source.bootstrap(source)
    recipe = source["recipe"]
    bootstrap = recipe["bootstrapOriginals"]
    config, control = (json.loads(bootstrap[name]) for name in ("configuration", "control"))
    window = json.loads(bootstrap["window"])["payload"]
    bridge, _, _ = fixture_source.signed.fixture()
    observed = json.loads(bridge["deliveryInputOriginal"])["observationOriginal"]
    authority = config["lifecycle"]["constructedAdmissionAuthority"]
    now = source["clocks"]["now_unix_ns"]
    payload = {"apiVersion": "serverware.nativeShadowBootstrapDriverAdmission/v1",
        "purpose": "native-driver-bootstrap-admission", "configurationSha256": control["configurationSha256"],
        "windowSha256": control["windowSha256"], "bootstrapObservationOriginal": observed,
        "parent": {"processId": 42, "startTimeTicks": 99, "parentId": 2, "pidfdDevice": 0, "pidfdInode": 77},
        "parentExecutableSha256": control["supervisorExecutableSha256"], "pidNamespaceSha256": p.sha(b"synthetic pid namespace"),
        "issuedAtUnixNanos": now - 1_000_000_000, "expiresAtUnixNanos": now + 29_000_000_000,
        **{name: window[name] for name in ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs")},
        "signingKeyId": authority["keyId"], "signingKeySpkiSha256": authority["keySpkiSha256"]}
    parameters = {name + "_original": lifecycle["originals"][name] for name in ("policy", "recipe")}
    parameters.update({name + "_sha256": lifecycle["pins"][name] for name in ("policy", "recipe")})
    parameters.update(prior={}, observations={}, cold_prior={}, **source["clocks"])
    selected_policy = compiler.policy.shape(parameters["policy_original"])
    conductor = {"apiVersion": "serverware.nativePilotOperatorRequest/v2", "sequence": 1,
        "phase": "bootstrap-admission", "payload": {"bootstrapObservationOriginal": observed,
            "admissionPayloadOriginal": p.canonical(payload).decode("ascii")},
        "deadlineBoottimeNs": str(lifecycle["deadline"]), "expiresAtUnixNanos": str(lifecycle["epochLimit"])}
    return dict(parameters=parameters, conductor=conductor, policy=selected_policy, payload=payload)


def pending(f, *, ticket_changes=None, observation_changes=None):
    conductor_raw = p.canonical(f["conductor"])
    observed = {"apiVersion": "serverware.nativePilotAdoptedSupervisorObservation/v1",
        "policySha256": f["parameters"]["policy_sha256"], "catalogueSha256": f["policy"]["catalogueSha256"],
        "intakeConfigurationSha256": f["policy"]["intakeConfigurationSha256"],
        "conductorRequestOriginal": conductor_raw.decode("ascii"), "measuredConfiguration": None, "recipeOriginals": None}
    observed.update(observation_changes or {})
    ticket = {"apiVersion": profile.API, "sequence": 1, "conductorSequence": 1,
        "conductorRequestSha256": p.sha(conductor_raw), "phase": "bootstrap-admission", "jobIndex": 1,
        "job": "driver-bootstrap", "deadlineBoottimeNs": f["conductor"]["deadlineBoottimeNs"],
        "expiresAtUnixNanos": f["conductor"]["expiresAtUnixNanos"],
        "conductorRequest": copy.deepcopy(f["conductor"]), "previousResult": None}
    ticket.update(ticket_changes or {})
    request_raw, observed_raw = p.canonical(ticket), p.canonical(observed)
    return {"phase": ticket["phase"], "job": ticket["job"], "sequence": ticket["sequence"],
        "status": "awaiting-independent-job-approval", "requestOriginal": request_raw.decode("ascii"),
        "requestSha256": p.sha(request_raw), "observationOriginal": observed_raw.decode("ascii"),
        "observationSha256": p.sha(observed_raw)}


class AdoptedInputControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="adopted-inputs-fixture-")
        cls.addClassCleanup(temporary.cleanup)
        cls.addClassCleanup(fixture_source.runtime_fixture.thaw, Path(temporary.name))
        cls.source = fixture(Path(temporary.name))

    def test_exact_catalogue_has_closed_selection_for_every_job(self):
        self.assertEqual(len(context.CATALOGUE), 176)
        for _, job in context.CATALOGUE:
            fields = compiler.selection_fields(job.name)
            self.assertIs(type(fields), tuple)
            self.assertEqual(len(fields), len(set(fields)))
        with self.assertRaises(ValueError): compiler.selection_fields("unknown-job")

    def test_bootstrap_candidate_uses_exact_policy_and_observation(self):
        f = copy.deepcopy(self.source)
        before = copy.deepcopy(f)
        packet = pending(f)
        result = compiler.compose(packet, {}, **f["parameters"])
        value = p.document(result["inputOriginal"], profile.MAX_FRAME)
        self.assertEqual(value["payloadOriginal"], f["conductor"]["payload"]["admissionPayloadOriginal"])
        for name, original in f["policy"]["bootstrapOriginals"].items():
            self.assertEqual(value[name + "Original"], original)
        self.assertEqual(result["inputSha256"], p.sha(result["inputOriginal"]))
        self.assertEqual(result["observations"], {"bootstrap-admission": packet["observationOriginal"].encode("ascii")})
        self.assertEqual(result["deadline"], int(f["conductor"]["deadlineBoottimeNs"]))
        self.assertEqual(f, before)

    def test_request_and_observation_original_pins_are_not_optional(self):
        for field in ("requestSha256", "observationSha256"):
            packet = pending(self.source); packet[field] = p.sha(b"different")
            with self.subTest(field=field), self.assertRaises(ERRORS):
                compiler.compose(packet, {}, **self.source["parameters"])

    def test_policy_recipe_and_nested_intake_pins_are_bound(self):
        for field in ("policy_sha256", "recipe_sha256"):
            options = self.source["parameters"] | {field: p.sha(b"different")}
            with self.subTest(field=field), self.assertRaises(ERRORS): compiler.compose(pending(self.source), {}, **options)
        for field in ("policySha256", "intakeConfigurationSha256"):
            with self.subTest(field=field), self.assertRaises(ERRORS):
                compiler.compose(pending(self.source, observation_changes={field: p.sha(b"different")}), {},
                    **self.source["parameters"])

    def test_first_job_has_no_previous_or_preloaded_observation(self):
        for changes in ({"previousResult": {}}, {"conductorRequest": None}, {"conductorSequence": True}):
            with self.subTest(changes=changes), self.assertRaises(ERRORS):
                compiler.compose(pending(self.source, ticket_changes=changes), {}, **self.source["parameters"])
        with self.assertRaises(ERRORS):
            compiler.compose(pending(self.source), {}, **(self.source["parameters"] | {"observations": {"release": b"{}"}}))

    def test_no_implicit_decisions_or_synthetic_measured_configuration(self):
        with self.assertRaises(ERRORS): compiler.compose(pending(self.source), {"approve": True}, **self.source["parameters"])
        with self.assertRaises(ERRORS):
            compiler.compose(pending(self.source, observation_changes={"measuredConfiguration": {}}), {},
                **self.source["parameters"])

    def test_clocks_refuse_expired_originals_and_wrong_boot(self):
        f = self.source
        for changes in ({"now_boottime_ns": int(f["conductor"]["deadlineBoottimeNs"])},
                {"now_unix_ns": int(f["conductor"]["expiresAtUnixNanos"])},
                {"boot": (f["parameters"]["boot"][0], 4, 6)}, {"now_boottime_ns": True}):
            with self.subTest(changes=changes), self.assertRaises(ERRORS):
                compiler.compose(pending(f), {}, **(f["parameters"] | changes))

    def test_selected_stop_and_adoption_do_not_offer_approval_defaults(self):
        self.assertEqual(compiler.selection_fields("stop"), ("action",))
        fields = compiler.selection_fields("publication-adoption")
        self.assertIn("validatorExecutableSha256", fields)
        self.assertNotIn("authority", fields)
        self.assertNotIn("coldBundleOriginal", fields)

    def test_transcript_authenticates_real_previous_signature_before_phase_advance(self):
        f = copy.deepcopy(self.source)
        first = compiler.compose(pending(f), {}, **f["parameters"])
        authority = profile.legacy.driver_authority
        signed = p.canonical({"payload": f["payload"], "signature": p.encoded(
            key_fixture("custody-supervisor-capability")[0].sign(
                p.preimage(authority.admission.BOOTSTRAP_DOMAIN, f["payload"])))})
        previous = {"original": signed.decode("ascii"), "sha256": p.sha(signed), "pin": {
            "path": profile.legacy.launch_install.publication.DESTINATIONS["driver-bootstrap-admission"],
            "sha256": p.sha(signed)}}
        prior = {"driver-bootstrap": {"input": first["inputOriginal"], "result": previous}}
        f["conductor"].update(sequence=2, phase="endpoint-precreation", payload={
            "bootstrapObservationOriginal": f["payload"]["bootstrapObservationOriginal"],
            "bootstrapAdmissionOriginal": signed.decode("ascii"), "gateBindingOriginal": "{}"})
        packet = pending(f, ticket_changes={"sequence": 2, "conductorSequence": 2,
            "phase": "endpoint-precreation", "job": "cohort-precreation",
            "previousResult": {"phase": "bootstrap-admission", "job": "driver-bootstrap", "result": previous}})
        clocks = {name: f["parameters"][name] for name in ("boot", "now_boottime_ns", "now_unix_ns")}
        # Only the transcript helper: the absent measured configuration and
        # gate above are NOT accepted as a full cohort candidate or live owner.
        result = context.transcript(packet, prior, first["observations"], f["policy"],
            f["parameters"]["policy_sha256"], clocks)
        self.assertEqual(result[1].name, "cohort-precreation")
        broken = copy.deepcopy(prior)
        broken["driver-bootstrap"]["result"]["sha256"] = p.sha(b"substituted signature")
        with self.assertRaises(ERRORS):
            context.transcript(packet, broken, first["observations"], f["policy"],
                f["parameters"]["policy_sha256"], clocks)

    def test_cold_handoff_rejects_incomplete_or_forged_prefix(self):
        with self.assertRaises(ERRORS): compiler.handoff._cold({}, {})
        prior = {job.name: {"input": b"{}", "result": b"{}"} for job in compiler.handoff.cold.catalogue(handoff=True)}
        with self.assertRaises(ERRORS):
            compiler.handoff._cold(prior, {"bundleOriginal": '{"changed":true}', "observationOriginal": "{}"})

    def test_cohort_precreation_projects_all_eleven_originals(self):
        _, supplied, _ = cohort_fixture()
        config = json.loads(supplied["configurationOriginal"])
        f = self.source
        bootstrap = f["policy"]["bootstrapOriginals"]
        selected = profile.BY_NAME["cohort-precreation"][1]
        selection = {"authority": config["authority"], "endpointExecutableSha256": config["executableSha256"],
            "cleanup": config["cleanup"], "nativeColdOriginals": supplied["coldOriginals"]}
        observations = {"endpoint-precreation": {"bootstrapObservationOriginal": f["payload"]["bootstrapObservationOriginal"]}}
        raw = compiler.foundation.compose(selected, selection, prior={}, observations=observations,
            bootstrap_originals=bootstrap)
        clocks = {name: f["parameters"][name] for name in ("boot", "now_boottime_ns", "now_unix_ns")}
        checked = profile.cohort_authority.prepare_input("precreation", raw, **clocks)
        self.assertEqual(len(json.loads(raw)["coldOriginals"]), 11)
        self.assertEqual(checked["window"]["startupDeadlineBoottimeNs"],
            json.loads(bootstrap["window"])["payload"]["startupDeadlineBoottimeNs"])
        changed = copy.deepcopy(selection)
        changed["nativeColdOriginals"].pop("publicationReconciliation")
        with self.assertRaises(ERRORS):
            compiler.foundation.compose(selected, changed, prior={}, observations=observations, bootstrap_originals=bootstrap)

    def test_cohort_release_uses_literal_precreation_and_installed_launch_pins(self):
        _, supplied, clocks = release_fixture()
        payload = json.loads(supplied["payloadOriginal"])
        first = {name: supplied[name] for name in profile.cohort_authority.FIELDS}
        first.update(operation="precreation", payloadOriginal=p.canonical(
            json.loads(supplied["precreationOriginal"])["payload"]).decode("ascii"))
        prior = {"cohort-precreation": {"input": p.canonical(first), "result": {
            "original": supplied["precreationOriginal"], "sha256": p.sha(supplied["precreationOriginal"].encode("ascii"))}}}
        for role in profile.cohort_authority.ROLES:
            prior["install-launch-" + role] = {"input": b"{}", "result": {"launch": payload[role]["launch"]}}
            closure = p.canonical({"manifest": {"imageSha256": payload[role]["image"]["sha256"]}})
            prior["native-closure-" + role] = {"input": b"{}", "result": {
                "original": closure.decode("ascii"), "sha256": p.sha(closure)}}
        selection = {"endpointImages": {role: payload[role]["image"] for role in profile.cohort_authority.ROLES}}
        raw = compiler.foundation.compose(profile.BY_NAME["cohort-release"][1], selection, prior=prior,
            observations={"service-originals": {"cohortObservationOriginal": supplied["observationsOriginal"]}},
            bootstrap_originals={})
        self.assertEqual(raw, p.canonical(supplied))
        profile.cohort_authority.prepare_input("release", raw, **clocks)


if __name__ == "__main__":
    unittest.main()
