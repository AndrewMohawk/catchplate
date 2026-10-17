#!/usr/bin/env python3
"""Signed synthetic public-plan controls, not a native adoption ceremony.

Assignment, driver, cohort and adoption signatures are real test signatures.
The adoption's nested cold framing is deliberately not a native-valid receipt
chain. No validator success, actual observation, approval or owner is mocked.
The shared fixture can exercise actual file publication separately, but never
establishes custody of its synthetic core observation.
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
from catchplate import native_pilot_adopted_endpoint_plan as plan
from catchplate import native_pilot_adopted_handoff_inputs as compiler
from test_native_pilot_adopted_bridge_keys import fixture as bridge_fixture, clocks
from test_native_pilot_adopted_cohort_authority import fixture as cohort_fixture
from test_native_pilot_adopted_ordinary import fixture as ordinary_fixture
from test_native_pilot_genesis_core import fixture as core_fixture
from test_native_pilot_publication_adoption_authority import fixture as adoption_fixture
from test_native_pilot_generation_scope import key_fixture

p, g, profile = plan.p, plan.g, plan.profile
FAILURES = (ValueError, InvalidSignature)


def _record(raw, output, purpose=None):
    result = dict(original=output.decode("ascii"), sha256=p.sha(output))
    if purpose:
        destinations = plan.adopted_publication.DESTINATIONS if purpose in plan.adopted_publication.DESTINATIONS else plan.publication.DESTINATIONS
        result["pin"] = dict(path=destinations[purpose], sha256=p.sha(output))
    return dict(input=raw, result=result)


def _peer_hash(peer):
    parts = [peer[name].to_bytes(4, "big") for name in ("uid", "gid", "pid")]
    parts.extend(peer[name].to_bytes(8, "big") for name in
        ("startTimeTicks", "executableDevice", "executableInode", "executableLength"))
    parts.extend((p.raw_digest(peer["executableSha256"]), peer["cgroupPathSha256"].encode("ascii"),
        peer["cgroupMountId"].to_bytes(8, "big"), peer["cgroupInode"].to_bytes(8, "big"),
        peer["securityLabelSha256"].encode("ascii"), peer["configurationGenerationSha256"].encode("ascii")))
    peer["processIdentitySha256"] = p.framed(b"catchplate.policyCustodyPeerProcessIdentity/v4", parts)


def fixture():
    bridge, _, _ = bridge_fixture()
    clock = clocks()
    source = json.loads(bridge["deliveryInputOriginal"])
    control, config = json.loads(bridge["controlOriginal"]), json.loads(source["ownerConfigurationOriginal"])
    window, observed = json.loads(source["windowOriginal"])["payload"], json.loads(source["observationOriginal"])
    authority = config["lifecycle"]["constructedAdmissionAuthority"]
    payload = dict(apiVersion="catchplate.nativeShadowBootstrapDriverAdmission/v1",
        purpose="native-driver-bootstrap-admission", configurationSha256=control["configurationSha256"],
        windowSha256=control["windowSha256"], bootstrapObservationOriginal=source["observationOriginal"],
        parent=dict(processId=42, startTimeTicks=99, parentId=2, pidfdDevice=0, pidfdInode=77),
        parentExecutableSha256=control["supervisorExecutableSha256"], pidNamespaceSha256=p.sha(b"synthetic namespace"),
        issuedAtUnixNanos=clock["now_unix_ns"] - 1_000_000_000, expiresAtUnixNanos=clock["now_unix_ns"] + 29_000_000_000,
        startupDeadlineBoottimeNs=window["startupDeadlineBoottimeNs"], lifetimeDeadlineBoottimeNs=window["lifetimeDeadlineBoottimeNs"],
        signingKeyId=authority["keyId"], signingKeySpkiSha256=authority["keySpkiSha256"])
    first = dict(apiVersion="catchplate.nativePilotDriverAuthorityInput/v1", operation="bootstrap",
        controlOriginal=bridge["controlOriginal"], configurationOriginal=source["ownerConfigurationOriginal"],
        deliveryConfigurationOriginal=source["configurationOriginal"], windowOriginal=source["windowOriginal"],
        observationOriginal=source["observationOriginal"], payloadOriginal=p.canonical(payload).decode("ascii"))
    key = key_fixture("custody-supervisor-capability")[0]
    bootstrap_raw = p.canonical(dict(payload=payload, signature=p.encoded(key.sign(
        p.preimage(profile.legacy.driver_authority.admission.BOOTSTRAP_DOMAIN, payload)))))
    prior = {"driver-bootstrap": _record(p.canonical(first), bootstrap_raw, "driver-bootstrap-admission")}
    cohort_key, cohort_input, _ = cohort_fixture()
    cohort = profile.cohort_authority.cohort
    cohort_config = json.loads(cohort_input["configurationOriginal"])
    cohort_config["externalDriver"] = dict(configurationSha256=p.sha(first["configurationOriginal"].encode("ascii")),
        windowSha256=p.sha(first["windowOriginal"].encode("ascii")), observationSha256=p.sha(first["observationOriginal"].encode("ascii")),
        supervisorExecutableSha256=control["supervisorExecutableSha256"])
    for role, original in cohort_input["coldOriginals"].items():
        cohort_config[role + "Configuration"] = dict(path=profile.legacy.launch_install.ADOPTED_DESTINATIONS["native-cold-" + role],
            sha256=p.sha(original.encode("ascii")))
    cohort_raw = p.canonical(cohort_config)
    cohort_window = {name: window[name] for name in plan.external_driver.WINDOW_JOIN}
    cohort_window.update(configurationSha256=p.sha(cohort_raw), authorityKeyId=cohort_config["authority"]["keyId"])
    cohort_input.update(configurationOriginal=cohort_raw.decode("ascii"), configurationSha256=p.sha(cohort_raw),
        payloadOriginal=p.canonical(cohort_window).decode("ascii"))
    precreation_raw = p.canonical(dict(apiVersion="catchplate.nativeShadowProofCohortPrecreation/v1",
        payload=cohort_window, signatureBase64url=p.encoded(cohort_key.sign(cohort.PRECREATE_DOMAIN + p.canonical(cohort_window)))))
    prior["cohort-precreation"] = _record(p.canonical(cohort_input), precreation_raw, "cohort-precreation")
    binding = dict(apiVersion="catchplate.nativeShadowEndpointDriverBinding/v1",
        **{name: first[name] for name in ("configurationOriginal", "windowOriginal", "observationOriginal")})
    pidfd, executable = observed["descriptors"][:2]
    kernel = observed["driver"]
    external = dict(apiVersion="catchplate.nativeShadowEndpointDriverOriginal/v1", bindingSha256=p.sha(p.canonical(binding)),
        **{name: cohort_config["externalDriver"][name] for name in plan.external_driver.CONFIG_FIELDS[:3]},
        supervisor={name: payload["parent"][name] for name in plan.external_driver.PROCESS_FIELDS},
        driver=dict(processId=observed["processId"], startTimeTicks=kernel["processStartTimeTicks"],
            pidfdDevice=pidfd["device"], pidfdInode=pidfd["inode"]),
        executable=dict(device=executable["device"], inode=executable["inode"], length=8192, sha256=kernel["driverExecutableSha256"]))
    cohort_observed = dict(apiVersion=cohort.originals_api(cohort_config), configurationSha256=p.sha(cohort_raw),
        precreationSha256=p.sha(precreation_raw), invocationId=window["invocationId"], externalDriver=external)
    for index, role in enumerate(cohort.roles(cohort_config)):
        cohort_observed[role] = dict(processId=1000 + index, startTimeTicks=100 + index,
            executable=dict(device=3, inode=1000 + index, length=8192, sha256=cohort_config["executableSha256"]))
    installed = ordinary_fixture()
    peer = json.loads(installed["runtimes"][g.ROLES[0]])["runtime"]["expectedPeer"]
    peer.update(uid=observed["uid"], gid=observed["gid"], pid=observed["processId"], startTimeTicks=kernel["processStartTimeTicks"],
        executableDevice=executable["device"], executableInode=executable["inode"], executableLength=8192,
        executableSha256=kernel["driverExecutableSha256"], cgroupMountId=kernel["cgroupMountId"], cgroupInode=kernel["cgroupInode"])
    _peer_hash(peer)
    runtime_originals = {}
    for role, raw in installed["runtimes"].items():
        runtime = json.loads(raw); runtime["runtime"]["expectedPeer"] = copy.deepcopy(peer)
        runtime_originals[role] = g.canonical(runtime).decode("ascii")
    history_originals = {role: raw.decode("ascii") for role, raw in installed["histories"].items()}
    prior["install-ordinary-runtime"] = dict(input=g.canonical(dict(runtimeOriginals=runtime_originals,
        historyOriginals=history_originals)), result={})
    prior["install-precreation"] = dict(input=p.canonical(dict(driverConfigurationOriginal=first["configurationOriginal"],
        driverWindowOriginal=first["windowOriginal"], driverObservationOriginal=first["observationOriginal"],
        cohortConfigurationOriginal=cohort_raw.decode("ascii"), cohortPrecreationOriginal=precreation_raw.decode("ascii"),
        nativeColdOriginals=cohort_input["coldOriginals"])), result={})
    core_bundle, _, core_observed = core_fixture()
    observations = {"bootstrap-admission": dict(bootstrapObservationOriginal=first["observationOriginal"],
        admissionPayloadOriginal=first["payloadOriginal"]), "endpoint-inputs": dict(
        cohortObservationOriginal=p.canonical(cohort_observed).decode("ascii"), adoptedCore=dict(
            bundleOriginal=g.canonical(core_bundle).decode("ascii"), observationOriginal=g.canonical(core_observed).decode("ascii")))}
    validation, _, _ = adoption_fixture()
    adopted = json.loads(validation["payloadOriginal"])
    adopted_config = json.loads(adopted["coldConfigurationOriginal"])
    adopted_config["scope"].update(bootIdBase64url=clock["boot"][0], timeNamespaceDevice=clock["boot"][1],
        timeNamespaceInode=clock["boot"][2], issuedAtBoottimeNanos=int(window["issuedAtBoottimeNs"]),
        expiresAtBoottimeNanos=int(window["lifetimeDeadlineBoottimeNs"]))
    recipe, measured = bridge["recipeOriginals"], bridge["measured"]
    trust, assignment = json.loads(recipe["trustOriginal"]), json.loads(recipe["assignmentOriginal"])
    selected_key = next(row["key"] for row in trust["roleKeys"] if row["role"] == "custody-supervisor-capability")
    adopted.update(coldConfigurationOriginal=g.canonical(adopted_config).decode("ascii"),
        coldBundleOriginal=observations["endpoint-inputs"]["adoptedCore"]["bundleOriginal"],
        authority={name: selected_key[name] for name in ("keyId", "keySpkiSha256", "publicKeyBase64url")},
        assignmentPayloadSha256=assignment["payloadSha256"], assignmentRevision=assignment["payload"]["assignmentRevision"],
        productionConfigurationBindingSha256=measured["configurationBindingSha256"], proofScopeOriginal=measured["proofScopeOriginal"],
        trustCheckpointId=trust["checkpoint"]["checkpointId"], revocationGeneration=trust["checkpoint"]["revocationGeneration"],
        revocationRootSha256=trust["checkpoint"]["revocationRootSha256"], issuedAtUnixNanos=clock["now_unix_ns"],
        expiresAtUnixNanos=clock["now_unix_ns"] + 1_000_000_000, issuedAtBoottimeNanos=clock["now_boottime_ns"],
        expiresAtBoottimeNanos=1_900_000_000)
    validation.update(payloadOriginal=g.canonical(adopted).decode("ascii"), **{
        "current" + name[0].upper() + name[1:]: recipe[name]
        for name in ("trustOriginal", "trustSha256", "assignmentOriginal", "closureSetOriginal")},
        currentConfigurationBindingSha256=measured["configurationBindingSha256"], currentProofScopeOriginal=measured["proofScopeOriginal"])
    for row in validation["targetHistories"]:
        row.update(runtimeOriginal=runtime_originals[row["serviceRole"]], historyOriginal=history_originals[row["serviceRole"]])
    raw = p.canonical(validation)
    signed_adoption = p.canonical(dict(payload=adopted, signature=p.encoded(key.sign(
        p.preimage("catchplate.nativePublicationAdoptionAuthorization.signature/v2", adopted)))))
    control = dict(apiVersion=profile.adoption.CONTROL_API, validatorExecutableSha256=p.sha(b"synthetic validator"), inputSha256=p.sha(raw))
    prior["publication-adoption"] = _record(p.canonical(dict(apiVersion=profile.ADOPTION_INPUT_API,
        controlOriginal=p.canonical(control).decode("ascii"), validationInputOriginal=raw.decode("ascii"))),
        signed_adoption, "publication-adoption")
    originals = (g.canonical(peer), measured["proofScopeOriginal"].encode("ascii"),
        plan.retrieval.fresh_ledger_manifest_original(measured["proofScopeOriginal"].encode("ascii")), recipe["assignmentOriginal"].encode("ascii"))
    value = {name: dict(path=plan.publication.DESTINATIONS[purpose], sha256=p.sha(raw))
        for name, purpose, raw in zip(plan.PIN_FIELDS, plan.PURPOSES, originals, strict=True)}
    value.update(coldOriginals={role: copy.deepcopy(cohort_config[role + "Configuration"]) for role in profile.COMPOSITE},
        production=copy.deepcopy(measured["production"]), objectDirectory="/var/lib/catchplate/native-pilot-retrieval-objects",
        adoptionAuthorization=copy.deepcopy(prior["publication-adoption"]["result"]["pin"]))
    selection = {"peerPath": value["peer"]["path"], "proofScopePath": value["proofScope"]["path"],
        "assignmentPath": value["assignment"]["path"], "retrievalManifest": value["retrievalManifest"], "objectDirectory": value["objectDirectory"]}
    return dict(value=value, prior=prior, observations=observations, clocks=clock, selection=selection,
        supervisor=dict(measuredConfiguration=measured, recipeOriginals=recipe),
        prerequisites={**{"native-cold-" + role: cohort_input["coldOriginals"][role].encode("ascii")
            for role in profile.COMPOSITE}, "publication-adoption": signed_adoption})


class EndpointPlanControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.source = fixture()

    def test_signed_plan_exact_four_and_fresh_empty_auxiliary_manifest(self):
        f = self.source
        result = plan.prepare_current(f["value"], prior=f["prior"], observations=f["observations"], **f["clocks"])
        self.assertEqual(tuple(name for name, _ in result["plan"]), plan.PURPOSES)
        self.assertEqual(result["plan"], plan.prepare(f["value"], prior=f["prior"], observations=f["observations"]))
        raw = dict(result["plan"])["endpoint-retrieval-manifest"]
        self.assertEqual(plan.retrieval.manifest_objects(raw, p.sha(raw)), [])
        self.assertEqual(plan.retrieval.manifest_initialization(raw, p.sha(raw)), "fresh-ledger")
        self.assertEqual(result["deadline"], 1_900_000_000)
        self.assertLessEqual(result["epochLimit"], f["clocks"]["now_unix_ns"] + 1_000_000_000)

    def test_compiler_derives_exact_existing_input_and_manifest_pin(self):
        f = self.source
        raw = compiler.compose(profile.BY_NAME["endpoint-inputs"][1], f["selection"], prior=f["prior"],
            observations=f["observations"], supervisor_observation=f["supervisor"], cold_prior={}, boot=f["clocks"]["boot"])
        self.assertEqual(raw, g.canonical(f["value"]))
        selection = copy.deepcopy(f["selection"]); selection["retrievalManifest"]["sha256"] = p.sha(b"old manifest")
        with self.assertRaises(ValueError):
            compiler.compose(profile.BY_NAME["endpoint-inputs"][1], selection, prior=f["prior"], observations=f["observations"],
                supervisor_observation=f["supervisor"], cold_prior={}, boot=f["clocks"]["boot"])

    def test_each_fixed_pin_and_production_binding_are_required(self):
        for field in (*plan.PIN_FIELDS, "adoptionAuthorization"):
            f = copy.deepcopy(self.source); f["value"][field]["path"] = "/etc/catchplate/wrong.json"
            with self.subTest(field=field), self.assertRaises(FAILURES): plan.prepare(f["value"], prior=f["prior"], observations=f["observations"])
        f = copy.deepcopy(self.source); f["value"]["production"]["maximumInFlightCalls"] += 1
        with self.assertRaises(FAILURES): plan.prepare(f["value"], prior=f["prior"], observations=f["observations"])

    def test_actual_peer_descriptor_or_supervisor_rebinding_refuses(self):
        for member, field in (("driver", "pidfdInode"), ("supervisor", "processId"), ("executable", "inode")):
            f = copy.deepcopy(self.source)
            observed = json.loads(f["observations"]["endpoint-inputs"]["cohortObservationOriginal"])
            observed["externalDriver"][member][field] += 1
            f["observations"]["endpoint-inputs"]["cohortObservationOriginal"] = p.canonical(observed).decode("ascii")
            with self.subTest(member=member), self.assertRaises(FAILURES): plan.prepare(f["value"], prior=f["prior"], observations=f["observations"])

    def test_original_clocks_and_signature_are_not_replaceable(self):
        f = self.source
        for changed in (dict(now_boottime_ns=1_900_000_000), dict(now_unix_ns=f["clocks"]["now_unix_ns"] + 1_000_000_000),
                dict(boot=(f["clocks"]["boot"][0], 9, 10))):
            with self.subTest(changed=changed), self.assertRaises(FAILURES):
                plan.prepare_current(f["value"], prior=f["prior"], observations=f["observations"], **(f["clocks"] | changed))
        f = copy.deepcopy(f); row = f["prior"]["publication-adoption"]["result"]
        signed = json.loads(row["original"]); signed["signature"] = p.encoded(bytes(64)); raw = p.canonical(signed)
        row.update(original=raw.decode("ascii"), sha256=p.sha(raw)); row["pin"]["sha256"] = p.sha(raw)
        f["value"]["adoptionAuthorization"]["sha256"] = p.sha(raw)
        with self.assertRaises(FAILURES): plan.prepare(f["value"], prior=f["prior"], observations=f["observations"])

    def test_independent_auxiliary_path_has_no_silent_default(self):
        f = copy.deepcopy(self.source); f["value"]["objectDirectory"] = "/var/lib/independently-selected-objects"
        self.assertEqual(plan.prepare(f["value"], prior=f["prior"], observations=f["observations"]),
            plan.prepare(self.source["value"], prior=f["prior"], observations=f["observations"]))
        for path in ("/", "/var/lib/../objects", "/var//objects", "relative/path"):
            f["value"]["objectDirectory"] = path
            with self.subTest(path=path), self.assertRaises(ValueError): plan.prepare(f["value"], prior=f["prior"], observations=f["observations"])


if __name__ == "__main__": unittest.main()
