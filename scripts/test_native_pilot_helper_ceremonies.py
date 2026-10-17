#!/usr/bin/env python3
"""Nine bounded synthetic helper-ceremony controls, not owner/approval evidence.

Fixtures contain separately framed in-memory checkpoint and three-authority
anchor signatures. No authority entrypoint, real process/descriptor, protected
file, publication, clock, entropy source or native service is exercised.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))

from catchplate import native_pilot_ordinary_runtime_profile as runtime
from catchplate import native_pilot_phase_execution as execution
from catchplate import native_pilot_supervisor as supervisor
from catchplate import native_pilot_supervisor_helper_initial_profile as profile
from catchplate import native_pilot_supervisor_policy as policy
from test_native_pilot_endpoint_commissioning import peer
from test_native_pilot_helper_initial import HELPER, HELPER_ROLES, fixture, refresh
from test_native_pilot_initial_commissioning import OPERATIONS
from test_native_pilot_ordinary_initial import ANCHOR_FIELDS, SIGNATURE_FIELDS
from test_native_pilot_ordinary_keys import ROLES, canonical, encoded, labelled, sha


def selection(f):
    primary = f["initial_policy"]["services"][HELPER]["endpointRole"]
    return {"apiVersion": "catchplate.nativePilotSupervisorHelperInitialPolicy/v1",
        "supplementalEndpointRoles": [role for role in HELPER_ROLES if role != primary]}


def stage(f, slot, operation, *, wrapper=None):
    """Existing signed fixture originals projected into the real stage input."""
    endpoint_role = selection(f)["supplementalEndpointRoles"][slot - 1]
    wrapper = copy.deepcopy(wrapper) if wrapper is not None else json.loads(f["helper_histories"][endpoint_role])
    checkpoint = wrapper["initialCheckpoint"]
    authorities = f["initial_policy"]["services"][HELPER]["authorities"]
    anchor = wrapper["history"]["firstRetainedEpoch"]
    records = {name: {"apiVersion": "catchplate.custodyOrdinaryInitialAnchorSignature/v1", "signer": name,
        "anchorPayloadSha256": sha(canonical([anchor[field] for field in ANCHOR_FIELDS])),
        "keyId": authorities[name]["keyId"], "keySpkiSha256": authorities[name]["keySpkiSha256"],
        "signatureBase64": anchor[field]}
        for name, field in zip(("root", "checkpoint", "service"), SIGNATURE_FIELDS, strict=True)}
    # The pure result checker authenticates checkpoint/anchor outputs, not this
    # deliberately unsigned driver context or live provenance. Actual compose
    # must supply the retained, independently authenticated driver originals.
    window = {"apiVersion": "catchplate.nativeShadowDriverBootstrapWindow/v1", "payload": f["window"],
        "signatureBase64url": encoded(b"S" * 64)}
    value = {"apiVersion": "catchplate.nativePilotOrdinaryInitialAuthorityInput/v1", "operation": operation,
        "driverConfigurationOriginal": canonical({"syntheticUncheckedContext": True}).decode("ascii"),
        "driverWindowOriginal": canonical(window).decode("ascii"),
        "launchOriginal": canonical(f["launch"]).decode("ascii"),
        "configurationOriginal": canonical(f["cold"][HELPER]).decode("ascii"),
        "preparationOriginal": canonical(f["preparation"]).decode("ascii"),
        "resourcesOriginal": canonical(f["resources"]).decode("ascii"),
        "initialStateOriginal": canonical(wrapper["initialState"]).decode("ascii"),
        "authorities": copy.deepcopy(authorities), "payloadOriginal": canonical(checkpoint["payload"]).decode("ascii")}
    if operation != "checkpoint":
        value["initialCheckpointOriginal"] = canonical(checkpoint).decode("ascii")
    if operation == "assemble":
        value["anchorSignatures"] = {name: canonical(record).decode("ascii") for name, record in records.items()}
        output = wrapper
    elif operation == "checkpoint":
        output = checkpoint
    else:
        output = records[operation.removesuffix("-anchor")]
    raw = canonical(output)
    return value, {"original": raw.decode("ascii"), "sha256": sha(raw)}, raw


class HelperCeremonyControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f, _, _ = fixture()
        cls.fragment = selection(cls.f)

    def checked(self, slot, operation, value, result, *, fragment=None, initial_policy=None):
        return profile.checked_result(slot, operation, canonical(value), result,
            fragment=self.fragment if fragment is None else fragment,
            initial_policy=self.f["initial_policy"] if initial_policy is None else initial_policy)

    def supplementary(self):
        result = {}
        for slot in (1, 2, 3):
            value, output, _ = stage(self.f, slot, "assemble")
            result[slot] = self.checked(slot, "assemble", value, output)
        return result

    def test_policy_selects_exact_native_order_complement_and_copies(self):
        before = copy.deepcopy(self.fragment)
        for primary in HELPER_ROLES:
            approved = copy.deepcopy(self.f["initial_policy"])
            approved["services"][HELPER]["endpointRole"] = primary
            fragment = {"apiVersion": self.fragment["apiVersion"],
                "supplementalEndpointRoles": [role for role in HELPER_ROLES if role != primary]}
            checked = profile.validate_policy(fragment, initial_policy=approved)
            self.assertEqual(checked, fragment)
            checked["supplementalEndpointRoles"].clear()
            self.assertEqual(len(fragment["supplementalEndpointRoles"]), 3)
        for change in ("missing", "reversed", "duplicate", "primary", "unknown", "future", "version"):
            value = copy.deepcopy(self.fragment)
            roles = value["supplementalEndpointRoles"]
            if change == "missing": roles.pop()
            elif change == "reversed": roles.reverse()
            elif change == "duplicate": roles[1] = roles[0]
            elif change == "primary": roles[0] = self.f["initial_policy"]["services"][HELPER]["endpointRole"]
            elif change == "unknown": roles[0] = "signer-hsm"
            elif change == "future": value["endpointProcessIdentitySha256"] = labelled("predicted identity")
            else: value["apiVersion"] += "-unknown"
            with self.subTest(change=change), self.assertRaises(ValueError):
                profile.validate_policy(value, initial_policy=self.f["initial_policy"])
        self.assertEqual(self.fragment, before)
        outer = {"apiVersion": policy.HELPER_INITIAL_POLICY_API,
            "ordinaryInitialHistories": self.f["initial_policy"],
            "helperInitialHistoriesOriginal": canonical(self.fragment).decode("ascii")}
        # Parser skeleton only: this does not open/admit a SupervisorPolicy.
        self.assertEqual(policy._policy_document(canonical(outer)), outer)

    def test_source_slots_reuse_capabilities_and_precede_delivery(self):
        jobs = execution.HELPER_INITIAL_JOBS
        expected = tuple((slot, operation) for slot in (1, 2, 3) for operation in OPERATIONS)
        self.assertEqual(tuple(execution.HELPER_INITIAL_JOB_INFO[job.name] for job in jobs), expected)
        self.assertEqual(len(jobs), 15)
        start = execution.job_index("service-originals", jobs[0].name) - 1
        self.assertEqual(start, len(execution.INITIAL_JOBS))
        self.assertEqual(execution.JOBS["service-originals"][start:start + len(jobs)], jobs)
        self.assertEqual(execution.job_index("service-originals", "ordinary-delivery-" + ROLES[0]), start + len(jobs) + 1)
        key_names = set()
        for index, (job, (slot, operation)) in enumerate(zip(jobs, expected, strict=True)):
            self.assertEqual(job.name, "ordinary-helper-initial-" + operation + "-slot" + str(slot))
            key = None if operation == "assemble" else "ordinary-initial-" + {
                "checkpoint": "checkpoint", "root-anchor": "root", "checkpoint-anchor": "checkpoint",
                "service-anchor": "service"}[operation] + "-" + HELPER
            self.assertEqual((job.family, job.role, job.purpose, job.key, job.maximum),
                ("helper-initial", HELPER, None, key, 8 * 1024 * 1024))
            self.assertEqual(execution.job_index("service-originals", job.name), start + index + 1)
            self.assertIn(("service-originals", job.name), supervisor.SUPPORTED_JOBS)
            if key is not None: key_names.add(key)
        self.assertEqual(key_names, {"ordinary-initial-" + name + "-" + HELPER for name in ("root", "checkpoint", "service")})
        self.assertTrue(key_names.issubset(execution.KEY_PURPOSES))
        self.assertEqual(len(execution.KEY_PURPOSES), 108)
        with self.assertRaises(ValueError): execution.job_index("service-originals", "unknown-job")

    def test_all_fifteen_independent_signed_stage_results(self):
        digests = {operation: set() for operation in OPERATIONS}
        for slot in (1, 2, 3):
            for operation in OPERATIONS:
                value, result, raw = stage(self.f, slot, operation)
                before = copy.deepcopy((value, result, self.fragment, self.f["initial_policy"]))
                with self.subTest(slot=slot, operation=operation):
                    self.assertEqual(self.checked(slot, operation, value, result), raw)
                    self.assertEqual((value, result, self.fragment, self.f["initial_policy"]), before)
                    self.assertEqual(set(result), {"original", "sha256"})
                digests[operation].add(sha(raw))
        self.assertTrue(all(len(values) == 3 for values in digests.values()))

    def test_unsigned_conductor_association_preserves_u64_inner_counters(self):
        # Association-only namespace, not a PhaseExecution/retained owner.
        # These changed inner originals deliberately have no matching new
        # signatures: the authority's separate cryptographic checks are not
        # invoked or bypassed by this focused unbound-method regression.
        primary, _, _ = stage(self.f, 1, "checkpoint", wrapper=json.loads(self.f["histories"][HELPER]))
        supplemental, _, _ = stage(self.f, 1, "checkpoint")
        maximum = (1 << 64) - 1
        for value in (primary, supplemental):
            state = json.loads(value["initialStateOriginal"])
            payload = json.loads(value["payloadOriginal"])
            state["operationGeneration"] = maximum
            payload["revocationGenerationHighWater"] = maximum
            value["initialStateOriginal"] = canonical(state).decode("ascii")
            value["payloadOriginal"] = canonical(payload).decode("ascii")
        installed = {name: primary[name] for name in ("driverConfigurationOriginal", "driverWindowOriginal")}
        installed.update(ordinaryLaunchOriginal=primary["launchOriginal"],
            ordinaryColdOriginals={HELPER: primary["configurationOriginal"]})
        context = SimpleNamespace(_request=SimpleNamespace(payload={
            "ordinaryPreparationOriginal": primary["preparationOriginal"],
            "ordinaryInitialResourcesOriginal": primary["resourcesOriginal"]}),
            _inputs={"install-precreation": canonical(installed),
                "ordinary-initial-checkpoint-" + HELPER: canonical(primary)},
            _installations={"install-precreation": {}})
        job = execution.HELPER_INITIAL_JOBS[0]
        before = copy.deepcopy(supplemental)
        self.assertIsNone(execution.PhaseExecution._bind_initial(context, job, supplemental))
        self.assertEqual(supplemental, before)
        for change in ("state-counter", "payload-counter", "role"):
            changed = copy.deepcopy(supplemental)
            field = "initialStateOriginal" if change == "state-counter" else "payloadOriginal"
            inner = json.loads(changed[field])
            if change == "state-counter": inner["operationGeneration"] = maximum - 1
            elif change == "payload-counter": inner["revocationGenerationHighWater"] = maximum - 1
            else: inner["endpointRole"] = self.fragment["supplementalEndpointRoles"][1]
            changed[field] = canonical(inner).decode("ascii")
            with self.subTest(change=change), self.assertRaises(ValueError):
                execution.PhaseExecution._bind_initial(context, job, changed)

    def test_checkpoint_result_rejects_wrong_slot_policy_and_digest(self):
        value, result, _ = stage(self.f, 1, "checkpoint")
        for slot in (0, True, 2, 4):
            with self.subTest(slot=slot), self.assertRaises(ValueError):
                self.checked(slot, "checkpoint", value, result)
        for change in ("digest", "signature", "payload", "authority", "generation", "revocation"):
            v, r, approved = copy.deepcopy(value), copy.deepcopy(result), copy.deepcopy(self.f["initial_policy"])
            if change == "digest": r["sha256"] = labelled("different output")
            elif change == "signature":
                output = json.loads(r["original"]); output["authoritySignatureBase64"] = encoded(bytes(64))
                r = {"original": canonical(output).decode("ascii"), "sha256": sha(canonical(output))}
            elif change == "payload":
                payload = json.loads(v["payloadOriginal"]); payload["revocationRootSha256"] = labelled("different payload")
                v["payloadOriginal"] = canonical(payload).decode("ascii")
            elif change == "authority": approved["services"][HELPER]["authorities"]["root"]["keyId"] = labelled("other root")
            elif change == "generation": approved["services"][HELPER]["durableEpoch"] += 1
            else: approved["services"][HELPER]["revocationGenerationHighWater"] += 1
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                self.checked(1, "checkpoint", v, r, initial_policy=approved)

    def test_anchor_results_bind_each_signature_and_actual_checkpoint(self):
        for operation in OPERATIONS[1:4]:
            value, result, _ = stage(self.f, 1, operation)
            for change in ("signature", "payload-hash", "signer", "prior-checkpoint"):
                v, r = copy.deepcopy(value), copy.deepcopy(result)
                output = json.loads(r["original"])
                if change == "signature": output["signatureBase64"] = encoded(bytes(64))
                elif change == "payload-hash": output["anchorPayloadSha256"] = labelled("other anchor payload")
                elif change == "signer": output["signer"] = "service" if operation == "root-anchor" else "root"
                else:
                    other, _, _ = stage(self.f, 2, operation)
                    v["initialCheckpointOriginal"] = other["initialCheckpointOriginal"]
                r = {"original": canonical(output).decode("ascii"), "sha256": sha(canonical(output))}
                with self.subTest(operation=operation, change=change), self.assertRaises((ValueError, InvalidSignature)):
                    self.checked(1, operation, v, r)

    def test_assembly_requires_all_actual_anchors_and_has_no_public_pin(self):
        value, result, _ = stage(self.f, 1, "assemble")
        for signer in ("root", "checkpoint", "service"):
            for change in ("missing", "signature", "cross-role"):
                v = copy.deepcopy(value)
                if change == "missing": del v["anchorSignatures"][signer]
                elif change == "cross-role":
                    other, _, _ = stage(self.f, 2, "assemble")
                    v["anchorSignatures"][signer] = other["anchorSignatures"][signer]
                else:
                    record = json.loads(v["anchorSignatures"][signer]); record["signatureBase64"] = encoded(bytes(64))
                    v["anchorSignatures"][signer] = canonical(record).decode("ascii")
                with self.subTest(signer=signer, change=change), self.assertRaises((ValueError, InvalidSignature)):
                    self.checked(1, "assemble", v, result)
        for changed in (result | {"pin": {"path": "/etc/catchplate/invented-helper-history.json", "sha256": result["sha256"]}},
                result | {"ready": True}):
            with self.assertRaises(ValueError): self.checked(1, "assemble", value, changed)
        wrapper = json.loads(result["original"]); wrapper["history"]["manifestSha256"] = labelled("false semantic hash")
        bad = canonical(wrapper)
        with self.assertRaises((ValueError, InvalidSignature)):
            self.checked(1, "assemble", value, {"original": bad.decode("ascii"), "sha256": sha(bad)})

    def test_exact_four_history_handoff_builds_explicit_runtime_successor(self):
        supplements = self.supplementary()
        before = copy.deepcopy(supplements)
        selected = profile.authenticate_histories(self.f["histories"][HELPER], supplements,
            fragment=self.fragment, initial_policy=self.f["initial_policy"])
        self.assertEqual(tuple(selected), HELPER_ROLES)
        self.assertEqual(selected, self.f["helper_histories"])
        self.assertEqual(supplements, before)
        raw = runtime.build(HELPER, fragment=self.f["fragment"], history_originals=self.f["histories"],
            preparation_raw=canonical(self.f["preparation"]), resources_raw=canonical(self.f["resources"]),
            launch_raw=canonical(self.f["launch"]), configuration_raw=canonical(self.f["cold"][HELPER]),
            peer=peer(), helper_history_originals=selected)
        self.assertEqual(raw, self.f["runtimes"][HELPER])
        value = runtime.validate_runtime(HELPER, raw)
        self.assertEqual(self.f["fragment"]["apiVersion"], "catchplate.nativePilotOrdinaryRuntimePolicy/v2")
        self.assertEqual(value["runtime"]["apiVersion"], "catchplate.policyCustodyServiceRuntimeConfig/v9")
        for role in HELPER_ROLES:
            self.assertEqual(value["initialEndpointHistories"][role].encode("ascii"), selected[role])
            checkpoint = json.loads(selected[role])["initialCheckpoint"]
            self.assertEqual(value["initialEndpointPins"][role]["signedCurrentKeyAuthorization"], checkpoint)
        for change in ("legacy", "missing-member", "false-pin"):
            broken = copy.deepcopy(value)
            if change == "legacy": broken["runtime"]["apiVersion"] = "catchplate.policyCustodyServiceRuntimeConfig/v5"
            elif change == "missing-member": del broken["initialEndpointHistories"][HELPER_ROLES[0]]
            else: broken["initialEndpointPins"][HELPER_ROLES[0]]["declaredSocketPath"] += "-other"
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                runtime.validate_runtime(HELPER, canonical(broken))

    def test_handoff_refuses_primary_role_signature_and_window_substitution(self):
        primary = self.f["histories"][HELPER]
        originals = self.supplementary()
        for change in ("missing", "bool-slot", "cross-role", "primary-copy", "swapped-primary", "signature", "window"):
            chosen, supplements = primary, dict(originals)
            if change == "missing": del supplements[3]
            elif change == "bool-slot": supplements = {True: supplements[1], 2: supplements[2], 3: supplements[3]}
            elif change == "cross-role": supplements[1], supplements[2] = supplements[2], supplements[1]
            elif change == "primary-copy": supplements[1] = primary
            elif change == "swapped-primary": chosen = supplements[1]
            else:
                wrapper = json.loads(supplements[1])
                if change == "signature": wrapper["initialCheckpoint"]["authoritySignatureBase64"] = encoded(bytes(64))
                else:
                    # Authentic new test signatures cannot excuse a different
                    # original window from the other three helper members.
                    until = int(wrapper["initialState"]["lifetimeDeadlineBoottimeNs"]) + 1
                    wrapper["initialState"]["lifetimeDeadlineBoottimeNs"] = str(until)
                    wrapper["initialCheckpoint"]["payload"]["validUntilBoottime"]["absoluteBoottimeNanos"] = until
                    wrapper = refresh(wrapper)
                supplements[1] = canonical(wrapper)
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                profile.authenticate_histories(chosen, supplements, fragment=self.fragment,
                    initial_policy=self.f["initial_policy"])
        value, result, _ = stage(self.f, 1, "checkpoint")
        window = json.loads(value["driverWindowOriginal"])
        window["payload"]["startupDeadlineBoottimeNs"] = str(int(window["payload"]["startupDeadlineBoottimeNs"]) - 1)
        value["driverWindowOriginal"] = canonical(window).decode("ascii")
        with self.assertRaises(ValueError): self.checked(1, "checkpoint", value, result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
