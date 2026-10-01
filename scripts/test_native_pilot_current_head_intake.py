#!/usr/bin/env python3
"""Nine pure SYNTHETIC late-intake controls, not independent approval evidence.

Keys, observations, request entropy, clocks and currentness decisions are
test-only. Existing C9, generation and current-head signatures are framed in
memory. No issuer entrypoint, protected FD, actual owner, publisher, service or
pending/resume ceremony runs. The unbound phase check is association-only.
"""
from __future__ import annotations

import copy
from functools import lru_cache
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))

from serverware import custody_generation_grants as grants
from serverware import native_pilot_current_head_profile as head
from serverware import native_pilot_phase_execution as execution
from serverware import native_pilot_service_authority as services
from serverware import native_pilot_service_handshakes as handshakes
from serverware import native_pilot_supervisor as supervisor
from serverware import native_pilot_supervisor_current_head_profile as profile
from serverware import native_pilot_supervisor_current_heads as intake
from serverware import native_pilot_supervisor_policy as policy
from test_native_pilot_bridge_preparation import fixture as bridge_fixture
from test_native_pilot_current_head import refresh_decision, refresh_request, signed_result
from test_native_pilot_helper_initial import HELPER, HELPER_ROLES, fixture as helper_fixture, head_input
from test_native_pilot_ordinary_commissioning import plan, private
from test_native_pilot_ordinary_generations import context as generation_context, result as grant_result, scope_fixture
from test_native_pilot_ordinary_keys import ROLES, canonical, encoded, labelled, sha


def selection():
    return {"apiVersion": "serverware.nativePilotSupervisorCurrentHeadPolicy/v1",
        "targets": [job.name for job in execution.CURRENT_HEAD_JOBS]}


@lru_cache(maxsize=2)
def _fixture(lifetime_boottime_ns=9_000_000):
    """Authentic test signatures over public synthetic originals, never owners."""
    f, contexts, kw = helper_fixture(lifetime_boottime_ns=lifetime_boottime_ns)
    source = generation_context()
    files = plan(f, f["runtimes"])
    ordinary = {}
    for role in ROLES:
        cold_raw = canonical(f["cold"][role])
        delivery = json.loads(source["deliveries"][role])
        payload = delivery["payload"]
        payload["lifetimeDeadlineBoottimeNs"] = f["launch"]["lifetimeDeadlineBoottimeNs"]
        payload["runtimeConfig"]["sha256"] = sha(f["runtimes"][role])
        payload["credentials"] = copy.deepcopy(f["fragment"]["services"][role]["credentials"])
        for kind, name in (("history", "authority-history"), ("inspection", "peer-inspection-policy")):
            item = next(row for row in files if row["role"] == role and row["kind"] == kind)
            payload["credentials"].append({"name": name,
                "original": {"path": item["path"], "sha256": sha(item["raw"])},
                "length": len(item["raw"]), "signing": None})
        delivery["signatureBase64url"] = encoded(f["delivery_keys"][role].sign(
            b"serverware.policyCustodyGuestDelivery.signature/v1\0" + canonical(payload)))
        delivery_raw = canonical(delivery)
        _, guest = grants._admit_delivery(signed_raw=delivery_raw, cold_raw=cold_raw,
            cold_sha=sha(cold_raw), role=role, activation=payload["activation"], boot=kw["boot"],
            startup=5000, lifetime=lifetime_boottime_ns, now=1300, **services._flags(role))
        grant = {"apiVersion": "serverware.custodyServiceGenerationGrant/v1",
            "purpose": "cold-service-generation-admission", "serviceRole": role, "guest": guest,
            "runtimeConfigurationSha256": sha(f["runtimes"][role]),
            "authorityHistoryManifestSha256": json.loads(f["histories"][role])["history"]["manifestSha256"],
            "scope": scope_fixture(), "issuedAtBoottimeNanos": 1200, "expiresAtBoottimeNanos": lifetime_boottime_ns}
        ordinary[role] = {"configurationOriginal": cold_raw.decode("ascii"), "configurationSha256": sha(cold_raw),
            "deliveryOriginal": delivery_raw.decode("ascii"), "runtimeOriginal": f["runtimes"][role].decode("ascii"),
            "historyOriginal": f["histories"][role].decode("ascii"),
            "generationGrantOriginal": grant_result(role, grant)["original"]}
    bridge, runtime, _ = bridge_fixture(fresh_helper=True, lifetime_boottime_ns=lifetime_boottime_ns)
    peers = json.loads(bridge["ordinaryPeerPreparationOriginal"])
    peers["configurationSha256"] = sha(kw["launch_original"])
    for role in ROLES:
        actual, peer = f["preparation"]["services"][role], peers["peers"][role]
        peer.update(processId=actual["processId"], startTimeTicks=actual["startTimeTicks"],
            pidfd={name: actual["pidfdStat"][name] for name in ("device", "inode")},
            targetExecutable={name: actual["targetExecutable"][name] for name in ("device", "inode", "length", "sha256")})
    bridge["ordinaryPeerPreparationOriginal"] = canonical(peers).decode("ascii")
    base = head_input(f, contexts, kw, HELPER_ROLES[0])
    exported = json.loads(bridge["initialTrustRequestsOriginal"])
    inputs, outputs = {}, {}
    for job in execution.CURRENT_HEAD_JOBS:
        role, endpoint_role = execution.CURRENT_HEAD_JOB_INFO[job.name]
        row = exported["requests"][role]
        if endpoint_role is not None:
            row = row[endpoint_role]
        value = copy.deepcopy(base)
        value.update(serviceRole=role, configurationOriginal=ordinary[role]["configurationOriginal"],
            initialHistoryOriginal=ordinary[role]["historyOriginal"], requestOriginal=row["requestOriginal"])
        if endpoint_role is None:
            value["apiVersion"] = head.API
            del value["endpointRole"], value["runtimeOriginal"]
        else:
            value["endpointRole"] = endpoint_role
        authority = f["initial_policy"]["services"][role]["authorities"]
        value["rootAuthority"] = {name: authority["root"][name] for name in ("keyId", "keySpkiSha256")}
        pending = json.loads(row["requestOriginal"])
        value["currentness"] = {"profile": "initial-checkpoint-current-for-exact-request-v1",
            "initialHistorySha256": row["initialHistorySha256"], "checkpointSha256": row["checkpointSha256"],
            "requestSha256": row["requestSha256"], "requestNonceSha256": pending["requestNonceSha256"],
            "issuedAtBoottimeNanos": 1400}
        wrapper = json.loads(f["helper_histories"][endpoint_role] if endpoint_role is not None else f["histories"][role])
        checkpoint = wrapper["initialCheckpoint"]
        cp = checkpoint["payload"]
        statement = {"apiVersion": "serverware.policyCustodyProtocol/v3", "endpointRole": row["endpointRole"],
            "requestNonceSha256": pending["requestNonceSha256"], "requestSha256": row["requestSha256"],
            "checkpointSequence": cp["checkpointSequence"], "checkpointSha256": checkpoint["checkpointSha256"],
            "endpointGeneration": cp["exactEndpointGeneration"],
            "revocationGenerationHighWater": cp["revocationGenerationHighWater"],
            "revocationRootSha256": cp["revocationRootSha256"], "issuedAtBoottimeNanos": 1400,
            "deadline": pending["deadline"]}
        inputs[job.name] = canonical(value)
        outputs[job.name] = signed_result(statement, authority["checkpoint"], private(role + "/checkpoint"))
    args = dict(fragment=selection(), bridge_preparation_raw=canonical(bridge),
        driver_configuration_raw=base["driverConfigurationOriginal"].encode("ascii"),
        driver_window_raw=base["driverWindowOriginal"].encode("ascii"), launch_raw=kw["launch_original"],
        preparation_raw=kw["preparation_original"], resources_raw=kw["resources_original"],
        ordinary_context=ordinary, initial_policy=f["initial_policy"], boot=kw["boot"], now_boottime_ns=1400)
    return dict(args=args, context=profile.prepare_context(**args), inputs=inputs, outputs=outputs, runtime=runtime,
        clocks=dict(boot=kw["boot"], now_boottime_ns=1400), fixture=f)


def fixture(*, lifetime_boottime_ns=9_000_000):
    return copy.deepcopy(_fixture(lifetime_boottime_ns))


class CurrentHeadIntakeControls(unittest.TestCase):
    def test_fixed_eight_jobs_alias_existing_keys_without_publication_or_auto_approval(self):
        jobs = execution.CURRENT_HEAD_JOBS
        targets = tuple((role, None) for role in ROLES[:-1]) + tuple((HELPER, role) for role in HELPER_ROLES)
        self.assertEqual(tuple(execution.CURRENT_HEAD_JOB_INFO[job.name] for job in jobs), targets)
        self.assertEqual(tuple(job.name for job in jobs), profile.JOB_NAMES)
        self.assertEqual(execution.JOBS["bridge-runtime"][:8], jobs)
        self.assertEqual(execution.job_index("bridge-runtime", "install-bridge-runtime"), 9)
        for index, (job, (role, _)) in enumerate(zip(jobs, targets, strict=True), 1):
            self.assertEqual((job.family, job.role, job.key, job.purpose, job.maximum),
                ("current-head", role, "ordinary-initial-checkpoint-" + role, None, head.MAX_INPUT))
            self.assertEqual(execution.job_index("bridge-runtime", job.name), index)
            self.assertIn(job.key, execution.KEY_PURPOSES)
            self.assertIn(("bridge-runtime", job.name), supervisor.SUPPORTED_JOBS)
            self.assertNotIn(("bridge-runtime", job.name), supervisor._COMPOSERS)
        self.assertEqual((len(execution.KEY_PURPOSES), len(supervisor._COMPOSERS)), (113, 153))
        self.assertEqual((len(supervisor.SUPPORTED_JOBS), len(supervisor._ORDER), len(supervisor.missing_jobs())),
            (164, 164, 0))
        self.assertIsNone(supervisor.require_complete_coverage())

    def test_static_intake_policy_is_closed_and_never_contains_future_currentness(self):
        value = selection()
        selected = profile.validate_policy(value)
        self.assertEqual(selected, value)
        selected["targets"].pop()
        self.assertEqual(len(value["targets"]), 8)
        for change in ("missing", "reordered", "duplicate", "unknown", "currentness", "automatic"):
            bad = copy.deepcopy(value)
            if change == "missing": bad["targets"].pop()
            elif change == "reordered": bad["targets"].reverse()
            elif change == "duplicate": bad["targets"][-1] = bad["targets"][0]
            elif change == "unknown": bad["apiVersion"] += "-unknown"
            else: bad[change] = True
            with self.subTest(change=change), self.assertRaises(ValueError): profile.validate_policy(bad)
        self.assertEqual(set(policy.CURRENT_HEAD_FIELDS) - set(policy.HELPER_INITIAL_FIELDS), {"currentHeadIntakeOriginal"})
        self.assertEqual(policy.CURRENT_HEAD_POLICY_API, "serverware.nativePilotSupervisorCommissioningPolicy/v15")

    def test_observed_eight_requests_export_evidence_not_decision_or_authority_input(self):
        f = fixture()
        before = copy.deepcopy(f["context"])
        requests, selected_histories = set(), set()
        for name in profile.JOB_NAMES:
            raw = profile.observed_original(name, f["context"])
            value = json.loads(raw)
            target = f["context"]["targets"][name]
            self.assertEqual(value["apiVersion"], profile.OBSERVED_API)
            self.assertEqual((value["jobName"], value["serviceRole"], value["endpointRole"]),
                (name, target["serviceRole"], target["endpointRole"]))
            self.assertEqual(value["originals"]["request"], target["request"]["requestOriginal"])
            self.assertEqual(value["originals"]["selectedInitialHistory"], target["selectedHistoryOriginal"])
            self.assertEqual(value["deadlineBoottimeNanos"], target["deadline"])
            self.assertNotIn("currentness", value)
            self.assertNotIn("currentness", value["originals"])
            requests.add(value["requestSha256"])
            selected_histories.add(sha(value["originals"]["selectedInitialHistory"].encode("ascii")))
            with self.assertRaises(ValueError):
                profile.prepare_input(name, raw, context=f["context"], **f["clocks"])
        self.assertEqual((len(requests), len(selected_histories)), (8, 8))
        self.assertEqual(f["context"], before)

    def test_all_eight_complete_inputs_and_independent_checkpoint_signatures(self):
        f = fixture()
        before = copy.deepcopy((f["context"], f["inputs"], f["outputs"]))
        for name in profile.JOB_NAMES:
            raw, result = f["inputs"][name], f["outputs"][name]
            with self.subTest(job=name):
                prepared = profile.prepare_input(name, raw, context=f["context"], **f["clocks"])
                self.assertEqual(prepared["statement"], json.loads(result["original"])["statement"])
                self.assertEqual(profile.checked_result(name, raw, result, context=f["context"], **f["clocks"]),
                    result["original"].encode("ascii"))
                self.assertEqual(set(result), {"original", "sha256"})
        self.assertEqual((f["context"], f["inputs"], f["outputs"]), before)

    def test_wrong_slot_stale_or_self_consistent_replaced_request_is_not_actual_request(self):
        f = fixture(); name = profile.JOB_NAMES[-4]; raw = f["inputs"][name]
        with self.assertRaises(ValueError):
            profile.prepare_input(profile.JOB_NAMES[-3], raw, context=f["context"], **f["clocks"])
        value = json.loads(raw)
        pending = json.loads(value["requestOriginal"])
        pending["requestEntropyBase64"] = encoded(b"Z" * 32)
        refresh_request(pending)
        value["requestOriginal"] = canonical(pending).decode("ascii")
        refresh_decision(value)
        # This is independently internally valid, but not the retained request.
        head.prepare_input(canonical(value), **f["clocks"])
        with self.assertRaises(ValueError):
            profile.prepare_input(name, canonical(value), context=f["context"], **f["clocks"])
        for now in (1399, f["context"]["deadline"]):
            with self.subTest(now=now), self.assertRaises(ValueError):
                profile.prepare_input(name, raw, context=f["context"], boot=f["clocks"]["boot"], now_boottime_ns=now)
        value = json.loads(raw); del value["currentness"]
        with self.assertRaises(ValueError):
            profile.prepare_input(name, canonical(value), context=f["context"], **f["clocks"])

    def test_signed_output_still_requires_exact_input_authority_hash_and_closed_result(self):
        f = fixture(); name = profile.JOB_NAMES[0]; raw = f["inputs"][name]; result = f["outputs"][name]
        role = execution.CURRENT_HEAD_JOB_INFO[name][0]
        public = f["fixture"]["initial_policy"]["services"][role]["authorities"]["checkpoint"]
        statement = json.loads(result["original"])["statement"]
        changed = dict(statement, issuedAtBoottimeNanos=1401)
        alternatives = (result | {"sha256": labelled("wrong output")}, result | {"pin": {}},
            signed_result(statement, public, private("unapproved checkpoint")),
            signed_result(changed, public, private(role + "/checkpoint")))
        for bad in alternatives:
            with self.assertRaises((ValueError, InvalidSignature)):
                profile.checked_result(name, raw, bad, context=f["context"], **f["clocks"])

    def test_context_refuses_runtime_history_generation_peer_and_policy_substitution(self):
        f = fixture(); role = ROLES[0]
        for change in ("runtime", "history", "generation-signature", "generation-after-request",
                "peer", "future-peer", "policy-root", "window"):
            args = copy.deepcopy(f["args"])
            row = args["ordinary_context"][role]
            if change in ("runtime", "history"):
                field = change + "Original"
                row[field] = args["ordinary_context"][ROLES[1]][field]
            elif change in ("generation-signature", "generation-after-request"):
                grant = json.loads(row["generationGrantOriginal"])
                if change == "generation-signature":
                    grant["signatureBase64url"] = encoded(bytes(64))
                    row["generationGrantOriginal"] = canonical(grant).decode("ascii")
                else:
                    grant["payload"]["issuedAtBoottimeNanos"] = 1300
                    row["generationGrantOriginal"] = grant_result(role, grant["payload"])["original"]
            elif change in ("peer", "future-peer"):
                bridge = json.loads(args["bridge_preparation_raw"])
                peers = json.loads(bridge["ordinaryPeerPreparationOriginal"])
                if change == "peer": peers["peers"][role]["startTimeTicks"] += 1
                else: peers["observedAtBoottimeNs"] = "1401"
                bridge["ordinaryPeerPreparationOriginal"] = canonical(peers).decode("ascii")
                args["bridge_preparation_raw"] = canonical(bridge)
            elif change == "policy-root":
                args["initial_policy"]["services"][role]["authorities"]["root"] = copy.deepcopy(
                    args["initial_policy"]["services"][ROLES[1]]["authorities"]["root"])
            else:
                window = json.loads(args["driver_window_raw"])
                window["payload"]["startupDeadlineBoottimeNs"] = "5001"
                args["driver_window_raw"] = canonical(window)
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                profile.prepare_context(**args)

    def test_bridge_inner_association_requires_actual_eight_outputs_not_valid_replacements(self):
        f = fixture(); runtime = f["runtime"]
        jobs = {target: name for name, target in execution.CURRENT_HEAD_JOB_INFO.items()}
        for session in runtime["serviceSessions"]:
            role = session["serviceRole"]
            for item in session["handshakes"]:
                name = jobs[role, item["endpointRole"] if role == HELPER else None]
                item["request"] = json.loads(handshakes.build(f["inputs"][name], f["outputs"][name],
                    **f["clocks"], client_process_identity_sha256=runtime["expectedDriverProcessIdentitySha256"],
                    client_configuration_generation_sha256=runtime["expectedDriverConfigurationGenerationSha256"]))
        # Not a PhaseExecution owner: exercise only the existing inner byte join.
        data = SimpleNamespace(_inputs=f["inputs"], _outputs={name: value["original"].encode("ascii")
            for name, value in f["outputs"].items()}, _boot=f["clocks"]["boot"])
        with patch.object(execution.originals, "_clock", return_value=1401):
            self.assertIsNone(execution.PhaseExecution._bind_bridge_heads(data, runtime))
            missing = copy.deepcopy(runtime); missing["serviceSessions"][-1]["handshakes"].pop()
            with self.assertRaises(ValueError): execution.PhaseExecution._bind_bridge_heads(data, missing)
            name = profile.JOB_NAMES[0]; role = ROLES[0]
            alternate_input = json.loads(f["inputs"][name]); alternate_input["currentness"]["issuedAtBoottimeNanos"] = 1401
            statement = dict(json.loads(f["outputs"][name]["original"])["statement"], issuedAtBoottimeNanos=1401)
            public = f["fixture"]["initial_policy"]["services"][role]["authorities"]["checkpoint"]
            alternate = signed_result(statement, public, private(role + "/checkpoint"))
            alternate_raw = canonical(alternate_input)
            self.assertEqual(profile.checked_result(name, alternate_raw, alternate, context=f["context"],
                boot=f["clocks"]["boot"], now_boottime_ns=1401), alternate["original"].encode("ascii"))
            runtime["serviceSessions"][0]["handshakes"][0]["request"] = json.loads(handshakes.build(
                alternate_raw, alternate, boot=f["clocks"]["boot"], now_boottime_ns=1401,
                client_process_identity_sha256=runtime["expectedDriverProcessIdentitySha256"],
                client_configuration_generation_sha256=runtime["expectedDriverConfigurationGenerationSha256"]))
            with self.assertRaises(ValueError): execution.PhaseExecution._bind_bridge_heads(data, runtime)

    def test_inner_prior_verifies_once_and_rejects_changed_retained_originals(self):
        # This is only the inner cache/association method. The namespace below
        # is NOT a CurrentHeadIntake or coordinator owner; original-source,
        # lifetime and process guards of check() are neither exercised nor
        # replaced. The first cryptographic verification is the real helper.
        f = fixture(); name = profile.JOB_NAMES[0]; role = ROLES[0]
        raw, result = f["inputs"][name], f["outputs"][name]
        alternate_input = json.loads(raw)
        alternate_input["currentness"]["issuedAtBoottimeNanos"] = 1401
        alternate_raw = canonical(alternate_input)
        statement = dict(json.loads(result["original"])["statement"], issuedAtBoottimeNanos=1401)
        public = f["fixture"]["initial_policy"]["services"][role]["authorities"]["checkpoint"]
        alternate_result = signed_result(statement, public, private(role + "/checkpoint"))
        self.assertEqual(head.checked_result(alternate_raw, alternate_result,
            boot=f["clocks"]["boot"], now_boottime_ns=1401), alternate_result["original"].encode("ascii"))
        observed = dict(input=raw, pin=sha(raw), result=copy.deepcopy(result))
        def supplied(field, phase, job):
            self.assertEqual((phase, job), ("bridge-runtime", name))
            return observed[field]
        process_data = SimpleNamespace(
            approved_input_original=lambda phase, job: supplied("input", phase, job),
            approved_input_sha256=lambda phase, job: supplied("pin", phase, job),
            prior_result=lambda phase, job: supplied("result", phase, job))
        reservations = []
        data = SimpleNamespace(_process=process_data, _inputs={name: raw}, _outputs={}, _results={},
            _context=f["context"], _boot=f["clocks"]["boot"], _clock=lambda: 1401,
            _reserve=reservations.append)
        with patch.object(intake.profile, "checked_result", wraps=profile.checked_result) as verify:
            self.assertIsNone(intake.CurrentHeadIntake._prior(data, 1))
            self.assertEqual(verify.call_count, 1)
            self.assertEqual(data._outputs, {name: result["original"].encode("ascii")})
            self.assertEqual(data._results, {name: canonical(result)})
            cached = copy.deepcopy((data._inputs, data._outputs, data._results, reservations))
            for _ in range(3):
                self.assertIsNone(intake.CurrentHeadIntake._prior(data, 1))
            self.assertEqual(verify.call_count, 1)
            mutations = (
                dict(input=alternate_raw, pin=sha(alternate_raw), result=copy.deepcopy(result)),
                dict(input=raw, pin=labelled("substituted retained input pin"), result=copy.deepcopy(result)),
                dict(input=raw, pin=sha(raw), result=alternate_result),
            )
            for changed in mutations:
                observed.clear(); observed.update(changed)
                with self.assertRaises(ValueError): intake.CurrentHeadIntake._prior(data, 1)
                self.assertEqual((data._inputs, data._outputs, data._results, reservations), cached)
                self.assertEqual(verify.call_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
