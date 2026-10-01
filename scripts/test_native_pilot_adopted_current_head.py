#!/usr/bin/env python3
"""Pure signed synthetic adopted current-head controls, never live currentness.

All observations, clocks, requests, keys and separately supplied currentness
decisions are test-only. Genuine signature formulas bind complete synthetic
State3/Runtime12/C9 originals; no owner, authority CLI or service is invoked.
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from serverware import custody_generation_grants as g
from serverware import native_pilot_bridge_preparation as bridge
from serverware import native_pilot_current_head_profile as head
from serverware import native_pilot_initial_requests_profile as requests
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_install as installation
from serverware import native_pilot_ordinary_runtime_profile as runtime
from serverware import native_pilot_peer_preparation as peers
from serverware import native_pilot_service_authority as service
from serverware import native_pilot_supervisor_current_head_profile as intake
from test_native_pilot_current_head import refresh_decision, refresh_request, signed_result
from test_native_pilot_current_head_intake import fixture as old_fixture
from test_native_pilot_helper_initial import export, refresh
from test_native_pilot_ordinary_commissioning import private
from test_native_pilot_ordinary_generations import result as generation_result
from test_native_pilot_ordinary_keys import canonical, encoded, labelled, sha

FAILURES = (ValueError, KeyError, TypeError, InvalidSignature)


@lru_cache(maxsize=1)
def _fixture():
    source = old_fixture()
    f = source["fixture"]
    args = source["args"]
    f["launch"]["apiVersion"] = "serverware.custodyFiveServiceLaunch/v7"
    f["preparation"]["configurationSha256"] = sha(canonical(f["launch"]))
    f["resources"].update(apiVersion="serverware.custodyFiveServiceInitialResources/v2",
        preparationSha256=sha(canonical(f["preparation"])))
    for index in (0, 3):
        role = g.ROLES[index]
        row = copy.deepcopy(next(iter(f["resources"]["services"][role]["directories"].values())))
        row["identity"]["inode"] = 97200 + index
        f["resources"]["services"][role]["directories"]["publication-journal"] = row

    def reissue(raw):
        wrapper = json.loads(raw)
        state = wrapper["initialState"]
        role = state["serviceRole"]
        selected = role in initial.ADOPTED_ROLES
        wrapper["apiVersion"] = initial.ADOPTED_WRAPPER_API if selected else initial.WRAPPER_API
        state.update(apiVersion=initial.ADOPTED_STATE_API if selected else initial.STATE_API,
            preparationSha256=sha(canonical(f["preparation"])), resourcesSha256=sha(canonical(f["resources"])),
            launchSha256=sha(canonical(f["launch"])), directories=copy.deepcopy(f["resources"]["services"][role]["directories"]))
        return canonical(refresh(wrapper))

    f["histories"] = {role: reissue(raw) for role, raw in f["histories"].items()}
    f["helper_histories"] = {role: reissue(raw) for role, raw in f["helper_histories"].items()}
    f["runtimes"] = {role: runtime.build(role, fragment=f["fragment"], history_originals=f["histories"],
        preparation_raw=canonical(f["preparation"]), resources_raw=canonical(f["resources"]),
        launch_raw=canonical(f["launch"]), configuration_raw=canonical(f["cold"][role]),
        peer=json.loads(raw)["runtime"]["expectedPeer"], helper_history_originals=f["helper_histories"], adopted=True)
        for role, raw in f["runtimes"].items()}
    files = installation.plan(runtime_originals=f["runtimes"], history_originals=f["histories"],
        cold_originals={role: canonical(f["cold"][role]) for role in g.ROLES},
        launch_original=canonical(f["launch"]), adopted=True)
    contexts, ordinary = {}, {}
    for index, role in enumerate(g.ROLES):
        old = args["ordinary_context"][role]
        delivery = json.loads(old["deliveryOriginal"])
        payload = delivery["payload"]
        payload["runtimeConfig"]["sha256"] = sha(f["runtimes"][role])
        for kind, name in (("history", "authority-history"), ("inspection", "peer-inspection-policy")):
            file = next(row for row in files if row["role"] == role and row["kind"] == kind)
            credential = next(row for row in payload["credentials"] if row["name"] == name)
            credential.update(original={"path": file["path"], "sha256": sha(file["raw"])}, length=len(file["raw"]))
        if role in initial.ADOPTED_ROLES:
            for name in ("publication-journal", "publication-grant"):
                payload["activation"].append({"name": name, "fd": 6 + len(payload["activation"]),
                    "device": 8, "inode": 970000 + index * 100 + len(payload["activation"]),
                    "mode": (stat.S_IFREG | 0o600) if name.endswith("grant") else stat.S_IFDIR | 0o700,
                    "uid": f["cold"][role]["uid"], "gid": f["cold"][role]["gid"]})
        delivery["signatureBase64url"] = encoded(f["delivery_keys"][role].sign(g.c9.DOMAIN + canonical(payload)))
        delivery_raw = canonical(delivery)
        cold_raw = canonical(f["cold"][role])
        _, guest = g._admit_delivery(signed_raw=delivery_raw, cold_raw=cold_raw, cold_sha=sha(cold_raw),
            role=role, activation=payload["activation"], boot=args["boot"], startup=5000,
            lifetime=int(f["launch"]["lifetimeDeadlineBoottimeNs"]), now=1300, **service._flags(role, adopted=True))
        grant = json.loads(old["generationGrantOriginal"])["payload"]
        grant.update(guest=guest, runtimeConfigurationSha256=sha(f["runtimes"][role]),
            authorityHistoryManifestSha256=json.loads(f["histories"][role])["history"]["manifestSha256"])
        ordinary[role] = {"configurationOriginal": cold_raw.decode("ascii"), "configurationSha256": sha(cold_raw),
            "deliveryOriginal": delivery_raw.decode("ascii"), "runtimeOriginal": f["runtimes"][role].decode("ascii"),
            "historyOriginal": f["histories"][role].decode("ascii"),
            "generationGrantOriginal": generation_result(role, grant)["original"]}
        contexts[role] = dict(configurationOriginal=cold_raw, runtimeOriginal=f["runtimes"][role],
            historyOriginal=f["histories"][role], guest=guest)
    kw = dict(preparation_original=canonical(f["preparation"]), resources_original=canonical(f["resources"]),
        launch_original=canonical(f["launch"]), window=f["window"], boot=args["boot"], now_boottime_ns=1400)
    exported = export(requests.select(contexts, **kw, adopted=True), kw)
    observed = json.loads(args["bridge_preparation_raw"])
    observed.update(apiVersion=bridge.ADOPTED_API, initialTrustRequestsOriginal=canonical(exported).decode("ascii"))
    native = json.loads(observed["nativePeerPreparationOriginal"])
    native["apiVersion"] = peers.ADOPTED_API
    extra = copy.deepcopy(native["peers"]["retrieval"])
    extra.update(processId=97531, startTimeTicks=97001)
    extra["pidfd"]["inode"] = 979797
    native["peers"]["publicationReconciliation"] = extra
    observed["nativePeerPreparationOriginal"] = canonical(native).decode("ascii")
    ordinary_peers = json.loads(observed["ordinaryPeerPreparationOriginal"])
    ordinary_peers.update(configurationSha256=sha(kw["launch_original"]), sourceOriginalSha256=sha(kw["launch_original"]))
    observed["ordinaryPeerPreparationOriginal"] = canonical(ordinary_peers).decode("ascii")
    args.update(bridge_preparation_raw=canonical(observed), launch_raw=kw["launch_original"],
        preparation_raw=kw["preparation_original"], resources_raw=kw["resources_original"], ordinary_context=ordinary)
    inputs, outputs = {}, {}
    for name, (role, endpoint) in zip(intake.JOB_NAMES, intake.TARGETS, strict=True):
        selected = exported["requests"][role] if endpoint is None else exported["requests"][role][endpoint]
        pending = json.loads(selected["requestOriginal"])
        value = json.loads(source["inputs"][name])
        value.update(apiVersion=head.ADOPTED_API, endpointRole=selected["endpointRole"],
            runtimeOriginal=ordinary[role]["runtimeOriginal"], initialHistoryOriginal=ordinary[role]["historyOriginal"],
            launchOriginal=kw["launch_original"].decode("ascii"), preparationOriginal=kw["preparation_original"].decode("ascii"),
            resourcesOriginal=kw["resources_original"].decode("ascii"), requestOriginal=selected["requestOriginal"])
        value["currentness"].update(initialHistorySha256=selected["initialHistorySha256"],
            checkpointSha256=selected["checkpointSha256"], requestSha256=selected["requestSha256"],
            requestNonceSha256=pending["requestNonceSha256"])
        cp = json.loads(f["histories"][role] if endpoint is None else f["helper_histories"][endpoint])["initialCheckpoint"]
        statement = json.loads(source["outputs"][name]["original"])["statement"]
        statement.update(requestNonceSha256=pending["requestNonceSha256"], requestSha256=selected["requestSha256"],
            checkpointSha256=cp["checkpointSha256"], deadline=pending["deadline"])
        inputs[name] = canonical(value)
        authority = f["initial_policy"]["services"][role]["authorities"]["checkpoint"]
        outputs[name] = signed_result(statement, authority, private(role + "/checkpoint"))
    return dict(args=args, context=intake.prepare_context(**args), inputs=inputs, outputs=outputs,
        clocks=source["clocks"], fixture=f)


def fixture():
    return copy.deepcopy(_fixture())


class AdoptedCurrentHeadControls(unittest.TestCase):
    def test_all_eight_signed_decisions_and_same_call_intake(self):
        f = fixture()
        self.assertTrue(intake.adoption_selected(f["context"]))
        for name in intake.JOB_NAMES:
            raw, result = f["inputs"][name], f["outputs"][name]
            with self.subTest(job=name):
                prepared = head.prepare_input(raw, **f["clocks"], adopted=True)
                self.assertEqual(prepared["statement"], json.loads(result["original"])["statement"])
                self.assertEqual(intake._prepared_input(name, raw, context=f["context"], **f["clocks"]), prepared)
                self.assertEqual(intake.checked_result(name, raw, result, context=f["context"], **f["clocks"]),
                    result["original"].encode("ascii"))

    def test_old_and_adopted_selection_remain_disjoint(self):
        f = fixture(); old = old_fixture()
        for name in intake.JOB_NAMES:
            with self.subTest(job=name), self.assertRaises(FAILURES):
                head.prepare_input(f["inputs"][name], **f["clocks"])
            with self.assertRaises(FAILURES):
                head.prepare_input(old["inputs"][name], **old["clocks"], adopted=True)
            with self.assertRaises(FAILURES):
                intake.prepare_input(name, f["inputs"][name], context=old["context"], **old["clocks"])

    def test_both_runtime_twelve_targets_bind_actual_state_and_keys(self):
        f = fixture()
        for role in initial.ADOPTED_ROLES:
            raw = f["inputs"]["current-head-" + role]
            for mutation in ("version", "history", "directories", "generation", "root", "checkpoint"):
                value = json.loads(raw); selected = json.loads(value["runtimeOriginal"])
                if mutation == "version": selected["runtime"]["apiVersion"] = "serverware.policyCustodyServiceRuntimeConfig/v8"
                elif mutation == "history": selected["runtime"]["authorityHistoryManifestSha256"] = labelled("other manifest")
                elif mutation == "directories": selected["runtime"]["activationDirectoryIdentities"]["publication-journal"]["inode"] += 1
                elif mutation == "generation": selected["runtime"]["operationGeneration"] += 1
                elif mutation == "root": selected["runtime"]["authorityHistoryRootKeyId"] = labelled("other root")
                elif role == g.ROLES[0]: selected["currentKeyAuthorizationCheckpointSha256"] = labelled("other checkpoint")
                else: selected["serviceSigningPin"]["signedCurrentKeyAuthorization"]["authoritySignatureBase64"] = encoded(bytes(64))
                value["runtimeOriginal"] = canonical(selected).decode("ascii")
                with self.subTest(role=role, mutation=mutation), self.assertRaises(FAILURES):
                    head.prepare_input(canonical(value), **f["clocks"], adopted=True)

    def test_supplied_decision_and_retained_request_are_not_replaceable(self):
        f = fixture(); name = intake.JOB_NAMES[0]
        value = json.loads(f["inputs"][name])
        absent = copy.deepcopy(value); del absent["currentness"]
        with self.assertRaises(FAILURES): head.prepare_input(canonical(absent), **f["clocks"], adopted=True)
        pending = json.loads(value["requestOriginal"])
        pending["requestEntropyBase64"] = encoded(b"Z" * 32); refresh_request(pending)
        value["requestOriginal"] = canonical(pending).decode("ascii"); refresh_decision(value)
        # Internally valid separately supplied decision is not the actual retained request.
        head.prepare_input(canonical(value), **f["clocks"], adopted=True)
        with self.assertRaises(FAILURES):
            intake.prepare_input(name, canonical(value), context=f["context"], **f["clocks"])

    def test_all_original_clocks_and_exact_runtime_source_remain_bound(self):
        f = fixture(); name = intake.JOB_NAMES[0]; raw = f["inputs"][name]
        deadline = f["context"]["deadline"]
        for clocks in (f["clocks"] | {"now_boottime_ns": deadline},
                f["clocks"] | {"boot": (f["clocks"]["boot"][0], 12, 13)}):
            with self.assertRaises(FAILURES): head.prepare_input(raw, **clocks, adopted=True)
        value = json.loads(raw); selected = json.loads(value["runtimeOriginal"])
        selected["runtime"]["startupTimeoutMillis"] += 1
        value["runtimeOriginal"] = canonical(selected).decode("ascii")
        head.prepare_input(canonical(value), **f["clocks"], adopted=True)
        with self.assertRaises(FAILURES): intake.prepare_input(name, canonical(value), context=f["context"], **f["clocks"])

    def test_checkpoint_authority_cannot_be_replaced_by_root_or_service_key(self):
        f = fixture(); name = intake.JOB_NAMES[0]; role = g.ROLES[0]
        statement = json.loads(f["outputs"][name]["original"])["statement"]
        authority = f["fixture"]["initial_policy"]["services"][role]["authorities"]["checkpoint"]
        for other in ("root", "service"):
            signed = signed_result(statement, authority, private(role + "/" + other))
            with self.assertRaises(FAILURES):
                head.checked_result(f["inputs"][name], signed, **f["clocks"], adopted=True)

    def test_helper_member_swaps_and_missing_runtime_are_refused(self):
        f = fixture(); name = intake.JOB_NAMES[-1]
        for mutation in ("endpoint", "runtime", "history"):
            value = json.loads(f["inputs"][name])
            if mutation == "endpoint": value["endpointRole"] = initial.HELPER_ENDPOINT_ROLES[0]
            elif mutation == "runtime": del value["runtimeOriginal"]
            else: value["initialHistoryOriginal"] = f["fixture"]["helper_histories"][initial.HELPER_ENDPOINT_ROLES[0]].decode("ascii")
            with self.subTest(mutation=mutation), self.assertRaises(FAILURES):
                head.prepare_input(canonical(value), **f["clocks"], adopted=True)

    def test_observation_is_evidence_only_and_native_signed_i64_stays_closed(self):
        f = fixture(); name = intake.JOB_NAMES[0]
        observed = json.loads(intake.observed_original(name, f["context"]))
        self.assertNotIn("currentness", observed)
        self.assertEqual(observed["originals"]["runtime"], json.loads(f["inputs"][name])["runtimeOriginal"])
        with self.assertRaises(FAILURES): head.prepare_input(canonical(observed), **f["clocks"], adopted=True)
        signed = json.loads(f["outputs"][name]["original"])
        statement = signed["statement"] | {"revocationGenerationHighWater": 1 << 63}
        with self.assertRaises(FAILURES): head.signature_preimage(statement, signed["authorityKeyId"], signed["authorityKeySpkiSha256"])


if __name__ == "__main__":
    unittest.main()
