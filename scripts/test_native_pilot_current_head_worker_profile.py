#!/usr/bin/env python3
"""Pure signed-source decisions with explicitly synthetic authority state.

Only this test fixture projects matching state rows from synthetic histories.
Production requires a separately authorized maintained state original; neither
these rows nor successful pure validation claim actual freshness or file custody.
No process/store owner or successful validator is fabricated or mocked.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
from scripts.test_native_pilot_approval_current_heads import fixture as head_fixture
from catchplate import native_pilot_current_head_worker_profile as profile

p = profile.p
ERRORS = (ValueError, KeyError, TypeError, InvalidSignature)


def fixture():
    cases = []
    targets = {}
    for name in profile.JOB_NAMES:
        case = head_fixture(name)
        evidence_raw = profile.heads.observed_original(name, case["source"]["context"])
        evidence = p.document(evidence_raw, profile.MAX_EVIDENCE)
        wrapper = p.document(evidence["originals"]["selectedInitialHistory"].encode("ascii"), profile.head.g.MAX_BYTES)
        initial, checkpoint = wrapper["initialState"], wrapper["initialCheckpoint"]
        payload = checkpoint["payload"]
        row = dict(serviceRole=evidence["serviceRole"], endpointRole=evidence["endpointRole"],
            rootAuthority=copy.deepcopy(evidence["rootAuthority"]),
            checkpointAuthority={key: evidence["checkpointAuthority"][key] for key in ("keyId", "keySpkiSha256")},
            initialHistorySha256=p.sha(evidence["originals"]["selectedInitialHistory"].encode("ascii")),
            checkpointSequence=payload["checkpointSequence"], checkpointSha256=checkpoint["checkpointSha256"],
            revocationGenerationHighWater=payload["revocationGenerationHighWater"],
            revocationRootSha256=payload["revocationRootSha256"], status="active")
        row.update({key: initial[key] for key in ("endpointProcessIdentitySha256", "deploymentGenerationSha256",
            "endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch")})
        targets[name] = row
        cases.append(case | dict(request_raw=case["pending"]["requestOriginal"].encode("ascii"), evidence_raw=evidence_raw))
    first = p.document(cases[0]["evidence_raw"], profile.MAX_EVIDENCE)
    window = p.document(first["originals"]["driverWindow"].encode("ascii"), 32768)["payload"]
    clocks = cases[0]["clocks"]
    current = dict(apiVersion=profile.STATE_API, generation=1,
        **dict(zip(profile.BOOT, clocks["boot"], strict=True)), invocationId=window["invocationId"],
        **{field: p.sha(first["originals"][source].encode("ascii")) for field, source in
            (("driverConfigurationSha256", "driverConfiguration"), ("driverWindowSha256", "driverWindow"),
             ("launchSha256", "launch"))}, issuedAtBoottimeNs="1", deadlineBoottimeNs="8000",
        issuedAtUnixNanos=1, expiresAtUnixNanos=10000, targets=targets)
    state_raw = p.canonical(current)
    policy = dict(apiVersion=profile.API, purpose=profile.PURPOSE,
        supervisorInventorySha256=p.sha(b"synthetic installed worker inventory"),
        stateDirectory=dict(device=20, inode=21), decisionDirectory=dict(device=20, inode=22),
        initialStateSha256=p.sha(state_raw), initialStateGeneration=1,
        **dict(zip(profile.BOOT, clocks["boot"], strict=True)), issuedAtBoottimeNs="1", deadlineBoottimeNs="8000",
        issuedAtUnixNanos=1, expiresAtUnixNanos=10000)
    return dict(cases=cases, state=current, state_raw=state_raw, policy=policy, clocks=clocks)


def prepared(source, policy=None, **changes):
    value = source["policy"] if policy is None else policy
    return profile.prepare(p.canonical(value), inventory_sha256=source["policy"]["supervisorInventorySha256"],
        **(source["clocks"] | changes))


def composed(source, index=0, *, current=None, policy=None, request_raw=None, evidence_raw=None, **clocks):
    case = source["cases"][index]
    first = p.document(source["cases"][0]["request_raw"], profile.MAX_REQUEST)["conductorRequest"]
    return profile.compose(case["request_raw"] if request_raw is None else request_raw,
        case["evidence_raw"] if evidence_raw is None else evidence_raw,
        source["state_raw"] if current is None else p.canonical(current), prepared(source, policy), index=index,
        first_conductor_raw=None if index == 0 else p.canonical(first), **(source["clocks"] | clocks))


def update_value(source, after, *, initial=False):
    return dict(apiVersion=profile.UPDATE_API, directory=source["policy"]["stateDirectory"],
        expectedStateSha256=None if initial else p.sha(source["state_raw"]),
        expectedGeneration=0 if initial else source["state"]["generation"], nextStateOriginal=p.canonical(after).decode("ascii"))


class CurrentHeadWorkerProfileControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.source = fixture()

    def test_exact_eight_state_rows_keep_shared_helper_endpoint_roles(self):
        value = profile.state(self.source["state_raw"])
        self.assertEqual(set(value["targets"]), set(profile.JOB_NAMES))
        self.assertEqual(len({(row["serviceRole"], row["endpointRole"]) for row in value["targets"].values()}), 8)
        self.assertLess(len({row["endpointRole"] for row in value["targets"].values()}), 8)
        self.assertEqual(profile.STATE_DIRECTORY, "/etc/catchplate/native-pilot-current-head-state")
        for change in ("extra", "missing", "bool"):
            value = copy.deepcopy(self.source["state"])
            if change == "extra": value["fresh"] = True
            elif change == "missing": del value["targets"][profile.JOB_NAMES[-1]]
            else: value["generation"] = True
            with self.subTest(change=change), self.assertRaises(ERRORS): profile.state(p.canonical(value))

    def test_initializer_is_explicit_empty_store_generation_one_only(self):
        source = self.source
        raw = p.canonical(update_value(source, source["state"], initial=True))
        self.assertEqual(profile.update(raw, None), source["state_raw"])
        with self.assertRaises(ERRORS): profile.update(raw, source["state_raw"])
        after = copy.deepcopy(source["state"]); after["generation"] = 2
        with self.assertRaises(ERRORS): profile.update(p.canonical(update_value(source, after, initial=True)), None)
        with self.assertRaises(ERRORS): profile.update(p.canonical(update_value(source, after)), None)

    def test_explicit_monotonic_cas_can_revoke_but_cannot_reset_or_renew(self):
        source = self.source
        after = copy.deepcopy(source["state"]); after["generation"] += 1
        row = after["targets"][profile.JOB_NAMES[0]]
        row.update(status="revoked", revocationGenerationHighWater=row["revocationGenerationHighWater"] + 1,
            revocationRootSha256=p.sha(b"independent updated revocation root"))
        raw = p.canonical(update_value(source, after))
        self.assertEqual(profile.update(raw, source["state_raw"]), p.canonical(after))
        for change in ("pin", "generation", "scope", "renew", "root"):
            value = update_value(source, after); next_state = copy.deepcopy(after)
            if change == "pin": value["expectedStateSha256"] = p.sha(b"other")
            elif change == "generation": value["expectedGeneration"] += 1
            elif change == "scope": next_state["launchSha256"] = p.sha(b"other launch")
            elif change == "renew": next_state["deadlineBoottimeNs"] = "8001"
            else:
                next_state["targets"][profile.JOB_NAMES[0]]["revocationGenerationHighWater"] -= 1
            value["nextStateOriginal"] = p.canonical(next_state).decode("ascii")
            with self.subTest(change=change), self.assertRaises(ERRORS): profile.update(p.canonical(value), source["state_raw"])
        undo = copy.deepcopy(after); undo["generation"] += 1
        undo["targets"][profile.JOB_NAMES[0]]["status"] = "active"
        value = dict(apiVersion=profile.UPDATE_API, directory=source["policy"]["stateDirectory"],
            expectedStateSha256=p.sha(p.canonical(after)), expectedGeneration=after["generation"],
            nextStateOriginal=p.canonical(undo).decode("ascii"))
        with self.assertRaises(ERRORS): profile.update(p.canonical(value), p.canonical(after))

    def test_full_eight_compositions_reenter_existing_input_and_approval_validators(self):
        source = self.source; conductor = None
        for index, case in enumerate(source["cases"]):
            with self.subTest(job=profile.JOB_NAMES[index]):
                result = profile.compose(case["request_raw"], case["evidence_raw"], source["state_raw"], prepared(source),
                    index=index, first_conductor_raw=conductor, **source["clocks"])
                conductor = result["conductorOriginal"]
                profile.delivery.require_pair(case["pending"], case["evidence_raw"], result["inputOriginal"],
                    result["approvalOriginal"], **source["clocks"])
                value = p.document(result["inputOriginal"], profile.head.MAX_INPUT)
                self.assertEqual(value["currentness"]["issuedAtBoottimeNanos"], source["clocks"]["now_boottime_ns"])
                self.assertEqual((result["deadline"], result["epochLimit"]), (5000, 9000))

    def test_any_baseline_change_or_revoked_row_refuses_before_output(self):
        source = self.source
        changed = copy.deepcopy(source["state"]); changed["generation"] += 1
        with self.assertRaises(ERRORS): composed(source, current=changed)
        revoked = copy.deepcopy(source["state"]); revoked["targets"][profile.JOB_NAMES[-1]]["status"] = "revoked"
        policy = source["policy"] | {"initialStateSha256": p.sha(p.canonical(revoked))}
        with self.assertRaises(ERRORS): composed(source, current=revoked, policy=policy)
        for field in ("checkpointSequence", "endpointGeneration", "revocationGenerationHighWater"):
            changed = copy.deepcopy(source["state"]); changed["targets"][profile.JOB_NAMES[0]][field] += 1
            policy = source["policy"] | {"initialStateSha256": p.sha(p.canonical(changed))}
            with self.subTest(field=field), self.assertRaises(ERRORS): composed(source, current=changed, policy=policy)

    def test_authority_identity_history_scope_and_revocation_root_are_exact(self):
        source = self.source
        for field in ("rootAuthority", "checkpointAuthority", "initialHistorySha256", "endpointProcessIdentitySha256",
                "deploymentGenerationSha256", "checkpointSha256", "revocationRootSha256"):
            changed = copy.deepcopy(source["state"]); row = changed["targets"][profile.JOB_NAMES[0]]
            if field.endswith("Authority"): row[field]["keyId"] = p.sha(b"other authority")
            else: row[field] = p.sha(b"other exact state")
            policy = source["policy"] | {"initialStateSha256": p.sha(p.canonical(changed))}
            with self.subTest(field=field), self.assertRaises(ERRORS): composed(source, current=changed, policy=policy)

    def test_outer_request_caps_must_fit_policy_and_state_without_wire_rewrite(self):
        source = self.source
        for change in ({"deadlineBoottimeNs": "4999"}, {"expiresAtUnixNanos": 8999}):
            with self.subTest(change=change), self.assertRaises(ERRORS): composed(source, policy=source["policy"] | change)
        for changes in ({"now_boottime_ns": 5000}, {"now_unix_ns": 9000},
                {"boot": (source["clocks"]["boot"][0], 1, 999)}):
            with self.subTest(clocks=changes), self.assertRaises(ERRORS): composed(source, **changes)
        result = composed(source)
        approval = p.document(result["approvalOriginal"], profile.intake.MAX_APPROVAL)
        self.assertEqual((approval["deadlineBoottimeNs"], approval["expiresAtUnixNanos"]), ("5000", "9000"))

    def test_actual_first_conductor_and_eight_job_order_cannot_be_synthesized(self):
        source = self.source; second = source["cases"][1]
        with self.assertRaises(ERRORS): profile.bounds(second["request_raw"], second["evidence_raw"], index=1,
            first_conductor_raw=None)
        first = p.document(source["cases"][0]["request_raw"], profile.MAX_REQUEST)["conductorRequest"]
        changed = copy.deepcopy(first); changed["payload"]["extra"] = "not original"
        with self.assertRaises(ERRORS): profile.bounds(second["request_raw"], second["evidence_raw"], index=1,
            first_conductor_raw=p.canonical(changed))
        with self.assertRaises(ERRORS): profile.bounds(second["request_raw"], second["evidence_raw"], index=0,
            first_conductor_raw=None)
        with self.assertRaises(ERRORS): profile.bounds(source["cases"][0]["request_raw"], source["cases"][0]["evidence_raw"],
            index=False, first_conductor_raw=None)

    def test_altered_evidence_cannot_authorize_an_input_with_valid_state_pin(self):
        source = self.source; case = source["cases"][0]
        for field in ("requestNonceSha256", "checkpointSha256", "rootAuthority"):
            value = p.document(case["evidence_raw"], profile.MAX_EVIDENCE)
            if field == "rootAuthority": value[field]["keyId"] = p.sha(b"other")
            else: value[field] = p.sha(b"other")
            with self.subTest(field=field), self.assertRaises(ERRORS): composed(source, evidence_raw=p.canonical(value))
        value = p.document(case["evidence_raw"], profile.MAX_EVIDENCE)
        value["originals"]["primaryInitialHistory"] = "{}"
        with self.assertRaises(ERRORS): composed(source, evidence_raw=p.canonical(value))

    def test_consumption_receipt_binds_exact_input_approval_nonce_and_baseline(self):
        source = self.source; result = composed(source)
        value = profile.receipt(result["receiptOriginal"])
        self.assertEqual(value["stateSha256"], p.sha(source["state_raw"]))
        self.assertEqual(value["stateGeneration"], 1)
        self.assertEqual(value["requestSha256"], p.sha(source["cases"][0]["request_raw"]))
        self.assertEqual(value["evidenceSha256"], p.sha(source["cases"][0]["evidence_raw"]))
        self.assertEqual(value["inputSha256"], p.sha(result["inputOriginal"]))
        self.assertEqual(value["approvalSha256"], p.sha(result["approvalOriginal"]))
        for change in ({"stateGeneration": True}, {"job": "*"}, {"expiresAtUnixNanos": 9000}, {"success": True}):
            with self.subTest(change=change), self.assertRaises(ERRORS): profile.receipt(p.canonical(value | change))


if __name__ == "__main__": unittest.main()
