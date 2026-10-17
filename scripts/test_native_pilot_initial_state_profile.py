#!/usr/bin/env python3
"""Pure initial-state projections; no current-state or installation ownership.

Only this fixture derives a matching synthetic delegation from signed synthetic
histories. Production receives independently authorized counter/revocation and
active-state choices before installation. Tiny inert package inventories are
real codec inputs, not installed supervisor admission. No validator is mocked.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
from scripts import native_pilot_runtime_artifacts as artifacts
from scripts import test_native_pilot_adopted_ordinary_inputs as ordinary_fixture
from scripts import test_native_pilot_supervisor_runtime as runtime_fixture
from catchplate import native_pilot_initial_state_profile as profile
from catchplate import native_pilot_adopted_ordinary_install as installation

p, worker = profile.p, profile.worker
ERRORS = (ValueError, KeyError, TypeError, InvalidSignature)


def fixture(parent):
    source = ordinary_fixture.fixture()
    installation_original = source["records"]["install-ordinary-runtime"]["input"]
    installed = p.document(installation_original, profile.MAX_INPUT)
    root, package_source = runtime_fixture.fixture(parent, profile="supervisor")
    inventory_raw = artifacts._canonical(artifacts.supervisor_inventory(root, package_source))
    window = p.document(installed["driverWindowOriginal"].encode("ascii"), 32768)["payload"]
    helper = profile.runtime.validate_runtime(profile.g.ROLES[-1],
        installed["runtimeOriginals"][profile.g.ROLES[-1]].encode("ascii"), adopted=True)
    rows, deadlines = {}, []
    for name in worker.JOB_NAMES:
        role, endpoint = worker.phase.legacy.CURRENT_HEAD_JOB_INFO[name]
        text = installed["historyOriginals"][role] if endpoint is None else helper["initialEndpointHistories"][endpoint]
        wrapper = profile.g.document(text.encode("ascii"), profile.g.MAX_BYTES)
        state, checkpoint, history = wrapper["initialState"], wrapper["initialCheckpoint"], wrapper["history"]
        epoch, payload = history["firstRetainedEpoch"]["retainedEpoch"], checkpoint["payload"]
        rows[name] = dict(serviceRole=role, endpointRole=payload["endpointRole"],
            rootAuthority={field: history["rootAuthority"][field] for field in ("keyId", "keySpkiSha256")},
            checkpointAuthority={field: epoch["checkpointAuthority"][field] for field in ("keyId", "keySpkiSha256")},
            **{field: state[field] for field in ("endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch")},
            **{field: payload[field] for field in ("checkpointSequence", "revocationGenerationHighWater", "revocationRootSha256")},
            status="active")
        deadlines.append(payload["validUntilBoottime"]["absoluteBoottimeNanos"])
    clocks = source["clocks"]
    value = dict(apiVersion=profile.API, purpose=profile.PURPOSE, supervisorInventorySha256=p.sha(inventory_raw),
        stateDirectory=dict(device=20, inode=21), decisionDirectory=dict(device=20, inode=22),
        **{field: window[field] for field in (*worker.BOOT, "invocationId")},
        driverConfigurationSha256=p.sha(installed["driverConfigurationOriginal"].encode("ascii")),
        driverWindowSha256=p.sha(installed["driverWindowOriginal"].encode("ascii")), launchSha256=p.sha(installed["launchOriginal"].encode("ascii")),
        issuedAtBoottimeNs=window["issuedAtBoottimeNs"], deadlineBoottimeNs=str(min(deadlines)),
        issuedAtUnixNanos=clocks["now_unix_ns"] - 1, expiresAtUnixNanos=clocks["now_unix_ns"] + 10000, targets=rows)
    return dict(source=source, installation_original=installation_original, inventory_raw=inventory_raw,
        value=value, delegation_raw=p.canonical(value), clocks=clocks)


def prepared(source, value=None, *, installation_original=None, inventory_raw=None, **clocks):
    return profile.prepare(source["delegation_raw"] if value is None else p.canonical(value),
        source["installation_original"] if installation_original is None else installation_original,
        source["inventory_raw"] if inventory_raw is None else inventory_raw, **(source["clocks"] | clocks))


class InitialStateProfileControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory(prefix="initial-state-profile-")
        cls.addClassCleanup(directory.cleanup)
        cls.addClassCleanup(runtime_fixture.thaw, Path(directory.name))
        cls.source = fixture(Path(directory.name))

    def test_eight_authorized_rows_use_existing_state_update_and_worker_policy(self):
        source = self.source; result = prepared(source)
        self.assertEqual(set(result), {"stateOriginal", "updateOriginal", "workerPolicyOriginal", "deadline", "epochLimit"})
        state = worker.state(result["stateOriginal"])
        self.assertEqual(state["generation"], 1)
        self.assertEqual(set(state["targets"]), set(worker.JOB_NAMES))
        self.assertEqual(worker.update(result["updateOriginal"], None), result["stateOriginal"])
        policy = worker.prepare(result["workerPolicyOriginal"], inventory_sha256=p.sha(source["inventory_raw"]), **source["clocks"])
        self.assertEqual(policy["value"]["initialStateSha256"], p.sha(result["stateOriginal"]))
        for name, row in state["targets"].items():
            self.assertEqual({field: row[field] for field in profile.TARGET_FIELDS}, source["value"]["targets"][name])
            self.assertTrue(all(p.digest(row[field]) for field in profile.DERIVED_PINS))
        self.assertLess(len({row["endpointRole"] for row in state["targets"].values()}), 8)

    def test_permission_is_explicit_closed_initial_active_and_exact_eight(self):
        for change in ("purpose", "status", "missing", "extra", "checkpoint", "counter-bool", "directory"):
            value = copy.deepcopy(self.source["value"]); first = value["targets"][worker.JOB_NAMES[0]]
            if change == "purpose": value["purpose"] = "derive-currentness-from-signatures"
            elif change == "status": first["status"] = "revoked"
            elif change == "missing": del value["targets"][worker.JOB_NAMES[-1]]
            elif change == "extra": value["generation"] = 1
            elif change == "checkpoint": first["checkpointSequence"] = 2
            elif change == "counter-bool": first["endpointGeneration"] = True
            else: value["decisionDirectory"] = value["stateDirectory"]
            with self.subTest(change=change), self.assertRaises(ERRORS): prepared(self.source, value)

    def test_independent_scope_and_inventory_pins_cannot_be_rebound(self):
        for field in ("driverConfigurationSha256", "driverWindowSha256", "launchSha256", "supervisorInventorySha256"):
            value = copy.deepcopy(self.source["value"]); value[field] = p.sha(b"other original")
            with self.subTest(field=field), self.assertRaises(ERRORS): prepared(self.source, value)
        value = copy.deepcopy(self.source["value"]); value["invocationId"] = "f" * 32
        with self.assertRaises(ERRORS): prepared(self.source, value)
        with self.assertRaises(ERRORS): prepared(self.source, inventory_raw=self.source["inventory_raw"] + b" ")

    def test_independent_authorities_counters_and_revocation_facts_must_match(self):
        for field in ("rootAuthority", "checkpointAuthority", "endpointGeneration", "serviceGeneration",
                "operationGeneration", "durableEpoch", "revocationGenerationHighWater", "revocationRootSha256"):
            value = copy.deepcopy(self.source["value"]); row = value["targets"][worker.JOB_NAMES[0]]
            if field.endswith("Authority"): row[field]["keyId"] = p.sha(b"other independent authority")
            elif field.endswith("Sha256"): row[field] = p.sha(b"other independently current root")
            else: row[field] += 1
            with self.subTest(field=field), self.assertRaises(ERRORS): prepared(self.source, value)

    def test_each_primary_and_supplemental_helper_is_really_authenticated(self):
        for role in profile.g.ROLES:
            installed = p.document(self.source["installation_original"], profile.MAX_INPUT)
            installed["historyOriginals"][role] = "{}"
            with self.subTest(role=role), self.assertRaises(ERRORS):
                prepared(self.source, installation_original=p.canonical(installed))
        installed = p.document(self.source["installation_original"], profile.MAX_INPUT)
        helper = p.document(installed["runtimeOriginals"][profile.g.ROLES[-1]].encode("ascii"), profile.g.MAX_BYTES)
        name = next(name for name, raw in helper["initialEndpointHistories"].items()
            if raw != installed["historyOriginals"][profile.g.ROLES[-1]])
        helper["initialEndpointHistories"][name] = "{}"
        installed["runtimeOriginals"][profile.g.ROLES[-1]] = p.canonical(helper).decode("ascii")
        with self.assertRaises(ERRORS): prepared(self.source, installation_original=p.canonical(installed))

    def test_original_clocks_are_copied_and_never_extended_past_checkpoints(self):
        source = self.source; result = prepared(source)
        for raw, maximum in ((result["stateOriginal"], worker.MAX_STATE), (result["workerPolicyOriginal"], worker.MAX_POLICY)):
            value = p.document(raw, maximum)
            self.assertEqual({field: value[field] for field in worker.CLOCKS}, {field: source["value"][field] for field in worker.CLOCKS})
        base = installation.prepare_input(source["installation_original"], **source["clocks"])
        self.assertEqual(result["deadline"], min(base["deadline"], p.ns(source["value"]["deadlineBoottimeNs"])))
        value = copy.deepcopy(source["value"]); value["deadlineBoottimeNs"] = str(p.ns(value["deadlineBoottimeNs"]) + 1)
        with self.assertRaises(ERRORS): prepared(source, value)
        for clock in ({"now_boottime_ns": result["deadline"]}, {"now_unix_ns": result["epochLimit"]},
                {"boot": (source["clocks"]["boot"][0], 1, 999)}):
            with self.subTest(clock=clock), self.assertRaises(ERRORS): prepared(source, **clock)

    def test_projection_accepts_only_base_input_and_fixed_total_budget(self):
        source = self.source; value = p.document(source["installation_original"], profile.MAX_INPUT)
        value["apiVersion"] = "catchplate.nativePilotAdoptedOrdinaryInstallationInput/v2"
        with self.assertRaises(ERRORS): prepared(source, installation_original=p.canonical(value))
        with self.assertRaises(ERRORS): profile.prepare(b"x" * profile.MAX_INPUT, source["installation_original"],
            source["inventory_raw"], **source["clocks"])
        self.assertEqual(profile.MAX_INPUT, 32 * 1024 * 1024)
        self.assertEqual((profile.POLICY_NAME, profile.INVENTORY_NAME), ("worker-policy.json", "worker-supervisor-inventory.json"))


if __name__ == "__main__": unittest.main()
