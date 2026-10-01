#!/usr/bin/env python3
"""Pure synthetic State3/runtime12/C9/generation controls; never live evidence.

All process, directory, time and key material is test-only. Re-signing the full
checkpoint and three-authority anchor is intentional: version relabelling is
not a migration. No owner, private installed credential or service is created.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from serverware import custody_generation_grants as g
from serverware import native_pilot_ordinary_delivery_profile as delivery
from serverware import native_pilot_ordinary_generation_profile as generation
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_install as installation
from serverware import native_pilot_ordinary_publication_authority as publication
from serverware import native_pilot_ordinary_runtime_profile as runtime
from serverware import native_pilot_ordinary_transition_profile as transition
from serverware import native_pilot_service_authority as service
from test_native_pilot_ordinary_commissioning import fixture as old_fixture, private, peer
from test_native_pilot_ordinary_generations import scope_fixture, result as generation_result, root_pin
from test_native_pilot_ordinary_initial import checkpoint, sign_anchor, DOMAINS
from test_native_pilot_ordinary_keys import canonical, encoded, framed, labelled, sha

ROLES = g.ROLES
FAILURES = (ValueError, KeyError, TypeError, InvalidSignature)


def fixture():
    f = old_fixture()
    f["launch"]["apiVersion"] = "serverware.custodyFiveServiceLaunch/v7"
    f["preparation"]["configurationSha256"] = sha(canonical(f["launch"]))
    f["resources"].update(apiVersion="serverware.custodyFiveServiceInitialResources/v2",
        preparationSha256=sha(canonical(f["preparation"])))
    for index in (0, 3):
        role = ROLES[index]
        row = copy.deepcopy(next(iter(f["resources"]["services"][role]["directories"].values())))
        row["identity"]["inode"] = 92000 + index
        f["resources"]["services"][role]["directories"]["publication-journal"] = row
    for role in ROLES:
        wrapper = json.loads(f["histories"][role])
        state = wrapper["initialState"]
        selected = role in initial.ADOPTED_ROLES
        state.update(apiVersion=initial.ADOPTED_STATE_API if selected else initial.STATE_API,
            preparationSha256=sha(canonical(f["preparation"])), resourcesSha256=sha(canonical(f["resources"])),
            launchSha256=sha(canonical(f["launch"])), directories=copy.deepcopy(f["resources"]["services"][role]["directories"]))
        roots = {name: framed(domain, (canonical(state),)) for name, domain in DOMAINS.items()}
        payload = wrapper["initialCheckpoint"]["payload"]
        payload["predecessorCheckpointSha256"] = roots["predecessorCheckpointSha256"]
        authorities = f["initial_policy"]["services"][role]["authorities"]
        wrapper["initialCheckpoint"] = checkpoint(payload, authorities["checkpoint"], private(role + "/checkpoint"))
        anchor = wrapper["history"]["firstRetainedEpoch"]
        anchor["prunedHistoryRootSha256"] = roots["prunedHistoryRootSha256"]
        anchor["retainedEpoch"].update(checkpointSha256=wrapper["initialCheckpoint"]["checkpointSha256"],
            durableEpochHeadSha256=roots["durableEpochHeadSha256"])
        sign_anchor(wrapper["history"], {name: private(role + "/" + name) for name in ("root", "checkpoint", "service")})
        wrapper["apiVersion"] = initial.ADOPTED_WRAPPER_API if selected else initial.WRAPPER_API
        f["histories"][role] = canonical(wrapper)
    f["runtimes"] = {role: runtime.build(role, fragment=f["fragment"], history_originals=f["histories"],
        preparation_raw=canonical(f["preparation"]), resources_raw=canonical(f["resources"]),
        launch_raw=canonical(f["launch"]), configuration_raw=canonical(f["cold"][role]), peer=peer(), adopted=True) for role in ROLES}
    f["plan"] = installation.plan(runtime_originals=f["runtimes"], history_originals=f["histories"],
        cold_originals={role: canonical(f["cold"][role]) for role in ROLES}, launch_original=canonical(f["launch"]), adopted=True)
    f["boot"] = tuple(f["launch"][name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"))
    f["deliveries"], f["delivery_inputs"] = {}, {}
    for index, role in enumerate(ROLES):
        cold = f["cold"][role]
        names = g.BUSINESS[role] + ("generation-journal", "generation-grant")
        if index in (0, 3): names += ("dispatch-journal", "dispatch-grant")
        prefix = {0: "spool-head", 1: "active-effect-cleanup", 3: "spool-current"}.get(index)
        if prefix: names += (prefix + "-journal", prefix + "-grant")
        if index in (0, 3): names += ("publication-journal", "publication-grant")
        activation = [{"name": name, "fd": number + 6, "device": 8, "inode": 910000 + index * 100 + number,
            "mode": (stat.S_IFSOCK | 0o777) if name == "listener" else (stat.S_IFREG | 0o600)
                if name.endswith("-grant") else stat.S_IFDIR | 0o700,
            "uid": 0 if name == "listener" else cold["uid"], "gid": 0 if name == "listener" else cold["gid"]}
            for number, name in enumerate(names)]
        credentials = copy.deepcopy(f["fragment"]["services"][role]["credentials"])
        for kind, name in (("history", "authority-history"), ("inspection", "peer-inspection-policy")):
            item = next(item for item in f["plan"] if item["role"] == role and item["kind"] == kind)
            credentials.append({"name": name, "original": {"path": item["path"], "sha256": sha(item["raw"])},
                "length": len(item["raw"]), "signing": None})
        payload = {"configurationSha256": sha(canonical(cold)), "authorityKeyId": cold["authority"]["keyId"],
            **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
            **{name: f["launch"][name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
                "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")}, "issuedAtBoottimeNs": "1200",
            "runtimeConfig": {"path": installation.RUNTIME_PATHS[role], "sha256": sha(f["runtimes"][role])},
            "credentials": credentials, "activation": activation}
        f["delivery_inputs"][role] = delivery.build(role, launch_raw=canonical(f["launch"]),
            configuration_raw=canonical(cold), runtime_raw=f["runtimes"][role], payload_raw=canonical(payload), activation=activation, adopted=True)
        signature = f["delivery_keys"][role].sign(g.c9.DOMAIN + canonical(payload))
        f["deliveries"][role] = canonical({"apiVersion": "serverware.policyCustodyGuestDelivery/v1", "payload": payload,
            "signatureBase64url": encoded(signature)})
    return f


def generation_input(f, role):
    return generation.build(role, launch_raw=canonical(f["launch"]), configuration_raw=canonical(f["cold"][role]),
        delivery_raw=f["deliveries"][role], runtime_raw=f["runtimes"][role], history_raw=f["histories"][role],
        scope=scope_fixture(), issued_boottime_ns=1300, expires_boottime_ns=8500, adopted=True)


class AdoptedOrdinaryControls(unittest.TestCase):
    def test_exact_seventeen_directories_and_independent_anchor_chain(self):
        f = fixture()
        resources = initial.resources(canonical(f["resources"]), adopted=True)
        self.assertEqual(sum(len(row["directories"]) for row in resources["services"].values()), 17)
        for role in ROLES:
            wrapper = json.loads(f["histories"][role])
            self.assertEqual(initial.manifest(f["histories"][role], role=role, root_pin=root_pin(f, role), adopted=True), wrapper["history"])
            self.assertEqual(wrapper["apiVersion"], initial.ADOPTED_WRAPPER_API if role in initial.ADOPTED_ROLES else initial.WRAPPER_API)
        with self.assertRaises(FAILURES): initial.resources(canonical(f["resources"]))

    def test_version_relabelling_is_not_an_authority_transition(self):
        f = fixture(); role = ROLES[0]
        old = json.loads(old_fixture()["histories"][role])
        old["apiVersion"] = initial.ADOPTED_WRAPPER_API; old["initialState"]["apiVersion"] = initial.ADOPTED_STATE_API
        with self.assertRaises(FAILURES): initial.manifest(canonical(old), role=role, root_pin=root_pin(f, role), adopted=True)
        with self.assertRaises(FAILURES): initial.manifest(f["histories"][role], role=role, root_pin=root_pin(f, role))

    def test_resources_refuse_nonempty_duplicate_and_other_role_publication(self):
        for mutation in ("entries", "duplicate", "wrong-role"):
            f = fixture(); rows = f["resources"]["services"]
            if mutation == "entries": rows[ROLES[0]]["directories"]["publication-journal"]["entryCount"] = 1
            elif mutation == "duplicate": rows[ROLES[3]]["directories"]["publication-journal"] = copy.deepcopy(rows[ROLES[0]]["directories"]["publication-journal"])
            else: rows[ROLES[1]]["directories"]["publication-journal"] = copy.deepcopy(rows[ROLES[0]]["directories"]["publication-journal"])
            with self.subTest(mutation=mutation), self.assertRaises(FAILURES): initial.resources(canonical(f["resources"]), adopted=True)

    def test_prepared_state_binds_literal_launch_resources_and_same_process(self):
        f = fixture(); role = ROLES[0]; state = json.loads(f["histories"][role])["initialState"]
        kwargs = dict(preparation_raw=canonical(f["preparation"]), resources_raw=canonical(f["resources"]),
            launch_raw=canonical(f["launch"]), configuration=f["cold"][role], window=f["window"],
            endpoint_role="settlement-store", now=1300, adopted=True)
        identity = initial.prepared_state(state, **kwargs)
        self.assertEqual(identity["endpointPid"], f["preparation"]["services"][role]["processId"])
        with self.assertRaises(FAILURES): initial.prepared_state(state | {"resourcesSha256": labelled("different")}, **kwargs)

    def test_runtime12_and_public_plan_remain_explicit(self):
        f = fixture()
        self.assertEqual(len(f["plan"]), 15)
        for role in ROLES:
            header = runtime.validate_runtime(role, f["runtimes"][role], adopted=True)["runtime"]
            if role in initial.ADOPTED_ROLES:
                self.assertEqual(header["apiVersion"], "serverware.policyCustodyServiceRuntimeConfig/v12")
                self.assertEqual(header["publicationAdmission"], {"grantFdName": "publication-grant"})
                with self.assertRaises(FAILURES): runtime.validate_runtime(role, f["runtimes"][role])
            else:
                self.assertNotIn("publicationAdmission", header)

    def test_c9_actual_selected_inventory_precedes_key_selection(self):
        f = fixture()
        for role in ROLES:
            context = service.prepare_input("delivery", role, f["delivery_inputs"][role],
                boot=f["boot"], now_boottime_ns=1300, now_unix_ns=1500, adopted=True)
            self.assertEqual(context["message"], g.c9.DOMAIN + canonical(context["payload"]))
            if role in initial.ADOPTED_ROLES:
                self.assertEqual([row["name"] for row in context["payload"]["activation"]][-2:], ["publication-journal", "publication-grant"])
            with self.assertRaises(FAILURES): service.prepare_input("delivery", role, f["delivery_inputs"][role],
                boot=f["boot"], now_boottime_ns=1300, now_unix_ns=1500)

    def test_generation_root_signature_and_original_limits(self):
        f = fixture()
        for role in ROLES:
            raw = generation_input(f, role)
            prepared = service.prepare_input("generation", role, raw, boot=f["boot"], now_boottime_ns=1400, now_unix_ns=1500, adopted=True)
            self.assertEqual(prepared["epochLimit"], 2000)
            result = generation_result(role, prepared["payload"])
            self.assertEqual(generation.checked_result(role, raw, result, root_pin=root_pin(f, role), adopted=True).decode("ascii"), result["original"])
            with self.assertRaises(FAILURES): service.prepare_input("generation", role, raw, boot=f["boot"],
                now_boottime_ns=1400, now_unix_ns=2000, adopted=True)

    def test_epoch_projection_requires_selected_wrapper(self):
        f = fixture(); role = ROLES[0]
        payload = json.loads(f["deliveries"][role])["payload"]
        guest = g._delivery_guest(f["deliveries"][role], payload)
        header = json.loads(f["runtimes"][role])["runtime"]
        epoch, _ = transition.epoch_reference(f["histories"][role], runtime=header, guest=guest, adopted=True)
        self.assertEqual(epoch["authorityRole"]["role"], role)
        with self.assertRaises(FAILURES): transition.epoch_reference(f["histories"][role], runtime=header, guest=guest)

    def test_publication_signature_domain_is_exact_and_not_legacy(self):
        payload = {"apiVersion": publication.GRANT_API, "testOnly": "synthetic framing control"}
        raw = canonical(payload); domain = b"serverware.nativePublicationServiceGrant.signature/v2"
        expected = b"serverware-signature-v1\0" + len(domain).to_bytes(8, "big") + domain + len(raw).to_bytes(8, "big") + raw
        self.assertEqual(publication.message(payload), expected)
        with self.assertRaises(FAILURES): publication.message({"u64Only": 1 << 63})


if __name__ == "__main__":
    unittest.main()
