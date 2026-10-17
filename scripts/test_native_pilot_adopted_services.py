#!/usr/bin/env python3
"""Pure adopted-history and profile controls, never operational admission.

All keys, process/resource metadata and times are synthetic. The initial v3
transcript is independently re-signed over its exact state; changing a version
tag alone never authorizes it. These controls do not fabricate a ReceivedCore,
run a native validator, sign an operational grant, install files or claim a
complete eleven-endpoint commissioning ceremony.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_adopted_launch_profile as bundle
from catchplate import native_pilot_adopted_ordinary as ordinary
from catchplate import native_pilot_adopted_service_authority as service
from catchplate import native_pilot_launch_publication as launch
from catchplate import native_pilot_native_service_authority as legacy
from catchplate import native_pilot_ordinary_initial_profile as initial
from test_native_pilot_adopted_closure import fixture as closure_fixture, input_for, signed
from test_native_pilot_ordinary_initial import fixture, checkpoint, sign_anchor, DOMAINS
from test_native_pilot_ordinary_keys import canonical, encoded, framed, labelled

p = service.p
FAILURES = (ValueError, TypeError, KeyError, InvalidSignature)


def target_fixture():
    """Re-sign an independent v3 state, with its real-format new directory."""
    f = fixture(); wrapper = copy.deepcopy(f["wrapper"])
    state = wrapper["initialState"]
    state["apiVersion"] = ordinary.STATE_API
    row = copy.deepcopy(state["directories"]["journal"])
    row["identity"]["inode"] += 1000
    state["directories"]["publication-journal"] = row
    roots = {name: framed(domain, (canonical(state),)) for name, domain in DOMAINS.items()}
    payload = copy.deepcopy(wrapper["initialCheckpoint"]["payload"])
    payload["predecessorCheckpointSha256"] = roots["predecessorCheckpointSha256"]
    wrapper["initialCheckpoint"] = checkpoint(payload, f["public"]["checkpoint"], f["keys"]["checkpoint"])
    anchor = wrapper["history"]["firstRetainedEpoch"]
    anchor["prunedHistoryRootSha256"] = roots["prunedHistoryRootSha256"]
    anchor["retainedEpoch"].update(checkpointSha256=wrapper["initialCheckpoint"]["checkpointSha256"],
        durableEpochHeadSha256=roots["durableEpochHeadSha256"])
    sign_anchor(wrapper["history"], f["keys"])
    wrapper["apiVersion"] = ordinary.WRAPPER_API
    header = {"apiVersion": ordinary.RUNTIME_API,
        "authorityHistoryRootKeyId": f["root_pin"]["keyId"],
        "authorityHistoryRootKeySpkiSha256": f["root_pin"]["keySpkiSha256"],
        "authorityHistoryManifestSha256": wrapper["history"]["manifestSha256"],
        "operationGeneration": state["operationGeneration"], "serviceRestartEpoch": state["serviceGeneration"],
        "deploymentGenerationSha256": state["deploymentGenerationSha256"],
        "activationDirectoryIdentities": {name: item["identity"] for name, item in state["directories"].items()},
        "publicationAdmission": {"grantFdName": "publication-grant"},
        "generationAdmission": {"grantFdName": "generation-grant"},
        "dispatchAdmission": {"grantFdName": "dispatch-grant"}, "spoolHead": {"grantFdName": "spool-head-grant"}}
    boot = tuple(state[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"))
    return {**f, "wrapper": wrapper, "header": header, "boot": boot, "issued": 1200, "expires": 7000}


class AdoptedTargetHistoryControls(unittest.TestCase):
    def validate(self, f, **changes):
        return ordinary.history(canonical(f["wrapper"]), role=g.ROLES[0],
            **{**{name: f[name] for name in ("header", "boot", "issued", "expires")}, **changes})

    def test_exact_v3_checkpoint_and_three_anchor_signatures(self):
        f = target_fixture(); checked = self.validate(f)
        self.assertEqual(checked["state"], f["wrapper"]["initialState"])
        self.assertEqual(checked["deadline"], 8000)
        self.assertNotEqual(checked["epoch"]["durableEpochHeadSha256"], f["roots"]["durableEpochHeadSha256"])
        with self.assertRaises(FAILURES):
            initial.manifest(canonical(f["wrapper"]), role=g.ROLES[0], root_pin=f["root_pin"])

    def test_cross_version_and_tag_only_upgrade_refused(self):
        f = target_fixture()
        for field, version in (("wrapper", initial.WRAPPER_API), ("state", initial.STATE_API), ("runtime", "catchplate.policyCustodyServiceRuntimeConfig/v10")):
            changed = copy.deepcopy(f)
            target = changed["wrapper"] if field == "wrapper" else changed["wrapper"]["initialState"] if field == "state" else changed["header"]
            target["apiVersion"] = version
            with self.subTest(field=field), self.assertRaises(FAILURES): self.validate(changed)
        old = fixture(); old["wrapper"]["apiVersion"] = ordinary.WRAPPER_API
        old["wrapper"]["initialState"]["apiVersion"] = ordinary.STATE_API
        changed = copy.deepcopy(f); changed["wrapper"] = old["wrapper"]
        with self.assertRaises(FAILURES): self.validate(changed)

    def test_state_changes_require_new_checkpoint_and_anchor(self):
        for field in ("inode", "entryCount", "missing"):
            f = target_fixture(); row = f["wrapper"]["initialState"]["directories"]["publication-journal"]
            if field == "inode": row["identity"]["inode"] += 1
            elif field == "entryCount": row["entryCount"] = 1
            else: del f["wrapper"]["initialState"]["directories"]["publication-journal"]
            with self.subTest(field=field), self.assertRaises(FAILURES): self.validate(f)

    def test_each_actual_signature_is_required(self):
        for field in ("authoritySignatureBase64", "rootSignatureBase64", "checkpointAuthoritySignatureBase64", "serviceKeySignatureBase64"):
            f = target_fixture()
            target = f["wrapper"]["initialCheckpoint"] if field == "authoritySignatureBase64" else f["wrapper"]["history"]["firstRetainedEpoch"]
            target[field] = encoded(bytes(64))
            with self.subTest(field=field), self.assertRaises(FAILURES): self.validate(f)

    def test_original_checkpoint_interval_and_boot_are_not_renewed(self):
        f = target_fixture()
        for changes in ({"issued": 1149}, {"expires": 8001}, {"issued": 7000, "expires": 7000},
                {"boot": (f["boot"][0], f["boot"][1], f["boot"][2] + 1)}):
            with self.subTest(changes=changes), self.assertRaises(FAILURES): self.validate(f, **changes)

    def test_runtime_root_directory_generation_and_permissions_are_exact(self):
        for mutation in ("root", "directory", "generation", "publication", "spool"):
            f = target_fixture(); header = f["header"]
            if mutation == "root": header["authorityHistoryRootKeyId"] = labelled("other-root")
            elif mutation == "directory": header["activationDirectoryIdentities"] = {}
            elif mutation == "generation": header["operationGeneration"] += 1
            elif mutation == "publication": header["publicationAdmission"] = {"grantFdName": "generation-grant"}
            else: header["spoolCurrent"] = {"grantFdName": "spool-current-grant"}
            with self.subTest(mutation=mutation), self.assertRaises(FAILURES): self.validate(f)

    def test_native_epoch_reference_uses_flat_authenticated_key_fields(self):
        f = target_fixture(); epoch = self.validate(f)["epoch"]
        reference = ordinary.epoch_reference(epoch)
        self.assertEqual(reference["authorityEpochSha256"], epoch["epochSha256"])
        self.assertEqual(reference["checkpointAuthorityKeyId"], epoch["checkpointAuthority"]["keyId"])
        self.assertEqual(reference["serviceSigningKeySpkiSha256"], epoch["serviceSigningKey"]["keySpkiSha256"])
        self.assertEqual(len(reference), 17)
        self.assertNotIn("checkpointAuthority", reference)


class AdoptedProfileIsolationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.f = closure_fixture()

    def test_genuine_synthetic_closure_v5_has_separate_shape_entrypoint(self):
        raw, _ = signed(input_for(self.f))
        selected = launch.shape_adopted("native-publicationReconciliation-closure", raw)
        self.assertEqual(selected["apiVersion"], "catchplate.nativeCustodyClosure/v5")
        for purpose in ("native-publicationReconciliation-closure", "native-retrieval-closure"):
            with self.subTest(purpose=purpose), self.assertRaises(FAILURES): launch.shape(purpose, raw)
        with self.assertRaises(FAILURES): launch.shape_adopted("native-persistence-closure", raw)

    def test_three_unsigned_launch_selectors_require_exact_fixed_paths(self):
        for role in bundle.ROLES:
            inner = {"apiVersion": "catchplate.nativeShadowGuestLaunch/v1"}
            for name, suffix in (("deliveryConfiguration", "cold"), ("delivery", "delivery")):
                inner[name] = {"path": launch.ADOPTED_DESTINATIONS["native-" + suffix + "-" + role], "sha256": labelled(name)}
            for name, (suffix, _) in launch.COMPONENTS.items():
                inner[name] = {"path": launch.ADOPTED_DESTINATIONS["native-" + role + "-" + suffix], "sha256": labelled(name)}
            api, field, operation = launch.ADOPTED_LAUNCHES[role]
            value = {"apiVersion": "catchplate." + api, "keyAdmission": inner,
                field: {"path": launch.ADOPTED_DESTINATIONS["native-service-" + operation], "sha256": labelled("grant")}}
            self.assertEqual(launch.shape_adopted("native-launch-" + role, canonical(value)), value)
            with self.assertRaises(FAILURES): launch.shape("native-launch-" + role, canonical(value))
            changed = copy.deepcopy(value); changed[field]["path"] = inner["delivery"]["path"]
            with self.assertRaises(FAILURES): launch.shape_adopted("native-launch-" + role, canonical(changed))

    def test_c9_unsigned_u64_reader_does_not_widen_native_signed_payload(self):
        value = {"timeNamespaceInode": (1 << 64) - 1}
        raw = g.canonical(value)
        self.assertEqual(service.original(raw.decode("ascii"), 4096)[1], value)
        with self.assertRaises(FAILURES): p.canonical(value)
        with self.assertRaises(FAILURES): p.preimage(service.PROFILES["persistence"][2], value)

    def test_service_input_version_and_operation_cannot_select_fallback(self):
        for operation in service.PROFILES:
            value = {name: None for name in service.COMMON + service.EXTRA[operation]}
            value.update(apiVersion=service.INPUT_API, operation=operation)
            self.assertEqual(service.input_document(operation, canonical(value)), value)
            for changed in ({**value, "apiVersion": "catchplate.nativePilotNativeServiceAuthorityInput/v5"},
                    {**value, "operation": "trustedTime"}, {**value, "extra": True}):
                with self.subTest(operation=operation), self.assertRaises(FAILURES): service.input_document(operation, canonical(changed))
            # Framing success is not public authority admission. No key or
            # successful semantic-validation substitute is supplied here.
            with self.assertRaises(FAILURES):
                legacy.prepare_input(operation, canonical(value), boot=("", 1, 1), now_boottime_ns=1, now_unix_ns=1)

    def test_signed_authorization_cannot_be_omitted_or_replaced_by_result(self):
        api, purpose, _, _ = service.PROFILES["persistence"]
        value = {name: None for name in service.PAYLOAD["persistence"]}
        value.update(apiVersion=api, purpose=purpose, permissions=list(service.PERMISSIONS))
        for candidate in (None, {"validated": True}, {"payload": {}, "signature": encoded(bytes(64))}):
            with self.subTest(candidate=candidate), self.assertRaises(FAILURES):
                service.grant_shape("persistence", {**value, "adoption": candidate})

    def test_launch_composition_is_three_roles_not_implicit_hot_fallback(self):
        self.assertEqual(bundle.ROLES, ("retrieval", "persistence", "publicationReconciliation"))
        value = {name: None for name in bundle.FIELDS}
        value.update(apiVersion=bundle.API, role="trustedTime")
        with self.assertRaises(FAILURES): bundle.input_document("trustedTime", canonical(value))
        value.update(role="persistence", apiVersion="catchplate.nativePilotLaunchBundle/v1")
        with self.assertRaises(FAILURES): bundle.input_document("persistence", canonical(value))


if __name__ == "__main__": unittest.main()
