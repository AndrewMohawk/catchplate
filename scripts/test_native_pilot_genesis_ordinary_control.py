"""Pure protocol controls only; no fabricated successful process owner."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_ordinary_control as control
from serverware import native_pilot_genesis_ordinary_control_process as process
from serverware import native_pilot_genesis_ordinary_resources as resources

p = g.p


def fixture():
    window = {"bootIdBase64url": p.encoded(bytes(range(16))), "timeNamespaceDevice": (1 << 63) + 7,
        "timeNamespaceInode": (1 << 63) + 9, "issuedAtBoottimeNs": "1000",
        "startupDeadlineBoottimeNs": "2000", "lifetimeDeadlineBoottimeNs": "3000", "invocationId": "a" * 32}
    launch = {"apiVersion": control.LAUNCH_API,
        **{name: window[name] for name in control.LAUNCH_FIELDS[1:-1]}, "services": {
            role: {"executableSha256": p.sha(role.encode()), "deliveryConfiguration": {
                "path": "/etc/serverware/" + role + ".json", "sha256": p.sha((role + "-cold").encode())}}
            for role in resources.ROLES}}
    return window, launch


class Controls(unittest.TestCase):
    def test_fixed_two_role_inventory_has_no_hot_generation_resources(self):
        self.assertEqual(resources.ROLES, ("durable-recovery-store", "current-signature-authority"))
        self.assertEqual(resources.DIRECTORIES[resources.ROLES[0]], ("journal", "publication-genesis-journal"))
        self.assertEqual(resources.DIRECTORIES[resources.ROLES[1]], ("publication-genesis-journal",))
        for role in resources.ROLES:
            self.assertEqual(resources.ACTIVATION[role], ("listener", *resources.DIRECTORIES[role], "publication-genesis-grant"))

    def test_closed_original_launch_preserves_native_u64(self):
        window, launch = fixture()
        self.assertEqual(control._launch(g.canonical(launch), window), launch)

    def test_legacy_extra_service_and_changed_window_refuse(self):
        window, launch = fixture()
        changes = []
        old = copy.deepcopy(launch); old["apiVersion"] = "serverware.custodyFiveServiceLaunch/v6"; changes.append(old)
        extra = copy.deepcopy(launch); extra["services"][g.ROLES[1]] = extra["services"][resources.ROLES[0]]; changes.append(extra)
        late = copy.deepcopy(launch); late["startupDeadlineBoottimeNs"] = "2001"; changes.append(late)
        for changed in changes:
            with self.assertRaises((ValueError, TypeError)):
                control._launch(g.canonical(changed), window)

    def test_bool_is_not_original_namespace_integer(self):
        window, launch = fixture()
        window["timeNamespaceDevice"] = 1
        launch["timeNamespaceDevice"] = True
        with self.assertRaises((ValueError, TypeError)):
            control._launch(g.canonical(launch), window)

    def test_independent_control_is_closed_and_pinned(self):
        value = {"apiVersion": control.CONTROL_API, "launchConfigurationSha256": p.sha(b"launch"),
            "parentConfigurationSha256": p.sha(b"parent"), "parentPrecreationSha256": p.sha(b"precreation")}
        self.assertEqual(control._control(g.canonical(value)), value)
        value["unapproved"] = True
        with self.assertRaises((ValueError, TypeError)):
            control._control(g.canonical(value))

    def test_native_launch_selects_only_explicit_inspected_v7(self):
        pin = {"path": "/etc/serverware/public.json", "sha256": p.sha(b"public")}
        value = {"apiVersion": "serverware.custodyOrdinaryServiceGuestLaunch/v7",
            "deliveryConfiguration": pin, "delivery": pin, "peerInspectionCredential": "peer-inspection-policy"}
        self.assertEqual(control._native_launch(g.canonical(value), resources.ROLES[0]), value)
        for field, replacement in (("apiVersion", "serverware.custodyOrdinaryServiceGuestLaunch/v6"),
                ("peerInspectionCredential", "generation-grant")):
            changed = copy.deepcopy(value); changed[field] = replacement
            with self.assertRaises((ValueError, TypeError)):
                control._native_launch(g.canonical(changed), resources.ROLES[0])

    def test_kernel_ucred_abi_preserves_unsigned_ids_and_distinct_wire(self):
        self.assertEqual(process.UCRED.size, 12)
        self.assertEqual(process.UCRED.unpack(process.UCRED.pack(123, (1 << 32) - 2, (1 << 31) + 5)),
            (123, (1 << 32) - 2, (1 << 31) + 5))
        self.assertNotEqual(process.PARKED, process.RELEASE)
        self.assertNotIn(b"FiveService", process.RELEASE)


if __name__ == "__main__":
    unittest.main()
