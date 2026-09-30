#!/usr/bin/env python3
"""Pure five-role commissioning controls; all keys and observations synthetic.

No live composer, protected installer, authority signing entrypoint, service,
filesystem credential or network is used. Test signatures exist only in memory.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))
from serverware import custody_generation_grants as generation
from serverware import native_pilot_ordinary_install as installer
from serverware import native_pilot_ordinary_runtime_profile as runtime
from serverware import native_pilot_supervisor_ordinary_deliveries as composer
from serverware import native_pilot_supervisor_policy as policy
from serverware import native_pilot_publication as publication
from test_native_pilot_ordinary_initial import DOMAINS, checkpoint, fixture as initial_fixture, sign_anchor
from test_native_pilot_ordinary_keys import PROCESS_DOMAIN, ROLES, canonical, encoded, framed, labelled, sha
from test_native_pilot_endpoint_commissioning import peer

ENDPOINT_ROLES = ("settlement-store", "fence-authority", "cleanup-watchdog", "signer-hsm", "termination-ledger")


def private(label):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
        ("SYNTHETIC ORDINARY COMMISSIONING TEST / " + label).encode("ascii")).digest())


def public(key, label):
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"keyId": labelled(label), "keySpkiSha256": sha(der), "publicKeySpkiBase64": encoded(der)}


def fixture():
    f = initial_fixture()
    delivery_keys = {role: private("delivery/" + role) for role in ROLES}
    for role in ROLES:
        raw = delivery_keys[role].public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        f["cold"][role]["authority"] = {"publicKeyBase64url": encoded(raw), "keyId": sha(raw)}
        digest = sha(canonical(f["cold"][role]))
        f["launch"]["services"][role]["deliveryConfiguration"]["sha256"] = digest
        f["preparation"]["services"][role]["configurationSha256"] = digest
    f["preparation"]["configurationSha256"] = sha(canonical(f["launch"]))
    f["resources"]["preparationSha256"] = sha(canonical(f["preparation"]))
    histories, approved, keys, publics = {}, {}, {}, {}
    for role, endpoint_role in zip(ROLES, ENDPOINT_ROLES, strict=True):
        keys[role] = {name: private(role + "/" + name) for name in ("root", "checkpoint", "service")}
        pubs = publics[role] = {name: public(key, role + "/" + name) for name, key in keys[role].items()}
        row = f["preparation"]["services"][role]
        executable = row["targetExecutable"]
        values = [endpoint_role, row["plannedUid"], row["plannedGid"], row["processId"], row["startTimeTicks"],
            row["pidfdStat"]["inode"], row["pidfdStat"]["sha256"], executable["device"], executable["inode"],
            executable["length"], executable["sha256"], executable["imaSha256"], executable["fsVeritySha256"]]
        names = ("endpointRole", "endpointUid", "endpointGid", "endpointPid", "endpointStartTimeTicks",
            "endpointPidfdInode", "endpointPidfdStatSha256", "executableDevice", "executableInode",
            "executableLength", "executableSha256", "executableImaSha256", "executableFsVeritySha256")
        identity = {**dict(zip(names, values, strict=True)), "identitySha256": framed(PROCESS_DOMAIN, (canonical(values),))}
        state = {**copy.deepcopy(f["state"]), "serviceRole": role,
            "preparationSha256": sha(canonical(f["preparation"])), "resourcesSha256": sha(canonical(f["resources"])),
            "launchSha256": sha(canonical(f["launch"])), "endpointProcessIdentitySha256": identity["identitySha256"],
            "directories": copy.deepcopy(f["resources"]["services"][role]["directories"])}
        roots = {name: framed(domain, (canonical(state),)) for name, domain in DOMAINS.items()}
        payload = copy.deepcopy(f["wrapper"]["initialCheckpoint"]["payload"])
        payload.update(endpointRole=endpoint_role, endpointProcessIdentitySha256=identity["identitySha256"],
            authorizedSigningKeyId=pubs["service"]["keyId"], authorizedSigningKeySpkiSha256=pubs["service"]["keySpkiSha256"],
            predecessorCheckpointSha256=roots["predecessorCheckpointSha256"])
        payload["validUntilBoottime"]["absoluteBoottimeNanos"] = int(state["lifetimeDeadlineBoottimeNs"])
        signed = checkpoint(payload, pubs["checkpoint"], keys[role]["checkpoint"])
        history = copy.deepcopy(f["wrapper"]["history"])
        history.update(authorityRole={"authorityKind": "isolated-service", "role": role}, rootAuthority=pubs["root"])
        anchor = history["firstRetainedEpoch"]
        anchor.update(rootAuthorityKeyId=pubs["root"]["keyId"], rootAuthorityKeySpkiSha256=pubs["root"]["keySpkiSha256"],
            prunedHistoryRootSha256=roots["prunedHistoryRootSha256"])
        anchor["retainedEpoch"].update(authorityRole=history["authorityRole"], checkpointSha256=signed["checkpointSha256"],
            checkpointAuthority=pubs["checkpoint"], serviceSigningKey=pubs["service"], endpointProcessIdentity=identity,
            endpointProcessIdentitySha256=identity["identitySha256"], durableEpochHeadSha256=roots["durableEpochHeadSha256"])
        sign_anchor(history, keys[role])
        histories[role] = canonical({"apiVersion": "serverware.custodyOrdinaryInitialHistory/v1",
            "initialState": state, "initialCheckpoint": signed, "history": history})
        approved[role] = {"authorities": pubs, "endpointRole": endpoint_role,
            **{name: state[name] for name in ("endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch",
                "deploymentGenerationSha256")}, "revocationGenerationHighWater": payload["revocationGenerationHighWater"],
            "revocationRootSha256": payload["revocationRootSha256"],
            "validity": "observed-initial-resources-through-original-lifetime"}
    initial_policy = {"apiVersion": "serverware.nativePilotSupervisorOrdinaryInitialPolicy/v1", "services": approved}
    rows = {}
    for index, role in enumerate(ROLES):
        credentials = []
        def credential(name, public, signing=False):
            raw = base64.urlsafe_b64decode(public["publicKeySpkiBase64"] + "==")[-32:]
            credentials.append({"name": name, "original": {"path": "/etc/serverware/test-" + role + "-" + name,
                "sha256": labelled("synthetic-private-original/" + role) if signing else sha(raw)}, "length": 32,
                "signing": {"publicKeyBase64url": encoded(raw), "keyId": public["keyId"]} if signing else None})
            return name
        def pin(target, prefix):
            return {"endpointVerifyingKeyCredential": credential(prefix + "-service", publics[target]["service"]),
                "checkpointAuthorityVerifyingKeyCredential": credential(prefix + "-checkpoint", publics[target]["checkpoint"]),
                "consumeCursor": {"sequenceHighWater": 0, "expectedNextSequence": 1,
                    "expectedPredecessorReceiptSha256": labelled("independent-cursor/" + role + "/" + prefix)}}
        signing = credential("signing-seed", publics[role]["service"], True)
        if index in (0, 1, 4):
            service = {"signingKeyCredential": signing,
                "currentHeadAuthorityVerifyingKeyCredential": credential("current-head-key", publics[role]["checkpoint"])}
            if index == 0:
                service.update(ownershipSeed=[], recoveryMaterialSeed=[])
            elif index == 1:
                service.update(minimumCheckpointSequence=1, minimumRevocationGeneration=1,
                    cleanupAuthority={"serviceRole": ROLES[4],
                        "verifyingKeyCredential": credential("cleanup-authority", publics[ROLES[4]]["service"])},
                    genesisPredecessorReceiptSha256=labelled("independent-cleanup-genesis"))
            else:
                service["helperGeneration"] = 1
        elif index == 2:
            lineage = public(private("lineage"), "lineage")
            service = {"signingKeyCredential": signing, "serviceSigningPin": pin(role, "self"),
                "maximumRegistrations": 16, "lineageAuthority": lineage,
                "lineageAuthorityVerifyingKeyCredential": credential("lineage-key", lineage), "durableReapLineageProofs": []}
        else:
            service = {"serviceSigningKeyCredential": signing, "serviceSigningPin": pin(role, "self"),
                "currentSubjects": [{"subject": {"authority": "endpoint", "identity": {"endpoint_role": ENDPOINT_ROLES[0]}},
                    "serviceRole": ROLES[0], "pin": pin(ROLES[0], "subject")} ]}
        rows[role] = {"runtimeHeader": {"startupTimeoutMillis": 1000, "readinessEpoch": 13,
            "maximumDurabilityWorkerNanos": 1000000, "productionDispatchProtocolSetSha256": labelled("protocol-set"),
            "sharedConfigurationSha256": labelled("shared-config"), "authorityHistoryRootKeyId": publics[role]["root"]["keyId"],
            "authorityHistoryRootKeySpkiSha256": publics[role]["root"]["keySpkiSha256"]},
            "service": service, "credentials": credentials}
    f.update(histories=histories, initial_policy=initial_policy, delivery_keys=delivery_keys,
        fragment={"apiVersion": "serverware.nativePilotOrdinaryRuntimePolicy/v1", "services": rows})
    return f


def runtimes(f):
    return {role: runtime.build(role, fragment=f["fragment"], history_originals=f["histories"],
        preparation_raw=canonical(f["preparation"]), resources_raw=canonical(f["resources"]),
        launch_raw=canonical(f["launch"]), configuration_raw=canonical(f["cold"][role]), peer=peer()) for role in ROLES}


def plan(f, built):
    return installer.plan(runtime_originals=built, history_originals=f["histories"],
        cold_originals={role: canonical(f["cold"][role]) for role in ROLES}, launch_original=canonical(f["launch"]))


class OrdinaryCommissioningControls(unittest.TestCase):
    def test_five_actual_wrapper_runtimes_and_explicit_static_policy(self):
        f = fixture()
        selected = runtime.validate_policy(f["fragment"],
            ordinary_cold_originals={role: canonical(f["cold"][role]).decode("ascii") for role in ROLES},
            initial_policy=f["initial_policy"])
        self.assertEqual(selected, f["fragment"])
        selected["services"][ROLES[0]]["runtimeHeader"]["readinessEpoch"] += 1
        self.assertNotEqual(selected, f["fragment"])
        for role, raw in runtimes(f).items():
            value, wrapper = json.loads(raw), json.loads(f["histories"][role])
            self.assertEqual(value["runtime"]["authorityHistoryManifestSha256"], wrapper["history"]["manifestSha256"])
            self.assertEqual(value["runtime"]["operationGeneration"], wrapper["initialState"]["operationGeneration"])
            self.assertEqual(value["runtime"]["expectedPeer"], peer())
            self.assertEqual(value["runtime"]["activationDirectoryIdentities"],
                {name: item["identity"] for name, item in wrapper["initialState"]["directories"].items()})

    def test_closed_policy_rejects_history_and_key_shortcuts(self):
        f = fixture()
        for mutation in ("future", "seed", "root", "credential", "reserved-path", "subject", "predecessor"):
            value = copy.deepcopy(f["fragment"])
            if mutation == "future":
                value["services"][ROLES[0]]["runtimeHeader"]["endpointPid"] = 42
            elif mutation == "seed":
                value["services"][ROLES[0]]["service"]["ownershipSeed"] = [{"invented": True}]
            elif mutation == "root":
                value["services"][ROLES[0]]["runtimeHeader"]["authorityHistoryRootKeyId"] = labelled("wrong-root")
            elif mutation == "credential":
                value["services"][ROLES[0]]["credentials"][1]["original"]["sha256"] = labelled("wrong-key")
            elif mutation == "reserved-path":
                value["services"][ROLES[0]]["credentials"][0]["original"]["path"] = installer.RUNTIME_PATHS[ROLES[1]]
            elif mutation == "subject":
                value["services"][ROLES[3]]["service"]["currentSubjects"][0]["subject"]["identity"]["endpoint_role"] = "signer-hsm"
            else:
                value["services"][ROLES[2]]["service"]["serviceSigningPin"]["consumeCursor"]["expectedNextSequence"] = 2
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                runtime.validate_policy(value, ordinary_cold_originals={role: canonical(f["cold"][role]).decode("ascii")
                    for role in ROLES}, initial_policy=f["initial_policy"])

    def test_runtime_requires_signed_original_observation_bindings(self):
        for mutation in ("resources", "signature", "peer"):
            f = fixture()
            supplied_peer = peer()
            if mutation == "resources":
                f["resources"]["issuedAtBoottimeNs"] = "1151"
            elif mutation == "signature":
                wrapper = json.loads(f["histories"][ROLES[0]])
                wrapper["history"]["firstRetainedEpoch"]["rootSignatureBase64"] = encoded(b"X" * 64)
                f["histories"][ROLES[0]] = canonical(wrapper)
            else:
                supplied_peer["pid"] += 1
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, InvalidSignature)):
                runtime.build(ROLES[0], fragment=f["fragment"], history_originals=f["histories"],
                    preparation_raw=canonical(f["preparation"]), resources_raw=canonical(f["resources"]),
                    launch_raw=canonical(f["launch"]), configuration_raw=canonical(f["cold"][ROLES[0]]), peer=supplied_peer)

    def test_fifteen_public_file_records_preserve_roles_modes_and_hashes(self):
        f = fixture(); built = runtimes(f); records = plan(f, built)
        self.assertEqual(len(records), 15)
        self.assertEqual(len({item["path"] for item in records}), 15)
        for role in ROLES:
            items = {item["kind"]: item for item in records if item["role"] == role}
            self.assertEqual(set(items), {"runtime", "history", "inspection"})
            for kind, suffix in (("runtime", "runtime"), ("history", "initial-history"), ("inspection", "peer-inspection")):
                self.assertEqual(items[kind]["path"], "/etc/serverware/custody-" + role + "-" + suffix + ".json")
            self.assertEqual(items["runtime"]["raw"], built[role])
            self.assertEqual(items["history"]["raw"], f["histories"][role])
            self.assertEqual((items["runtime"]["uid"], items["runtime"]["gid"]), (0, 0))
            for kind in ("history", "inspection"):
                self.assertEqual((items[kind]["uid"], items[kind]["gid"]), (f["cold"][role]["uid"], f["cold"][role]["gid"]))
            self.assertTrue(all(item["mode"] == 0o400 for item in items.values()))
            inspection = json.loads(items["inspection"]["raw"])
            self.assertEqual(inspection["runtimeConfigurationSha256"], sha(built[role]))
            self.assertEqual(inspection["startupDeadlineBoottimeNs"], f["launch"]["startupDeadlineBoottimeNs"])

    def test_public_install_plan_refuses_runtime_history_substitution(self):
        f = fixture(); built = runtimes(f)
        changed = json.loads(built[ROLES[0]])
        changed["runtime"]["authorityHistoryManifestSha256"] = labelled("foreign-history")
        built[ROLES[0]] = canonical(changed)
        with self.assertRaises(ValueError):
            plan(f, built)

    def test_v5_literal_recipe_preserves_u64_without_widening_legacy_fields(self):
        f = fixture()
        f["fragment"]["services"][ROLES[4]]["service"]["helperGeneration"] = (1 << 64) - 1
        value = {"apiVersion": policy.DELIVERY_POLICY_API, "ordinaryInitialHistories": f["initial_policy"],
            "ordinaryDeliveriesOriginal": canonical(f["fragment"]).decode("ascii")}
        selected = policy._policy_document(canonical(value))
        self.assertEqual(selected, value)
        runtime.validate_policy(json.loads(selected["ordinaryDeliveriesOriginal"]),
            ordinary_cold_originals={role: canonical(f["cold"][role]).decode("ascii") for role in ROLES},
            initial_policy=f["initial_policy"])
        value["unrelatedInteger"] = (1 << 64) - 1
        with self.assertRaises(ValueError):
            policy._policy_document(canonical(value))

    def test_each_c9_result_binds_approved_input_signature_and_fixed_pin(self):
        f = fixture(); built = runtimes(f); records = plan(f, built)
        business = (("listener", "journal"), ("listener", "state", "journal"),
            ("listener", "journal"), ("listener",), ("listener", "journal"))
        for index, role in enumerate(ROLES):
            names = business[index] + ("generation-journal", "generation-grant")
            if index in (0, 3):
                names += ("dispatch-journal", "dispatch-grant")
            prefix = {0: "spool-head", 1: "active-effect-cleanup", 3: "spool-current"}.get(index)
            if prefix:
                names += (prefix + "-journal", prefix + "-grant")
            cold = f["cold"][role]
            activation = [{"name": name, "fd": number + 6, "device": 8, "inode": 900000 + number,
                "mode": (stat.S_IFSOCK if name == "listener" else stat.S_IFREG) | 0o600,
                "uid": cold["uid"], "gid": cold["gid"]} for number, name in enumerate(names)]
            credentials = copy.deepcopy(f["fragment"]["services"][role]["credentials"])
            items = {item["kind"]: item for item in records if item["role"] == role}
            for kind, name in (("history", "authority-history"), ("inspection", "peer-inspection-policy")):
                item = items[kind]
                credentials.append({"name": name, "original": {"path": item["path"], "sha256": sha(item["raw"])},
                    "length": len(item["raw"]), "signing": None})
            payload = {"configurationSha256": sha(canonical(cold)), "authorityKeyId": cold["authority"]["keyId"],
                **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
                **{name: f["launch"][name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
                    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")},
                "issuedAtBoottimeNs": "1200", "runtimeConfig": {"path": installer.RUNTIME_PATHS[role], "sha256": sha(built[role])},
                "credentials": credentials, "activation": activation}
            input_value = {"apiVersion": "serverware.nativePilotServiceAuthorityInput/v1", "operation": "delivery",
                "serviceRole": role, "launchOriginal": canonical(f["launch"]).decode("ascii"),
                "payloadOriginal": canonical(payload).decode("ascii"), "configurationOriginal": canonical(cold).decode("ascii"),
                "configurationSha256": sha(canonical(cold)), "runtimeOriginal": built[role].decode("ascii"), "activation": activation}
            signature = f["delivery_keys"][role].sign(b"serverware.policyCustodyGuestDelivery.signature/v1\0" + canonical(payload))
            envelope = {"apiVersion": "serverware.policyCustodyGuestDelivery/v1", "payload": payload,
                "signatureBase64url": encoded(signature)}
            raw = canonical(envelope)
            result = {"original": raw.decode("ascii"), "sha256": sha(raw),
                "pin": {"path": publication.DESTINATIONS["ordinary-delivery-" + role], "sha256": sha(raw)}}
            with self.subTest(role=role):
                self.assertEqual(composer.checked_result(role, canonical(input_value), result), raw)
                bad = copy.deepcopy(result); bad["pin"]["path"] += ".wrong"
                with self.assertRaises(ValueError):
                    composer.checked_result(role, canonical(input_value), bad)
                envelope["signatureBase64url"] = encoded(bytes([signature[0] ^ 1]) + signature[1:])
                altered = canonical(envelope)
                bad = {"original": altered.decode("ascii"), "sha256": sha(altered),
                    "pin": {"path": result["pin"]["path"], "sha256": sha(altered)}}
                with self.assertRaises(InvalidSignature):
                    composer.checked_result(role, canonical(input_value), bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
