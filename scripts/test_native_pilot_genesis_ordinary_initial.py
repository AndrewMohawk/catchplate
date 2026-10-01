#!/usr/bin/env python3
"""Synthetic cold initial ceremonies, never actual process or journal proof.

Deterministic test keys and labelled process/directory facts are confined to
these pure controls. Independent native-frame transcripts exercise validators;
no live signer, authority CLI, owner, protected FD or native service is run.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import test_native_pilot_genesis_parent_authority as parents
import test_native_pilot_ordinary_initial as ordinary
from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_ordinary_initial_authority as authority
from serverware import native_pilot_genesis_ordinary_initial_profile as profile
from serverware import native_pilot_ordinary_key_profile as key

p = g.p


def fixture():
    parent, old = parents.fixture(), ordinary.fixture()
    window = g.document(parent["precreation_raw"], 32768)["payload"]
    common = {name: window[name] for name in authority.parent.WINDOW_FIELDS[2:] if name != "issuedAtBoottimeNs"}
    cold = {role: old["cold"][role] for role in profile.ROLES}
    launch = {"apiVersion": authority.LAUNCH_API, **common,
        "services": {role: old["launch"]["services"][role] for role in profile.ROLES}}
    launch_raw = g.canonical(launch)
    preparation = {"apiVersion": authority.PREPARATION_API, "phase": "parked-pre-exec", **common,
        "configurationSha256": p.sha(launch_raw), "issuedAtBoottimeNs": window["issuedAtBoottimeNs"],
        "services": {role: old["preparation"]["services"][role] for role in profile.ROLES}}
    preparation_raw = g.canonical(preparation)
    directories = {}
    for role in profile.ROLES:
        available = list(old["resources"]["services"][role]["directories"].values())
        directories[role] = {"directories": {name: copy.deepcopy(row)
            for name, row in zip(profile.DIRECTORIES[role], available, strict=False)}}
    resources = {"apiVersion": authority.RESOURCES_API, "preparationSha256": p.sha(preparation_raw),
        "issuedAtBoottimeNs": window["issuedAtBoottimeNs"], "services": directories}
    resources_raw = g.canonical(resources)
    base = {"parentConfigurationOriginal": parent["configuration_raw"].decode("ascii"),
        "parentDeliveryConfigurationOriginal": parent["cold_raw"].decode("ascii"),
        "parentPrecreationOriginal": parent["precreation_raw"].decode("ascii"),
        "parentObservationOriginal": parent["observation_raw"].decode("ascii"),
        "launchOriginal": launch_raw.decode("ascii"), "preparationOriginal": preparation_raw.decode("ascii"),
        "resourcesOriginal": resources_raw.decode("ascii")}
    rows = {}
    for role in profile.ROLES:
        endpoint_role = "settlement-store" if role == profile.ROLES[0] else "signer-hsm"
        measured = preparation["services"][role]
        target, pidfd = measured["targetExecutable"], measured["pidfdStat"]
        identity_values = (endpoint_role, cold[role]["uid"], cold[role]["gid"], measured["processId"],
            measured["startTimeTicks"], pidfd["inode"], pidfd["sha256"], target["device"], target["inode"],
            target["length"], target["sha256"], target["imaSha256"], target["fsVeritySha256"])
        identity = {**dict(zip(key.IDENTITY_FIELDS[:-1], identity_values, strict=True)),
            "identitySha256": ordinary.framed(key.PROCESS_DOMAIN, (ordinary.canonical(identity_values),))}
        state = {"apiVersion": profile.STATE_API, "serviceRole": role, "preparationSha256": p.sha(preparation_raw),
            "resourcesSha256": p.sha(resources_raw), "launchSha256": p.sha(launch_raw),
            "endpointProcessIdentitySha256": identity["identitySha256"], **common,
            "issuedAtBoottimeNs": window["issuedAtBoottimeNs"], "deploymentGenerationSha256": ordinary.labelled("cold-deployment"),
            "endpointGeneration": 11, "serviceGeneration": 13, "operationGeneration": 17, "durableEpoch": 19,
            "directories": directories[role]["directories"]}
        roots = {name: ordinary.framed(domain, (ordinary.canonical(state),)) for name, domain in ordinary.DOMAINS.items()}
        keys, public = {}, {}
        for name in authority.KEY_NAMES:
            keys[name] = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
                ("SYNTHETIC COLD INITIAL / " + role + "/" + name).encode("ascii")).digest())
            der = keys[name].public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            public[name] = {"keyId": ordinary.labelled(role + "/" + name), "keySpkiSha256": p.sha(der),
                "publicKeySpkiBase64": p.encoded(der)}
        payload = copy.deepcopy(old["wrapper"]["initialCheckpoint"]["payload"])
        payload.update(endpointRole=endpoint_role, endpointProcessIdentitySha256=identity["identitySha256"],
            predecessorCheckpointSha256=roots["predecessorCheckpointSha256"],
            authorizedSigningKeyId=public["service"]["keyId"], authorizedSigningKeySpkiSha256=public["service"]["keySpkiSha256"])
        domain = {"authorityBootId": list(p.decoded(common["bootIdBase64url"], size=16)),
            "timeNamespaceDevice": common["timeNamespaceDevice"], "timeNamespaceInode": common["timeNamespaceInode"]}
        payload["validFromBoottime"] = {"domain": domain, "absoluteBoottimeNanos": int(window["issuedAtBoottimeNs"])}
        payload["validUntilBoottime"] = {"domain": domain, "absoluteBoottimeNanos": 9_000_000_000}
        checkpoint = ordinary.checkpoint(payload, public["checkpoint"], keys["checkpoint"])
        history = copy.deepcopy(old["wrapper"]["history"])
        history["authorityRole"] = {"authorityKind": "isolated-service", "role": role}
        history["rootAuthority"] = public["root"]
        anchor = history["firstRetainedEpoch"]
        anchor.update(rootAuthorityKeyId=public["root"]["keyId"], rootAuthorityKeySpkiSha256=public["root"]["keySpkiSha256"],
            prunedHistoryRootSha256=roots["prunedHistoryRootSha256"])
        epoch = anchor["retainedEpoch"]
        epoch.update(authorityRole=history["authorityRole"], checkpointSha256=checkpoint["checkpointSha256"],
            checkpointAuthority=public["checkpoint"], serviceSigningKey=public["service"], endpointProcessIdentity=identity,
            endpointProcessIdentitySha256=identity["identitySha256"], durableEpochHeadSha256=roots["durableEpochHeadSha256"],
            deploymentGenerationSha256=state["deploymentGenerationSha256"])
        ordinary.sign_anchor(history, keys)
        wrapper = {"apiVersion": profile.WRAPPER_API, "initialState": state, "initialCheckpoint": checkpoint, "history": history}
        anchor_raw = ordinary.canonical([anchor[name] for name in ordinary.ANCHOR_FIELDS])
        signatures = {name: {"apiVersion": authority.SIGNATURE_API, "signer": name, "anchorPayloadSha256": p.sha(anchor_raw),
            "keyId": public[name]["keyId"], "keySpkiSha256": public[name]["keySpkiSha256"], "signatureBase64": anchor[field]}
            for name, field in zip(authority.KEY_NAMES, ordinary.SIGNATURE_FIELDS, strict=True)}
        original = {"apiVersion": authority.INPUT_API, **base, "serviceRole": role,
            "configurationOriginal": g.canonical(cold[role]).decode("ascii"), "initialStateOriginal": g.canonical(state).decode("ascii"),
            "authorities": public, "payloadOriginal": g.canonical(payload).decode("ascii")}
        inputs, results = {}, {"checkpoint": g.canonical(checkpoint), "assemble": g.canonical(wrapper)}
        for operation in authority.OPERATIONS:
            value = {**original, "operation": operation}
            if operation != "checkpoint": value["initialCheckpointOriginal"] = g.canonical(checkpoint).decode("ascii")
            if operation == "assemble": value["anchorSignatures"] = {name: g.canonical(record).decode("ascii") for name, record in signatures.items()}
            elif operation != "checkpoint": results[operation] = g.canonical(signatures[operation.removesuffix("-anchor")])
            inputs[operation] = g.canonical(value)
        rows[role] = {"inputs": inputs, "results": results, "state": state, "wrapper": wrapper, "keys": keys,
            "authorities": public, "root_pin": {name: public["root"][name] for name in ("keyId", "keySpkiSha256")}, "identity": identity}
    return {"parent": parent, "launch": launch, "preparation": preparation, "resources": resources,
        "cold": cold, "base": base, "rows": rows}, {"boot": parent["boot"], "now_boottime_ns": parent["now"]}


class ColdOrdinaryInitialTests(unittest.TestCase):
    def setUp(self):
        self.f, self.kw = fixture()
        self.row = self.f["rows"][profile.ROLES[0]]

    def prepare(self, value, operation="checkpoint", **kw):
        return authority.prepare_input(operation, g.canonical(value), **(kw or self.kw))

    def test_both_complete_native_transcripts_and_all_ten_stage_results(self):
        for role, row in self.f["rows"].items():
            for operation in authority.OPERATIONS:
                raw = row["results"][operation]
                self.assertEqual(authority.checked_result(operation, row["inputs"][operation],
                    {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **self.kw), raw)
            self.assertEqual(profile.manifest(row["results"]["assemble"], role=role, root_pin=row["root_pin"]), row["wrapper"]["history"])

    def test_state_derivation_binds_only_cold_sources_and_explicit_counters(self):
        for role, row in self.f["rows"].items():
            value = g.document(row["inputs"]["checkpoint"], authority.MAX_INPUT)
            sources = {argument: value[name].encode("ascii") for name, (argument, _) in authority.SOURCE_FIELDS.items()}
            counters = {name: row["state"][name] for name in ("deploymentGenerationSha256", "endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch")}
            self.assertEqual(authority.state_original(role=role, endpoint_role=row["identity"]["endpointRole"], counters=counters,
                **sources, **self.kw), g.canonical(row["state"]))
            self.assertEqual(self.prepare(value)["deadline"], 5_000_000_000)

    def test_hot_versions_and_extra_service_or_directories_refuse(self):
        mutations = (("launchOriginal", "serverware.custodyFiveServiceLaunch/v6"),
            ("preparationOriginal", "serverware.custodyFiveServicePreparation/v1"),
            ("resourcesOriginal", "serverware.custodyFiveServiceInitialResources/v1"),
            ("initialStateOriginal", "serverware.custodyOrdinaryInitialState/v1"))
        for field, api in mutations:
            value = g.document(self.row["inputs"]["checkpoint"], authority.MAX_INPUT)
            nested = g.document(value[field].encode("ascii"), 65536); nested["apiVersion"] = api
            value[field] = g.canonical(nested).decode("ascii")
            with self.assertRaises(ValueError): self.prepare(value)
        state = copy.deepcopy(self.row["state"])
        state["directories"]["generation-journal"] = state["directories"]["journal"]
        with self.assertRaises(ValueError): profile.validate_state(state)
        wrapper = copy.deepcopy(self.row["wrapper"]); wrapper["apiVersion"] = "serverware.custodyOrdinaryInitialHistory/v1"
        with self.assertRaises(ValueError): profile.manifest(g.canonical(wrapper), role=profile.ROLES[0], root_pin=self.row["root_pin"])

    def test_changed_process_resources_parent_or_state_original_refuses(self):
        for field, target, replacement in (("preparationOriginal", "configurationSha256", ordinary.labelled("changed")),
                ("resourcesOriginal", "preparationSha256", ordinary.labelled("changed")),
                ("parentObservationOriginal", "precreationSha256", ordinary.labelled("changed")),
                ("initialStateOriginal", "endpointProcessIdentitySha256", ordinary.labelled("changed")),
                ("initialStateOriginal", "resourcesSha256", ordinary.labelled("changed"))):
            value = g.document(self.row["inputs"]["checkpoint"], authority.MAX_INPUT)
            nested = g.document(value[field].encode("ascii"), 65536); nested[target] = replacement
            value[field] = g.canonical(nested).decode("ascii")
            with self.assertRaises(ValueError): self.prepare(value)
        value = g.document(self.row["inputs"]["checkpoint"], authority.MAX_INPUT)
        resources = g.document(value["resourcesOriginal"].encode("ascii"), 65536)
        resources["services"][profile.ROLES[0]]["directories"]["journal"]["entryCount"] = 1
        value["resourcesOriginal"] = g.canonical(resources).decode("ascii")
        with self.assertRaises(ValueError): self.prepare(value)

    def test_root_pin_key_independence_and_each_anchor_signature_refuse(self):
        pin = {**self.row["root_pin"], "keyId": ordinary.labelled("wrong-root")}
        with self.assertRaises(ValueError): profile.manifest(self.row["results"]["assemble"], role=profile.ROLES[0], root_pin=pin)
        value = g.document(self.row["inputs"]["checkpoint"], authority.MAX_INPUT)
        value["authorities"]["service"] = value["authorities"]["root"]
        with self.assertRaises(ValueError): self.prepare(value)
        for name in authority.KEY_NAMES:
            value = g.document(self.row["inputs"]["assemble"], authority.MAX_INPUT)
            record = g.document(value["anchorSignatures"][name].encode("ascii"), 4096)
            record["signatureBase64"] = p.encoded(bytes(64))
            value["anchorSignatures"][name] = g.canonical(record).decode("ascii")
            with self.assertRaises(InvalidSignature): self.prepare(value, "assemble")

    def test_checkpoint_initial_boundary_and_wrong_native_frame_refuse(self):
        for field, changed in (("checkpointSequence", 2), ("rollbackFloorConsumerSequence", 2),
                ("predecessorCheckpointSha256", ordinary.labelled("arbitrary-root"))):
            value = g.document(self.row["inputs"]["checkpoint"], authority.MAX_INPUT)
            payload = g.document(value["payloadOriginal"].encode("ascii"), 65536); payload[field] = changed
            value["payloadOriginal"] = g.canonical(payload).decode("ascii")
            with self.assertRaises(ValueError): self.prepare(value)
        raw = g.document(self.row["results"]["checkpoint"], 65536)
        raw["authoritySignatureBase64"] = p.encoded(self.row["keys"]["checkpoint"].sign(b"not-the-C3-frame"))
        raw = key.envelope(raw["payload"], raw["authorityKeyId"], raw["authorityKeySpkiSha256"], raw["authoritySignatureBase64"])
        with self.assertRaises(InvalidSignature):
            profile.validate_checkpoint(self.row["state"], raw, checkpoint_authority=self.row["authorities"]["checkpoint"],
                service_key=self.row["authorities"]["service"])

    def test_original_startup_checkpoint_and_retained_lifetime_bounds(self):
        raw = self.row["results"]["assemble"]
        kwargs = {"role": profile.ROLES[0], "root_pin": self.row["root_pin"], "boot": self.kw["boot"]}
        with self.assertRaises(ValueError): profile.require_window(raw, **kwargs, now_boottime_ns=5_000_000_000)
        self.assertEqual(profile.require_window(raw, **kwargs, now_boottime_ns=6_000_000_000, startup=False)["deadline"], 9_000_000_000)
        with self.assertRaises(ValueError): profile.require_window(raw, **kwargs, now_boottime_ns=9_000_000_000, startup=False)
        with self.assertRaises(ValueError): profile.require_window(raw, **kwargs, now_boottime_ns=self.kw["now_boottime_ns"],
            issued=1_000_000_000, expires=9_000_000_001)
        value = g.document(self.row["inputs"]["checkpoint"], authority.MAX_INPUT)
        with self.assertRaises(ValueError): self.prepare(value, boot=(self.kw["boot"][0], 7, 999), now_boottime_ns=self.kw["now_boottime_ns"])

    def test_closed_canonical_shapes_and_u64_state_counters(self):
        value = g.document(self.row["inputs"]["checkpoint"], authority.MAX_INPUT); value["driverOriginal"] = "{}"
        with self.assertRaises(ValueError): self.prepare(value)
        with self.assertRaises(ValueError): authority.input_document(self.row["inputs"]["checkpoint"] + b"\n")
        state = copy.deepcopy(self.row["state"]); state["operationGeneration"] = (1 << 64) - 1
        self.assertEqual(profile.validate_state(state)["operationGeneration"], (1 << 64) - 1)
        for invalid in (True, 0, 1 << 64):
            state["operationGeneration"] = invalid
            with self.assertRaises(ValueError): profile.validate_state(state)


if __name__ == "__main__":
    unittest.main()
