#!/usr/bin/env python3
"""Synthetic cold C9 transcripts; no protected signer, owner, FD or image run.

All process/resource identities are test data. Signatures use deterministic
test keys and independently spelled native frames, never validator mocks.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

import test_native_pilot_genesis_parent_authority as parents
import test_native_pilot_genesis_closure_schema as closures
import test_native_pilot_genesis_ordinary_runtime as ordinary_tests
from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_delivery_authority as authority
from serverware import native_pilot_genesis_coordinator_runtime as runtime
from serverware import native_pilot_genesis_endpoint_profile as endpoints

p = g.p


def text(value): return g.canonical(value).decode("ascii")
def digest(label): return p.sha(("SYNTHETIC COLD C9 / " + label).encode("ascii"))


def peer(uid, pid, *, identity=None):
    value = {"uid": uid, "gid": uid, "pid": pid, "startTimeTicks": 99,
        "executableDevice": 11, "executableInode": 120 + pid, "executableLength": 65536,
        "executableSha256": digest("peer-executable"), "cgroupPathSha256": digest("peer-cgroup"),
        "cgroupMountId": 77, "cgroupInode": 880 + pid, "securityLabelSha256": digest("approved-label"),
        "configurationGenerationSha256": digest("approved-generation")}
    if identity is not None:
        for target, source in (("uid", "endpointUid"), ("gid", "endpointGid"), ("pid", "endpointPid"),
                ("startTimeTicks", "endpointStartTimeTicks")):
            value[target] = identity[source]
        for field in ("executableDevice", "executableInode", "executableLength", "executableSha256"):
            value[field] = identity[field]
    parts = [value[name].to_bytes(width, "big") for name, width in (("uid", 4), ("gid", 4), ("pid", 4),
        ("startTimeTicks", 8), ("executableDevice", 8), ("executableInode", 8), ("executableLength", 8))]
    parts += [bytes.fromhex(value["executableSha256"].removeprefix("sha256:")), value["cgroupPathSha256"].encode("ascii"),
        value["cgroupMountId"].to_bytes(8, "big"), value["cgroupInode"].to_bytes(8, "big"),
        value["securityLabelSha256"].encode("ascii"), value["configurationGenerationSha256"].encode("ascii")]
    value["processIdentitySha256"] = p.framed(b"serverware.policyCustodyPeerProcessIdentity/v4", parts)
    return value


def coordinator_runtime(*, cold_binding_input=None):
    f = ordinary_tests.fixture()
    if cold_binding_input is not None:
        bound = ordinary_tests.binding.result_document(ordinary_tests.binding.prepare(cold_binding_input,
            expected_input_sha256=p.sha(cold_binding_input), **f["kw"]))
        scope = g.document(bound["genesisScopeOriginal"].encode("ascii"), 16384)
        native = g.document(f["grants"][runtime.ROLES[0]]["nativePublicationOriginal"].encode("ascii"), g.MAX_BYTES)["payload"]
        native["scope"] = scope
        native["authorization"]["assignmentPayloadSha256"] = scope["assignmentPayloadSha256"]
        native_raw = ordinary_tests.native_signed("nativePublicationGenesisAssignment", native, f["native_key"])
        retrieval = g.document(f["grants"][runtime.ROLES[0]]["nativeRetrievalOriginal"].encode("ascii"), g.MAX_BYTES)["payload"]
        retrieval["scope"] = scope
        retrieval["authorization"]["assignmentPayloadSha256"] = scope["assignmentPayloadSha256"]
        retrieval["native"]["grantSha256"] = p.sha(native_raw)
        retrieval_raw = ordinary_tests.native_signed("nativePublicationGenesisRetrievalGrant", retrieval, f["native_key"])
        for value in f["grants"].values():
            value.update(coldBindingInputOriginal=cold_binding_input.decode("ascii"), coldBindingInputSha256=p.sha(cold_binding_input),
                nativePublicationOriginal=native_raw.decode("ascii"), nativeRetrievalOriginal=retrieval_raw.decode("ascii"))
    grant_raws, histories, sessions = [], [], []
    for index, role in enumerate(runtime.ROLES):
        prepared = ordinary_tests.authority.prepare_input("grant", g.canonical(f["grants"][role]), **f["kw"])
        grant_raws.append(ordinary_tests.signed_grant(prepared["payload"], f["f"]["rows"][role]["keys"]["root"]))
        header = g.document(f["runtimes"][role], g.MAX_BYTES)["runtime"]
        histories.append({"serviceRole": role, "runtimeOriginal": f["runtimes"][role].decode("ascii"),
            "historyOriginal": f["build_args"]["history_originals"][role].decode("ascii"),
            "rootKeyId": header["authorityHistoryRootKeyId"], "rootKeySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]})
        sessions.append({"serviceRole": role, "activationFdName": runtime.SESSIONS[index],
            "expectedSocketPath": runtime.ordinary.listener(role),
            "expectedPeer": peer(61000 + index, 2000 + index, identity=f["f"]["rows"][role]["identity"])})
    native = [{"kind": kind, "activationFdName": runtime.NATIVE_SESSIONS[index],
        "expectedSocketPath": "/run/serverware-shadow-" + kind + "/listener.sock",
        "expectedPeer": peer(62002 - index, 3002 - index)} for index, kind in enumerate(runtime.NATIVE)]
    return {"apiVersion": runtime.API, "scope": g.document(grant_raws[0], 262144)["payload"]["scope"],
        "durableGrantOriginal": grant_raws[0].decode("ascii"), "currentGrantOriginal": grant_raws[1].decode("ascii"),
        "histories": histories, "serviceSessions": sessions, "nativeEndpoints": native, "resultPeer": peer(0, 4001)}


def fixture(role=authority.ROLES[0], *, cold_binding_input=None):
    parent = parents.fixture()
    parent_originals = {name: parent[source].decode("ascii") for name, source in zip(authority.PARENTS,
        ("configuration_raw", "cold_raw", "precreation_raw", "observation_raw"), strict=True)}
    window = g.document(parent["precreation_raw"], 32768)["payload"]
    owner = {"apiVersion": endpoints.CONFIG_API, "parentConfigurationSha256": p.sha(parent["configuration_raw"]),
        "parentPrecreationSha256": p.sha(parent["precreation_raw"]), "releaseAuthority": parents.selected_key(8)[1], "services": {}}
    cold_configs, cold_keys, observations, resources = {}, {}, {}, {}
    for index, member in enumerate(endpoints.ROLES):
        key, selected = parents.selected_key(10 + index)
        cold = {"apiVersion": "serverware.policyCustodyGuestConfiguration/v1", "authority": selected,
            "serviceRole": "production-bridge", "uid": 62001 + index, "gid": 62001 + index}
        cold_configs[member], cold_keys[member] = cold, key
        manifest = closures.fixture(member)["manifest"]
        owner["services"][member] = {"executableSha256": manifest["workerExecutableSha256"],
            "deliveryConfiguration": parents.pin(member, p.sha(g.canonical(cold))),
            "image": parents.pin(member + "-image", manifest["imageSha256"])}
        observations[member] = {"processId": 3001 + index, "startTimeTicks": 99, "pidfdDevice": 5,
            "pidfdInode": 31 + index, "executable": {"device": 11, "inode": 51 + index, "length": 65536,
                "sha256": manifest["workerExecutableSha256"]}}
        activation, directories = [], {}
        for slot, name in enumerate(endpoints.ACTIVATION[member], 6):
            kind = stat.S_IFSOCK if slot == 6 else stat.S_IFREG if name.endswith("-lock") else stat.S_IFDIR
            row = {"name": name, "fd": slot, "device": os.makedev(8, 1), "inode": 100 + index * 10 + slot,
                "mode": kind | (0o777 if slot == 6 else 0o600 if name.endswith("-lock") else 0o700),
                "uid": 0 if slot == 6 else cold["uid"], "gid": 0 if slot == 6 else cold["gid"]}
            activation.append(row)
            if kind == stat.S_IFDIR:
                directories[name] = {"identity": {"mountId": 77, "deviceMajor": 8, "deviceMinor": 1,
                    **{field: row[field] for field in ("inode", "uid", "gid", "mode")}},
                    "entryCount": 1 if name == "ledger-spool-store" else 0}
        resources[member] = {"activation": activation, "directories": directories,
            "listenerSocketPath": endpoints.LISTENERS[member]}
    observation = {"apiVersion": endpoints.OBSERVATION_API, "configurationSha256": p.sha(g.canonical(owner)),
        "parentConfigurationSha256": owner["parentConfigurationSha256"], "parentPrecreationSha256": owner["parentPrecreationSha256"],
        "invocationId": window["invocationId"], "services": observations}
    preparation = {"apiVersion": endpoints.PREPARATION_API, **{name: observation[name] for name in
        ("configurationSha256", "parentConfigurationSha256", "parentPrecreationSha256")},
        "observationOriginal": text(observation), **{name: window[name] for name in endpoints.WINDOW},
        "observedAtBoottimeNs": str(parent["now"]), "services": {member: {"processId": row["processId"],
            "startTimeTicks": row["startTimeTicks"], "pidfd": {"device": row["pidfdDevice"], "inode": row["pidfdInode"]},
            "targetExecutable": row["executable"], "cgroup": {"pathSha256": digest(member + "-cgroup"), "mountId": 77, "inode": 900 + index}}
            for index, (member, row) in enumerate(observations.items())}}
    resource_wire = {"apiVersion": endpoints.RESOURCES_API, "preparationSha256": p.sha(g.canonical(preparation)),
        "issuedAtBoottimeNs": window["issuedAtBoottimeNs"], "services": resources}
    if role in endpoints.ROLES:
        cold, key, observed = cold_configs[role], cold_keys[role], observations[role]
        runtime_raw = g.canonical({"apiVersion": "serverware.nativePilotEndpointRuntime/v1", "role": role})
        activation, image = resources[role]["activation"], owner["services"][role]["image"]
        extra = dict(ownerConfigurationOriginal=text(owner), preparationOriginal=text(preparation), resourcesOriginal=text(resource_wire))
    else:
        cold, key = g.document(parent["cold_raw"], 65536), parents.selected_key(3)[0]
        observed = g.document(parent["observation_raw"], 32768)
        runtime_raw = g.canonical(coordinator_runtime(cold_binding_input=cold_binding_input))
        activation = [{"name": name, "fd": slot, "device": 18, "inode": 1000 + slot,
            "mode": kind | (0o777 if kind == stat.S_IFSOCK else 0o711), "uid": 0, "gid": 0}
            for slot, (name, kind) in enumerate(runtime.ACTIVATION[:-2], 6)] + observed["resultActivation"]
        image = parents.pin("coordinator-image", closures.fixture(role)["manifest"]["imageSha256"])
        extra = {}
    payload = {"configurationSha256": p.sha(g.canonical(cold)), "authorityKeyId": cold["authority"]["keyId"],
        **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
        **{name: window[name] for name in endpoints.WINDOW}, "runtimeConfig": parents.pin(role + "-runtime", p.sha(runtime_raw)),
        "credentials": [{"name": "synthetic-nonsecret", "original": parents.pin(role + "-credential"), "length": 32, "signing": None}],
        "activation": activation}
    value = {"apiVersion": authority.API, "role": role, "parentOriginals": parent_originals,
        "configurationOriginal": text(cold), "runtimeOriginal": runtime_raw.decode("ascii"),
        "payloadOriginal": text(payload), "activationOriginal": text(activation), "image": image, **extra}
    raw = g.canonical({"apiVersion": "serverware.policyCustodyGuestDelivery/v1", "payload": payload,
        "signatureBase64url": p.encoded(key.sign(b"serverware.policyCustodyGuestDelivery.signature/v1\0" + g.canonical(payload)))})
    return dict(input=value, raw=raw, configuration=cold, window=window, observed=observed, parentOriginals=parent_originals,
        key=key, boot=parent["boot"], now=parent["now"], runtime_raw=runtime_raw, image_sha256=image["sha256"],
        executable_sha256=observed["executable"]["sha256"])


class GenesisDeliveryTests(unittest.TestCase):
    def test_all_three_exact_signed_deliveries_keep_original_deadline(self):
        for role in authority.ROLES:
            f = fixture(role)
            checked = authority.verified_delivery(role, p.canonical(f["input"]), f["raw"], boot=f["boot"], now_boottime_ns=f["now"])
            self.assertEqual(checked["guest"]["deliverySha256"], p.sha(f["raw"]))
            self.assertEqual(checked["deadline"], 5_000_000_000)
            self.assertEqual(checked["parentOriginals"], f["parentOriginals"])

    def test_cold_role_source_activation_and_runtime_substitution_refuse(self):
        f = fixture()
        for field in ("role", "runtimeOriginal", "activationOriginal", "resourcesOriginal", "preparationOriginal", "extra"):
            value = copy.deepcopy(f["input"])
            value[field] = "retrieval" if field == "role" else "{}"
            with self.subTest(field=field), self.assertRaises((ValueError, KeyError, TypeError)):
                authority.prepare_input(authority.ROLES[0], p.canonical(value), boot=f["boot"], now_boottime_ns=f["now"])

    def test_original_window_and_signed_payload_tampering_refuse(self):
        f = fixture()
        for now in (999_999_999, 5_000_000_000, 10_000_000_000):
            with self.assertRaises(ValueError):
                authority.prepare_input(authority.ROLES[0], p.canonical(f["input"]), boot=f["boot"], now_boottime_ns=now)
        signed = g.document(f["raw"], 65536); signed["signatureBase64url"] = p.encoded(bytes(64))
        with self.assertRaises(InvalidSignature):
            authority.verified_delivery(authority.ROLES[0], p.canonical(f["input"]), g.canonical(signed), boot=f["boot"], now_boottime_ns=f["now"])

    def test_endpoint_image_and_credential_path_separation(self):
        f = fixture()
        for what in ("image", "credentials"):
            value = copy.deepcopy(f["input"])
            if what == "image": value["image"]["sha256"] = digest("wrong image")
            else:
                payload = g.document(value["payloadOriginal"].encode("ascii"), 65536)
                payload["credentials"][0]["original"]["path"] = payload["runtimeConfig"]["path"]
                value["payloadOriginal"] = text(payload)
            with self.assertRaises(ValueError):
                authority.prepare_input(authority.ROLES[0], p.canonical(value), boot=f["boot"], now_boottime_ns=f["now"])

    def test_full_native_u64_namespace_survives_all_literal_sources(self):
        f, value = fixture(), copy.deepcopy(fixture()["input"])
        parent = value["parentOriginals"]
        window = g.document(parent["parentPrecreationOriginal"].encode("ascii"), 32768)["payload"]
        window.update(timeNamespaceDevice=(1 << 64) - 1, timeNamespaceInode=(1 << 64) - 1)
        signed = parents.independently_signed(parents.authority.PRECREATION_API,
            parents.authority.PRECREATION_DOMAIN, window, parents.selected_key(1)[0])
        parent["parentPrecreationOriginal"] = signed.decode("ascii")
        observation = g.document(parent["parentObservationOriginal"].encode("ascii"), 32768)
        observation["precreationSha256"] = p.sha(signed)
        parent["parentObservationOriginal"] = text(observation)
        config = endpoints.configuration(value["ownerConfigurationOriginal"].encode("ascii"))
        config["parentPrecreationSha256"] = p.sha(signed)
        value["ownerConfigurationOriginal"] = text(config)
        prepared = endpoints.preparation(value["preparationOriginal"].encode("ascii"))
        observed = endpoints.observation(prepared["observationOriginal"].encode("ascii"))
        for target in (prepared, observed):
            target.update(configurationSha256=p.sha(g.canonical(config)), parentPrecreationSha256=p.sha(signed))
        prepared.update(timeNamespaceDevice=window["timeNamespaceDevice"], timeNamespaceInode=window["timeNamespaceInode"],
            observationOriginal=text(observed))
        value["preparationOriginal"] = text(prepared)
        resources = endpoints.resources(value["resourcesOriginal"].encode("ascii"))
        resources["preparationSha256"] = p.sha(g.canonical(prepared))
        value["resourcesOriginal"] = text(resources)
        payload = g.document(value["payloadOriginal"].encode("ascii"), 65536)
        payload.update(timeNamespaceDevice=window["timeNamespaceDevice"], timeNamespaceInode=window["timeNamespaceInode"])
        value["payloadOriginal"] = text(payload)
        result = g.canonical({"apiVersion": "serverware.policyCustodyGuestDelivery/v1", "payload": payload,
            "signatureBase64url": p.encoded(f["key"].sign(b"serverware.policyCustodyGuestDelivery.signature/v1\0" + g.canonical(payload)))})
        context = authority.verified_delivery(authority.ROLES[0], p.canonical(value), result,
            boot=(f["boot"][0], (1 << 64) - 1, (1 << 64) - 1), now_boottime_ns=f["now"])
        self.assertEqual(context["guest"]["timeNamespaceInode"], (1 << 64) - 1)


if __name__ == "__main__": unittest.main()
