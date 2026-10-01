#!/usr/bin/env python3
"""Synthetic cold runtime/C9/grant transcripts, never live owners or admission.

All process, directory, native guest and activation values are labelled data.
Actual Ed25519 signatures exercise public authentication only. No protected
signer, provisioning, FD owner, native service, journal or authority is run.
"""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

import test_native_pilot_genesis_ordinary_initial as initial_tests
import test_native_pilot_ordinary_initial as initial_wire
import test_native_pilot_publication_cold_binding as binding_tests
from test_native_pilot_generation_scope import key_fixture, NOW
from serverware import custody_generation_grants as g
from serverware import native_pilot_bridge_preparation as peer_wire
from serverware import native_pilot_genesis_coordinator_peer as coordinator
from serverware import native_pilot_genesis_ordinary_authority as authority
from serverware import native_pilot_genesis_ordinary_runtime as runtime
from serverware import native_pilot_genesis_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_runtime_recipe as recipe
from serverware import native_pilot_publication_cold_binding as binding

p = g.p


def labelled(text): return p.sha(("SYNTHETIC COLD RUNTIME ONLY / " + text).encode("ascii"))
def raw_public(key): return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
def text(value): return g.canonical(value).decode("ascii")


def native_signed(stem, payload, key):
    message = b"serverware.signedEnvelope/v1\0serverware." + stem.encode("ascii") + b".signature/v1\0serverware.canonicalJson/ascii-integer-v1\0" + g.canonical(payload)
    return g.canonical({"payload": payload, "signature": p.encoded(key.sign(message))})


def signed_grant(payload, key):
    raw = g.canonical(payload); domain = b"serverware.nativePublicationGenesisGrant.signature/v1"
    message = b"serverware-signature-v1\0" + len(domain).to_bytes(8, "big") + domain + len(raw).to_bytes(8, "big") + raw
    return g.canonical({"payload": payload, "signatureBase64url": p.encoded(key.sign(message))})


def reference(history):
    e = history["firstRetainedEpoch"]["retainedEpoch"]
    result = {field: e[field] for field in ("apiVersion", "authorityRole", "authorityEpochSequence", "checkpointSequence",
        "checkpointSha256", "endpointProcessIdentitySha256", "endpointGeneration", "serviceGeneration", "operationGeneration",
        "durableEpoch", "durableEpochHeadSha256", "deploymentGenerationSha256")}
    result.update(authorityEpochSha256=e["epochSha256"], checkpointAuthorityKeyId=e["checkpointAuthority"]["keyId"],
        checkpointAuthorityKeySpkiSha256=e["checkpointAuthority"]["keySpkiSha256"],
        serviceSigningKeyId=e["serviceSigningKey"]["keyId"], serviceSigningKeySpkiSha256=e["serviceSigningKey"]["keySpkiSha256"])
    return result


def fixture():
    f, kw = initial_tests.fixture()
    keys = {role: Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("SYNTHETIC C9 / " + role).encode()).digest()) for role in initial.ROLES}
    # Replace old public-only fixture keys with synthetic keypairs and resign
    # the actual source-linked initial transcripts. No owner is fabricated.
    for role in initial.ROLES:
        public = raw_public(keys[role])
        f["cold"][role]["authority"] = {"publicKeyBase64url": p.encoded(public), "keyId": p.sha(public)}
        digest = p.sha(g.canonical(f["cold"][role]))
        f["launch"]["services"][role]["deliveryConfiguration"]["sha256"] = digest
        f["preparation"]["services"][role]["configurationSha256"] = digest
    f["preparation"]["configurationSha256"] = p.sha(g.canonical(f["launch"]))
    f["resources"]["preparationSha256"] = p.sha(g.canonical(f["preparation"]))
    for field, source in (("launchOriginal", "launch"), ("preparationOriginal", "preparation"), ("resourcesOriginal", "resources")):
        f["base"][field] = text(f[source])
    histories = {}
    for role, row in f["rows"].items():
        state, wrapper = row["state"], row["wrapper"]
        for field, source in (("launchSha256", "launch"), ("preparationSha256", "preparation"), ("resourcesSha256", "resources")):
            state[field] = p.sha(g.canonical(f[source]))
        roots = {name: initial_wire.framed(domain, (initial_wire.canonical(state),)) for name, domain in initial_wire.DOMAINS.items()}
        payload = wrapper["initialCheckpoint"]["payload"]
        payload["predecessorCheckpointSha256"] = roots["predecessorCheckpointSha256"]
        checkpoint = initial_wire.checkpoint(payload, row["authorities"]["checkpoint"], row["keys"]["checkpoint"])
        wrapper["initialCheckpoint"] = checkpoint
        anchor = wrapper["history"]["firstRetainedEpoch"]
        anchor["prunedHistoryRootSha256"] = roots["prunedHistoryRootSha256"]
        anchor["retainedEpoch"].update(checkpointSha256=checkpoint["checkpointSha256"], durableEpochHeadSha256=roots["durableEpochHeadSha256"])
        initial_wire.sign_anchor(wrapper["history"], row["keys"])
        histories[role] = g.canonical(wrapper)
    source = {**f["base"], "configurationOriginals": {role: text(f["cold"][role]) for role in initial.ROLES}}
    parent = f["parent"]
    observation = g.document(parent["observation_raw"], 32768)
    window = g.document(parent["precreation_raw"], 32768)["payload"]
    cold = g.document(parent["cold_raw"], 65536)
    cgroup = {"pathSha256": labelled("coordinator-cgroup"), "mountId": 77, "inode": 88}
    peer = {"uid": cold["uid"], "gid": cold["gid"], "pid": observation["processId"], "startTimeTicks": observation["startTimeTicks"],
        **{"executable" + name[0].upper() + name[1:]: observation["executable"][name] for name in ("device", "inode", "length", "sha256")},
        "cgroupPathSha256": cgroup["pathSha256"], "cgroupMountId": cgroup["mountId"], "cgroupInode": cgroup["inode"],
        "securityLabelSha256": labelled("approved-security-label"), "configurationGenerationSha256": labelled("approved-config-generation")}
    peer["processIdentitySha256"] = peer_wire.peer_identity(peer)
    peer_preparation = {"apiVersion": coordinator.API, "profile": coordinator.wire.PROFILE, "ownerKind": coordinator.ROLE,
        "phase": "parked-pre-exec", "configurationSha256": p.sha(parent["configuration_raw"]),
        "sourceOriginalSha256": p.sha(parent["observation_raw"]), "observedAtBoottimeNs": str(kw["now_boottime_ns"]),
        **{name: window[name] for name in initial_tests.authority.parent.WINDOW_FIELDS[2:]},
        "peers": {coordinator.ROLE: {"processId": observation["processId"], "startTimeTicks": observation["startTimeTicks"],
            "pidfd": {"device": observation["pidfdDevice"], "inode": observation["pidfdInode"]},
            "targetExecutable": observation["executable"], "cgroup": cgroup}}}
    rows = {}
    def credential(name, role, kind, signing=False):
        row = f["rows"][role]; public = raw_public(row["keys"][kind])
        return {"name": name, "original": {"path": "/approved/synthetic/credentials/" + name,
            "sha256": labelled("private-original-" + name) if signing else p.sha(public)}, "length": 32,
            "signing": {"keyId": row["authorities"][kind]["keyId"], "publicKeyBase64url": p.encoded(public)} if signing else None}
    def pin(prefix):
        return {"endpointVerifyingKeyCredential": prefix + "-service-public", "checkpointAuthorityVerifyingKeyCredential": prefix + "-checkpoint-public",
            "consumeCursor": {"sequenceHighWater": 0, "expectedNextSequence": 1,
                "expectedPredecessorReceiptSha256": labelled("independently-selected-cursor-" + prefix)}}
    for index, role in enumerate(initial.ROLES):
        root = f["rows"][role]["authorities"]["root"]
        header = {"startupTimeoutMillis": 1000, "readinessEpoch": 13, "maximumDurabilityWorkerNanos": 1_000_000,
            "productionDispatchProtocolSetSha256": labelled("approved-protocol-set"), "sharedConfigurationSha256": labelled("approved-shared-configuration"),
            "authorityHistoryRootKeyId": root["keyId"], "authorityHistoryRootKeySpkiSha256": root["keySpkiSha256"]}
        if role == initial.ROLES[0]:
            service = {"signingKeyCredential": "drs-signing", "currentHeadAuthorityVerifyingKeyCredential": "drs-head",
                "ownershipSeed": [], "recoveryMaterialSeed": []}
            credentials = [credential("drs-signing", role, "service", True), credential("drs-head", role, "checkpoint")]
        else:
            service = {"serviceSigningKeyCredential": "csa-signing", "serviceSigningPin": pin("self"), "currentSubjects": [{
                "subject": {"authority": "endpoint", "identity": {"endpoint_role": "settlement-store"}},
                "serviceRole": initial.ROLES[0], "pin": pin("drs")}]}
            credentials = [credential("csa-signing", role, "service", True)]
            for prefix, target in (("self", role), ("drs", initial.ROLES[0])):
                credentials += [credential(prefix + "-service-public", target, "service"), credential(prefix + "-checkpoint-public", target, "checkpoint")]
        rows[role] = {"runtimeHeader": header, "service": service, "credentials": credentials}
    fragment = {"apiVersion": runtime.API, "services": rows}
    build_args = dict(fragment=fragment, history_originals=histories, source=source,
        peer_preparation_raw=g.canonical(peer_preparation), approved_peer=peer, **kw)
    runtimes = {role: runtime.build(role, **build_args) for role in initial.ROLES}
    common = {"apiVersion": authority.API, "source": source, "runtimePolicy": fragment,
        "historyOriginals": {role: raw.decode("ascii") for role, raw in histories.items()},
        "coordinatorPeerPreparationOriginal": text(peer_preparation), "expectedPeer": peer}
    delivery_inputs, deliveries, activations = {}, {}, {}
    for index, role in enumerate(initial.ROLES):
        cold, wrapper = f["cold"][role], f["rows"][role]["wrapper"]
        activation = [{"name": "listener", "fd": 6, "device": 10, "inode": 10000 + index,
            "mode": stat.S_IFSOCK | 0o777, "uid": 0, "gid": 0}]
        for name in initial.DIRECTORIES[role]:
            ident = wrapper["initialState"]["directories"][name]["identity"]
            activation.append({"name": name, "fd": 6 + len(activation), "device": os.makedev(ident["deviceMajor"], ident["deviceMinor"]),
                **{field: ident[field] for field in ("inode", "mode", "uid", "gid")}})
        activation.append({"name": "publication-genesis-grant", "fd": 6 + len(activation), "device": 11,
            "inode": 11000 + index, "mode": stat.S_IFREG | 0o600, "uid": cold["uid"], "gid": cold["gid"]})
        credentials = copy.deepcopy(rows[role]["credentials"])
        for name, raw in ((recipe.HISTORY_NAME, histories[role]), (recipe.INSPECTION_NAME, runtime.inspection_original(role, runtimes[role], cold, window))):
            credentials.append({"name": name, "original": {"path": "/approved/synthetic/" + role + "/" + name, "sha256": p.sha(raw)}, "length": len(raw), "signing": None})
        payload = {"configurationSha256": p.sha(g.canonical(cold)), "authorityKeyId": cold["authority"]["keyId"],
            "serviceRole": role, "uid": cold["uid"], "gid": cold["gid"],
            **{name: window[name] for name in initial_tests.authority.parent.WINDOW_FIELDS[2:]},
            "runtimeConfig": {"path": "/approved/synthetic/" + role + "/runtime", "sha256": p.sha(runtimes[role])},
            "credentials": credentials, "activation": activation}
        delivery_inputs[role] = {**common, "operation": "delivery", "serviceRole": role, "payloadOriginal": text(payload), "activation": activation}
        deliveries[role] = g.canonical({"apiVersion": "serverware.policyCustodyGuestDelivery/v1", "payload": payload,
            "signatureBase64url": p.encoded(keys[role].sign(b"serverware.policyCustodyGuestDelivery.signature/v1\0" + g.canonical(payload)))})
        activations[role] = activation
    items = {role: authority.verify_delivery(signed_raw=deliveries[role], configuration_raw=g.canonical(f["cold"][role]), runtime_raw=runtimes[role],
        history_raw=histories[role], activation=activations[role], **kw) for role in initial.ROLES}
    cold_input = binding_tests.fixture()
    cold_input["window"].update({name: window[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")})
    cold_input["window"].update(issuedAtBoottimeNanos=int(window["issuedAtBoottimeNs"]), expiresAtBoottimeNanos=9_000_000_000)
    cold_raw = g.canonical(cold_input)
    scope = g.document(binding.result_document(binding.prepare(cold_raw, expected_input_sha256=p.sha(cold_raw), **kw,
        now_unix_ns=NOW))["genesisScopeOriginal"].encode("ascii"), 16384)
    trust = g.document(cold_input["trustOriginal"].encode("ascii"), 1024 * 1024)
    supervisor, supervisor_public = key_fixture("custody-supervisor-capability")
    native_public = key_fixture("custody-publication-reconciliation")[1]
    retrieval_public = key_fixture("custody-retrieval-response")[1]
    guests = []
    for index in range(2):
        guest = copy.deepcopy(items[initial.ROLES[0]]["guest"])
        guest.update(serviceRole="production-bridge", uid=62001 + index, gid=62101 + index,
            configurationSha256=labelled("native-config-" + str(index)), deliverySha256=labelled("native-delivery-" + str(index)),
            runtimeConfigurationSha256=labelled("native-runtime-" + str(index)))
        guests.append(guest)
    def authorization(guest):
        return {"guest": guest, "assignmentPayloadSha256": scope["assignmentPayloadSha256"], "keyAuthorizationSha256": labelled("native-key-authorization"),
            "trustCheckpointId": trust["checkpoint"]["checkpointId"], "revocationGeneration": trust["checkpoint"]["revocationGeneration"],
            "revocationRootSha256": trust["checkpoint"]["revocationRootSha256"], "issuedAtUnixNanos": NOW - 100,
            "expiresAtUnixNanos": NOW + 10_000_000_000, "signingKeyId": supervisor_public["keyId"],
            "signingKeySpkiSha256": supervisor_public["keySpkiSha256"]}
    native_common = {"scope": scope, "expectedPeer": peer,
        **{name: {"epoch": reference(items[role]["history"]), "publicKeyBase64url": p.encoded(raw_public(f["rows"][role]["keys"]["service"]))}
            for name, role in (("durableAuthority", initial.ROLES[0]), ("currentAuthority", initial.ROLES[1]))}}
    native_payload = {**native_common, "apiVersion": "serverware.nativePublicationGenesisAssignment/v1", "purpose": "native-policy-publication-genesis",
        "authorization": authorization(guests[0]), "retrieval": {name: retrieval_public[name] for name in ("keyId", "keySpkiSha256", "publicKeyBase64url")}, "retrievalGuest": guests[1]}
    native_raw = native_signed("nativePublicationGenesisAssignment", native_payload, supervisor)
    role_key = {"role": "custody-publication-reconciliation", **{name: native_public[name] for name in ("keyId", "keySpkiSha256", "publicKeyBase64url")}, "grantSha256": p.sha(native_raw)}
    retrieval_payload = {**native_common, "apiVersion": "serverware.nativePublicationGenesisRetrievalGrant/v1", "purpose": "native-policy-publication-genesis-retrieval",
        "authorization": authorization(guests[1]), "native": role_key,
        "store": {"genesisSha256": labelled("approved-empty-store-head"), "sequence": 0, "headSha256": labelled("approved-empty-store-head")}}
    retrieval_raw = native_signed("nativePublicationGenesisRetrievalGrant", retrieval_payload, supervisor)
    grants = {role: {**common, "operation": "grant", "serviceRole": role, "deliveryOriginals": {name: raw.decode("ascii") for name, raw in deliveries.items()},
        "activation": activations, "coldBindingInputOriginal": cold_raw.decode("ascii"), "coldBindingInputSha256": p.sha(cold_raw),
        "nativePublicationOriginal": native_raw.decode("ascii"), "nativeRetrievalOriginal": retrieval_raw.decode("ascii"),
        "initialTransitionHeadSha256": labelled("independently-approved-transition-head-" + role)} for role in initial.ROLES}
    return dict(f=f, kw={**kw, "now_unix_ns": NOW}, build_args=build_args, runtimes=runtimes, delivery_inputs=delivery_inputs,
        deliveries=deliveries, grants=grants, items=items, native_key=supervisor)


class ColdOrdinaryRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.f = fixture()

    def refused(self, operation, value, **kw):
        with self.assertRaises((ValueError, InvalidSignature, KeyError, TypeError)):
            authority.prepare_input(operation, g.canonical(value), **(kw or self.f["kw"]))

    def test_two_complete_cold_runtimes_from_signed_initial_histories(self):
        for role, raw in self.f["runtimes"].items():
            value = runtime.validate_runtime(role, raw); header = value["runtime"]
            self.assertEqual(header["apiVersion"], initial.RUNTIME_API)
            self.assertEqual(header["publicationGenesisAdmission"], {"grantFdName": "publication-genesis-grant"})
            self.assertEqual(header["listenerSocketPath"], runtime.listener(role))
            self.assertEqual(set(header["activationDirectoryIdentities"]), set(initial.DIRECTORIES[role]))
            self.assertFalse({"generationAdmission", "dispatchAdmission", "spoolHead", "spoolCurrent", "publicationAdmission"} & set(header))
        csa = g.document(self.f["runtimes"][initial.ROLES[1]], g.MAX_BYTES)
        self.assertEqual(csa["currentSubjects"][0]["pin"]["declaredSocketPath"], runtime.listener(initial.ROLES[0]))

    def test_two_independently_signed_c9_originals_and_exact_results(self):
        for role in initial.ROLES:
            raw = self.f["deliveries"][role]
            prepared = authority.prepare_input("delivery", g.canonical(self.f["delivery_inputs"][role]), **self.f["kw"])
            self.assertEqual(prepared["deadline"], 5_000_000_000)
            self.assertIsNone(prepared["epochLimit"])
            self.assertEqual(authority.checked_result("delivery", g.canonical(self.f["delivery_inputs"][role]),
                {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **self.f["kw"]), raw)

    def test_two_root_grants_bind_real_synthetic_native_signatures_and_epochs(self):
        for role in initial.ROLES:
            source = self.f["grants"][role]
            prepared = authority.prepare_input("grant", g.canonical(source), **self.f["kw"])
            payload = prepared["payload"]
            self.assertEqual(payload["guest"], self.f["items"][role]["guest"])
            self.assertEqual(payload["native"]["grantSha256"], p.sha(source["nativePublicationOriginal"].encode("ascii")))
            self.assertEqual(payload["retrieval"]["grantSha256"], p.sha(source["nativeRetrievalOriginal"].encode("ascii")))
            self.assertEqual(prepared["epochLimit"], NOW + 10_000_000_000)
            raw = signed_grant(payload, self.f["f"]["rows"][role]["keys"]["root"])
            self.assertEqual(authority.verify_grant(raw, item=self.f["items"][role]), raw)
            self.assertEqual(authority.checked_result("grant", g.canonical(source), {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **self.f["kw"]), raw)
            self.assertNotIn("generationScope", payload)

    def test_closed_policy_runtime_and_hot_cross_versions_refuse(self):
        role = initial.ROLES[0]
        for mutate in (lambda v: v.update(apiVersion=recipe.API), lambda v: v["services"].update({"bounded-cleanup-helper": {}})):
            value = copy.deepcopy(self.f["build_args"]["fragment"]); mutate(value)
            with self.assertRaises(ValueError): runtime.validate_policy(value)
        for mutate in (lambda v: v["runtime"].update(apiVersion="serverware.policyCustodyServiceRuntimeConfig/v8"),
                lambda v: v["runtime"].update(generationAdmission=None), lambda v: v["runtime"].update(publicationAdmission={"grantFdName": "publication-grant"}),
                lambda v: v["runtime"].update(listenerSocketPath="/run/serverware-custody-business/" + role + "/listener.sock")):
            value = g.document(self.f["runtimes"][role], g.MAX_BYTES); mutate(value)
            with self.assertRaises(ValueError): runtime.validate_runtime(role, g.canonical(value))

    def test_changed_sources_history_and_actual_peer_associations_refuse(self):
        base = self.f["delivery_inputs"][initial.ROLES[0]]
        for field in ("preparationOriginal", "resourcesOriginal", "parentObservationOriginal"):
            value = copy.deepcopy(base); parsed = g.document(value["source"][field].encode("ascii"), 65536)
            if field == "parentObservationOriginal": parsed["processId"] += 1
            elif field == "resourcesOriginal": parsed["services"][initial.ROLES[0]]["directories"]["journal"]["entryCount"] = 1
            else: parsed["services"][initial.ROLES[0]]["startTimeTicks"] += 1
            value["source"][field] = text(parsed); self.refused("delivery", value)
        value = copy.deepcopy(base); value["expectedPeer"]["pid"] += 1; self.refused("delivery", value)
        value = copy.deepcopy(base); value["historyOriginals"][initial.ROLES[0]] = value["historyOriginals"][initial.ROLES[1]]; self.refused("delivery", value)

    def test_c9_activation_credential_runtime_and_signature_substitutions_refuse(self):
        role = initial.ROLES[0]; base = self.f["delivery_inputs"][role]
        for mutate in (lambda v: v["runtimeConfig"].update(sha256=labelled("wrong-runtime")),
                lambda v: v["credentials"][-1].update(length=1), lambda v: v["activation"][-1].update(name="generation-grant"),
                lambda v: v.update(invocationId="b" * 32)):
            value = copy.deepcopy(base); payload = g.document(value["payloadOriginal"].encode("ascii"), 65536)
            mutate(payload); value["payloadOriginal"] = text(payload); self.refused("delivery", value)
        raw = self.f["deliveries"][role]; signed = g.document(raw, 65536); signed["signatureBase64url"] = p.encoded(b"x" * 64)
        bad = g.canonical(signed)
        with self.assertRaises(InvalidSignature): authority.checked_result("delivery", g.canonical(base), {"original": bad.decode("ascii"), "sha256": p.sha(bad)}, **self.f["kw"])

    def test_grant_native_domain_signature_scope_peer_and_pin_refusals(self):
        base = self.f["grants"][initial.ROLES[0]]
        for field in ("nativePublicationOriginal", "nativeRetrievalOriginal"):
            value = copy.deepcopy(base); signed = g.document(value[field].encode("ascii"), g.MAX_BYTES)
            signed["signature"] = p.encoded(b"x" * 64); value[field] = text(signed); self.refused("grant", value)
        for mutate in (lambda payload: payload["scope"].update(commissioningIdSha256=labelled("other-scope")),
                lambda payload: payload["expectedPeer"].update(pid=9999),
                lambda payload: payload.update(apiVersion="serverware.nativePublicationServiceAssignment/v1")):
            value = copy.deepcopy(base); signed = g.document(value["nativePublicationOriginal"].encode("ascii"), g.MAX_BYTES)
            mutate(signed["payload"])
            value["nativePublicationOriginal"] = native_signed("nativePublicationGenesisAssignment", signed["payload"], self.f["native_key"]).decode("ascii")
            self.refused("grant", value)
        value = copy.deepcopy(base); value["coldBindingInputSha256"] = labelled("unapproved-binding-input"); self.refused("grant", value)

    def test_original_clock_bounds_no_renewal_and_u64_guest_grammar(self):
        for operation, source in (("delivery", self.f["delivery_inputs"]), ("grant", self.f["grants"])):
            for change in ({"now_boottime_ns": 5_000_000_000}, {"boot": (p.encoded(b"x" * 16), 7, 8)}):
                self.refused(operation, source[initial.ROLES[0]], **{**self.f["kw"], **change})
        self.refused("grant", self.f["grants"][initial.ROLES[0]], **{**self.f["kw"], "now_unix_ns": NOW + 10_000_000_000})
        guest = copy.deepcopy(self.f["items"][initial.ROLES[0]]["guest"])
        guest.update(timeNamespaceDevice=(1 << 63) + 1, timeNamespaceInode=(1 << 63) + 2)
        self.assertEqual(authority._guest(g.document(g.canonical(guest), 65536)), guest)


if __name__ == "__main__": unittest.main()
