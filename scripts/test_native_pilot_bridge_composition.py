#!/usr/bin/env python3
"""Bounded SYNTHETIC bridge projection controls, not full build admission.

The ordinary C9/generation/history and eight current-head signatures are real
test signatures. Native/transition items passed directly to the production
builder's internal projection are explicitly synthetic prechecked data. There
is no complete authenticated native-eleven/transition-five positive transcript
here. No fake live owner, protected I/O, issuer, publication or service runs.
"""
from __future__ import annotations

import copy
from functools import lru_cache
import json
from pathlib import Path
import sys
import stat
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))

from serverware import native_pilot_bridge_runtime_policy as policy
from serverware import native_pilot_bridge_runtime_profile as profile
from serverware import native_pilot_peer_preparation as peers
from serverware import native_pilot_bridge_preparation as preparation
from serverware import native_pilot_service_authority as services
from serverware import native_pilot_supervisor_current_head_profile as current_heads
from serverware import native_shadow_driver_outgoing as outgoing
from test_native_pilot_current_head import WINDOW_DOMAIN
from test_native_pilot_current_head_intake import fixture as current_fixture
from test_native_pilot_endpoint_commissioning import peer as bridge_peer
from test_native_pilot_generation_scope import key_fixture
from test_native_pilot_peer_preparation import fixture as peer_fixture
from test_native_pilot_ordinary_keys import ROLES, canonical, encoded, labelled, sha

EXTERNAL = ("unavailable-ingress", "spool-compaction", "publication-reconciliation", "activation-publication")
EXPECTATION_FIELDS = ("securityLabelSha256", "configurationGenerationSha256")


def fragment():
    expectations = {group: {role: {name: labelled("SYNTHETIC final expectation/" + group + "/" + role + "/" + name)
        for name in EXPECTATION_FIELDS} for role in roles} for group, roles in peers.ROLES.items()}
    bindings = {}
    for role in sorted(outgoing._SIGNERS | set(outgoing._PROOFS)):
        public = key_fixture("SYNTHETIC bridge public authority/" + role)[1]
        bindings[role] = {"authorityBindingCredential": "bridge-authority-" + role,
            "authorityKeyId": public["keyId"], "authorityKeySpkiSha256": public["keySpkiSha256"]}
    external = {}
    for index, role in enumerate(EXTERNAL):
        peer = bridge_peer()
        peer.update(uid=51000 + index, gid=51000 + index)
        peer["processIdentitySha256"] = preparation.peer_identity({name: value for name, value in peer.items()
            if name != "processIdentitySha256"})
        external[role] = {"expectedSocketPath": "/run/synthetic-external-" + role + "/listener.sock",
            "expectedPeer": peer}
    return {"apiVersion": "serverware.nativePilotSupervisorBridgeRuntimePolicy/v1", "startupTimeoutMillis": 30000,
        "peerExpectations": expectations, "historyCredentials": {role: "bridge-history-" + role for role in ROLES},
        "authorityBindings": bindings, "externalSignerEndpoints": external}


@lru_cache(maxsize=1)
def _projection_fixture():
    """Real test signatures plus explicitly synthetic prechecked projection data."""
    f = current_fixture()
    args, boot, now = f["args"], f["clocks"]["boot"], f["clocks"]["now_boottime_ns"]
    launch, startup, lifetime = services._launch(args["launch_raw"], boot, now)
    ordinary = {role: services._service(row, role, launch, boot, startup, lifetime, now, granted=True)
        for role, row in args["ordinary_context"].items()}
    for item in ordinary.values():
        del item["root"]  # Cryptographic verifier already used; projection does not consume it.
    peer = ordinary[ROLES[0]]["header"]["expectedPeer"]
    config = json.loads(args["driver_configuration_raw"])
    public = key_fixture("SYNTHETIC bridge C9 authority")[1]
    cold = {"apiVersion": "serverware.policyCustodyGuestConfiguration/v1", "serviceRole": "production-bridge",
        "uid": peer["uid"], "gid": peer["gid"], "authority": {
            "publicKeyBase64url": public["publicKeyBase64url"],
            "keyId": sha(profile.p.decoded(public["publicKeyBase64url"], size=32))}}
    cold_raw = canonical(cold)
    config.update(uid=peer["uid"], gid=peer["gid"])
    config["deliveryConfiguration"]["sha256"] = sha(cold_raw)
    config["image"]["executableSha256"] = peer["executableSha256"]
    config_raw = canonical(config)
    signed_window = json.loads(args["driver_window_raw"])
    window = signed_window["payload"]
    window["configurationSha256"] = sha(config_raw)
    signed_window["signatureBase64url"] = encoded(key_fixture("window")[0].sign(WINDOW_DOMAIN + canonical(window)))
    window_raw = canonical(signed_window)
    args.update(driver_configuration_raw=config_raw, driver_window_raw=window_raw)
    heads = {}
    for job, raw in f["inputs"].items():
        value = json.loads(raw)
        value.update(driverConfigurationOriginal=config_raw.decode("ascii"), driverWindowOriginal=window_raw.decode("ascii"))
        heads[job] = {"inputOriginal": canonical(value), "headOriginal": f["outputs"][job]["original"].encode("ascii")}
    # Synthetic kernel/cohort observations are data, never real process owners.
    driver = {"driverInstanceSha256": labelled("SYNTHETIC bridge instance"),
        "driverExecutableSha256": peer["executableSha256"],
        "supervisorBootIdSha256": sha(profile.p.decoded(boot[0], size=16)),
        "processStartTimeTicks": peer["startTimeTicks"], "pidfdInode": 9001, "cgroupId": 9,
        "cgroupMountId": peer["cgroupMountId"], "cgroupInode": peer["cgroupInode"],
        "retainedDescriptorManifestSha256": labelled("SYNTHETIC retained descriptors"), "verifiedAtBoottimeNanos": 1200}
    driver["identitySha256"] = profile.p.framed(b"serverware.policyShadowCustodyKernelDriverIdentity/v1",
        (canonical(list(driver.values())),))
    observed = {"apiVersion": "serverware.nativeShadowDriverObservation/v1", "configurationSha256": sha(config_raw),
        "windowSha256": sha(window_raw), "invocationId": window["invocationId"], "processId": peer["pid"],
        "uid": peer["uid"], "gid": peer["gid"], "cgroupOriginalSha256": labelled("SYNTHETIC cgroup original"),
        "root": {"syntheticPrechecked": True}, "seccompFilterCount": 1, "descriptors": [], "driver": driver}
    observed_raw = canonical(observed)
    bridge = json.loads(args["bridge_preparation_raw"])
    groups = {kind: json.loads(bridge[field]) for field, kind in preparation.PEER_FIELDS}
    cohort = {"externalDriver": {"driver": {"processId": peer["pid"], "startTimeTicks": peer["startTimeTicks"]},
        "executable": {target: peer[source] for target, source in (("device", "executableDevice"),
            ("inode", "executableInode"), ("length", "executableLength"), ("sha256", "executableSha256"))}}}
    for role, row in groups["native-endpoints"]["peers"].items():
        cohort[role] = {"processId": row["processId"], "startTimeTicks": row["startTimeTicks"],
            "executable": copy.deepcopy(row["targetExecutable"])}
    cohort_raw = canonical(cohort)
    groups["native-endpoints"]["sourceOriginalSha256"] = sha(cohort_raw)
    gate_peer = groups["gate"]["peers"]["gate"]
    gate_peer["targetExecutable"]["sha256"] = config["lifecycle"]["gate"]["executableSha256"]
    gate = {"apiVersion": "serverware.nativeShadowDriverGateBound/v1", "configurationSha256": sha(config_raw),
        "windowSha256": sha(window_raw), "bootstrapObservationSha256": sha(observed_raw),
        "gateExecutableSha256": gate_peer["targetExecutable"]["sha256"], "binding": {
            "apiVersion": "serverware.nativeShadowDriverLifecycleBound/v1", "preparedSha256": labelled("SYNTHETIC gate preparation"),
            "gateProcessId": gate_peer["processId"], "gateStartTimeTicks": gate_peer["startTimeTicks"],
            "uid": 65534, "gid": 65534, "observedAtBoottimeNs": "1200"}}
    for field, kind in preparation.PEER_FIELDS:
        bridge[field] = canonical(groups[kind]).decode("ascii")
    bridge["driverObservationSha256"] = sha(observed_raw)
    args["bridge_preparation_raw"] = canonical(bridge)
    context = current_heads.prepare_context(**args)
    selected, native = fragment(), {}
    source_roles = {role: name for name, role in (preparation.NATIVE_SIGNERS | preparation.NATIVE_PROOFS).items()}
    for index, role in enumerate(peers.NATIVE_ROLES):
        public = key_fixture("SYNTHETIC bridge public authority/" + source_roles[role])[1]
        native[role] = {"guest": {"uid": 50000 + index, "gid": 50000 + index},
            "key": public | {"role": profile._KEY_ROLE[role]}, "expectedPeer": copy.deepcopy(peer)}
    control = {"apiVersion": "serverware.nativeShadowDriverBootstrapControl/v1",
        "supervisorExecutableSha256": labelled("SYNTHETIC supervisor executable"),
        "configurationSha256": sha(config_raw), "windowSha256": sha(window_raw)}
    return dict(fragment=selected, current_context=context, heads=heads, ordinary=ordinary, native=native,
        transition_originals={job: canonical({"syntheticPrecheckedTransition": job}) for job in profile.TRANSITION_JOBS},
        bootstrap_originals={"control": canonical(control), "configuration": config_raw, "window": window_raw,
            "deliveryConfiguration": cold_raw}, driver_observation_raw=observed_raw, cohort_observation_raw=cohort_raw,
        gate_binding_raw=canonical(gate), bridge_journal={"mountId": 17, "deviceMajor": 8, "deviceMinor": 1,
            "inode": 9100, "uid": peer["uid"], "gid": peer["gid"], "mode": stat.S_IFDIR | 0o700},
        boot=boot, now_boottime_ns=now)


def projection_fixture():
    return copy.deepcopy(_projection_fixture())


class BridgeCompositionControls(unittest.TestCase):
    def test_closed_static_policy_has_nineteen_distinct_public_credential_names(self):
        value = fragment()
        selected = policy.validate_policy(value)
        self.assertEqual(selected, value)
        self.assertEqual(set(selected), {"apiVersion", "startupTimeoutMillis", "peerExpectations",
            "historyCredentials", "authorityBindings", "externalSignerEndpoints"})
        self.assertEqual(set(selected["externalSignerEndpoints"]), set(EXTERNAL))
        self.assertEqual(set(selected["authorityBindings"]), outgoing._SIGNERS | set(outgoing._PROOFS))
        names = list(selected["historyCredentials"].values()) + [row["authorityBindingCredential"]
            for row in selected["authorityBindings"].values()]
        self.assertEqual((len(names), len(set(names))), (19, 19))
        selected["historyCredentials"][ROLES[0]] = "changed-copy"
        self.assertNotEqual(selected, value)
        for change in ("unknown", "missing-role", "extra-role", "duplicate-name", "legacy", "timeout"):
            bad = copy.deepcopy(value)
            if change == "unknown": bad["approvedFuturePeer"] = True
            elif change == "missing-role": bad["authorityBindings"].pop("unavailable-ingress")
            elif change == "extra-role": bad["externalSignerEndpoints"]["lineage-replay"] = copy.deepcopy(
                bad["externalSignerEndpoints"]["unavailable-ingress"])
            elif change == "duplicate-name": bad["authorityBindings"]["retrieval"]["authorityBindingCredential"] = bad["historyCredentials"][ROLES[0]]
            elif change == "legacy": bad["apiVersion"] = "serverware.nativePilotSupervisorBridgeRuntimePolicy/v0"
            else: bad["startupTimeoutMillis"] = 30001
            with self.subTest(change=change), self.assertRaises(ValueError): policy.validate_policy(bad)

    def test_peer_projection_uses_exact_observations_and_independent_final_expectations(self):
        observed = peer_fixture()["peers"][ROLES[0]]
        ids = {"uid": 42001, "gid": 42002}
        expectations = fragment()["peerExpectations"]["ordinary-services"][ROLES[0]]
        before = copy.deepcopy((observed, ids, expectations))
        selected = policy.build_peer(observed, ids, expectations)
        self.assertEqual(set(selected), set(outgoing._PEER_FIELDS))
        self.assertEqual(selected["pid"], observed["processId"])
        self.assertEqual(selected["startTimeTicks"], observed["startTimeTicks"])
        self.assertEqual(selected["executableSha256"], observed["targetExecutable"]["sha256"])
        self.assertEqual(selected["cgroupPathSha256"], observed["cgroup"]["pathSha256"])
        self.assertEqual({name: selected[name] for name in EXPECTATION_FIELDS}, expectations)
        self.assertEqual((observed, ids, expectations), before)
        fields = ("uid", "gid", "pid", "startTimeTicks", "executableDevice", "executableInode", "executableLength")
        parts = [selected[name].to_bytes(4 if index < 3 else 8, "big") for index, name in enumerate(fields)]
        parts.extend((bytes.fromhex(selected["executableSha256"][7:]), selected["cgroupPathSha256"].encode("ascii"),
            selected["cgroupMountId"].to_bytes(8, "big"), selected["cgroupInode"].to_bytes(8, "big"),
            selected["securityLabelSha256"].encode("ascii"), selected["configurationGenerationSha256"].encode("ascii")))
        from test_native_pilot_ordinary_keys import framed
        self.assertEqual(selected["processIdentitySha256"], framed(b"serverware.policyCustodyPeerProcessIdentity/v4", parts))
        for bad in (expectations | {"pid": 123}, {"securityLabelSha256": expectations["securityLabelSha256"]}):
            with self.assertRaises(ValueError): policy.build_peer(observed, ids, bad)
        for bad in (observed | {"uid": ids["uid"]}, observed | {"ready": True}):
            with self.assertRaises(ValueError): policy.build_peer(bad, ids, expectations)
        bad = fragment(); bad["externalSignerEndpoints"][EXTERNAL[0]]["expectedPeer"]["pid"] += 1
        with self.assertRaises(ValueError): policy.validate_policy(bad)

    def test_internal_projection_builds_complete_v11_runtime_and_actual_outgoing_inventory(self):
        args = projection_fixture()
        before = copy.deepcopy(args)
        bundle_raw = profile._project(**args)
        bundle = json.loads(bundle_raw)
        self.assertEqual(set(bundle), {"apiVersion", "driverControlSha256", "driverObservationOriginal",
            "runtimeOriginal", "outgoingOriginal"})
        runtime_raw = bundle["runtimeOriginal"].encode("ascii")
        runtime, other, native = outgoing._selection(runtime_raw, "serverware.nativeProofBridgeLaunch/v7", 1001)
        self.assertEqual(runtime["apiVersion"], "serverware.policyCustodyProductionRpcRuntime/v11")
        self.assertEqual((len(other), len(native)), (9, 10))
        self.assertEqual({name for name, _ in other}, set(profile.SERVICE_ACTIVATIONS.values())
            | {profile.SIGNER_ACTIVATIONS[role] for role in EXTERNAL})
        self.assertEqual(set(native), set(profile.PROOF_ACTIVATIONS.values())
            | {profile.SIGNER_ACTIVATIONS[role] for role in preparation.NATIVE_SIGNERS})
        self.assertEqual([row["serviceRole"] for row in runtime["serviceSessions"]], list(ROLES))
        self.assertEqual(sum(len(row["handshakes"]) for row in runtime["serviceSessions"]), 8)
        helper = runtime["serviceSessions"][-1]
        self.assertEqual([row["endpointRole"] for row in helper["handshakes"]], list(profile.helper.ROLES))
        self.assertEqual(runtime["helperBootstrap"]["deadline"], helper["handshakes"][0]["request"]["deadline"])
        selected = json.loads(bundle["outgoingOriginal"])
        self.assertEqual(selected["runtime"], {"path": profile.install.RUNTIME_DESTINATION, "sha256": sha(runtime_raw)})
        self.assertEqual(selected["bridgeLaunchVersion"], "serverware.nativeProofBridgeLaunch/v7")
        self.assertEqual(selected["driverObservationSha256"], sha(args["driver_observation_raw"]))
        self.assertEqual(bundle["driverControlSha256"], sha(args["bootstrap_originals"]["control"]))
        self.assertEqual(args, before)

    def test_projection_preserves_literal_originals_and_credential_digest_semantics(self):
        args = projection_fixture()
        runtime = json.loads(json.loads(profile._project(**args))["runtimeOriginal"])
        for role, item in args["ordinary"].items():
            self.assertEqual(runtime["ordinaryInitialHistories"][role], {
                "runtimeOriginal": item["runtime_raw"].decode("ascii"),
                "generationGrantOriginal": item["grant_raw"].decode("ascii")})
            self.assertEqual(runtime["generationAdmission"]["grants"][role], sha(item["grant_raw"]))
            self.assertEqual(runtime["expectedServiceConfigurationSha256"][role], sha(item["runtime_raw"]))
            service = json.loads(item["runtime_raw"])
            name = service["serviceSigningKeyCredential" if role == ROLES[3] else "signingKeyCredential"]
            credential = next(row for row in json.loads(item["delivery_raw"])["payload"]["credentials"] if row["name"] == name)
            self.assertEqual(runtime["expectedServiceSigningCredentialSha256"][role], credential["original"]["sha256"])
            history = next(row for row in runtime["histories"] if row["serviceRole"] == role)
            self.assertEqual(history["manifestSha256"], item["header"]["authorityHistoryManifestSha256"])
            self.assertNotEqual(history["manifestSha256"], sha(item["history_raw"]))
        for role in (ROLES[0], ROLES[3]):
            self.assertEqual(runtime["commitRequest"]["serviceGrantOriginals"][role],
                args["transition_originals"]["ordinary-dispatch-" + role].decode("ascii"))
        for field, job in (("headGrantOriginal", "ordinary-head"), ("cleanupGrantOriginal", "ordinary-cleanup"),
                ("currentGrantOriginal", "ordinary-current")):
            self.assertEqual(runtime["spool"][field], args["transition_originals"][job].decode("ascii"))

    def test_projection_refuses_substituted_authority_peer_journal_and_head(self):
        original = projection_fixture()
        for change in ("authority", "peer", "journal", "head", "transition-inventory"):
            bad = copy.deepcopy(original)
            if change == "authority":
                bad["fragment"]["authorityBindings"]["retrieval"]["authorityKeyId"] = labelled("wrong approved key")
            elif change == "peer":
                bad["native"]["retrieval"]["expectedPeer"]["pid"] += 1
            elif change == "journal":
                bad["bridge_journal"]["uid"] += 1
            elif change == "head":
                jobs = current_heads.JOB_NAMES
                bad["heads"][jobs[0]]["headOriginal"] = bad["heads"][jobs[1]]["headOriginal"]
            else:
                bad["transition_originals"].pop("ordinary-head")
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                profile._project(**bad)

    def test_same_call_head_core_has_exact_clock_boot_and_public_refresh_boundary(self):
        f = current_fixture()
        job = current_heads.JOB_NAMES[0]
        kw = dict(context=f["context"], **f["clocks"])
        actual = current_heads._prepared_input(job, f["inputs"][job], **kw)
        self.assertEqual(actual, current_heads.prepare_input(job, f["inputs"][job], **kw))
        for clock in (f["clocks"]["now_boottime_ns"] - 1, f["clocks"]["now_boottime_ns"] + 1):
            with self.assertRaises(ValueError):
                current_heads._prepared_input(job, f["inputs"][job], **(kw | {"now_boottime_ns": clock}))
        wrong_boot = (encoded(b"X" * 16), *f["clocks"]["boot"][1:])
        with self.assertRaises(ValueError):
            current_heads._prepared_input(job, f["inputs"][job], **(kw | {"boot": wrong_boot}))
        later = kw | {"now_boottime_ns": f["clocks"]["now_boottime_ns"] + 1}
        self.assertEqual(current_heads.prepare_input(job, f["inputs"][job], **later), actual)
        substituted = copy.deepcopy(f["context"])
        substituted["sources"]["ordinary_context"][ROLES[0]]["generationGrantOriginal"] = canonical({"notAGrant": True}).decode("ascii")
        with self.assertRaises(ValueError):
            current_heads.prepare_input(job, f["inputs"][job], **(later | {"context": substituted}))

    def test_complete_public_builder_does_not_accept_prechecked_projection_as_authority(self):
        args = projection_fixture()
        for name in ("ordinary", "native", "transition_originals"):
            args.pop(name)
        args.update(native_context={}, native_delivery_context={}, transition_context={}, now_unix_ns=1_000_000_000_000)
        with self.assertRaises(ValueError):
            profile.prepare(**args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
