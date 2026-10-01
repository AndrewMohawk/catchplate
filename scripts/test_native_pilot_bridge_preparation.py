#!/usr/bin/env python3
"""Synthetic public joins only; no acquisition, publisher or native admission.

Initial wrappers have test signatures. Peer values, ID policy, runtime member
grant signatures and head signatures are synthetic fixtures, not live evidence.
The runtime join does not verify a signing authority or run any protected owner.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_native_pilot_initial_requests import fixture as request_fixture, export
from test_native_pilot_peer_preparation import fixture as peer_fixture
from test_native_pilot_bridge_runtime import fixture as runtime_fixture
from serverware import native_pilot_bridge_preparation as profile
from serverware import native_pilot_driver_authority as driver

p = profile.p


def expected(observed, ids):
    value = dict(ids, pid=observed["processId"], startTimeTicks=observed["startTimeTicks"],
        executableDevice=observed["targetExecutable"]["device"], executableInode=observed["targetExecutable"]["inode"],
        executableLength=observed["targetExecutable"]["length"], executableSha256=observed["targetExecutable"]["sha256"],
        cgroupPathSha256=observed["cgroup"]["pathSha256"], cgroupMountId=observed["cgroup"]["mountId"],
        cgroupInode=observed["cgroup"]["inode"], securityLabelSha256=p.sha(b"SYNTHETIC approved label"),
        configurationGenerationSha256=p.sha(b"SYNTHETIC approved configuration generation"))
    parts = [value[name].to_bytes(width, "big") for name, width in (("uid", 4), ("gid", 4), ("pid", 4),
        ("startTimeTicks", 8), ("executableDevice", 8), ("executableInode", 8), ("executableLength", 8))]
    parts += [bytes.fromhex(value["executableSha256"].split(":")[1]), value["cgroupPathSha256"].encode(),
        value["cgroupMountId"].to_bytes(8, "big"), value["cgroupInode"].to_bytes(8, "big"),
        value["securityLabelSha256"].encode(), value["configurationGenerationSha256"].encode()]
    value["processIdentitySha256"] = p.framed(b"serverware.policyCustodyPeerProcessIdentity/v4", parts)
    return value


def fixture():
    _, contexts, kw = request_fixture()
    selected = profile.requests_profile.select(contexts, **kw)
    requests = export(selected, kw)
    driver_raw, cohort_raw = b'{"synthetic":"driver"}', b'{"synthetic":"cohort"}'
    value = dict(apiVersion=profile.API, driverObservationSha256=p.sha(driver_raw),
        initialTrustRequestsOriginal=p.canonical(requests).decode("ascii"))
    groups, ids = {}, {}
    for index, (field, kind) in enumerate(profile.PEER_FIELDS):
        peer = peer_fixture(kind)
        peer.update({field: kw["window"][field] for field in profile.WINDOW})
        peer["issuedAtBoottimeNs"] = kw["window"]["issuedAtBoottimeNs"]
        peer["observedAtBoottimeNs"] = str(kw["now_boottime_ns"])
        for row in peer["peers"].values():
            row["processId"] += index * 100
            row["pidfd"]["inode"] += index * 100
        ids[kind] = {role: dict(uid=30000 + index * 100 + number, gid=40000 + index * 100 + number)
            for number, role in enumerate(peer["peers"])}
        if kind == "ordinary-services": peer["sourceOriginalSha256"] = requests["launchSha256"]
        if kind == "native-endpoints": peer["sourceOriginalSha256"] = p.sha(cohort_raw)
        groups[kind] = peer
        value[field] = p.canonical(peer).decode("ascii")
    runtime = runtime_fixture()
    runtime["expectedFacadePeer"] = expected(groups["gate"]["peers"]["gate"], ids["gate"]["gate"])
    runtime["expectedServiceConfigurationSha256"] = {}
    runtime["serviceSessions"] = []
    for role, row in requests["requests"].items():
        pending = profile.head.request(row["requestOriginal"].encode("ascii"))
        statement = dict(apiVersion=profile.head.PROTOCOL_API, endpointRole=row["endpointRole"],
            requestNonceSha256=pending["requestNonceSha256"], requestSha256=row["requestSha256"],
            checkpointSequence=1, checkpointSha256=row["checkpointSha256"], endpointGeneration=1,
            revocationGenerationHighWater=1, revocationRootSha256=p.sha(b"SYNTHETIC revocation"),
            issuedAtBoottimeNanos=pending["requestedAtBoottimeNanos"], deadline=pending["deadline"])
        signed = profile.head.envelope(statement, p.sha(b"SYNTHETIC key ID"), p.sha(b"SYNTHETIC SPKI"), p.encoded(bytes(64)))
        runtime["serviceSessions"].append(dict(serviceRole=role,
            expectedPeer=expected(groups["ordinary-services"]["peers"][role], ids["ordinary-services"][role]),
            handshakes=[dict(endpointRole=row["endpointRole"], request=dict(deadline=pending["deadline"],
                expectedCurrentHead=profile.head.binding(signed)))]))
        runtime["ordinaryInitialHistories"][role]["runtimeOriginal"] = contexts[role]["runtimeOriginal"].decode("ascii")
        runtime["expectedServiceConfigurationSha256"][role] = row["runtimeConfigurationSha256"]
    for field, discriminator, mapping in (("parentSignerEndpoints", "signerRole", profile.NATIVE_SIGNERS),
            ("proofEndpoints", "endpointKind", profile.NATIVE_PROOFS)):
        runtime[field] = [{discriminator: name,
            "expectedPeer": expected(groups["native-endpoints"]["peers"][role], ids["native-endpoints"][role])}
            for name, role in mapping.items()]
    return value, runtime, dict(driver_observation_raw=driver_raw, cohort_observation_raw=cohort_raw, peer_ids=ids)


class BridgePreparationControls(unittest.TestCase):
    def test_closed_composite_and_all_owned_peer_request_joins(self):
        value, runtime, context = fixture()
        self.assertEqual(profile.shape(p.canonical(value)), value)
        self.assertEqual(profile.require_runtime(p.canonical(value), p.canonical(runtime), **context), runtime)

    def test_wrong_window_source_or_extra_field_refused(self):
        value, _, _ = fixture()
        for field in ("invocationId", "startupDeadlineBoottimeNs", "sourceOriginalSha256"):
            changed = copy.deepcopy(value)
            peers = profile.peers_profile.shape(changed["ordinaryPeerPreparationOriginal"].encode())
            peers[field] = p.sha(b"SYNTHETIC wrong source") if field == "sourceOriginalSha256" else "999999999"
            changed["ordinaryPeerPreparationOriginal"] = p.canonical(peers).decode()
            with self.assertRaises(ValueError): profile.shape(p.canonical(changed))
        value["extraApproval"] = True
        with self.assertRaises(ValueError): profile.shape(p.canonical(value))

    def test_ids_are_actual_prior_guest_values_not_self_hashed_substitutes(self):
        value, runtime, context = fixture()
        peer = runtime["serviceSessions"][0]["expectedPeer"]
        _, groups = profile._parts(value)
        role = runtime["serviceSessions"][0]["serviceRole"]
        peer.update(expected(groups["ordinary-services"]["peers"][role], dict(uid=55555, gid=55556)))
        with self.assertRaises(ValueError): profile.require_runtime(p.canonical(value), p.canonical(runtime), **context)

    def test_cgroup_executable_and_process_digest_drift_refuse(self):
        value, runtime, context = fixture()
        for name, changed_value in (("executableInode", 999999), ("cgroupInode", 999999),
                ("processIdentitySha256", p.sha(b"SYNTHETIC wrong v4 hash"))):
            changed = copy.deepcopy(runtime); changed["expectedFacadePeer"][name] = changed_value
            with self.assertRaises(ValueError): profile.require_runtime(p.canonical(value), p.canonical(changed), **context)

    def test_current_head_must_bind_exact_retained_request_not_handshake_digest(self):
        value, runtime, context = fixture()
        request = runtime["serviceSessions"][0]["handshakes"][0]["request"]
        signed = request["expectedCurrentHead"]["signedCurrentHead"]
        signed["statement"]["requestSha256"] = p.sha(b"SYNTHETIC unrelated handshake digest")
        signed = profile.head.envelope(signed["statement"], signed["authorityKeyId"], signed["authorityKeySpkiSha256"],
            signed["authoritySignatureBase64"])
        request["expectedCurrentHead"] = profile.head.binding(signed)
        with self.assertRaises(ValueError): profile.require_runtime(p.canonical(value), p.canonical(runtime), **context)

    def test_original_driver_cohort_and_ordinary_runtime_are_pinned(self):
        value, runtime, context = fixture()
        for field in ("driver_observation_raw", "cohort_observation_raw"):
            changed = dict(context, **{field: b'{"synthetic":"different"}'})
            with self.assertRaises(ValueError): profile.require_runtime(p.canonical(value), p.canonical(runtime), **changed)
        runtime["ordinaryInitialHistories"][next(iter(runtime["ordinaryInitialHistories"]))]["runtimeOriginal"] = '{"runtime":{}}'
        with self.assertRaises(ValueError): profile.require_runtime(p.canonical(value), p.canonical(runtime), **context)

    def test_constructed_bundle_reader_selects_v10_size_only(self):
        for version in (9, 10):
            runtime = runtime_fixture(version)
            runtime["expectedSharedConfigurationSha256"] = "SYNTHETIC padding " * 5000
            bundle = dict(runtimeOriginal=p.canonical(runtime).decode(), deliveryOriginal="{}", generationOriginals={})
            if version == 10:
                self.assertEqual(driver._phase_bundle(p.canonical(bundle).decode())[3], runtime)
            else:
                with self.assertRaises(ValueError): driver._phase_bundle(p.canonical(bundle).decode())

    def test_public_data_does_not_construct_or_claim_actual_owner(self):
        with self.assertRaises(ValueError): profile.BridgePreparation(None, {})
        with self.assertRaises(ValueError): profile.BridgePreparation.claim({})


if __name__ == "__main__":
    unittest.main()
