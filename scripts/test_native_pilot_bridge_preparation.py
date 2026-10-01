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


def fixture(*, fresh_helper=False, lifetime_boottime_ns=9_000_000):
    if fresh_helper:
        from test_native_pilot_helper_initial import fixture as helper_fixture, export as helper_export
        _, contexts, kw = helper_fixture(lifetime_boottime_ns=lifetime_boottime_ns)
    else:
        _, contexts, kw = request_fixture()
    selected = profile.requests_profile.select(contexts, **kw)
    requests = helper_export(selected, kw) if fresh_helper else export(selected, kw)
    driver_raw, cohort_raw = b'{"synthetic":"driver"}', b'{"synthetic":"cohort"}'
    value = dict(apiVersion=profile.HELPER_API if fresh_helper else profile.API, driverObservationSha256=p.sha(driver_raw),
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
    runtime = runtime_fixture(11 if fresh_helper else 10)
    runtime["expectedDriverProcessIdentitySha256"] = p.sha(b"SYNTHETIC admitted client process")
    runtime["expectedDriverConfigurationGenerationSha256"] = p.sha(b"SYNTHETIC admitted client configuration")
    runtime["expectedFacadePeer"] = expected(groups["gate"]["peers"]["gate"], ids["gate"]["gate"])
    runtime["expectedServiceConfigurationSha256"] = {}
    sessions = {}
    for role, _, row in profile.requests_profile.iter_requests(requests):
        pending = profile.head.request(row["requestOriginal"].encode("ascii"))
        statement = dict(apiVersion=profile.head.PROTOCOL_API, endpointRole=row["endpointRole"],
            requestNonceSha256=pending["requestNonceSha256"], requestSha256=row["requestSha256"],
            checkpointSequence=1, checkpointSha256=row["checkpointSha256"], endpointGeneration=1,
            revocationGenerationHighWater=1, revocationRootSha256=p.sha(b"SYNTHETIC revocation"),
            issuedAtBoottimeNanos=pending["requestedAtBoottimeNanos"], deadline=pending["deadline"])
        signed = profile.head.envelope(statement, p.sha(b"SYNTHETIC key ID"), p.sha(b"SYNTHETIC SPKI"), p.encoded(bytes(64)))
        handshake = profile.handshakes_profile.frame(service_role=role,
            trust_request_original=row["requestOriginal"].encode("ascii"), signed_current_head=signed,
            client_process_identity_sha256=runtime["expectedDriverProcessIdentitySha256"],
            client_configuration_generation_sha256=runtime["expectedDriverConfigurationGenerationSha256"])
        session = sessions.setdefault(role, dict(serviceRole=role,
            expectedPeer=expected(groups["ordinary-services"]["peers"][role], ids["ordinary-services"][role]), handshakes=[]))
        session["handshakes"].append(dict(endpointRole=row["endpointRole"], request=p.document(handshake, 65536)))
        runtime["ordinaryInitialHistories"][role]["runtimeOriginal"] = contexts[role]["runtimeOriginal"].decode("ascii")
        runtime["expectedServiceConfigurationSha256"][role] = row["runtimeConfigurationSha256"]
    runtime["serviceSessions"] = list(sessions.values())
    if fresh_helper:
        pending = [profile.head.request(row["requestOriginal"].encode("ascii"))
            for role, _, row in profile.requests_profile.iter_requests(requests) if role == "bounded-cleanup-helper"]
        deadline = copy.deepcopy(pending[0]["deadline"])
        deadline["absoluteBoottimeNanos"] = min(row["deadline"]["absoluteBoottimeNanos"] for row in pending)
        raw = profile.helper_bootstrap.build(contexts["bounded-cleanup-helper"]["runtimeOriginal"], deadline=deadline)
        runtime["helperBootstrap"] = p.document(raw, 65536)
        runtime["expectedHelperEndpointRoles"] = list(profile.helper_bootstrap.ROLES)
    for field, discriminator, mapping in (("parentSignerEndpoints", "signerRole", profile.NATIVE_SIGNERS),
            ("proofEndpoints", "endpointKind", profile.NATIVE_PROOFS)):
        runtime[field] = [{discriminator: name,
            "expectedPeer": expected(groups["native-endpoints"]["peers"][role], ids["native-endpoints"][role])}
            for name, role in mapping.items()]
    return value, runtime, dict(driver_observation_raw=driver_raw, cohort_observation_raw=cohort_raw, peer_ids=ids)


class BridgePreparationControls(unittest.TestCase):
    def test_v11_binds_all_eight_role_requests_and_exact_fresh_manifest(self):
        value, runtime, context = fixture(fresh_helper=True)
        self.assertEqual(sum(len(row["handshakes"]) for row in runtime["serviceSessions"]), 8)
        self.assertEqual(profile.require_runtime(p.canonical(value), p.canonical(runtime), **context), runtime)

    def test_v11_missing_duplicate_extra_or_reordered_helper_role_refuses(self):
        value, runtime, context = fixture(fresh_helper=True)
        for mutation in ("missing", "duplicate", "extra", "reordered"):
            changed = copy.deepcopy(runtime)
            helper = next(row for row in changed["serviceSessions"] if row["serviceRole"] == "bounded-cleanup-helper")
            if mutation == "missing": helper["handshakes"].pop()
            elif mutation == "duplicate": helper["handshakes"][1] = copy.deepcopy(helper["handshakes"][0])
            elif mutation == "reordered": helper["handshakes"].reverse()
            else: helper["handshakes"].append(copy.deepcopy(helper["handshakes"][0]))
            with self.assertRaises(ValueError): profile.require_runtime(p.canonical(value), p.canonical(changed), **context)

    def test_v11_manifest_rehash_does_not_authorize_another_runtime_or_deadline(self):
        value, runtime, context = fixture(fresh_helper=True)
        for name, replacement in (("serviceConfigurationSha256", p.sha(b"SYNTHETIC wrong helper")),
                ("deadline", dict(runtime["helperBootstrap"]["deadline"], absoluteBoottimeNanos=9999999))):
            changed = copy.deepcopy(runtime); manifest = changed["helperBootstrap"]
            manifest[name] = replacement
            manifest["manifestSha256"] = p.framed(profile.helper_bootstrap.DOMAIN,
                (p.canonical([manifest[field] for field in profile.helper_bootstrap.FIELDS[:-1]]),))
            with self.assertRaises(ValueError): profile.require_runtime(p.canonical(value), p.canonical(changed), **context)
        runtime["apiVersion"] = profile.runtime_profile.PREFIX + "10"
        del runtime["helperBootstrap"]
        with self.assertRaises(ValueError): profile.require_runtime(p.canonical(value), p.canonical(runtime), **context)

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
        request["requestSha256"] = p.framed(profile.handshakes_profile.DOMAIN,
            (p.canonical([request[name] for name in profile.handshakes_profile.FIELDS[:-1]]),))
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
