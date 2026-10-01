#!/usr/bin/env python3
"""Pure synthetic C3 wire controls, never authority or runtime evidence.

All identities, measurements, timestamps and signature-shaped bytes are
explicitly synthetic. No signing function, kernel observer, live owner, CLI,
protected file or service is exercised. Expected bytes use the published Rust
framing directly, never the helper under test. The full coordinator stays held.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import native_pilot_ordinary_key_profile as profile
from serverware import native_pilot_supervisor as supervisor

ROLES = ("durable-recovery-store", "cleanup-authorization-consumer", "recovery-target-provider",
    "current-signature-authority", "bounded-cleanup-helper")
PROCESS_DOMAIN = b"serverware.policyCustodyEndpointProcessIdentity/v3"
PIDFD_DOMAIN = b"serverware.policyCustodyPidfdStatIdentity/v3"
KEY_DOMAIN = b"serverware.policyCustodyCurrentKeyAuthorization/v3"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def labelled(name):
    return sha(("SYNTHETIC ORDINARY WIRE ONLY / " + name).encode("ascii"))


def encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def framed(domain, parts):
    return sha(domain + b"\0" + b"".join(struct.pack(">Q", len(part)) + part for part in parts))


def stat_fixture(index=0):
    value = {"device": 14, "inode": 61001 + index, "mode": 0o600, "uid": 0, "gid": 0}
    value["sha256"] = framed(PIDFD_DOMAIN, (struct.pack(">Q", value["device"]),
        struct.pack(">Q", value["inode"]), struct.pack(">I", value["mode"]),
        struct.pack(">I", value["uid"]), struct.pack(">I", value["gid"])))
    return value


def identity_fixture():
    """New synthetic identity14; not measured, signed, or a real process."""
    values = ["settlement-store", 31001, 32001, 41001, 51001, 61001, stat_fixture()["sha256"],
        71, 81001, 4096, labelled("executable-0"), labelled("ima-0"), labelled("verity-0")]
    names = ("endpointRole", "endpointUid", "endpointGid", "endpointPid", "endpointStartTimeTicks",
        "endpointPidfdInode", "endpointPidfdStatSha256", "executableDevice", "executableInode",
        "executableLength", "executableSha256", "executableImaSha256", "executableFsVeritySha256")
    return {**dict(zip(names, values)), "identitySha256": framed(PROCESS_DOMAIN, (canonical(values),))}


def preparation_fixture():
    """Synthetic closed originals; no key generation or signature operation."""
    cold, services, rows = {}, {}, {}
    for index, role in enumerate(ROLES):
        public = hashlib.sha256(("SYNTHETIC PUBLIC BYTES / " + role).encode("ascii")).digest()
        cold[role] = {"apiVersion": "serverware.policyCustodyGuestConfiguration/v1", "serviceRole": role,
            "uid": 31001 + index, "gid": 32001 + index,
            "authority": {"publicKeyBase64url": encoded(public), "keyId": sha(public)}}
        cold_sha = sha(canonical(cold[role]))
        services[role] = {"executableSha256": labelled("executable-" + str(index)),
            "deliveryConfiguration": {"path": "/etc/serverware/custody-" + role + "-configuration.json",
                "sha256": cold_sha}}
        rows[role] = {"configurationSha256": cold_sha, "plannedUid": 31001 + index,
            "plannedGid": 32001 + index, "processId": 41001 + index, "startTimeTicks": 51001 + index,
            "pidfdStat": stat_fixture(index), "targetExecutable": {"device": 71, "inode": 81001 + index,
                "length": 4096, "sha256": labelled("executable-" + str(index)),
                "imaSha256": labelled("ima-" + str(index)), "fsVeritySha256": labelled("verity-" + str(index))}}
    common = {"bootIdBase64url": encoded(bytes(range(1, 17))), "timeNamespaceDevice": 11,
        "timeNamespaceInode": 12, "startupDeadlineBoottimeNs": "5000", "lifetimeDeadlineBoottimeNs": "9000",
        "invocationId": "123456789abcdef0123456789abcdef0"}
    launch = {"apiVersion": "serverware.custodyFiveServiceLaunch/v6", **common, "services": services}
    window = {**common, "configurationSha256": labelled("driver-configuration"),
        "signingKeyId": labelled("driver-window-key"), "issuedAtBoottimeNs": "1000"}
    observation = {"apiVersion": "serverware.custodyFiveServicePreparation/v1", "phase": "parked-pre-exec",
        **common, "configurationSha256": sha(canonical(launch)), "issuedAtBoottimeNs": "1100", "services": rows}
    return observation, launch, cold, window, 1200


def payload_fixture():
    domain = {"authorityBootId": list(range(1, 17)), "timeNamespaceDevice": 11, "timeNamespaceInode": 12}
    return {"apiVersion": "serverware.policyCustodyCurrentKeyAuthorization/v3", "endpointRole": "settlement-store",
        "endpointProcessIdentitySha256": identity_fixture()["identitySha256"], "exactEndpointGeneration": 2,
        "authorizedSigningKeyId": labelled("service-key-id"), "authorizedSigningKeySpkiSha256": labelled("service-spki"),
        "checkpointSequence": 3, "predecessorCheckpointSha256": labelled("prior-checkpoint"),
        "revocationGenerationHighWater": 1, "revocationRootSha256": labelled("revocation"),
        "revocationStatus": "authorized-and-not-revoked", "rollbackFloorCheckpointSequence": 1,
        "rollbackFloorEndpointGeneration": 1, "rollbackFloorConsumerSequence": 1,
        "validFromBoottime": {"domain": copy.deepcopy(domain), "absoluteBoottimeNanos": 1100},
        "validUntilBoottime": {"domain": copy.deepcopy(domain), "absoluteBoottimeNanos": 8000}}


class OrdinaryKeyProfileTests(unittest.TestCase):
    def bind(self, observation, launch, cold, window, now, *, role=ROLES[0], endpoint_role="settlement-store"):
        return profile.prepared_identity(observation, role=role, endpoint_role=endpoint_role,
            launch=launch, configuration=cold[role], window=window, now=now)

    def test_pidfd_stat_matches_independent_binary_frames(self):
        value = stat_fixture()
        raw = {name: value[name] for name in ("device", "inode", "mode", "uid", "gid")}
        self.assertEqual(profile.pidfd_stat_sha256(raw), value["sha256"])
        self.assertNotEqual(value["sha256"], framed(PIDFD_DOMAIN, (canonical(raw),)))
        for field in raw:
            for invalid in (True, -1, 1 << (64 if field in ("device", "inode") else 32)):
                with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                    profile.pidfd_stat_sha256({**raw, field: invalid})

    def test_identity_matches_independent_ordered_tuple_and_refuses_mutation(self):
        value = identity_fixture()
        checked = profile.validate_identity(value)
        self.assertEqual(checked, value)
        checked["endpointPid"] += 1
        self.assertNotEqual(checked, value)
        for field, invalid in (("endpointPid", 0), ("endpointUid", True), ("endpointStartTimeTicks", 0),
                ("executableImaSha256", "sha256:" + "0" * 64), ("endpointRole", ROLES[0]),
                ("identitySha256", labelled("wrong-identity"))):
            with self.subTest(field=field), self.assertRaises(ValueError):
                profile.validate_identity({**value, field: invalid})
        with self.assertRaises(ValueError):
            profile.validate_identity({**value, "preExec": True})

    def test_checkpoint_uses_c3_signature_and_signature_text_digest_frames(self):
        payload = payload_fixture()
        authority_id, authority_spki = labelled("checkpoint-authority-id"), labelled("checkpoint-authority-spki")
        raw = canonical([payload, authority_id, authority_spki])
        expected = (b"serverware-signature-v1\0" + struct.pack(">Q", len(KEY_DOMAIN)) + KEY_DOMAIN
            + struct.pack(">Q", len(raw)) + raw)
        self.assertEqual(profile.signature_preimage(payload, authority_id, authority_spki), expected)
        # Encoding sentinel only: deliberately no valid signature or signer.
        signature_bytes = bytes(range(64))
        signature = encoded(signature_bytes)
        expected_digest = framed(KEY_DOMAIN, (raw, signature.encode("ascii")))
        value = profile.envelope(payload, authority_id, authority_spki, signature)
        self.assertEqual(value, {"payload": payload, "authorityKeyId": authority_id,
            "authorityKeySpkiSha256": authority_spki, "authoritySignatureBase64": signature,
            "checkpointSha256": expected_digest})
        self.assertNotEqual(expected_digest, framed(KEY_DOMAIN, (raw, signature_bytes)))
        for changed in ({**value, "checkpointSha256": labelled("wrong-checkpoint")},
                {**value, "authoritySignatureBase64": signature + "="}, {**value, "apiVersion": "unexpected"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                profile.validate_checkpoint(changed)

    def test_preparation_is_exact_canonical_and_not_an_exec_verdict(self):
        observation, *_ = preparation_fixture()
        raw = canonical(observation)
        self.assertEqual(profile.preparation(raw), observation)
        for bad_raw in (raw + b"\n", b" " + raw, raw[:-1] + b',"phase":"parked-pre-exec"}',
                canonical({**observation, "phase": "executed"}), canonical({**observation, "liveOwner": True})):
            with self.subTest(bad_raw=bad_raw[:100]), self.assertRaises(ValueError):
                profile.preparation(bad_raw)
        mutations = []
        missing = copy.deepcopy(observation); del missing["services"][ROLES[-1]]; mutations.append(missing)
        bad_hash = copy.deepcopy(observation)
        bad_hash["services"][ROLES[0]]["pidfdStat"]["sha256"] = labelled("wrong-stat"); mutations.append(bad_hash)
        duplicate = copy.deepcopy(observation)
        duplicate["services"][ROLES[1]]["processId"] = duplicate["services"][ROLES[0]]["processId"]
        mutations.append(duplicate)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(ValueError):
                profile.preparation(canonical(value))

    def test_prepared_identity_joins_all_originals_and_explicit_protocol_role(self):
        original = preparation_fixture()
        self.assertEqual(self.bind(*original), identity_fixture())
        alternate = self.bind(*original, role=ROLES[1], endpoint_role="termination-ledger")
        self.assertEqual(alternate["endpointRole"], "termination-ledger")
        with self.assertRaises(ValueError):
            self.bind(*original, endpoint_role="signer-hsm")
        observation, launch, cold, window, now = original
        with self.assertRaises(ValueError):
            profile.prepared_identity(observation, role="unknown", endpoint_role="settlement-store",
                launch=launch, configuration=cold[ROLES[0]], window=window, now=now)
        for target in ("cold", "executable", "plannedUid", "configurationSha256", "invocationId"):
            observation, launch, cold, window, now = copy.deepcopy(original)
            if target == "cold":
                cold[ROLES[0]]["uid"] += 10
            elif target == "executable":
                observation["services"][ROLES[-1]]["targetExecutable"]["sha256"] = labelled("changed-executable")
            elif target == "plannedUid":
                observation["services"][ROLES[0]][target] += 10
            elif target == "configurationSha256":
                observation[target] = labelled("changed-launch")
            else:
                window[target] = "9" * 32
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.bind(observation, launch, cold, window, now)

    def test_preparation_refuses_changed_domains_and_original_window(self):
        for field, invalid in (("bootIdBase64url", encoded(bytes(range(2, 18)))),
                ("timeNamespaceInode", 13), ("issuedAtBoottimeNs", "1201"),
                ("issuedAtBoottimeNs", "999"), ("startupDeadlineBoottimeNs", "5001"),
                ("lifetimeDeadlineBoottimeNs", "9001"), ("timeNamespaceDevice", True)):
            observation, launch, cold, window, now = preparation_fixture()
            observation[field] = invalid
            with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                self.bind(observation, launch, cold, window, now)
        observation, launch, cold, window, _ = preparation_fixture()
        for now in (True, 1099, 5000):
            with self.subTest(now=now), self.assertRaises(ValueError):
                self.bind(observation, launch, cold, window, now)

    def test_payload_refuses_shape_identity_domain_and_expiry_mismatches(self):
        _, _, _, window, now = preparation_fixture()
        payload = payload_fixture()
        self.assertEqual(profile.validate_payload(payload, identity=identity_fixture(), window=window, now=now), payload)
        mutations = [{**payload, field: invalid} for field, invalid in (
            ("apiVersion", "serverware.policyCustodyCurrentKeyAuthorization/v4"),
            ("endpointProcessIdentitySha256", labelled("wrong-process")), ("revocationStatus", "revoked"),
            ("checkpointSequence", True), ("rollbackFloorCheckpointSequence", 4),
            ("rollbackFloorEndpointGeneration", 3), ("validFromBoottime", None))]
        for field, number in (("validFromBoottime", 999), ("validFromBoottime", 1201),
                              ("validUntilBoottime", 1200), ("validUntilBoottime", 9001)):
            changed = copy.deepcopy(payload); changed[field]["absoluteBoottimeNanos"] = number; mutations.append(changed)
        changed = copy.deepcopy(payload); changed["validUntilBoottime"]["domain"]["timeNamespaceInode"] = 13
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                profile.validate_payload(changed, identity=identity_fixture(), window=window, now=now)

    def test_current_coverage_still_refuses_full_startup(self):
        self.assertEqual(len(supervisor.SUPPORTED_JOBS), 158)
        self.assertEqual(supervisor._ORDER[:158], supervisor.SUPPORTED_JOBS)
        self.assertEqual(len(supervisor._ORDER), 164)
        self.assertEqual(len(supervisor.missing_jobs()), 6)
        self.assertEqual(supervisor.missing_jobs()[0],
            ("release", "cohort-release"))
        with self.assertRaises(ValueError):
            supervisor.require_complete_coverage()


if __name__ == "__main__":
    unittest.main(verbosity=2)
