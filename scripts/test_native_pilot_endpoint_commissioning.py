#!/usr/bin/env python3
"""Focused public grammar checks, not commissioning or runtime evidence.

All values below are labelled synthetic wire inputs. No key is generated or
signature verified; no protected file, live owner, installer or signer is used.
The full-run guard must still refuse until the remaining composers exist.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.test_native_pilot_fresh_ledger import canonical, encoded, labelled, scope_original, sha
from serverware import native_pilot_assignment as assignment
from serverware import native_pilot_publication as publication
from serverware import native_pilot_publication_profiles as profiles
from serverware import native_pilot_supervisor as supervisor
from serverware import native_pilot_supervisor_endpoint_policy as endpoints
from serverware import native_pilot_supervisor_policy as policy
from serverware import native_shadow_retrieval_artifacts as retrieval


def fragment():
    return {"apiVersion": "serverware.nativePilotSupervisorEndpointPolicy/v2",
        "initialization": "fresh-ledger", "objectDirectory": "/var/lib/serverware/empty-retrieval",
        "peerExpectations": {name: labelled(name) for name in
            ("cgroupPathSha256", "securityLabelSha256", "configurationGenerationSha256")}}


def envelope(version=2):
    payload = dict.fromkeys(assignment.NATIVE_FIELDS, "SYNTHETIC SHAPE ONLY")
    payload.update(custodyAuthority={}, authorityKeyIndependence={})
    if version == 2:
        payload["nativeClosureSet"] = {"setRootSha256": labelled("set"), "seccompSetRootSha256": labelled("seccomp")}
    domain = "serverware.policyShadowAssignment/v" + str(version)
    return {"apiVersion": domain, "kind": "PolicyShadowAssignment", "signatureDomain": domain,
        "canonicalProfile": "serverware.canonicalJson/ascii-integer-v1", "signatureAlgorithm": "Ed25519",
        "payload": payload, "payloadSha256": sha(canonical(payload)), "signingKeyId": labelled("key-id"),
        "signingKeySpkiSha256": labelled("spki"), "signature": "A" * 86}  # Invalid zero sentinel only.


def peer():
    value = {name: 1 for name in retrieval.PEER_FIELDS}
    value.update(uid=1001, gid=1001, pid=2, startTimeTicks=3, executableDevice=4,
        executableInode=5, executableLength=6, cgroupMountId=7, cgroupInode=8)
    for name in ("executableSha256", "cgroupPathSha256", "securityLabelSha256", "configurationGenerationSha256"):
        value[name] = labelled(name)
    pieces = [value[name].to_bytes(4, "big") for name in ("uid", "gid", "pid")]
    pieces.extend(value[name].to_bytes(8, "big") for name in
        ("startTimeTicks", "executableDevice", "executableInode", "executableLength"))
    pieces.extend((bytes.fromhex(value["executableSha256"][7:]), value["cgroupPathSha256"].encode("ascii"),
        value["cgroupMountId"].to_bytes(8, "big"), value["cgroupInode"].to_bytes(8, "big"),
        value["securityLabelSha256"].encode("ascii"), value["configurationGenerationSha256"].encode("ascii")))
    value["processIdentitySha256"] = sha(b"serverware.policyCustodyPeerProcessIdentity/v4\0"
        + b"".join(len(piece).to_bytes(8, "big") + piece for piece in pieces))
    return value


class EndpointCommissioningGrammarTests(unittest.TestCase):
    def test_source_order_and_full_startup_refusal(self):
        expected = (("bootstrap-admission", "driver-bootstrap"),
            ("endpoint-precreation", "cohort-precreation"), ("endpoint-precreation", "install-precreation"),
            ("endpoint-inputs", "endpoint-inputs"), ("endpoint-deliveries", "native-delivery-retrieval"),
            ("endpoint-deliveries", "native-delivery-persistence"),
            ("endpoint-deliveries", "native-delivery-trustedTime"))
        self.assertEqual(supervisor.SUPPORTED_JOBS, expected)
        self.assertEqual(supervisor._ORDER[:7], expected)
        self.assertEqual(len(supervisor._ORDER), 60)
        self.assertEqual(len(supervisor.missing_jobs()), 53)
        self.assertEqual(supervisor.missing_jobs()[0],
            ("service-originals", "ordinary-delivery-durable-recovery-store"))
        with self.assertRaises(ValueError):
            supervisor.require_complete_coverage()

    def test_policy_versions_keep_distinct_field_sets(self):
        self.assertEqual((len(policy.FIELDS), len(policy.MEASURED_FIELDS), len(policy.ENDPOINT_FIELDS)), (8, 9, 11))
        self.assertEqual(set(policy.MEASURED_FIELDS) - set(policy.FIELDS), {"measuredRecipeSha256"})
        self.assertEqual(set(policy.ENDPOINT_FIELDS) - set(policy.MEASURED_FIELDS),
            {"endpointPreparation", "endpointDeliveries"})
        self.assertEqual(len({policy.POLICY_API, policy.MEASURED_POLICY_API, policy.ENDPOINT_POLICY_API}), 3)

    def test_static_fragment_is_explicit_and_copied(self):
        value = fragment()
        selected = endpoints.validate_policy(value)
        self.assertEqual(selected, value)
        selected["peerExpectations"]["cgroupPathSha256"] = labelled("changed")
        self.assertNotEqual(selected, value)
        self.assertEqual(set(value), {"apiVersion", "initialization", "objectDirectory", "peerExpectations"})

    def test_fragment_refuses_future_values_mixed_versions_and_missing_fields(self):
        values = []
        for name in ("production", "proofScopeOriginal", "retrievalManifestOriginal", "assignmentOriginal"):
            values.append({**fragment(), name: {}})
        for mode in (None, "", "historical", False):
            values.append({**fragment(), "initialization": mode})
        values.append({**fragment(), "apiVersion": "serverware.nativePilotSupervisorEndpointPolicy/v1"})
        for name in fragment():
            value = fragment()
            del value[name]
            values.append(value)
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                endpoints.validate_policy(value)

    def test_fragment_path_and_peer_bounds(self):
        for path in ("/", "/a", "/a/b", "var/lib/serverware", "/var//serverware/a", "/var/./serverware/a",
                     "/var/lib/../a", "/var/lib/a\0b", "/var/lib/" + "x" * 256, "/" + "/".join(["a"] * 33)):
            with self.subTest(path=path), self.assertRaises(ValueError):
                endpoints.validate_policy({**fragment(), "objectDirectory": path})
        for name in fragment()["peerExpectations"]:
            for digest in (None, "", "sha256:" + "0" * 64, sha(b"")):
                value = fragment()
                value["peerExpectations"][name] = digest
                with self.subTest(field=name, digest=digest), self.assertRaises(ValueError):
                    endpoints.validate_policy(value)

    def test_fixed_publication_slots_accept_only_their_wire_profiles(self):
        scope = scope_original(2)
        values = {"endpoint-peer": canonical(peer()), "endpoint-proof-scope": scope,
            "endpoint-retrieval-manifest": retrieval.fresh_ledger_manifest_original(scope),
            "endpoint-assignment": canonical(envelope())}
        for purpose, raw in values.items():
            with self.subTest(purpose=purpose):
                self.assertEqual(publication.DESTINATIONS[purpose],
                    "/etc/serverware/native-pilot-inputs/" + purpose + ".json")
                publication._shape(purpose, raw)
                with self.assertRaises(ValueError):
                    profiles.shape(purpose, raw + b"\n")
                with self.assertRaises(ValueError):
                    profiles.shape(purpose, b" " * (publication.LIMITS[purpose] + 1))
        self.assertEqual(tuple(publication.LIMITS[name] for name in values), (4096, 16384, 32768, 4194304))

    def test_endpoint_publication_refuses_legacy_scope_manifest_and_assignment(self):
        with self.assertRaises(ValueError):
            profiles.shape("endpoint-proof-scope", scope_original(1))
        value = {"apiVersion": "serverware.nativeShadowRetrievalStoreManifest/v1",
            "proofScopeOriginalBase64url": encoded(scope_original(2)), "objectOriginalsBase64url": []}
        with self.assertRaises(ValueError):
            profiles.shape("endpoint-retrieval-manifest", canonical(value))
        with self.assertRaises(ValueError):
            profiles.shape("endpoint-assignment", canonical(envelope(1)))
        wrong_peer = copy.deepcopy(peer())
        wrong_peer["pid"] += 1
        with self.assertRaises(ValueError):
            profiles.shape("endpoint-peer", canonical(wrong_peer))


if __name__ == "__main__":
    unittest.main(verbosity=2)
