#!/usr/bin/env python3
"""Cold native public-issuer transcripts, not real owners or native acceptance.

Deterministic test signatures authenticate complete source-shaped inputs. The
process, file and persisted-store observations are explicitly synthetic; no
protected signer, kernel owner, store write, key import or native service runs.
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

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_endpoint_profile as endpoints
from catchplate import native_pilot_genesis_key_profile as key_profile
from catchplate import native_pilot_genesis_native_service_authority as authority
from catchplate import native_pilot_publication_cold_binding as binding
import test_native_pilot_genesis_key_authority as key_tests
import test_native_pilot_genesis_ordinary_runtime as ordinary_tests

p = g.p


def labelled(value):
    return p.sha(("SYNTHETIC NATIVE COLD ISSUER / " + value).encode("ascii"))


def independent_signed(operation, payload, key):
    domain = {"publication": b"catchplate.nativePublicationGenesisAssignment.signature/v1",
        "retrieval": b"catchplate.nativePublicationGenesisRetrievalGrant.signature/v1"}[operation]
    message = b"catchplate.signedEnvelope/v1\0" + domain + b"\0catchplate.canonicalJson/ascii-integer-v1\0" + g.canonical(payload)
    return g.canonical({"payload": payload, "signature": p.encoded(key.sign(message))})


def fixture():
    keys, ordinary = key_tests.fixture(), ordinary_tests.fixture()
    clocks = {field: keys[field] for field in ("boot", "now_boottime_ns", "now_unix_ns")}
    args = ordinary["build_args"]
    pairs = {role: key_profile.admitted_pair(role, *(keys["pairs"][role][name] for name in authority.PAIR_FIELDS), **clocks)
        for role in authority.ENDPOINTS}
    bound = binding.result_document(binding.prepare(keys["coldBindingInputOriginal"],
        expected_input_sha256=keys["coldBindingInputSha256"], **clocks))
    low = max(bound["issuedAtUnixNanos"], *(pair[field]["payload"]["issuedAtUnixNanos"]
        for pair in pairs.values() for field in ("authorization", "admissionAuthorization")))
    high = min(bound["expiresAtUnixNanos"], *(pair["epochLimit"] for pair in pairs.values()))
    value = {"apiVersion": authority.API, "operation": "publication",
        "coldBindingInputOriginal": keys["coldBindingInputOriginal"].decode("ascii"),
        "coldBindingInputSha256": keys["coldBindingInputSha256"],
        "ordinary": {"runtimePolicy": args["fragment"], "source": args["source"],
            "historyOriginals": {role: raw.decode("ascii") for role, raw in args["history_originals"].items()}},
        "coordinatorPeerPreparationOriginal": args["peer_preparation_raw"].decode("ascii"),
        "expectedPeer": args["approved_peer"],
        "endpointPairs": {role: {field: raw.decode("ascii") for field, raw in keys["pairs"][role].items()}
            for role in authority.ENDPOINTS},
        "window": {"issuedAtUnixNanos": low, "expiresAtUnixNanos": high}}
    prepared = authority.prepare_input("publication", g.canonical(value), **clocks)
    signed = independent_signed("publication", prepared["payload"], keys["supervisor_key"])
    scope = g.document(bound["genesisScopeOriginal"].encode("ascii"), 16384)
    source = pairs[authority.ENDPOINTS[1]]["source"]
    guest = pairs[authority.ENDPOINTS[1]]["expectedScope"]["guest"]
    resources_raw, delivery_raw = source["delivery"]["resources_raw"], source["deliveryOriginal"]
    resources = endpoints.resources(resources_raw)
    directory = resources["services"][authority.ENDPOINTS[1]]["directories"]["ledger-spool-store"]["identity"]
    proof_raw = scope["proofScopeOriginal"].encode("ascii")
    genesis_raw = g.canonical({"apiVersion": "catchplate.nativeLedgerSpoolStoreGenesis/v1", "guest": guest,
        "proofScopeSha256": p.sha(proof_raw)})
    store = {"apiVersion": endpoints.STORE_API, "resourcesSha256": p.sha(resources_raw), "deliverySha256": p.sha(delivery_raw),
        "proofScopeSha256": p.sha(proof_raw), "genesisOriginal": genesis_raw.decode("ascii"),
        "genesisFile": {"device": os.makedev(directory["deviceMajor"], directory["deviceMinor"]),
            "inode": 990001, "mode": stat.S_IFREG | 0o400, "uid": guest["uid"], "gid": guest["gid"],
            "length": len(genesis_raw), "sha256": p.sha(genesis_raw)},
        "store": {"genesisSha256": p.sha(genesis_raw), "sequence": 0, "headSha256": p.sha(genesis_raw)}}
    retrieval = {**value, "operation": "retrieval", "nativePublicationOriginal": signed.decode("ascii"),
        "retrievalStoreObservationOriginal": g.canonical(store).decode("ascii")}
    return dict(publication=value, retrieval=retrieval, publication_raw=signed, prepared=prepared,
        pairs=pairs, clocks=clocks, key=keys["supervisor_key"], store=store)


class GenesisNativeServiceAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = fixture()

    def prepare(self, operation, value=None, **clocks):
        return authority.prepare_input(operation, g.canonical(value or self.f[operation]), **(clocks or self.f["clocks"]))

    def refused(self, operation, value=None, **clocks):
        with self.assertRaises((ValueError, InvalidSignature, KeyError, TypeError)):
            self.prepare(operation, value, **clocks)

    def test_publication_first_authenticates_both_guest_pairs_and_real_history_epochs(self):
        payload = self.f["prepared"]["payload"]
        publication, retrieval = (self.f["pairs"][role] for role in authority.ENDPOINTS)
        self.assertEqual(payload["authorization"]["guest"], publication["expectedScope"]["guest"])
        self.assertEqual(payload["authorization"]["keyAuthorizationSha256"], publication["expectedScope"]["keyAuthorizationSha256"])
        self.assertEqual(payload["retrievalGuest"], retrieval["expectedScope"]["guest"])
        self.assertEqual(payload["retrieval"], {name: retrieval["expectedScope"]["localKeys"][0][name]
            for name in ("keyId", "keySpkiSha256", "publicKeyBase64url")})
        self.assertNotIn("grantSha256", payload["retrieval"])
        self.assertNotIn("native", payload)
        self.assertNotIn("generationScope", payload)
        for name, role in (("durableAuthority", "durable-recovery-store"), ("currentAuthority", "current-signature-authority")):
            wrapper = g.document(self.f["publication"]["ordinary"]["historyOriginals"][role].encode("ascii"), g.MAX_BYTES)
            self.assertEqual(payload[name]["epoch"], ordinary_tests.reference(wrapper["history"]))
        raw = self.f["publication_raw"]
        self.assertEqual(authority.checked_result("publication", g.canonical(self.f["publication"]),
            {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **self.f["clocks"]), raw)

    def test_retrieval_second_binds_exact_prior_signature_and_persisted_store_original(self):
        prepared = self.prepare("retrieval"); payload = prepared["payload"]
        self.assertEqual(payload["native"]["grantSha256"], p.sha(self.f["publication_raw"]))
        self.assertEqual(payload["native"]["role"], "custody-publication-reconciliation")
        self.assertEqual(payload["store"], self.f["store"]["store"])
        self.assertEqual(payload["store"]["genesisSha256"], p.sha(self.f["store"]["genesisOriginal"].encode("ascii")))
        self.assertEqual(payload["store"]["sequence"], 0)
        raw = independent_signed("retrieval", payload, self.f["key"])
        self.assertEqual(authority.checked_result("retrieval", g.canonical(self.f["retrieval"]),
            {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **self.f["clocks"]), raw)
        self.assertLessEqual(prepared["deadline"], self.f["prepared"]["deadline"])
        self.assertLessEqual(prepared["epochLimit"], self.f["prepared"]["epochLimit"])

    def test_closed_input_profiles_forbid_hot_selector_future_hash_and_unsigned_prior(self):
        for change in ({"apiVersion": "catchplate.nativePilotNativeServiceAuthorityInput/v1"},
                {"futureRetrievalGrantSha256": labelled("future-grant")}, {"operation": "persistence"}):
            self.refused("publication", {**self.f["publication"], **change})
        changed = copy.deepcopy(self.f["retrieval"]); del changed["nativePublicationOriginal"]
        self.refused("retrieval", changed)
        changed = copy.deepcopy(self.f["retrieval"])
        changed["nativePublicationOriginal"] = g.canonical(self.f["prepared"]["payload"]).decode("ascii")
        self.refused("retrieval", changed)

    def test_signature_domain_and_same_key_wrong_context_are_not_interchangeable(self):
        wrong = independent_signed("retrieval", self.f["prepared"]["payload"], self.f["key"])
        changed = {**self.f["retrieval"], "nativePublicationOriginal": wrong.decode("ascii")}
        self.refused("retrieval", changed)
        for mutate in (lambda payload: payload["scope"].update(commissioningIdSha256=labelled("other-ceremony")),
                lambda payload: payload["retrievalGuest"].update(deliverySha256=labelled("other-C9")),
                lambda payload: payload["authorization"].update(keyAuthorizationSha256=labelled("other-keys"))):
            payload = copy.deepcopy(self.f["prepared"]["payload"]); mutate(payload)
            raw = independent_signed("publication", payload, self.f["key"])
            self.refused("retrieval", {**self.f["retrieval"], "nativePublicationOriginal": raw.decode("ascii")})
        raw = self.f["publication_raw"]
        with self.assertRaises(ValueError):
            authority.checked_result("publication", g.canonical(self.f["publication"]),
                {"original": raw.decode("ascii"), "sha256": labelled("false-result-pin")}, **self.f["clocks"])

    def test_current_assignment_pair_role_peer_and_parent_source_substitutions_refuse(self):
        changed = copy.deepcopy(self.f["publication"]); changed["coldBindingInputSha256"] = labelled("unapproved-input")
        self.refused("publication", changed)
        changed = copy.deepcopy(self.f["publication"])
        first, second = authority.ENDPOINTS
        changed["endpointPairs"][first] = changed["endpointPairs"][second]
        self.refused("publication", changed)
        changed = copy.deepcopy(self.f["publication"]); changed["expectedPeer"]["pid"] += 1
        self.refused("publication", changed)
        changed = copy.deepcopy(self.f["publication"])
        source = changed["ordinary"]["source"]
        observation = g.document(source["parentObservationOriginal"].encode("ascii"), 32768)
        observation["processId"] += 1; source["parentObservationOriginal"] = g.canonical(observation).decode("ascii")
        self.refused("publication", changed)

    def test_authenticated_history_role_signature_and_full_scope_window_refusals(self):
        changed = copy.deepcopy(self.f["publication"])
        histories = changed["ordinary"]["historyOriginals"]
        histories["durable-recovery-store"] = histories["current-signature-authority"]
        self.refused("publication", changed)
        changed = copy.deepcopy(self.f["publication"])
        histories = changed["ordinary"]["historyOriginals"]
        wrapper = g.document(histories["durable-recovery-store"].encode("ascii"), g.MAX_BYTES)
        wrapper["history"]["firstRetainedEpoch"]["rootSignatureBase64"] = p.encoded(b"x" * 64)
        histories["durable-recovery-store"] = g.canonical(wrapper).decode("ascii")
        self.refused("publication", changed)
        changed = copy.deepcopy(self.f["publication"]); changed["window"]["expiresAtUnixNanos"] += 1
        self.refused("publication", changed)

    def test_store_observation_is_literal_and_sequence_zero_not_a_claimed_empty_state(self):
        for mutate in (lambda value: value["store"].update(sequence=1),
                lambda value: value["store"].update(genesisSha256=labelled("other-genesis"), headSha256=labelled("other-genesis")),
                lambda value: value["genesisFile"].update(mode=stat.S_IFREG | 0o600),
                lambda value: value.update(resourcesSha256=labelled("other-resources")),
                lambda value: value.update(deliverySha256=labelled("other-delivery")),
                lambda value: value.update(genesisOriginal="{}")):
            store = copy.deepcopy(self.f["store"]); mutate(store)
            self.refused("retrieval", {**self.f["retrieval"], "retrievalStoreObservationOriginal": g.canonical(store).decode("ascii")})

    def test_original_boot_and_wall_bounds_do_not_renew_at_signing_or_retrieval(self):
        clocks = self.f["clocks"]
        for operation in authority.OPERATIONS:
            self.refused(operation, **{**clocks, "now_boottime_ns": self.f["prepared"]["deadline"]})
            self.refused(operation, **{**clocks, "now_unix_ns": self.f["prepared"]["epochLimit"]})
            self.refused(operation, **{**clocks, "boot": (p.encoded(b"x" * 16), *clocks["boot"][1:])})
        changed = copy.deepcopy(self.f["retrieval"])
        changed["window"]["issuedAtUnixNanos"] = self.f["publication"]["window"]["issuedAtUnixNanos"] - 1
        self.refused("retrieval", changed)


if __name__ == "__main__":
    unittest.main()
