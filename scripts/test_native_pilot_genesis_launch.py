#!/usr/bin/env python3
"""Signed synthetic cold launch chains; no owner, KMS, installation or admission.

Endpoint ciphertext/C9/pairs precede native grants, ordinary grants, and the
complete late coordinator C9/pair. Signatures are real test signatures; all
process/resource identities and opaque ciphertext remain synthetic evidence.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_closure_authority as closure
from catchplate import native_pilot_genesis_key_profile as keys
from catchplate import native_pilot_genesis_launch_profile as launch
from catchplate import native_pilot_genesis_native_service_authority as services
from catchplate import native_pilot_genesis_verifier_authority as verifier
import test_native_pilot_genesis_closure_authority as closure_tests
import test_native_pilot_genesis_coordinator_runtime as coordinator_tests
import test_native_pilot_genesis_key_authority as key_tests
import test_native_pilot_genesis_native_service_authority as native_tests
import test_native_pilot_genesis_ordinary_runtime as ordinary_tests
import test_native_pilot_genesis_transport_authority as transport_tests

p = g.p


def text(value): return g.canonical(value).decode("ascii")
def labelled(value): return p.sha(("SYNTHETIC COLD LAUNCH / " + value).encode("ascii"))


def _native_grants(base, rows, clocks):
    prior = native_tests.fixture()
    publication = copy.deepcopy(prior["publication"])
    publication.update(coldBindingInputOriginal=base["coldBindingInputOriginal"].decode("ascii"),
        coldBindingInputSha256=base["coldBindingInputSha256"], endpointPairs={role:
            {name: raw.decode("ascii") for name, raw in rows[role]["pair"].items()} for role in services.ENDPOINTS})
    prepared = services.prepare_input("publication", g.canonical(publication), **clocks)
    native_raw = native_tests.independent_signed("publication", prepared["payload"], base["supervisor_key"])
    row = rows["publicationGenesisRetrieval"]
    pair = keys.admitted_pair("publicationGenesisRetrieval", *(row["pair"][name] for name in launch.PAIR_FIELDS), **clocks)
    store = copy.deepcopy(prior["store"])
    genesis = g.document(store["genesisOriginal"].encode("ascii"), 65536)
    genesis["guest"] = pair["expectedScope"]["guest"]
    genesis_raw = g.canonical(genesis)
    store.update(deliverySha256=p.sha(row["delivery"]["raw"]), genesisOriginal=genesis_raw.decode("ascii"))
    store["genesisFile"].update(length=len(genesis_raw), sha256=p.sha(genesis_raw))
    store["store"].update(genesisSha256=p.sha(genesis_raw), headSha256=p.sha(genesis_raw))
    retrieval = {**publication, "operation": "retrieval", "nativePublicationOriginal": native_raw.decode("ascii"),
        "retrievalStoreObservationOriginal": text(store)}
    prepared = services.prepare_input("retrieval", g.canonical(retrieval), **clocks)
    retrieval_raw = native_tests.independent_signed("retrieval", prepared["payload"], base["supervisor_key"])
    return {name: {"inputOriginal": text(value), "grantOriginal": raw.decode("ascii")}
        for name, value, raw in (("publication", publication, native_raw), ("retrieval", retrieval, retrieval_raw))}


def _coordinator_runtime(base, rows, contexts, clocks):
    original = ordinary_tests.fixture()
    runtime = g.document(base["deliveries"][keys.ROLES[-1]]["runtime_raw"], g.MAX_BYTES)
    for role, field in zip(ordinary_tests.initial.ROLES, ("durableGrantOriginal", "currentGrantOriginal"), strict=True):
        value = copy.deepcopy(original["grants"][role])
        value.update(coldBindingInputOriginal=base["coldBindingInputOriginal"].decode("ascii"),
            coldBindingInputSha256=base["coldBindingInputSha256"],
            nativePublicationOriginal=contexts["publication"]["grantOriginal"],
            nativeRetrievalOriginal=contexts["retrieval"]["grantOriginal"])
        prepared = ordinary_tests.authority.prepare_input("grant", g.canonical(value), **clocks)
        runtime[field] = ordinary_tests.signed_grant(prepared["payload"], original["f"]["rows"][role]["keys"]["root"]).decode("ascii")
    for endpoint, role in zip(runtime["nativeEndpoints"], services.ENDPOINTS, strict=True):
        source = rows[role]["delivery"]
        observed = source["observed"]
        preparation = g.document(source["input"]["preparationOriginal"].encode("ascii"), 65536)
        cgroup = preparation["services"][role]["cgroup"]
        peer = endpoint["expectedPeer"]
        peer.update(uid=source["configuration"]["uid"], gid=source["configuration"]["gid"],
            pid=observed["processId"], startTimeTicks=observed["startTimeTicks"],
            **{"executable" + name[0].upper() + name[1:]: observed["executable"][name]
                for name in ("device", "inode", "length", "sha256")},
            cgroupPathSha256=cgroup["pathSha256"], cgroupMountId=cgroup["mountId"], cgroupInode=cgroup["inode"])
        coordinator_tests.rehash_peer(peer)
    return g.canonical(runtime)


def _input(base, role, row, contexts, clocks):
    first = keys.input_document(row["pair"]["roleKeyInputOriginal"])
    closure_input = {"apiVersion": closure.API, "role": role, **{name: first[name] for name in keys.SOURCE_FIELDS},
        "policy": {name: first["policy"][name] for name in ("issuedAtUnixNanos", "expiresAtUnixNanos")}}
    prepared = closure.prepare_input(role, p.canonical(closure_input), **clocks)
    closure_raw = closure_tests.independently_signed(prepared, base["supervisor_key"])
    source = row["delivery"]
    payload = g.document(source["raw"], 65536)["payload"]
    approved = g.document(base["coldBindingInputOriginal"], g.MAX_BYTES)
    role_authorization = g.document(row["pair"]["roleKeyOriginal"], keys.MAX_OUTPUT)
    clock = {"parentPort": 6000 + keys.ROLES.index(role), "maximumBracketNanos": "1000000",
        "timestampErrorNanos": 100, "maximumClockRateErrorPpm": 10}
    trust = g.document(approved["trustOriginal"].encode("ascii"), 1024 * 1024)
    public = {"deliveryConfiguration": g.canonical(source["configuration"]), "delivery": source["raw"],
        "runtime": source["runtime_raw"], "trust": approved["trustOriginal"].encode("ascii"),
        "timeBootstrap": g.canonical({"apiVersion": "catchplate.nativeShadowGuestTimeBootstrap/v1",
            "guest": role_authorization["payload"]["guest"], "signingKeyId": trust["timeKey"]["keyId"], **clock}),
        "assignment": approved["assignmentOriginal"].encode("ascii"), "closure": closure_raw,
        "keys": g.canonical({"apiVersion": "catchplate.nativeShadowRoleKeys/v2", "authorization": role_authorization}),
        "encryptedKeys": row["encrypted_raw"], "admission": row["pair"]["admissionOriginal"],
        "verifierTransport": row["verifier_raw"], "encryptedInventory": row["ciphertext_raw"]}
    operation = launch.SELECTORS[role][1]
    if operation: public["serviceGrant"] = contexts[operation]["grantOriginal"].encode("ascii")
    pins = {name: {"path": "/approved/synthetic/cold-launch/" + role + "/" + name + ".json", "sha256": p.sha(raw)}
        for name, raw in public.items()}
    if role == keys.ROLES[-1]:
        config = g.document(source["parentOriginals"]["parentConfigurationOriginal"].encode("ascii"), 65536)
        pins["deliveryConfiguration"] = config["deliveryConfiguration"]
    else:
        config = g.document(source["input"]["ownerConfigurationOriginal"].encode("ascii"), 32768)
        pins["deliveryConfiguration"] = config["services"][role]["deliveryConfiguration"]
    pins["runtime"] = payload["runtimeConfig"]
    pins["encryptedInventory"] = payload["credentials"][0]["original"]
    pins["verifierTransport"]["path"] = verifier.PATHS[role]
    # Independent literal native selector spelling: no producer build shortcut.
    api, field = {"publicationGenesisRetrieval": ("catchplate.nativeShadowPublicationGenesisRetrievalGuestLaunch/v1", "retrieval"),
        "publicationGenesis": ("catchplate.nativeShadowPublicationGenesisGuestLaunch/v1", "publication"),
        "publicationGenesisCoordinator": ("catchplate.nativeShadowPublicationGenesisCoordinatorGuestLaunch/v2", None)}[role]
    selected = {"apiVersion": api, "keyAdmission": {"apiVersion": "catchplate.nativeShadowGuestLaunch/v1",
        **{name: pins[name] for name in ("deliveryConfiguration", "delivery", "trust", "timeBootstrap", "assignment", "closure",
            "keys", "encryptedKeys", "admission", "verifierTransport")}}}
    if field: selected[field] = pins["serviceGrant"]
    launch_raw = g.canonical(selected)
    pins["launch"] = {"path": "/approved/synthetic/cold-launch/" + role + "/launch.json", "sha256": p.sha(launch_raw)}
    value = {"apiVersion": launch.API, "role": role,
        "pairContext": {name: raw.decode("ascii") for name, raw in row["pair"].items()},
        "authorizations": {
            "closure": {"inputOriginal": p.canonical(closure_input).decode("ascii"), "authorizationOriginal": closure_raw.decode("ascii")},
            "encrypted-delivery": {"inputOriginal": row["encrypted_input_raw"].decode("ascii"), "authorizationOriginal": row["encrypted_raw"].decode("ascii")},
            "verifier-transport": {"inputOriginal": row["verifier_input_raw"].decode("ascii"), "authorizationOriginal": row["verifier_raw"].decode("ascii")}},
        "timeBootstrap": clock, "pins": pins,
        "serviceContexts": {operation: contexts[operation]} if operation else contexts}
    return value, launch_raw


def fixture():
    base = key_tests.fixture(); clocks = transport_tests.clocks_for(base)
    rows = {role: transport_tests.attach_ciphertext(base, role) for role in keys.ROLES[:-1]}
    contexts = _native_grants(base, rows, clocks)
    runtime = _coordinator_runtime(base, rows, contexts, clocks)
    rows[keys.ROLES[-1]] = transport_tests.attach_ciphertext(base, keys.ROLES[-1], runtime_raw=runtime)
    inputs, expected = {}, {}
    for role, row in rows.items(): inputs[role], expected[role] = _input(base, role, row, contexts, clocks)
    return {"base": base, "rows": rows, "inputs": inputs, "expected": expected, "clocks": clocks}


class GenesisLaunchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.f = fixture()

    def prepare(self, role, value=None, **clocks):
        return launch.prepare_input(role, p.canonical(self.f["inputs"][role] if value is None else value), **(clocks or self.f["clocks"]))

    def refused(self, role, value=None, **clocks):
        with self.assertRaises((ValueError, InvalidSignature, KeyError, TypeError)):
            self.prepare(role, value, **clocks)

    def test_all_three_literal_native_selectors_and_exact_public_pins(self):
        for role in keys.ROLES:
            prepared = self.prepare(role); bundle = p.document(prepared["bundleOriginal"], launch.MAX_OUTPUT)
            self.assertEqual(prepared["launchOriginal"], self.f["expected"][role])
            self.assertEqual(bundle["launchOriginal"].encode("ascii"), self.f["expected"][role])
            self.assertEqual(bundle["launchPin"]["sha256"], bundle["launchSha256"])
            for row in bundle["originals"].values(): self.assertEqual(row["pin"]["sha256"], p.sha(row["original"].encode("ascii")))
            self.assertEqual(bundle["originals"]["encryptedInventory"]["original"].encode("ascii"), self.f["rows"][role]["ciphertext_raw"])
            self.assertEqual(bundle["originals"]["verifierTransport"]["pin"]["path"], verifier.PATHS[role])
            self.assertNotIn("installed", bundle); self.assertNotIn("ready", bundle)

    def test_coordinator_uses_actual_prior_native_and_ordinary_grants(self):
        role = keys.ROLES[-1]; value = self.f["inputs"][role]
        bundle = p.document(self.prepare(role)["bundleOriginal"], launch.MAX_OUTPUT)
        runtime = g.document(bundle["originals"]["runtime"]["original"].encode("ascii"), g.MAX_BYTES)
        for field in ("durableGrantOriginal", "currentGrantOriginal"):
            grant = g.document(runtime[field].encode("ascii"), 262144)["payload"]
            for name, operation in (("native", "publication"), ("retrieval", "retrieval")):
                self.assertEqual(grant[name]["grantSha256"], p.sha(value["serviceContexts"][operation]["grantOriginal"].encode("ascii")))
        selected = g.document(self.f["expected"][role], 32768)
        self.assertEqual(set(selected), {"apiVersion", "keyAdmission"})

    def test_closed_roles_profiles_and_required_context_rosters(self):
        role = keys.ROLES[-1]
        for change in ({"apiVersion": "catchplate.nativePilotLaunchBundle/v1"}, {"role": "bridge"}, {"fallback": None}):
            self.refused(role, {**self.f["inputs"][role], **change})
        value = copy.deepcopy(self.f["inputs"][role]); del value["serviceContexts"]["retrieval"]; self.refused(role, value)
        role = keys.ROLES[0]; value = copy.deepcopy(self.f["inputs"][role])
        value["serviceContexts"]["publication"] = self.f["inputs"][keys.ROLES[-1]]["serviceContexts"]["publication"]
        self.refused(role, value)

    def test_fixed_verifier_runtime_and_cold_pin_paths_cannot_be_relocated(self):
        role = keys.ROLES[0]
        for name in ("verifierTransport", "runtime", "deliveryConfiguration", "encryptedInventory"):
            value = copy.deepcopy(self.f["inputs"][role]); value["pins"][name]["path"] = "/approved/synthetic/not-the-original.json"
            self.refused(role, value)
        value = copy.deepcopy(self.f["inputs"][role]); value["pins"]["assignment"]["path"] = value["pins"]["trust"]["path"]
        self.refused(role, value)
        value = copy.deepcopy(self.f["inputs"][role]); value["pins"]["launch"]["sha256"] = labelled("false launch pin")
        self.refused(role, value)

    def test_authorizations_are_exact_pair_bound_signatures_not_role_claims(self):
        role, other = keys.ROLES[:2]
        for name in launch.AUTHORIZATIONS:
            value = copy.deepcopy(self.f["inputs"][role]); value["authorizations"][name] = self.f["inputs"][other]["authorizations"][name]
            self.refused(role, value)
        value = copy.deepcopy(self.f["inputs"][role]); value["pairContext"] = self.f["inputs"][other]["pairContext"]
        self.refused(role, value)

    def test_changed_ciphertext_transport_and_time_settings_cannot_reuse_pins(self):
        role = keys.ROLES[0]
        value = copy.deepcopy(self.f["inputs"][role]); value["timeBootstrap"]["parentPort"] += 1; self.refused(role, value)
        for field in ("encryptedInventoryOriginal", "transportOriginal"):
            value = copy.deepcopy(self.f["inputs"][role]); row = value["authorizations"]["encrypted-delivery"]
            raw = p.document(row["inputOriginal"].encode("ascii"), launch.MAX_INPUT)
            raw[field] = "{}"; row["inputOriginal"] = p.canonical(raw).decode("ascii"); self.refused(role, value)

    def test_coordinator_rejects_authentic_but_unrelated_native_grant_transcript(self):
        role = keys.ROLES[-1]
        prior = native_tests.fixture()
        value = copy.deepcopy(self.f["inputs"][role])
        value["serviceContexts"]["publication"] = {"inputOriginal": text(prior["publication"]),
            "grantOriginal": prior["publication_raw"].decode("ascii")}
        self.refused(role, value)

    def test_original_boot_and_earliest_authorization_windows_are_not_renewed(self):
        for role in keys.ROLES:
            prepared = self.prepare(role); clocks = self.f["clocks"]
            self.assertEqual(prepared["epochLimit"], clocks["now_unix_ns"] + 5_000_000_000)
            for changed in ({**clocks, "now_boottime_ns": prepared["deadline"]},
                    {**clocks, "now_unix_ns": prepared["epochLimit"]},
                    {**clocks, "boot": (p.encoded(bytes([71]) * 16), *clocks["boot"][1:])}):
                self.refused(role, **changed)


if __name__ == "__main__": unittest.main()
