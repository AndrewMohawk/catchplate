#!/usr/bin/env python3
"""Fixed cold graph controls over authentic synthetic public transcripts.

No executor, installer, protected signer, owner or native admission is run.
Unexamined catalogue positions are explicit padding, not successful owner
receipts. Every original consumed by a plan is a real-format, independently
signed synthetic fixture; no successful validator is mocked.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_jobs as jobs
from catchplate import native_pilot_genesis_job_publication as publication
import test_native_pilot_genesis_ordinary_initial as initial_tests
import test_native_pilot_genesis_ordinary_runtime as ordinary_tests
from test_native_pilot_generation_scope import NOW

p = g.p
ERRORS = (ValueError, InvalidSignature, KeyError, TypeError)
PADDING = b'{"testOnly":"unexamined catalogue position; not an owner receipt"}'


def record(raw, result):
    return {"input": raw, "result": result}


def prefix(name, records):
    index = jobs.JOBS.index(jobs.job(name))
    return {item.name: records.get(item.name, record(PADDING, PADDING)) for item in jobs.JOBS[:index]}


def static_records(cold_raw, clocks):
    value = jobs.binding.input_document(cold_raw)
    selected = p.document(value["closureSetOriginal"].encode("ascii"), jobs.sets.MAX_BYTES)
    envelope = g.document(value["assignmentOriginal"].encode("ascii"), g.MAX_BYTES)
    closure_input = g.canonical({"apiVersion": "catchplate.nativePilotClosureSetPreparation/v3",
        "setApiVersion": jobs.sets.GENESIS_BOOTSTRAP_API, "members": selected["members"]})
    assignment_input = g.canonical({"apiVersion": jobs.assignment.GENESIS_BOOTSTRAP_INPUT_API,
        "setApiVersion": jobs.sets.GENESIS_BOOTSTRAP_API, "trustOriginal": value["trustOriginal"],
        "trustSha256": value["trustSha256"], "closureSetOriginal": value["closureSetOriginal"],
        "payloadOriginal": g.canonical(envelope["payload"]).decode("ascii")})
    return {
        "closure-set": record(closure_input, value["closureSetOriginal"].encode("ascii")),
        "assignment": record(assignment_input, value["assignmentOriginal"].encode("ascii")),
        "cold-binding": record(cold_raw, jobs.binding.prepare(input_original=cold_raw,
            expected_input_sha256=p.sha(cold_raw), **clocks)),
    }


def observations(source, peer=None, activations=None):
    result = {name: source[field].encode("ascii") for field, name in jobs.PARENTS.items()}
    for field, name in (("launchOriginal", "ordinary.configuration"),
            ("preparationOriginal", "ordinary.preparation"), ("resourcesOriginal", "ordinary.resources")):
        result[name] = source[field].encode("ascii")
    if peer is not None:
        result["parent.peer"] = peer.encode("ascii")
    for role, activation in (activations or {}).items():
        result["ordinary.activation." + role] = g.canonical(activation)
    return result


def fixture():
    source = ordinary_tests.fixture()
    clocks, original = source["kw"], source["f"]
    values, deliveries = copy.deepcopy(source["delivery_inputs"]), {}
    # Only independently approved public destinations change. Re-sign the
    # exact C9 bytes under the fixture's existing deterministic C9 authority.
    for role, value in values.items():
        payload = g.document(value["payloadOriginal"].encode("ascii"), jobs.ordinary.MAX_DELIVERY)
        payload["runtimeConfig"]["path"] = "/etc/catchplate/custody-" + role + "-runtime.json"
        for row in payload["credentials"]:
            suffix = {"authority-history": "initial-history", "peer-inspection-policy": "peer-inspection"}.get(row["name"])
            if suffix:
                row["original"]["path"] = "/etc/catchplate/custody-" + role + "-" + suffix + ".json"
        value["payloadOriginal"] = g.canonical(payload).decode("ascii")
        key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("SYNTHETIC C9 / " + role).encode()).digest())
        deliveries[role] = g.canonical({"apiVersion": "catchplate.policyCustodyGuestDelivery/v1", "payload": payload,
            "signatureBase64url": p.encoded(key.sign(b"catchplate.policyCustodyGuestDelivery.signature/v1\0" + g.canonical(payload)))})
    cold_raw = source["grants"][jobs.ORDINARY[0]]["coldBindingInputOriginal"].encode("ascii")
    records = static_records(cold_raw, clocks)
    parent = original["parent"]
    records["parent-precreation"] = record(g.canonical(parent["pre_input"]), parent["precreation_raw"])
    first = values[jobs.ORDINARY[0]]
    observed = observations(first["source"], first["coordinatorPeerPreparationOriginal"],
        {role: value["activation"] for role, value in values.items()})
    for role in jobs.ORDINARY:
        records["initial-assemble-" + role] = record(original["rows"][role]["inputs"]["assemble"],
            first["historyOriginals"][role].encode("ascii"))
        raw = g.canonical(values[role])
        records["ordinary-runtime-" + role] = record(raw, source["runtimes"][role])
        records["ordinary-delivery-" + role] = record(raw, deliveries[role])
        grant = copy.deepcopy(source["grants"][role])
        grant["deliveryOriginals"] = {name: raw.decode("ascii") for name, raw in deliveries.items()}
        grant_raw = g.canonical(grant)
        prepared = jobs.ordinary.prepare_input("grant", grant_raw, **clocks)
        signed = ordinary_tests.signed_grant(prepared["payload"], original["rows"][role]["keys"]["root"])
        records["ordinary-grant-" + role] = record(grant_raw, signed)
    for kind, field in (("publication", "nativePublicationOriginal"), ("retrieval", "nativeRetrievalOriginal")):
        records["native-" + kind + "-grant"] = record(PADDING, source["grants"][jobs.ORDINARY[0]][field].encode("ascii"))
    return {"records": records, "observations": observed, "clocks": clocks, "source": source}


class GenesisJobTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = fixture()

    def prepare(self, name, raw=None, *, records=None, observed=None, clocks=None):
        records = self.f["records"] if records is None else records
        return jobs.prepare_input(name, records[name]["input"] if raw is None else raw,
            prior=prefix(name, records), observations=self.f["observations"] if observed is None else observed,
            **(self.f["clocks"] if clocks is None else clocks))

    def plan(self, name, *, records=None, observed=None, clocks=None):
        records = self.f["records"] if records is None else records
        return jobs.publication_plan(name, prefix(name, records),
            self.f["observations"] if observed is None else observed,
            **(self.f["clocks"] if clocks is None else clocks))

    def test_closed_catalogue_order_and_distinct_key_purposes(self):
        names = tuple(item.name for item in jobs.JOBS)
        self.assertEqual((len(names), len(set(names)), len(jobs.KEY_PURPOSES)), (64, 64, 36))
        self.assertEqual(len(set(jobs.KEY_PURPOSES)), 36)
        self.assertEqual({item.role for item in jobs.JOBS if item.role}, set(jobs.ORDINARY + jobs.NATIVE))
        for before, after in (("assignment", "cold-binding"), ("install-precreation", "parent-start"),
                ("initialize-retrieval-store", "native-retrieval-grant"), ("native-publication-grant", "native-retrieval-grant"),
                ("ordinary-release", "coordinator-assemble"), ("coordinator-assemble", "native-delivery-" + jobs.COORDINATOR),
                ("coordinator-finish", "cleanup")):
            self.assertLess(names.index(before), names.index(after))
        for name in ("hot-bridge", "initial-checkpoint-spool-head", "native-launch-bridge"):
            with self.assertRaises(ValueError): jobs.job(name)

    def test_static_successors_and_complete_assignment_public_preparation(self):
        records = self.f["records"]
        selected = self.prepare("closure-set")
        self.assertEqual(selected["nativeContext"]["outputOriginal"], records["closure-set"]["result"])
        assigned = self.prepare("assignment")["nativeContext"]
        envelope = g.document(records["assignment"]["result"], g.MAX_BYTES)
        self.assertEqual(assigned["payload"], envelope["payload"])
        assigned["public"].verify(p.decoded(envelope["signature"], size=64), assigned["message"])
        self.assertGreater(assigned["epochLimit"], NOW)
        self.assertEqual(self.prepare("cold-binding")["nativeContext"]["outputOriginal"], records["cold-binding"]["result"])
        value = p.document(records["assignment"]["input"], jobs.assignment.MAX_INPUT)
        value["apiVersion"] = "catchplate.nativePilotAssignmentAuthorityInput/v2"
        with self.assertRaises(ValueError): self.prepare("assignment", g.canonical(value))

    def test_framed_but_invalid_public_assignment_refuses_before_private_loader(self):
        value = p.document(self.f["records"]["assignment"]["input"], jobs.assignment.MAX_INPUT)
        value["trustSha256"] = p.sha(b"different independently pinned trust")
        raw = g.canonical(value)
        # Framing alone accepts this input; full public admission must not.
        jobs.assignment.input_document(raw)
        calls = []
        with self.assertRaises(ValueError):
            jobs.run("assignment", input_original=raw, prior=prefix("assignment", self.f["records"]),
                observations={}, key_loader=lambda purpose: calls.append(purpose))
        self.assertEqual(calls, [])

    def test_exact_completed_prefix_and_owner_dispatch_refuse_before_key_use(self):
        raw = self.f["records"]["assignment"]["input"]
        for prior in ({}, {**prefix("assignment", self.f["records"]), "cleanup": record(PADDING, PADDING)}):
            with self.assertRaises(ValueError):
                jobs.prepare_input("assignment", raw, prior=prior, observations={}, **self.f["clocks"])
        calls = []
        with self.assertRaises(ValueError):
            jobs.run("cleanup", input_original=PADDING, prior={}, observations={}, key_loader=lambda purpose: calls.append(purpose))
        self.assertEqual(calls, [])

    def test_initial_exact_checkpoint_and_anchor_predecessors(self):
        source, mono = initial_tests.fixture()
        observed = observations(source["base"])
        clocks, records = {**mono, "now_unix_ns": NOW}, {}
        for role, row in source["rows"].items():
            for operation in jobs.initial.OPERATIONS:
                name = "initial-" + operation + "-" + role
                records[name] = record(row["inputs"][operation], row["results"][operation])
                prepared = self.prepare(name, records=records, observed=observed, clocks=clocks)
                self.assertGreater(prepared["deadline"], mono["now_boottime_ns"])
            value = jobs.initial.input_document(row["inputs"]["assemble"])
            value["anchorSignatures"]["root"] = value["anchorSignatures"]["checkpoint"]
            with self.assertRaises(ERRORS):
                jobs.associate(jobs.job("initial-assemble-" + role), value, prior=records, observations=observed)

    def test_runtime_then_delivery_requires_identical_input_and_actual_activation(self):
        for role in jobs.ORDINARY:
            prepared = self.prepare("ordinary-runtime-" + role)
            self.assertEqual(prepared["nativeContext"]["outputOriginal"], self.f["records"]["ordinary-runtime-" + role]["result"])
            self.assertGreater(self.prepare("ordinary-delivery-" + role)["deadline"], self.f["clocks"]["now_boottime_ns"])
            records = copy.deepcopy(self.f["records"])
            records["ordinary-runtime-" + role]["input"] += b" "
            with self.assertRaises(ValueError): self.prepare("ordinary-delivery-" + role, records=records)
            observed = {**self.f["observations"], "ordinary.activation." + role: b"[]"}
            with self.assertRaises(ValueError): self.prepare("ordinary-runtime-" + role, observed=observed)

    def test_precreation_plan_authenticates_signature_binding_and_original_bounds(self):
        plan = self.plan("install-precreation")
        self.assertEqual(plan["launchPin"], None)
        self.assertEqual(plan["files"], ({"path": publication.PARENT_PATH, "uid": 0, "gid": 0, "mode": 0o400,
            "raw": self.f["records"]["parent-precreation"]["result"],
            "sha256": p.sha(self.f["records"]["parent-precreation"]["result"])},))
        self.assertEqual(plan["deadline"], 5_000_000_000)
        self.assertGreater(plan["epochLimit"], NOW)
        for name in ("parent-precreation", "cold-binding"):
            records = copy.deepcopy(self.f["records"])
            value = g.document(records[name]["result"], g.MAX_BYTES)
            if name == "parent-precreation": value["signatureBase64url"] = p.encoded(bytes(64))
            else: value["inputSha256"] = p.sha(b"not the retained input")
            records[name]["result"] = g.canonical(value)
            with self.assertRaises(ERRORS): self.plan("install-precreation", records=records)
        for field, value in (("now_boottime_ns", plan["deadline"]), ("now_unix_ns", plan["epochLimit"])):
            with self.assertRaises(ERRORS): self.plan("install-precreation", clocks={**self.f["clocks"], field: value})

    def test_ordinary_plans_authenticate_grants_and_fixed_owner_separation(self):
        for role in jobs.ORDINARY:
            plan = self.plan("install-ordinary-" + role)
            rows = plan["files"]
            self.assertEqual(tuple(row["path"] for row in rows), tuple(
                "/etc/catchplate/custody-" + role + "-" + suffix + ".json" for suffix in publication.SUFFIXES))
            cold = self.f["source"]["f"]["cold"][role]
            self.assertEqual(tuple((row["uid"], row["gid"], row["mode"]) for row in rows),
                ((0, 0, 0o400), (cold["uid"], cold["gid"], 0o400), (cold["uid"], cold["gid"], 0o400),
                    (0, 0, 0o400), (0, 0, 0o400)))
            self.assertEqual(plan["launchPin"], {"path": rows[-1]["path"], "sha256": p.sha(rows[-1]["raw"])})
            self.assertEqual(g.document(rows[-1]["raw"], 65536)["apiVersion"], "catchplate.custodyOrdinaryServiceGuestLaunch/v7")
            records = copy.deepcopy(self.f["records"])
            value = g.document(records["ordinary-grant-" + role]["result"], g.MAX_BYTES)
            value["signatureBase64url"] = p.encoded(bytes(64))
            records["ordinary-grant-" + role]["result"] = g.canonical(value)
            with self.assertRaises(ERRORS): self.plan("install-ordinary-" + role, records=records)

    def test_ordinary_plan_refuses_signed_nonfixed_destination(self):
        role = jobs.ORDINARY[0]
        # The original fixture is genuinely signed and validates publicly, but
        # its independently supplied synthetic paths are not this fixed plan.
        records = copy.deepcopy(self.f["records"])
        source = self.f["source"]
        raw = g.canonical(source["delivery_inputs"][role])
        records["ordinary-runtime-" + role] = record(raw, source["runtimes"][role])
        records["ordinary-delivery-" + role] = record(raw, source["deliveries"][role])
        with self.assertRaises(ValueError): self.plan("install-ordinary-" + role, records=records)

    def test_changed_native_grant_original_cannot_be_borrowed_by_ordinary_grant(self):
        for role in jobs.ORDINARY:
            self.assertGreater(self.prepare("ordinary-grant-" + role)["deadline"], self.f["clocks"]["now_boottime_ns"])
            records = copy.deepcopy(self.f["records"])
            records["native-publication-grant"]["result"] += b" "
            with self.assertRaises(ValueError): self.prepare("ordinary-grant-" + role, records=records)


if __name__ == "__main__":
    unittest.main()
