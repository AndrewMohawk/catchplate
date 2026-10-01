#!/usr/bin/env python3
"""Synthetic release-signature controls, never real endpoint/process release.

The cold closure and C9 transcripts are signed with deterministic test keys.
Remaining native grant/encrypted/verifier pins are labelled unexecuted inputs,
not proof of their contents or native acceptance. Only the owner's pure signed
release parser is called; no retained owner, descriptor or signer entrypoint is.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_closure_authority as closure
from serverware import native_pilot_genesis_endpoint_control as control
from serverware import native_pilot_genesis_endpoint_release_authority as authority
import test_native_pilot_genesis_closure_authority as closure_tests
import test_native_pilot_genesis_key_authority as key_tests
import test_native_pilot_genesis_parent_authority as parents

p = g.p
DOMAIN = "serverware.nativePublicationGenesisEndpointRelease.signature/v1"


def independent_signed(payload, key, *, domain=DOMAIN):
    message = (b"serverware.signedEnvelope/v1\0" + domain.encode("ascii")
        + b"\0serverware.canonicalJson/ascii-integer-v1\0" + g.canonical(payload))
    return g.canonical({"apiVersion": "serverware.nativePublicationGenesisEndpointRelease/v1",
        "payload": payload, "signatureBase64url": p.encoded(key.sign(message))})


def fixture():
    keys = key_tests.fixture()
    clocks = {name: keys[name] for name in ("boot", "now_boottime_ns", "now_unix_ns")}
    source = keys["deliveries"][authority.ROLES[0]]["input"]
    value = {"apiVersion": authority.API, "parentOriginals": source["parentOriginals"],
        "configurationOriginal": source["ownerConfigurationOriginal"], "preparationOriginal": source["preparationOriginal"],
        "resourcesOriginal": source["resourcesOriginal"], "services": {}}
    configuration = g.document(value["configurationOriginal"].encode("ascii"), 32768)
    binding = g.document(keys["coldBindingInputOriginal"], g.MAX_BYTES)
    for role in authority.ROLES:
        closure_input = closure_tests.input_for(keys, role)
        prepared = closure.prepare_input(role, p.canonical(closure_input), **clocks)
        closure_raw = closure_tests.independently_signed(prepared, keys["supervisor_key"])
        inner = {"apiVersion": "serverware.nativeShadowGuestLaunch/v1",
            **{name: parents.pin("unexecuted-" + role + "-" + name) for name in authority.parent.LAUNCH_PINS}}
        inner.update(deliveryConfiguration=configuration["services"][role]["deliveryConfiguration"],
            delivery=parents.pin(role + "-C9", p.sha(keys["deliveries"][role]["raw"])),
            closure=parents.pin(role + "-closure", p.sha(closure_raw)),
            trust=parents.pin("trust", p.sha(binding["trustOriginal"].encode("ascii"))),
            assignment=parents.pin("assignment", p.sha(binding["assignmentOriginal"].encode("ascii"))))
        inner["verifierTransport"]["path"] = "/etc/serverware/native-pilot-inputs/native-" + role + "-verifier.json"
        api, native_field = authority.LAUNCHES[role]
        launch = {"apiVersion": api, "keyAdmission": inner, native_field: parents.pin("unexecuted-" + role + "-native-grant")}
        launch_raw = g.canonical(launch)
        value["services"][role] = {"launch": parents.pin(role + "-launch", p.sha(launch_raw)),
            "launchOriginal": launch_raw.decode("ascii"), "closureInputOriginal": p.canonical(closure_input).decode("ascii"),
            "closureOriginal": closure_raw.decode("ascii")}
    return {"input": value, "clocks": clocks, "key": parents.selected_key(8)[0], "keys": keys}


def repack_launch(row, launch):
    raw = g.canonical(launch)
    row["launchOriginal"] = raw.decode("ascii")
    row["launch"]["sha256"] = p.sha(raw)


class GenesisEndpointReleaseAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = fixture()

    def prepare(self, value=None, **clocks):
        return authority.prepare_input(p.canonical(value or self.f["input"]), **(clocks or self.f["clocks"]))

    def refused(self, value=None, **clocks):
        with self.assertRaises((ValueError, InvalidSignature, TypeError, KeyError)):
            self.prepare(value, **clocks)

    def check(self, raw):
        return authority.checked_result(p.canonical(self.f["input"]),
            {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **self.f["clocks"])

    def test_exact_native_payload_pins_actual_observation_and_both_launches(self):
        value, prepared = self.f["input"], self.prepare()
        payload = prepared["payload"]
        self.assertEqual(set(payload), set(authority.PAYLOAD_FIELDS))
        self.assertEqual(payload["configurationSha256"], p.sha(value["configurationOriginal"].encode("ascii")))
        preparation = g.document(value["preparationOriginal"].encode("ascii"), 65536)
        self.assertEqual(payload["observationSha256"], p.sha(preparation["observationOriginal"].encode("ascii")))
        self.assertNotEqual(payload["observationSha256"], p.sha(value["preparationOriginal"].encode("ascii")))
        configuration = g.document(value["configurationOriginal"].encode("ascii"), 32768)
        for role in authority.ROLES:
            self.assertEqual(payload["services"][role]["launch"]["sha256"], p.sha(value["services"][role]["launchOriginal"].encode("ascii")))
            self.assertEqual(payload["services"][role]["image"], configuration["services"][role]["image"])
        raw = independent_signed(payload, self.f["key"])
        self.assertEqual(self.check(raw), raw)

    def test_pure_owner_parser_accepts_same_native_frame_without_owner_construction(self):
        value, prepared = self.f["input"], self.prepare()
        raw = independent_signed(prepared["payload"], self.f["key"])
        preparation = g.document(value["preparationOriginal"].encode("ascii"), 65536)
        payload = control.release_original(raw, configuration_raw=value["configurationOriginal"].encode("ascii"),
            observation_raw=preparation["observationOriginal"].encode("ascii"))
        self.assertEqual(payload, prepared["payload"])

    def test_separate_release_authority_and_domain_cannot_be_replaced_by_supervisor(self):
        payload = self.prepare()["payload"]
        for raw in (independent_signed(payload, self.f["keys"]["supervisor_key"]),
                independent_signed(payload, self.f["key"], domain="serverware.nativePublicationGenesisParentRelease.signature/v1")):
            with self.assertRaises(InvalidSignature):
                self.check(raw)

    def test_original_config_preparation_resources_and_parent_sources_cannot_drift(self):
        for field in ("configurationOriginal", "preparationOriginal", "resourcesOriginal"):
            value = copy.deepcopy(self.f["input"])
            wire = g.document(value[field].encode("ascii"), 65536)
            target = "parentPrecreationSha256" if field == "configurationOriginal" else "configurationSha256" if field == "preparationOriginal" else "preparationSha256"
            wire[target] = key_tests.labelled("different-source")
            value[field] = g.canonical(wire).decode("ascii")
            self.refused(value)
        value = copy.deepcopy(self.f["input"])
        value["parentOriginals"]["parentObservationOriginal"] += "\n"
        self.refused(value)

    def test_role_launch_pin_c9_closure_assignment_and_fixed_verifier_joins_refuse_drift(self):
        role = authority.ROLES[0]
        mutations = (
            lambda launch: launch.update(apiVersion="serverware.nativeShadowRetrievalGuestLaunch/v1"),
            lambda launch: launch["keyAdmission"]["delivery"].update(sha256=key_tests.labelled("different C9")),
            lambda launch: launch["keyAdmission"]["closure"].update(sha256=key_tests.labelled("different closure")),
            lambda launch: launch["keyAdmission"]["assignment"].update(sha256=key_tests.labelled("different assignment")),
            lambda launch: launch["keyAdmission"]["trust"].update(sha256=key_tests.labelled("different trust")),
            lambda launch: launch["keyAdmission"]["verifierTransport"].update(path="/approved/synthetic/not-fixed-verifier.json"),
        )
        for mutate in mutations:
            value = copy.deepcopy(self.f["input"]); row = value["services"][role]
            launch = g.document(row["launchOriginal"].encode("ascii"), 32768)
            mutate(launch); repack_launch(row, launch)
            self.refused(value)
        value = copy.deepcopy(self.f["input"])
        value["services"][role]["launch"]["sha256"] = key_tests.labelled("false launch pin")
        self.refused(value)

    def test_real_closure_signature_is_required_not_merely_its_hash_or_shape(self):
        value = copy.deepcopy(self.f["input"]); row = value["services"][authority.ROLES[0]]
        signed = g.document(row["closureOriginal"].encode("ascii"), closure.MAX_OUTPUT)
        signed["authorization"]["signature"] = p.encoded(bytes(64))
        raw = g.canonical(signed); row["closureOriginal"] = raw.decode("ascii")
        launch = g.document(row["launchOriginal"].encode("ascii"), 32768)
        launch["keyAdmission"]["closure"]["sha256"] = p.sha(raw)
        repack_launch(row, launch)
        self.refused(value)

    def test_original_closure_unix_ceiling_and_parent_boot_deadline_are_preserved(self):
        prepared = self.prepare()
        for clocks in ({**self.f["clocks"], "now_boottime_ns": prepared["deadline"]},
                {**self.f["clocks"], "now_unix_ns": prepared["epochLimit"]}):
            self.refused(**clocks)
        value = copy.deepcopy(self.f["input"]); role = authority.ROLES[0]; row = value["services"][role]
        closure_input = p.document(row["closureInputOriginal"].encode("ascii"), closure.MAX_INPUT)
        ceiling = self.f["clocks"]["now_unix_ns"] + 5_000_000_000
        closure_input["policy"]["expiresAtUnixNanos"] = ceiling
        context = closure.prepare_input(role, p.canonical(closure_input), **self.f["clocks"])
        raw = closure_tests.independently_signed(context, self.f["keys"]["supervisor_key"])
        row.update(closureInputOriginal=p.canonical(closure_input).decode("ascii"), closureOriginal=raw.decode("ascii"))
        launch = g.document(row["launchOriginal"].encode("ascii"), 32768)
        launch["keyAdmission"]["closure"]["sha256"] = p.sha(raw); repack_launch(row, launch)
        self.assertEqual(self.prepare(value)["epochLimit"], ceiling)

    def test_closed_exact_two_member_input_and_output_pin(self):
        for mutate in (lambda value: value.update(apiVersion="serverware.nativePilotGenesisParentAuthorityInput/v1"),
                lambda value: value.update(payloadOriginal="{}"),
                lambda value: value["services"].pop(authority.ROLES[1]),
                lambda value: value["services"].update(publicationGenesisCoordinator=value["services"][authority.ROLES[0]])):
            value = copy.deepcopy(self.f["input"]); mutate(value); self.refused(value)
        raw = independent_signed(self.prepare()["payload"], self.f["key"])
        with self.assertRaises(ValueError):
            authority.checked_result(p.canonical(self.f["input"]),
                {"original": raw.decode("ascii"), "sha256": key_tests.labelled("wrong output pin")}, **self.f["clocks"])


if __name__ == "__main__":
    unittest.main()
