#!/usr/bin/env python3
"""Synthetic signed public originals, never a retained parent or live signer.

Keys and observations are explicitly synthetic. Closure public-shape fixtures
carry an invalid signature sentinel: these controls do not claim native closure
authentication, actual image/C9 ownership, independent approval or process life.
No protected I/O, sign entrypoint or controller is invoked.
"""
from __future__ import annotations

import copy
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import test_native_pilot_genesis_closure_schema as closure_fixtures
from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_parent_authority as authority

p = authority.p


def selected_key(seed):
    key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, {"publicKeyBase64url": p.encoded(public), "keyId": p.sha(public)}


def independently_signed(api, domain, payload, key):
    preimage = (b"catchplate.signedEnvelope/v1\0" + domain.encode("ascii")
        + b"\0catchplate.canonicalJson/ascii-integer-v1\0" + g.canonical(payload))
    return g.canonical({"apiVersion": api, "payload": payload, "signatureBase64url": p.encoded(key.sign(preimage))})


def pin(label, digest=None):
    return {"path": "/approved/synthetic/" + label + ".json", "sha256": digest or p.sha(label.encode("ascii"))}


def fixture():
    """Complete public source fixture; none of its process/image facts are live."""
    pre_key, pre_authority = selected_key(1)
    release_key, release_authority = selected_key(2)
    _, delivery_authority = selected_key(3)
    closure = closure_fixtures.fixture("publicationGenesisCoordinator")
    cold = {"apiVersion": "catchplate.policyCustodyGuestConfiguration/v1", "authority": delivery_authority,
        "serviceRole": "production-bridge", "uid": 64001, "gid": 64001}
    cold_raw = g.canonical(cold)
    configuration = {"apiVersion": authority.CONFIGURATION_API, "precreationAuthority": pre_authority,
        "releaseAuthority": release_authority, "executableSha256": closure["manifest"]["workerExecutableSha256"],
        "deliveryConfiguration": pin("cold", p.sha(cold_raw))}
    configuration_raw = g.canonical(configuration)
    boot, now = (p.encoded(bytes([4]) * 16), 7, 8), 2_000_000_000
    window = {"configurationSha256": p.sha(configuration_raw), "authorityKeyId": pre_authority["keyId"],
        "bootIdBase64url": boot[0], "timeNamespaceDevice": boot[1], "timeNamespaceInode": boot[2],
        "issuedAtBoottimeNs": "1000000000", "startupDeadlineBoottimeNs": "5000000000",
        "lifetimeDeadlineBoottimeNs": "10000000000", "invocationId": "a" * 32}
    precreation_raw = independently_signed(authority.PRECREATION_API, authority.PRECREATION_DOMAIN, window, pre_key)
    observation = {"apiVersion": authority.OBSERVATION_API, "configurationSha256": p.sha(configuration_raw),
        "precreationSha256": p.sha(precreation_raw), "invocationId": window["invocationId"], "processId": 1024,
        "startTimeTicks": 99, "pidfdDevice": 5, "pidfdInode": 9,
        "executable": {"device": 11, "inode": 12, "length": 65536, "sha256": configuration["executableSha256"]},
        "resultActivation": [{"name": name, "fd": fd, "device": 13, "inode": 20 + fd,
            "mode": stat.S_IFSOCK | 0o777, "uid": 0, "gid": 0} for fd, name in
            ((14, "publication-genesis-result"), (15, "publication-genesis-result-parent"))]}
    observation_raw = g.canonical(observation)
    guest = closure["authorization"]["payload"]["guest"]
    guest.update({name: window[name] for name in authority.WINDOW_FIELDS[2:]})
    guest["configurationSha256"] = p.sha(cold_raw)
    closure_raw = g.canonical(closure)
    inner = {"apiVersion": "catchplate.nativeShadowGuestLaunch/v1",
        **{name: pin(name) for name in authority.LAUNCH_PINS}}
    inner["deliveryConfiguration"] = configuration["deliveryConfiguration"]
    inner["delivery"] = pin("delivery", guest["deliverySha256"])
    inner["closure"] = pin("closure", p.sha(closure_raw))
    inner["verifierTransport"]["path"] = "/etc/catchplate/native-pilot-inputs/native-publicationGenesisCoordinator-verifier.json"
    launch_raw = g.canonical({"apiVersion": "catchplate.nativeShadowPublicationGenesisCoordinatorGuestLaunch/v2", "keyAdmission": inner})
    release_payload = {"configurationSha256": p.sha(configuration_raw), "precreationSha256": p.sha(precreation_raw),
        "observationSha256": p.sha(observation_raw), "invocationId": window["invocationId"],
        "launch": pin("launch", p.sha(launch_raw)), "image": pin("image", closure["manifest"]["imageSha256"]),
        "signingKeyId": release_authority["keyId"]}
    common = {"apiVersion": authority.INPUT_API, "configurationOriginal": configuration_raw.decode("ascii"),
        "deliveryConfigurationOriginal": cold_raw.decode("ascii")}
    pre_input = {**common, "operation": "precreation", "payloadOriginal": g.canonical(window).decode("ascii")}
    release_input = {**common, "operation": "release", "payloadOriginal": g.canonical(release_payload).decode("ascii"),
        "precreationOriginal": precreation_raw.decode("ascii"), "observationOriginal": observation_raw.decode("ascii"),
        "launchOriginal": launch_raw.decode("ascii"), "closureOriginal": closure_raw.decode("ascii")}
    return {"configuration_raw": configuration_raw, "cold_raw": cold_raw, "precreation_raw": precreation_raw,
        "observation_raw": observation_raw, "launch_raw": launch_raw, "closure_raw": closure_raw,
        "pre_input": pre_input, "release_input": release_input, "pre_key": pre_key, "release_key": release_key,
        "boot": boot, "now": now}


class GenesisParentAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture()
        self.kw = {"boot": self.f["boot"], "now_boottime_ns": self.f["now"]}

    def prepare(self, value, **kw):
        return authority.prepare_input(p.canonical(value), **(kw or self.kw))

    def output(self, value, key):
        prepared = self.prepare(value)
        return independently_signed(prepared["apiVersion"], prepared["domain"], prepared["payload"], key)

    def check(self, value, raw):
        return authority.checked_result(p.canonical(value), {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **self.kw)

    def test_precreation_exact_native_frame_and_original_deadline(self):
        value = self.f["pre_input"]
        prepared = self.prepare(value)
        self.assertEqual(prepared["deadline"], 5_000_000_000)
        self.assertEqual(self.output(value, self.f["pre_key"]), self.f["precreation_raw"])
        self.assertEqual(self.check(value, self.f["precreation_raw"]), self.f["precreation_raw"])
        context = authority.validate_precreation(self.f["precreation_raw"], configuration_raw=self.f["configuration_raw"],
            delivery_configuration_raw=self.f["cold_raw"], **self.kw)
        self.assertEqual(set(context), {"configuration", "cold", "window", "deadline"})
        self.assertEqual(context["window"], prepared["payload"])

    def test_release_separately_signed_actual_original_associations(self):
        value = self.f["release_input"]
        raw = self.output(value, self.f["release_key"])
        self.assertEqual(self.check(value, raw), raw)
        context = authority.validate_release(raw, configuration_raw=self.f["configuration_raw"],
            delivery_configuration_raw=self.f["cold_raw"], precreation_raw=self.f["precreation_raw"],
            observation_raw=self.f["observation_raw"], launch_raw=self.f["launch_raw"], closure_raw=self.f["closure_raw"], **self.kw)
        self.assertEqual(context["deadline"], 5_000_000_000)

    def test_distinct_authorities_and_wrong_signer_refuse(self):
        value = copy.deepcopy(self.f["pre_input"])
        config = g.document(self.f["configuration_raw"], authority.MAX_WIRE)
        config["releaseAuthority"] = config["precreationAuthority"]
        value["configurationOriginal"] = g.canonical(config).decode("ascii")
        with self.assertRaises(ValueError): self.prepare(value)
        for name, wrong in (("pre_input", "release_key"), ("release_input", "pre_key")):
            value = self.f[name]
            with self.assertRaises(InvalidSignature): self.check(value, self.output(value, self.f[wrong]))

    def test_original_boot_window_expiry_and_cleanup_reserve(self):
        for now in (999_999_999, 5_000_000_000, 10_000_000_000):
            with self.assertRaises(ValueError): self.prepare(self.f["pre_input"], boot=self.f["boot"], now_boottime_ns=now)
        with self.assertRaises(ValueError): self.prepare(self.f["pre_input"], boot=(self.f["boot"][0], 7, 99), now_boottime_ns=self.f["now"])
        value = copy.deepcopy(self.f["pre_input"])
        window = g.document(value["payloadOriginal"].encode("ascii"), authority.MAX_WIRE)
        window["lifetimeDeadlineBoottimeNs"] = window["startupDeadlineBoottimeNs"]
        value["payloadOriginal"] = g.canonical(window).decode("ascii")
        self.assertEqual(self.prepare(value)["deadline"], 4_750_000_000)
        with self.assertRaises(ValueError): self.prepare(value, boot=self.f["boot"], now_boottime_ns=4_750_000_000)

    def test_observation_process_executable_and_result_pairs_are_closed(self):
        context = authority.validate_precreation(self.f["precreation_raw"], configuration_raw=self.f["configuration_raw"],
            delivery_configuration_raw=self.f["cold_raw"], **self.kw)
        original = g.document(self.f["observation_raw"], authority.MAX_WIRE)
        mutations = [("processId", 1), ("startTimeTicks", 0), ("invocationId", "b" * 32),
            ("precreationSha256", p.sha(b"other")), ("extra", True)]
        for field, replacement in mutations:
            changed = copy.deepcopy(original); changed[field] = replacement
            with self.assertRaises(ValueError):
                authority.validate_observation(g.canonical(changed), configuration_raw=self.f["configuration_raw"],
                    precreation_raw=self.f["precreation_raw"], context=context)
        for change in ("alias", "mode", "uid", "fd", "sha"):
            changed = copy.deepcopy(original)
            if change == "alias": changed["resultActivation"][1]["inode"] = changed["resultActivation"][0]["inode"]
            elif change == "sha": changed["executable"]["sha256"] = p.sha(b"other")
            else: changed["resultActivation"][0][change] = {"mode": stat.S_IFREG | 0o400, "uid": 1, "fd": 15}[change]
            with self.assertRaises(ValueError):
                authority.validate_observation(g.canonical(changed), configuration_raw=self.f["configuration_raw"],
                    precreation_raw=self.f["precreation_raw"], context=context)

    def test_release_pins_versions_and_literal_source_drift_refuse(self):
        for name in ("configurationSha256", "precreationSha256", "observationSha256", "signingKeyId"):
            value = copy.deepcopy(self.f["release_input"])
            payload = g.document(value["payloadOriginal"].encode("ascii"), authority.MAX_WIRE)
            payload[name] = p.sha(b"other")
            value["payloadOriginal"] = g.canonical(payload).decode("ascii")
            with self.assertRaises(ValueError): self.prepare(value)
        for name in ("launch", "image"):
            value = copy.deepcopy(self.f["release_input"])
            payload = g.document(value["payloadOriginal"].encode("ascii"), authority.MAX_WIRE)
            payload[name]["sha256"] = p.sha(b"other")
            value["payloadOriginal"] = g.canonical(payload).decode("ascii")
            with self.assertRaises(ValueError): self.prepare(value)
        for field, api in (("launchOriginal", "catchplate.nativeShadowPublicationGenesisCoordinatorGuestLaunch/v1"),
                ("closureOriginal", "catchplate.nativeCustodyClosure/v4")):
            value = copy.deepcopy(self.f["release_input"])
            doc = g.document(value[field].encode("ascii"), authority.MAX_CLOSURE); doc["apiVersion"] = api
            value[field] = g.canonical(doc).decode("ascii")
            with self.assertRaises(ValueError): self.prepare(value)

    def test_native_u64_is_preserved_in_signature_and_observation(self):
        value = copy.deepcopy(self.f["pre_input"])
        window = g.document(value["payloadOriginal"].encode("ascii"), authority.MAX_WIRE)
        window["timeNamespaceDevice"] = (1 << 64) - 1
        value["payloadOriginal"] = g.canonical(window).decode("ascii")
        kw = {"boot": (self.f["boot"][0], (1 << 64) - 1, 8), "now_boottime_ns": self.f["now"]}
        prepared = self.prepare(value, **kw)
        raw = independently_signed(prepared["apiVersion"], prepared["domain"], prepared["payload"], self.f["pre_key"])
        self.assertEqual(authority.checked_result(p.canonical(value), {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **kw), raw)
        context = authority.validate_precreation(self.f["precreation_raw"], configuration_raw=self.f["configuration_raw"],
            delivery_configuration_raw=self.f["cold_raw"], **self.kw)
        observation = g.document(self.f["observation_raw"], authority.MAX_WIRE)
        observation["startTimeTicks"] = (1 << 64) - 1
        self.assertEqual(authority.validate_observation(g.canonical(observation), configuration_raw=self.f["configuration_raw"],
            precreation_raw=self.f["precreation_raw"], context=context)["startTimeTicks"], (1 << 64) - 1)
        window["timeNamespaceDevice"] = True; value["payloadOriginal"] = g.canonical(window).decode("ascii")
        with self.assertRaises(ValueError): self.prepare(value, **kw)

    def test_closed_canonical_input_result_and_signature_domain(self):
        value = copy.deepcopy(self.f["pre_input"]); value["futureApproval"] = "yes"
        with self.assertRaises(ValueError): self.prepare(value)
        with self.assertRaises(ValueError): authority.input_document(p.canonical(self.f["pre_input"]) + b"\n")
        with self.assertRaises(ValueError): authority.input_document(b"{" + b" " * authority.MAX_INPUT + b"}")
        raw = self.f["precreation_raw"]
        with self.assertRaises(ValueError):
            authority.checked_result(p.canonical(self.f["pre_input"]), {"original": raw.decode("ascii"), "sha256": p.sha(b"other")}, **self.kw)
        signed = g.document(raw, authority.MAX_WIRE)
        signed["signatureBase64url"] = p.encoded(self.f["pre_key"].sign(authority.PRECREATION_DOMAIN.encode("ascii")
            + b"\0" + g.canonical(signed["payload"])))
        with self.assertRaises(InvalidSignature): self.check(self.f["pre_input"], g.canonical(signed))


if __name__ == "__main__":
    unittest.main()
