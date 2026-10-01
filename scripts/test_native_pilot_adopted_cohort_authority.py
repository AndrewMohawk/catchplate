#!/usr/bin/env python3
"""Pure synthetic adopted issuer controls; no process or descriptor admission."""
from __future__ import annotations

import copy
from pathlib import Path
import stat
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import native_pilot_adopted_cohort_authority as issuer

p, cohort = issuer.p, issuer.cohort


def fixture():
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    def authority(value):
        raw = value.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return dict(publicKeyBase64url=p.encoded(raw), keyId=p.sha(raw))
    auth = authority(key)
    cold = {role: p.canonical(dict(apiVersion="serverware.policyCustodyGuestConfiguration/v1", authority=auth,
        serviceRole="production-bridge", uid=2000 + i, gid=3000 + i)).decode("ascii")
        for i, role in enumerate(issuer.ROLES)}
    config = dict(apiVersion=cohort.ADOPTED_CONFIGURATION_API, authority=auth, executableSha256=p.sha(b"exe"),
        cleanup=dict(authority=authority(other), scopeId=p.sha(b"scope"), genesisSha256=p.sha(b"genesis"),
            journal=dict(device=1, inode=2, mode=stat.S_IFDIR | 0o700, uid=0, gid=0)),
        externalDriver={name: p.sha(name.encode()) for name in
            ("configurationSha256", "windowSha256", "observationSha256", "supervisorExecutableSha256")})
    config.update({role + "Configuration": dict(path="/etc/serverware/" + role + ".json", sha256=p.sha(raw.encode()))
        for role, raw in cold.items()})
    config_raw = p.canonical(config)
    boot = p.encoded(bytes(range(16))), 1, 2
    window = dict(configurationSha256=p.sha(config_raw), authorityKeyId=auth["keyId"], bootIdBase64url=boot[0],
        timeNamespaceDevice=boot[1], timeNamespaceInode=boot[2], issuedAtBoottimeNs="1000000000",
        startupDeadlineBoottimeNs="10000000000", lifetimeDeadlineBoottimeNs="20000000000",
        invocationId="1234567890abcdef1234567890abcdef")
    value = dict(apiVersion=issuer.API, operation="precreation", configurationOriginal=config_raw.decode(),
        configurationSha256=p.sha(config_raw), coldOriginals=cold, payloadOriginal=p.canonical(window).decode())
    clocks = dict(boot=boot, now_boottime_ns=2_000_000_000, now_unix_ns=5_000_000_000)
    return key, value, clocks


def release_fixture():
    key, value, clocks = fixture()
    context = issuer.prepare_input("precreation", p.canonical(value), **clocks)
    signed = cohort.sign_precreation(**context["kwargs"], signing_key=key, boot=clocks["boot"], now=clocks["now_boottime_ns"])
    config = p.document(context["kwargs"]["configuration_raw"], cohort.MAX_BYTES)
    window = context["window"]
    observed = dict(apiVersion=cohort.originals_api(config), configurationSha256=value["configurationSha256"],
        precreationSha256=p.sha(signed), invocationId=window["invocationId"])
    observed.update({role: dict(processId=100 + i, startTimeTicks=10 + i,
        executable=dict(device=1, inode=1000 + i, length=8192, sha256=config["executableSha256"]))
        for i, role in enumerate(issuer.ROLES)})
    observed["externalDriver"] = dict(apiVersion="serverware.nativeShadowEndpointDriverOriginal/v1",
        bindingSha256=p.sha(b"binding"), **{name: config["externalDriver"][name] for name in
            ("configurationSha256", "windowSha256", "observationSha256")},
        supervisor=dict(processId=10, startTimeTicks=2, pidfdDevice=0, pidfdInode=4),
        driver=dict(processId=11, startTimeTicks=3, pidfdDevice=0, pidfdInode=5),
        executable=dict(device=1, inode=12, length=8192, sha256=p.sha(b"driver")))
    observed_raw = p.canonical(observed)
    payload = dict(apiVersion=cohort.release_api(config), configurationSha256=value["configurationSha256"],
        precreationSha256=p.sha(signed), observationSha256=p.sha(observed_raw), invocationId=window["invocationId"],
        signingKeyId=config["authority"]["keyId"], externalDriverSha256=cohort.external_driver_sha256(config, observed))
    payload.update({role: {kind: dict(path="/etc/serverware/" + role + "-" + kind + ".json", sha256=p.sha((role + kind).encode()))
        for kind in ("launch", "image")} for role in issuer.ROLES})
    value.update(operation="release", payloadOriginal=p.canonical(payload).decode(), precreationOriginal=signed.decode(),
        observationsOriginal=observed_raw.decode())
    return key, value, clocks


class AdoptedCohortAuthorityControls(unittest.TestCase):
    def test_exact_precreation_prevalidates_all_eleven(self):
        _, value, clocks = fixture()
        context = issuer.prepare_input("precreation", p.canonical(value), **clocks)
        self.assertEqual(context["deadline"], 10_000_000_000)
        self.assertIsNone(context["epochLimit"])
        self.assertIsNone(context["kwargs"]["bridge_configuration_raw"])
        self.assertIn("publication_reconciliation_configuration_raw", context["kwargs"])

    def test_exact_release_uses_v7_domain_and_originals(self):
        key, value, clocks = release_fixture()
        context = issuer.prepare_input("release", p.canonical(value), **clocks)
        raw = cohort.sign_release(**context["kwargs"], signing_key=key, boot=clocks["boot"], now=clocks["now_boottime_ns"])
        result = p.document(raw, cohort.MAX_BYTES)
        self.assertEqual(result["payload"]["apiVersion"], "serverware.nativeShadowProofCohortRelease/v7")
        key.public_key().verify(p.decoded(result["signatureBase64url"], size=64),
            b"serverware.nativeShadowProofCohortRelease.signature/v7\0" + p.canonical(result["payload"]))

    def test_old_input_and_missing_or_extra_roles_refused(self):
        _, original, clocks = fixture()
        for variant in ("old", "missing", "extra"):
            value = copy.deepcopy(original)
            if variant == "old": value["apiVersion"] = "serverware.nativePilotCohortAuthorityInput/v1"
            elif variant == "missing": value["coldOriginals"].pop("publicationReconciliation")
            else: value["coldOriginals"]["bridge"] = value["coldOriginals"]["retrieval"]
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                issuer.prepare_input("precreation", p.canonical(value), **clocks)

    def test_mismatched_public_configuration_refused_before_key(self):
        _, value, clocks = fixture()
        value["coldOriginals"]["publicationReconciliation"] = value["coldOriginals"]["retrieval"]
        with self.assertRaises(ValueError): issuer.prepare_input("precreation", p.canonical(value), **clocks)

    def test_release_binds_exact_observation_and_precreation(self):
        _, original, clocks = release_fixture()
        for field in ("observationSha256", "precreationSha256", "externalDriverSha256"):
            value = copy.deepcopy(original); payload = p.document(value["payloadOriginal"].encode(), cohort.MAX_BYTES)
            payload[field] = p.sha(b"replacement"); value["payloadOriginal"] = p.canonical(payload).decode()
            with self.subTest(field=field), self.assertRaises(ValueError):
                issuer.prepare_input("release", p.canonical(value), **clocks)

    def test_original_deadlines_and_operation_cannot_be_renewed(self):
        _, value, clocks = fixture()
        for now in (999_999_999, 10_000_000_000, 20_000_000_000):
            with self.subTest(now=now), self.assertRaises(ValueError):
                issuer.prepare_input("precreation", p.canonical(value), **{**clocks, "now_boottime_ns": now})
        with self.assertRaises(ValueError): issuer.prepare_input("release", p.canonical(value), **clocks)

    def test_noncanonical_and_unknown_fields_refused(self):
        _, value, clocks = fixture()
        with self.assertRaises(ValueError): issuer.prepare_input("precreation", p.canonical(value) + b"\n", **clocks)
        value["approval"] = True
        with self.assertRaises(ValueError): issuer.prepare_input("precreation", p.canonical(value), **clocks)


if __name__ == "__main__": unittest.main()
