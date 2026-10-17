#!/usr/bin/env python3
"""Pure signed C9/full5 controls, not owner or native adoption evidence.

All inode/process/core facts are synthetic. No FD, filesystem, listener,
watcher, native process, grant authority or operational owner is constructed.
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
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
import test_native_pilot_genesis_core as cores
from catchplate import custody_generation_grants as g
from catchplate import native_pilot_adopted_delivery as adopted
from catchplate import native_pilot_delivery_authority as authority
from catchplate import native_shadow_guest_delivery as delivery

p = g.p


def fixture():
    bundle, _, observation = cores.fixture()
    key = Ed25519PrivateKey.from_private_bytes(bytes([19]) * 32)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    cold = dict(apiVersion="catchplate.policyCustodyGuestConfiguration/v1", serviceRole="production-bridge", uid=2345, gid=2346,
        authority=dict(keyId=p.sha(public), publicKeyBase64url=p.encoded(public)))
    cold_raw = g.canonical(cold)
    activation = [dict(name=name, fd=slot, device=1, inode=slot * 10, mode=mode, uid=uid, gid=gid)
        for slot, (name, mode, uid, gid) in enumerate((
            ("retrieval-listener", stat.S_IFSOCK | 0o777, 0, 0),
            ("retrieval-objects", stat.S_IFDIR | 0o555, 0, 0),
            ("ledger-spool-store", stat.S_IFDIR | 0o700, 2345, 2346),
            ("ledger-spool-lock", stat.S_IFREG | 0o600, 2345, 2346)), 6)]
    activation.append(dict(name="publication-genesis-core", fd=10,
        **{name: observation["file"][name] for name in ("device", "inode", "mode", "uid", "gid")}))
    boot = p.encoded(bytes(range(16))), 0, (1 << 63) + 10
    payload = dict(configurationSha256=p.sha(cold_raw), authorityKeyId=cold["authority"]["keyId"], serviceRole="production-bridge",
        uid=2345, gid=2346, bootIdBase64url=boot[0], timeNamespaceDevice=boot[1], timeNamespaceInode=boot[2],
        issuedAtBoottimeNs="11", startupDeadlineBoottimeNs="80", lifetimeDeadlineBoottimeNs="90",
        invocationId="1234567890abcdef1234567890abcdef", runtimeConfig={"path": "/etc/catchplate/runtime.json", "sha256": cores.digest("runtime")},
        credentials=[dict(name="fixture-public", original={"path": "/etc/catchplate/fixture-public.json", "sha256": cores.digest("credential")},
            length=1, signing=None)], activation=activation)
    kwargs = dict(configuration_raw=cold_raw, configuration_sha256=p.sha(cold_raw), activation=activation, boot=boot,
        startup_deadline=80, now=50, core_observation_raw=g.canonical(observation), core_bundle_raw=g.canonical(bundle))
    return key, payload, kwargs


def signed(key, payload):
    return g.canonical(dict(apiVersion="catchplate.policyCustodyGuestDelivery/v1", payload=payload,
        signatureBase64url=p.encoded(key.sign(delivery.DOMAIN + g.canonical(payload)))))


class AdoptedDeliveryControls(unittest.TestCase):
    def setUp(self): self.key, self.payload, self.kwargs = fixture()

    def test_exact_full5_keeps_prior_uid_and_u64_inode(self):
        raw = signed(self.key, self.payload)
        self.assertEqual(delivery.verify_adopted_retrieval_delivery(signed_delivery_original=raw, **self.kwargs), raw)
        guest = delivery.adopted_delivery_guest(self.payload, raw)
        self.assertEqual(guest["uid"], 2345)
        self.assertEqual(self.payload["activation"][4]["uid"], 1234)
        self.assertGreater(self.payload["activation"][4]["inode"], p.MAX_I64)

    def test_old_full4_intake_never_accepts_fifth_fd(self):
        kwargs = {name: value for name, value in self.kwargs.items() if not name.startswith("core_")}
        with self.assertRaises(ValueError):
            delivery.verify_spool_retrieval_delivery(signed_delivery_original=signed(self.key, self.payload), **kwargs)

    def test_old_full4_remains_separate_and_valid(self):
        payload = copy.deepcopy(self.payload); payload["activation"].pop()
        payload.update(timeNamespaceDevice=1, timeNamespaceInode=2)
        kwargs = {name: value for name, value in self.kwargs.items() if not name.startswith("core_")}
        kwargs.update(activation=payload["activation"], boot=(self.kwargs["boot"][0], 1, 2))
        raw = signed(self.key, payload)
        self.assertEqual(delivery.verify_spool_retrieval_delivery(signed_delivery_original=raw, **kwargs), raw)

    def test_core_is_not_relabelled_or_reopened_metadata(self):
        for field, value in (("fd", 9), ("name", "ledger-spool-lock"), ("uid", 2345), ("inode", 123),
                ("mode", stat.S_IFREG | 0o600), ("device", True)):
            payload = copy.deepcopy(self.payload); payload["activation"][4][field] = value
            kwargs = {**self.kwargs, "activation": payload["activation"]}
            with self.subTest(field=field), self.assertRaises(ValueError):
                delivery.verify_adopted_retrieval_delivery(signed_delivery_original=signed(self.key, payload), **kwargs)

    def test_prior_uid_exception_is_not_allowed_on_current_ledger(self):
        payload = copy.deepcopy(self.payload); payload["activation"][2]["uid"] = 1234
        with self.assertRaises(ValueError):
            delivery.verify_adopted_retrieval_delivery(signed_delivery_original=signed(self.key, payload),
                **{**self.kwargs, "activation": payload["activation"]})

    def test_core_bundle_cannot_be_substituted(self):
        bundle = g.document(self.kwargs["core_bundle_raw"], g.MAX_BYTES)
        bundle["completion"]["receiptOriginal"] = "substitution"
        with self.assertRaises(ValueError):
            delivery.verify_adopted_retrieval_delivery(signed_delivery_original=signed(self.key, self.payload),
                **{**self.kwargs, "core_bundle_raw": g.canonical(bundle)})

    def test_signature_original_clock_and_canonical_wire_fail_closed(self):
        raw = signed(self.key, self.payload)
        for now in (10, 80, 90):
            with self.subTest(now=now), self.assertRaises(ValueError):
                delivery.verify_adopted_retrieval_delivery(signed_delivery_original=raw, **{**self.kwargs, "now": now})
        with self.assertRaises(ValueError):
            delivery.verify_adopted_retrieval_delivery(signed_delivery_original=raw + b"\n", **self.kwargs)
        bad = g.document(raw, delivery.MAX_DELIVERY); bad["signatureBase64url"] = p.encoded(bytes(64))
        with self.assertRaises(InvalidSignature):
            delivery.verify_adopted_retrieval_delivery(signed_delivery_original=g.canonical(bad), **self.kwargs)

    def test_explicit_signer_profile_not_old_implicit_inventory(self):
        self.assertEqual(adopted.ROLES, tuple(authority.ENDPOINTS) + ("publicationReconciliation",))
        self.assertEqual(tuple(name for name, _ in adopted.inventory("retrieval")), delivery.ADOPTED_RETRIEVAL_NAMES)
        self.assertEqual(len(authority.ENDPOINTS["retrieval"]), 4)
        self.assertNotIn("publicationReconciliation", authority.ENDPOINTS)
        with self.assertRaises(ValueError):
            adopted.prepare_input(g.canonical(dict(apiVersion="catchplate.nativePilotDeliverySigningInput/v1", role="retrieval")),
                boot=self.kwargs["boot"], now_boottime_ns=50, now_unix_ns=1200)


if __name__ == "__main__": unittest.main()
