#!/usr/bin/env python3
"""Synthetic signature/byte controls only; no owner, FD, fs-verity or runtime.

Fixture grant roots stand only for the narrow checker's supplied authenticated
context. This is not a valid native receipt or cold commissioning transcript.
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_core_profile as wire

p = g.p


def digest(text): return p.sha(("SYNTHETIC CORE CONTROL / " + text).encode("ascii"))
def sha(value): return p.sha(g.canonical(value))


def fixture():
    keys = {name: Ed25519PrivateKey.from_private_bytes(bytes([index]) * 32)
        for index, name in enumerate(("native", "retrieval", "durable", "current"), 1)}
    materials = {}
    for name, key in keys.items():
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        materials[name] = dict(keyId=digest(name), keySpkiSha256=p.sha(bytes.fromhex("302a300506032b6570032100") + public),
            publicKeyBase64url=p.encoded(public))
    scope = dict(apiVersion="serverware.nativePublicationGenesisScope/v1", commissioningIdSha256=digest("commission"),
        productionConfigurationBindingSha256=digest("config"), assignmentPayloadSha256=digest("assignment"),
        assignmentRevision=1, proofScopeOriginal='{"fixture":"not-native-admission"}', retrievalNamespaceSha256=digest("namespace"),
        initialPublicationRevision=1, bootIdBase64url=p.encoded(bytes(range(16))), timeNamespaceDevice=0,
        timeNamespaceInode=(1 << 63) + 10, issuedAtBoottimeNanos=10, expiresAtBoottimeNanos=100)
    guest = dict(uid=1234, gid=1235, deliverySha256=digest("delivery"))
    authorization = dict(issuedAtUnixNanos=1000, expiresAtUnixNanos=2000, trustCheckpointId=digest("trust"), guest=guest)
    genesis_raw = g.canonical(dict(apiVersion="serverware.nativeLedgerSpoolStoreGenesis/v1", guest=guest,
        proofScopeSha256=p.sha(scope["proofScopeOriginal"].encode("ascii"))))
    native = dict(scope=scope, authorization=authorization, retrieval=materials["retrieval"], retrievalGuest=guest)
    native_raw = g.canonical(dict(payload=native, signature=p.encoded(bytes(64))))
    native_role = dict(materials["native"], role="custody-publication-reconciliation", grantSha256=p.sha(native_raw))
    retrieval = dict(scope=scope, authorization=authorization, native=native_role,
        store=dict(genesisSha256=p.sha(genesis_raw), sequence=0, headSha256=p.sha(genesis_raw)))
    retrieval_raw = g.canonical(dict(payload=retrieval, signature=p.encoded(bytes(64))))
    retrieval_role = dict(materials["retrieval"], role="custody-retrieval-response", grantSha256=p.sha(retrieval_raw))
    payload = dict(scope=scope, native=native_role, retrieval=retrieval_role)
    for name in ("durable", "current"):
        payload[name + "AuthorityEpoch"] = dict(serviceSigningKeyId=materials[name]["keyId"],
            serviceSigningKeySpkiSha256=materials[name]["keySpkiSha256"])
        payload[name + "PublicKeyBase64url"] = materials[name]["publicKeyBase64url"]
    grants = {role: digest(role + " grant") for role in wire.ordinary.initial.ROLES}
    state = dict(apiVersion="serverware.nativePublicationInitialState/v1", scopeSha256=sha(scope), publicationRevision=1,
        state="uninstalled", ledgerEventOrdinal=0, **{name: None for name in ("predecessorGenerationSha256",
            "committedGenerationSha256", "publishedGenerationSha256", "firstIngressSequence", "lastIngressSequence",
            "preparedPublicationSha256")})
    evidence = dict(apiVersion="serverware.nativePublicationGenesis/v1", scope=scope, genesisOriginal=g.canonical(state).decode("ascii"),
        grantSha256=grants[wire.ordinary.initial.ROLES[0]], authorityEpoch=payload["durableAuthorityEpoch"], observedAtBoottimeNanos=20)
    evidence["signatureBase64url"] = p.encoded(keys["durable"].sign(wire._ordinary_message(
        b"serverware.nativePublicationGenesisEvidence.signature/v1", [evidence[name] for name in (
            "apiVersion", "scope", "genesisOriginal", "grantSha256", "authorityEpoch", "observedAtBoottimeNanos")])))
    core = dict(apiVersion="serverware.nativeInitialPublicationCore/v1", nativeGrantSha256=p.sha(native_raw), genesis=evidence,
        observedAtUnixNanos=1100, trustCheckpointSha256=digest("trust"), signingKeyId=materials["native"]["keyId"],
        signingKeySpkiSha256=materials["native"]["keySpkiSha256"])
    prepared = dict(core=core, preparedAtBoottimeNanos=30)
    prepared["signature"] = p.encoded(keys["native"].sign(wire.ordinary.native_message(wire.PREPARED_DOMAIN, [core, 30])))
    core_raw = g.canonical(core); identity = p.framed(b"serverware.nativeInitialPublicationCore/v1", (core_raw,))
    rid = p.framed(b"serverware.nativeInitialPublicationRetrievalId/v1", (scope["retrievalNamespaceSha256"].encode("ascii"), identity.encode("ascii")))
    stored_payload = dict(apiVersion="serverware.nativePublicationGenesisStorage/v1", guest=guest, grantSha256=p.sha(retrieval_raw),
        coreSha256=identity, objectSha256=p.sha(core_raw), fsveritySha256=digest("fixture-not-measured-verity"), retrievalIdSha256=rid,
        retrievalProofSha256=p.framed(b"serverware.nativeInitialPublicationRetrievalProof/v1",
            (scope["proofScopeOriginal"].encode("ascii"), rid.encode("ascii"), core_raw)),
        previousHeadSha256=p.sha(genesis_raw), sequence=1, storedAtBoottimeNanos=40, originalDeadlineBoottimeNanos=100,
        signingKeyId=materials["retrieval"]["keyId"], signingKeySpkiSha256=materials["retrieval"]["keySpkiSha256"])
    stored = dict(payload=stored_payload, signature=p.encoded(keys["retrieval"].sign(
        wire.ordinary.native_message(wire.STORAGE_DOMAIN, stored_payload))))
    completion = dict(apiVersion="serverware.nativePublicationGenesisCompletion/v1", prepared=prepared, stored=stored,
        receiptOriginal='{"fixture":"not-a-receipt"}', completedAtBoottimeNanos=50)
    completion["signature"] = p.encoded(keys["native"].sign(wire.ordinary.native_message(wire.COMPLETION_DOMAIN,
        [completion[name] for name in ("apiVersion", "prepared", "stored", "receiptOriginal", "completedAtBoottimeNanos")])))
    bundle = dict(completion=completion); prior = evidence
    for name, role, moment in zip(("durable", "current"), wire.ordinary.initial.ROLES, (60, 70)):
        row = dict(apiVersion="serverware.nativePublicationGenesisWitness/v1", scopeSha256=sha(scope),
            commissioningIdSha256=scope["commissioningIdSha256"], completionSha256=sha(completion), predecessorEvidenceSha256=sha(prior),
            grantSha256=grants[role], authorityEpoch=payload[name + "AuthorityEpoch"], completedAtBoottimeNanos=moment)
        row["signatureBase64url"] = p.encoded(keys[name].sign(wire._ordinary_message(
            b"serverware.nativePublicationGenesisWitness.signature/v1", [row[field] for field in wire.WITNESS_FIELDS[:-1]])))
        bundle[name], prior = row, row
    kwargs = dict(scope=scope, native_grant_raw=native_raw, retrieval_grant_raw=retrieval_raw,
        ordinary_payloads={role: copy.deepcopy(payload) for role in wire.ordinary.initial.ROLES}, ordinary_grant_sha256=grants,
        retrieval_guest=guest, genesis_raw=genesis_raw, now_boottime_ns=80, now_unix_ns=1200)
    metadata = dict(device=0, inode=(1 << 63) + 9, mode=stat.S_IFREG | 0o400, uid=1234, gid=1235,
        nlink=1, length=len(core_raw), mtimeNanos=10, ctimeNanos=11)
    observation = {"apiVersion": wire.API, **{name: digest(name) for name in wire.HASH_FIELDS},
        "bundleSha256": sha(bundle), "scopeSha256": sha(scope), "commissioningIdSha256": scope["commissioningIdSha256"],
        "nativeGrantSha256": p.sha(native_raw), "retrievalGrantSha256": p.sha(retrieval_raw), "retrievalDeliverySha256": guest["deliverySha256"],
        "coreSha256": identity, "objectSha256": p.sha(core_raw), "fsveritySha256": stored_payload["fsveritySha256"],
        "filename": wire.FILENAME, "file": metadata, "directory": dict(device=0, inode=123, mode=stat.S_IFDIR | 0o700, uid=1234, gid=1235),
        "issuedAtBoottimeNs": "10", "deadlineBoottimeNs": "100", "issuedAtUnixNanos": 1000, "expiresAtUnixNanos": 2000}
    return bundle, kwargs, observation


class CoreControls(unittest.TestCase):
    def setUp(self): self.bundle, self.kwargs, self.observed = fixture()

    def verify(self): return wire.verify(g.canonical(self.bundle), **self.kwargs)

    def test_exact_signatures_and_literal_core(self):
        result = self.verify()
        self.assertEqual(result["core"], g.canonical(self.bundle["completion"]["prepared"]["core"]))
        self.assertEqual(result["epochLimit"], 2000)
        self.assertEqual(g.document(result["head"], 4096)["storedOriginalSha256"], sha(self.bundle["completion"]["stored"]))

    def test_wrong_native_or_storage_signature_refused(self):
        for name in ("prepared", "stored"):
            with self.subTest(name=name):
                bundle = copy.deepcopy(self.bundle); bundle["completion"][name]["signature"] = p.encoded(bytes(64))
                with self.assertRaises(InvalidSignature): wire.verify(g.canonical(bundle), **self.kwargs)

    def test_actual_ordinary_grant_hash_is_required(self):
        for role in wire.ordinary.initial.ROLES:
            with self.subTest(role=role):
                values = copy.deepcopy(self.kwargs); values["ordinary_grant_sha256"][role] = digest("replacement")
                with self.assertRaises(ValueError): wire.verify(g.canonical(self.bundle), **values)

    def test_original_clock_bounds_not_renewed(self):
        for field, value in (("now_boottime_ns", 100), ("now_boottime_ns", 69), ("now_unix_ns", 2000), ("now_unix_ns", 1099)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                wire.verify(g.canonical(self.bundle), **{**self.kwargs, field: value})

    def test_sequence_zero_or_arbitrary_content_refused(self):
        for field, value in (("sequence", 0), ("sequence", True), ("objectSha256", digest("replacement"))):
            bundle = copy.deepcopy(self.bundle); bundle["completion"]["stored"]["payload"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): wire.verify(g.canonical(bundle), **self.kwargs)

    def test_exact_observation_full_u64_identity_and_fixed_name(self):
        self.assertEqual(wire.observation(g.canonical(self.observed), g.canonical(self.bundle)), self.observed)
        for field, value in (("filename", "core-2.json"), ("bundleSha256", digest("other")), ("deadlineBoottimeNs", "101")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                wire.observation(g.canonical({**self.observed, field: value}), g.canonical(self.bundle))

    def test_no_root_writable_or_replaced_file_metadata(self):
        expected = self.observed["file"]
        wire.verify_file_metadata(expected, expected)
        for field, value in (("uid", 0), ("mode", stat.S_IFREG | 0o600), ("nlink", 2), ("inode", 123), ("ctimeNanos", 12)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                wire.verify_file_metadata({**expected, field: value}, expected)

    def test_noncanonical_or_extra_observation_refused(self):
        with self.assertRaises(ValueError): wire.observation(g.canonical(self.observed) + b"\n")
        with self.assertRaises(ValueError): wire.observation(g.canonical({**self.observed, "fd": 9}))


if __name__ == "__main__": unittest.main()
