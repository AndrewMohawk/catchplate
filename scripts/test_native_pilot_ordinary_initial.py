#!/usr/bin/env python3
"""Eight pure SYNTHETIC initial-state controls, never commissioning evidence.

Test-only deterministic Ed25519 seeds, process/directory identities and times
exist only in memory. Independent transcript construction exercises pure wire
and signature validation, not authority entrypoints, protected owners, kernel
observation, filesystem installation or services.
"""
from __future__ import annotations

import base64
import copy
import hashlib
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))

from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_key_authority as authority
from test_native_pilot_ordinary_keys import (
    ROLES, canonical, encoded, framed, identity_fixture, labelled, payload_fixture,
    preparation_fixture, sha,
)
from test_native_pilot_ordinary_key_history import _fixture as legacy_fixture

DIRECTORIES = (
    ("journal", "generation-journal", "dispatch-journal", "spool-head-journal"),
    ("state", "journal", "generation-journal", "active-effect-cleanup-journal"),
    ("journal", "generation-journal"),
    ("generation-journal", "dispatch-journal", "spool-current-journal"),
    ("journal", "generation-journal"),
)
DOMAINS = {
    "predecessorCheckpointSha256": b"serverware.custodyOrdinaryInitialCheckpointPredecessor/v1",
    "prunedHistoryRootSha256": b"serverware.custodyOrdinaryInitialHistoryRoot/v1",
    "durableEpochHeadSha256": b"serverware.custodyOrdinaryInitialDurableHead/v1",
}
KEY_DOMAIN = b"serverware.policyCustodyCurrentKeyAuthorization/v3"
ANCHOR_DOMAIN = b"serverware.policyCustodyRetainedAuthorityEpochAnchor/v3"
ANCHOR_FIELDS = ("apiVersion", "retainedEpoch", "prunedThroughEpochSequence", "prunedHistoryRootSha256",
    "prunedTerminalEpochSha256", "rootAuthorityKeyId", "rootAuthorityKeySpkiSha256")
SIGNATURE_FIELDS = ("rootSignatureBase64", "checkpointAuthoritySignatureBase64", "serviceKeySignatureBase64")
HISTORY_FIELDS = ("apiVersion", "authorityRole", "rootAuthority", "retention", "firstRetainedEpoch",
    "adjacentTransitions", "compactionAnchors", "replayTombstones")


def signature_preimage(domain, raw):
    return (b"serverware-signature-v1\0" + len(domain).to_bytes(8, "big") + domain
        + len(raw).to_bytes(8, "big") + raw)


def checkpoint(payload, public, key):
    raw = canonical([payload, public["keyId"], public["keySpkiSha256"]])
    signature = encoded(key.sign(signature_preimage(KEY_DOMAIN, raw)))
    return {"payload": copy.deepcopy(payload), "authorityKeyId": public["keyId"],
        "authorityKeySpkiSha256": public["keySpkiSha256"], "authoritySignatureBase64": signature,
        "checkpointSha256": framed(KEY_DOMAIN, (raw, signature.encode("ascii")))}


def refresh_hashes(history):
    anchor = history["firstRetainedEpoch"]
    anchor["retainedAnchorSha256"] = framed(b"serverware.policyCustodyRetainedAuthorityEpochAnchorDigest/v3",
        (canonical([anchor[name] for name in ANCHOR_FIELDS]),
         *(anchor[name].encode("ascii") for name in SIGNATURE_FIELDS)))
    history["manifestSha256"] = framed(b"serverware.policyCustodyAuthorityHistoryManifest/v3",
        (canonical([history[name] for name in HISTORY_FIELDS]),))


def sign_anchor(history, keys):
    anchor = history["firstRetainedEpoch"]
    epoch = anchor["retainedEpoch"]
    groups = (
        ("apiVersion", "authorityRole", "authorityEpochSequence", "predecessorEpochSha256"),
        ("checkpointSequence", "checkpointSha256", "checkpointAuthority", "serviceSigningKey"),
        ("endpointProcessIdentity", "endpointProcessIdentitySha256", "endpointGeneration", "serviceGeneration"),
        ("operationGeneration", "durableEpoch", "durableEpochHeadSha256", "deploymentGenerationSha256"),
    )
    epoch["epochSha256"] = framed(b"serverware.policyCustodyAuthorityEpochStatement/v3",
        (canonical([[epoch[name] for name in group] for group in groups]),))
    message = signature_preimage(ANCHOR_DOMAIN, canonical([anchor[name] for name in ANCHOR_FIELDS]))
    for field, name in zip(SIGNATURE_FIELDS, ("root", "checkpoint", "service"), strict=True):
        anchor[field] = encoded(keys[name].sign(message))
    refresh_hashes(history)


def fixture():
    preparation, launch, cold, window, now = preparation_fixture()
    services = {}
    for index, (role, names) in enumerate(zip(ROLES, DIRECTORIES, strict=True)):
        services[role] = {"directories": {name: {"identity": {"mountId": 21,
            "deviceMajor": 8, "deviceMinor": 2, "inode": 91000 + index * 10 + number,
            "uid": cold[role]["uid"], "gid": cold[role]["gid"], "mode": stat.S_IFDIR | 0o700},
            "entryCount": 0} for number, name in enumerate(names)}}
    resources = {"apiVersion": "serverware.custodyFiveServiceInitialResources/v1",
        "preparationSha256": sha(canonical(preparation)), "issuedAtBoottimeNs": "1150", "services": services}
    state = {"apiVersion": "serverware.custodyOrdinaryInitialState/v1", "serviceRole": ROLES[0],
        "preparationSha256": sha(canonical(preparation)), "resourcesSha256": sha(canonical(resources)),
        "launchSha256": sha(canonical(launch)), "endpointProcessIdentitySha256": identity_fixture()["identitySha256"],
        **{name: preparation[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
            "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")},
        "issuedAtBoottimeNs": "1150", "deploymentGenerationSha256": labelled("initial-deployment"),
        "endpointGeneration": 11, "serviceGeneration": 13, "operationGeneration": 17, "durableEpoch": 19,
        "directories": copy.deepcopy(services[ROLES[0]]["directories"])}
    roots = {name: framed(domain, (canonical(state),)) for name, domain in DOMAINS.items()}
    keys = {name: Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
        ("SYNTHETIC INITIAL HISTORY TEST SEED / " + name).encode("ascii")).digest())
        for name in ("root", "checkpoint", "service")}
    public = {}
    for name, key in keys.items():
        der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        public[name] = {"keyId": labelled("initial-key/" + name), "keySpkiSha256": sha(der),
            "publicKeySpkiBase64": encoded(der)}
    payload = payload_fixture()
    payload.update(exactEndpointGeneration=11, checkpointSequence=1, rollbackFloorCheckpointSequence=1,
        rollbackFloorEndpointGeneration=11, predecessorCheckpointSha256=roots["predecessorCheckpointSha256"],
        authorizedSigningKeyId=public["service"]["keyId"],
        authorizedSigningKeySpkiSha256=public["service"]["keySpkiSha256"])
    payload["validFromBoottime"]["absoluteBoottimeNanos"] = 1150
    signed = checkpoint(payload, public["checkpoint"], keys["checkpoint"])
    history, _, _ = legacy_fixture()
    history["rootAuthority"] = public["root"]
    anchor = history["firstRetainedEpoch"]
    anchor.update(rootAuthorityKeyId=public["root"]["keyId"],
        rootAuthorityKeySpkiSha256=public["root"]["keySpkiSha256"],
        prunedHistoryRootSha256=roots["prunedHistoryRootSha256"])
    anchor["retainedEpoch"].update(checkpointSequence=1, checkpointSha256=signed["checkpointSha256"],
        checkpointAuthority=public["checkpoint"], serviceSigningKey=public["service"],
        durableEpochHeadSha256=roots["durableEpochHeadSha256"],
        deploymentGenerationSha256=state["deploymentGenerationSha256"])
    history["retention"].update(oldestRetainedCheckpointSequence=1, currentCheckpointSequence=1)
    sign_anchor(history, keys)
    wrapper = {"apiVersion": "serverware.custodyOrdinaryInitialHistory/v1", "initialState": state,
        "initialCheckpoint": signed, "history": history}
    root_pin = {name: public["root"][name] for name in ("keyId", "keySpkiSha256")}
    return dict(preparation=preparation, launch=launch, cold=cold, window=window, now=now,
        resources=resources, state=state, roots=roots, keys=keys, public=public, wrapper=wrapper, root_pin=root_pin)


class SyntheticInitialHistoryControls(unittest.TestCase):
    def manifest(self, f):
        return initial.manifest(canonical(f["wrapper"]), role=ROLES[0], root_pin=f["root_pin"])

    def prepared(self, f):
        return initial.prepared_state(f["state"], preparation_raw=canonical(f["preparation"]),
            resources_raw=canonical(f["resources"]), launch_raw=canonical(f["launch"]),
            configuration=f["cold"][ROLES[0]], window=f["window"], endpoint_role="settlement-store", now=f["now"])

    def test_valid_independent_transcript_and_legacy_crypto_agree(self):
        f = fixture()
        self.assertEqual(initial.resources(canonical(f["resources"])), f["resources"])
        self.assertEqual(self.prepared(f), identity_fixture())
        self.assertEqual(initial.commitments(f["state"]), f["roots"])
        self.assertEqual(len(set(f["roots"].values())), 3)
        history = self.manifest(f)
        epoch, key = authority._history(canonical(history), role=ROLES[0], root_pin=f["root_pin"])
        self.assertEqual(epoch, history["firstRetainedEpoch"]["retainedEpoch"])
        self.assertEqual(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            f["keys"]["checkpoint"].public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def test_resources_refuse_nonempty_unknown_duplicate_and_noncanonical(self):
        f = fixture(); original = f["resources"]
        for mutation in ("nonempty", "bool-count", "unknown", "missing-role", "duplicate", "mode"):
            value = copy.deepcopy(original)
            directory = value["services"][ROLES[0]]["directories"]["journal"]
            if mutation in ("nonempty", "bool-count"):
                directory["entryCount"] = 1 if mutation == "nonempty" else False
            elif mutation == "unknown":
                value["ready"] = True
            elif mutation == "missing-role":
                del value["services"][ROLES[-1]]
            elif mutation == "duplicate":
                value["services"][ROLES[0]]["directories"]["generation-journal"] = copy.deepcopy(directory)
            else:
                directory["identity"]["mode"] = stat.S_IFDIR | 0o755
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                initial.resources(canonical(value))
        with self.assertRaises(ValueError):
            initial.resources(canonical(original) + b"\n")

    def test_state_and_original_cross_bindings_refuse_changes(self):
        f = fixture()
        for field in ("preparationSha256", "resourcesSha256", "launchSha256", "endpointProcessIdentitySha256"):
            changed = fixture(); changed["state"][field] = labelled("wrong/" + field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.prepared(changed)
        for mutation in ("issued", "expiry", "owner", "unknown", "empty-digest"):
            changed = fixture()
            if mutation == "issued":
                changed["now"] = 1149
            elif mutation == "expiry":
                changed["now"] = 5000
            elif mutation == "owner":
                changed["state"]["directories"]["journal"]["identity"]["uid"] += 1
            elif mutation == "unknown":
                changed["state"]["historyExists"] = False
            else:
                changed["state"]["deploymentGenerationSha256"] = sha(b"")
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.prepared(changed)

    def test_initial_checkpoint_refuses_resigned_wrong_boundary_and_bad_signature(self):
        f = fixture(); original = f["wrapper"]["initialCheckpoint"]
        for field, value in (("checkpointSequence", 2), ("predecessorCheckpointSha256", labelled("fake-prior")),
                ("rollbackFloorConsumerSequence", 2), ("authorizedSigningKeyId", labelled("other-service"))):
            payload = copy.deepcopy(original["payload"]); payload[field] = value
            signed = checkpoint(payload, f["public"]["checkpoint"], f["keys"]["checkpoint"])
            with self.subTest(field=field), self.assertRaises(ValueError):
                initial.validate_checkpoint(f["state"], signed,
                    checkpoint_authority=f["public"]["checkpoint"], service_key=f["public"]["service"])
        signed = copy.deepcopy(original)
        raw = canonical([signed["payload"], signed["authorityKeyId"], signed["authorityKeySpkiSha256"]])
        signature = base64.urlsafe_b64decode(signed["authoritySignatureBase64"] + "==")
        signed["authoritySignatureBase64"] = encoded(bytes([signature[0] ^ 1]) + signature[1:])
        signed["checkpointSha256"] = framed(KEY_DOMAIN, (raw, signed["authoritySignatureBase64"].encode("ascii")))
        with self.assertRaises(InvalidSignature):
            initial.validate_checkpoint(f["state"], signed,
                checkpoint_authority=f["public"]["checkpoint"], service_key=f["public"]["service"])

    def test_each_anchor_signature_and_independent_root_are_required(self):
        for field in SIGNATURE_FIELDS:
            f = fixture(); history = f["wrapper"]["history"]
            anchor = history["firstRetainedEpoch"]
            signature = base64.urlsafe_b64decode(anchor[field] + "==")
            anchor[field] = encoded(bytes([signature[0] ^ 1]) + signature[1:])
            refresh_hashes(history)
            with self.subTest(signer=field), self.assertRaises(InvalidSignature):
                self.manifest(f)
        f = fixture(); f["root_pin"]["keyId"] = labelled("not-approved-root")
        with self.assertRaises(ValueError):
            self.manifest(f)

    def test_resigned_wrong_commitments_or_nonempty_history_still_refuse(self):
        for mutation in ("pruned-root", "durable-head", "records", "capacity", "extra-state"):
            f = fixture(); history = f["wrapper"]["history"]; anchor = history["firstRetainedEpoch"]
            if mutation == "pruned-root":
                anchor["prunedHistoryRootSha256"] = labelled("fake-pruned-root")
            elif mutation == "durable-head":
                anchor["retainedEpoch"]["durableEpochHeadSha256"] = labelled("fake-durable-head")
            elif mutation == "records":
                history["retention"].update(oldestReplayableRecordSequence=1, currentRecordSequence=1)
            elif mutation == "capacity":
                history["retention"]["maximumRetainedEpochs"] = 2
            else:
                f["state"]["approved"] = True
            sign_anchor(history, f["keys"])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.manifest(f)

    def test_runtime_guest_original_directory_and_deadline_joins(self):
        f = fixture(); state = f["state"]
        runtime = {"authorityHistoryRootKeyId": f["root_pin"]["keyId"],
            "authorityHistoryRootKeySpkiSha256": f["root_pin"]["keySpkiSha256"],
            "operationGeneration": state["operationGeneration"], "serviceRestartEpoch": state["serviceGeneration"],
            "deploymentGenerationSha256": state["deploymentGenerationSha256"],
            "activationDirectoryIdentities": {name: item["identity"] for name, item in state["directories"].items()}}
        guest = {name: state[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
            "invocationId", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs")}
        guest.update(serviceRole=ROLES[0], uid=31001, gid=32001, issuedAtBoottimeNs="1200")
        raw = canonical(f["wrapper"])
        self.assertEqual(initial.runtime_manifest(raw, runtime=runtime, guest=guest), f["wrapper"]["history"])
        for mutation in ("directory", "deadline", "issued", "generation"):
            r, g = copy.deepcopy(runtime), copy.deepcopy(guest)
            if mutation == "directory":
                r["activationDirectoryIdentities"]["journal"]["inode"] += 1
            elif mutation == "deadline":
                g["startupDeadlineBoottimeNs"] = "5001"
            elif mutation == "issued":
                g["issuedAtBoottimeNs"] = "1149"
            else:
                r["serviceRestartEpoch"] += 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                initial.runtime_manifest(raw, runtime=r, guest=g)

    def test_legacy_raw_history_remains_shape_only_without_initial_fallback(self):
        history, root_pin, _ = legacy_fixture()
        self.assertEqual(initial.manifest(canonical(history), role=ROLES[0], root_pin=root_pin), history)
        f = fixture(); f["wrapper"]["apiVersion"] = "serverware.custodyOrdinaryInitialHistory/v2"
        with self.assertRaises(ValueError):
            self.manifest(f)


if __name__ == "__main__":
    unittest.main()
