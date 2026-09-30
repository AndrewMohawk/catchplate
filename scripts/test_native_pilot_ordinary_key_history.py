#!/usr/bin/env python3
"""Four bounded SYNTHETIC fresh-history controls, never admission evidence.

Deterministic test-only Ed25519 seeds and signatures exist only in this
in-memory unittest fixture. They are not provisioned keys, approval, real
process measurements, or a first-checkpoint/retained-anchor ceremony. These
controls call only the pure history verifier, never authority.sign, protected
CLI/owners, kernel observation, network, or service execution.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))

from serverware import native_pilot_ordinary_key_authority as authority
from test_native_pilot_ordinary_keys import identity_fixture

API = "serverware.policyCustodyAuthorityHistory/v3"
ROLE = "durable-recovery-store"
EPOCH_DOMAIN = b"serverware.policyCustodyAuthorityEpochStatement/v3"
ANCHOR_SIGNATURE_DOMAIN = b"serverware.policyCustodyRetainedAuthorityEpochAnchor/v3"
ANCHOR_DIGEST_DOMAIN = b"serverware.policyCustodyRetainedAuthorityEpochAnchorDigest/v3"
HISTORY_DOMAIN = b"serverware.policyCustodyAuthorityHistoryManifest/v3"
HISTORY_FIELDS = ("apiVersion", "authorityRole", "rootAuthority", "retention", "firstRetainedEpoch",
    "adjacentTransitions", "compactionAnchors", "replayTombstones")
ANCHOR_FIELDS = ("apiVersion", "retainedEpoch", "prunedThroughEpochSequence", "prunedHistoryRootSha256",
    "prunedTerminalEpochSha256", "rootAuthorityKeyId", "rootAuthorityKeySpkiSha256")
SIGNATURE_FIELDS = ("rootSignatureBase64", "checkpointAuthoritySignatureBase64", "serviceKeySignatureBase64")


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _synthetic(label):
    return _sha(("SYNTHETIC ORDINARY HISTORY TEST ONLY / " + label).encode("ascii"))


def _encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _frame(domain, *parts):
    return _sha(domain + b"\0" + b"".join(len(part).to_bytes(8, "big") + part for part in parts))


def _raw_public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _public(key, label):
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"keyId": _synthetic("key-id/" + label), "keySpkiSha256": _sha(der),
        "publicKeySpkiBase64": _encoded(der)}


def _refresh_manifest(history):
    history["manifestSha256"] = _frame(HISTORY_DOMAIN,
        _canonical([history[field] for field in HISTORY_FIELDS]))


def _refresh_anchor_hash(history):
    anchor = history["firstRetainedEpoch"]
    anchor["retainedAnchorSha256"] = _frame(ANCHOR_DIGEST_DOMAIN,
        _canonical([anchor[field] for field in ANCHOR_FIELDS]),
        *(anchor[field].encode("ascii") for field in SIGNATURE_FIELDS))
    _refresh_manifest(history)


def _fixture(*, reused_pair=None):
    # Deliberately deterministic, public test seeds. Never use them outside
    # this synthetic fixture or describe its observations as kernel evidence.
    names = ("root", "checkpoint", "service")
    keys = {name: Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
        ("SYNTHETIC ORDINARY HISTORY TEST SEED / " + name).encode("ascii")).digest()) for name in names}
    if reused_pair is not None:
        source, destination = reused_pair
        keys[destination] = keys[source]
    public = {name: _public(keys[name], name) for name in names}
    identity = identity_fixture()
    role = {"authorityKind": "isolated-service", "role": ROLE}
    epoch = {"apiVersion": API, "authorityRole": role, "authorityEpochSequence": 1,
        "predecessorEpochSha256": None, "checkpointSequence": 7,
        "checkpointSha256": _synthetic("supplied-prior-checkpoint"), "checkpointAuthority": public["checkpoint"],
        "serviceSigningKey": public["service"], "endpointProcessIdentity": identity,
        "endpointProcessIdentitySha256": identity["identitySha256"], "endpointGeneration": 11,
        "serviceGeneration": 13, "operationGeneration": 17, "durableEpoch": 19,
        "durableEpochHeadSha256": _synthetic("durable-head"),
        "deploymentGenerationSha256": _synthetic("deployment")}
    epoch["epochSha256"] = _frame(EPOCH_DOMAIN, _canonical([
        [epoch[field] for field in ("apiVersion", "authorityRole", "authorityEpochSequence", "predecessorEpochSha256")],
        [epoch[field] for field in ("checkpointSequence", "checkpointSha256", "checkpointAuthority", "serviceSigningKey")],
        [epoch[field] for field in ("endpointProcessIdentity", "endpointProcessIdentitySha256", "endpointGeneration", "serviceGeneration")],
        [epoch[field] for field in ("operationGeneration", "durableEpoch", "durableEpochHeadSha256", "deploymentGenerationSha256")],
    ]))
    anchor = {"apiVersion": API, "retainedEpoch": epoch, "prunedThroughEpochSequence": 0,
        "prunedHistoryRootSha256": _synthetic("supplied-pruned-history-root"), "prunedTerminalEpochSha256": None,
        "rootAuthorityKeyId": public["root"]["keyId"], "rootAuthorityKeySpkiSha256": public["root"]["keySpkiSha256"]}
    raw = _canonical([anchor[field] for field in ANCHOR_FIELDS])
    preimage = (b"serverware-signature-v1\0" + len(ANCHOR_SIGNATURE_DOMAIN).to_bytes(8, "big")
        + ANCHOR_SIGNATURE_DOMAIN + len(raw).to_bytes(8, "big") + raw)
    for field, name in zip(SIGNATURE_FIELDS, names, strict=True):
        anchor[field] = _encoded(keys[name].sign(preimage))
    retention = {"oldestRetainedEpochSequence": 1, "currentEpochSequence": 1,
        "oldestRetainedCheckpointSequence": 7, "currentCheckpointSequence": 7,
        "oldestRetainedEndpointGeneration": 11, "currentEndpointGeneration": 11,
        "oldestRetainedServiceGeneration": 13, "currentServiceGeneration": 13,
        "oldestRetainedOperationGeneration": 17, "currentOperationGeneration": 17,
        "oldestRetainedDurableEpoch": 19, "currentDurableEpoch": 19,
        "oldestReplayableRecordSequence": 0, "currentRecordSequence": 0,
        "oldestRetainedCompactionSequence": 0, "currentCompactionSequence": 0,
        "maximumRetainedEpochs": 1, "maximumCompactionAnchors": 1, "maximumReplayTombstones": 1}
    history = {"apiVersion": API, "authorityRole": role, "rootAuthority": public["root"],
        "retention": retention, "firstRetainedEpoch": anchor, "adjacentTransitions": [],
        "compactionAnchors": [], "replayTombstones": []}
    _refresh_anchor_hash(history)
    root_pin = {field: public["root"][field] for field in ("keyId", "keySpkiSha256")}
    return history, root_pin, _raw_public(keys["checkpoint"])


class SyntheticFreshHistoryControls(unittest.TestCase):
    def test_valid_three_signatures_select_exact_checkpoint_key(self):
        history, root_pin, expected_key = _fixture()
        epoch, key = authority._history(_canonical(history), role=ROLE, root_pin=root_pin)
        self.assertEqual(epoch, history["firstRetainedEpoch"]["retainedEpoch"])
        self.assertEqual(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), expected_key)

    def test_wrong_independent_root_pin_refused(self):
        history, root_pin, _ = _fixture()
        for field in ("keyId", "keySpkiSha256"):
            with self.subTest(field=field):
                wrong = dict(root_pin)
                wrong[field] = _synthetic("wrong-independent-root/" + field)
                with self.assertRaises(ValueError):
                    authority._history(_canonical(history), role=ROLE, root_pin=wrong)

    def test_each_altered_or_missing_signer_refused(self):
        history, root_pin, _ = _fixture()
        for field in SIGNATURE_FIELDS:
            with self.subTest(field=field, mutation="signature-bit"):
                changed = copy.deepcopy(history)
                signature = base64.urlsafe_b64decode(changed["firstRetainedEpoch"][field] + "==")
                changed["firstRetainedEpoch"][field] = _encoded(bytes([signature[0] ^ 1]) + signature[1:])
                _refresh_anchor_hash(changed)  # Keep hashes valid: reject the actual signature.
                with self.assertRaises(InvalidSignature):
                    authority._history(_canonical(changed), role=ROLE, root_pin=root_pin)
            with self.subTest(field=field, mutation="missing-signer"):
                missing = copy.deepcopy(history)
                del missing["firstRetainedEpoch"][field]
                _refresh_manifest(missing)
                with self.assertRaises(ValueError):
                    authority._history(_canonical(missing), role=ROLE, root_pin=root_pin)

    def test_reused_material_and_nonempty_history_refused(self):
        for pair in (("root", "checkpoint"), ("root", "service"), ("checkpoint", "service")):
            with self.subTest(reused_pair=pair):
                history, root_pin, _ = _fixture(reused_pair=pair)
                # IDs stay distinct and every signature/hash is recomputed;
                # same underlying key material must still be refused.
                with self.assertRaises(ValueError):
                    authority._history(_canonical(history), role=ROLE, root_pin=root_pin)
        history, root_pin, _ = _fixture()
        for field in ("adjacentTransitions", "compactionAnchors", "replayTombstones"):
            with self.subTest(nonempty=field):
                changed = copy.deepcopy(history)
                changed[field] = [{"syntheticUnsupportedHistory": True}]
                _refresh_manifest(changed)
                with self.assertRaises(ValueError):
                    authority._history(_canonical(changed), role=ROLE, root_pin=root_pin)


if __name__ == "__main__":
    unittest.main()
