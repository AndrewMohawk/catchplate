#!/usr/bin/env python3
"""Local real-key protocol controls; no Cosign process, registry or trust claim."""
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import cosign_sigstore
import sigstore_json
import sign_release_images
import verify_release_completion as completion


def wire(value: object) -> bytes:
    # Independent preimage serializer: intentionally not the helper under test.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class SigstoreJsonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.signer = ec.generate_private_key(ec.SECP256R1())
        cls.rekor = ec.generate_private_key(ec.SECP256R1())
        cls.signer_pem = cls.signer.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        cls.rekor_pem = cls.rekor.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        cls.signer_id = completion.release_public_key_id(cls.signer_pem)
        cls.rekor_id = completion.release_public_key_id(cls.rekor_pem)

    def proof(self, statement: dict, *, strings: bool = True) -> dict:
        statement_digest = digest(wire(statement))
        signature = b64(self.signer.sign(wire(statement), ec.ECDSA(hashes.SHA256())))
        body = wire({
            "apiVersion": "0.0.1", "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {"algorithm": "sha256", "value": statement_digest[7:]}},
                "signature": {"content": signature, "publicKey": {"content": b64(self.signer_pem.encode("ascii"))}},
            },
        })
        timestamp = 1779830000
        set_bytes = wire({"body": b64(body), "integratedTime": timestamp,
                          "logID": self.rekor_id[7:], "logIndex": 0})
        root = hashlib.sha256(b"\x00" + body).digest()
        note = f"rekor.local.test - 1\n1\n{b64(root)}\n"
        note_signature = self.rekor.sign(note.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        envelope = note + "\n\u2014 rekor.local.test " + b64(bytes.fromhex(self.rekor_id[7:])[:4] + note_signature) + "\n"
        number = str if strings else int
        inclusion = {"treeSize": number(1), "logIndex": number(0), "rootHash": b64(root),
                     "hashes": [], "checkpoint": {"envelope": envelope}}
        entry = {
            "logIndex": number(0), "integratedTime": number(timestamp),
            "logId": {"keyId": b64(bytes.fromhex(self.rekor_id[7:]))},
            "canonicalizedBody": b64(body), "inclusionProof": inclusion,
            "inclusionPromise": {"signedEntryTimestamp": b64(self.rekor.sign(set_bytes, ec.ECDSA(hashes.SHA256())))},
        }
        return {
            "ok": True, "provider": "cosign", "signature": signature,
            "statement_digest": statement_digest,
            "key_provider": {"type": "sigstore-key", "key_id": self.signer_id},
            "transparency": {"log_id": self.rekor_id, "entry_uuid": "local-real-signature-control",
                             "integrated_time": number(timestamp), "log_index": number(0),
                             "inclusion_proof": copy.deepcopy(inclusion)},
            "bundle": {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "messageSignature": {"messageDigest": {"algorithm": "SHA2_256", "digest": b64(bytes.fromhex(statement_digest[7:]))},
                                     "signature": signature},
                "verificationMaterial": {"publicKey": {"hint": b64(bytes.fromhex(self.signer_id[7:]))}, "tlogEntries": [entry]},
            },
        }

    def image_payload(self, *, strings: bool = True) -> dict:
        statement = {"subject": [{"name": "local-image", "digest": {"sha256": "a" * 64}}], "predicate": {"rollbackEpoch": 1}}
        proof = self.proof(statement, strings=strings)
        return {"apiVersion": "serverware.imageSignatures/v1", "kind": "ImageSignatureBundle",
                "metadata": {"sourceTreeDigest": "sha256:" + "b" * 64},
                "images": [{"service": "local-image", "statement": statement,
                            "signature": proof["signature"], "statement_digest": proof["statement_digest"], "sigstore": proof}]}

    def verify(self, statement: dict, proof: dict, *, expected_digest: str | None = None) -> None:
        completion.verify_sigstore_bundle_binding(
            proof, expected_statement=statement,
            expected_statement_digest=expected_digest or proof["statement_digest"],
            expected_signature=proof["signature"], trusted_signing_public_key_pem=self.signer_pem,
            expected_signing_key_id=self.signer_id, expected_rekor_log_id=self.rekor_id,
            trusted_rekor_public_key_pem=self.rekor_pem, label="local fixture",
        )

    def test_decimal_string_and_integer_bundles_authenticate_without_rewriting(self) -> None:
        for strings in (True, False):
            with self.subTest(strings=strings):
                payload = self.image_payload(strings=strings)
                outer = self.proof(payload, strings=strings)
                before = copy.deepcopy((payload, outer))
                self.verify(payload["images"][0]["statement"], payload["images"][0]["sigstore"])
                self.verify(payload, outer)
                self.assertEqual(sigstore_json.statement_json(payload).encode("utf-8"), wire(payload))
                self.assertEqual((payload, outer), before)

    def test_representation_substitution_is_not_normalized_before_authentication(self) -> None:
        payload = self.image_payload()
        outer = self.proof(payload)
        changed = copy.deepcopy(payload)
        inner = changed["images"][0]["sigstore"]
        inner["bundle"]["verificationMaterial"]["tlogEntries"][0]["logIndex"] = 0
        inner["transparency"]["log_index"] = 0
        self.assertNotEqual(wire(payload), wire(changed))
        with self.assertRaisesRegex(ValueError, "expected statement digest mismatch"):
            self.verify(changed, outer)
        new_digest = digest(wire(changed))
        with self.assertRaisesRegex(ValueError, "Sigstore bundle digest mismatch"):
            self.verify(changed, outer, expected_digest=new_digest)
        rebound = copy.deepcopy(outer)
        rebound["statement_digest"] = new_digest
        rebound["bundle"]["messageSignature"]["messageDigest"]["digest"] = b64(bytes.fromhex(new_digest[7:]))
        with self.assertRaisesRegex(ValueError, "Sigstore message signature verification failed"):
            self.verify(changed, rebound)
        # A newly signed statement may legitimately use the integer form.
        self.verify(changed, self.proof(changed))

    def test_decimal_bounds_and_malformed_values(self) -> None:
        for value in (0, "0", (1 << 63) - 1, str((1 << 63) - 1)):
            self.assertEqual(sigstore_json.parse_nonnegative_int64(value, "counter"), int(value))
            self.assertEqual(completion.parse_nonnegative_int64(value, "counter"), int(value))
        invalid = [True, False, None, 0.0, -1, "-1", "+1", "01", "1.0", "1e3", " 1", "1 ", "", "\u0661"]
        overflow = [(1 << 63), str(1 << 63), "9" * 5000]
        for value in invalid + overflow:
            with self.subTest(value=str(value)[:30]):
                with self.assertRaisesRegex(ValueError, "counter (is invalid|is outside int64 range)"):
                    sigstore_json.parse_nonnegative_int64(value, "counter")
                bundle = self.proof({"payload": "test"})["bundle"]
                bundle["verificationMaterial"]["tlogEntries"][0]["logIndex"] = value
                with self.assertRaisesRegex(ValueError, "logIndex (is invalid|is outside int64 range)"):
                    sigstore_json.validate(bundle, scope="bundle")

    def test_serverware_counters_and_unrecognized_paths_remain_integer_only(self) -> None:
        for field in ("rollbackEpoch", "sequence", "generation", "ordinal", "logIndex", "treeSize"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, f"{field} must be an unsigned integer"):
                    completion.canonical_json({field: "1"})
                payload = self.image_payload()
                payload["metadata"][field] = "1"
                with self.assertRaisesRegex(ValueError, f"{field} must be an unsigned integer"):
                    sigstore_json.statement_json(payload)
        payload = self.image_payload()
        payload["images"][0]["statement"]["predicate"]["logIndex"] = "0"
        with self.assertRaisesRegex(ValueError, "logIndex must be an unsigned integer"):
            sigstore_json.statement_json(payload)
        with self.assertRaisesRegex(ValueError, "log_index must be an unsigned integer"):
            completion.canonical_json(self.image_payload())

    def test_json_duplicates_floats_and_ambiguous_aliases_fail_closed(self) -> None:
        for data, error in ((b'{"a":1,"a":2}', "duplicate JSON object key"),
                            (b'{"a":1.0}', "non-integer JSON number"),
                            (b'{"a":NaN}', "non-integer JSON number")):
            with self.assertRaisesRegex(ValueError, error):
                sigstore_json.parse_json(data)
        bundle = self.proof({"payload": "test"})["bundle"]
        entry = bundle["verificationMaterial"]["tlogEntries"][0]
        entry["log_index"] = entry["logIndex"]
        with self.assertRaisesRegex(ValueError, "requires exactly one of logIndex, log_index"):
            sigstore_json.validate(bundle, scope="bundle")
        del entry["log_index"]
        bundle["tlogEntries"] = copy.deepcopy(bundle["verificationMaterial"]["tlogEntries"])
        with self.assertRaisesRegex(ValueError, "exactly one transparency entry location"):
            sigstore_json.validate(bundle, scope="bundle")
        del bundle["tlogEntries"]
        bundle["verificationMaterial"]["tlogEntries"].append(copy.deepcopy(entry))
        with self.assertRaisesRegex(ValueError, "exactly one transparency entry$"):
            sigstore_json.validate(bundle, scope="bundle")

    def test_crypto_and_merkle_guards_are_not_replaced_by_shape_validation(self) -> None:
        statement = {"payload": "test"}
        proof = self.proof(statement)
        bad = copy.deepcopy(proof)
        bad["transparency"]["integrated_time"] = "1779830001"
        with self.assertRaisesRegex(ValueError, "bundle/top-level integrated_time mismatch"):
            self.verify(statement, bad)
        bad = copy.deepcopy(proof)
        entry = bad["bundle"]["verificationMaterial"]["tlogEntries"][0]
        entry["inclusionPromise"]["signedEntryTimestamp"] = b64(self.signer.sign(b"wrong SET", ec.ECDSA(hashes.SHA256())))
        with self.assertRaisesRegex(ValueError, "signed entry timestamp signature verification failed"):
            self.verify(statement, bad)
        for field, value, error in (
            ("logIndex", "1", "inclusion log index is invalid"),
            ("hashes", [b64(bytes(32))], "inclusion proof has extra hashes"),
            ("rootHash", b64(bytes(32)), "Merkle inclusion proof did not verify"),
        ):
            bad = copy.deepcopy(proof)
            bad["transparency"]["inclusion_proof"][field] = value
            bad["bundle"]["verificationMaterial"]["tlogEntries"][0]["inclusionProof"][field] = value
            with self.assertRaisesRegex(ValueError, error):
                self.verify(statement, bad)
        bad = copy.deepcopy(proof)
        checkpoint = bad["transparency"]["inclusion_proof"]["checkpoint"]
        checkpoint["envelope"] = checkpoint["envelope"].replace("rekor.local.test - 1", "rekor.local.test - 2", 1)
        bad["bundle"]["verificationMaterial"]["tlogEntries"][0]["inclusionProof"] = copy.deepcopy(bad["transparency"]["inclusion_proof"])
        with self.assertRaisesRegex(ValueError, "checkpoint signature verification failed"):
            self.verify(statement, bad)

    def test_artifact_loader_and_cosign_adapter_preserve_original_values(self) -> None:
        payload = self.image_payload()
        outer = self.proof(payload)
        document = copy.deepcopy(payload)
        document["bundle_signature"] = outer
        document["metadata"]["bundleSigstore"] = copy.deepcopy(outer)
        document["image_signature_bundle_digest"] = digest(wire(payload))
        raw = wire(document)
        snapshot = SimpleNamespace(data=raw, path=Path("local-image-signatures.json"))
        self.assertEqual(completion.load_image_signatures_json_snapshot(snapshot), document)
        for encoding in ("utf-16", "utf-32", "utf-8-sig"):
            with self.subTest(encoding=encoding):
                invalid = SimpleNamespace(data=raw.decode("utf-8").encode(encoding), path=snapshot.path)
                with self.assertRaises(ValueError):
                    completion.load_image_signatures_json_snapshot(invalid)
        with self.assertRaisesRegex(ValueError, "logIndex must be an unsigned integer"):
            completion.load_json_bytes(raw, snapshot.path, "ordinary Serverware document")
        with patch.object(Path, "read_bytes", return_value=wire(outer["bundle"])):
            self.assertEqual(cosign_sigstore.load_bundle(Path("local.bundle.json")), outer["bundle"])
        with patch.dict("os.environ", {"SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID": ""}):
            transparency = cosign_sigstore.transparency_from_bundle(outer["bundle"])
        self.assertEqual(transparency["log_index"], "0")
        self.assertEqual(transparency["inclusion_proof"], outer["transparency"]["inclusion_proof"])
        request = {"apiVersion": "serverware.sigstoreSignRequest/v1", "kind": "image-signature-bundle",
                   "statement": payload, "statement_digest": digest(wire(payload))}
        cosign_sigstore.validate_statement_request(request)
        request["kind"] = "oci-image-statement"
        with self.assertRaisesRegex(ValueError, "request kind does not match statement schema"):
            cosign_sigstore.validate_statement_request(request)
        with patch.object(Path, "write_text") as write:
            cosign_sigstore.write_statement(Path("local.statement.json"), payload)
        self.assertEqual(write.call_args.args[0].encode("utf-8"), wire(payload))

    def test_release_signing_command_boundary_is_scoped_and_representation_exact(self) -> None:
        payload = self.image_payload()
        proof = self.proof(payload)
        verified = {"ok": True, "statement_digest": proof["statement_digest"], "key_provider": proof["key_provider"],
                    "verified_transparency": True, "transparency": copy.deepcopy(proof["transparency"])}
        with patch.object(sign_release_images, "run_json_command", side_effect=[proof, verified]) as command:
            result = sign_release_images.external_sign_statement(
                command="never-executed-sign", verify_command="never-executed-verify", require_transparency=True,
                kind="image-signature-bundle", service="bundle", image_id=None, statement=payload,
            )
        self.assertEqual(result, proof)
        self.assertEqual(command.call_count, 2)
        for call in command.call_args_list:
            self.assertEqual(wire(call.args[1]["statement"]), wire(payload))
            self.assertEqual(call.args[1]["statement_digest"], digest(wire(payload)))
        malformed = copy.deepcopy(proof)
        malformed["transparency"]["log_index"] = True
        with self.assertRaisesRegex(ValueError, "log_index is invalid"):
            sign_release_images.validate_sigstore_response(malformed, statement_digest=proof["statement_digest"], require_transparency=True)
        verified["transparency"]["log_index"] = 0
        with self.assertRaisesRegex(RuntimeError, "different transparency log_index"):
            sign_release_images.validate_sigstore_verify_response(
                verified, signature_response=proof, statement_digest=proof["statement_digest"], require_transparency=True,
            )
        # Real parser, mocked process boundary: duplicate responses must never
        # collapse to whichever authority field happens to occur last.
        duplicate = SimpleNamespace(returncode=0, stdout=b'{"ok":false,"ok":true}', stderr=b"")
        with patch.object(sign_release_images.subprocess, "run", return_value=duplicate):
            with self.assertRaisesRegex(RuntimeError, "returned invalid JSON"):
                sign_release_images.run_json_command("never-executed", {})

    def test_final_image_verifier_checks_representation_exact_payload_digest(self) -> None:
        payload = self.image_payload()
        document = copy.deepcopy(payload)
        bundle_digest = digest(wire(payload))
        document["image_signature_bundle_digest"] = bundle_digest
        provenance_digest = "sha256:" + "c" * 64
        provenance = {"provenance_digest": provenance_digest, "release_signing_key_id": self.signer_id}
        summary = {"ok": True, "image_signatures": "pass", "image_signature_provider": "sigstore-command",
                   "inclusion_verified": True, "provenance_digest": provenance_digest,
                   "release_signing_key_id": self.signer_id, "image_signing_key_id": self.signer_id,
                   "image_signature_bundle_digest": bundle_digest, "images": 1}

        def verify_document(value: dict) -> None:
            completion.verify_image_signatures(
                summary, value, provenance, [], [], self.signer_id, self.rekor_id,
                "unused-local-boundary", self.rekor_id, self.signer_pem, self.rekor_pem, self.rekor_pem,
            )

        # Deliberately incomplete release metadata is rejected AFTER the real
        # image-payload digest guard. This is not an accepted release fixture.
        with self.assertRaisesRegex(ValueError, "metadata provenance digest mismatch"):
            verify_document(document)
        document["images"][0]["sigstore"]["transparency"]["log_index"] = 0
        with self.assertRaisesRegex(ValueError, "image signature bundle payload digest mismatch"):
            verify_document(document)

    def test_production_call_sites_use_the_scoped_boundary(self) -> None:
        # Complements direct call tests without executing the CLI, Docker, or
        # the full release fixture (which has independent source/host inputs).
        source = Path(completion.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        calls = lambda node: {ast.unparse(call.func) for call in ast.walk(node) if isinstance(call, ast.Call)}
        self.assertIn("load_image_signatures_json_snapshot", calls(functions["main"]))
        self.assertIn("sigstore_json.statement_json", calls(functions["verify_image_signatures"]))
        self.assertIn("sigstore_json.statement_json", calls(functions["verify_sigstore_bundle_binding"]))
        handoff = ast.parse(Path(__file__).with_name("generate_production_handoff.py").read_text(encoding="utf-8"))
        scope = next(node for node in handoff.body if isinstance(node, ast.FunctionDef) and node.name == "image_signature_scope")
        self.assertIn("completion.verify_sigstore_bundle_binding", calls(scope))


if __name__ == "__main__":
    unittest.main()
