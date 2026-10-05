"""UNRUN transport-codec controls; raw framing is not proof admission.

Native chunks are consumed by the actual source codec. Independent trees give
real primary proofs; counted descriptors are deliberately synthetic untrusted
records because only their framing is in scope here. No SQL/current-root,
compound schedule, signature or authority claim is made.
"""
from __future__ import annotations

import ast
import copy
from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_jit_original_frames as source
from serverware import authority_primary_original_reader as primary_reader
from test_authority_jit_primary_chunks import frames, meter, native, query, row
from test_authority_radix_mutation import IndependentTree


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def index_input(identity=None):
    # This intentionally does not purport to be a coherent Merkle frontier.
    return source.indexed.IndexedMutationInput(identity or source.heads._jit_receipt_ids()[0], 7,
        source.CountedNode("sha256:" + "a" * 64, 2),
        (source.IndexLeaf("01" * 80, "sha256:" + "b" * 64, "sha256:" + "c" * 64),
         source.OpaqueSubtree("f", "sha256:" + "d" * 64, 1)))


class JitOriginalFrameControls(unittest.TestCase):
    def test_last_consumed_native_bytes_round_trip_into_same_actual_codec(self):
        expected = row(4)
        expected["bundle_json"] = ""
        prefix = native(expected).index(b'"bundle_json": "') + len(b'"bundle_json": "')
        expected["bundle_json"] = "x" * (source.chunks.CHUNK_BYTES - prefix - 1) + "\U0001f642" + "tail"
        native_bytes = native(expected)
        originals = frames(native_bytes)
        self.assertEqual(native_bytes[source.chunks.CHUNK_BYTES - 1], 0xf0)
        produced = source.chunks.JitPrimaryRowChunks(query(4), work=meter())
        replayed = source.chunks.JitPrimaryRowChunks(query(4), work=meter())
        for original in originals:
            held = copy.deepcopy(original)
            produced.accept([held], work=meter())
            held["chunk_hex"] = "00"  # Original caller alias is no longer the source.
            work = meter()
            encoded = source.encode_consumed_chunk(produced, work=work)
            self.assertEqual(encoded, canonical([original]))
            self.assertLessEqual(len(encoded), source.MAX_CHUNK_BYTES)
            self.assertEqual(work.hash_work, 0)
            decoded = source.decode_chunk(encoded, work=meter())
            replayed.accept(decoded, work=meter())
        self.assertEqual(produced.finish(work=meter()), expected)
        self.assertEqual(replayed.finish(work=meter()), expected)
        self.assertEqual(produced.native_bytes, replayed.native_bytes)
        self.assertEqual(produced.data_chunks, 2)

    def test_literal_absence_requires_consumption_and_cannot_use_finished_codec(self):
        codec = source.chunks.JitPrimaryRowChunks(query(), work=meter())
        with self.assertRaises(ValueError):
            source.encode_consumed_chunk(codec, work=meter())
        codec.accept([], work=meter())
        self.assertEqual(source.encode_consumed_chunk(codec, work=meter()), b"[]")
        self.assertEqual(source.decode_chunk(b"[]", work=meter()), [])
        self.assertIsNone(codec.finish(work=meter()))
        with self.assertRaises(ValueError):
            source.encode_consumed_chunk(codec, work=meter())

    def test_chunk_shape_canonical_types_lengths_and_original_work_are_fixed(self):
        original = frames(native(row()))[0]
        for defect in ("extra", "bool", "ordinal", "offset", "hex", "length", "duplicate"):
            changed = copy.deepcopy(original)
            if defect == "extra": changed["success"] = True
            elif defect == "bool": changed["total_bytes"] = True
            elif defect == "ordinal": changed["chunk_ordinal"] = 33
            elif defect == "offset": changed["chunk_offset"] = 1
            elif defect == "hex": changed["chunk_hex"] = "FF" + changed["chunk_hex"][2:]
            elif defect == "length": changed["chunk_hex"] = changed["chunk_hex"][:-2]
            raw = canonical([changed, changed] if defect == "duplicate" else [changed])
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                source.decode_chunk(raw, work=meter())
        for raw in (b"[ ]", b"[null]", b"{}", canonical([original]) + b"\n"):
            with self.assertRaises(ValueError):
                source.decode_chunk(raw, work=meter())
        codec = source.chunks.JitPrimaryRowChunks(query(), work=meter())
        codec.accept([original], work=meter())
        held = codec.native_bytes, codec.data_chunks, codec.complete
        work = meter(max_input_bytes=512)
        limits = work.limits
        with self.assertRaises(ValueError):
            source.encode_consumed_chunk(codec, work=work)
        self.assertIs(work.limits, limits)
        self.assertEqual((codec.native_bytes, codec.data_chunks, codec.complete), held)

    def test_real_primary_proof_round_trip_retains_raw_truth_obligation(self):
        tree = IndependentTree([{"id": "one", "value": "synthetic"}], table="webauthn_challenges")
        for identity in ("one", "missing"):
            selected = tree.selected({"id": identity})
            proof = tree.proof(selected)
            work = meter()
            encoded = source.encode_proof(proof, work=work)
            self.assertEqual(encoded, canonical(proof))
            self.assertEqual(source.decode_proof(encoded, work=meter()), proof)
            self.assertEqual(work.hash_work, 0)
        selected = tree.selected({"id": "one"})
        changed = tree.proof(selected)
        changed["proofDigest"] = "sha256:" + "f" * 64
        # A canonical digest-shaped claim is still raw/untrusted after decode.
        decoded = source.decode_proof(source.encode_proof(changed, work=meter()), work=meter())
        contract = next(value for value in source.primary_contract.primary_table_contracts(source.OPERATION)
            if value.table == tree.table)
        with self.assertRaises(ValueError):
            primary_reader._membership(selected, decoded, tree.root, contract, meter())

    def test_proof_fixed_inventory_pk_vectors_and_exact_scalar_shapes(self):
        for contract in source.primary_contract.primary_table_contracts(source.OPERATION):
            self.assertEqual(len(contract.key_columns), 1)
            key = {contract.key_columns[0]: "one"}
            tree = IndependentTree([], table=contract.table, columns=contract.key_columns)
            proof = tree.proof(tree.selected(key))
            self.assertEqual(source.decode_proof(source.encode_proof(proof, work=meter()), work=meter()), proof)
        tree = IndependentTree([], table="webauthn_challenges")
        proof = tree.proof(tree.selected({"id": "one"}))
        for defect in ("table", "key", "present", "root-revision", "level", "slots", "prefix", "extra"):
            changed = copy.deepcopy(proof)
            if defect == "table": changed["table"] = "unselected_table"
            elif defect == "key": changed["key"] = {"not_id": "one"}
            elif defect == "present": changed["present"] = 0
            elif defect == "root-revision": changed["rootRevision"] = False
            elif defect == "level": changed["siblings"] = changed["siblings"][:-1]
            elif defect == "slots": changed["siblings"][0]["childDigests"] = []
            elif defect == "prefix": changed["siblings"][1]["pathPrefix"] = "zz"
            else: changed["admitted"] = True
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                source.decode_proof(canonical(changed), work=meter())
        duplicate = canonical(proof).replace(b'"present":false', b'"present":false,"present":false')
        with self.assertRaises(ValueError):
            source.decode_proof(duplicate, work=meter())

    def test_all_twelve_index_inputs_round_trip_without_a_head_or_fold_verdict(self):
        for identity in source.heads._jit_receipt_ids():
            original = index_input(identity)
            work = meter()
            encoded = source.encode_index(original, work=work)
            actual = source.decode_index(encoded, work=meter())
            self.assertEqual(actual, original)
            self.assertIsNot(actual, original)
            self.assertIsNot(actual.frontier[0], original.frontier[0])
            self.assertEqual(work.hash_work, 0)
        original = index_input()
        changed = replace(original, index_root=source.CountedNode("sha256:" + "f" * 64, 2))
        self.assertEqual(source.decode_index(source.encode_index(changed, work=meter()), work=meter()), changed)
        # Independent owner head equality and actual sparse replay are required
        # elsewhere. This codec intentionally cannot assert either one.

    def test_index_unknown_profiles_records_alias_types_and_frame_caps_refuse(self):
        original = json.loads(source.encode_index(index_input(), work=meter()))
        for defect in ("index", "revision", "count", "root", "kind", "leaf", "opaque", "extra"):
            changed = copy.deepcopy(original)
            if defect == "index": changed["indexId"] = "caller_index"
            elif defect == "revision": changed["indexRevision"] = True
            elif defect == "count": changed["rootCount"] = True
            elif defect == "root": changed["rootDigest"] = "not-a-digest"
            elif defect == "kind": changed["frontier"][0]["kind"] = "success"
            elif defect == "leaf": changed["frontier"][0]["key"] = "0"
            elif defect == "opaque": changed["frontier"][1]["prefix"] = ""
            else: changed["frontier"][0]["verdict"] = True
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                source.decode_index(canonical(changed), work=meter())
        for decode, maximum in ((source.decode_chunk, source.MAX_CHUNK_BYTES),
                (source.decode_proof, source.MAX_PROOF_BYTES), (source.decode_index, source.MAX_INDEX_BYTES)):
            work = meter()
            with self.assertRaises(ValueError):
                decode(b" " * (maximum + 1), work=work)
            self.assertEqual(work.input_bytes, 0)
            self.assertEqual(work.json_nodes, 0)
        self.assertEqual(source.MAX_INDEX_BYTES, 4 * 1024 * 1024)
        self.assertEqual(source.MAX_PROOF_BYTES, 128 * 1024)

    def test_no_new_meter_clock_sql_hash_admission_or_source_state_consumption(self):
        parsed = ast.parse((Path(__file__).resolve().parents[1]
            / "serverware/authority_jit_original_frames.py").read_text())
        forbidden = {"_ValidationWork", "QueryReadValidationLimits", "_ReadAcquisitionBudget",
            "connect", "execute", "commit", "accept", "finish", "_membership", "_verify_primary",
            "_evaluate_one_index", "evaluate_index_mutations", "sha256", "monotonic_ns", "time_ns"}
        calls = {node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            for node in ast.walk(parsed) if isinstance(node, ast.Call)
            and isinstance(node.func, (ast.Name, ast.Attribute))}
        self.assertFalse(calls & forbidden)


if __name__ == "__main__":
    unittest.main()
