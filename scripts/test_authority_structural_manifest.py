#!/usr/bin/env python3
"""Pure actual manifest-codec controls; no SQL, owner or admission simulation."""
from __future__ import annotations

import ast
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from catchplate import authority_contract, db
from catchplate.authority_store import metadata_schema_source, schema


class StructuralManifestTests(unittest.TestCase):
    def test_source_contract_preserves_frozen_mutation_templates(self):
        captured = []
        original_dumps = schema.dumps

        def observe(value):
            # Observe the actual payload, delegating unchanged strict encoding.
            captured.append(value)
            return original_dumps(value)

        with patch.object(schema, "dumps", side_effect=observe):
            digest = db._policy_candidate_authority_source_contract_digest()
        self.assertEqual(len(captured), 1)
        material = captured[0]
        grants = material["sqlGrantManifest"]
        self.assertEqual(set(grants), set(authority_contract.SQL_GRANT_MANIFEST))
        count = 0
        for operation, source in authority_contract.SQL_GRANT_MANIFEST.items():
            actual = grants[operation]["mutationTemplates"]
            self.assertEqual(actual, [dict(template) for template in source["mutationTemplates"]])
            self.assertTrue(all(type(template) is dict for template in actual))
            count += len(actual)
        self.assertGreater(count, 0)
        domain = "catchplate.policyCandidateAuthoritySourceContract/v1"
        self.assertEqual(digest, db._policy_candidate_authority_framed_digest(
            domain, original_dumps(material).encode("utf-8")))
        operation = next(name for name, grant in grants.items() if grant["mutationTemplates"])
        grants[operation]["mutationTemplates"][0]["changedForControl"] = True
        self.assertNotEqual(digest, db._policy_candidate_authority_framed_digest(
            domain, original_dumps(material).encode("utf-8")))
        self.assertNotIn("changedForControl", authority_contract.SQL_GRANT_MANIFEST[operation]["mutationTemplates"][0])
        with self.assertRaises(TypeError):
            original_dumps(authority_contract.SQL_GRANT_MANIFEST[operation]["mutationTemplates"][0])

    def test_structural_bound_does_not_widen_authority_messages(self):
        maximum = schema._POLICY_CANDIDATE_AUTHORITY_STRUCTURAL_MANIFEST_MAX_BYTES
        self.assertEqual(maximum, 8 * 1024 * 1024)
        self.assertEqual(authority_contract.MAX_REQUEST_BYTES, 4 * 1024 * 1024)
        self.assertEqual(db._POLICY_AUTHORITY_MAX_CANONICAL_AGGREGATE_BYTES, 4 * 1024 * 1024)
        manifest = {"definition": "x" * (4 * 1024 * 1024 + 128)}
        original, digest = db._policy_candidate_authority_manifest_digest(manifest)
        self.assertEqual(schema._policy_candidate_authority_manifest_json(original), original)
        self.assertEqual(json.loads(original), manifest)
        self.assertEqual(digest, db._policy_candidate_authority_framed_digest(
            "catchplate.policyCandidateAuthorityStructuralManifest/v1", original.encode("ascii")))
        with self.assertRaises(db.PolicyCandidateAuthorityError):
            db._candidate_authority_canonical_json("ordinary original", original)
        with self.assertRaises(db.PolicyCandidateAuthorityError):
            db._candidate_authority_canonical_json("aggregate", original,
                maximum=db._POLICY_AUTHORITY_MAX_CANONICAL_AGGREGATE_BYTES)

        # Exercise the inclusive exact structural limit and one byte over it.
        overhead = len(db.dumps({"definition": ""}).encode("ascii"))
        at_limit = {"definition": "x" * (maximum - overhead)}
        boundary, _ = db._policy_candidate_authority_manifest_digest(at_limit)
        self.assertEqual(len(boundary.encode("ascii")), maximum)
        self.assertEqual(schema._policy_candidate_authority_manifest_json(boundary), boundary)
        over = {"definition": at_limit["definition"] + "x"}
        with self.assertRaises(db.PolicyCandidateAuthorityError):
            db._policy_candidate_authority_manifest_digest(over)
        with self.assertRaises(db.PolicyCandidateAuthorityError):
            schema._policy_candidate_authority_manifest_json(db.dumps(over))

    def test_manifest_codec_retains_canonical_profile_and_storage_links(self):
        for original in (
            '{"n": 1}', '{"n":1,"n":1}', '{"n":1.5}',
            '{"n":9223372036854775808}', '{"n":"\\u00e9"}',
        ):
            with self.subTest(original=original), self.assertRaises(db.PolicyCandidateAuthorityError):
                schema._policy_candidate_authority_manifest_json(original)
        source = metadata_schema_source.metadata_base_schema_source()
        self.assertIn("length(structural_manifest_json)\n                    BETWEEN 2 AND 8388608", source)
        tree = ast.parse((ROOT / "catchplate/authority_store/schema.py").read_text())
        validator = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name == "_validate_policy_candidate_authority_structure")
        calls = [node for node in ast.walk(validator) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_policy_candidate_authority_manifest_json"]
        self.assertEqual(len(calls), 1)
        self.assertIn("structural_manifest_json", ast.unparse(calls[0]))
        current = (ROOT / "catchplate/authority_current_root_commit_reader.py").read_text()
        self.assertIn("db._policy_candidate_authority_manifest_digest(manifest)", current)


if __name__ == "__main__":
    unittest.main()
