#!/usr/bin/env python3
"""Small source/input-association controls, not a signed installed package."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.test_authority_local_provenance import fixture, repin
from serverware import authority_local_composition as local
from serverware import authority_local_provenance as observed
from scripts.authority import local_composition as cli


def inputs():
    selected, measured, originals, archive = fixture()
    selected.update(schema=local.APPROVAL_SCHEMA, purpose=local.PURPOSE)
    raw = observed.spec.canonical_json_bytes(local.composition_manifest(selected, measured, originals))
    repin(selected, measured, originals, "report", raw)
    return selected, measured, originals, archive


class CompositionControls(unittest.TestCase):
    def test_explicit_closed_approval_and_unchanged_descriptor_grammar(self):
        selected, _, _, _ = inputs()
        self.assertEqual(local.approval(observed.spec.canonical_json_bytes(selected)), selected)
        with self.assertRaises(ValueError):
            observed.approval(observed.spec.canonical_json_bytes(selected))
        for change in ({"schema": observed.APPROVAL_SCHEMA}, {"purpose": "claim-build"},
                       {"extra": True}, {"files": []}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                local.approval(observed.spec.canonical_json_bytes(dict(selected, **change)))
        self.assertIs(cli.arguments, __import__(
            "scripts.authority.local_provenance", fromlist=["arguments"]).arguments)

    def test_exact_association_and_distinct_local_predicate(self):
        selected, measured, originals, _ = inputs()
        payload, source = local.association(selected, measured, originals)
        self.assertEqual(payload["predicateType"], local.PREDICATE)
        self.assertEqual(payload["sourceTreeDigest"], measured["treeDigest"])
        self.assertEqual(payload["ociRootDigest"], observed.sha(originals["ociManifest"]))
        self.assertNotEqual(payload["sourceTreeDigest"], source["sourceTreeDigest"])
        self.assertIs(local.LocalCompositionIssuer.associate, local.association)
        self.assertIs(local.LocalCompositionIssuer.issue, observed.LocalProvenanceIssuer.issue)

    def test_runtime_is_not_claimed_built_from_selected_source(self):
        selected, measured, originals, _ = inputs()
        config = observed.document(originals["ociConfig"])
        config["config"]["Labels"] = {"org.opencontainers.image.revision": "retained-older-source"}
        config_raw = observed.spec.canonical_json_bytes(config)
        repin(selected, measured, originals, "ociConfig", config_raw)
        manifest = observed.document(originals["ociManifest"])
        manifest["config"].update(digest=observed.sha(config_raw), size=len(config_raw))
        repin(selected, measured, originals, "ociManifest", observed.spec.canonical_json_bytes(manifest))
        declaration = local.composition_manifest(selected, measured, originals)
        repin(selected, measured, originals, "report", observed.spec.canonical_json_bytes(declaration))
        self.assertEqual(local.association(selected, measured, originals)[0]["predicateType"], local.PREDICATE)
        self.assertTrue(all(value is False for value in declaration["assurances"].values()))
        with self.assertRaises(ValueError):
            observed.association(selected, measured, originals)

    def test_build_claim_extra_fields_and_noncanonical_bytes_refuse(self):
        selected, measured, originals, _ = inputs()
        good = observed.document(originals["report"])
        wrong = copy.deepcopy(good); wrong["assurances"]["buildExecution"] = True
        numeric = copy.deepcopy(good); numeric["assurances"]["buildExecution"] = 0
        for raw in (observed.spec.canonical_json_bytes(wrong), observed.spec.canonical_json_bytes(numeric),
                    observed.spec.canonical_json_bytes(dict(good, ok=True)), originals["report"] + b"\n"):
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                changed = copy.deepcopy((selected, measured, originals))
                repin(*changed, "report", raw)
                local.association(*changed)

    def test_wrong_source_and_oci_joins_refuse_even_with_remeasured_report(self):
        selected, measured, originals, _ = inputs()
        for field in ("sourceCommit", "sourceTreeDigest", "sourceArchiveSha256", "sourceManifestSha256",
                      "runtimeManifestSha256", "runtimeConfigSha256", "runtimeLayerSha256s"):
            declaration = observed.document(originals["report"])
            declaration[field] = [] if field == "runtimeLayerSha256s" else "wrong"
            changed = copy.deepcopy((selected, measured, originals))
            repin(*changed, "report", observed.spec.canonical_json_bytes(declaration))
            with self.subTest(field=field), self.assertRaises(ValueError):
                local.association(*changed)
        wrong = copy.deepcopy((selected, measured, originals))
        config = observed.document(wrong[2]["ociConfig"]); config["architecture"] = "arm64"
        repin(*wrong, "ociConfig", observed.spec.canonical_json_bytes(config))
        with self.assertRaises(ValueError):
            local.association(*wrong)

    def test_legacy_build_report_is_not_a_composition_declaration(self):
        selected, measured, originals, _ = fixture()
        with self.assertRaises(ValueError):
            local.association(selected, measured, originals)
        original_payload, _ = observed.association(selected, measured, originals)
        self.assertEqual(original_payload["predicateType"], observed.PREDICATE)


if __name__ == "__main__":
    unittest.main()
