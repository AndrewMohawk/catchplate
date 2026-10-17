#!/usr/bin/env python3
"""Closed preparation/byte joins; no claimed full package or installation."""
import ast
import copy
import inspect
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.authority import assemble_local_package as cli
from scripts.authority import generate_artifact_bundle as generator
from scripts.test_authority_local_artifact_witness import fixture, signed_generation
from catchplate import authority_artifact_spec as spec

PIN = "sha256:" + "1" * 64


def selection():
    core, trust, _ = fixture()
    value = dict.fromkeys(generator.INPUT_FIELDS)
    value.update(schema=generator.INPUT_SCHEMA, artifactRoot="/not-a-synthetic-success",
        sourceRevision=generator.authority_contract.SOURCE_REVISION, sourceCommitDigest=PIN,
        authoritySchemaVersion=spec.AUTHORITY_SCHEMA_VERSION, trustMode=copy.deepcopy(core["trustMode"]),
        generation={name: core[name] for name in ("sequence", "generationId", "predecessorDigest",
            "minimumRollbackSequence", "validFrom", "validUntil")})
    return value, trust, core["validFrom"]


class LocalAssemblyControls(unittest.TestCase):
    def test_fixed_two_mode_public_arguments_no_signer_or_path_options(self):
        args = ["--mode", "core", "--spec-fd", "3", "--spec-sha256", PIN,
                "--trust-fd", "4", "--trust-sha256", PIN]
        for mode in ("core", "package"):
            self.assertEqual(cli.arguments([args[0], mode, *args[2:]])["mode"], mode)
        for wrong in (args + ["--key-fd", "5"], args + ["--output", "/anywhere"],
                      [args[0], "sign", *args[2:]], args[:3] + ["03"] + args[4:],
                      args[:7] + ["3"] + args[8:]):
            with self.subTest(args=wrong), self.assertRaises(ValueError):
                cli.arguments(wrong)

    def test_core_rejects_native_mode_and_any_checkpoint_placeholder(self):
        value, trust, instant = selection()
        for mode in ("external-production", "tee-hardware"):
            changed = copy.deepcopy(value); changed["trustMode"]["mode"] = mode
            with self.assertRaises(generator.GeneratorError):
                generator.prepare_local_generation_core(changed, trust_state=trust, validation_time=instant)
        for checkpoint in (None, {}, "predicted"):
            changed = copy.deepcopy(value); changed["generation"]["witnessCheckpoint"] = checkpoint
            with self.assertRaises(generator.GeneratorError):
                generator.prepare_local_generation_core(changed, trust_state=trust, validation_time=instant)

    def test_original_generation_sequence_predecessor_floor_and_time_refuse(self):
        value, trust, instant = selection()
        changes = ({"sequence": 1}, {"sequence": True}, {"predecessorDigest": PIN},
                   {"minimumRollbackSequence": -1}, {"validUntil": instant},
                   {"validFrom": value["generation"]["validUntil"]})
        for mutation in changes:
            changed = copy.deepcopy(value); changed["generation"].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(generator.GeneratorError):
                generator.prepare_local_generation_core(changed, trust_state=trust, validation_time=instant)

    def test_real_signed_checkpoint_binds_exact_core_and_canonical_output(self):
        # A genuine synthetic checkpoint tests the existing exact core binding;
        # it is not a fabricated complete bundle or a successful assembly owner.
        core, trust, private = fixture()
        final_generation = signed_generation(core, trust, private)
        spec.validate_generation_statement(final_generation)
        output = cli.encode_result("core", core)
        self.assertEqual(output, spec.canonical_json_bytes(core))
        self.assertFalse(output.endswith(b"\n"))
        self.assertEqual(json.loads(output), {key: value for key, value in final_generation.items()
                                             if key != "witnessCheckpoint"})
        changed = copy.deepcopy(final_generation)
        changed["sourceTreeDigest"] = "sha256:" + "9" * 64
        with self.assertRaises(spec.ArtifactContractError):
            spec.validate_generation_statement(changed)

    def test_package_output_cannot_be_a_core_or_a_placeholder(self):
        core, _, _ = fixture()
        for value in (core, {"schema": spec.UNSIGNED_PACKAGE_SCHEMA}, {},
                      dict(core, witnessCheckpoint=None)):
            with self.subTest(value=value.get("schema")), self.assertRaises(spec.ArtifactContractError):
                cli.encode_result("package", value)
        with self.assertRaises(ValueError):
            cli.encode_result("sign", core)

    def test_both_modes_share_actual_bundle_and_core_builders_and_final_checkpoint(self):
        tree = ast.parse(inspect.getsource(generator))
        methods = {row.name: row for row in tree.body if isinstance(row, ast.FunctionDef)}
        for name in ("prepare_local_generation_core", "_build_package"):
            calls = [row.func.id for row in ast.walk(methods[name])
                     if isinstance(row, ast.Call) and isinstance(row.func, ast.Name)]
            self.assertIn("_build_bundle", calls)
            self.assertIn("_generation_core", calls)
        final = methods["_build_package"]
        assignment = next(row for row in ast.walk(final) if isinstance(row, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == "generation" for target in row.targets))
        self.assertEqual(ast.unparse(assignment.value),
            "dict(_generation_core(value, bundle), witnessCheckpoint=generation_input['witnessCheckpoint'])")
        self.assertFalse(methods["_build_bundle"].args.kw_defaults[-1].value)
        prep = inspect.getsource(generator.prepare_local_generation_core)
        self.assertIn("_verify_key_documents(", prep)
        self.assertNotIn("signing_key(", prep)
        source = inspect.getsource(cli.run)
        self.assertIn("deadline = initial_boot + expiry - initial_unix", source)
        self.assertIn("io.write_public(raw, deadline_boottime_ns=deadline, check=check)", source)
        self.assertIn("io.read_public(fd, io.MAX_PUBLIC) != original", source)


if __name__ == "__main__":
    unittest.main()
