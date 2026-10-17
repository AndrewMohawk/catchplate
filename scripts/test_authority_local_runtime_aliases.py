#!/usr/bin/env python3
"""Pure authenticated-path projections; no synthetic owner or installed proof."""
import ast
import copy
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import authority_artifact_spec as spec
from catchplate import authority_launcher as launcher
from catchplate import authority_stage_zero_contract as stage

ROOT = "/var/lib/catchplate/authority/generations/g0"


def fixture():
    # These are explicitly unsigned fragments for the pure projection, not a
    # VerifiedArtifactPackage or a claim that a real installation exists.
    paths = (("runtime/python", "elf-executable", b"interpreter"),
        ("runtime/libpython", "elf-shared-object", b"library"),
        ("bootstrap/launcher.py", "authority-source", b"bootstrap"),
        ("app/catchplate/sample.py", "authority-source", b"module"),
        ("roles/witness.json", "role-manifest", b"role"),
        ("data/unmapped.json", "data", b"data"))
    files = [dict(path=path, kind=kind, mode=0o444, uid=0, gid=0, size=len(raw),
        sha256="sha256:" + hashlib.sha256(raw).hexdigest()) for path, kind, raw in paths]
    by_path = {row["path"]: row for row in files}
    interpreter = dict(path="runtime/python", runtimePath="/runtime/python/bin/python3",
        size=by_path["runtime/python"]["size"], sha256=by_path["runtime/python"]["sha256"])
    native = dict(executables=[dict(path=interpreter["path"], runtimePath=interpreter["runtimePath"],
        sha256=interpreter["sha256"], elfClass="ELF64", machine=62, ptInterp=None, needed=[])],
        objects=[dict(path="runtime/libpython", runtimePath="/runtime/python/lib/libpython3.11.so.1.0",
            sha256=by_path["runtime/libpython"]["sha256"], elfClass="ELF64", machine=62, needed=[], soname=None)])
    bootstrap = dict(path="bootstrap/launcher.py", runtimePath="/runtime/authority-bootstrap/authority_launcher.py",
        size=by_path["bootstrap/launcher.py"]["size"], sha256=by_path["bootstrap/launcher.py"]["sha256"],
        interfaceSchema=spec.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA, interpreter=interpreter)
    imported = dict(module="catchplate.sample", path="app/catchplate/sample.py", kind="source",
        isPackage=False, sha256=by_path["app/catchplate/sample.py"]["sha256"])
    closure = [dict(path="/runtime/app/catchplate/sample.py", module=imported["module"], kind="source",
        isPackage=False, sha256=imported["sha256"], size=by_path[imported["path"]]["size"])]
    mappings = {interpreter["runtimePath"]: interpreter["path"],
        native["objects"][0]["runtimePath"]: "runtime/libpython", bootstrap["runtimePath"]: bootstrap["path"],
        closure[0]["path"]: imported["path"], ROOT + "/roles/witness.json": "roles/witness.json"}
    retained = [dict(runtimePath=runtime, sha256=by_path[path]["sha256"], size=by_path[path]["size"])
        for runtime, path in mappings.items()]
    bundle = dict(trustMode=dict(mode="trusted-host-local"), files=files,
        nativeClosure=native, stageZero=bootstrap, pythonImportClosure=[imported])
    return dict(bundle=bundle, generation_root=ROOT, retained_files=retained, launch_closure=closure), mappings


class LocalRuntimeAliasTests(unittest.TestCase):
    def test_local_native_bootstrap_python_and_literal_role_paths(self):
        selected, expected = fixture()
        self.assertEqual(spec.retained_installation_paths(**selected), expected)
        self.assertEqual(expected[ROOT + "/roles/witness.json"], "roles/witness.json")

    def test_native_profiles_keep_lexical_generation_requirement(self):
        selected, _ = fixture()
        selected["bundle"]["stageZero"]["interfaceSchema"] = stage.STAGE_ZERO_INTERFACE_SCHEMA
        for mode in ("trusted-host-local", "external-production", "tee-hardware"):
            selected["bundle"]["trustMode"]["mode"] = mode
            with self.assertRaises(spec.ArtifactContractError): spec.retained_installation_paths(**selected)
        selected["retained_files"] = [dict(runtimePath=ROOT + "/runtime/python")]
        self.assertEqual(spec.retained_installation_paths(**selected), {ROOT + "/runtime/python": "runtime/python"})

    def test_unknown_data_role_or_bootstrap_aliases_are_not_inferred(self):
        for path, target in (("/runtime/unmapped.json", "data/unmapped.json"),
                ("/runtime/roles/witness.json", "roles/witness.json"),
                ("/runtime/other-bootstrap.py", "bootstrap/launcher.py")):
            selected, _ = fixture()
            original = next(row for row in selected["bundle"]["files"] if row["path"] == target)
            selected["retained_files"].append(dict(runtimePath=path, sha256=original["sha256"], size=original["size"]))
            with self.assertRaises(spec.ArtifactContractError): spec.retained_installation_paths(**selected)

    def test_python_alias_requires_exact_authenticated_module_join(self):
        for change in ("module", "kind", "package", "digest", "missing", "duplicate"):
            selected, _ = fixture()
            row = selected["launch_closure"][0]
            if change == "module": row["module"] = "catchplate.other"
            elif change == "kind": row["kind"] = "extension"
            elif change == "package": row["isPackage"] = True
            elif change == "digest": row["sha256"] = "sha256:" + "0" * 64
            elif change == "missing": selected["launch_closure"] = []
            else: selected["launch_closure"].append(copy.deepcopy(row))
            with self.assertRaises(spec.ArtifactContractError): spec.retained_installation_paths(**selected)

    def test_alias_conflict_retained_bytes_and_cross_profile_refuse(self):
        for change in ("conflict", "sha", "size", "profile", "file-sha"):
            selected, _ = fixture()
            if change == "conflict": selected["launch_closure"][0]["path"] = "/runtime/python/bin/python3"
            elif change == "sha": selected["retained_files"][0]["sha256"] = "sha256:" + "0" * 64
            elif change == "size": selected["retained_files"][0]["size"] += 1
            elif change == "profile": selected["bundle"]["trustMode"]["mode"] = "external-production"
            else: selected["bundle"]["files"][0]["sha256"] = "sha256:" + "0" * 64
            with self.assertRaises(spec.ArtifactContractError): spec.retained_installation_paths(**selected)

    def test_noncanonical_and_duplicate_runtime_paths_refuse(self):
        for path in (ROOT + "/../outside", "/runtime//python/bin/python3", "runtime/python", ROOT):
            selected, _ = fixture()
            selected["retained_files"][0]["runtimePath"] = path
            with self.assertRaises(spec.ArtifactContractError): spec.retained_installation_paths(**selected)
        selected, _ = fixture()
        selected["retained_files"].append(copy.deepcopy(selected["retained_files"][0]))
        with self.assertRaises(spec.ArtifactContractError): spec.retained_installation_paths(**selected)

    def test_launcher_keeps_complete_physical_receipt_comparison(self):
        tree = ast.parse(Path(launcher.__file__).read_text())
        function = next(row for row in tree.body if isinstance(row, ast.FunctionDef)
            and row.name == "_validate_canonical_launch_evidence")
        helper = [row for row in ast.walk(function) if isinstance(row, ast.Constant)
            and row.value == "retained_installation_paths"]
        self.assertEqual(len(helper), 1)
        compared = []
        for row in ast.walk(function):
            if not isinstance(row, ast.Compare) or not isinstance(row.left, ast.Tuple): continue
            if len(row.comparators) != 1 or not isinstance(row.comparators[0], ast.Tuple): continue
            pair = []
            for side in (row.left, row.comparators[0]):
                if not all(isinstance(item, ast.Subscript) and isinstance(item.value, ast.Name)
                    and isinstance(item.slice, ast.Constant) for item in side.elts): break
                pair.append(tuple((item.value.id, item.slice.value) for item in side.elts))
            if len(pair) == 2: compared.append(pair)
        fields = ("device", "inode", "generation", "mode", "uid", "gid", "size", "sha256", "fsVerityDigest")
        self.assertIn([tuple(("retained", name) for name in fields),
                       tuple(("installed_entry", name) for name in fields)], compared)


if __name__ == "__main__":
    unittest.main()
