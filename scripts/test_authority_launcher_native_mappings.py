#!/usr/bin/env python3
"""Public native-file controls, not an authority admission or R14 replay.

The explicit --public-drop-fixture mode belongs only in a disposable container
with SETUID/SETGID initially available and no other capabilities or network.
"""
import ast
import ctypes
import errno
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import os
import stat
import sys
import unittest
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_launcher as subject


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def device(metadata):
    return f"{os.major(metadata.st_dev):x}:{os.minor(metadata.st_dev):x}"


@contextmanager
def public_file(*, sealed=False):
    raw = b"public native fixture"
    if sealed:
        fd = subject._seal_bytes("native-fixture", raw, mode=0o444)
    else:
        fd = os.memfd_create("native-fixture", os.MFD_CLOEXEC)
        os.write(fd, raw)
    try:
        binding = subject._native_file_binding(fd, sha(raw), sealed=sealed)
        yield fd, raw, binding
    finally:
        os.close(fd)


def row(fd, path="/public/native"):
    metadata = os.fstat(fd)
    return ("1000-2000", "r-xp", "00001000", device(metadata),
            str(metadata.st_ino), path)


def signed_file_row(fd, raw, *, survives=True):
    metadata = os.fstat(fd)
    return dict(fd=fd, runtimePath="/public/native", device=metadata.st_dev,
                inode=metadata.st_ino, size=metadata.st_size,
                mode=stat.S_IMODE(metadata.st_mode), uid=metadata.st_uid,
                gid=metadata.st_gid, sha256=sha(raw), surviveExec=survives)


def dependency_bundle():
    def native(name, needed):
        return dict(path="native/" + name, runtimePath="/native/" + name,
                    sha256=sha(name.encode()), needed=needed, soname=None,
                    elfClass="ELF64", machine=62)
    objects = [native("first.so", ["/native/direct.so"]),
               native("second.so", ["/native/shared.so"]),
               native("direct.so", ["/native/shared.so"]),
               native("shared.so", ["/native/direct.so"])]
    imports = [dict(module=name, path="native/" + name + ".so",
                    kind="extension", isPackage=False,
                    sha256=sha((name + ".so").encode()))
               for name in ("first", "second")]
    return dict(nativeClosure=dict(objects=objects, executables=[]),
                pythonImportClosure=imports)


@contextmanager
def preload_fixture():
    """Real public sealed bytes; synthetic graph, not loadable ELF or admission."""
    edges = {"first.so": ("direct.so", "shared.so"), "second.so": ("shared.so",),
             "direct.so": ("shared.so", "system.so"), "shared.so": ("system.so",),
             "system.so": (), "unrelated.so": ()}
    objects, files = [], {}
    with ExitStack() as owner:
        for name, needed in edges.items():
            raw = ("public preload fixture " + name).encode("ascii")
            fd = subject._seal_bytes(name, raw, mode=0o444)
            owner.callback(os.close, fd)
            path = "/native/" + name
            files[path] = subject._native_file_binding(fd, sha(raw), sealed=True)
            objects.append(dict(path="native/" + name, runtimePath=path,
                sha256=sha(raw), needed=["/native/" + value for value in needed],
                soname=name, elfClass="ELF64", machine=62))
        imports = [dict(module=name, path="native/" + name + ".so", kind="extension",
            isPackage=False, sha256=files["/native/" + name + ".so"]["sha256"])
            for name in ("first", "second")]
        bundle = dict(nativeClosure=dict(objects=objects, executables=[]),
                      pythonImportClosure=imports)
        yield bundle, files, {"/native/system.so": files["/native/system.so"]["sha256"]}


class NativeMappingsTests(unittest.TestCase):
    def test_missing_measured_module_preserves_not_found_name(self):
        finder = subject._SealedClosureFinder({}, {})
        for name in ("unmeasured_fixture", "unmeasured_fixture.child"):
            with self.subTest(name=name), self.assertRaises(ModuleNotFoundError) as failure:
                finder.find_spec(name)
            self.assertEqual(failure.exception.name, name)
            self.assertIsInstance(failure.exception, ImportError)

    def test_missing_measured_module_never_reaches_downstream_finder(self):
        name = "catchplate_unmeasured_import_fixture"
        self.assertNotIn(name, sys.modules)
        finder = subject._SealedClosureFinder({}, {})
        with patch.object(importlib.machinery.PathFinder, "find_spec") as downstream, \
                patch.object(sys, "meta_path", [finder, importlib.machinery.PathFinder]):
            with self.assertRaises(ModuleNotFoundError) as failure:
                importlib.import_module(name)
            downstream.assert_not_called()
        self.assertEqual(failure.exception.name, name)
        self.assertNotIn(name, sys.modules)

    def test_optional_absent_platform_import_is_catchable_without_fallback(self):
        self.assertNotIn("msvcrt", sys.modules)
        self.assertNotIn("msvcrt", sys.builtin_module_names)
        finder = subject._SealedClosureFinder({}, {})
        namespace = {}
        # Match the optional Windows-module probe used by Linux subprocess.
        code = compile("try:\n    import msvcrt\nexcept ModuleNotFoundError as error:\n"
                       "    missing_name = error.name\n    windows = False\n"
                       "else:\n    windows = True\n", "public-platform-probe", "exec")
        with patch.object(importlib.machinery.PathFinder, "find_spec") as downstream, \
                patch.object(sys, "meta_path", [finder, importlib.machinery.PathFinder]):
            exec(code, namespace)
            downstream.assert_not_called()
        self.assertFalse(namespace["windows"])
        self.assertEqual(namespace["missing_name"], "msvcrt")
        self.assertNotIn("msvcrt", sys.modules)

    def test_preload_dependency_first_shared_and_retained_handles(self):
        with preload_fixture() as (bundle, files, baseline):
            handles = [object(), object()]
            with patch.object(ctypes, "CDLL", side_effect=handles) as load:
                held = subject._preload_native_dependencies(bundle, files, baseline,
                    modules=("first", "second"))
            self.assertIs(type(held), tuple)
            self.assertEqual(len(held), 2)
            self.assertTrue(all(actual is expected for actual, expected in zip(held, handles)))
            self.assertEqual(load.call_args_list, [call(
                "/proc/self/fd/" + str(files[path]["fd"]), mode=os.RTLD_NOW | os.RTLD_LOCAL)
                for path in ("/native/shared.so", "/native/direct.so")])
            # No extension root, already-verified baseline or unrelated object
            # was loaded. The caller's originals remain open and unchanged.
            for binding in files.values():
                self.assertEqual(subject._retained_native_digest(binding), binding["sha256"])

    def test_preload_invalid_graph_or_original_refuses_before_any_load(self):
        failures = ("unknown-module", "root-digest", "missing-edge", "runtime-path",
                    "missing-retained", "signed-digest", "retained-digest",
                    "retained-inode", "baseline-digest", "cycle")
        with preload_fixture() as (original, originals, baseline):
            for failure in failures:
                bundle, files, observed = deepcopy(original), deepcopy(originals), dict(baseline)
                modules = ("first", "second")
                objects = {row["runtimePath"]: row for row in bundle["nativeClosure"]["objects"]}
                if failure == "unknown-module":
                    modules = ("unselected",)
                elif failure == "root-digest":
                    bundle["pythonImportClosure"][0]["sha256"] = sha(b"changed")
                elif failure == "missing-edge":
                    objects["/native/direct.so"]["needed"] = ["/native/missing.so"]
                elif failure == "runtime-path":
                    objects["/native/direct.so"]["runtimePath"] = "/unselected/alias.so"
                elif failure == "missing-retained":
                    del files["/native/direct.so"]
                elif failure == "signed-digest":
                    objects["/native/direct.so"]["sha256"] = sha(b"changed")
                elif failure == "retained-digest":
                    files["/native/direct.so"]["sha256"] = sha(b"changed")
                elif failure == "retained-inode":
                    files["/native/direct.so"]["fd"] = files["/native/unrelated.so"]["fd"]
                elif failure == "baseline-digest":
                    observed["/native/system.so"] = sha(b"changed")
                else:
                    objects["/native/shared.so"]["needed"] = ["/native/direct.so"]
                with self.subTest(failure=failure), patch.object(ctypes, "CDLL") as load:
                    with self.assertRaises(subject.LaunchError):
                        subject._preload_native_dependencies(bundle, files, observed, modules=modules)
                    load.assert_not_called()

    def test_preload_rechecks_original_immediately_before_and_after_load(self):
        for timing in ("before", "after"):
            with self.subTest(timing=timing), preload_fixture() as (bundle, files, baseline):
                selected = files["/native/shared.so"]
                original_digest = subject._retained_native_digest
                checked = []

                def digest(binding):
                    if binding is selected:
                        checked.append(True)
                        if timing == "before" and len(checked) == 2:
                            # Substitute a different real FD after full graph
                            # preflight but before the first attempted load.
                            binding["fd"] = files["/native/unrelated.so"]["fd"]
                    return original_digest(binding)

                def load(path, *, mode):
                    self.assertEqual(path, "/proc/self/fd/" + str(selected["fd"]))
                    self.assertEqual(mode, os.RTLD_NOW | os.RTLD_LOCAL)
                    os.fchmod(selected["fd"], 0o400)
                    return object()

                with patch.object(subject, "_retained_native_digest", side_effect=digest), \
                        patch.object(ctypes, "CDLL", side_effect=load) as loader:
                    with self.assertRaises(subject.LaunchError):
                        subject._preload_native_dependencies(bundle, files, baseline,
                            modules=("first", "second"))
                    self.assertEqual(loader.call_count, 0 if timing == "before" else 1)
                    self.assertEqual(len(checked), 2 if timing == "before" else 3)

    def test_partial_native_measurement_returns_observed_not_available(self):
        with public_file() as (fd, raw, binding):
            mapped = row(fd)
            observed = {mapped[5]: sha(raw)}
            available = dict(observed, **{"/available/not-loaded.so": sha(b"unloaded")})
            with patch.object(subject, "_executable_mapping_rows", return_value=(mapped,)):
                actual = subject._verify_native_mappings(available, require_exact=False,
                    files={mapped[5]: binding}, memory=None)
            self.assertEqual(actual, observed)
            self.assertEqual(available, dict(observed, **{"/available/not-loaded.so": sha(b"unloaded")}))

    def test_required_driver_import_precedes_final_native_measurement_and_close(self):
        tree = ast.parse(Path(subject.__file__).read_text("utf-8"))
        enter = next(node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_enter")
        calls = [node for node in ast.walk(enter) if isinstance(node, ast.Call)]

        def only(name, predicate=lambda node: True):
            selected = [node for node in calls if ast.unparse(node.func) == name and predicate(node)]
            self.assertEqual(len(selected), 1, name)
            return selected[0]

        preload = only("_preload_native_dependencies")
        self.assertEqual(ast.unparse(preload.args[0]), "verified_package.package['bundle']")
        self.assertEqual([ast.unparse(arg) for arg in preload.args[1:]],
                         ["native_files", "verified_native"])
        baseline = only("_verify_native_mappings", lambda node: any(keyword.arg == "require_exact"
            and isinstance(keyword.value, ast.Constant) and keyword.value.value is False
            for keyword in node.keywords))
        baseline_assignment = next(node for node in ast.walk(enter)
            if isinstance(node, ast.Assign) and node.value is baseline)
        self.assertEqual([ast.unparse(node) for node in baseline_assignment.targets], ["verified_native"])
        self.assertLess(baseline.lineno, preload.lineno)
        self.assertEqual(ast.literal_eval(next(keyword.value for keyword in preload.keywords
            if keyword.arg == "modules")), ("psycopg_binary.pq", "psycopg_binary._psycopg"))
        assignment = next(node for node in ast.walk(enter)
            if isinstance(node, ast.Assign) and node.value is preload)
        self.assertEqual([ast.unparse(node) for node in assignment.targets], ["native_dependency_handles"])
        imported = only("importlib.import_module", lambda node: len(node.args) == 1
            and isinstance(node.args[0], ast.Constant) and node.args[0].value == "psycopg")
        graph = only("_loaded_native_dependency_mappings")
        measured = only("_verify_native_mappings", lambda node: any(keyword.arg == "require_exact"
            and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
            for keyword in node.keywords))
        closed = only("native_readers.close")
        service = only("authority_service.main")
        ordered = (preload, imported, graph, measured, closed, service)
        self.assertEqual([node.lineno for node in ordered], sorted(node.lineno for node in ordered))
        memory_scope = next(node for node in ast.walk(enter) if isinstance(node, ast.With)
            and preload in tuple(ast.walk(node)))
        self.assertTrue(any(ast.unparse(item.context_expr) == "_retained_process_memory()"
                            for item in memory_scope.items))
        self.assertTrue(all(node in tuple(ast.walk(memory_scope)) for node in (imported, graph, measured)))

    def test_loaded_dependency_graph_direct_transitive_shared_and_cycle(self):
        bundle = dependency_bundle()
        loaded = {"/memfd:" + name + " (deleted)": sha((name + ".so").encode())
                  for name in ("first", "second")}
        self.assertEqual(subject._loaded_native_dependency_mappings(bundle, loaded),
                         {"/native/direct.so": sha(b"direct.so"),
                          "/native/shared.so": sha(b"shared.so")})

    def test_unloaded_extension_dependencies_are_not_mandatory(self):
        bundle = dependency_bundle()
        objects = bundle["nativeClosure"]["objects"]
        objects.append(dict(objects[2], path="native/unloaded.so",
                            runtimePath="/native/unloaded.so", needed=[],
                            sha256=sha(b"unloaded.so")))
        objects[1]["needed"] = ["/native/unloaded.so"]
        self.assertEqual(subject._loaded_native_dependency_mappings(bundle, {}), {})
        self.assertEqual(subject._loaded_native_dependency_mappings(
            bundle, {"/memfd:first (deleted)": sha(b"first.so")}),
            {"/native/direct.so": sha(b"direct.so"),
             "/native/shared.so": sha(b"shared.so")})

    def test_loaded_extension_root_and_digest_joins_fail_closed(self):
        loaded = {"/memfd:first (deleted)": sha(b"first.so")}
        for failure in ("unknown", "loaded-digest", "import-digest", "native-digest", "path"):
            bundle, values = dependency_bundle(), dict(loaded)
            if failure == "unknown":
                values = {"/memfd:unknown (deleted)": sha(b"first.so")}
            elif failure == "loaded-digest":
                values["/memfd:first (deleted)"] = sha(b"wrong")
            elif failure == "import-digest":
                bundle["pythonImportClosure"][0]["sha256"] = sha(b"wrong")
            elif failure == "native-digest":
                bundle["nativeClosure"]["objects"][0]["sha256"] = sha(b"wrong")
            else:
                bundle["pythonImportClosure"][0]["path"] = "native/unselected.so"
            with self.subTest(failure=failure), self.assertRaises(subject.LaunchError):
                subject._loaded_native_dependency_mappings(bundle, values)

    def test_missing_edges_and_ambiguous_graph_joins_fail_closed(self):
        for failure in ("missing-edge", "duplicate-path", "duplicate-runtime", "duplicate-module"):
            bundle = dependency_bundle()
            objects = bundle["nativeClosure"]["objects"]
            if failure == "missing-edge":
                objects[2]["needed"] = ["/native/unselected.so"]
            elif failure in ("duplicate-path", "duplicate-runtime"):
                extra = deepcopy(objects[2])
                extra["runtimePath" if failure == "duplicate-path" else "path"] = "/different"
                objects.append(extra)
            else:
                bundle["pythonImportClosure"].append(deepcopy(bundle["pythonImportClosure"][0]))
            with self.subTest(failure=failure), self.assertRaises(subject.LaunchError):
                subject._loaded_native_dependency_mappings(
                    bundle, {"/memfd:first (deleted)": sha(b"first.so")})

    def test_exact_path_inode_device_and_retained_descriptor_required(self):
        with public_file() as (fd, raw, binding):
            mapped = row(fd)
            values = dict(files={mapped[5]: binding}, path=mapped[5],
                          device=mapped[3], inode=mapped[4])
            self.assertEqual(subject._mapped_file_digest(**values), sha(raw))
            for changes in (dict(files={}), dict(path="/unapproved/alias"),
                            dict(device="ff:ff"), dict(inode=str(int(mapped[4]) + 1))):
                with self.subTest(changes=changes), self.assertRaises(subject.LaunchError):
                    subject._mapped_file_digest(**dict(values, **changes))
            with patch.object(subject.os, "open", side_effect=AssertionError("no reopen")):
                self.assertEqual(subject._mapped_file_digest(**values), sha(raw))

    def test_changed_content_and_descriptor_identity_refused(self):
        with public_file() as (fd, raw, binding):
            with patch.object(subject, "_read_file", return_value=b"different bytes"):
                with self.assertRaises(subject.LaunchError):
                    subject._retained_native_digest(binding)
            with public_file() as (other_fd, _, _):
                with self.assertRaises(subject.LaunchError):
                    subject._retained_native_digest(dict(binding, fd=other_fd))
            original = subject._read_file

            def changed_during_read(descriptor, size):
                result = original(descriptor, size)
                os.ftruncate(descriptor, size + 1)
                return result

            with patch.object(subject, "_read_file", side_effect=changed_during_read):
                with self.assertRaises(subject.LaunchError):
                    subject._retained_native_digest(binding)

    def test_exact_mapping_set_and_full_snapshot_stability(self):
        with public_file() as (fd, raw, binding):
            mapped = row(fd)
            expected = {mapped[5]: sha(raw)}
            arguments = dict(require_exact=True, files={mapped[5]: binding}, memory=None)
            with patch.object(subject, "_executable_mapping_rows", return_value=(mapped,)):
                subject._verify_native_mappings(expected, **arguments)
                for wrong in ({}, dict(expected, **{"/phantom/extension": sha(raw)})):
                    with self.assertRaises(subject.LaunchError):
                        subject._verify_native_mappings(wrong, **arguments)
            # Every kernel executable-row field, including offset, is guarded.
            for index, value in enumerate(("2000-3000", "r-xs", "00002000",
                                           "ff:ff", "999", "/other/native")):
                changed = list(mapped)
                changed[index] = value
                with self.subTest(field=index), patch.object(
                        subject, "_executable_mapping_rows",
                        side_effect=[(mapped,), (tuple(changed),)]):
                    with self.assertRaises(subject.LaunchError):
                        subject._verify_native_mappings(expected, **arguments)

    def test_retained_source_index_uses_signed_path_and_stat_identity(self):
        with public_file() as (fd, raw, _):
            original = dict(signed_file_row(fd, raw), runtimePath="/signed/native")
            self.assertEqual(set(subject._native_file_index([original])), {"/signed/native"})
            for field in ("inode", "device", "size", "mode", "uid", "gid"):
                with self.subTest(field=field), self.assertRaises(subject.LaunchError):
                    subject._native_file_index([dict(original, **{field: original[field] + 1})])

    def test_false_survival_skips_closed_declaration_and_unknown_refuses(self):
        with public_file() as (fd, raw, _):
            original = signed_file_row(fd, raw, survives=False)
            with patch.object(subject.os, "fstat", side_effect=AssertionError("closed declaration inspected")):
                self.assertEqual(subject._native_file_index([original]), {})
                for value in (None, 0, 1, "false"):
                    with self.subTest(value=value), self.assertRaises(subject.LaunchError):
                        subject._native_file_index([dict(original, surviveExec=value)])
                missing = dict(original)
                del missing["surviveExec"]
                with self.assertRaises(subject.LaunchError):
                    subject._native_file_index([missing])

    def test_native_temporary_original_is_exact_and_closes_on_all_paths(self):
        # Synthetic map_files acquisition returns a real public inode. This
        # tests ownership and joins, not a privileged native-stage admission.
        with public_file() as (fd, raw, _):
            mapped = row(fd)
            original = signed_file_row(fd, raw, survives=False)
            for failure in (None, "metadata", "baseline", "mapping", "later"):
                acquired = []

                def acquire(path, flags):
                    self.assertEqual(path, "/proc/self/map_files/" + mapped[0])
                    self.assertEqual(flags, os.O_RDONLY | os.O_CLOEXEC)
                    acquired.append(os.dup(fd))
                    return acquired[-1]

                declaration = dict(original, size=original["size"] + (failure == "metadata"))
                expected = {mapped[5]: sha(b"wrong") if failure == "baseline" else sha(raw)}
                changed = tuple(list(mapped[:4]) + [str(int(mapped[4]) + 1), mapped[5]])
                inventory = [((changed if failure == "mapping" else mapped),), (mapped,)]
                try:
                    with ExitStack() as owner, patch.object(subject.os, "geteuid", return_value=0), \
                            patch.object(subject.os, "open", side_effect=acquire), \
                            patch.object(subject, "_executable_mapping_rows", side_effect=inventory):
                        files = subject._native_file_index([declaration])
                        subject._retain_native_mapped_sources([declaration], expected, files, owner)
                        self.assertEqual(subject._mapped_file_digest(files=files, path=mapped[5],
                            device=mapped[3], inode=mapped[4]), sha(raw))
                        if failure == "later":
                            raise ValueError("synthetic later admission failure")
                        owner.close()  # Same pre-service explicit close as _enter.
                        with self.assertRaises(OSError):
                            os.fstat(acquired[0])
                except (subject.LaunchError, ValueError):
                    self.assertIsNotNone(failure)
                else:
                    self.assertIsNone(failure)
                self.assertEqual(len(acquired), 1)
                with self.assertRaises(OSError) as closed:
                    os.fstat(acquired[0])
                self.assertEqual(closed.exception.errno, errno.EBADF)
            for declarations in ([], [dict(original, surviveExec=True)],
                                 [dict(original, surviveExec=None)]):
                with self.subTest(declarations=declarations), ExitStack() as owner, \
                        patch.object(subject.os, "open", side_effect=AssertionError("unapproved acquisition")), \
                        patch.object(subject, "_executable_mapping_rows", return_value=(mapped,)):
                    with self.assertRaises(subject.LaunchError):
                        subject._retain_native_mapped_sources(declarations, {mapped[5]: sha(raw)}, {}, owner)

    def test_only_successful_extension_execution_adds_mapping(self):
        with public_file(sealed=True) as (fd, raw, binding):
            loaded = {}
            entry = dict(descriptor=fd, nativeBinding=binding, kind="extension",
                         path="/public/native-fixture.so", isPackage=False)
            finder = subject._SealedClosureFinder({"native_fixture": entry}, loaded)
            spec = finder.find_spec("native_fixture")
            module = ModuleType("native_fixture")
            module.__spec__ = spec
            self.assertEqual(loaded, {})
            with patch.object(importlib.machinery.ExtensionFileLoader, "create_module", return_value=module):
                self.assertIs(spec.loader.create_module(spec), module)
            self.assertEqual(loaded, {})
            with patch.object(importlib.machinery.ExtensionFileLoader, "exec_module", side_effect=ImportError):
                with self.assertRaises(ImportError):
                    spec.loader.exec_module(module)
            self.assertEqual(loaded, {})
            with patch.object(importlib.machinery.ExtensionFileLoader, "exec_module", return_value=None):
                spec.loader.exec_module(module)
            self.assertEqual(loaded, {"/memfd:native_fixture (deleted)": sha(raw)})
            spec.loader.path = "/changed/loader"
            with self.assertRaises(subject.LaunchError):
                spec.loader.exec_module(module)

    def test_only_public_extensions_change_mode_and_seals_are_required(self):
        private = subject._seal_bytes("source-or-credential", b"synthetic")
        try:
            self.assertEqual(stat.S_IMODE(os.fstat(private).st_mode), 0o400)
        finally:
            os.close(private)
        with public_file(sealed=True) as (fd, _, binding):
            self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode), 0o444)
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GET_SEALS) & subject.REQUIRED_MEMFD_SEALS,
                             subject.REQUIRED_MEMFD_SEALS)
            with patch.object(subject.fcntl, "fcntl", return_value=0):
                with self.assertRaises(subject.LaunchError):
                    subject._retained_native_digest(binding)

    def test_own_memory_descriptor_closes_on_success_and_failure(self):
        for fail in (False, True):
            try:
                with subject._retained_process_memory() as memory:
                    fd = memory[0]
                    self.assertTrue(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
                    if fail:
                        raise ValueError("synthetic failure")
            except ValueError:
                self.assertTrue(fail)
            with self.assertRaises(OSError) as failure:
                os.fstat(fd)
            self.assertEqual(failure.exception.errno, errno.EBADF)


def public_drop_fixture():
    """Real public executable, vDSO and extension only; no authority custody claim."""
    assert os.getresuid() == os.getresgid() == (0, 0, 0)
    assert "_csv" not in sys.modules
    csv_spec = importlib.machinery.PathFinder.find_spec("_csv")
    assert isinstance(csv_spec.loader, importlib.machinery.ExtensionFileLoader)
    with open(csv_spec.origin, "rb") as stream:
        extension_raw = stream.read(subject.MAX_NATIVE_MAPPING_BYTES + 1)
    assert len(extension_raw) <= subject.MAX_NATIVE_MAPPING_BYTES
    extension = subject._seal_bytes("_csv", extension_raw, mode=0o444)
    executable = os.open("/proc/self/exe", os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(executable)
        executable_raw = subject._read_file(executable, metadata.st_size)
        rows = subject._executable_mapping_rows()
        executable_rows = [value for value in rows
            if (*[int(part, 16) for part in value[3].split(":")], int(value[4]))
            == (os.major(metadata.st_dev), os.minor(metadata.st_dev), metadata.st_ino)]
        assert executable_rows
        selected = executable_rows[0]
        files = {selected[5]: subject._native_file_binding(executable, sha(executable_raw))}
        extension_binding = subject._native_file_binding(extension, sha(extension_raw), sealed=True)
        vdso_rows = [value for value in rows if value[5] == "[vdso]"]
        assert len(vdso_rows) == 1
        bounds = tuple(int(value, 16) for value in vdso_rows[0][0].split("-"))
        assert 0 < bounds[1] - bounds[0] <= 128 * 1024
        with subject._retained_process_memory() as memory:
            vdso_digest = sha(subject._read_process_mapping(memory, *bounds))
            os.setgroups([])
            os.setgid(65523)
            os.setuid(65523)
            assert os.getresuid() == os.getresgid() == (65523,) * 3 and not os.getgroups()
            with open("/proc/self/status", encoding="ascii") as stream:
                status = dict(line.split(":", 1) for line in stream if ":" in line)
            assert all(int(status[key].strip(), 16) == 0 for key in ("CapEff", "CapPrm", "CapInh", "CapAmb"))
            assert status["NoNewPrivs"].strip() == "1"
            for label, path in (("MAP_FILES", "/proc/self/map_files/" + selected[0]),
                                ("OWN_MEMORY", "/proc/self/mem")):
                try:
                    fresh = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                except OSError as error:
                    assert error.errno in (errno.EACCES, errno.EPERM)
                    print("POST_DROP_" + label + "_ERRNO=" + str(error.errno), flush=True)
                else:
                    os.close(fresh)
                    raise AssertionError("fixture did not exercise denied reopen")
            assert selected in subject._executable_mapping_rows()
            assert subject._mapped_file_digest(files=files, path=selected[5], device=selected[3],
                                               inode=selected[4]) == sha(executable_raw)
            assert vdso_rows[0] in subject._executable_mapping_rows()
            assert sha(subject._read_process_mapping(memory, *bounds)) == vdso_digest
            print("POST_DROP_RETAINED_NATIVE_AND_VDSO_HELPERS_PASS=1", flush=True)
            loaded = {}
            finder = subject._SealedClosureFinder({"_csv": dict(descriptor=extension,
                nativeBinding=extension_binding, kind="extension", path=csv_spec.origin,
                isPackage=False)}, loaded)
            spec = finder.find_spec("_csv")
            module = importlib.util.module_from_spec(spec)
            assert loaded == {}
            spec.loader.exec_module(module)
            assert list(module.reader(["public,fixture"])) == [["public", "fixture"]]
            assert loaded == {"/memfd:_csv (deleted)": sha(extension_raw)}
            actual = [value for value in subject._executable_mapping_rows() if value[5] in loaded]
            assert actual
            for value in actual:
                assert subject._mapped_file_digest(files={value[5]: extension_binding}, path=value[5],
                    device=value[3], inode=value[4]) == loaded[value[5]]
            print("POST_DROP_MEASURED_PUBLIC_EXTENSION_LOAD_PASS=1", flush=True)
        try:
            os.fstat(memory[0])
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            raise AssertionError("temporary own-memory FD escaped")
    finally:
        os.close(executable)
        os.close(extension)
    print("PUBLIC_PERMISSION_FIXTURE_RESULT=0", flush=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["--public-drop-fixture"]:
        public_drop_fixture()
    else:
        unittest.main()
