#!/usr/bin/env python3
"""Pure recipe/provenance tests; never launch Docker, a checker or a socket.

Only the frozen source's stdlib-only recipe builders are imported. Launcher
guards use inert synthetic modules; temporary files test content/type checks.
This suite is not proxy, provider, runtime-import or deployment acceptance.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import importlib
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import prepare_operator_retained_pair_fixture as selected


FILES = {name.replace(".", "/") + ".py": format(index, "064x")
    for index, name in enumerate(selected.IMPORTS, 1)}
JOB = Path("/srv/catchplate-fast/tmp/catchplate-proxy-basic-private.recipe2026")
EVIDENCE = selected.EVIDENCE_ROOT / "private-retained-pair.recipe2026"
SUBNET = "172.30.249.112/28"


def launcher_namespace():
    tree = ast.parse(selected.checker_launcher(FILES, "a" * 64))
    # Do not execute the final invocation/exit. These definitions contain no
    # fixture, application or dependency imports and make no external calls.
    tree.body = [node for node in tree.body if isinstance(node,
        (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef))]
    namespace = {}
    exec(compile(tree, "<synthetic-launcher-guards>", "exec"), namespace)
    return namespace


def synthetic_modules():
    modules = {name: SimpleNamespace(__file__="/app/" + name.replace(".", "/") + ".py")
        for name in selected.IMPORTS}
    modules["scripts.check_operator_proxy_basic"] = SimpleNamespace(__file__=selected.CHECKER_TARGET)
    for name in ("requests", "urllib3"):
        modules[name] = SimpleNamespace(__file__="/client-dependencies/site-packages/" + name + "/__init__.py")
    for value in modules.values():
        value.__spec__ = SimpleNamespace(origin=value.__file__)
    modules["scripts"] = SimpleNamespace(__path__=["/app/scripts"])
    return modules


class RetainedPairRecipeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Read-only exact archive verification before importing its pure builder.
        selected.frozen_source()
        sys.path.insert(0, str(selected.SOURCE))
        cls.basic = importlib.import_module("scripts.prepare_operator_proxy_basic_fixture")
        assert Path(cls.basic.__file__).is_relative_to(selected.SOURCE)
        assert Path(cls.basic.base.__file__).is_relative_to(selected.SOURCE)

    def setUp(self):
        self.guards = ExitStack()
        self.addCleanup(self.guards.close)
        for target in ("subprocess.run", "subprocess.Popen", "socket.socket"):
            self.guards.enter_context(patch(target, side_effect=AssertionError("external execution forbidden")))

    def baseline(self):
        return self.basic.build(selected.SOURCE, selected.BINARY, selected.INITIALIZER,
            JOB, SUBNET, expected_binary_sha256=selected.BINARY_SHA)

    def test_exact_baseline_unchanged_except_dormant_checker_file_and_launch(self):
        baseline = self.baseline()
        original = deepcopy(baseline)
        adapted = selected.corrected_recipe(baseline, FILES, self.basic)
        self.assertEqual(baseline, original)
        for name in baseline["services"]:
            if name != "check":
                self.assertEqual(adapted["services"][name], baseline["services"][name])
        check, old = adapted["services"]["check"], baseline["services"]["check"]
        self.assertEqual(check["entrypoint"], ["/usr/bin/python3.10", "-I", "-B", "-c"])
        self.assertEqual(check["command"][1:], old["command"][1:])
        self.assertEqual(check["environment"], {"PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(check["volumes"][:-1], old["volumes"])
        self.assertEqual(check["volumes"][-1], self.basic.base.bind(selected.CHECKER, selected.CHECKER_TARGET))
        for key in set(check) - {"entrypoint", "command", "environment", "volumes"}:
            self.assertEqual(check[key], old[key])
        self.assertEqual(adapted["networks"], baseline["networks"])
        self.assertTrue(adapted["networks"]["fixture"]["internal"])

    def test_launcher_pins_exact_commits_and_closes_helper_inventory(self):
        script = selected.checker_launcher(FILES, self.basic.DEPENDENCY_MANIFEST_SHA256)
        compile(script, "<launcher>", "exec")
        namespace = launcher_namespace()
        self.assertEqual(namespace["CHECKER_HASH"], selected.CHECKER_SHA)
        self.assertEqual(set(namespace["SCRIPT_HASHES"]), set(selected.IMPORTS))
        self.assertEqual(selected.CHECKER_COMMIT, "3cfeb9a3ae088a7a8bce9bd063a569bf32a305e4")
        for changed in ({}, {**FILES, next(iter(FILES)): "bad"}):
            with self.assertRaises((KeyError, AssertionError)):
                selected.checker_launcher(changed, "a" * 64)
        with self.assertRaises(AssertionError):
            selected.checker_launcher(FILES, "bad")

    def test_runtime_import_roster_and_dependency_origins_are_exact(self):
        namespace = launcher_namespace()
        modules = synthetic_modules()
        namespace["sys"] = SimpleNamespace(modules=modules)
        namespace["pinned"] = Mock()
        dependencies = {"site-packages/" + name + "/__init__.py": "b" * 64 for name in ("requests", "urllib3")}
        namespace["verify_imports"](dependencies)
        self.assertEqual(namespace["pinned"].call_count, 2)
        cases = (
            lambda rows: rows["scripts"].__path__.append("/unreviewed/scripts"),
            lambda rows: rows.pop(selected.IMPORTS[0]),
            lambda rows: rows.update({"scripts.unreviewed": SimpleNamespace()}),
            lambda rows: setattr(rows[selected.IMPORTS[0]], "__file__", "/unreviewed/module.py"),
            lambda rows: setattr(rows[selected.IMPORTS[0]].__spec__, "origin", "/unreviewed/module.py"),
            lambda rows: setattr(rows["requests"], "__file__", "/usr/lib/python3/dist-packages/requests/__init__.py"),
            lambda rows: setattr(rows["urllib3"].__spec__, "origin", "/unreviewed/urllib3.py"),
            lambda rows: rows.pop("requests"),
        )
        for mutation in cases:
            with self.subTest(mutation=mutation):
                namespace["sys"].modules = synthetic_modules()
                mutation(namespace["sys"].modules)
                with self.assertRaises(ValueError):
                    namespace["verify_imports"](dependencies)
        namespace["sys"].modules = synthetic_modules()
        with self.assertRaises(ValueError):
            namespace["verify_imports"]({})

    def test_pin_checks_content_readonly_mode_regular_type_and_links(self):
        pinned = launcher_namespace()["pinned"]
        with tempfile.TemporaryDirectory(prefix="retained-recipe-pure-") as directory:
            path = Path(directory) / "module.py"
            path.write_bytes(b"synthetic inert source\n")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            path.chmod(0o444)
            pinned(path, expected)
            for target, digest in ((path, "f" * 64), (Path(directory), expected)):
                with self.assertRaises(ValueError):
                    pinned(target, digest)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                pinned(path, expected)
            path.chmod(0o444)
            link = Path(directory) / "symlink.py"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                pinned(link, expected)
            hardlink = Path(directory) / "hardlink.py"
            hardlink.hardlink_to(path)
            with self.assertRaises(ValueError):
                pinned(path, expected)

    def test_help_systemexit_still_performs_final_provenance_checks(self):
        namespace = launcher_namespace()
        scripts = ModuleType("scripts")
        scripts.__path__ = ["/app/scripts"]
        fake_sys = SimpleNamespace(flags=SimpleNamespace(isolated=1, optimize=0), dont_write_bytecode=True,
            path=["/usr/lib/python3.10", "/unreviewed", "/usr/lib/python3/dist-packages"],
            modules={}, argv=["-c", "--help"], version_info=sys.version_info)
        namespace["sys"] = fake_sys
        namespace["sysconfig"] = SimpleNamespace(get_path=lambda key: "/usr/lib/python3.10",
            get_config_var=lambda key: "/usr/lib/python3.10/lib-dynload")
        namespace["verify_files"] = Mock(return_value={"synthetic": "a" * 64})
        namespace["verify_imports"] = Mock()
        checker = SimpleNamespace(main=Mock(side_effect=SystemExit(0)))
        spec = SimpleNamespace(name="scripts.check_operator_proxy_basic", loader=SimpleNamespace(exec_module=Mock()))
        namespace["importlib"] = SimpleNamespace(util=SimpleNamespace(spec_from_file_location=Mock(return_value=spec),
            module_from_spec=Mock(return_value=checker)))
        with patch.dict(sys.modules, {"scripts": scripts}):
            with self.assertRaises(SystemExit) as caught:
                namespace["run"]()
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(namespace["verify_files"].call_count, 2)
        self.assertEqual(namespace["verify_imports"].call_count, 2)
        self.assertEqual(fake_sys.path, ["/app", "/client-dependencies/site-packages", "/usr/lib/python3.10"])
        self.assertEqual(fake_sys.argv, [selected.CHECKER_TARGET, "--help"])
        namespace["verify_files"].reset_mock()
        fake_sys.flags.isolated = 0
        with self.assertRaises(ValueError):
            namespace["run"]()
        namespace["verify_files"].assert_not_called()

    def test_default_preparation_is_readonly_and_describes_separate_help_preflight(self):
        args = SimpleNamespace(job_root=JOB, evidence_dir=EVIDENCE, subnet=SUBNET, write=False,
            verify_prepared=False, expected_plan_sha256=None)
        with patch.object(selected, "frozen_source", return_value=FILES), \
             patch.object(selected, "pinned_checker") as checker_pin, \
             patch.object(self.basic, "dependency_inventory"), \
             patch.object(self.basic, "prepare") as writer, \
             patch.object(selected, "write_new") as write, \
             patch.object(self.basic.base, "fresh_root") as fresh:
            plan = selected.prepare(args)
        writer.assert_not_called()
        write.assert_not_called()
        checker_pin.assert_called_once_with()
        self.assertEqual(fresh.call_count, 2)
        self.assertTrue(all(call.kwargs == {"must_exist": False} for call in fresh.call_args_list))
        self.assertFalse(plan["automaticExecution"] or plan["launched"] or plan["written"] or plan["productionReady"])
        self.assertEqual(plan["phaseOrder"][0], "network-none-import-help")
        preflight = plan["importOnlyPreflight"]
        self.assertEqual(preflight["networkMode"], "none")
        self.assertEqual(preflight["arguments"], ["--help"])
        self.assertEqual(preflight["mountTargetsOnly"], ["/app", "/client-dependencies", selected.CHECKER_TARGET])
        self.assertFalse(preflight["fixtureAuthorityMounted"])
        self.assertEqual((plan["peakDeclaredCpuLimit"], plan["peakDeclaredMemoryMiB"]), (5, 2432))
        self.assertEqual((plan["baselineStartupLimitSeconds"], plan["checkerLimitSeconds"], plan["edgeLifetimeSeconds"]),
            (150, 120, 240))

    def test_verification_requires_external_plan_pin_and_excludes_write(self):
        for verify, write, pin in ((True, False, None), (False, False, "a" * 64), (True, True, "a" * 64)):
            args = SimpleNamespace(job_root=JOB, evidence_dir=EVIDENCE, subnet=SUBNET, write=write,
                verify_prepared=verify, expected_plan_sha256=pin)
            with self.subTest(verify=verify, write=write, pin=pin), \
                 patch.object(selected, "frozen_source", return_value=FILES), \
                 patch.object(selected, "pinned_checker"), patch.object(selected, "write_new") as writer:
                with self.assertRaises(AssertionError):
                    selected.prepare(args)
                writer.assert_not_called()

    def test_preparation_and_readonly_verification_roundtrip_refuse_changed_outputs(self):
        # Synthetic temporary recipe documents only: no initializer, container,
        # credential, application database or checker execution is performed.
        with tempfile.TemporaryDirectory(prefix="retained-recipe-pure-") as directory:
            root = Path(directory)
            job = root / "catchplate-proxy-basic-private.roundtrip2026"
            evidence = root / "private-retained-pair.roundtrip2026"
            job.mkdir(mode=0o700)
            evidence.mkdir(mode=0o700)
            args = SimpleNamespace(job_root=job, evidence_dir=evidence, subnet=SUBNET, write=True,
                verify_prepared=False, expected_plan_sha256=None)
            with patch.object(self.basic.base, "SCRATCH", root), patch.object(selected, "EVIDENCE_ROOT", root):
                prepared = selected.prepare(args)
                self.assertEqual(set(path.name for path in job.iterdir()), {"runtime", "compose.json", "preparation.json"})
                self.assertEqual(list((job / "runtime").iterdir()), [])
                self.assertEqual(set(path.name for path in evidence.iterdir()), {"source-manifest.json", "exact-pair-plan.json"})
                expected = {path: path.read_bytes() for path in (job / "compose.json", job / "preparation.json",
                    evidence / "source-manifest.json", evidence / "exact-pair-plan.json")}
                args.write, args.verify_prepared = False, True
                args.expected_plan_sha256 = prepared["planFileSha256"]
                result = selected.prepare(args)
                self.assertTrue(result["verificationOnly"])
                self.assertFalse(result["launched"] or result["productionReady"])
                self.assertEqual({path: path.read_bytes() for path in expected}, expected)
                for path, content in expected.items():
                    with self.subTest(changed=path.name):
                        path.write_bytes(content + b" ")
                        with self.assertRaises(ValueError):
                            selected.prepare(args)
                        path.write_bytes(content)
                self.assertEqual(list((job / "runtime").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
