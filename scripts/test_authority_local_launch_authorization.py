#!/usr/bin/env python3
"""Bounded pure joins/source-order controls; no live process admission claim."""
from copy import deepcopy
from pathlib import Path
import ast
import fcntl
import os
import resource
import tempfile
import unittest

from serverware import authority_local_launch_authorization as subject
from scripts.authority import local_launch_authorization as cli


def binding():
    digest = "sha256:" + "a" * 64
    process = dict(pid=12, uid=0, gid=0, startTimeTicks=34, parentPid=11,
        bootIdDigest=digest, pidNamespaceInode=56, pidfd={"fd": 7})
    bootstrap = dict(fd=8, size=9, sha256=digest)
    interpreter = dict(fd=10, path="/runtime/python/bin/python3", sha256=digest)
    startup = dict(setup=dict(sha256=digest), channel={}, producerPidfd={})
    observed = dict(schema=subject.launch.LOCAL_OBSERVATION_SCHEMA, role="witness", setupSha256=digest,
        process=process, listener={}, bootstrap=bootstrap, interpreter=interpreter, retainedFiles=[],
        retainedDirectories=[], mutableStateDescriptors=[], credentials=[], argv=["actual"], environment={},
        execution=dict(cwd="/runtime", noNewPrivileges=True), startupDescriptors=startup,
        deadlineBoottimeNs=300, expiresAtUnixNanos=400)
    request = dict(schema=subject.stage.LOCAL_STAGE_ZERO_REQUEST_SCHEMA,
        process=dict(processId=12, processStartTicks=34, bootIdDigest=digest, pidfd={"fd": 7}),
        listener={}, startupDescriptors=deepcopy(startup), mutableStateDescriptors=[],
        execution=dict(argv=["actual"], cwd="/runtime", noNewPrivileges=True, executableFd=10),
        environment=dict(values={}), stageZero=dict(bootstrap, interpreter=dict(runtimePath=interpreter["path"], sha256=digest)),
        retainedFiles=[], retainedDirectories=[], credentials=[])
    return dict(role="witness", stageZeroRequest=request), observed


def environment_binding(*, evidence):
    # Synthetic public mappings only, not an authenticated launch request.
    role = "verifier" if evidence else "witness"
    credentials = [{"name": subject.ROOT_NAME, "fd": 77}]
    request = dict(credentials=credentials, bootstrapControl={"fd": 256},
        runtimeEvidence={"fd": 258} if evidence else None)
    assignments = {row["name"]: row["fd"] for row in credentials}
    assignments[subject.stage.BOOTSTRAP_CONTROL_NAME] = 256
    if evidence:
        assignments[subject.stage.RUNTIME_EVIDENCE_NAME] = 258
    startup = dict(setup=dict(fd=50, sha256="sha256:" + "a" * 64), channel=dict(fd=51))
    argv = ["/runtime/python/bin/python3", *subject.stage.REQUIRED_PYTHON_ISOLATION_FLAGS,
        "/proc/self/fd/41", "--bootstrap-fd", "41", "--trusted-host-local",
        "--local-admission-fd", "50", "--local-admission-sha256", startup["setup"]["sha256"],
        "--local-admission-channel-fd", "51"]
    for name, fd in assignments.items():
        argv.extend(("--descriptor", f"{name}={fd}"))
    argv.append(role)
    arguments = dict(role=role, entrypoint=argv[0], bootstrap_fd=41,
        startup=startup, descriptor_bindings=assignments)
    subject.stage.validate_local_argument_vector(argv, **arguments)
    initial = dict(LANG="C.UTF-8", PATH="/runtime/python/bin:/usr/bin",
        SERVERWARE_AUTHORITY_ROLE=role)
    effective = dict(initial, **{name: str(fd) for name, fd in assignments.items()})
    observed = {name: value for name, value in effective.items() if name in subject.launch.LOCAL_EXEC_ENVIRONMENT}
    return request, initial, observed, effective, argv, arguments


class LocalLaunchAuthorizationTests(unittest.TestCase):
    def test_effective_environment_joins_validated_descriptor_arguments(self):
        for evidence in (False, True):
            with self.subTest(evidence=evidence):
                request, initial, observed, effective, _argv, _arguments = environment_binding(evidence=evidence)
                original = deepcopy((request, initial, observed))
                self.assertEqual(subject._effective_environment(initial, request, observed), effective)
                self.assertEqual((request, initial, observed), original)
                self.assertNotIn(subject.ROOT_NAME, initial)
                self.assertEqual(effective[subject.ROOT_NAME], "77")

    def test_effective_environment_refuses_inherited_and_unapproved_values(self):
        request, initial, observed, _effective, _argv, arguments = environment_binding(evidence=True)
        for name in arguments["descriptor_bindings"]:
            for value in ("", str(arguments["descriptor_bindings"][name]), "999"):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    subject._effective_environment(dict(initial, **{name: value}), request, observed)
        for changed in (dict(initial, LD_PRELOAD="/unapproved.so"), dict(initial, UNAPPROVED="1"),
                        dict(initial, LANG="different")):
            with self.subTest(initial=changed), self.assertRaises(ValueError):
                subject._effective_environment(changed, request, observed)
        for changed in (dict(observed, **{subject.stage.BOOTSTRAP_CONTROL_NAME: "999"}),
                        dict(observed, **{subject.stage.RUNTIME_EVIDENCE_NAME: "999"}),
                        dict(observed, UNAPPROVED="1")):
            with self.subTest(observed=changed), self.assertRaises(ValueError):
                subject._effective_environment(initial, request, changed)

    def test_descriptor_environment_join_requires_exact_argument_contract(self):
        _request, _initial, _observed, _effective, argv, arguments = environment_binding(evidence=True)
        changed_fd = list(argv)
        index = changed_fd.index(subject.ROOT_NAME + "=77")
        changed_fd[index] = subject.ROOT_NAME + "=78"
        for changed in (changed_fd, argv[:-1] + ["--descriptor", subject.ROOT_NAME + "=77", argv[-1]],
                        argv[:-1] + ["--descriptor", "UNAPPROVED=79", argv[-1]]):
            with self.subTest(argv=changed), self.assertRaises(subject.stage.StageZeroContractError):
                subject.stage.validate_local_argument_vector(changed, **arguments)

    def test_environment_reconstruction_follows_live_argv_check_and_precedes_fd_checks(self):
        tree = ast.parse(Path(subject.__file__).read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LocalLaunchAuthorizationIssuer")
        verify = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "verify_live")
        calls = [node for node in ast.walk(verify) if isinstance(node, ast.Call)]
        argv_check = next(node for node in calls if ast.unparse(node.func) == "require"
                         and 'self._proc(\'cmdline\'' in ast.unparse(node))
        reconstruction = next(node for node in calls if ast.unparse(node.func) == "_effective_environment")
        self.assertLess(argv_check.lineno, reconstruction.lineno)
        self.assertTrue(all(node.lineno > reconstruction.lineno for node in calls
                            if ast.unparse(node.func) == "self._row"))
        self.assertIn("environment[row['name']] == str(row['fd'])", ast.unparse(verify))

    def test_real_high_pidfd_pending_and_invalid_refusal(self):
        # Actual kernel PIDFD, not a synthetic issuer/admission carrier.
        before = resource.getrlimit(resource.RLIMIT_NOFILE)
        original = high = None
        try:
            self.assertGreaterEqual(before[1], 1025)
            if before[0] < 1025:
                resource.setrlimit(resource.RLIMIT_NOFILE, (1025, before[1]))
            original = os.pidfd_open(os.getpid(), 0)
            high = fcntl.fcntl(original, fcntl.F_DUPFD_CLOEXEC, 1024)
            self.assertGreaterEqual(high, 1024)
            self.assertTrue(subject._pidfd_pending(high))
            closed = high
            os.close(high)
            high = None
            with self.assertRaises(ValueError):
                subject._pidfd_pending(closed)
        finally:
            if high is not None:
                os.close(high)
            if original is not None:
                os.close(original)
            resource.setrlimit(resource.RLIMIT_NOFILE, before)

    def test_literal_binding_only(self):
        payload, observed = binding()
        subject.bind_observation(payload, observed)
        # This helper deliberately does not assert an actual process owner.

    def test_process_and_argv_substitution_refused(self):
        for change in ("process", "argv"):
            payload, observed = binding()
            if change == "process":
                payload["stageZeroRequest"]["process"]["processId"] += 1
            else:
                payload["stageZeroRequest"]["execution"]["argv"] = ["different"]
            with self.assertRaises(ValueError):
                subject.bind_observation(payload, observed)

    def test_native_and_observation_extensions_refused(self):
        payload, observed = binding()
        payload["stageZeroRequest"]["schema"] = subject.stage.STAGE_ZERO_REQUEST_SCHEMA
        with self.assertRaises(ValueError):
            subject.bind_observation(payload, observed)
        payload, observed = binding()
        observed["hardwareBacked"] = True
        with self.assertRaises(ValueError):
            subject.bind_observation(payload, observed)

    def test_fixed_cli_and_alias_refusal(self):
        argv = ["--approval-fd", "3", "--approval-sha256", "sha256:" + "a" * 64,
            "--exchange-directory-fd", "4", "--root-key-fd", "5", "--certificate-key-fd", "6"]
        self.assertEqual(cli.arguments(argv)["certificate_key_fd"], 6)
        for bad in (argv + ["--command", "anything"], argv[:-1] + ["5"], argv[:1] + ["03"] + argv[2:]):
            with self.assertRaises(ValueError):
                cli.arguments(bad)

    def test_distinct_domains_and_partial_pair_contract(self):
        self.assertEqual(subject.OUTPUT_NAMES, ("certificate.json", "manifest.json"))
        self.assertEqual(subject.DELEGATION, "configuration-root-also-signs-local-launch-manifest-v7")
        self.assertNotEqual(subject.launch.LAUNCH_MANIFEST_SCHEMA, subject.stage.LOCAL_LAUNCH_CERTIFICATE_SIGNATURE_DOMAIN)
        self.assertIn("does NOT", cli.USAGE)

    def test_actual_measurement_before_signing_and_publication_last(self):
        tree = ast.parse(Path(subject.__file__).read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LocalLaunchAuthorizationIssuer")
        issue = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "issue")
        calls = [(node.lineno, ast.unparse(node.func)) for node in ast.walk(issue) if isinstance(node, ast.Call)]
        live = sorted(line for line, name in calls if name == "self.verify_live")
        signatures = [line for line, name in calls if name.endswith(".sign")]
        self.assertEqual(len(live), 2)
        self.assertLess(live[0], min(signatures))
        self.assertGreater(live[1], max(signatures))
        source = ast.unparse(owner)
        for actual in ("os.pidfd_open", "libc.syscall(438", "fcntl.ioctl", "io.signing_key", "_generation", "_frozen"):
            self.assertIn(actual, source)

    def test_keyless_observer_cannot_issue_pair(self):
        tree = ast.parse(Path(subject.__file__).read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LocalLaunchAuthorizationIssuer")
        observer = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "open_observer")
        self.assertIn("key_fds=()", ast.unparse(observer))
        issue = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "issue")
        condition = next(node.args[0] for node in ast.walk(issue)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "require")
        self.assertIsInstance(condition, ast.BoolOp)
        self.assertIsInstance(condition.op, ast.And)
        comparisons = {node.left.attr for node in condition.values
            if isinstance(node, ast.Compare) and isinstance(node.left, ast.Attribute)
            and isinstance(node.left.value, ast.Name) and node.left.value.id == "self"
            and len(node.ops) == 1 and isinstance(node.ops[0], ast.IsNot)
            and len(node.comparators) == 1 and isinstance(node.comparators[0], ast.Constant)
            and node.comparators[0].value is None}
        self.assertEqual(comparisons, {"root_key", "certificate_key"})

    def test_actual_anonymous_publication_and_no_overwrite(self):
        # Genuine local kernel file publication only; no fake child/issuer owner.
        with tempfile.TemporaryDirectory(prefix="local-late-publication-") as path:
            directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            held, linked = [], []
            try:
                def check():
                    self.assertLessEqual(set(os.listdir(directory)), {"evidence.json"})
                raw = b'{"complete":true}'
                fd = subject.publish_late_original(directory, "evidence.json", raw,
                    hold=held.append, check=check, linked=lambda: linked.append(True))
                self.assertEqual(linked, [True])
                self.assertEqual(os.pread(fd, len(raw) + 1, 0), raw)
                self.assertEqual(os.stat("evidence.json", dir_fd=directory).st_ino, os.fstat(fd).st_ino)
                with self.assertRaises(ValueError):
                    subject.publish_late_original(directory, "evidence.json", raw,
                        hold=held.append, check=check, linked=lambda: linked.append(False))
                self.assertEqual(linked, [True])
                self.assertEqual(set(os.listdir(directory)), {"evidence.json"})
            finally:
                for fd in reversed(held):
                    os.close(fd)
                os.close(directory)


if __name__ == "__main__":
    unittest.main()
