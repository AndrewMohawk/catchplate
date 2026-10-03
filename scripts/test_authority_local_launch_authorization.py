#!/usr/bin/env python3
"""Bounded pure joins/source-order controls; no live process admission claim."""
from copy import deepcopy
from contextlib import contextmanager
from pathlib import Path
import ast
import fcntl
import os
import resource
import tempfile
import unittest
from unittest.mock import Mock, patch

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


@contextmanager
def read_owner(raw):
    # Public memfds and this test process only; no authentic issuer or child.
    owner = subject.LocalLaunchAuthorizationIssuer.__new__(subject.LocalLaunchAuthorizationIssuer)
    owner.handles, owner.owned, owner.links, owner.child_handles = [], {}, [], {}
    owner.link_by_fd, owner.mapping_fds = {}, set()
    owner._check_live = Mock()
    originals = []
    try:
        for value in (raw, b"unrelated public fixture"):
            original = os.memfd_create("local-read-control", os.MFD_CLOEXEC)
            originals.append(original)
            os.write(original, value)
            held = os.dup(original)
            owner._hold(held)
            path = f"/proc/self/fd/{original}"
            identity = subject.io._identity(os.fstat(held))
            owner.links.append((held, path, identity))
            owner.link_by_fd[held] = (path, identity)
            owner.child_handles[original] = held
        yield owner, originals, owner.handles
    finally:
        for fd in reversed(owner.handles + originals):
            os.close(fd)


@contextmanager
def native_read_owner(raw):
    # Real local FDs/read/hash/link checks, synthetic generation/verity/frozen
    # results only. This is not kernel fs-verity or authentic child admission.
    with read_owner(raw) as (owner, originals, held):
        info = os.fstat(held[0])
        row = dict(fd=originals[0], runtimePath="/runtime/lib-control.so",
            device=info.st_dev, inode=info.st_ino, mode=subject.stat.S_IMODE(info.st_mode),
            uid=info.st_uid, gid=info.st_gid, size=len(raw), sha256=subject.sha(raw),
            generation=7, fsVerityDigest="sha256:" + "a" * 64)
        with patch.object(subject, "_generation", return_value=7), patch.object(subject, "_frozen"), \
                patch.object(subject.LocalLaunchAuthorizationIssuer, "_measured_verity", return_value=row["fsVerityDigest"]):
            yield owner, originals, held, row


def mapping_copy(owner, fd):
    mapped = os.dup(fd)
    owner._hold(mapped)
    owner.mapping_fds.add(mapped)
    return mapped


class LocalLaunchAuthorizationTests(unittest.TestCase):
    def test_same_call_native_measurement_reuses_only_full_verified_original(self):
        raw = b"synthetic native original" * 3000
        with native_read_owner(raw) as (owner, _originals, _held, row):
            measurements = {}
            owner._read = Mock(wraps=owner._read)
            fd = owner._row(row, regular=True, native_measurements=measurements)
            self.assertEqual(measurements[row["runtimePath"]][0], fd)
            mapped = mapping_copy(owner, fd)
            with patch.object(subject.os, "pread", wraps=os.pread) as pread:
                self.assertEqual(owner._retained_mapping_digest(mapped, measurements[row["runtimePath"]]), row["sha256"])
                pread.assert_called_once_with(mapped, 1, len(raw))
            owner._read.assert_called_once_with(fd, subject.launch.MAX_CLOSURE_FILE_BYTES)
            # A new call-local map still requires a new complete original read.
            fresh = {}
            owner._row(row, regular=True, native_measurements=fresh)
            self.assertEqual(owner._read.call_count, 2)
            self.assertEqual(fresh, measurements)
        for changed in ("sha256", "fsVerityDigest"):
            with self.subTest(changed=changed), native_read_owner(raw) as (owner, _originals, _held, row):
                measurements = {}
                row[changed] = "sha256:" + "b" * 64
                with self.assertRaises(ValueError):
                    owner._row(row, regular=True, native_measurements=measurements)
                self.assertEqual(measurements, {})

    def test_native_reuse_rechecks_physical_custody_guards_and_eof(self):
        for change in ("held", "child", "mapping", "child-index", "owner", "link", "size",
                       "generation", "verity", "frozen", "live", "eof", "after-eof"):
            with self.subTest(change=change), native_read_owner(b"native original") as (owner, originals, held, row):
                measurements = {}
                fd = owner._row(row, regular=True, native_measurements=measurements)
                mapped = mapping_copy(owner, fd)
                real_pread = os.pread
                if change in {"held", "child", "mapping"}:
                    os.dup2(originals[1], {"held": fd, "child": originals[0], "mapping": mapped}[change])
                elif change == "child-index": owner.child_handles[originals[0]] = held[1]
                elif change == "owner": del owner.owned[mapped]
                elif change == "link": del owner.link_by_fd[fd]
                elif change == "size": os.ftruncate(fd, row["size"] + 1)
                elif change == "generation": subject._generation.return_value = 8
                elif change == "verity": owner._measured_verity.return_value = "sha256:" + "b" * 64
                elif change == "frozen": subject._frozen.side_effect = ValueError("not frozen")
                elif change == "live": owner._check_live.side_effect = ValueError("expired or exited")
                def read(descriptor, size, offset):
                    value = real_pread(descriptor, size, offset)
                    if change == "after-eof": os.dup2(originals[1], mapped)
                    return b"unexpected" if change == "eof" else value
                with patch.object(subject.os, "pread", side_effect=read), self.assertRaises(ValueError):
                    owner._retained_mapping_digest(mapped, measurements[row["runtimePath"]])

    def test_mapping_fallback_fresh_vdso_and_unchanged_maps_remain_required(self):
        for scenario in ("eligible", "ineligible", "changed-maps"):
            with self.subTest(scenario=scenario), native_read_owner(b"native original") as (owner, _originals, held, row):
                if scenario == "ineligible": row["fsVerityDigest"] = None
                measurements = {}
                owner._read = Mock(wraps=owner._read)
                owner._row(row, regular=True, native_measurements=measurements)
                self.assertEqual(bool(measurements), scenario != "ineligible")
                known, unknown, memory = (mapping_copy(owner, held[index]) for index in (0, 1, 1))
                lines = []
                for address, fd, path in (("1000-2000", known, row["runtimePath"]),
                                         ("3000-4000", unknown, "/runtime/unknown.so")):
                    info = os.fstat(fd)
                    lines.append(f"{address} r-xp 0 {os.major(info.st_dev):x}:{os.minor(info.st_dev):x} {info.st_ino} {path}\n")
                maps = ("".join(lines) + "0-4 r-xp 0 00:00 0 [vdso]\n").encode("ascii")
                owner.child_pid = os.getpid()
                paths = {f"/proc/{owner.child_pid}/map_files/1000-2000": known,
                    f"/proc/{owner.child_pid}/map_files/3000-4000": unknown,
                    f"/proc/{owner.child_pid}/mem": memory}
                owner._open = Mock(side_effect=paths.__getitem__)
                owner._proc = Mock(side_effect=[maps, maps + b"\n" if scenario == "changed-maps" else maps])
                with patch.object(subject.os, "pread", wraps=os.pread) as pread:
                    if scenario == "changed-maps":
                        with self.assertRaises(ValueError): owner._mappings(measurements)
                    else:
                        self.assertEqual(owner._mappings(measurements), {
                            row["runtimePath"]: row["sha256"],
                            "/runtime/unknown.so": subject.sha(b"unrelated public fixture"),
                            "[vdso]": subject.sha(b"unre")})
                    pread.assert_any_call(memory, 4, 0)
                owner._read.assert_any_call(unknown, subject.launch.MAX_NATIVE_MAPPING_BYTES, mapping=True)
                self.assertEqual(owner._read.call_count, 3 if scenario == "ineligible" else 2)
                self.assertEqual(owner._proc.call_count, 2)

    def test_existing_borrowed_row_and_mappings_need_no_new_methods(self):
        # The pilot prepare helper borrows these methods, not the issuer class.
        # Preserve its complete-read default; this synthetic shape is no owner.
        class Borrower:
            _row = subject.LocalLaunchAuthorizationIssuer._row
            _mappings = subject.LocalLaunchAuthorizationIssuer._mappings
        with native_read_owner(b"native original") as (owner, _originals, held, row):
            borrower = Borrower()
            borrower._child_fd, borrower._read = owner._child_fd, Mock(wraps=owner._read)
            self.assertEqual(borrower._row(row, regular=True), held[0])
            mapped, memory = mapping_copy(owner, held[0]), mapping_copy(owner, held[1])
            info = os.fstat(mapped)
            maps = (f"1000-2000 r-xp 0 {os.major(info.st_dev):x}:{os.minor(info.st_dev):x} {info.st_ino} {row['runtimePath']}\n"
                    + "0-4 r-xp 0 00:00 0 [vdso]\n").encode("ascii")
            borrower.child_pid, borrower.mapping_fds = os.getpid(), owner.mapping_fds
            borrower._proc, borrower.check = Mock(return_value=maps), owner.check
            borrower._open = Mock(side_effect=[mapped, memory])
            self.assertEqual(borrower._mappings(), {
                row["runtimePath"]: row["sha256"], "[vdso]": subject.sha(b"unre")})
            borrower._read.assert_any_call(mapped, subject.launch.MAX_NATIVE_MAPPING_BYTES, mapping=True)
            self.assertFalse(hasattr(borrower, "_measured_verity"))
            self.assertFalse(hasattr(borrower, "_retained_mapping_digest"))

    def test_active_reads_check_each_chunk_and_empty_eof_without_global_sweeps(self):
        for raw in (b"", b"x", b"x" * 65537):
            with self.subTest(size=len(raw)), read_owner(raw) as (owner, _originals, held):
                owner.check = Mock(side_effect=AssertionError("unexpected global sweep"))
                owner._check_link = Mock(wraps=owner._check_link)
                self.assertEqual(owner._read(held[0], 65537), raw)
                calls = 2 * ((len(raw) + 65535) // 65536 + 1)
                self.assertEqual(owner._check_live.call_count, calls)
                self.assertEqual(owner._check_link.call_count, calls)
                self.assertTrue(all(call.args == (held[0],) for call in owner._check_link.call_args_list))
                owner.check.assert_not_called()

    def test_active_reads_refuse_held_or_child_replacement_before_and_after_read(self):
        for raw in (b"", b"payload"):
            for target in ("held", "child"):
                for after in (False, True):
                    with self.subTest(size=len(raw), target=target, after=after), read_owner(raw) as (owner, originals, held):
                        destination = held[0] if target == "held" else originals[0]
                        original_pread = os.pread
                        def changed(fd, size, offset):
                            value = original_pread(fd, size, offset)
                            os.dup2(originals[1], destination)
                            return value
                        if not after:
                            os.dup2(originals[1], destination)
                        with patch.object(subject.os, "pread", side_effect=changed if after else original_pread):
                            with self.assertRaises(ValueError):
                                owner._read(held[0], 65536)

    def test_reads_require_explicit_child_index_or_owned_mapping_registration(self):
        with read_owner(b"mapping") as (owner, _originals, held):
            fd = held[0]
            del owner.link_by_fd[fd]
            with self.assertRaises(ValueError):
                owner._read(fd, 64)
            with self.assertRaises(ValueError):
                owner._read(fd, 64, mapping=True)
            owner.mapping_fds.add(fd)
            self.assertEqual(owner._read(fd, 64, mapping=True), b"mapping")
            with self.assertRaises(ValueError):
                owner._read(fd, 64)
            with self.assertRaises(ValueError):
                owner._read(fd, 64, mapping=1)
            del owner.owned[fd]
            with self.assertRaises(ValueError):
                owner._read(fd, 64, mapping=True)

    def test_active_guard_refusals_and_cached_links_keep_full_boundary_check(self):
        for rejected_call in (1, 2):
            with self.subTest(rejected_call=rejected_call), read_owner(b"") as (owner, _originals, held):
                owner._check_live.side_effect = [None] * (rejected_call - 1) + [ValueError("live guard")]
                with self.assertRaises(ValueError):
                    owner._read(held[0], 64)
                self.assertEqual(owner._check_live.call_count, rejected_call)
        with read_owner(b"active") as (owner, originals, held):
            owner.check = Mock(side_effect=AssertionError("unexpected global sweep"))
            self.assertEqual(owner._child_fd(originals[0]), held[0])
            owner.check.assert_not_called()
            # Unrelated transient sampling is not claimed; full boundary checks
            # must still reject a changed retained link before acceptance.
            os.dup2(originals[0], originals[1])
            self.assertEqual(owner._read(held[0], 64), b"active")
            with self.assertRaises(ValueError):
                subject.LocalLaunchAuthorizationIssuer.check(owner)
            del owner.link_by_fd[held[0]]
            with self.assertRaises(ValueError):
                owner._child_fd(originals[0])

    def test_proc_reads_use_live_guards_and_keep_actual_size_bound(self):
        with read_owner(b"public proc fixture") as (owner, _originals, held):
            owner.child_pid = os.getpid()
            owner._open = Mock(return_value=held[0])
            owner.check = Mock(side_effect=AssertionError("unexpected global sweep"))
            os.lseek(held[0], 0, os.SEEK_SET)
            self.assertEqual(owner._proc("fixture", 64), b"public proc fixture")
            self.assertEqual(owner._check_live.call_count, 4)
            owner.check.assert_not_called()
            os.lseek(held[0], 0, os.SEEK_SET)
            with self.assertRaises(ValueError):
                owner._proc("fixture", 3)

    def test_full_sweeps_and_explicit_mapping_mode_stay_at_security_boundaries(self):
        tree = ast.parse(Path(subject.__file__).read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LocalLaunchAuthorizationIssuer")
        methods = {node.name: node for node in owner.body if isinstance(node, ast.FunctionDef)}
        self.assertEqual(ast.unparse(methods["verify_live"].body[0]), "self.check()")
        self.assertEqual(ast.unparse(methods["verify_live"].body[-1]), "self.check()")
        self.assertIn("self.check_sources()", ast.unparse(methods["_check_live"]))
        self.assertIn("_pidfd_pending(self.pidfd)", ast.unparse(methods["_check_live"]))
        self.assertIn("launch._process_identity(self.child_pid)", ast.unparse(methods["_check_live"]))
        self.assertIn("for fd, path, identity in self.links", ast.unparse(methods["check"]))
        self.assertIn("self.check_sources() if released else self.check()", ast.unparse(methods["publish"]))
        self.assertIn("linked=linked_last if name == OUTPUT_NAMES[-1]", ast.unparse(methods["publish"]))
        mappings = [node for node in ast.walk(owner) if isinstance(node, ast.Call)
            and ast.unparse(node.func) == "self._read" and any(keyword.arg == "mapping" for keyword in node.keywords)]
        self.assertEqual(len(mappings), 1)
        self.assertIn(mappings[0], list(ast.walk(methods["_mappings"])))
        self.assertIn("self.mapping_fds.add(fd)", ast.unparse(methods["_mappings"]))
        self.assertIn("native_measurements = {}", ast.unparse(methods["verify_live"]))
        self.assertIn("self._mappings(native_measurements)", ast.unparse(methods["verify_live"]))
        self.assertNotIn("self.native_measurements", ast.unparse(owner))

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
