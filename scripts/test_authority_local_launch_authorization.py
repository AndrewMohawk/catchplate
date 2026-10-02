#!/usr/bin/env python3
"""Bounded pure joins/source-order controls; no live process admission claim."""
from copy import deepcopy
from pathlib import Path
import ast
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


class LocalLaunchAuthorizationTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
