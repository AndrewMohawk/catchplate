#!/usr/bin/env python3
"""Build-selection/source controls; never run Docker or a privileged owner."""
from __future__ import annotations

import ast
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))
import build_production_images as build
import native_pilot_runtime_artifacts as artifact
from test_build_production_images import build_metadata_fixture
from serverware import native_pilot_coordinator_process as coordinator


class SupervisorBuildControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="supervisor-build-selection-")
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name).resolve() / "synthetic-supervisor.tar"

    def command(self, **changes):
        args = dict(dockerfile="Dockerfile.production", target=build.NATIVE_PILOT_SUPERVISOR_TARGET,
            output="type=tar,dest=" + str(self.output), network="none",
            platform="linux/amd64", metadata=build_metadata_fixture(),
            context=Path("/synthetic/private-context"), native_pilot_bounded_build=True)
        args.update(changes)
        return build.artifact_build_command(**args)

    def test_fixed_build_selection_preserves_existing_resource_and_network_limits(self):
        self.assertEqual(build.NATIVE_PILOT_SUPERVISOR_TARGET, artifact.SUPERVISOR_TARGET)
        target = ("Dockerfile.production", artifact.SUPERVISOR_TARGET)
        self.assertIn(target, build.PRODUCTION_ARTIFACT_TARGETS)
        self.assertIn(target, build.ENGINEERING_RAW_ARTIFACT_TARGETS)
        argv = self.command()
        self.assertEqual(argv[argv.index("--target") + 1], artifact.SUPERVISOR_TARGET)
        self.assertIn("--network=none", argv)
        self.assertEqual([argv[index + 1] for index, value in enumerate(argv) if value == "--resource"],
            list(build.ENGINEERING_BUILD_RESOURCES))
        self.assertNotIn("SHADOW_CUSTODY_INPUTS_SHA256", " ".join(argv))

    def test_no_arbitrary_target_network_guest_inputs_or_unbounded_raw_export(self):
        for changed in (dict(network="host"), dict(target="arbitrary-supervisor"),
                        dict(public_inputs_sha256="sha256:" + "1" * 64),
                        dict(native_pilot_bounded_build=False)):
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                self.command(**changed)

    def test_docker_source_closure_has_separate_namespace_and_original_child_base(self):
        source = (SCRIPTS.parent / "Dockerfile.production").read_text()
        selected = source.split("FROM verified-production-source AS native-pilot-supervisor-files\n", 1)[1]
        selected = selected.split("FROM gcr.io/distroless/", 1)[0]
        self.assertIn("FROM native-pilot-authority-rootfs AS native-pilot-supervisor-rootfs", selected)
        self.assertIn("FROM scratch AS " + artifact.SUPERVISOR_TARGET, selected)
        self.assertIn("RUN --network=none", selected)
        for name in artifact.SUPERVISOR_FILES:
            self.assertIn("install -m 0444 /source/" + name + " /supervisor-runtime-root/supervisor/app/" + name, selected)
        self.assertNotIn("/conductor/app/scripts", selected)
        self.assertNotIn("/authority/app/scripts", selected)

    def test_runtime_profile_selection_cannot_merge_authority_and_supervisor(self):
        for changed in (dict(authority=True, supervisor=True), dict(supervisor=1), dict(authority=1)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                coordinator._Runtime().admit(b"{}", **changed)
        # A source assertion, not an installed-runtime or privileged launch test.
        tree = ast.parse((SCRIPTS.parent / "serverware/native_pilot_coordinator_process.py").read_text())
        literals = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
        self.assertIn("supervisor", literals)
        self.assertIn("supervisor/app/scripts", literals)


if __name__ == "__main__":
    unittest.main(verbosity=2)
