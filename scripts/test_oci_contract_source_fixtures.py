#!/usr/bin/env python3
"""Hostile source fixtures for the closed OCI attestation contracts."""

from __future__ import annotations

import importlib.util
import base64
import hashlib
import io
import json
import sys
import unittest
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load fixture target: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


OCI = _load_module(
    "serverware_oci_contract_fixture_target",
    ROOT / "scripts/verify_agent_trust_same_journey.py",
)
CLEAN_ROOM = _load_module(
    "serverware_clean_room_fixture_target",
    ROOT / "scripts/test_agent_trust_clean_room.py",
)


def _wheel(
    name: str,
    version: str,
    *,
    requires: list[str] | None = None,
    provides_extras: list[str] | None = None,
) -> dict[str, Any]:
    normalized = CLEAN_ROOM.canonicalize_name(name)
    return {
        "memberCount": 1,
        "name": name,
        "normalizedName": normalized,
        "providesExtras": sorted(provides_extras or []),
        "recordPath": f"{normalized}.dist-info/RECORD",
        "recordSha256": "sha256:" + "1" * 64,
        "requires": sorted(requires or []),
        "sha256": "sha256:" + "2" * 64,
        "version": version,
        "wheel": f"{normalized}-{version}-py3-none-any.whl",
    }


def _tar_octal(value: int, width: int) -> bytes:
    return f"{value:0{width - 1}o}\0".encode("ascii")


def _wheel_archive(*, dist_info: str = "demo-1.0.dist-info") -> bytes:
    contents = {
        f"{dist_info}/METADATA": (
            b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n\n"
        ),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: serverware-fixture\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n\n"
        ),
        "demo/__init__.py": b"VALUE = 1\n",
    }
    record_path = f"{dist_info}/RECORD"
    rows = []
    for path, raw in sorted(contents.items()):
        encoded = base64.urlsafe_b64encode(
            hashlib.sha256(raw).digest()
        ).decode("ascii").rstrip("=")
        rows.append(f"{path},sha256={encoded},{len(raw)}")
    rows.append(f"{record_path},,")
    contents[record_path] = ("\n".join(rows) + "\n").encode("utf-8")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for path, raw in sorted(contents.items()):
            archive.writestr(path, raw)
    return output.getvalue()


def _single_member_tar(
    *,
    leaf: str,
    prefix: str = "",
    member_type: bytes = b"0",
    linkname: str = "",
    mode: int = 0o644,
    content: bytes = b"",
) -> bytes:
    header = bytearray(512)
    header[0:100] = leaf.encode("ascii").ljust(100, b"\0")
    header[100:108] = _tar_octal(mode, 8)
    header[108:116] = _tar_octal(0, 8)
    header[116:124] = _tar_octal(0, 8)
    header[124:136] = _tar_octal(len(content), 12)
    header[136:148] = _tar_octal(0, 12)
    header[148:156] = b"        "
    header[156:157] = member_type
    header[157:257] = linkname.encode("ascii").ljust(100, b"\0")
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[345:500] = prefix.encode("ascii").ljust(155, b"\0")
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    padding = b"\0" * ((512 - len(content) % 512) % 512)
    return bytes(header) + content + padding + b"\0" * 1024


def _outer_oci_tar(
    names: list[str],
    *,
    directories: set[str] | None = None,
) -> bytes:
    directory_names = directories or set()
    members = [
        _single_member_tar(
            leaf=name,
            member_type=b"5" if name in directory_names else b"0",
            mode=0o755 if name in directory_names else 0o644,
            content=b"" if name in directory_names else name.encode("ascii"),
        )[:-1024]
        for name in names
    ]
    return b"".join(members) + b"\0" * 1024


class GitEvidenceFixtures(unittest.TestCase):
    def test_raw_index_and_tree_are_nul_framed_and_complete(self) -> None:
        blob = OCI._git_object_id("sha1", "blob", b"hello\n")
        raw_oid = blob.split(":", 1)[1].encode("ascii")
        raw_index = b"100644 " + raw_oid + b" 0\tREADME.md\x00"
        raw_tree = b"100644 blob " + raw_oid + b"\tREADME.md\x00"
        index = OCI._parse_git_index_evidence(
            raw_index,
            object_format="sha1",
            object_length=40,
        )
        tree = OCI._parse_git_tree_evidence(
            raw_tree,
            object_format="sha1",
            object_length=40,
        )
        self.assertEqual(index[0]["objectId"], blob)
        self.assertEqual(tree[0]["objectId"], blob)
        self.assertEqual(
            OCI._reconstruct_git_tree(index, object_format="sha1"),
            OCI._git_object_id(
                "sha1",
                "tree",
                b"100644 README.md\x00" + bytes.fromhex(raw_oid.decode()),
            ),
        )
        with self.assertRaises(OCI.VerificationError):
            OCI._parse_git_index_evidence(
                raw_index.removesuffix(b"\x00"),
                object_format="sha1",
                object_length=40,
            )

    def test_status_separates_ignored_untracked_and_tracked(self) -> None:
        status = OCI._parse_git_status_evidence(
            b" M README.md\x00?? approved.txt\x00!! ignored.bin\x00"
        )
        self.assertEqual(status["trackedChanges"], [{"path": "README.md", "status": " M"}])
        self.assertEqual(status["untrackedPaths"], ["approved.txt"])
        self.assertEqual(status["ignoredPaths"], ["ignored.bin"])
        with self.assertRaises(OCI.VerificationError):
            OCI._parse_git_status_evidence(b"R  new.txt\x00old.txt\x00")

    def test_empty_status_is_a_canonical_clean_inventory(self) -> None:
        status = OCI._parse_git_status_evidence(b"")
        self.assertEqual(status["trackedChanges"], [])
        self.assertEqual(status["untrackedPaths"], [])
        self.assertEqual(status["ignoredPaths"], [])

    def test_git_inventory_schema_names_raw_index_evidence_exactly(self) -> None:
        verifier = (
            ROOT / "scripts/verify_agent_trust_same_journey.py"
        ).read_text(encoding="ascii")
        self.assertIn("serverware.gitSourceInventory/v3", verifier)
        self.assertIn('"indexInventoryRawSha256"', verifier)
        self.assertIn(
            "Git status and signed worktree changes differ",
            verifier,
        )
        self.assertNotIn('"indexFileSha256"', verifier)


class RequirementFixtures(unittest.TestCase):
    def test_versions_normalized_names_markers_and_extras(self) -> None:
        wheels = [
            _wheel(
                "serverware_enrollment",
                "1.4.0",
                requires=[
                    'dep-name[fast]~=2.1,!=2.2.0; python_version == "3.11"',
                    'unused>=99; python_version < "3"',
                ],
            ),
            _wheel(
                "Dep.Name",
                "2.3.0",
                requires=['leaf==1.0; extra == "fast"'],
                provides_extras=["fast"],
            ),
            _wheel("leaf", "1.0"),
        ]
        dependencies, resolution = CLEAN_ROOM._resolve_requirements(
            wheels,
            {"dep-name": ["fast"]},
        )
        self.assertEqual(len(dependencies), 3)
        active = [item for item in resolution if item["applies"]]
        self.assertEqual(
            sorted(item["normalizedName"] for item in active),
            ["dep-name", "leaf"],
        )
        self.assertTrue(all(item["satisfied"] for item in resolution))

    def test_unsatisfied_specifier_is_denied(self) -> None:
        wheels = [
            _wheel("serverware-enrollment", "1", requires=["dep>=999"]),
            _wheel("dep", "1"),
        ]
        with self.assertRaises(CLEAN_ROOM.ValidationError):
            CLEAN_ROOM._resolve_requirements(wheels, {})

    def test_unselected_extra_is_denied(self) -> None:
        wheels = [
            _wheel(
                "serverware-enrollment",
                "1",
                requires=["dep[fast]==1"],
            ),
            _wheel("dep", "1", provides_extras=["fast"]),
        ]
        with self.assertRaises(CLEAN_ROOM.ValidationError):
            CLEAN_ROOM._resolve_requirements(wheels, {})

    def test_direct_url_and_malformed_trailing_syntax_are_denied(self) -> None:
        for requirement in (
            "dep @ https://example.invalid/dep.whl",
            "dep>=1 trailing",
        ):
            wheels = [
                _wheel(
                    "serverware-enrollment",
                    "1",
                    requires=[requirement],
                ),
                _wheel("dep", "1"),
            ]
            with self.assertRaises(CLEAN_ROOM.ValidationError):
                CLEAN_ROOM._resolve_requirements(wheels, {})

    def test_duplicate_normalized_package_name_is_denied(self) -> None:
        wheels = [
            _wheel("serverware-enrollment", "1"),
            _wheel("Dep_Name", "1"),
            _wheel("dep-name", "1"),
        ]
        with self.assertRaises(CLEAN_ROOM.ValidationError):
            CLEAN_ROOM._resolve_requirements(wheels, {})

    def test_noncanonical_selected_version_is_denied(self) -> None:
        wheels = [_wheel("serverware-enrollment", "v1.0")]
        with self.assertRaises(CLEAN_ROOM.ValidationError):
            CLEAN_ROOM._resolve_requirements(wheels, {})

    def test_unreachable_dependency_cycle_is_denied(self) -> None:
        wheels = [
            _wheel("serverware-enrollment", "1"),
            _wheel("cycle-a", "1", requires=["cycle-b==1"]),
            _wheel("cycle-b", "1", requires=["cycle-a==1"]),
        ]
        with self.assertRaises(CLEAN_ROOM.ValidationError):
            CLEAN_ROOM._resolve_requirements(wheels, {})


class SourceContractFixtures(unittest.TestCase):
    def test_outer_oci_tar_has_one_exact_regular_member_sequence(self) -> None:
        blob = "blobs/sha256/" + "a" * 64
        canonical = ["oci-layout", "index.json", blob]
        records = OCI._validate_canonical_tar(
            _outer_oci_tar(canonical),
            label="outer OCI fixture",
            outer=True,
        )
        self.assertEqual(
            [record["logical"] for record in records],
            canonical,
        )
        for hostile in (
            ["index.json", "oci-layout", blob],
            ["oci-layout", "index.json", blob, "unexpected"],
        ):
            with self.assertRaises(OCI.VerificationError):
                OCI._validate_canonical_tar(
                    _outer_oci_tar(hostile),
                    label="hostile outer OCI fixture",
                    outer=True,
                )
        with self.assertRaises(OCI.VerificationError):
            OCI._validate_canonical_tar(
                _outer_oci_tar(
                    ["oci-layout", "index.json", "blobs/", blob],
                    directories={"blobs/"},
                ),
                label="directory-bearing outer OCI fixture",
                outer=True,
            )

    def test_layer_mode_bits_are_not_collapsed(self) -> None:
        canonical = OCI._validate_canonical_tar(
            _single_member_tar(leaf="member", mode=0o644),
            label="canonical layer fixture",
            outer=False,
        )
        self.assertEqual(canonical[0]["mode"], 0o644)
        with self.assertRaises(OCI.VerificationError):
            OCI._validate_canonical_tar(
                _single_member_tar(leaf="member", mode=0o100644),
                label="hostile layer fixture",
                outer=False,
            )

    def test_independent_wheel_derivation_rejects_wrong_metadata_root(self) -> None:
        def inputs(raw: bytes) -> tuple[dict[str, bytes], dict[str, Any], dict[str, Any]]:
            digest = OCI._sha256(raw)
            package = {
                "name": "demo",
                "normalizedName": "demo",
                "providesExtras": [],
                "requires": [],
                "sha256": digest,
                "version": "1.0",
                "wheel": "demo-1.0-py3-none-any.whl",
            }
            return (
                {
                    (
                        "/opt/serverware/clean-room/wheelhouse/"
                        "demo-1.0-py3-none-any.whl"
                    ): raw,
                },
                {
                    "wheels": [
                        {
                            "path": "demo-1.0-py3-none-any.whl",
                            "sha256": digest,
                        }
                    ],
                },
                {"packages": [package]},
            )

        valid = inputs(_wheel_archive())
        wheel_records, derived = OCI._independent_clean_room_wheel_derivation(
            content_state=valid[0],
            install_contract=valid[1],
            wheelhouse_manifest=valid[2],
        )
        self.assertEqual(wheel_records[0]["normalizedName"], "demo")
        self.assertTrue(derived)

        hostile = inputs(_wheel_archive(dist_info="other-1.0.dist-info"))
        with self.assertRaises(OCI.VerificationError):
            OCI._independent_clean_room_wheel_derivation(
                content_state=hostile[0],
                install_contract=hostile[1],
                wheelhouse_manifest=hostile[2],
            )

    def test_legacy_regular_typeflag_and_hardlink_are_denied(self) -> None:
        for member_type in (b"\0", b"1"):
            with self.assertRaises(OCI.VerificationError):
                OCI._validate_canonical_tar(
                    _single_member_tar(
                        leaf="member",
                        member_type=member_type,
                        linkname="target" if member_type == b"1" else "",
                    ),
                    label="hostile fixture",
                    outer=False,
                )

    def test_noncanonical_ustar_split_is_denied(self) -> None:
        first = "a" * 30
        second = "b" * 30
        leaf = "c" * 60
        logical = f"{first}/{second}/{leaf}"
        self.assertEqual(
            OCI._canonical_ustar_split(logical, label="fixture"),
            (f"{first}/{second}", leaf),
        )
        with self.assertRaises(OCI.VerificationError):
            OCI._validate_canonical_tar(
                _single_member_tar(
                    prefix=first,
                    leaf=f"{second}/{leaf}",
                ),
                label="hostile fixture",
                outer=True,
            )

    def test_full_width_ustar_string_is_not_forced_to_use_nul_padding(self) -> None:
        full_width = b"a" * 100
        self.assertEqual(
            OCI._tar_string(full_width, label="fixture"),
            "a" * 100,
        )
        with self.assertRaises(OCI.VerificationError):
            OCI._tar_string(b"a\x00b", label="fixture")

    def test_npm_companion_waits_for_pipe_close(self) -> None:
        raw = (ROOT / "scripts/npm_publish_companion.js").read_text(
            encoding="ascii"
        )
        self.assertIn('child.once("close"', raw)
        self.assertNotIn('child.once("exit"', raw)
        self.assertNotIn('child.once("error", fail)', raw)
        self.assertIn("let processError = null", raw)
        self.assertIn("processError = error", raw)
        self.assertIn('child.stdout.once("error"', raw)
        self.assertIn('child.stderr.once("error"', raw)

    def test_dependency_capabilities_are_signed_and_argv_bound(self) -> None:
        verifier = (
            ROOT / "scripts/verify_agent_trust_same_journey.py"
        ).read_text(encoding="ascii")
        launcher = (
            ROOT / "scripts/trusted_consolidated_launcher.py"
        ).read_text(encoding="ascii")
        for token in (
            "serverware.ociDependencyBundle/v5",
            "serverware.dependencyCapabilityAttestation/v1",
            "serverware.dependencyCapabilityCatalog/v2",
            "serverware.executableArgvPolicy/v1",
            '"pkg:pypi/packaging@25.0"',
        ):
            self.assertIn(token, verifier)
            self.assertIn(token, launcher)
        self.assertIn(
            "measured executables differ from the signed catalog",
            launcher,
        )

    def test_network_none_receipt_denies_network_events(self) -> None:
        verifier = (
            ROOT / "scripts/verify_agent_trust_same_journey.py"
        ).read_text(encoding="ascii")
        self.assertIn('"network" in event_type.casefold()', verifier)
        self.assertIn('body.get("kind") == "network"', verifier)
        self.assertNotIn('"network",\n            "snapshot"', verifier)

    def test_portal_entrypoint_has_no_absence_monkeypatch(self) -> None:
        raw = (ROOT / "scripts/oci_lane_entrypoint.py").read_text(
            encoding="ascii"
        )
        for forbidden in (
            "portalContainsNodeOrNpm",
            "harnessImportedNpmPrivateModules",
            "_assert_installed_npm_contract_unchanged\"] =",
            "ordinaryProcessInvocations",
            "publicCliEntrypointInvokedDirectly",
            "proxyTransportModuleWrapped",
            "makeFetchIntercepted",
            "preloadUsed",
        ):
            self.assertNotIn(forbidden, raw)

    def test_fixture_inventory_is_canonical_json(self) -> None:
        fixture = {
            "apiVersion": "serverware.ociHostileSourceFixtures/v1",
            "cases": [
                "direct-url-denied",
                "duplicate-normalized-name-denied",
                "empty-git-status-accepted",
                "independently-signed-capability-catalog",
                "legacy-nul-typeflag-denied",
                "network-resource-denied",
                "noncanonical-ustar-split-denied",
                "pipe-close-required",
                "unreachable-dependency-cycle-denied",
                "unselected-extra-denied",
                "unsatisfied-specifier-denied",
                "ustar-full-width-field-accepted",
            ],
        }
        self.assertEqual(
            json.dumps(fixture, separators=(",", ":"), sort_keys=True),
            OCI._canonical_json(fixture).decode("ascii"),
        )


if __name__ == "__main__":
    unittest.main()
