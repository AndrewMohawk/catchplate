#!/usr/bin/env python3
"""Inert real public-file/sealed-FD delivery; no cold admission or launch.

Only fixed path resolution is mapped to this test's private temporary files.
The actual source reader, root ownership/mode checks, seals, target reservations,
literal pins and CLI parser execute unchanged. No keys or valid authority
configuration are fabricated; final cold cryptographic admission is not tested.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import authority_fd_entrypoint as entry


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":")).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def refused(call):
    try:
        call()
    except (RuntimeError, ValueError):
        return
    raise AssertionError("invalid delivery was accepted")


def absent(targets):
    for target in targets:
        try:
            os.fstat(target)
        except OSError as error:
            assert error.errno == 9
        else:
            raise AssertionError("test will not overwrite an existing FD")


def main():
    assert os.getresuid() == os.getresgid() == (0, 0, 0), "run isolated as root"
    slots = {"creation": (80, 81, 82), "rotation": (84, 85, 86)}
    absent((*slots["creation"], *slots["rotation"]))
    actual_open, paths, rows, output = entry._open_source, {}, {}, []
    root, authority = b"public root fixture; not authority\n", b"public full-A fixture; not authority\n"
    with tempfile.TemporaryDirectory(prefix="static-portal-entry-") as temporary:
        def store(path, raw):
            local = Path(temporary) / path.rsplit("/", 1)[1]
            if local.exists():
                local.chmod(0o600)  # Only this test's private fixture is replaced.
            local.write_bytes(raw)
            local.chmod(0o400)
            paths[path] = str(local)

        for purpose, targets in slots.items():
            _, schema, name = entry.STATIC_PORTAL_SOURCES[purpose]
            prefix = "/run/serverware/authority-trust/" + name
            row = {"schema": schema, "sourceRevision": "inert-test",
                "controlPlaneConfigurationDigest": digest(authority), "authorityRootFd": targets[1],
                "authorityRootSha256": digest(root), "authorityRootSpkiSha256": digest(b"public-spki-fixture"),
                "authorityConfigurationFd": targets[2], "authorityConfigurationSha256": digest(authority),
                "authorityConfigurationDigest": digest(authority)}
            rows[purpose] = row
            store(prefix + ".json", canonical(row))
            store(prefix + "-root-public-key", root)
            store(prefix + "-authority-configuration.json", authority)

        def open_fixed(path, **keywords):
            assert path in paths and keywords["expected_owner_uid"] == 0 and keywords["required_mode"] == 0o400
            return actual_open(paths[path], **keywords)

        def selector(purpose, row):
            name = entry.STATIC_PORTAL_SOURCES[purpose][2]
            store("/run/serverware/authority-trust/" + name + ".json", canonical(row))

        def snapshots(targets):
            return [(entry._material_identity(os.fstat(fd)), os.pread(fd, 16385, 0)) for fd in targets]

        with patch.object(entry, "_open_source", side_effect=open_fixed):
            try:
                created = entry._open_static_portal_material("creation", 80, occupied_descriptors=set())
                assert created == slots["creation"]
                output.extend(created)
                before = snapshots(created)
                # A different purpose must not overwrite even identical public material.
                changed = dict(rows["rotation"], authorityRootFd=81)
                selector("rotation", changed)
                refused(lambda: entry._open_static_portal_material("rotation", 84, occupied_descriptors=set(created)))
                assert snapshots(created) == before
                absent(slots["rotation"])
                selector("rotation", rows["rotation"])
                rotated = entry._open_static_portal_material("rotation", 84, occupied_descriptors=set(created))
                assert rotated == slots["rotation"]
                output.extend(rotated)
                seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
                for purpose, targets in slots.items():
                    assert [os.pread(fd, 16385, 0) for fd in targets] == [canonical(rows[purpose]), root, authority]
                    for fd in targets:
                        assert os.get_inheritable(fd) and fcntl.fcntl(fd, fcntl.F_GET_SEALS) == seals
                        assert os.fstat(fd).st_mode & 0o777 == 0o400
                assert snapshots(created) == before
            finally:
                for fd in output:
                    os.close(fd)
                output.clear()
            for changed in (dict(rows["creation"], authorityRootSha256=digest(b"wrong")),
                    dict(rows["creation"], authorityRootFd=80),
                    dict(rows["creation"], schema=entry.STATIC_PORTAL_SOURCES["rotation"][1]),
                    dict(rows["creation"], unknown=True)):
                selector("creation", changed)
                refused(lambda: entry._open_static_portal_material("creation", 80, occupied_descriptors=set()))
                absent(slots["creation"])
            selector("creation", rows["creation"])
            refused(lambda: entry._open_static_portal_material("creation", 80, occupied_descriptors={81}))
            absent(slots["creation"])
            # An actual occupied FD also refuses when absent from the supplied set.
            original = os.memfd_create("static-portal-occupied", os.MFD_CLOEXEC)
            os.write(original, b"must survive unchanged")
            try:
                os.dup2(original, 81, inheritable=False)
                held = snapshots((81,))
                refused(lambda: entry._open_static_portal_material("creation", 80, occupied_descriptors=set()))
                assert snapshots((81,)) == held
                absent((80, 82))
            finally:
                os.close(81)
                os.close(original)
    # Only the final role dispatch is replaced; no service is started.
    arguments = ["entry", "control-plane", "--policy-canary-intake", "--setup-native-observation",
        "--static-credential-creation-fd", "80", "--static-credential-rotation-fd", "84"]
    with patch.object(sys, "argv", arguments), patch.object(entry, "_normal_main", return_value=7) as dispatch:
        assert entry.main() == 7
        dispatch.assert_called_once_with("control-plane", policy_canary_intake=True,
            setup_native_observation=True, static_credential_creation_fd=80, static_credential_rotation_fd=84)
    for tail in (["control-plane", "--static-credential-creation-fd", "080"],
            ["control-plane", "--static-credential-creation-fd", "31"],
            ["control-plane", "--static-credential-creation-fd", "80", "--arbitrary", "value"],
            ["control-plane", "--static-credential-rotation-fd", "84", "--static-credential-creation-fd", "80"],
            ["executor", "--static-credential-creation-fd", "80"],
            ["control-plane", "--policy-file-genesis-maintenance", "--static-credential-creation-fd", "80"]):
        with patch.object(sys, "argv", ["entry", *tail]):
            refused(entry.main)
    refused(lambda: entry._normal_main("executor", static_credential_creation_fd=80))
    refused(lambda: entry._normal_main("control-plane", genesis_maintenance=True, static_credential_creation_fd=80))
    refused(lambda: entry._normal_main("control-plane", static_credential_creation_fd=80, static_credential_rotation_fd=80))
    print("PASS real six-FD delivery, seals/pins, cross-purpose and occupied-slot refusals, closed dispatch; no cold admission/launch")


if __name__ == "__main__":
    main()
