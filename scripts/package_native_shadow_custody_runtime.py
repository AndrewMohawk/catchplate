#!/usr/bin/env python3
"""Fixed offline static claimant image; no key, trust or release authority.

Build-only Python/tool dependencies never enter this six-file SquashFS.
Public policy/runtime/provenance inputs are separately pinned, not generated.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import subprocess
import sys

sys.path.insert(0, "/source/scripts")
from package_native_broker_runtime import ENV, MAX_TOTAL, canonical, original, require, sha

ROOT = Path("/shadow-custody-runtime")
OUTPUT = Path("/shadow-custody-output")
INPUTS = Path("/shadow-custody-inputs")
PREFIX = "/opt/catchplate/native-shadow-custody/"
EXECUTABLE = "/usr/local/bin/catchplate-policy-shadow-custody-guest"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
FIELDS = {"apiVersion", "sourceManifestSha256", "seccompSha256", "runtimeConfigurationSha256",
          "buildRecipeSha256", "provenanceStatementSha256"}


def held(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
            "fixed image original must be a bounded regular non-symlink file")
    data = original(path)
    after = path.lstat()
    require((before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            and len(data) == before.st_size, "fixed image original changed")
    return data


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate fixed image input field")
        result[key] = value
    return result


def static_amd64(data: bytes) -> None:
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01"
            and struct.unpack_from("<H", data, 16)[0] in (2, 3)
            and struct.unpack_from("<H", data, 18)[0] == 62
            and struct.unpack_from("<I", data, 20)[0] == 1
            and struct.unpack_from("<H", data, 52)[0] == 64,
            "guest must be a static little-endian amd64 ELF")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    require(size == 56 and 0 < count <= 1024 and offset >= 64 and offset + count * size <= len(data),
            "guest ELF program table invalid")
    executable_segment = False
    for index in range(count):
        kind, flags, file_offset, _, _, file_size, _, _ = struct.unpack_from("<IIQQQQQQ", data, offset + index * size)
        require(file_offset + file_size <= len(data) and kind != 3, "guest ELF interpreter or segment refused")
        executable_segment |= kind == 1 and bool(flags & 1)
        if kind == 2:
            require(file_size % 16 == 0 and file_size <= 1024 * 1024, "guest ELF dynamic table invalid")
            ended = False
            for entry in range(file_offset, file_offset + file_size, 16):
                tag, _ = struct.unpack_from("<qQ", data, entry)
                require(tag != 1, "guest ELF dynamic dependency refused")
                if tag == 0:
                    ended = True
                    break
            require(ended, "guest ELF dynamic table lacks terminator")
    require(executable_segment, "guest ELF has no executable segment")


def main() -> None:
    require(len(sys.argv) == 1 and os.geteuid() == 0 and platform.machine() == "x86_64",
            "static custody producer requires its fixed build stage")
    epoch_text = os.environ.get("SOURCE_DATE_EPOCH", "")
    require(re.fullmatch(r"0|[1-9][0-9]{0,9}", epoch_text) is not None, "invalid source timestamp")
    epoch = int(epoch_text)
    require(epoch <= 2**32 - 1, "source timestamp exceeds SquashFS bound")
    pin = os.environ.get("SHADOW_CUSTODY_INPUTS_SHA256", "")
    require(DIGEST.fullmatch(pin) is not None and pin != "sha256:" + "0" * 64, "missing independent input pin")
    raw = held(INPUTS / "inputs.json", 16384)
    require(sha(raw) == pin, "public image input manifest pin differs")
    inputs = json.loads(raw, object_pairs_hook=no_duplicates)
    require(type(inputs) is dict and set(inputs) == FIELDS and canonical(inputs) == raw
            and inputs["apiVersion"] == "catchplate.nativeShadowCustodyImageInputs/v1",
            "public image inputs require the closed canonical profile")
    for field in FIELDS - {"apiVersion"}:
        require(type(inputs[field]) is str and DIGEST.fullmatch(inputs[field]) is not None
                and inputs[field] != "sha256:" + "0" * 64, "invalid public image input digest")
    source_pin = sha(held(Path("/source-contract/source-manifest.json"), 4 * 1024 * 1024))
    require(inputs["sourceManifestSha256"] == source_pin, "public inputs select a different admitted source")
    require(set(path.name for path in INPUTS.iterdir())
            == {"inputs.json", "seccomp.bpf", "runtime.json", "build-recipe.json", "provenance.json"},
            "unexpected fixed public image input")
    executable = held(Path("/shadow-static/catchplate-policy-shadow-custody-guest"), 64 * 1024 * 1024)
    static_amd64(executable)
    files = [(EXECUTABLE, executable, "0555")]
    for name, field, maximum in (
        ("seccomp.bpf", "seccompSha256", 32768),
        ("runtime.json", "runtimeConfigurationSha256", 4 * 1024 * 1024),
        ("build-recipe.json", "buildRecipeSha256", 4 * 1024 * 1024),
        ("provenance.json", "provenanceStatementSha256", 4 * 1024 * 1024),
    ):
        data = held(INPUTS / name, maximum)
        require(sha(data) == inputs[field], "public image artifact differs from independent pin")
        if name == "seccomp.bpf":
            require(len(data) % 8 == 0, "seccomp artifact is not exact classic-BPF instructions")
        files.append((PREFIX + name, data, "0444"))
    lock = held(Path("/source/data-plane/decision-gate-rs/Cargo.lock"), 4 * 1024 * 1024)
    files.append((PREFIX + "Cargo.lock", lock, "0444"))
    require(sum(len(data) for _, data, _ in files) <= MAX_TOTAL, "static image closure exceeds bound")
    ROOT.mkdir()
    OUTPUT.mkdir()
    inventory = {}
    for name, data, mode in files:
        destination = ROOT / name[1:]
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(data)
        destination.chmod(int(mode, 8))
        os.utime(destination, (epoch, epoch))
        inventory[name] = {"sha256": sha(data), "size": len(data), "mode": mode}
    (ROOT / "proc").mkdir()
    for directory, directories, names in os.walk(ROOT, followlinks=False, topdown=False):
        base = Path(directory)
        require(not base.is_symlink() and all(not (base / name).is_symlink() for name in directories + names),
                "static image symlink refused")
        base.chmod(0o555)
        os.utime(base, (epoch, epoch))
    image = OUTPUT / "native-shadow-custody-runtime.squashfs"
    subprocess.run(["/usr/bin/mksquashfs", str(ROOT), str(image), "-noappend", "-no-recovery",
        "-no-xattrs", "-no-exports", "-all-root", "-root-mode", "0555", "-comp", "gzip",
        "-b", "131072", "-processors", "1", "-mem", "256M", "-mkfs-time", str(epoch),
        "-all-time", str(epoch), "-reproducible", "-no-progress", "-exit-on-error"],
        env=ENV, check=True, timeout=300)
    require(0 < image.stat().st_size <= MAX_TOTAL, "static image exceeds admitted image bound")
    with image.open("rb") as stream:
        image_sha = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
    manifest = {"apiVersion": "catchplate.nativeShadowCustodyRuntimeBuild/v1",
        "purpose": "native-shadow-static-key-admission-v1", "releaseAuthority": False,
        "imagePath": "/opt/catchplate/native-shadow-custody-runtime.squashfs", "imageSha256": image_sha,
        "workerExecutableSha256": sha(executable), "imageBytes": image.stat().st_size,
        "sourceManifestSha256": source_pin, "inputManifestSha256": pin, "sourceDateEpoch": epoch,
        "files": inventory, "mountTargets": [{"path": "/proc", "type": "directory", "mode": "0555"}]}
    (OUTPUT / "native-shadow-custody-runtime.json").write_bytes(canonical(manifest))
    for path in OUTPUT.iterdir():
        path.chmod(0o444)
        os.utime(path, (epoch, epoch))
    OUTPUT.chmod(0o555)
    os.utime(OUTPUT, (epoch, epoch))


if __name__ == "__main__":
    main()
