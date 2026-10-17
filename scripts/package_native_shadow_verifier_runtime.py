#!/usr/bin/env python3
"""Offline external Nitro verifier image: no claimant service, keys or policy.

Run only after exact source, hash-locked wheels and pinned Debian build tools
were admitted. The fixed verifier remains an independently deployed authority;
this image producer does not approve a measurement or supply signing material.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

# Isolated Python has no script-directory imports. This source directory is
# fixed by the separately hash-admitted build stage, not a runtime selector.
sys.path.insert(0, "/source/scripts")
from package_native_broker_runtime import (
    Closure, ENV, INTERPRETER, MAX_TOTAL, PACKAGES as CRYPTO_PACKAGES, SITE, SOURCE,
    canonical, original, require, sha,
)

ROOT = Path("/shadow-verifier-runtime")
OUTPUT = Path("/shadow-verifier-output")
ENTRYPOINT = Path("/opt/catchplate/scripts/verify_native_shadow_custody.py")
PACKAGES = {**CRYPTO_PACKAGES, "cbor2": "5.9.0"}


def main():
    require(len(sys.argv) == 1 and os.geteuid() == 0 and platform.machine() == "x86_64"
        and sys.version_info[:2] == (3, 11), "verifier producer requires its fixed build stage")
    epoch_text = os.environ.get("SOURCE_DATE_EPOCH", "")
    require(re.fullmatch(r"0|[1-9][0-9]{0,9}", epoch_text) is not None, "invalid source timestamp")
    epoch = int(epoch_text)
    require(epoch <= 2**32 - 1, "source timestamp exceeds SquashFS range")
    ROOT.mkdir()
    OUTPUT.mkdir()
    closure = Closure(epoch, purpose="shadow-verifier")
    closure.add(INTERPRETER, INTERPRETER, executable=True)
    closure.add(Path("/usr/local/lib/libpython3.11.so.1.0"), Path("/usr/local/lib/libpython3.11.so.1.0"))
    closure.tree(Path("/usr/local/lib/python3.11"), Path("/usr/local/lib/python3.11"), stdlib=True)
    for package, version in PACKAGES.items():
        metadata = Path("/deps") / f"{package}-{version}.dist-info"
        require(metadata.is_dir(), "locked verifier dependency is unavailable")
        closure.tree(Path("/deps") / package, SITE / package)
        closure.tree(metadata, SITE / metadata.name)
    # These are the two top-level extension modules in the admitted CPython
    # 3.11 wheel closure. Refuse an absent/ambiguous wheel layout, no fallback.
    for pattern in ("_cffi_backend*.so", "_cbor2*.so"):
        extensions = sorted(Path("/deps").glob(pattern))
        require(len(extensions) == 1, "verifier requires one pinned native extension per package")
        closure.add(extensions[0], SITE / extensions[0].name)
    for name in ("__init__.py", "native_shadow_nitro_profile.py", "native_shadow_nitro_originals.py",
                 "native_shadow_nitro_verifier.py", "native_shadow_key_admission_profile.py", "native_shadow_key_admission_verifier.py",
                 "native_shadow_bridge_admission_profile.py", "native_shadow_bridge_admission_verifier.py"):
        closure.add(SOURCE / "catchplate" / name, SITE / "catchplate" / name)
    # scripts is deliberately a namespace package, as in the admitted source.
    # No other scripts or authority/store modules enter its isolated search path.
    closure.add(SOURCE / "scripts/verify_nitro_tee.py", SITE / "scripts/verify_nitro_tee.py")
    closure.add(SOURCE / "scripts/verify_native_shadow_custody.py", ENTRYPOINT)
    closure.libraries()
    mount_targets = closure.shadow_verifier_mount_targets()
    inventory = closure.finish()
    # Deferred build-only import check includes the actual lazy Originals and
    # Nitro dependency. It neither invokes run() nor verifies any real evidence.
    subprocess.run(["/usr/sbin/chroot", str(ROOT), str(INTERPRETER), "-I", "-B", "-c",
        "import cbor2,cffi,pycparser,cryptography; import _cbor2,_cffi_backend; "
        "import scripts.verify_nitro_tee; import catchplate.native_shadow_nitro_profile; "
        "import catchplate.native_shadow_nitro_originals; import catchplate.native_shadow_nitro_verifier; "
        "import catchplate.native_shadow_key_admission_profile; import catchplate.native_shadow_key_admission_verifier; "
        "import catchplate.native_shadow_bridge_admission_profile; import catchplate.native_shadow_bridge_admission_verifier; "
        "import sys; from importlib.metadata import version; assert sys.prefix == '/usr/local'; "
        "assert cryptography.__version__ == '50.0.0'; assert version('cbor2') == '5.9.0'"],
        env=ENV, check=True, timeout=30)
    image = OUTPUT / "native-shadow-verifier-runtime.squashfs"
    subprocess.run(["/usr/bin/mksquashfs", str(ROOT), str(image), "-noappend", "-no-recovery",
        "-no-xattrs", "-no-exports", "-all-root", "-root-mode", "0555", "-comp", "gzip",
        "-b", "131072", "-processors", "1", "-mem", "256M", "-mkfs-time", str(epoch),
        "-all-time", str(epoch), "-reproducible", "-no-progress", "-exit-on-error"],
        env=ENV, check=True, timeout=300)
    require(0 < image.stat().st_size <= MAX_TOTAL, "verifier runtime exceeds its bound")
    with image.open("rb") as stream:
        image_hash = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
    runtime_image = {"profile": "sealed-memfd-squashfs-v1",
        "imagePath": "/opt/catchplate/native-shadow-verifier-runtime.squashfs",
        "imageSha256": image_hash, "interpreterSha256": closure.files[str(INTERPRETER)]["sha256"],
        "entrypointSha256": closure.files[str(ENTRYPOINT)]["sha256"]}
    manifest = {"apiVersion": "catchplate.nativeShadowVerifierRuntimeBuild/v1",
        "purpose": "external-shadow-nitro-verifier-v1", "runtimeImage": runtime_image,
        "sourceManifestSha256": sha(original(Path("/source-contract/source-manifest.json"))),
        "sourceDateEpoch": epoch, "imageBytes": image.stat().st_size,
        "interpreterPath": str(INTERPRETER), "entrypointPath": str(ENTRYPOINT),
        "packages": PACKAGES, "files": inventory, "mountTargets": mount_targets, "releaseAuthority": False}
    (OUTPUT / "native-shadow-verifier-runtime.json").write_bytes(canonical(manifest))
    for path in OUTPUT.iterdir():
        path.chmod(0o444)
        os.utime(path, (epoch, epoch))
    OUTPUT.chmod(0o555)
    os.utime(OUTPUT, (epoch, epoch))


if __name__ == "__main__":
    main()
