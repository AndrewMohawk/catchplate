#!/usr/bin/env python3
"""Offline fixed shadow-key helper image; contains no seeds, KEK or inventory.

This build-stage producer shares bounded ELF/library copying, not the broker's
runtime owner, secret scope, helper entrypoint or image identity.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

# This exact sibling is in the independently admitted source archive. -I
# removes script-directory search; add only this fixed build-stage directory.
sys.path.insert(0, "/source/scripts")
from package_native_broker_runtime import (
    Closure, ENV, INTERPRETER, MAX_TOTAL, PACKAGES, SITE, SOURCE,
    canonical, original, require, sha,
)

ROOT = Path("/shadow-key-runtime")
OUTPUT = Path("/shadow-key-output")
HELPER = Path("/opt/serverware/serverware/native_shadow_key_helper.py")


def main():
    require(len(sys.argv) == 1 and os.geteuid() == 0 and platform.machine() == "x86_64"
        and sys.version_info[:2] == (3, 11), "shadow-key producer requires its fixed build stage")
    epoch_text = os.environ.get("SOURCE_DATE_EPOCH", "")
    require(re.fullmatch(r"0|[1-9][0-9]{0,9}", epoch_text) is not None, "invalid source timestamp")
    epoch = int(epoch_text)
    require(epoch <= 2**32 - 1, "source timestamp exceeds SquashFS range")
    ROOT.mkdir()
    OUTPUT.mkdir()
    closure = Closure(epoch, purpose="shadow-keys")
    closure.add(INTERPRETER, INTERPRETER, executable=True)
    closure.add(Path("/usr/local/lib/libpython3.11.so.1.0"), Path("/usr/local/lib/libpython3.11.so.1.0"))
    closure.tree(Path("/usr/local/lib/python3.11"), Path("/usr/local/lib/python3.11"), stdlib=True)
    for package, version in PACKAGES.items():
        metadata = Path("/deps") / f"{package}-{version}.dist-info"
        require(metadata.is_dir(), "locked shadow-key dependency is unavailable")
        closure.tree(Path("/deps") / package, SITE / package)
        closure.tree(metadata, SITE / metadata.name)
    backends = sorted(Path("/deps").glob("_cffi_backend*.so"))
    require(len(backends) == 1, "shadow-key runtime requires the pinned CFFI extension")
    closure.add(backends[0], SITE / backends[0].name)
    for name in ("__init__.py", "native_kms_cms.py", "native_shadow_nitro_profile.py",
                 "native_shadow_key_contract.py", "native_shadow_key_helper.py"):
        closure.add(SOURCE / "serverware" / name, SITE / "serverware" / name)
    closure.add(SOURCE / "serverware/native_shadow_key_helper.py", HELPER)
    closure.libraries()
    inventory = closure.finish()
    # Executes only in a later explicitly authorized build, never during the
    # source-only implementation. No outside modules or helper entrypoint run.
    subprocess.run(["/usr/sbin/chroot", str(ROOT), str(INTERPRETER), "-I", "-B", "-c",
        "import cryptography,cffi,pycparser; import serverware.native_shadow_key_helper; "
        "import sys; assert sys.prefix == '/usr/local'; assert cryptography.__version__ == '50.0.0'"],
        env=ENV, check=True, timeout=30)
    image = OUTPUT / "native-shadow-key-delivery-runtime.squashfs"
    subprocess.run(["/usr/bin/mksquashfs", str(ROOT), str(image), "-noappend", "-no-recovery",
        "-no-xattrs", "-no-exports", "-all-root", "-root-mode", "0555", "-comp", "gzip",
        "-b", "131072", "-processors", "1", "-mem", "256M", "-mkfs-time", str(epoch),
        "-all-time", str(epoch), "-reproducible", "-no-progress", "-exit-on-error"],
        env=ENV, check=True, timeout=300)
    require(0 < image.stat().st_size <= MAX_TOTAL, "shadow-key runtime exceeds its bound")
    with image.open("rb") as stream:
        image_hash = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
    helper_image = {"profile": "sealed-memfd-squashfs-v1",
        "imagePath": "/opt/serverware/native-shadow-key-delivery-runtime.squashfs",
        "imageSha256": image_hash, "interpreterSha256": closure.files[str(INTERPRETER)]["sha256"],
        "helperSha256": closure.files[str(HELPER)]["sha256"]}
    manifest = {"apiVersion": "serverware.nativeShadowKeyDeliveryRuntimeBuild/v1",
        "helperImage": helper_image,
        "sourceManifestSha256": sha(original(Path("/source-contract/source-manifest.json"))),
        "sourceDateEpoch": epoch, "imageBytes": image.stat().st_size,
        "interpreterPath": str(INTERPRETER), "helperPath": str(HELPER),
        "packages": PACKAGES, "files": inventory, "releaseAuthority": False}
    (OUTPUT / "native-shadow-key-delivery-runtime.json").write_bytes(canonical(manifest))
    for path in OUTPUT.iterdir():
        path.chmod(0o444)
        os.utime(path, (epoch, epoch))
    OUTPUT.chmod(0o555)
    os.utime(OUTPUT, (epoch, epoch))


if __name__ == "__main__":
    main()
