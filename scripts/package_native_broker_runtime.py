#!/usr/bin/env python3
"""Fixed, offline build-stage producer for the enclave broker's complete root.

Run only in the digest-pinned production Python build stage, after the exact
source archive and hash-locked wheelhouse were admitted. This is neither a
release signer nor a runtime loader. No caller-selected packages or commands.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys

ROOT = Path("/broker-runtime")
OUTPUT = Path("/broker-output")
SOURCE = Path("/source")
SITE = Path("/usr/local/lib/python3.11/site-packages")
INTERPRETER = Path("/usr/local/bin/python3.11")
HELPER = Path("/opt/serverware/serverware/native_secret_broker_helper.py")
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_FILES = 20000
ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}
PACKAGES = {"cryptography": "50.0.0", "cffi": "2.1.0", "pycparser": "3.0"}
SKIP = {"__pycache__", "site-packages", "ensurepip", "idlelib", "tkinter", "turtledemo", "test", "tests"}
SAFE_PATH = re.compile(r"/[A-Za-z0-9_./+:-]+\Z")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def original(path: Path) -> bytes:
    """The build inputs are trusted pins; still reject drift and special files."""
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= MAX_FILE,
                "runtime input is not a bounded regular file")
        data = stream.read(MAX_FILE + 1)
        require(len(data) == before.st_size and fingerprint(before) == fingerprint(os.fstat(stream.fileno())),
                "runtime input changed during capture")
        return data


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class Closure:
    def __init__(self, epoch: int, *, purpose: str = "broker") -> None:
        roots = {"broker": ROOT, "role-keys": Path("/role-key-runtime"),
                 "shadow-keys": Path("/shadow-key-runtime"),
                 "shadow-verifier": Path("/shadow-verifier-runtime")}
        require(purpose in roots, "unknown fixed runtime closure purpose")
        self.purpose = purpose
        self.root = roots[purpose]
        self.epoch = epoch
        self.files: dict[str, dict[str, object]] = {}
        self.elf_sources: list[Path] = []
        self.total = 0

    def add(self, source: Path, target: Path, *, executable: bool = False) -> None:
        name = str(target)
        require(SAFE_PATH.fullmatch(name) is not None and ".." not in target.parts,
                "runtime path is outside the fixed closure spelling")
        data = original(source)
        entry = {"sha256": sha(data), "size": len(data), "mode": "0555" if executable else "0444"}
        if name in self.files:
            require(self.files[name] == entry, "two runtime inputs disagree about one output path")
            return
        self.total += len(data)
        require(self.total <= MAX_TOTAL and len(self.files) < MAX_FILES, "runtime closure exceeds its bound")
        destination = self.root / name[1:]
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(data)
        destination.chmod(0o555 if executable else 0o444)
        os.utime(destination, (self.epoch, self.epoch))
        self.files[name] = entry
        if data.startswith(b"\x7fELF"):
            require(len(data) >= 64 and data[4:7] == b"\x02\x01\x01" and data[18:20] == b"\x3e\x00",
                    "runtime ELF must be Linux little-endian x86-64")
            self.elf_sources.append(source)

    def tree(self, source: Path, target: Path, *, stdlib: bool = False) -> None:
        require(source.is_dir() and not source.is_symlink(), "runtime tree must be an actual directory")
        for directory, subdirs, names in os.walk(source, followlinks=False):
            base = Path(directory)
            subdirs[:] = sorted(name for name in subdirs if name != "__pycache__"
                                and (not stdlib or name not in SKIP))
            for name in subdirs:
                require(not (base / name).is_symlink(), "runtime directory symlink refused")
            for name in sorted(names):
                if name.endswith((".pyc", ".pyo")):
                    continue
                path = base / name
                require(not path.is_symlink(), "runtime module symlink refused")
                self.add(path, target / path.relative_to(source))

    def libraries(self) -> None:
        """Use the pinned glibc loader's trace over admitted ELF inputs only.

        ldd reports the PT_INTERP target and recursive DT_NEEDED resolution. Its
        own shell and the build tools are never copied into the runtime. Every
        selected original is copied at the path the runtime loader will use;
        wheel $ORIGIN layouts are preserved under the fixed site-packages root.
        """
        inspected: set[Path] = set()
        while self.elf_sources:
            source = self.elf_sources.pop(0)
            if source in inspected:
                continue
            inspected.add(source)
            result = subprocess.run(["/usr/bin/ldd", str(source)], env=ENV, check=True,
                                    capture_output=True, text=True, timeout=30)
            require(len(result.stdout) <= 65536 and not result.stderr, "loader trace is not bounded and clean")
            for line in result.stdout.splitlines():
                line = line.strip()
                if re.fullmatch(r"linux-vdso\.so\.1 \(0x[0-9a-f]+\)", line):
                    continue
                if line == "statically linked" and source.name == "ld-linux-x86-64.so.2":
                    # The glibc interpreter itself has no external DT_NEEDED
                    # closure. This is not a general unresolved-ELF fallback.
                    continue
                match = re.fullmatch(r"(?:[A-Za-z0-9_.+-]+ => )?(/[A-Za-z0-9_./+-]+) \(0x[0-9a-f]+\)", line)
                require(match is not None, "loader trace contains unresolved or unexpected dependencies")
                library = Path(match.group(1))
                require(".." not in library.parts and library.parts[1] in {"lib", "lib64", "usr", "deps"},
                        "loader selected a path outside the pinned build roots")
                if library.is_relative_to("/deps"):
                    target = SITE / library.relative_to("/deps")
                else:
                    target = library
                # /lib and /usr/lib aliases in the builder become real files,
                # not symlinks, in the private chroot.
                self.add(library, target, executable=str(target).endswith("/ld-linux-x86-64.so.2"))

    def shadow_verifier_mount_targets(self) -> list[dict[str, str]]:
        """Only this offline image's fixed empty, non-authority mount targets."""
        require(self.purpose == "shadow-verifier" and os.geteuid() == 0,
                "mount targets belong only to the fixed external verifier image")
        proc = self.root / "proc"
        proc.mkdir(mode=0o555)
        configuration = self.root / "etc/serverware/native-shadow-nitro-verifier.json"
        configuration.parent.mkdir(parents=True)
        with configuration.open("xb"):
            pass
        configuration.chmod(0o400)
        os.utime(configuration, (self.epoch, self.epoch))
        name = "/etc/serverware/native-shadow-nitro-verifier.json"
        require(name not in self.files and len(self.files) < MAX_FILES,
                "verifier mount target conflicts with the admitted file inventory")
        self.files[name] = {"sha256": sha(b""), "size": 0, "mode": "0400"}
        return [{"path": "/proc", "kind": "directory", "mode": "0555"},
                {"path": name, "kind": "empty-file", "mode": "0400"}]

    def finish(self) -> list[dict[str, object]]:
        # Build a cache for this root only: /usr/local/lib is not a default
        # glibc search directory. -X prevents ldconfig-created symlink aliases.
        configuration = self.root / "etc/ld.so.conf"
        configuration.parent.mkdir(exist_ok=self.purpose == "shadow-verifier")
        configuration.write_text("/usr/local/lib\n/lib/x86_64-linux-gnu\n/usr/lib/x86_64-linux-gnu\n", encoding="ascii")
        subprocess.run(["/sbin/ldconfig", "-i", "-X", "-r", str(self.root)], env=ENV, check=True, timeout=30)
        for path in (configuration, self.root / "etc/ld.so.cache"):
            path.chmod(0o444)
            os.utime(path, (self.epoch, self.epoch))
            self.files["/" + str(path.relative_to(self.root))] = {
                "sha256": sha(original(path)), "size": path.stat().st_size, "mode": "0444"}
        for directory, subdirs, names in os.walk(self.root, followlinks=False):
            path = Path(directory)
            require(not path.is_symlink(), "runtime root contains a symlink")
            path.chmod(0o555)
            os.utime(path, (self.epoch, self.epoch))
            for name in subdirs + names:
                require(not (path / name).is_symlink(), "runtime root contains a symlink")
            for name in names:
                require("/" + str((path / name).relative_to(self.root)) in self.files,
                        "runtime tool introduced an unrecorded file")
        return [{"path": path, **entry} for path, entry in sorted(self.files.items())]


def main() -> None:
    require(len(sys.argv) == 1 and os.geteuid() == 0 and platform.machine() == "x86_64"
            and sys.version_info[:2] == (3, 11), "producer requires its fixed Linux/amd64 Python 3.11 build stage")
    epoch_text = os.environ.get("SOURCE_DATE_EPOCH", "")
    require(re.fullmatch(r"0|[1-9][0-9]{0,9}", epoch_text) is not None, "invalid source timestamp")
    epoch = int(epoch_text)
    require(epoch <= 2**32 - 1, "source timestamp exceeds SquashFS range")
    ROOT.mkdir()
    OUTPUT.mkdir()
    closure = Closure(epoch)
    closure.add(INTERPRETER, INTERPRETER, executable=True)
    closure.add(Path("/usr/local/lib/libpython3.11.so.1.0"), Path("/usr/local/lib/libpython3.11.so.1.0"))
    closure.tree(Path("/usr/local/lib/python3.11"), Path("/usr/local/lib/python3.11"), stdlib=True)
    for package, version in PACKAGES.items():
        metadata = Path("/deps") / f"{package}-{version}.dist-info"
        require(metadata.is_dir(), "locked broker dependency version is unavailable")
        closure.tree(Path("/deps") / package, SITE / package)
        closure.tree(metadata, SITE / metadata.name)
    backends = sorted(Path("/deps").glob("_cffi_backend*.so"))
    require(len(backends) == 1, "broker requires exactly one pinned CFFI extension")
    closure.add(backends[0], SITE / backends[0].name)
    for name in ("__init__.py", "native_kms_cms.py", "native_service_tokens.py", "native_secret_broker_helper.py",
                 "native_oauth_refresh.py", "native_oauth_refresh_receipts.py", "native_oauth_refresh_tls.py", "native_oauth_refresh_owner.py",
                 "native_oauth_exchange.py", "native_oauth_exchange_receipts.py", "native_oauth_exchange_tls.py", "native_oauth_exchange_owner.py",
                 "native_oauth_setup.py", "native_oauth_setup_rows.py", "native_oauth_setup_receipts.py", "native_oauth_setup_tls.py", "native_oauth_setup_owner.py",
                 "native_oauth_cleanup.py", "native_oauth_cleanup_receipts.py", "native_oauth_cleanup_owner.py",
                 "native_oauth_pending_retirement.py", "native_oauth_pending_retirement_receipts.py", "native_oauth_pending_retirement_owner.py",
                 "oauth_retirement_values.py", "native_oauth_capture_retirement.py", "native_oauth_capture_retirement_receipts.py", "native_oauth_capture_retirement_owner.py",
                 "oauth_retirement_policy_values.py", "oauth_pending_retirement_values.py",
                 "oauth_capture_retirement_policy.py", "oauth_pending_retirement_policy.py",
                 "native_oauth_reconnect.py", "native_oauth_reconnect_rows.py", "native_oauth_reconnect_receipts.py", "native_oauth_reconnect_tls.py", "native_oauth_reconnect_owner.py"):
        closure.add(SOURCE / "serverware" / name, SITE / "serverware" / name)
    closure.add(SOURCE / "serverware/native_secret_broker_helper.py", HELPER)
    closure.libraries()
    inventory = closure.finish()
    # This check executes only during the single post-freeze build, in the
    # generated root with no outside modules, loader cache or environment.
    subprocess.run(["/usr/sbin/chroot", str(ROOT), str(INTERPRETER), "-I", "-B", "-c",
                    "import ssl,cryptography,cffi,pycparser; import serverware.native_kms_cms; "
                    "import serverware.native_secret_broker_helper; import sys; "
                    "assert sys.prefix == '/usr/local'; assert cryptography.__version__ == '50.0.0'"],
                   env=ENV, check=True, timeout=30)
    image = OUTPUT / "native-broker-runtime.squashfs"
    # A single worker, fixed compressor, fixed times, root ownership and no
    # append/xattrs/recovery remove host-dependent defaults from the image.
    subprocess.run(["/usr/bin/mksquashfs", str(ROOT), str(image), "-noappend", "-no-recovery",
                    "-no-xattrs", "-no-exports", "-all-root", "-root-mode", "0555",
                    "-comp", "gzip", "-b", "131072", "-processors", "1", "-mem", "256M",
                    "-mkfs-time", str(epoch), "-all-time", str(epoch), "-reproducible",
                    "-no-progress", "-exit-on-error"], env=ENV, check=True, timeout=300)
    require(0 < image.stat().st_size <= MAX_TOTAL, "broker image exceeds its runtime bound")
    with image.open("rb") as stream:
        image_hash = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
    helper_image = {"profile": "sealed-memfd-squashfs-v1",
                    "imagePath": "/opt/serverware/native-broker-runtime.squashfs",
                    "imageSha256": image_hash,
                    "interpreterSha256": closure.files[str(INTERPRETER)]["sha256"],
                    "helperSha256": closure.files[str(HELPER)]["sha256"]}
    manifest = {"apiVersion": "serverware.nativeBrokerRuntimeBuild/v1", "helperImage": helper_image,
                "sourceManifestSha256": sha(original(Path("/source-contract/source-manifest.json"))),
                "sourceDateEpoch": epoch, "imageBytes": image.stat().st_size,
                "interpreterPath": str(INTERPRETER), "helperPath": str(HELPER),
                "packages": PACKAGES, "files": inventory,
                "releaseAuthority": False}
    (OUTPUT / "native-broker-runtime.json").write_bytes(canonical(manifest))
    for path in OUTPUT.iterdir():
        path.chmod(0o444)
        os.utime(path, (epoch, epoch))
    OUTPUT.chmod(0o555)
    os.utime(OUTPUT, (epoch, epoch))


if __name__ == "__main__":
    main()
