"""Offline source companion for the two retained Debian binaries; not legal approval."""
from __future__ import annotations

import argparse
import email.parser
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile


HERE = Path(__file__).resolve().parent
CANDIDATE_ID = "catchplate-production-dependencies-linux-amd64-v3-candidate-cba01916"
REPORT_SHA256 = "38b4ea78b2ab07faa68e3193087d33072998bddb9dd404e9b5fd9e6fe6f37a00"
GPL_SHA256 = "8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643"
# Exact official Debian source originals. Acquisition is a separate operation;
# these reviewed byte pins, not a newly inferred PGP verdict, admit local inputs.
PACKAGES = (
    {
        "source": "squashfs-tools", "version": "1:4.5.1-1", "binary": "squashfs-tools",
        "deb": "squashfs-tools_4.5.1-1_amd64.deb", "bytes": 182756,
        "sha256": "3f96b16c9b985ea03cf70f90a05f4dc5c15039e845326f8f4293a3280fd0b2f4",
        "base": "https://deb.debian.org/debian/pool/main/s/squashfs-tools/",
        "dsc": ("squashfs-tools_4.5.1-1.dsc", "b5ec6308d47e52fac7016763fe08b1bb7397e1322685e609b031dbd174c991fd"),
        "archives": (
            ("squashfs-tools_4.5.1.orig.tar.gz", 270112, "277b6e7f75a4a57f72191295ae62766a10d627a4f5e5f19eadfbc861378deea7"),
            ("squashfs-tools_4.5.1-1.debian.tar.xz", 10080, "7801421dfda21bf37563f0012d57f568332086eb1d31749844c7c52548db43fd"),
        ),
    },
    {
        "source": "lzo2", "version": "2.10-2", "binary": "liblzo2-2",
        "deb": "liblzo2-2_2.10-2_amd64.deb", "bytes": 56912,
        "sha256": "4f08e092c76e425295a498cd547dc9b8f6a595473f3020ab8c96309b29872636",
        "base": "https://deb.debian.org/debian/pool/main/l/lzo2/",
        "dsc": ("lzo2_2.10-2.dsc", "65a35d9d2511a88f30d4b10313f807c184d1906062e2421833797dafc2682166"),
        "archives": (
            ("lzo2_2.10.orig.tar.gz", 600622, "c0f892943208266f9b6543b3ae308fab6284c5c90e627931446fb49b4221a072"),
            ("lzo2_2.10-2.debian.tar.xz", 6880, "095b2bf2012138f6892fcf226a0d1eae5d29406d7afe7129d51d64116e61c472"),
        ),
    },
)


def require(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_fixed(path: Path, expected: str, maximum: int = 1024 * 1024) -> bytes:
    require(path.parent.resolve(strict=True) == path.parent, "input parent must be a real directory")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        # The source-fixed public license follows normal Git checkout modes;
        # its exact hash and stable identity remain mandatory, unlike a caller waiver.
        forbidden_write = 0o002 if path == HERE / "licenses/GPL-2.0.txt" else 0o022
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and not before.st_mode & forbidden_write and 0 < before.st_size <= maximum,
                "input must be a bounded, non-writable-by-others regular original")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(maximum + 1)
        require(len(raw) == before.st_size and digest(raw) == expected
                and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
                "input bytes or identity differ from the fixed reviewed original")
        return raw
    finally:
        os.close(fd)


def tar_member(raw: bytes, name: str) -> bytes:
    """Read one regular member in memory; never extract an archive into a directory."""
    found = None
    expanded = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
        for count, member in enumerate(archive, 1):
            expanded += member.size
            require(count <= 4096 and member.size >= 0 and expanded <= 32 * 1024 * 1024,
                    "archive metadata exceeds the companion bound")
            if member.name != name:
                continue
            require(found is None and member.isreg() and not member.sparse
                    and 0 < member.size <= 128 * 1024, "notice member is not exact")
            stream = archive.extractfile(member)
            require(stream is not None, "notice member has no bytes")
            with stream:
                found = stream.read(128 * 1024 + 1)
            require(len(found) == member.size, "notice member was truncated")
    require(found is not None, "required notice member is absent")
    return found


def deb_members(raw: bytes) -> dict[str, bytes]:
    require(raw.startswith(b"!<arch>\n"), "binary is not a Debian ar original")
    result = {}
    offset = 8
    while offset < len(raw):
        header = raw[offset:offset + 60]
        require(len(header) == 60 and header[58:] == b"`\n", "invalid Debian member header")
        name = header[:16].decode("ascii").strip().removesuffix("/")
        size = int(header[48:58].decode("ascii").strip())
        require(name in {"debian-binary", "control.tar.xz", "data.tar.xz"}
                and name not in result and 0 < size <= len(raw) - offset - 60,
                "unexpected Debian binary member")
        offset += 60
        result[name] = raw[offset:offset + size]
        offset += size + size % 2
    require(offset == len(raw) and set(result) == {"debian-binary", "control.tar.xz", "data.tar.xz"}
            and result["debian-binary"] == b"2.0\n", "incomplete Debian binary")
    return result


def field(message: object, name: str, expected: str) -> None:
    require(message.get_all(name) == [expected], "package metadata does not match the fixed binary/source identity")


def verify_dsc(raw: bytes, package: dict) -> None:
    require(raw.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----\n"), "missing original dsc framing")
    payload = raw.split(b"\n\n", 1)[1].split(b"\n-----BEGIN PGP SIGNATURE-----\n", 1)[0]
    message = email.parser.BytesParser().parsebytes(payload)
    field(message, "Format", "3.0 (quilt)")
    field(message, "Source", package["source"])
    field(message, "Version", package["version"])
    checksums = message.get_all("Checksums-Sha256", [])
    require(len(checksums) == 1, "dsc checksum section is not exact")
    rows = [tuple(line.split()) for line in checksums[0].splitlines() if line.strip()]
    expected = [(sha, str(size), name) for name, size, sha in package["archives"]]
    require(rows == expected, "dsc does not bind the exact reviewed source archives")


def prepare(*, candidate: Path, source_directory: Path, output: Path) -> dict:
    require(os.geteuid() != 0, "run companion preparation as an unprivileged operator")
    candidate, source_directory, output = (path.absolute() for path in (candidate, source_directory, output))
    for path in (candidate, source_directory):
        require(path.is_dir() and path.resolve(strict=True) == path, "input directory must be an existing real path")
    require(not os.path.lexists(output) and output.parent.resolve(strict=True) == output.parent
            and output.parent.is_dir(), "output must be absent under an existing real parent")
    require(all(path != output and path not in output.parents
                for path in (candidate, source_directory, HERE.parent, Path("/tmp"))),
            "sidecar must be outside its inputs, the checkout and root-backed /tmp")
    report_raw = read_fixed(candidate / "candidate-report.json", REPORT_SHA256)
    report = json.loads(report_raw)
    require(report["snapshot_id"] == CANDIDATE_ID and report["ok"] is True
            and report["published"] is False and report["reviewed_pins_installed"] is False
            and report["production_release_authority"] is False, "retained candidate identity differs")
    outputs = {"licenses/GPL-2.0.txt": read_fixed(HERE / "licenses/GPL-2.0.txt", GPL_SHA256, 32768)}
    mappings = []
    for package in PACKAGES:
        deb = read_fixed(candidate / "snapshot/cache" / package["deb"], package["sha256"], 256 * 1024)
        require(len(deb) == package["bytes"] and report["carried_forward"]["cache/" + package["deb"]]
                == {"sha256": package["sha256"], "size": len(deb)}, "retained binary/report join differs")
        members = deb_members(deb)
        control = email.parser.BytesParser().parsebytes(tar_member(members["control.tar.xz"], "./control"))
        for name, expected in (("Package", package["binary"]), ("Version", package["version"]), ("Architecture", "amd64")):
            field(control, name, expected)
        require(control.get_all("Source", [package["binary"]]) == [package["source"]], "binary source package differs")
        notice = tar_member(members["data.tar.xz"], "./usr/share/doc/" + package["binary"] + "/copyright")
        dsc_name, dsc_sha = package["dsc"]
        dsc = read_fixed(source_directory / dsc_name, dsc_sha, 16384)
        verify_dsc(dsc, package)
        outputs["sources/" + dsc_name] = dsc
        source_rows = [{"path": "sources/" + dsc_name, "url": package["base"] + dsc_name}]
        for name, size, sha in package["archives"]:
            raw = read_fixed(source_directory / name, sha)
            require(len(raw) == size, "source archive size differs from its reviewed pin")
            outputs["sources/" + name] = raw
            source_rows.append({"path": "sources/" + name, "url": package["base"] + name})
            if name.endswith(".debian.tar.xz"):
                require(tar_member(raw, "debian/copyright") == notice, "binary and source copyright notices differ")
        notice_path = "notices/" + package["binary"] + ".copyright"
        outputs[notice_path] = notice
        mappings.append({"binary": "cache/" + package["deb"], "binarySha256": package["sha256"],
                         "binaryBytes": len(deb), "sourcePackage": package["source"], "version": package["version"],
                         "license": "GPL-2.0-or-later", "copyright": notice_path,
                         "licenseText": "licenses/GPL-2.0.txt", "sources": source_rows})
    outputs["source-map.json"] = canonical({"schema": "catchplate.nativeDependencySourceCompanion/v1",
        "candidateId": CANDIDATE_ID, "candidateReportSha256": REPORT_SHA256, "packages": mappings,
        "distribution": "Publish these sources and notices beside the exact referenced binaries with equivalent access.",
        "writtenOffer": False, "licensingReviewApproved": False, "published": False,
        "productionReleaseAuthority": False, "dscSignaturesVerified": False})
    result = {"schema": "catchplate.nativeDependencySourceCompanionPreparation/v1", "ok": True,
        "scope": "two-retained-debian-binaries-only", "candidateId": CANDIDATE_ID,
        "candidateReportSha256": REPORT_SHA256, "published": False, "licensingReviewApproved": False,
        "productionReleaseAuthority": False, "candidateModified": False,
        "files": {name: {"sha256": digest(raw), "bytes": len(raw)} for name, raw in sorted(outputs.items())}}
    # All input admission precedes publication. Partial outputs are never reused.
    output.mkdir(mode=0o700)
    for name in ("sources", "licenses", "notices"):
        (output / name).mkdir(mode=0o700)
    # The success report is written last, after every declared file readback.
    for name, raw in [*sorted(outputs.items()), ("companion-report.json", canonical(result))]:
        path = output / name
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fchmod(stream.fileno(), 0o400)
            os.fsync(stream.fileno())
        require(read_fixed(path, digest(raw)) == raw, "sidecar literal readback differs")
    for path in (output / "sources", output / "licenses", output / "notices", output):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return result


def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--source-directory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = prepare(candidate=args.candidate, source_directory=args.source_directory, output=args.output)
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        parser.exit(1, f"native source companion refused: {error}\n")
    print(canonical({"ok": result["ok"], "published": False, "licensingReviewApproved": False,
                     "companion_report": str(args.output / "companion-report.json")}).decode("ascii"), end="")
