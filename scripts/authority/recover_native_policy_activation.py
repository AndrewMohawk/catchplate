"""Copy a retained native publication handoff; never publish, sign or settle it."""
import argparse
import fcntl
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from catchplate import native_policy_activation_recovery as recovery
from catchplate import authority_policy_canary as profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection-fd", type=int, required=True, help="read-only FD containing exact canonical selection JSON")
    parser.add_argument("--output", required=True, help="new private file; existing paths are never overwritten")
    args = parser.parse_args()
    try:
        profile.require(args.selection_fd >= 3)
        profile.require(fcntl.fcntl(args.selection_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY)
        before = os.fstat(args.selection_fd)
        profile.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 4096)
        selected = os.pread(args.selection_fd, 4097, 0)
        profile.require(len(selected) == before.st_size and recovery.inputs._file_identity(before)
            == recovery.inputs._file_identity(os.fstat(args.selection_fd)))
        handoff = recovery.recover(selected)
        raw = profile.canonical(handoff)
        path = Path(args.output)
        profile.require(path.is_absolute() and path.name not in {"", ".", ".."} and ".." not in path.parts)
        # Export only into an existing private operator directory; never print
        # authority originals to stdout, error logs or a shared terminal.
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            journal = recovery.selection(selected)["journal"]
            profile.require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
                and (info.st_dev, info.st_ino) != (journal["device"], journal["inode"]))
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                os.fchmod(fd, 0o600)
                view = memoryview(raw)
                while view:
                    written = os.write(fd, view)
                    profile.require(written > 0)
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory)
        finally:
            os.close(directory)
        sys.stderr.write("Recovery handoff copied. Import for authenticated review and settlement; no effect was authorized or repeated.\n")
    except Exception:
        sys.stderr.write("Native publication recovery refused; no publication was retried. A newly created partial export may remain; do not use it.\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
