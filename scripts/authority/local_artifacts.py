#!/usr/bin/env python3
"""Fixed local artifact signing/verification command, not an installer."""
from pathlib import Path
import signal
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

OPTIONS = ("unsigned-fd", "unsigned-sha256", "trust-fd", "trust-sha256", "approval-fd",
           "approval-sha256", "source-root-fd", "output-directory-fd", "artifact-bundle-key-fd",
           "generation-key-fd", "verifier-key-fd")
USAGE = """Usage: python -I -B scripts/authority/local_artifacts.py --unsigned-fd N --unsigned-sha256 SHA --trust-fd N --trust-sha256 SHA --approval-fd N --approval-sha256 SHA --source-root-fd N --output-directory-fd N --artifact-bundle-key-fd N --generation-key-fd N --verifier-key-fd N

Run as root with protected root:root0400 canonical public originals and sealed
32-byte private-key FDs. The independently pinned local approval selects exact
unsigned package/trust bytes, authorized key IDs and original clock limits.
The source tree must already be genuinely immutable/read-only and match its
independently signed snapshot and selected-profile closure originals. The local
measured roster does not claim production complete closure. No key material
is accepted in argv, environment, output, or logs. Shared purpose-authorized
key FDs are allowed; none may alias a public or directory FD.

Writes only package.json then verification.json, root0400, atomically and
without replacement in the pinned empty root0700 output directory. Failure can
leave partial public files; inspect them, do not blindly retry. No source flags
are changed, no trust high-water is committed, and no installation is done.
Existing snapshot/closure/provenance/migration/witness originals are required;
this command neither generates those assertions nor claims production custody.
"""


def arguments(argv):
    if len(argv) != 2 * len(OPTIONS) or argv[::2] != ["--" + key for key in OPTIONS]:
        raise ValueError("fixed artifact arguments required")
    result = {}
    for name, value in zip(OPTIONS, argv[1::2], strict=True):
        if name.endswith("-fd"):
            parsed = int(value)
            if str(parsed) != value or not 3 <= parsed < 2**31:
                raise ValueError("descriptor argument invalid")
        else:
            if len(value) != 71 or not value.startswith("sha256:") or any(c not in "0123456789abcdef" for c in value[7:]):
                raise ValueError("public digest invalid")
            parsed = value
        result[name.replace("-", "_")] = parsed
    public = [result[name] for name in ("unsigned_fd", "trust_fd", "approval_fd", "source_root_fd", "output_directory_fd")]
    private = [result[name] for name in ("artifact_bundle_key_fd", "generation_key_fd", "verifier_key_fd")]
    if len(set(public)) != 5 or set(public) & set(private):
        raise ValueError("descriptor aliases refused")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end="")
        return 0
    try:
        selected = arguments(argv)
    except (ValueError, TypeError):
        print("local artifacts refused: use --help", file=sys.stderr)
        return 2
    def cancelled(_signo, _frame):
        raise KeyboardInterrupt()
    for signo in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signo, cancelled)
    try:
        from serverware.authority_local_artifacts import produce
        from serverware.authority_artifact_spec import canonical_json_bytes
        result = produce(**selected)
        print(canonical_json_bytes(result).decode("ascii"))
        return 0
    except BaseException:
        print("local artifacts failed; any partial public files retained; no trust or installation claimed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
