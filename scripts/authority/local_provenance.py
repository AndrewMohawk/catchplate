#!/usr/bin/env python3
"""Issue one fixed, truthful local measured-artifact provenance reference."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

USAGE = """Usage: python -I -B scripts/authority/local_provenance.py \
--approval-fd N --approval-sha256 sha256:HEX --trust-fd N --trust-sha256 sha256:HEX \
--source-root-fd N --signing-key-fd N

Root-only; protected public originals, pre-existing immutable measured tree and
independently authorized sealed32-byte provenance key are mandatory. No keys,
trust, frozen tree or build outputs are generated. Clean productionImagesBuild/v2
report, exact sourceArchive/v1 and raw Git commit object, and actual OCI manifest,
config and layers are required; current dirty engineering reports/rootfs TARs
refuse. SourceCommitDigest is SHA256 of the literal Git commit object frame.
The local predicate records an observed association, NOT historical execution,
independence, reproducibility, SLSA, hardware custody or production approval.

Writes the existing full detached provenance reference to a root-owned pipe.
Use its existing path/predicateType/mediaType/builderId/statementDigest/signerKeyId/
algorithm/signatureBase64Url fields as generator provenance input; the generator
must independently join its remaining measured source/tree/OCI fields. Require
complete output and successful exit. Never retry partial signing/output; an
external supervisor bounds kernel filesystem stalls. No trust high-water update.
"""


def arguments(argv):
    names = ["--approval-fd", "--approval-sha256", "--trust-fd", "--trust-sha256",
             "--source-root-fd", "--signing-key-fd"]
    if len(argv) != 12 or argv[::2] != names:
        raise ValueError("fixed provenance arguments required")
    result = dict(zip((name[2:].replace("-", "_") for name in names), argv[1::2]))
    for name in ("approval_fd", "trust_fd", "source_root_fd", "signing_key_fd"):
        raw = result[name]
        result[name] = int(raw)
        if str(result[name]) != raw or not 3 <= result[name] < 2**31:
            raise ValueError("provenance descriptor refused")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end="")
        return 0
    try:
        selected = arguments(argv)
        from serverware.authority_local_provenance import LocalProvenanceIssuer
        LocalProvenanceIssuer(**selected).publish()
        return 0
    except BaseException:
        try:
            import os
            os.write(2, b"local provenance refused; no acceptance or retry authorized\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
