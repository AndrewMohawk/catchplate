#!/usr/bin/env python3
"""Fixed local source/runtime-input observation, never a build attestation."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.authority.local_provenance import arguments

USAGE = """Usage: python -I -B scripts/authority/local_composition.py \
--approval-fd N --approval-sha256 sha256:HEX --trust-fd N --trust-sha256 sha256:HEX \
--source-root-fd N --signing-key-fd N

Root-only explicit local profile. Protected canonical approval/trust originals,
an existing frozen tree, actual clean sourceArchive/v1/raw Git commit, retained
OCI manifest/config/layer bytes and an independently authorized sealed32-byte
provenance key are required. The report path contains canonical
authorityTrustedHostLocalCompositionInputs/v1, not a production build report.

Observes separately selected source/runtime inputs; does NOT claim the OCI was
built from that source, historical build execution, a matching executed rootfs,
independent administration, hardware custody or production approval. Only local
Python stageZero packages accept this predicate. Existing measured-roster,
immutable-installation and runtime-admission checks remain necessary.

Writes the existing detached provenance reference to a root-owned output pipe.
No keys, files, trust high-water, package installation or fake evidence are
created. Require complete output and successful exit; do not retry partial
signing/output. Original clocks/deadlines remain in force.
"""


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end="")
        return 0
    try:
        from serverware.authority_local_composition import LocalCompositionIssuer
        LocalCompositionIssuer(**arguments(argv)).publish()
        return 0
    except BaseException:
        try:
            import os
            os.write(2, b"local composition refused; no acceptance or retry authorized\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
