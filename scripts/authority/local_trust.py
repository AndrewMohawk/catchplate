#!/usr/bin/env python3
"""Issue first-generation local artifact key authorization/revocation originals."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
USAGE = """Usage: python -I -B scripts/authority/local_trust.py --approval-fd N --approval-sha256 sha256:HEX --trust-fd N --trust-sha256 sha256:HEX --public-keys-fd N --public-keys-sha256 sha256:HEX --witness-directory-fd N --signing-key-fd N

Root-only trusted-host-local first generation, never rotation or continuation.
Provide independently approved canonical root0400 public originals, a pinned
actually empty root0700 witness directory, and the matching sealed32-byte
trust-document root key. Public roster is exactly the13 existing artifact
purposes mapped to distinct canonical base64url raw32 Ed25519 public keys.
Key IDs are local-<purpose>-v1; selected public bundle files are expected at
keys/artifact/<purpose>.pub, raw32 root0400. No keys or files are created here.

Initial trust must already be independently provisioned/pinned with sequence-1,
empty replay/revocation sets and explicit directory-bound empty-witness anchors.
The13-key roster includes the separate trust root; only12 nonroot authorizations
are emitted. Configuration-root and service/runtime keys are outside this roster.
Writes the existing exact trustMaterial object to a root-owned pipe. Require
complete output and exit0; no output retry, trust advancement, witness append,
package acceptance, successful installation or independent custody is implied.
Original approval clocks are never renewed; independently bound kernel stalls.
"""


def arguments(argv):
    flags = [flag for name in ("approval", "trust", "public-keys")
        for flag in ("--"+name+"-fd", "--"+name+"-sha256")]
    flags += ["--witness-directory-fd", "--signing-key-fd"]
    if len(argv) != 16 or argv[::2] != flags: raise ValueError("fixed local trust arguments required")
    result = {}
    for flag, raw in zip(argv[::2], argv[1::2]):
        name = flag[2:].replace("-", "_")
        if name.endswith("_fd"):
            value = int(raw)
            if str(value) != raw or not 3 <= value < 2**31: raise ValueError("descriptor refused")
        else:
            value = raw
            if len(raw) != 71 or not raw.startswith("sha256:") or any(c not in "0123456789abcdef" for c in raw[7:]):
                raise ValueError("original pin refused")
        result[name] = value
    fds = [value for name, value in result.items() if name.endswith("_fd")]
    if len(fds) != len(set(fds)): raise ValueError("descriptor alias refused")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]: print(USAGE, end=""); return 0
    try:
        selected = arguments(argv)
        from catchplate.authority_local_trust import LocalTrustIssuer
        LocalTrustIssuer(**selected).publish()
        return 0
    except BaseException:
        import os
        try: os.write(2, b"initial local trust issuance refused; no document acceptance or retry authorized\n")
        except OSError: pass
        return 1


if __name__ == "__main__": raise SystemExit(main())
