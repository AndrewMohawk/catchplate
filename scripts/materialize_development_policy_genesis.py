#!/usr/bin/env python3
"""One explicit offline development public-policy install; no authority creation."""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
FIELDS = ("policy-fd", "policy-sha256", "genesis-preparation-digest", "genesis-finalization-digest")
USAGE = """Usage: python -I -B scripts/materialize_development_policy_genesis.py \\
  --policy-fd FD --policy-sha256 SHA256 \\
  --genesis-preparation-digest SHA256 --genesis-finalization-digest SHA256

Requires root, a non-production image/development release, the explicit
CATCHPLATE_PROCESS_MODE=metadata-bootstrap offline invocation, existing public
signing trust, and the protected fixed genesis-materializer DSN path/SHA.
Admin/executor DSNs are forbidden. The inherited policy original is root:root
0400, read-only or sealed, and already signed. No keys, policy signing, genesis
creation or database authority mutation is performed. The fixed active target
must be absent and the publication journal absent/empty.

Failure is not rollback: stage/installed files may remain and installed genuine
signed/committed bytes may independently load. Never automatically retry,
delete or restore. Success is reported only after durable readback and close.
"""


def arguments(argv):
    if len(argv) != 8 or tuple(argv[::2]) != tuple("--" + field for field in FIELDS):
        raise ValueError("closed argument list required")
    values = dict(zip((field.replace("-", "_") for field in FIELDS), argv[1::2]))
    text = values["policy_fd"]
    if not re.fullmatch(r"[1-9][0-9]{0,9}", text) or not 3 <= int(text) < (1 << 31):
        raise ValueError("canonical inherited FD required")
    values["policy_fd"] = int(text)
    if any(re.fullmatch(r"sha256:[0-9a-f]{64}", values[field]) is None for field in
           ("policy_sha256", "genesis_preparation_digest", "genesis_finalization_digest")):
        raise ValueError("canonical SHA256 required")
    return values


def main(argv=None):
    supplied = sys.argv[1:] if argv is None else argv
    if supplied == ["--help"]:
        print(USAGE, end="")
        return 0
    owner = None
    try:
        kwargs = arguments(supplied)
        from catchplate.development_policy_genesis import OfflineDevelopmentGenesis
        owner = OfflineDevelopmentGenesis.open(**kwargs)
        result = owner.run()
    except BaseException as error:
        # Never expose exception text: PostgreSQL errors can include private DSNs.
        owner = owner or getattr(error, "owner", None)
        if owner is not None:
            try:
                owner.close()
            except BaseException:
                print("development policy materialization cleanup uncertain; preserve files; do not retry", file=sys.stderr)
                return 1
        print("development policy materialization failed; files may remain; no automatic retry", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
