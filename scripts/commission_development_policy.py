#!/usr/bin/env python3
"""Fixed genuine development-demo prepare/inclusion/finalize caller."""
from __future__ import annotations

from pathlib import Path
import re
import signal
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
FIELDS = ("policy-fd", "policy-sha256", "prepare-fd", "prepare-sha256", "finalize-fd", "result-fd",
    "deadline-monotonic-ns", "expires-at-unix-ns")
USAGE = """Usage: python -I -B scripts/commission_development_policy.py \\
  --policy-fd FD --policy-sha256 SHA256 --prepare-fd FD --prepare-sha256 SHA256 \\
  --finalize-fd FD --result-fd FD --deadline-monotonic-ns NS --expires-at-unix-ns NS

Development image/channel only, SERVERWARE_PROCESS_MODE=serverware-control-plane.
The actual UID/GID and complete inherited FD set must already match independently
signed AuthorityRuntimeClient trust. No privileged database/signing credentials.
The policy is an existing signed exact demo; prepare is canonical existing runtime
input {input:{record,policySignatureEvidenceDigest},webauthnAuthorization}.
Both are root:root0400 protected originals, pinned by their literal SHA256.

Finalize is an initially empty root:root0400 unsealed memfd. Independent automation
writes the existing final runtime input {input:{genesisPreparationDigest,
inclusionReceipt,inclusionEvidenceDigest,auditStoreIdentityDigest},
webauthnAuthorization}, then applies SEAL_SEAL|SHRINK|GROW|WRITE together.
Result is a nonblocking anonymous writable pipe. It receives two canonical JSON
lines: the actual committed prepare result (including audit_submission), then
the actual committed finalization. The same foreground owner retains the first
result and binds the late request to it. No caller-supplied prior result is used.
All four distinct descriptors must be inherited before runtime admission; this
command takes their ownership. Original total bounds must be within 300 seconds;
each existing runtime call also retains its own maximum 30-second bound.

This is NOT automatic full commissioning: a genuine policy-signature evidence
registration, independently signed audit inclusion/evidence registration, and
fresh bound WebAuthn assertions remain required. No inclusion signer/registration
producer is supplied here. Existing app /api/authority/webauthn/challenges can
serve an already enrolled authenticated operator when the app itself is admitted.
No keys, assertions, trust, authority results, schema or genesis are fabricated.
The separate materialize_development_policy_genesis.py installs finalized bytes.
Failure may follow a committed mutation or an emitted result; do not retry or
infer rollback. EOF/exit zero is separate from the public committed result lines.
"""


def arguments(argv):
    if len(argv) != 16 or tuple(argv[::2]) != tuple("--" + name for name in FIELDS):
        raise ValueError("closed argument list required")
    value = dict(zip((name.replace("-", "_") for name in FIELDS), argv[1::2]))
    for name in ("policy_sha256", "prepare_sha256"):
        if re.fullmatch(r"sha256:[0-9a-f]{64}", value[name]) is None:
            raise ValueError("canonical SHA256 required")
    for name in ("policy_fd", "prepare_fd", "finalize_fd", "result_fd", "deadline_monotonic_ns", "expires_at_unix_ns"):
        text = value[name]
        if re.fullmatch(r"[1-9][0-9]{0,18}", text) is None:
            raise ValueError("canonical positive integer required")
        value[name] = int(text)
        if not (3 <= value[name] < 2**31 if name.endswith("_fd") else 0 < value[name] < 2**63):
            raise ValueError("integer outside bound")
    if len({value[name] for name in ("policy_fd", "prepare_fd", "finalize_fd", "result_fd")}) != 4:
        raise ValueError("descriptors must be distinct")
    return value


def _cancel(_signal, _frame):
    raise InterruptedError("commissioning cancelled")


def main(argv=None):
    supplied = sys.argv[1:] if argv is None else argv
    if supplied == ["--help"]:
        print(USAGE, end="")
        return 0
    owner = None
    try:
        kwargs = arguments(supplied)
        signal.signal(signal.SIGTERM, _cancel)
        signal.signal(signal.SIGINT, _cancel)
        from serverware.development_policy_commissioning import DevelopmentPolicyCommissioning
        owner = DevelopmentPolicyCommissioning.open(**kwargs)
        owner.run()
        return 0
    except BaseException as error:
        owner = owner or getattr(error, "owner", None)
        if owner is not None:
            try:
                owner.close()
            except BaseException:
                print("development commissioning cleanup uncertain; no automatic retry", file=sys.stderr)
                return 1
        # Never print runtime exception text, assertions, DSNs or raw requests.
        print("development commissioning failed; authority outcome may require reconciliation; no retry", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
