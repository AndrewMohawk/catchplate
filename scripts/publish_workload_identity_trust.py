#!/usr/bin/env python3
"""Explicit public trust-artifact preparation; never install or restart."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from catchplate.workload_identity_trust_publication import (
    PinnedFile,
    WorkloadIdentityTrustPublicationError,
    publish_trust,
)


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False,
        description="Publish independently authorized public workload trust into an empty, "
            "preprovisioned owner-only directory. No installation, chmod, restart or retry.")
    for name in ("authorization", "authorizer-public-key", "issuer", "bundle", "principals"):
        parser.add_argument("--" + name, required=True, type=Path)
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--destination", required=True, type=Path,
        help="Existing empty current-user-owned mode-0700 directory; partial output is never removed.")
    parser.add_argument("--expected-deployment-id", required=True)
    parser.add_argument("--expected-runtime-binary-sha256", required=True)
    parser.add_argument("--expected-server-certificate-spki-sha256", required=True)
    parser.add_argument("--expected-policy-hash", required=True)
    parser.add_argument("--timeout-ms", type=int, default=30000,
        help="Tightening-only original deadline, 1..30000 ms; native calls still require an outer watchdog.")
    args = parser.parse_args(argv)
    try:
        result = publish_trust(
            authorization_original=PinnedFile(args.authorization, args.authorization_sha256),
            authorizer=PinnedFile(args.authorizer_public_key, args.authorizer_public_key_sha256),
            issuer=PinnedFile(args.issuer, args.issuer_sha256),
            bundle=PinnedFile(args.bundle, args.bundle_sha256),
            principals=PinnedFile(args.principals, args.principals_sha256),
            destination=args.destination, expected_deployment_id=args.expected_deployment_id,
            expected_runtime_binary_sha256=args.expected_runtime_binary_sha256,
            expected_server_certificate_spki_sha256=args.expected_server_certificate_spki_sha256,
            expected_policy_hash=args.expected_policy_hash, timeout_ms=args.timeout_ms)
        # Bounded public paths/digests only; neither originals nor private data
        # are printed. A broken output pipe does not undo any publication.
        sys.stdout.buffer.write(result + b"\n")
        sys.stdout.buffer.flush()
        return 0
    except (WorkloadIdentityTrustPublicationError, OSError, ValueError):
        sys.stderr.write("Trust publication did not complete. Preserve any claim/artifacts; "
            "do not retry, overwrite or assume installed runtime trust.\n")
        return 1
    except KeyboardInterrupt:
        sys.stderr.write("Trust publication interrupted. Preserve any claim/artifacts; "
            "no rollback, installation or retry is authorized.\n")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
