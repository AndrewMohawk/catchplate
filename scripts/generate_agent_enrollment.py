#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a Serverware agent enrollment packet.")
    parser.add_argument("--base", default=os.getenv("SERVERWARE_PUBLIC_URL", "http://localhost:3000"))
    parser.add_argument("--admin-token", default=os.getenv("SERVERWARE_ADMIN_TOKEN", "dev-admin-token"))
    parser.add_argument("--principal-id", required=True)
    parser.add_argument("--proxy-url", required=True)
    parser.add_argument("--proxy-egress-cidr", action="append", required=True)
    parser.add_argument("--control-plane-url", default=None)
    parser.add_argument("--namespace", default="serverware-agents")
    parser.add_argument("--selector", action="append", default=[], help="pod selector label as key=value")
    parser.add_argument("--ca-mount-path", default="/etc/serverware/serverware-ca.pem")
    args = parser.parse_args()

    selector: dict[str, str] = {}
    for item in args.selector:
        key, sep, value = item.partition("=")
        if not sep or not key or not value:
            raise SystemExit(f"invalid --selector {item!r}; expected key=value")
        selector[key] = value

    base = args.base.rstrip("/")
    payload = {
        "principalId": args.principal_id,
        "proxyUrl": args.proxy_url,
        "controlPlaneUrl": args.control_plane_url or base,
        "proxyEgressCidrs": args.proxy_egress_cidr,
        "namespace": args.namespace,
        "podSelector": selector,
        "caMountPath": args.ca_mount_path,
    }
    request = urllib.request.Request(
        f"{base}/api/agents/enrollment",
        data=(canonical_json(payload) + "\n").encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Serverware-Admin-Token": args.admin_token,
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        packet = json.loads(response.read())
    json.dump(packet, sys.stdout, indent=2, sort_keys=True)
    print()


if __name__ == "__main__":
    main()
