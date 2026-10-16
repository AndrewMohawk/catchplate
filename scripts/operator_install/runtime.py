"""Small baked-image entrypoint; startup never compiles or hashes a source tree."""
import json
import os
from pathlib import Path
import re
import sys
import urllib.request

ARTIFACT = Path("/opt/serverware/artifact.json")


def artifact():
    raw = ARTIFACT.read_bytes()
    if len(raw) > 8192:
        raise ValueError("standalone artifact manifest too large")
    value = json.loads(raw)
    if (set(value) != {"schema", "sourceRevision", "sourceTreeDigest", "compilerInputsDigest", "dataPlaneBinaryDigest"}
            or value["schema"] != "serverware.standaloneArtifact/v1"
            or not re.fullmatch(r"[0-9a-f]{40}", value["sourceRevision"])
            or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", value[key])
                for key in ("sourceTreeDigest", "compilerInputsDigest", "dataPlaneBinaryDigest"))):
        raise ValueError("standalone artifact manifest invalid")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def pair_status():
    expected = artifact()["dataPlaneBinaryDigest"]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def get(url, filename):
        token = (Path("/run/secrets/serverware") / filename).read_text().strip()
        if not token or len(token) > 4096:
            raise ValueError("standalone machine credential unavailable")
        request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
        with opener.open(request, timeout=3) as response:
            raw = response.read(2 * 1024**2 + 1)
            if response.status != 200 or len(raw) > 2 * 1024**2:
                raise ValueError("standalone pair readback refused")
            return json.loads(raw)

    catalog = get("http://127.0.0.1:3000/api/operator-demo/catalog", "admin.token")
    gate = get("http://decision-gate-rs:9091/healthz", "management.token")
    policy = catalog["policy"]
    ready = (policy["activation"] == "active" and policy["policy_hash"] == policy["loaded_policy_hash"]
        == gate["policy_hash"] and gate["ok"] and gate["policy_shadow_serving_ready"]
        and gate["data_plane_binary_digest"] == expected)
    return {"ready": bool(ready), "policy_hash": policy["policy_hash"],
        "loaded_policy_hash": policy["loaded_policy_hash"]}


def main():
    os.umask(0o077)
    if len(sys.argv) != 2:
        raise ValueError("choose app, gate, artifact, or pair-status")
    role = sys.argv[1]
    if role == "artifact":
        print(json.dumps(artifact(), sort_keys=True))
    elif role == "pair-status":
        print(json.dumps(pair_status(), sort_keys=True))
    elif role == "app":
        artifact()
        os.execv(sys.executable, [sys.executable, "-B", "-m", "serverware.operator_demo_runner"])
    elif role == "gate":
        artifact()
        os.execv("/usr/local/bin/serverware-decision-gate", ["serverware-decision-gate"])
    else:
        raise ValueError("unknown standalone role")


if __name__ == "__main__":
    main()
