"""GET-only runtime observation, streamed over stdin to one exact app container.

No application imports, writes, retries, redirects or caller-supplied headers.
The administrator token stays inside this process; response bytes are unchanged.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys

PUBLIC = "https://serverware-demo.example.com"
TOKEN_FILE = "/run/secrets/serverware/admin.token"
PATHS = {"/", "/api/operator-demo/catalog", "/api/operator-demo/notifications", "/api/operator-demo/proxy/upstreams"}
PRIVATE = {"secret", "client_token", "access_token", "refresh_token", "id_token", "admin_token", "encrypted_secret",
           "token_hash", "secret_nonce", "encrypted_dek", "client_secret", "provider_secret", "password",
           "proxy_password", "proxy_authorization", "authorization", "cookie", "set_cookie", "private_key"}


def require(value):
    if not value:
        raise ValueError("refused")


def public_json(body, token):
    pending, seen = [(json.loads(body), 0)], 0
    while pending:
        item, depth = pending.pop()
        seen += 1
        require(seen <= 32768 and depth <= 24)
        if isinstance(item, dict):
            for key, child in item.items():
                require(key.lower().replace("-", "_") not in PRIVATE)
                pending.append((child, depth + 1))
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            require(len(item) <= 65536 and "PRIVATE KEY-----" not in item and token not in item)
            require(not re.search(r"synthetic-operator-[A-Za-z0-9_-]{32,}|oauth-sim-(?:access|refresh)-[^ ]+-material", item))


def source(command):
    require(set(command) == {"op", "manifest_sha256", "files"} and
            re.fullmatch(r"[0-9a-f]{64}", command["manifest_sha256"]) and type(command["files"]) is int and 0 < command["files"] <= 16384)
    root, manifest, total = Path("/app"), [], 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        folder = Path(directory)
        require(folder.resolve() == folder and stat.S_IMODE(folder.lstat().st_mode) == 0o555)
        require(all(not (folder / name).is_symlink() for name in dirs))
        for name in files:
            path = folder / name
            info = path.lstat()
            mode = stat.S_IMODE(info.st_mode)
            total += info.st_size
            require(path.resolve() == path and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and mode in {0o444, 0o555})
            require(info.st_size <= 64 * 1024 * 1024 and total <= 1024 * 1024 * 1024 and len(manifest) < 16384)
            manifest.append([str(path.relative_to(root)), "100755" if mode == 0o555 else "100644", hashlib.sha256(path.read_bytes()).hexdigest()])
    digest = hashlib.sha256(json.dumps(sorted(manifest), separators=(",", ":")).encode()).hexdigest()
    require(len(manifest) == command["files"] and digest == command["manifest_sha256"])
    return {"ok": True, "files": len(manifest), "manifest_sha256": digest}


def get(command):
    require(set(command) == {"op", "path"} and command["op"] == "get" and command["path"] in PATHS)
    descriptor = os.open(TOKEN_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and 32 <= info.st_size <= 8192 and not info.st_mode & 0o027)
        token_bytes = os.read(descriptor, 8193).rstrip(b"\r\n")
    finally:
        os.close(descriptor)
    require(32 <= len(token_bytes) <= 8192 and all(33 <= byte <= 126 for byte in token_bytes))
    token, path = token_bytes.decode("ascii"), command["path"]
    connection = http.client.HTTPConnection("127.0.0.1", 3000, timeout=5)
    try:
        media = "text/html" if path == "/" else "application/json"
        connection.request("GET", path, headers={"Host": "serverware-demo.example.com", "Origin": PUBLIC,
            "X-Serverware-Admin-Token": token, "Accept-Encoding": "identity", "Accept": media, "Connection": "close"})
        response = connection.getresponse()
        headers = response.getheaders()
        require(response.status == 200 and len(headers) <= 64 and len({key.lower() for key, _ in headers}) == len(headers))
        require(all(token not in key and token not in value and len(key) + len(value) <= 8192 and
                    key.lower() not in {"location", "set-cookie", "content-encoding", "transfer-encoding", "www-authenticate"} for key, value in headers))
        mapped = {key.lower(): value for key, value in headers}
        require(mapped.get("content-type", "").split(";", 1)[0].strip().lower() == media and "no-store" in mapped.get("cache-control", ""))
        maximum = 32768 if path.endswith("/upstreams") else 131072 if path.endswith("/notifications") else 2 * 1024 * 1024
        body = response.read(maximum + 1)
        require(0 < len(body) <= maximum and token_bytes not in body and b"PRIVATE KEY-----" not in body)
        if "content-length" in mapped:
            require(int(mapped["content-length"]) == len(body))
        if path != "/":
            public_json(body, token)
        return {"ok": True, "status": response.status, "headers": headers, "body_base64": base64.b64encode(body).decode("ascii")}
    finally:
        connection.close()


def deadline(_signal, _frame):
    raise TimeoutError("bounded")


def main():
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(20)
    try:
        require(len(sys.argv) == 2 and len(sys.argv[1]) <= 1024)
        command = json.loads(sys.argv[1])
        require(isinstance(command, dict) and os.environ.get("SERVERWARE_OPERATOR_DEMO") == "1" and
                os.environ.get("SERVERWARE_PUBLIC_URL") == PUBLIC and os.environ.get("SERVERWARE_ADMIN_TOKEN_FILE") == TOKEN_FILE and
                "SERVERWARE_ADMIN_TOKEN" not in os.environ and os.environ.get("SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED") == "1" and
                "SERVERWARE_OPERATOR_NOTIFICATIONS_PILOT_SOURCE_JSON" not in os.environ)
        print(json.dumps(source(command) if command.get("op") == "source" else get(command), separators=(",", ":")))
    except Exception:
        print('{"ok":false,"reason":"runtime_readonly_bridge_refused"}')
        raise SystemExit(2) from None
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
