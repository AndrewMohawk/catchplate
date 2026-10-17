"""Closed internal transport for the browser's three-resource creation check.

Root alone executes it in the reviewed app container. Commands (including the
synthetic key) arrive on stdin, never argv. The admin token never leaves this
process. This is not an external SSO, provider, or proxy transport check.
"""
import base64
import http.client
import json
import os
import re
import signal
import stat
import sys

PUBLIC = "https://catchplate-demo.example.com"
PREFIX = "/api/operator-demo/"
TOKEN_FILE = "/run/secrets/catchplate/admin.token"
COLLECTIONS = ("credentials", "applications", "access_rules")
KINDS = ("credential", "application", "rule")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
DUMMY = "Bearer CATCHPLATE_BROWSER_SYNTHETIC_DUMMY"
PRIVATE = {"secret", "access_token", "refresh_token", "id_token", "admin_token", "encrypted_secret", "token_hash",
           "token_sha256", "secret_nonce", "encrypted_dek", "client_secret", "provider_secret", "password",
           "proxy_password", "proxy_authorization", "authorization", "cookie", "set_cookie", "private_key"}


def require(value):
    if not value:
        raise ValueError("runtime_creation_bridge_refused")


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 2 * 1024 * 1024)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: require(False))


def name(run, index):
    return "catchplate-browser-" + run + "-" + KINDS[index]


def rule_values(run, owned):
    return {"name": name(run, 2), "application_id": owned["applications"], "credential_id": owned["credentials"],
            "upstream_url": "https://demo-upstream:8443/echo", "methods": ["POST"], "request_fields": [],
            "response_fields": [], "request_body_mode": "preserve_json_v1", "response_mode": "unfiltered_json_or_empty_v2",
            "credential_input": "replace_exact", "placeholder": DUMMY, "query_keys": [], "allowed_headers": ["accept", "user-agent"]}


def admit(command):
    """Pure closed route/body/header validation, before token reads or sockets."""
    require(type(command) is dict and set(command) == {"method", "path", "body_base64", "headers", "run_id", "owned"})
    run, owned = command["run_id"], command["owned"]
    require(type(run) is str and re.fullmatch(r"[0-9a-f]{32}", run))
    require(type(owned) is dict and set(owned) == set(COLLECTIONS))
    require(all(value is None or type(value) is str and UUID.fullmatch(value) for value in owned.values()))
    require(len([v for v in owned.values() if v]) == len(set(v for v in owned.values() if v)))
    require(type(command["headers"]) is dict and type(command["body_base64"]) is str)
    if command["method"] == "GET":
        require(command["path"] in {"/", PREFIX + "catalog"} and command["body_base64"] == "" and command["headers"] == {})
        return b"", None, None
    require(command["method"] == "POST" and command["headers"] == {"content-type": "application/json"})
    routes = {PREFIX + path: (index, revoke) for index, path in enumerate(("credentials", "applications", "access-rules"))
              for revoke in (False,)}
    routes.update({path + "/revoke": (index, True) for path, (index, _) in list(routes.items())})
    require(type(command["path"]) is str and command["path"] in routes and len(command["body_base64"]) <= 16384)
    raw = base64.b64decode(command["body_base64"], validate=True)
    require(base64.b64encode(raw).decode() == command["body_base64"] and len(raw) <= 8192)
    body = decode(raw)
    require(type(body) is dict and type(body.get("expected_revision")) is int and body["expected_revision"] >= 1
            and type(body.get("expected_policy_hash")) is str and DIGEST.fullmatch(body["expected_policy_hash"]))
    content = {key: value for key, value in body.items() if key not in {"expected_revision", "expected_policy_hash"}}
    index, revoke = routes[command["path"]]
    if revoke:
        require(owned[COLLECTIONS[index]] is not None and content == {"id": owned[COLLECTIONS[index]]})
    elif index == 0:
        require(all(value is None for value in owned.values()) and content == {"name": name(run, 0), "auth_type": "bearer",
                "header_name": "Authorization", "secret": "catchplate-browser-synthetic-key-" + run})
    elif index == 1:
        require(owned["credentials"] is not None and owned["applications"] is None and owned["access_rules"] is None)
        expected = {"name": name(run, 1), "token_lifetime_seconds": 3600}
        require(content == expected or content == {**expected, "proxy_authentication": "basic_and_bearer_v1"})
    else:
        require(owned["credentials"] is not None and owned["applications"] is not None and owned["access_rules"] is None
                and content == rule_values(run, owned))
    return raw, body, (index, revoke)


def public_json(body, token, *, application_created=False):
    value = decode(body)
    pending = [(value, 0, True)]
    count = 0
    while pending:
        item, depth, top = pending.pop()
        count += 1
        require(count <= 32768 and depth <= 24)
        if type(item) is dict:
            for key, child in item.items():
                normalized = key.lower().replace("-", "_")
                require(normalized not in PRIVATE)
                if normalized == "client_token":
                    require(application_created and top and key == "client_token" and type(child) is str
                            and re.fullmatch(r"[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]", child))
                pending.append((child, depth + 1, False))
        elif type(item) is list:
            pending.extend((child, depth + 1, False) for child in item)
        elif type(item) is str:
            require(len(item) <= 65536 and token not in item and "PRIVATE KEY-----" not in item
                    and "catchplate-browser-synthetic-key-" not in item)
    return value


def exchange(method, path, raw, token, *, application_created=False):
    connection = http.client.HTTPConnection("127.0.0.1", 3000, timeout=5)
    try:
        media = "text/html" if path == "/" else "application/json"
        headers = {"Host": "catchplate-demo.example.com", "Origin": PUBLIC, "X-Catchplate-Admin-Token": token,
                   "Accept-Encoding": "identity", "Accept": media, "Connection": "close"}
        if method == "POST":
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=raw if method == "POST" else None, headers=headers)
        response = connection.getresponse()
        pairs = response.getheaders()
        require(len(pairs) <= 64 and len({key.lower() for key, _ in pairs}) == len(pairs))
        require(all(token not in key + value and len(key) + len(value) <= 8192 and key.lower() not in
                    {"location", "set-cookie", "content-encoding", "transfer-encoding", "www-authenticate"} for key, value in pairs))
        mapped = {key.lower(): value for key, value in pairs}
        require(mapped.get("content-type", "").split(";", 1)[0].strip().lower() == media and "no-store" in mapped.get("cache-control", ""))
        body = response.read(2 * 1024 * 1024 + 1)
        require(0 < len(body) <= 2 * 1024 * 1024 and token.encode() not in body and b"PRIVATE KEY-----" not in body)
        require("content-length" not in mapped or int(mapped["content-length"]) == len(body))
        # Refused/uncertain responses never become success or trigger a retry.
        require(response.status in ({200} if method == "GET" else {200, 201}))
        parsed = None if path == "/" else public_json(body, token, application_created=application_created)
        return {"ok": True, "status": response.status, "headers": pairs, "body_base64": base64.b64encode(body).decode()}, parsed
    finally:
        connection.close()


def bind_catalog(command, body, operation, catalog):
    require(catalog.get("schema") == "catchplate.operatorCatalog/v1" and catalog.get("mode") == "operator-development"
            and catalog.get("productionReady") is False and catalog.get("hardwareVerified") is False
            and "https://demo-upstream:8443" in catalog.get("allowed_upstreams", []))
    require(body["expected_revision"] == catalog["revision"] and body["expected_policy_hash"] == catalog["policy"]["policy_hash"])
    owned, run = command["owned"], command["run_id"]
    rows = {}
    for index, collection in enumerate(COLLECTIONS):
        matches = [row for row in catalog[collection] if row.get("name") == name(run, index)]
        require(len(matches) == (0 if owned[collection] is None else 1))
        if matches:
            row = matches[0]
            require(row["id"] == owned[collection])
            rows[collection] = row
    credential, application, rule = (rows.get(key) for key in COLLECTIONS)
    if credential:
        require(credential["auth_type"] == "bearer" and credential["header_name"] == "Authorization")
    if application:
        require(application["principal_id"] == "agent:operator-demo:" + application["id"] and application["token_generation"] == 1)
    if rule:
        require(all(rule.get(key) == value for key, value in rule_values(run, owned).items()))
    index, revoke = operation
    if revoke:
        require(rows[COLLECTIONS[index]]["status"] == "active")
        if index != 2:
            require(rows[COLLECTIONS[index]]["active_rule_count"] == 0 and (not rule or rule["status"] == "revoked"))
        if index == 0:
            require(not application or application["status"] == "revoked")
    else:
        require(all(row["status"] == "active" for row in rows.values()))
        if index == 1:
            basic = catalog.get("capabilities", {}).get("application_proxy_authentication")
            require((body.get("proxy_authentication") == "basic_and_bearer_v1") == bool(basic))


def main():
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("bounded")))
    signal.alarm(12)
    try:
        require(len(sys.argv) == 1)
        wire = sys.stdin.buffer.read(32769)
        require(len(wire) <= 32768)
        command = decode(wire)
        raw, body, operation = admit(command)
        require(os.environ.get("CATCHPLATE_OPERATOR_DEMO") == "1" and os.environ.get("CATCHPLATE_PUBLIC_URL") == PUBLIC
                and os.environ.get("CATCHPLATE_ADMIN_TOKEN_FILE") == TOKEN_FILE and "CATCHPLATE_ADMIN_TOKEN" not in os.environ)
        descriptor = os.open(TOKEN_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and 32 <= info.st_size <= 8192 and not info.st_mode & 0o027)
            token_bytes = os.read(descriptor, 8193).rstrip(b"\r\n")
        finally:
            os.close(descriptor)
        require(32 <= len(token_bytes) <= 8192 and all(33 <= byte <= 126 for byte in token_bytes))
        token = token_bytes.decode("ascii")
        if operation:
            _, catalog = exchange("GET", PREFIX + "catalog", b"", token)
            bind_catalog(command, body, operation, catalog)
        response, _ = exchange(command["method"], command["path"], raw, token, application_created=operation == (1, False))
        print(json.dumps(response, separators=(",", ":")))
    except Exception:
        print('{"ok":false,"reason":"runtime_creation_bridge_refused"}')
        raise SystemExit(2) from None
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
