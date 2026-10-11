"""Closed browser-permission bridge for the isolated Gmail SDK checker only.

The host browser receives public bytes over stdio, not an administrator token.
There is one grant POST, no replay, no provider route, and no new clock window.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import selectors
import signal
import sys
import time

from scripts.check_operator_demo import require

ORIGIN = "https://serverware-demo.example.com"
CATALOG = "/api/operator-demo/catalog"
GRANT = "/api/operator-demo/access-rules/gmail-read"
SCHEMA = "serverware.privateGmailBrowserPermission/v1"
JOINED_SCHEMA = "serverware.privateGmailBrowserSdk/v1"
MAX_FRAME, MAX_BODY, GRANT_SECONDS = 16384, 2 * 1024**2, 20


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "duplicate browser JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def expected_payload(before, application_id, credential_id):
    return {"name": "Read Gmail", "application_id": application_id, "credential_id": credential_id,
        "operation_bundle": "gmail_read_v1", "age_policy": {"mode": "unrestricted"},
        "credential_input": "replace_exact", "placeholder": "Bearer serverware-gmail-placeholder-v1",
        "expected_revision": before["revision"], "expected_policy_hash": before["policy"]["policy_hash"]}


def validate_request(frame, expected, *, posted, documents, catalogs):
    require(type(frame) is dict and set(frame) == {"id", "type", "method", "path", "headers", "body"}
        and frame["type"] == "request" and type(frame["id"]) is int and 1 <= frame["id"] <= 16,
        "browser request frame differs")
    headers = frame["headers"]
    require(type(headers) is dict and set(headers) <= {"accept", "content-type", "origin", "referer"}
        and all(type(value) is str and len(value) <= 1024 and "\r" not in value and "\n" not in value
            for value in headers.values()), "browser request headers differ")
    require(type(frame["body"]) is str and len(frame["body"]) <= 5464, "browser body bound differs")
    raw = base64.b64decode(frame["body"], validate=True)
    require(base64.b64encode(raw).decode() == frame["body"], "browser body encoding differs")
    if frame["method"] == "GET":
        require(not raw and ((frame["path"] == "/" and documents == 0)
            or (frame["path"] == CATALOG and catalogs < 8)), "browser GET route or count differs")
    else:
        require(frame["method"] == "POST" and frame["path"] == GRANT and not posted and documents == 1
            and catalogs >= 1 and 0 < len(raw) <= 4096 and headers.get("origin") == ORIGIN
            and headers.get("content-type") == "application/json", "browser grant route or count differs")
        value = strict_json(raw)
        require(type(value) is dict and value == expected and type(value.get("expected_revision")) is int,
            "browser grant selected identities or CAS differs")
    return raw


def emit(value):
    print(json.dumps(value, separators=(",", ":"), allow_nan=False), flush=True)


def exchange(check, frame, raw):
    # Only the fixed validated fixture endpoint is used. Preserve request bytes,
    # Origin/media headers, response bytes and security headers without rewriting.
    connection = http.client.HTTPConnection(check.control.host, check.control.port, timeout=check.timeout())
    connection.connect = lambda: setattr(connection, "sock", check.control.connect(check.timeout(), check.control_ca))
    try:
        headers = {**frame["headers"], "Host": check.control.host, "Connection": "close",
            "Accept-Encoding": "identity", "X-Serverware-Admin-Token": check.admin_token}
        connection.request(frame["method"], frame["path"], body=raw if frame["method"] == "POST" else None, headers=headers)
        response = connection.getresponse()
        body, pairs = response.read(MAX_BODY + 1), response.getheaders()
        require(0 < len(body) <= MAX_BODY and len(pairs) <= 64 and len(str(pairs)) <= 16384,
            "browser response bound differs")
        check.clean(body); check.clean(str(pairs).encode())
        require(all(value.encode() not in body for value in check.transient_values), "OAuth flow material escaped")
        mapped = {key.lower(): value for key, value in pairs}
        require(len(mapped) == len(pairs) and not set(mapped) & {"set-cookie", "location", "content-encoding", "transfer-encoding"}
            and "no-store" in mapped.get("cache-control", ""), "browser response headers differ")
        media = "text/html" if frame["path"] == "/" else "application/json"
        require(mapped.get("content-type", "").split(";", 1)[0] == media
            and response.status == (201 if frame["method"] == "POST" else 200), "browser API response differs")
        return response.status, pairs, body
    finally:
        connection.close()


def create_permission(check, application, credential):
    """Clamp every original checker call; restore only its remaining budget."""
    original, started = check.deadline, time.monotonic()
    alarm, interval = signal.getitimer(signal.ITIMER_REAL)
    require(alarm > 0 and interval == 0, "original checker alarm unavailable")
    check.deadline = min(original, started + GRANT_SECONDS)
    signal.setitimer(signal.ITIMER_REAL, min(alarm, GRANT_SECONDS))
    try:
        return _create_permission(check, application, credential)
    finally:
        check.deadline = original
        signal.setitimer(signal.ITIMER_REAL, max(0.000001, alarm - (time.monotonic() - started)))


def read_frame(fd, selected, buffer, end):
    while b"\n" not in buffer:
        remaining = end - time.monotonic()
        require(remaining > 0 and selected.select(remaining), "browser grant deadline expired")
        try:
            chunk = os.read(fd, MAX_FRAME + 1 - len(buffer))
        except BlockingIOError:
            continue
        require(chunk, "browser frame unavailable")
        buffer += chunk
        require(len(buffer) <= MAX_FRAME, "browser frame bound exceeded")
    line, buffer = buffer.split(b"\n", 1)
    require(line and time.monotonic() < end, "browser frame budget expired")
    return strict_json(line), buffer


def _create_permission(check, application, credential):
    before = check.catalog()
    expected = expected_payload(before, application["id"], credential["id"])
    end = check.deadline
    emit({"type": "ready", "schema": SCHEMA, "applicationId": application["id"],
        "credentialId": credential["id"], "expectedRevision": before["revision"],
        "expectedPolicyHash": before["policy"]["policy_hash"]})
    posted, documents, catalogs, sequence = False, 0, 0, 0
    result = proof = None
    html_digest = None
    fd, buffer = sys.stdin.fileno(), b""
    blocking = os.get_blocking(fd)
    os.set_blocking(fd, False)
    selected = selectors.DefaultSelector()
    try:
        selected.register(fd, selectors.EVENT_READ)
        while True:
            frame, buffer = read_frame(fd, selected, buffer, end)
            require(type(frame) is dict and type(frame.get("id")) is int and frame["id"] == sequence + 1,
                "browser frame sequence differs")
            sequence += 1
            require(sequence <= 16 and time.monotonic() < end, "browser frame budget expired")
            if frame.get("type") == "done":
                require(set(frame) == {"id", "type"} and posted and proof is not None,
                    "browser completed without its single saved grant")
                proof["catalogGets"] = catalogs
                emit({"type": "permission", "id": sequence, "permission": proof})
                return result["access_rule"], result
            raw = validate_request(frame, expected, posted=posted, documents=documents, catalogs=catalogs)
            if frame["method"] == "POST":
                current = check.catalog()
                require(current["revision"] == before["revision"] and current["policy"] == before["policy"],
                    "browser grant state changed before dispatch")
                posted = True  # Consumed before the real send, including uncertain outcomes.
            status, headers, body = exchange(check, frame, raw)
            if frame["path"] == "/":
                documents += 1; html_digest = sha(body)
            elif frame["method"] == "GET":
                catalogs += 1
            else:
                result = strict_json(body)
                require(type(result) is dict and "client_token" not in result
                    and result.get("revision") == before["revision"] + 1
                    and result.get("policy", {}).get("sequence") == before["policy"]["sequence"] + 1
                    and result["policy"]["policy_hash"] != before["policy"]["policy_hash"],
                    "browser grant publication differs")
                rule = result.get("access_rule", {})
                require(rule.get("application_id") == application["id"] and rule.get("credential_id") == credential["id"],
                    "browser saved another grant")
                check.finalize_mutation(result, check.catalog(), collection="access_rules", result_key="access_rule",
                    event="operator_catalog.access_rule.created")
                proof = {"schema": SCHEMA, "submitted": expected, "requestSha256": sha(raw),
                    "responseSha256": sha(body), "htmlSha256": html_digest, "ruleId": rule["id"],
                    "revision": result["revision"], "policyHash": result["policy"]["policy_hash"], "grantPosts": 1}
            emit({"type": "response", "id": sequence, "status": status, "headers": headers,
                "body": base64.b64encode(body).decode()})
    finally:
        selected.close()
        os.set_blocking(fd, blocking)


def validate_joined_result(value):
    from scripts.check_operator_gmail_sdk import validate_success_result, SHA256, UUID
    require(type(value) is dict and set(value) == {"schema", "ok", "browserPermissionVerified", "syntheticOAuthProgrammatic",
        "externalSsoVerified", "browser", "permission", "sdk"} and value["schema"] == JOINED_SCHEMA
        and value["ok"] is True and value["browserPermissionVerified"] is True
        and value["syntheticOAuthProgrammatic"] is True and value["externalSsoVerified"] is False,
        "joined Gmail browser result differs")
    sdk, proof, browser = value["sdk"], value["permission"], value["browser"]
    validate_success_result(sdk)  # Legacy SDK evidence and negative controls stay unchanged.
    require(type(proof) is dict and set(proof) == {"schema", "submitted", "requestSha256", "responseSha256", "htmlSha256",
        "ruleId", "revision", "policyHash", "grantPosts", "catalogGets"} and proof["schema"] == SCHEMA
        and proof["ruleId"] == sdk["ruleId"] and proof["policyHash"] == sdk["policyHash"]
        and type(proof["revision"]) is int and proof["revision"] == sdk["policyRevisions"]["accepted"] and type(proof["grantPosts"]) is int
        and proof["grantPosts"] == 1 and type(proof["catalogGets"]) is int and 1 <= proof["catalogGets"] <= 8
        and all(type(proof[key]) is str and SHA256.fullmatch(proof[key])
            for key in ("requestSha256", "responseSha256", "htmlSha256")), "joined Gmail grant proof differs")
    payload = proof["submitted"]
    require(type(payload) is dict and type(payload.get("expected_revision")) is int
        and payload["expected_revision"] + 1 == proof["revision"]
        and type(payload.get("expected_policy_hash")) is str and SHA256.fullmatch(payload["expected_policy_hash"])
        and payload["expected_policy_hash"] != proof["policyHash"]
        and payload == expected_payload({"revision": payload["expected_revision"],
            "policy": {"policy_hash": payload["expected_policy_hash"]}}, sdk["applicationIds"][0], sdk["credentialId"]),
        "joined Gmail browser selection differs")
    require(type(browser) is dict and set(browser) == {"postCount", "getCount", "pageErrors", "consoleErrors",
        "refusedRequests", "browserClosed", "selectedApplicationId", "selectedCredentialId", "savedRuleId",
        "requestSha256", "responseSha256", "htmlSha256", "steps", "screenshots"}
        and type(browser["postCount"]) is int and browser["postCount"] == 1
        and type(browser["getCount"]) is int and browser["getCount"] == proof["catalogGets"] + 1
        and all(type(browser[key]) is int and browser[key] == 0 for key in ("pageErrors", "consoleErrors", "refusedRequests"))
        and browser["browserClosed"] is True and browser["selectedApplicationId"] == payload["application_id"]
        and browser["selectedCredentialId"] == payload["credential_id"] and browser["savedRuleId"] == proof["ruleId"]
        and all(browser[key] == proof[key] for key in ("requestSha256", "responseSha256", "htmlSha256"))
        and browser["steps"] == ["saved_account", "saved_basic_app", "official_sdk_default", "review", "grant", "saved_setup"]
        and type(browser["screenshots"]) is list and len(browser["screenshots"]) == 2,
        "joined Gmail browser observations differ")
    for row, name in zip(browser["screenshots"], ("review.png", "saved.png")):
        require(type(row) is dict and set(row) == {"file", "sha256"} and row["file"] == name
            and type(row["sha256"]) is str and SHA256.fullmatch(row["sha256"]), "Gmail browser screenshot receipt differs")
    return True
