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
import re
import selectors
import signal
import sys
import time

from scripts.check_operator_demo import require

ORIGIN = "https://catchplate-demo.example.com"
CATALOG = "/api/operator-demo/catalog"
GRANT = "/api/operator-demo/access-rules/gmail-read"
INTENTS = "/api/operator-demo/oauth/google/intents"
SCHEMA = "catchplate.privateGmailBrowserPermission/v1"
JOINED_SCHEMA = "catchplate.privateGmailBrowserSdk/v1"
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


_RECIPE_COMMENTS = (
    "# Gmail SDK job (Bash): run from examples/google-gmail-go with the reviewed ./gmail-example already built.",
    "# Prepare dependencies/build before supplying the app token. This recipe does not download or build anything.",
    "# Set CATCHPLATE_PROXY_TOKEN privately first. Never use a Google token. Both TLS checks remain enabled.",
    "# catchplate.gmailSdkClient/v1",
)
_RECIPE_PREFIX = "\n".join((
    "(", "  set +x", "  set -eu", '  case "${CATCHPLATE_PROXY_TOKEN-}" in',
    "    ''|*[!A-Za-z0-9_-]*) printf '%s\\n' 'Set the issued Catchplate application token privately' >&2; exit 1 ;;",
    "  esac",
    '  [ "${#CATCHPLATE_PROXY_TOKEN}" -eq 43 ] || { printf \'%s\\n\' \'Set the issued Catchplate application token privately\' >&2; exit 1; }',
    '  printf \'%s\\n\' "$CATCHPLATE_PROXY_TOKEN" |',
    "    /usr/bin/env -i LANG=C.UTF-8 /bin/sh -c ",
))
_CHILD_PREFIX = ("set -eu", "IFS= read -r CATCHPLATE_PROXY_TOKEN", "exec </dev/null",
    "unset PWD OLDPWD SHLVL _", "export CATCHPLATE_PROXY_TOKEN")
_PUBLIC_ENV = ("CATCHPLATE_PROXY_URL", "CATCHPLATE_APP_ID", "CATCHPLATE_CA_FILE", "CATCHPLATE_PROXY_CA_FILE")


def _unquote_recipe(value):
    """Inverse of the one admitted single-quote encoding, not a shell parser."""
    require(type(value) is str and value.startswith("'") and value.endswith("'"),
        "copied Gmail recipe quoting differs")
    decoded = value[1:-1].replace("'\\''", "'")
    require("'" + decoded.replace("'", "'\\''") + "'" == value,
        "copied Gmail recipe quoting differs")
    return decoded


def parse_copied_recipe(raw):
    """Admit only the complete public recipe; never evaluate browser text."""
    require(type(raw) is bytes and 0 < len(raw) <= 8192, "copied Gmail recipe bound differs")
    text = raw.decode("utf-8", errors="strict")
    require("\0" not in text and "\r" not in text, "copied Gmail recipe characters differ")
    lines = text.split("\n", 6)
    require(len(lines) == 7 and tuple(lines[:4]) == _RECIPE_COMMENTS,
        "copied Gmail recipe header differs")
    rule = re.fullmatch(r"# access_rule_id: ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", lines[4])
    expiry = re.fullmatch(r"# token_expires_at_epoch_ms: ([1-9][0-9]{0,15})", lines[5])
    require(rule is not None and expiry is not None and int(expiry[1]) <= 2**53 - 1,
        "copied Gmail recipe saved identity differs")
    outer = lines[6]
    require(outer.startswith(_RECIPE_PREFIX) and outer.endswith("\n)"), "copied Gmail recipe commands differ")
    child = _unquote_recipe(outer[len(_RECIPE_PREFIX):-2]).split("\n")
    require(len(child) in (9, 10) and tuple(child[:5]) == _CHILD_PREFIX and child[-1] == "exec ./gmail-example",
        "copied Gmail recipe child differs")
    environment = {"LANG": "C.UTF-8"}
    for key, line in zip(_PUBLIC_ENV, child[5:-1]):
        prefix = "export " + key + "="
        require(line.startswith(prefix), "copied Gmail recipe environment differs")
        value = _unquote_recipe(line[len(prefix):])
        require(0 < len(value) <= 512 and not any(ord(ch) < 32 or ord(ch) == 127 for ch in value),
            "copied Gmail recipe value differs")
        environment[key] = value
    return {"environment": environment, "access_rule_id": rule[1], "token_expires_at_epoch_ms": int(expiry[1])}


def copied_client_environment(raw, *, application, rule, token):
    from scripts.check_operator_gmail_sdk import BROWSER_PROXY_URL, TRUST_FILES
    parsed = parse_copied_recipe(raw)
    environment = parsed["environment"]
    require(set(environment) == {"LANG", *_PUBLIC_ENV}
        and environment["CATCHPLATE_PROXY_URL"] == BROWSER_PROXY_URL
        and environment["CATCHPLATE_APP_ID"] == application["id"]
        and environment["CATCHPLATE_CA_FILE"] == str(TRUST_FILES["inner"])
        and environment["CATCHPLATE_PROXY_CA_FILE"] == str(TRUST_FILES["outer"])
        and parsed["access_rule_id"] == rule["id"] and rule["application_id"] == application["id"]
        and type(application.get("token_expires_at_epoch_ms")) is int
        and parsed["token_expires_at_epoch_ms"] == application["token_expires_at_epoch_ms"]
        and parsed["token_expires_at_epoch_ms"] > time.time_ns() // 1_000_000,
        "copied Gmail recipe does not match the saved fixture")
    require(type(token) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is not None
        and token.encode() not in raw, "copied Gmail recipe token boundary differs")
    environment["CATCHPLATE_PROXY_TOKEN"] = token
    return environment


def copied_phase_environment(environment, *, application, token, phase):
    from scripts.check_operator_gmail_sdk import PHASES, TRUST_FILES, UUID
    require(type(environment) is dict and set(environment) == {"LANG", *_PUBLIC_ENV, "CATCHPLATE_PROXY_TOKEN"}
        and phase in PHASES and type(application) is str and UUID.fullmatch(application)
        and type(token) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", token),
        "copied Gmail SDK handoff unavailable")
    # All positive calls and revocation reuse the copied identity and token. The
    # existing explicit wrong-app control alone substitutes another saved app.
    require((application != environment["CATCHPLATE_APP_ID"] and token != environment["CATCHPLATE_PROXY_TOKEN"])
        if phase == "wrong_app" else (application == environment["CATCHPLATE_APP_ID"]
            and token == environment["CATCHPLATE_PROXY_TOKEN"]), "copied Gmail SDK app differs")
    result = dict(environment)
    if phase == "wrong_outer_ca":
        result["CATCHPLATE_CA_FILE"], result["CATCHPLATE_PROXY_CA_FILE"] = (
            environment["CATCHPLATE_PROXY_CA_FILE"], environment["CATCHPLATE_CA_FILE"])
    elif phase == "wrong_inner_ca":
        result["CATCHPLATE_CA_FILE"] = environment["CATCHPLATE_PROXY_CA_FILE"]
        result["CATCHPLATE_PROXY_CA_FILE"] = str(TRUST_FILES["combined"])
    elif phase == "wrong_app":
        result["CATCHPLATE_APP_ID"], result["CATCHPLATE_PROXY_TOKEN"] = application, token
    return result


def expected_payload(before, application_id, credential_id):
    return {"name": "Read Gmail", "application_id": application_id, "credential_id": credential_id,
        "operation_bundle": "gmail_read_v1", "age_policy": {"mode": "unrestricted"},
        "credential_input": "replace_exact", "placeholder": "Bearer catchplate-gmail-placeholder-v1",
        "expected_revision": before["revision"], "expected_policy_hash": before["policy"]["policy_hash"]}


def validate_request(frame, expected, *, posted, documents, catalogs, intents=0):
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
            or (frame["path"] == CATALOG and catalogs < 8)
            or (frame["path"] == INTENTS and documents == 1 and catalogs >= 1 and intents == 0 and not posted)),
            "browser GET route or count differs")
    else:
        require(frame["method"] == "POST" and frame["path"] == GRANT and not posted and documents == 1
            and catalogs >= 1 and 0 < len(raw) <= 4096 and headers.get("origin") == ORIGIN
            and headers.get("content-type") == "application/json", "browser grant route or count differs")
        value = strict_json(raw)
        require(type(value) is dict and value == expected and type(value.get("expected_revision")) is int,
            "browser grant selected identities or CAS differs")
    return raw


def validate_intents(raw, credential):
    """Only the single already-connected fixture account's public history."""
    value = strict_json(raw)
    require(type(value) is dict and set(value) == {"apiVersion", "intents", "limits", "productionReady", "protectedActivationSupported"}
        and value["apiVersion"] == "catchplate.operatorGoogleConsent/v1" and value["productionReady"] is False
        and value["protectedActivationSupported"] is False and value["limits"] == {"active": 32, "retained": 1024}
        and type(value["intents"]) is list and len(value["intents"]) == 1, "browser consent public envelope differs")
    row = value["intents"][0]
    require(type(row) is dict and set(row) == {"id", "name", "provider_id", "permission_preset", "scopes", "created_at",
        "expires_at_epoch", "status", "credential_id"} and row["status"] == "connected"
        and row["credential_id"] == credential["id"] and row["name"] == credential["name"]
        and row["provider_id"] == "google" and row["permission_preset"] == "gmail_readonly"
        and row["scopes"] == ["email", "https://www.googleapis.com/auth/gmail.readonly", "openid"]
        and type(row["expires_at_epoch"]) is int and 0 < row["expires_at_epoch"] < 2**53
        and type(row["id"]) is str and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", row["id"])
        and type(row["created_at"]) is str and 1 <= len(row["created_at"]) <= 64
        and all(32 <= ord(char) < 127 for char in row["created_at"]), "browser consent public binding differs")


def emit(value):
    print(json.dumps(value, separators=(",", ":"), allow_nan=False), flush=True)


def exchange(check, frame, raw):
    # Only the fixed validated fixture endpoint is used. Preserve request bytes,
    # Origin/media headers, response bytes and security headers without rewriting.
    connection = http.client.HTTPConnection(check.control.host, check.control.port, timeout=check.timeout())
    connection.connect = lambda: setattr(connection, "sock", check.control.connect(check.timeout(), check.control_ca))
    try:
        headers = {**frame["headers"], "Host": check.control.host, "Connection": "close",
            "Accept-Encoding": "identity", "X-Catchplate-Admin-Token": check.admin_token}
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
    posted, documents, catalogs, intents, sequence = False, 0, 0, 0, 0
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
                require(set(frame) == {"id", "type", "copiedRecipe"} and posted and proof is not None and intents == 1,
                    "browser completed without its single saved grant")
                require(type(frame["copiedRecipe"]) is str and len(frame["copiedRecipe"]) <= 10924,
                    "browser copied recipe bound differs")
                recipe = base64.b64decode(frame["copiedRecipe"], validate=True)
                require(base64.b64encode(recipe).decode() == frame["copiedRecipe"],
                    "browser copied recipe encoding differs")
                # Only the public clipboard bytes cross the bridge. The application
                # token stays in this checker and is never returned to the browser.
                check.browser_client_environment = copied_client_environment(recipe,
                    application=application, rule=result["access_rule"], token=check.client_token)
                proof["copiedRecipeSha256"] = sha(recipe)
                proof["copiedRecipeBytes"] = len(recipe)
                proof["catalogGets"] = catalogs
                proof["intentGets"] = intents
                emit({"type": "permission", "id": sequence, "permission": proof})
                return result["access_rule"], result
            raw = validate_request(frame, expected, posted=posted, documents=documents, catalogs=catalogs, intents=intents)
            if frame["method"] == "POST":
                require(intents == 1 and catalogs >= 2, "browser consent observer has not completed")
                current = check.catalog()
                require(current["revision"] == before["revision"] and current["policy"] == before["policy"],
                    "browser grant state changed before dispatch")
                posted = True  # Consumed before the real send, including uncertain outcomes.
            status, headers, body = exchange(check, frame, raw)
            if frame["path"] == "/":
                documents += 1; html_digest = sha(body)
            elif frame["path"] == INTENTS:
                validate_intents(body, credential)
                intents += 1
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
        "browserClientHandoffVerified", "externalSsoVerified", "browser", "permission", "sdk"} and value["schema"] == JOINED_SCHEMA
        and value["ok"] is True and value["browserPermissionVerified"] is True
        and value["browserClientHandoffVerified"] is True
        and value["syntheticOAuthProgrammatic"] is True and value["externalSsoVerified"] is False,
        "joined Gmail browser result differs")
    sdk, proof, browser = value["sdk"], value["permission"], value["browser"]
    validate_success_result(sdk)  # Legacy SDK evidence and negative controls stay unchanged.
    require(type(proof) is dict and set(proof) == {"schema", "submitted", "requestSha256", "responseSha256", "htmlSha256",
        "ruleId", "revision", "policyHash", "grantPosts", "catalogGets", "intentGets",
        "copiedRecipeSha256", "copiedRecipeBytes"} and proof["schema"] == SCHEMA
        and proof["ruleId"] == sdk["ruleId"] and proof["policyHash"] == sdk["policyHash"]
        and type(proof["revision"]) is int and proof["revision"] == sdk["policyRevisions"]["accepted"] and type(proof["grantPosts"]) is int
        and proof["grantPosts"] == 1 and type(proof["catalogGets"]) is int and 3 <= proof["catalogGets"] <= 8
        and type(proof["intentGets"]) is int and proof["intentGets"] == 1
        and type(proof["copiedRecipeBytes"]) is int and 0 < proof["copiedRecipeBytes"] <= 8192
        and all(type(proof[key]) is str and SHA256.fullmatch(proof[key])
            for key in ("requestSha256", "responseSha256", "htmlSha256", "copiedRecipeSha256")), "joined Gmail grant proof differs")
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
        "requestSha256", "responseSha256", "htmlSha256", "copiedRecipeSha256", "copiedRecipeBytes", "steps", "screenshots"}
        and type(browser["postCount"]) is int and browser["postCount"] == 1
        and type(browser["getCount"]) is int and browser["getCount"] == proof["catalogGets"] + proof["intentGets"] + 1
        and all(type(browser[key]) is int and browser[key] == 0 for key in ("pageErrors", "consoleErrors", "refusedRequests"))
        and browser["browserClosed"] is True and browser["selectedApplicationId"] == payload["application_id"]
        and browser["selectedCredentialId"] == payload["credential_id"] and browser["savedRuleId"] == proof["ruleId"]
        and type(browser["copiedRecipeBytes"]) is int
        and all(browser[key] == proof[key] for key in ("requestSha256", "responseSha256", "htmlSha256",
            "copiedRecipeSha256", "copiedRecipeBytes"))
        and browser["steps"] == ["saved_account", "saved_basic_app", "official_sdk_default", "review", "grant", "saved_setup", "copy_sdk_recipe"]
        and type(browser["screenshots"]) is list and len(browser["screenshots"]) == 2,
        "joined Gmail browser observations differ")
    for row, name in zip(browser["screenshots"], ("review.png", "saved.png")):
        require(type(row) is dict and set(row) == {"file", "sha256"} and row["file"] == name
            and type(row["sha256"]) is str and SHA256.fullmatch(row["sha256"]), "Gmail browser screenshot receipt differs")
    return True
