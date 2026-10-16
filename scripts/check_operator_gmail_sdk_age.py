"""Age-only scenarios using the existing Gmail SDK checker's real boundaries."""
from __future__ import annotations

from collections import Counter, defaultdict, deque
import os
from pathlib import Path
import time
from urllib.parse import parse_qsl

from scripts import check_operator_gmail_sdk as sdk
from scripts import operator_gmail_sdk_age_fixture as fixture

SCHEMA = "serverware.privateGmailAgeCheck/v1"
ERRORS = {"old-list": "gmail_read_age_internal_date_too_old",
    "missing-list": "gmail_read_age_metadata_invalid", "future-list": "gmail_read_age_internal_date_future",
    "mismatch-list": "gmail_read_age_metadata_id_mismatch", "old-get": "gmail_read_age_internal_date_too_old",
    "missing-get": "gmail_read_age_internal_date_invalid"}


def observe(check, count):
    status, value = check.json_request(check.upstream, sdk.base.fixture.OBSERVATIONS_PATH, context=check.upstream_ca)
    sdk.require(status == 200 and value.get("schema") == "serverware.privateGoogleObservations/v1", "age observations unavailable")
    age = value.get("gmailAge", {})
    sdk.require(age.get("schema") == fixture.SCHEMA and age.get("maxAttempts") == 32
        and type(age.get("anchorEpochMs")) is int and type(age.get("attempts")) is list
        and len(age["attempts"]) == count and value["counts"]["google"].get("resource_attempts", 0) == count,
        "age provider attempt count differs")
    expected = fixture.plan(age["anchorEpochMs"])
    consent, refresh = int(count > 0), int(count > 10)
    lists = sum(row["kind"] == "list" for row in expected[:count])
    counters = {"authorization_requests": consent, "authorization_codes_issued": consent,
        "authorization_code_exchanges": consent, "token_requests": consent + refresh,
        "token_responses": consent + refresh, "refresh_exchanges": refresh, "identity_requests": consent,
        "resource_requests": count, "resource_attempts": count, "resource_gmail.messages.list": lists,
        "resource_gmail.message.get": count - lists}
    inventory = {"authorization_validated": consent, "authorization_code_issued": consent,
        "authorization_code_exchanged": consent, "identity_returned": consent, "tokens_issued": consent + refresh,
        "refresh_token_rotated": refresh, "resource_received": count, "resource_authorized": count}
    sdk.require(value["counts"].get("x") == {} and {k: v for k, v in value["counts"]["google"].items() if v}
        == {k: v for k, v in counters.items() if v}
        and Counter(row["type"] for row in value["events"]) == Counter({k: v for k, v in inventory.items() if v})
        and all(row.get("sequence") == index + 1 and row.get("provider") == "google"
            for index, row in enumerate(value["events"]))
        and value.get("tokenLifetimes") == {"authorizationCodeExchangeSeconds": 90, "refreshExchangeSeconds": 300}
        and value.get("active") == {"authorizationCodes": 0, "grants": consent}
        and value.get("initialAccessExpired") is bool(refresh), "age unexpected OAuth exchange, retry or expiry")
    expiry = value.get("initialAccessExpiresAtEpochMs")
    sdk.require((type(expiry) is int and expiry > 0) if consent else expiry is None, "age initial expiry missing")
    for index, row in enumerate(age["attempts"]):
        spec = expected[index]
        path, query = fixture.target(spec, age["afterEpochSeconds"].get(spec["phase"]))
        headers = fixture.PROBE_HEADERS if spec["kind"] == "probe" else fixture.CLIENT_HEADERS
        sdk.require(row.get("ordinal") == index + 1 and row.get("case") == spec["phase"] + ":" + spec["kind"] + ":" + str(spec["page"])
            and row.get("phase") == spec["phase"] and row.get("kind") == spec["kind"] and row.get("method") == "GET"
            and row.get("path") == path and row.get("rawQuery") == query and row.get("requestHeaders") == headers
            and all(row.get(key) is True for key in ("hostMatches", "headersMatch", "framingMatch", "authorized"))
            and row.get("status") == 200 and row.get("tokenGeneration") == spec["generation"] and row.get("tokenState") == "active"
            and row.get("responseFraming") == ("chunked" if index == 5 else "content-length")
            and row.get("responseBodySha256") == sdk.digest(spec["body"])
            and row.get("responseBodyBytes") == len(sdk.encoded(spec["body"])), "age provider wire or generation differs")
        sdk.require(type(row.get("timestampEpochMs")) is int and
            ((row["timestampEpochMs"] < expiry) if spec["generation"] == 1 else (row["timestampEpochMs"] >= expiry)),
            "age provider generation precedes actual expiry")
    return value


def configuration(app, token, rule, name):
    environment = {"SERVERWARE_PROXY_URL": sdk.PROXY, "SERVERWARE_APP_ID": app["id"],
        "SERVERWARE_PROXY_TOKEN": token, "SERVERWARE_CA_FILE": str(sdk.TRUST_FILES["inner"]),
        "SERVERWARE_PROXY_CA_FILE": str(sdk.TRUST_FILES["outer"])}
    value = {**rule, "application_id": app["id"], "access_rule_id": rule["id"],
        "token_expires_at_epoch_ms": app["token_expires_at_epoch_ms"], "proxy_authentication": "basic_and_bearer_v1",
        "proxy_username": app["id"], "proxy_password": token, "proxy_url": sdk.PROXY,
        "ca_file": str(sdk.TRUST_FILES["inner"]), "proxy_ca_file": str(sdk.TRUST_FILES["outer"]),
        "client_recipe": {"schema": "serverware.gmailSdkClient/v2", "clear_environment": True,
            "environment": environment, "access_rule_id": rule["id"], "token_expires_at_epoch_ms": app["token_expires_at_epoch_ms"]}}
    path = Path("/tmp/gmail-age-" + name + ".json")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(sdk.encoded(value))
    return path


def canonical(row, scope, credential):
    operation = {"operation": "gmail.messages.list", "gmailUser": "me"}
    if row["kind"] == "get":
        operation = {"operation": "gmail.message.get", "gmailUser": "me", "messageId": row["path"].rsplit("/", 1)[1]}
    value = {"v": 3, "principal": scope[0], "client_ip": "127.0.0.1", "route_id": scope[1],
        "credential_ref": credential, "credential_version": str(row["tokenGeneration"]), "policy_hash": scope[2],
        "request": {"method": "GET", "scheme": "https", "authority": "gmail.googleapis.com", "path": row["path"],
            "query": [list(pair) for pair in parse_qsl(row["rawQuery"], keep_blank_values=True)],
            "query_mode": "orderedFormV1", "query_wire": row["rawQuery"],
            "headers": sdk.profiles.canonical_headers("python:list_page_1"), "body_sha256": sdk.digest(b""),
            "discard_headers": ["accept-encoding"]}, "operation": operation}
    return sdk.digest(value), sdk.digest({key: item for key, item in value.items() if key not in {"v", "client_ip"}})


def audit(check, document, scopes, credential):
    events = check.settled_audit()
    sdk.features.audit_cutoff(events)
    ordered = ordered_events(events)
    starts = [row["event"] for row in ordered if row["event_type"] == sdk.START]
    terminals = [row["event"] for row in ordered if row["event_type"] in {sdk.RELEASE, "data_plane.response.blocked"}]
    parents = [row for row in document["gmailAge"]["attempts"] if row["kind"] != "probe"]
    sdk.require(len(starts) == len(terminals) == len(parents) == 20, "age parent audit count differs")
    expected = defaultdict(deque)
    for row in parents:
        scope = scopes["unrestricted" if row["phase"] == "unrestricted" else "recent"]
        key = canonical(row, scope, credential)
        expected[key].append((row, scope))
    by_attempt = {event["attempt_id"]: event for event in terminals}
    sdk.require(len(by_attempt) == 20, "age terminal attempt reused")
    seen = set()
    positions = {row["event"]["attempt_id"]: index for index, row in enumerate(ordered) if row["event_type"] == sdk.START}
    end_positions = {row["event"]["attempt_id"]: index for index, row in enumerate(ordered)
        if row["event_type"] in {sdk.RELEASE, "data_plane.response.blocked"}}
    for start in starts:
        attempt = start.get("attempt_id")
        key = (start.get("request_digest"), start.get("operation_digest"))
        sdk.require(attempt not in seen and attempt in by_attempt and expected.get(key)
            and positions[attempt] < end_positions[attempt], "age response lacks unique ordered attempt")
        seen.add(attempt)
        row, scope = expected[key].popleft()
        event = by_attempt[attempt]
        for item in (start, event):
            sdk.require(tuple(item.get(k) for k in ("principal_id", "route_id", "policy_hash")) == scope
                and item.get("credential_ref") == credential and str(item.get("credential_version")) == str(row["tokenGeneration"])
                and item.get("method") == "GET" and item.get("request_digest") == key[0]
                and item.get("operation_digest") == key[1], "age parent authority/generation binding differs")
        blocked = row["phase"] in ERRORS and (row["phase"].endswith("-list") or row["kind"] == "get")
        sdk.require(event.get("outcome") == ("blocked" if blocked else "released") and event.get("upstream_status") == 200,
            "age whole-response outcome differs")
        validation = event.get("response_validation", {})
        if blocked:
            sdk.require(validation.get("ok") is False and validation.get("error") == ERRORS[row["phase"]], "age refusal reason differs")
        else:
            sdk.require(event.get("response_body_sha256") == row["responseBodySha256"]
                and event.get("response_body_bytes") == row["responseBodyBytes"], "age original response bytes changed")
            if row["phase"] != "unrestricted":
                sdk.require(validation.get("age_policy") == "recent_internal_date_v1" and validation.get("max_age_days") == fixture.DAYS
                    and validation.get("metadata_probes") == (1 if row["kind"] == "list" else 0)
                    and validation.get("body_bytes_preserved") is True, "age release evidence differs")
    sdk.require(not any(expected.values()), "age parent commitment was not consumed")
    refresh = [row["event"] for row in events if row["event_type"] == "credential.oauth_refreshed"]
    sdk.require(len(refresh) == 1 and refresh[0].get("credential_id") == credential
        and refresh[0].get("previous_credential_version") == 1 and refresh[0].get("credential_version") == 2
        and refresh[0].get("refresh_token_rotated") is True, "age real token generation transition differs")
    chain = check.control_json("/api/audit/verify?limit=1000", authenticated=True)
    sdk.require(chain.get("ok") is True and chain.get("complete") is True, "age audit chain failed")
    return {"parentStarts": len(starts), "released": sum(event["outcome"] == "released" for event in terminals),
        "blocked": sum(event["outcome"] == "blocked" for event in terminals), "metadataProbes": 11,
        "initialCredentialVersion": 1, "refreshedCredentialVersion": 2}


def ordered_events(events):
    """Use the durable predecessor chain, never UUID order or clock delays."""
    by_hash = {row["event_hash"]: row for row in events}
    sdk.require(len(by_hash) == len(events), "age audit hashes reused")
    predecessors = {row.get("prev_event_hash") for row in events}
    tips = [row for row in events if row["event_hash"] not in predecessors]
    sdk.require(len(tips) == 1, "age audit chain tip differs")
    current, reverse, seen = tips[0], [], set()
    while current is not None:
        sdk.require(current["event_hash"] not in seen, "age audit chain cycle")
        seen.add(current["event_hash"]); reverse.append(current)
        current = by_hash.get(current.get("prev_event_hash"))
    sdk.require(len(reverse) == len(events), "age audit chain disconnected")
    return list(reversed(reverse))


def revoked_control(check, app, token, rule, config, document, pinned):
    check.phase = "age:revoke"
    check.mutate("/access-rules/revoke", {"id": rule["id"]}, collection="access_rules", result_key="access_rule",
        event="operator_catalog.access_rule.revoked", authority_changed=True)
    revoked, _ = check.wait_catalog_loaded("gmail_age_revoked")
    sdk.require(revoked["revision"] == pinned["revision"] + 1
        and revoked["policy"]["sequence"] == pinned["policy"]["sequence"] + 1
        and check.resource(revoked, "access_rules", rule["id"])["status"] == "revoked",
        "age revocation publication differs")
    before = sdk.features.audit_cutoff(check.settled_audit())
    check.phase = "age:revoked"
    code, out, error = sdk.run_example(sdk.client_environment(app["id"], token, "revoked"),
        min(30, check.deadline - time.monotonic()), command=sdk.profiles.COMMANDS["python"], config_file=config)
    check.clean(out); check.clean(error)
    sdk.require(code == 1 and not out and error == sdk.profiles.FAILURES["python"], "age revoked SDK call differs")
    sdk.require(observe(check, 31) == document, "age revoked client reached provider or token endpoint")
    events = check.settled_audit()
    after = sdk.features.audit_cutoff(events)
    sdk.require(all(after.get(key) == value for key, value in before.items()), "age revoked audit prefix changed")
    added = [row for row in events if row["id"] not in before]
    sdk.require(len(added) == 1 and added[0]["event_type"] == sdk.DENIED, "age revoked audit differs")
    event = added[0]["event"]
    sdk.require(event.get("method") == "CONNECT" and event.get("target") == "gmail.googleapis.com:443"
        and event.get("outcome") == "denied" and event.get("principal_id") is None,
        "age revoked application retained CONNECT authority")
    check.unchanged(revoked)
    return {"providerAttemptsBefore": 31, "providerAttemptsAfter": 31, "auditEventType": sdk.DENIED,
        "policyHash": check.policy_hash}


def run(check):
    check.health(); check.admin_token = sdk.token_file(check.args.admin_token_file)
    initial = check.catalog()
    sdk.require(initial["revision"] == 1 and all(not initial[key] for key in sdk.COLLECTIONS), "age fixture must be fresh")
    sdk.require_bundle(initial)
    check.policy_hash = initial["policy"]["policy_hash"]
    check.wait_catalog_loaded("gmail_age_fresh")
    observe(check, 0)
    credential = check.connect_account(initial)
    accounts, rules, configs = {}, {}, {}
    for name in ("unrestricted", "recent"):
        app, token, _ = check.mutate("/applications", {"name": check.run_id + "-" + name, "token_lifetime_seconds": 3600,
            "proxy_authentication": "basic_and_bearer_v1"}, collection="applications", result_key="application",
            event="operator_catalog.application.created", creates=True, token=True)
        age = {"mode": "unrestricted"} if name == "unrestricted" else {"mode": "recent_internal_date_v1", "max_age_days": fixture.DAYS}
        rule, _, _ = check.mutate("/access-rules/gmail-read", {"name": check.run_id + "-" + name, "application_id": app["id"],
            "credential_id": credential["id"], "operation_bundle": "gmail_read_v1", "age_policy": age,
            "credential_input": "replace_exact", "placeholder": sdk.DUMMY}, collection="access_rules", result_key="access_rule",
            event="operator_catalog.access_rule.created", creates=True, authority_changed=True)
        sdk.require(rule.get("age_policy") == age and rule.get("query_mode") == "orderedFormV1", "age saved scope differs")
        sdk.require_rule({**rule, "age_policy": {"mode": "unrestricted"}}, app["id"], credential["id"])
        accounts[name], rules[name] = (app, token), rule
        configs[name] = configuration(app, token, rule, name)
    pinned, _ = check.wait_catalog_loaded("gmail_age_rules")
    scopes = {name: (accounts[name][0]["principal_id"], rule["route_id"], check.policy_hash) for name, rule in rules.items()}
    count, completed = 0, []
    for phase, increment in zip(fixture.PHASES, fixture.COUNTS):
        if phase == "refreshed":
            expiry = document["initialAccessExpiresAtEpochMs"]
            remaining = (expiry + 1000 - time.time_ns() // 1000000) / 1000
            sdk.require(0 < remaining <= 91 and check.deadline - time.monotonic() > remaining + 45, "age expiry exceeds bounded run")
            until = time.monotonic() + remaining
            while time.monotonic() < until:
                time.sleep(min(1, max(0, until - time.monotonic()), check.timeout()))
        name = "unrestricted" if phase == "unrestricted" else "recent"
        app, token = accounts[name]
        check.client_token = token
        check.phase = "age:" + phase
        environment = sdk.client_environment(app["id"], token, "first")
        result = sdk.run_example(environment, min(30, check.deadline - time.monotonic()),
            command=sdk.profiles.COMMANDS["python"], config_file=configs[name])
        check.clean(result[1]); check.clean(result[2])
        sdk.require(all(value[1].encode() not in result[1] + result[2] for value in accounts.values()), "age application token escaped")
        positive = phase in {"unrestricted", "recent", "refreshed"}
        code, out, error = result
        check.client_result = {"phase": check.phase, "exitCode": code, "stdoutBytes": len(out), "stderrBytes": len(error)}
        sdk.require((code == 0 and out == sdk.SUCCESS and error == b"") if positive else
            (code == 1 and out == b"" and error == sdk.profiles.FAILURES["python"]), "age SDK response differs")
        count += increment
        document = observe(check, count)
        check.unchanged(pinned)
        completed.append({"phase": phase, "success": positive, "providerArrivals": increment})
    checked_audit = audit(check, document, scopes, credential["id"])
    accepted_policy = check.policy_hash
    revoked = revoked_control(check, *accounts["recent"], rules["recent"], configs["recent"], document, pinned)
    check.current_files(); check.current_dependencies()
    result = {"schema": SCHEMA, "ok": True, "syntheticOnly": True, "realGoogleVerified": False,
        "productionReady": False, "actualExampleEntrypoint": True, "sdk": "python", "providerAttempts": count,
        "policyHash": accepted_policy, "dataPlaneBinaryDigest": check.args.expected_binary_sha256,
        "sdkDependenciesSha256": check.args.expected_dependencies_sha256, "completed": completed,
        "provider": document["gmailAge"], "audit": checked_audit, "revokedControl": revoked}
    serialized = sdk.encoded(result)
    check.clean(serialized)
    sdk.require(all(value[1].encode() not in serialized for value in accounts.values())
        and all(value.encode() not in serialized for value in check.transient_values), "age private input escaped")
    validate_result(result)
    return result


def validate_result(value):
    sdk.require(value.get("schema") == SCHEMA and value.get("ok") is True and value.get("syntheticOnly") is True
        and value.get("realGoogleVerified") is False and value.get("productionReady") is False
        and value.get("actualExampleEntrypoint") is True
        and value.get("sdk") == "python" and value.get("providerAttempts") == 31
        and value.get("audit") == {"parentStarts": 20, "released": 14, "blocked": 6, "metadataProbes": 11,
            "initialCredentialVersion": 1, "refreshedCredentialVersion": 2}
        and value.get("completed") == [{"phase": phase, "success": phase in {"unrestricted", "recent", "refreshed"},
            "providerArrivals": count} for phase, count in zip(fixture.PHASES, fixture.COUNTS)]
        and len(value.get("provider", {}).get("attempts", [])) == 31
        and all(type(value.get(key)) is str and sdk.SHA256.fullmatch(value[key]) for key in ("policyHash", "dataPlaneBinaryDigest"))
        and type(value.get("sdkDependenciesSha256")) is str and sdk.HEX.fullmatch(value["sdkDependenciesSha256"])
        and value.get("revokedControl", {}).get("providerAttemptsBefore") == 31
        and value["revokedControl"].get("providerAttemptsAfter") == 31
        and value["revokedControl"].get("auditEventType") == sdk.DENIED
        and sdk.SHA256.fullmatch(value["revokedControl"].get("policyHash", ""))
        and value["revokedControl"]["policyHash"] != value["policyHash"], "Gmail age result differs")
