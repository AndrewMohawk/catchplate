"""Fixed ordinary native dispatch receipt, reverified from its signed bytes."""
import base64
import json
import re

from serverware import authority_setup_native_runtime as p
from serverware import authority_setup_native_ca as keys


def exact(value, fields):
    p.require(type(value) is dict and set(value) == set(fields))
    return value


def uint(value, low=0, high=2**63 - 1):
    p.require(type(value) is int and low <= value <= high)
    return value


def utf8(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def b64(value, maximum, minimum=0):
    p.require(type(value) is str and value.isascii() and len(value) <= (maximum * 8 + 5) // 6)
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    p.require(minimum <= len(raw) <= maximum and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def document(raw, maximum):
    p.require(type(raw) is bytes and 0 < len(raw) <= maximum)
    def pairs(items):
        result = {}
        for key, item in items:
            p.require(key not in result); result[key] = item
        return result
    def invalid(_):
        raise ValueError("native runtime original contains a noninteger")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop(); count += 1
        p.require(count <= 20000 and depth <= 48)
        if type(item) is dict:
            pending.extend((child, depth + 1) for pair in item.items() for child in pair)
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            item.encode("utf-8")
        elif type(item) is int:
            p.require(-(2**63) <= item < 2**64)
        else:
            p.require(item is None or type(item) is bool)
        p.require(count + len(pending) <= 20000)
    p.require(type(value) is dict)
    return value


def original(obj, name, digest, maximum):
    raw = b64(obj[name], maximum, 1); p.require(p.sha256(raw) == obj[digest])
    value = document(raw, maximum); p.require(p.canonical(value) == raw)
    return value


def signature(value, original_bytes, expected_pem, *, capture=False):
    exact(value, {"algorithm", "key_id", "public_key_pem", "signature"} | ({"capture_digest"} if capture else set()))
    key = keys._public(expected_pem)
    p.require(value["algorithm"] == "Ed25519" and value["public_key_pem"] == expected_pem and value["key_id"] == keys.key_id(key))
    if capture:
        p.require(value["capture_digest"] == p.sha256(original_bytes))
    p.require(type(value["signature"]) is str and value["signature"].startswith("ed25519:"))
    key.verify(b64(value["signature"][8:], 64, 64), original_bytes)
    return key


def verify(statement, scope, attempt, now):
    authority = exact(statement["release_authority"], {"authority_mode", "grant_id", "approval_id", "credential_ref",
        "credential_version", "request_digest", "operation_digest", "attempt_id", "consumption_identity_digest",
        "authorization_state_at_upstream_dispatch", "authorization_state_observed_at_epoch_ms",
        "reservation_expires_at_epoch_ms", "dispatch_expires_at_epoch_ms"})
    p.require(authority["authority_mode"] == "atomic" and authority["grant_id"] is None and authority["approval_id"] is None
        and authority["credential_ref"] == attempt["credentialId"] and type(authority["credential_version"]) is int
        and authority["credential_version"] == attempt["credentialVersion"] and authority["authorization_state_at_upstream_dispatch"] == "dispatching")
    for field in ("request_digest", "operation_digest", "attempt_id", "consumption_identity_digest"):
        p.digest(authority[field])
    p.require(all(authority[field] == statement[field] for field in ("request_digest", "operation_digest")))
    receipt = exact(statement["control_plane_authorization_receipt"], {"apiVersion", "kind", "principal_id", "route_id", "release_authority", "request", "response"})
    p.require(receipt["apiVersion"] == "serverware.nativeControlPlaneAuthorizationReceipt/v1"
        and receipt["kind"] == "ServerwareNativeControlPlaneAuthorizationReceipt"
        and all(receipt[field] == statement[field] for field in ("principal_id", "route_id", "release_authority")))
    request = exact(receipt["request"], {"method", "path", "query", "nonce", "body_b64", "body_sha256"})
    p.require((request["method"], request["path"], request["query"]) == ("POST", "/api/data-plane/release-authorizations/dispatch", ""))
    b64(request["nonce"], 32, 32)
    body = exact(original(request, "body_b64", "body_sha256", 4096), {"apiVersion", "attemptId", "bindingDigest"})
    p.require(body == {"apiVersion": "serverware.nativeReleaseAuthorizationDispatch/v1", "attemptId": authority["attempt_id"],
        "bindingDigest": authority["consumption_identity_digest"]})
    response = exact(receipt["response"], {"status", "body_b64", "body_sha256", "response_headers", "response_signing_key_id", "statement_b64", "statement_sha256", "signature"})
    result = exact(original(response, "body_b64", "body_sha256", 32768), {"apiVersion", "ok", "authorized", "state", "reason", "attemptId", "bindingDigest",
        "idempotentReplay", "grantId", "approvalRequestId", "reservationExpiresAtEpochMs", "dispatchStartedAtEpochMs", "dispatchExpiresAtEpochMs",
        "completionOutcome", "retryAfterSeconds", "quotas", "store"})
    p.require(type(response["status"]) is int and response["status"] == 200
        and result["apiVersion"] == "serverware.nativeReleaseAuthorizationResponse/v1"
        and result["ok"] is True and result["authorized"] is True and result["state"] == result["reason"] == "dispatching"
        and type(result["idempotentReplay"]) is bool and result["completionOutcome"] is None and result["quotas"] == []
        and type(result["retryAfterSeconds"]) is int and result["retryAfterSeconds"] == 0)
    store = exact(result["store"], {"backend", "ha"}); p.enrollment.setup.text(store["backend"], 256); p.require(store["ha"] is True)
    for name, source in (("attemptId", "attempt_id"), ("bindingDigest", "consumption_identity_digest"), ("grantId", "grant_id"),
            ("approvalRequestId", "approval_id"), ("reservationExpiresAtEpochMs", "reservation_expires_at_epoch_ms"),
            ("dispatchStartedAtEpochMs", "authorization_state_observed_at_epoch_ms"), ("dispatchExpiresAtEpochMs", "dispatch_expires_at_epoch_ms")):
        p.require(type(result[name]) is type(authority[source]) and result[name] == authority[source])
    signed = exact(original(response, "statement_b64", "statement_sha256", 8192), {"version", "issued_at_ms", "request", "status_code", "body_sha256",
        "response_headers_sha256", "response_header_count", "nonce", "response_signing_key_id", "context"})
    headers = response["response_headers"]; p.require(type(headers) is list and 0 < len(headers) <= 128)
    previous, total = "", 0
    for item in headers:
        exact(item, {"name", "value_b64"}); name = item["name"]
        p.require(type(name) is str and re.fullmatch(r"[a-z0-9!#$%&'*+.^_`|~-]{1,256}", name) is not None
            and not name.startswith("x-serverware-response-") and name not in {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"}
            and not any(term in name for term in ("authorization", "cookie", "secret", "token", "password", "passwd", "api-key", "apikey", "private-key"))
            and previous <= name and (previous != name or name in {"link", "warning", "www-authenticate"}))
        raw = b64(item["value_b64"], 65536); total += len(name) + len(raw); previous = name
        p.require(total <= 65536 and not any(byte < 32 and byte != 9 or byte == 127 for byte in raw))
    expected_key = keys.key_id(keys._public(scope["controlPlanePublicKeyPem"]))
    p.require(signed["version"] == "serverware.responseSignature/v3" and signed["nonce"] == request["nonce"]
        and signed["request"] == {"method": request["method"], "path": request["path"], "query_sha256": p.sha256(b"")}
        and type(signed["status_code"]) is int and signed["status_code"] == 200
        and signed["body_sha256"] == response["body_sha256"] and signed["response_signing_key_id"] == response["response_signing_key_id"] == expected_key
        and type(signed["response_header_count"]) is int and signed["response_header_count"] == len(headers)
        and signed["response_headers_sha256"] == p.sha256(utf8(headers)))
    context = exact(signed["context"], {"runtime_manifest_digest", "policy_bundle_digest", "provenance_digest", "image_signatures_digest", "source_tree_digest"})
    for name, value in context.items():
        if value is not None or name in {"runtime_manifest_digest", "policy_bundle_digest"}:
            p.digest(value)
    p.require(context["policy_bundle_digest"] == statement["policy_digest"] and context["provenance_digest"] == statement["release_digest"])
    start, reservation, deadline = (uint(authority[field], 1) for field in
        ("authorization_state_observed_at_epoch_ms", "reservation_expires_at_epoch_ms", "dispatch_expires_at_epoch_ms"))
    signed_at = uint(signed["issued_at_ms"], 1); end = (uint(statement["issued_at_unix"], 1) + 1) * 1000 - 1
    p.require(attempt["issuedAtEpochNs"] <= start * 1_000_000 <= signed_at * 1_000_000
        and start <= signed_at < min(reservation, deadline) and signed_at <= end and end - start <= 300000
        and deadline * 1_000_000 > now)
    p.require(type(response["signature"]) is str and response["signature"].startswith("ed25519:"))
    keys._public(scope["controlPlanePublicKeyPem"]).verify(b64(response["signature"][8:], 64, 64), p.canonical(signed))
    return receipt
