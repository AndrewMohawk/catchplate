"""Separate cold authority for a fixed trusted collector and native runtime."""
import re

from serverware import authority_setup_native_runtime as p
from serverware import authority_credential_currentness_policy as native
from serverware import authority_policy_canary_policy as configuration
from serverware import authority_setup_native_ca as ca

FIELD = "setupNativeRuntimePolicy"
SCHEMA = "serverware.setupNativeRuntimeAuthorityPolicy/v1"
TRUST = "serverware.setupNativeRuntimeTrustRoots/v1"
SCOPE_FIELDS = frozenset({"sessionId", "principalId", "routeId", "credentialId", "credentialVersion", "clientRequest",
    "serverInstanceId", "collectorPublicKeyPem", "controlPlanePublicKeyPem", "nativeAssignment", "issuedAtEpochNs",
    "expiresAtEpochNs", "maximumAttemptNanos", "responseRuntimeManifestSha256", "responseProvenanceSha256"})
ROTATED_SCOPE = "serverware.setupNativeRuntimeRotationScope/v1"
ROTATED_SCOPE_FIELDS = SCOPE_FIELDS | {"apiVersion", "continuationSha256"}


def scope(value):
    p.require(type(value) is dict)
    rotated = value.get("apiVersion") == ROTATED_SCOPE
    p.require(set(value) == (ROTATED_SCOPE_FIELDS if rotated else SCOPE_FIELDS))
    if rotated:
        p.digest(value["continuationSha256"])
    for name in ("sessionId", "credentialId"):
        p.enrollment.setup.identifier(value[name])
    for name in ("principalId", "routeId", "serverInstanceId"):
        p.enrollment.setup.text(value[name], 1024)
    p.require(type(value["credentialVersion"]) is int and
        (2 <= value["credentialVersion"] <= 2**63-1 if rotated else value["credentialVersion"] == 1))
    before, after, limit = value["issuedAtEpochNs"], value["expiresAtEpochNs"], value["maximumAttemptNanos"]
    p.require(all(type(item) is int for item in (before, after, limit)) and 0 < before < after <= 2**63 - 1
        and after - before <= 86400_000_000_000 and 1_000_000_000 <= limit <= 300_000_000_000)
    assignment = native._assignment(value["nativeAssignment"])
    p.digest(value["responseRuntimeManifestSha256"]); p.digest(value["responseProvenanceSha256"])
    collector, control = ca._public(value["collectorPublicKeyPem"]), ca._public(value["controlPlanePublicKeyPem"])
    p.require(ca.key_id(control) == assignment["controlPlaneResponseSigningKeyId"]
        and assignment["keyId"] not in {ca.key_id(control), assignment["caPublicKeySpkiSha256"]}
        and ca.key_id(collector) not in {ca.key_id(control), assignment["keyId"], assignment["caPublicKeySpkiSha256"]})
    request = value["clientRequest"]
    p.require(type(request) is dict and set(request) == {"apiVersion", "method", "scheme", "authority", "path", "query", "headers", "body_sha256"}
        and request["apiVersion"] == "serverware.clientProofRequest/v1" and request["method"] == "GET"
        and request["scheme"] == "https" and request["query"] == [] and request["headers"] == {}
        and request["body_sha256"] == p.sha256(b""))
    from urllib.parse import urlsplit
    p.enrollment.setup.text(request["authority"], 256); p.enrollment.setup.text(request["path"], 4096)
    target = urlsplit("https://" + request["authority"] + request["path"])
    p.require(target.netloc == request["authority"] == request["authority"].lower()
        and target.path == request["path"] and request["path"].startswith("/")
        and not target.query and not target.fragment and target.username is None and target.password is None
        and request["authority"].isascii() and request["path"].isascii())
    # A narrow URL subset that the actual Rust URL owner leaves unchanged.
    # Refuse default-port, IDNA, IP-number and dot-segment normalization, rather
    # than pin a digest that the real collector cannot produce.
    host, port = target.hostname, target.port
    p.require(type(host) is str and len(host) <= 253 and not host.endswith(".")
        and re.match(r"[a-z]", host.rsplit(".", 1)[-1]) is not None
        and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is not None for label in host.split("."))
        and (port is None or 1 <= port <= 65535 and port != 443)
        and request["authority"] == host + (":" + str(port) if port is not None else "")
        and re.fullmatch(r"/[A-Za-z0-9/._~!$&'()*+,;=:@-]*", request["path"]) is not None
        and not any(part in {".", ".."} for part in request["path"].split("/")))
    p.require(len(p.canonical(value)) <= 32768)
    return value


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & p.OPERATIONS for role in payload["roles"].values())
    if value is None:
        p.require(not enabled); return None
    p.require(type(value) is dict and set(value) == {"schema", "credentialPolicy", "trustRoots", "scopes"} and value["schema"] == SCHEMA)
    p.enrollment.hardware.policy(value["credentialPolicy"])
    cp = ca.validate_policy(payload.get(ca.FIELD), payload=payload, root_key=root_key)
    p.require(cp is not None and cp["credentialPolicy"] == value["credentialPolicy"])
    roots = value["trustRoots"]
    p.require(type(roots) is dict and roots.get("apiVersion") == TRUST)
    native._trust({**roots, "apiVersion": native.TRUST_SCHEMA})
    scopes = value["scopes"]; p.require(type(scopes) is list and 1 <= len(scopes) <= 32)
    excluded = {host["keyId"] for host in cp["hosts"]}
    excluded.add(ca.key_id(ca._public(cp["installationRootPublicKeyPem"])))
    excluded.add(ca.key_id(ca._public(payload[ca.issuer_policy.FIELD]["issuerRootPublicKeyPem"])))
    if root_key is not None:
        excluded.add(ca.key_id(root_key))
    for role in payload["roles"].values():
        excluded.update(item for name, item in role.items() if type(item) is str and (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")))
    identities = []
    for item in scopes:
        scope(item); identities.append(item["sessionId"])
        p.require(ca.key_id(ca._public(item["collectorPublicKeyPem"])) not in excluded
            and item["nativeAssignment"]["keyId"] not in excluded)
    p.require(identities == sorted(set(identities)) and len(p.canonical(value)) <= 512 * 1024)
    return value


def attempt_scope(attempt, actual):
    from serverware import authority_setup_native_runtime_receipt as original
    p.require(attempt["apiVersion"] == (p.ROTATED_PREPARED if actual.get("apiVersion") == ROTATED_SCOPE else p.PREPARED))
    for name in ("sessionId", "principalId", "routeId", "credentialId", "credentialVersion"):
        p.require(type(attempt[name]) is type(actual[name]) and attempt[name] == actual[name])
    p.require(attempt["policyHash"] == actual["nativeAssignment"]["policyHash"]
        and attempt["clientRequestSha256"] == p.sha256(original.utf8(actual["clientRequest"]))
        and actual["issuedAtEpochNs"] <= attempt["issuedAtEpochNs"] < attempt["expiresAtEpochNs"] <= actual["expiresAtEpochNs"]
        and attempt["expiresAtEpochNs"] - attempt["issuedAtEpochNs"] <= actual["maximumAttemptNanos"])


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    values = p.arguments(operation, arguments, typed="businessIntent" in arguments)
    policy = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    p.require(policy is not None and type(now_epoch_ns) is int and now_epoch_ns > 0 and values["credential_policy"] == policy["credentialPolicy"]
        and values["control_plane_configuration_digest"] == configuration.full_configuration_digest(configuration_payload))
    actual = scope(p.enrollment.setup.document(values["scope_original"].encode("ascii"), 32768))
    p.require(actual in policy["scopes"] and actual["issuedAtEpochNs"] <= now_epoch_ns < actual["expiresAtEpochNs"])
    if operation == p.COMPLETE:
        from serverware import authority_setup_native_runtime_capture as capture
        attempt = p.prepared(values["attempt_original"])
        p.require(attempt["scopeSha256"] == p.sha256(values["scope_original"].encode("ascii")))
        attempt_scope(attempt, actual)
        capture.verify(p.enrollment.original(values["capture_original_base64url"], p.MAX_CAPTURE),
            attempt, actual, policy["trustRoots"], now_epoch_ns)
    return actual
