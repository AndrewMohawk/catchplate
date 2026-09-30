"""Closed native Setup hardware/proxy successor; no measured-host promotion."""
from collections.abc import Mapping
from serverware import authority_setup_native_runtime as runtime
from serverware import authority_setup_native_ca as ca

enrollment = runtime.enrollment
canonical, require, digest, sha256 = runtime.canonical, runtime.require, runtime.digest, runtime.sha256
PREPARE, COMPLETE = "setup.native-hardware.prepare", "setup.native-hardware.complete"
OPERATIONS, ASSERTION_OPERATIONS = frozenset({PREPARE, COMPLETE}), frozenset({PREPARE})
TABLE = "setup_native_hardware_attempts"
HTTP, OPTIONS = "serverware.setupNativeHardwareRequest/v1", "serverware.setupNativeHardwareOptions/v1"
ATTEMPT, STATEMENT = "serverware.setupNativeHardwareAttempt/v1", "serverware.nativeSetupHardwareStatement/v1"
QUOTE_DOMAIN = b"serverware/native-setup-hardware-attestation/v1\0"
RECEIPT_DOMAIN = b"serverware/setup-native-independent-verification/v1\0"
ROLES = ("hardware-verifier", "proxy-verifier")
MAX_ARGUMENT_BYTES, MAX_ROW_BYTES, MAX_BUNDLE = 4*1024*1024, 4*1024*1024, 4*1024*1024
FIELDS = frozenset({"actor_id", "control_plane_configuration_digest", "credential_policy", "maximum_attempt_nanos", "association_original",
    "runtime_original", "enrollment_original", "installation_original", "scope_original", "attempt_original",
    "evidence_original", "hardware_receipt_original", "proxy_receipt_original"})
ATTEMPT_FIELDS = frozenset({"apiVersion", "attemptId", "sessionId", "ownerId", "associationSha256", "runtimeSha256",
    "enrollmentSha256", "installationSha256", "scopeSha256", "nonce", "policyHash", "principalId", "routeId",
    "credentialId", "credentialVersion", "issuedAtEpochNs", "expiresAtEpochNs"})
ROW_FIELDS = frozenset({"session_id", "revision", "phase", "owner_id", "inputs_original", "attempt_original", "attempt_sha256",
    "prepare_request_digest", "prepare_audit_id", "evidence_original", "hardware_receipt_original", "proxy_receipt_original",
    "result_original", "complete_request_digest", "configuration_digest", "created_at", "completed_at"})
INPUT_FIELDS = FIELDS - {"attempt_original", "evidence_original", "hardware_receipt_original", "proxy_receipt_original"}
RECEIPT_FIELDS = frozenset({"apiVersion", "purpose", "resultScope", "attemptSha256", "evidenceSha256", "runtimeSha256",
    "enrollmentSha256", "installationSha256", "scopeSha256", "quoteSha256", "releaseRecordSha256", "policyHash",
    "verifierKeyId", "verifierProvider", "issuedAtEpochNs", "expiresAtEpochNs", "measuredHost", "finalSetup", "proxyReady"})


def original(text, maximum):
    require(type(text) is str and text.isascii())
    return enrollment.setup.document(text.encode("ascii"), maximum)


def prepared(text):
    value = original(text, 8192)
    require(set(value) == ATTEMPT_FIELDS and value["apiVersion"] == ATTEMPT)
    for name in ("attemptId", "sessionId", "credentialId"):
        enrollment.setup.identifier(value[name])
    for name in ("ownerId", "principalId", "routeId"):
        enrollment.setup.text(value[name], 1024)
    require(value["ownerId"].startswith("oidc:") and type(value["credentialVersion"]) is int and value["credentialVersion"] == 1)
    for name in ("associationSha256", "runtimeSha256", "enrollmentSha256", "installationSha256", "scopeSha256", "policyHash"):
        digest(value[name])
    require(len(enrollment.original(value["nonce"], 32)) == 32)
    before, after = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    require(type(before) is int and type(after) is int and 0 < before < after <= 2**63-1 and after-before <= 300_000_000_000)
    return value


def inputs(value):
    require(type(value) is dict and set(value) == INPUT_FIELDS)
    enrollment.setup.text(value["actor_id"], 1024); require(value["actor_id"].startswith("oidc:"))
    digest(value["control_plane_configuration_digest"]); enrollment.hardware.policy(value["credential_policy"])
    require(type(value["maximum_attempt_nanos"]) is int and 1_000_000_000 <= value["maximum_attempt_nanos"] <= 300_000_000_000)
    a = runtime.association(value["association_original"])
    rows = [(runtime, "runtime_original", "runtime_evidence_recorded"), (enrollment, "enrollment_original", "certificate_issued"),
        (ca, "installation_original", "ca_readback_authenticated")]
    for codec, name, phase in rows:
        row = original(value[name], enrollment.MAX_ROW_BYTES if codec is enrollment else MAX_ROW_BYTES)
        require(codec.row_original(row).decode("ascii") == value[name] and row["phase"] == phase
            and row["session_id"] == a["session_id"] and row["owner_id"] == value["actor_id"]
            and row["configuration_digest"] == value["control_plane_configuration_digest"])
    from serverware import authority_setup_native_runtime_policy as rp
    scope=rp.scope(original(value["scope_original"], 32768))
    require(all(len(scope[name].encode("utf-8")) <= 256 for name in ("principalId","routeId")))
    require(len(canonical(value)) <= MAX_ARGUMENT_BYTES)
    # Refuse BEFORE reservation when even the bounded native output could make
    # the fixed response overflow. Include both string-nesting levels and the
    # public wrapper; this is a size bound, never a synthetic evidence object.
    empty_request=canonical({**value,"attempt_original":"","evidence_original":""}).decode("ascii")
    empty_bundle={"inputsOriginal":canonical(value).decode("ascii"),"attemptOriginal":"","evidenceOriginal":"","verifierRequestOriginal":empty_request}
    require(len(canonical(empty_bundle))+24*(8192+65536)+32768 <= MAX_BUNDLE)
    return value


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping))
    require(FIELDS <= set(value) <= FIELDS | ({"businessIntent", "authn_evidence"} if typed else set())
        and (not typed or "businessIntent" in value))
    result = {name:value[name] for name in FIELDS}; inputs({name:value[name] for name in INPUT_FIELDS})
    if operation == PREPARE:
        require(all(value[name] is None for name in FIELDS-INPUT_FIELDS))
    else:
        attempt = prepared(value["attempt_original"])
        for name, field in (("associationSha256", "association_original"), ("runtimeSha256", "runtime_original"),
                ("enrollmentSha256", "enrollment_original"), ("installationSha256", "installation_original"), ("scopeSha256", "scope_original")):
            require(attempt[name] == sha256(value[field].encode("ascii")))
        require(attempt["ownerId"] == value["actor_id"])
        evidence(value["evidence_original"])
        receipt(value["hardware_receipt_original"], ROLES[0]); receipt(value["proxy_receipt_original"], ROLES[1])
    require(len(canonical(result)) <= MAX_ARGUMENT_BYTES)
    return result


def evidence(text):
    value = original(text, 65536)
    require(set(value) == {"statement", "signature", "nativeKeyEvidence"})
    statement = value["statement"]
    require(type(statement) is dict and set(statement) == {"apiVersion", "attempt", "policyOriginalSha256", "routePolicyDigest",
        "bootId", "keyId", "controlPlaneResponseSigningKeyId", "dataPlaneBinarySha256", "observedAtEpochNs"}
        and statement["apiVersion"] == STATEMENT)
    prepared(canonical(statement["attempt"]).decode("ascii"))
    require(type(statement["observedAtEpochNs"]) is int and statement["observedAtEpochNs"] > 0)
    for name in ("policyOriginalSha256", "routePolicyDigest", "keyId", "controlPlaneResponseSigningKeyId", "dataPlaneBinarySha256"):
        digest(statement[name])
    require(len(enrollment.original(statement["bootId"], 32)) == 32)
    require(type(value["signature"]) is str and value["signature"].startswith("ed25519:")
        and len(enrollment.original(value["signature"][8:], 64)) == 64)
    return value


def receipt(text, role):
    value = original(text, 16384); require(role in ROLES and set(value) == {"payload", "signature"})
    p = value["payload"]
    require(type(p) is dict and set(p) == RECEIPT_FIELDS and p["apiVersion"] == "serverware.setupNativeIndependentVerification/v1"
        and p["purpose"] == role and p["resultScope"] == "enclave-hardware-and-proxy-only"
        and all(p[name] is False for name in ("measuredHost", "finalSetup", "proxyReady")))
    for name in RECEIPT_FIELDS - {"apiVersion", "purpose", "resultScope", "verifierProvider", "issuedAtEpochNs", "expiresAtEpochNs",
            "measuredHost", "finalSetup", "proxyReady"}:
        digest(p[name])
    enrollment.setup.text(p["verifierProvider"], 128)
    require(type(p["issuedAtEpochNs"]) is int and type(p["expiresAtEpochNs"]) is int
        and 0 < p["issuedAtEpochNs"] < p["expiresAtEpochNs"] <= 2**63-1
        and p["expiresAtEpochNs"]-p["issuedAtEpochNs"] <= 300_000_000_000)
    require(type(value["signature"]) is str and value["signature"].startswith("ed25519:")
        and len(enrollment.original(value["signature"][8:], 64)) == 64)
    return value


def row_original(row):
    require(type(row) is dict and set(row) == ROW_FIELDS and type(row["revision"]) is int)
    i = inputs(original(row["inputs_original"], MAX_ARGUMENT_BYTES)); a = prepared(row["attempt_original"])
    require(row["owner_id"] == i["actor_id"] == a["ownerId"] and row["session_id"] == a["sessionId"]
        and row["configuration_digest"] == i["control_plane_configuration_digest"]
        and row["attempt_sha256"] == sha256(row["attempt_original"].encode("ascii")))
    digest(row["prepare_request_digest"]); enrollment.setup.identifier(row["prepare_audit_id"]); enrollment.setup.epoch(row["created_at"])
    completed = ("evidence_original", "hardware_receipt_original", "proxy_receipt_original", "result_original", "complete_request_digest", "completed_at")
    if row["revision"] == 0:
        require(row["phase"] == "hardware_outcome_unknown" and all(row[name] is None for name in completed))
    else:
        require(row["revision"] == 1 and row["phase"] == "hardware_proxy_verified" and all(row[name] is not None for name in completed))
        arguments(COMPLETE, {**i, **{name:row[name] for name in FIELDS-INPUT_FIELDS}})
        digest(row["complete_request_digest"]); enrollment.setup.epoch(row["completed_at"])
        require(row["result_original"] == canonical(projection(row["attempt_original"], row["evidence_original"],
            row["hardware_receipt_original"], row["proxy_receipt_original"])).decode("ascii"))
    raw=canonical(row); require(len(raw) <= MAX_ROW_BYTES); return raw


def projection(attempt, quote, hardware, proxy):
    return {"apiVersion":"serverware.setupNativeHardwareResult/v1", "resultScope":"enclave-hardware-and-proxy-only",
        "hostAssociationTrust":"trusted-host-local", "measuredHost":False, "finalSetup":False, "proxyReady":False,
        "okForAction":False, "attemptSha256":sha256(attempt.encode("ascii")), "evidenceSha256":sha256(quote.encode("ascii")),
        "hardwareReceiptSha256":sha256(hardware.encode("ascii")), "proxyReceiptSha256":sha256(proxy.encode("ascii"))}


def public(row):
    if row is None: return None
    row_original(row)
    return {name:row[field] for name,field in (("revision","revision"),("phase","phase"),("attemptSha256","attempt_sha256"),
        ("prepareRequestDigest","prepare_request_digest"),("completeRequestDigest","complete_request_digest"))}


def request_digest(operation,value):
    from serverware import authority_contract as contract, authority_request_commitment as commitment
    v=arguments(operation,value,typed="businessIntent" in value)
    typed={**v,"businessIntent":contract.synthesize_business_intent(operation,v)}
    return commitment.framed_digest("serverware.policyAuthorityV9Request/v1",canonical({"schema":"serverware.policyAuthorityV9Authorization/v1",
        "operation":operation,"handler":contract.operation_spec(operation)["handler"],"operationManifestDigest":contract.OPERATION_MANIFEST_DIGEST,
        "arguments":commitment._authorization_arguments(typed)}))
