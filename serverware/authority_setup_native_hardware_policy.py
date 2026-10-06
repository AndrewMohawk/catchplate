"""Cold independent hardware/proxy authorities; shared genuine original verifier."""
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from scripts import verify_nitro_tee as nitro
from serverware import authority_setup_native_hardware as p
from serverware import authority_setup_native_runtime_policy as runtime_policy
from serverware import authority_setup_native_runtime_capture as capture

FIELD, SCHEMA = "setupNativeHardwarePolicy", "serverware.setupNativeHardwareAuthorityPolicy/v1"


def authority(value):
    p.require(type(value) is dict and set(value) == {"provider", "publicKeyPem"})
    p.enrollment.setup.text(value["provider"], 128)
    return p.ca._public(value["publicKeyPem"])


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & p.OPERATIONS for role in payload["roles"].values())
    if value is None:
        p.require(not enabled); return None
    p.require(type(value) is dict and set(value) == {"schema", "credentialPolicy", "hardwareVerifier", "proxyVerifier", "finalAuthority", "maximumAttemptNanos"}
        and value["schema"] == SCHEMA and type(value["maximumAttemptNanos"]) is int and 1_000_000_000 <= value["maximumAttemptNanos"] <= 300_000_000_000)
    rp = runtime_policy.validate_policy(payload.get(runtime_policy.FIELD), payload=payload, root_key=root_key)
    p.require(rp is not None and value["credentialPolicy"] == rp["credentialPolicy"])
    names = ("hardwareVerifier", "proxyVerifier", "finalAuthority")
    keys = [p.ca.key_id(authority(value[name])) for name in names]
    p.require(len(set(keys)) == 3 and len({value[name]["provider"] for name in names}) == 3)
    excluded = {p.ca.key_id(p.ca._public(payload[p.ca.FIELD]["installationRootPublicKeyPem"])),
        p.ca.key_id(p.ca._public(payload[p.ca.issuer_policy.FIELD]["issuerRootPublicKeyPem"]))}
    excluded.update(host["keyId"] for host in payload[p.ca.FIELD]["hosts"])
    if root_key is not None: excluded.add(p.ca.key_id(root_key))
    for role in payload["roles"].values():
        excluded.update(v for name,v in role.items() if type(v) is str and (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")))
    for scope in rp["scopes"]:
        excluded.update((scope["nativeAssignment"]["keyId"], scope["nativeAssignment"]["caPublicKeySpkiSha256"],
            p.ca.key_id(p.ca._public(scope["collectorPublicKeyPem"])), p.ca.key_id(p.ca._public(scope["controlPlanePublicKeyPem"]))))
    p.require(not set(keys) & excluded)
    return value


def verify_inputs(values, payload, root_key, now):
    policy = validate_policy(payload.get(FIELD), payload=payload, root_key=root_key)
    p.require(policy is not None and values["credential_policy"] == policy["credentialPolicy"]
        and values["maximum_attempt_nanos"] == policy["maximumAttemptNanos"]
        and values["control_plane_configuration_digest"] == runtime_policy.configuration.full_configuration_digest(payload))
    p.inputs({name:values[name] for name in p.INPUT_FIELDS})
    scope = runtime_policy.scope(p.original(values["scope_original"], 32768))
    rp = payload[runtime_policy.FIELD]; p.require(scope in rp["scopes"] and scope["issuedAtEpochNs"] <= now < scope["expiresAtEpochNs"])
    runtime = p.original(values["runtime_original"], p.runtime.MAX_ROW_BYTES)
    enrollment = p.original(values["enrollment_original"], p.enrollment.MAX_ROW_BYTES)
    installation = p.original(values["installation_original"], p.MAX_ROW_BYTES)
    association = p.runtime.association(values["association_original"])
    p.require(runtime["association_sha256"] == p.sha256(values["association_original"].encode("ascii"))
        and runtime["scope_original"] == values["scope_original"]
        and association["enrollment_sha256"] == installation["enrollment_sha256"] == p.sha256(values["enrollment_original"].encode("ascii"))
        and association["installation_sha256"] == p.sha256(values["installation_original"].encode("ascii")))
    intent = p.enrollment.intent(enrollment["intent_original"])
    p.require((scope.get("apiVersion") == runtime_policy.ROTATED_SCOPE) == (intent["apiVersion"] == p.enrollment.ROTATED_SCHEMA))
    if intent["apiVersion"] == p.enrollment.ROTATED_SCHEMA:
        p.require(scope["continuationSha256"] == intent["continuationSha256"])
    runtime_attempt = p.runtime.prepared(runtime["attempt_original"])
    runtime_policy.attempt_scope(runtime_attempt, scope)
    raw = p.enrollment.original(runtime["capture_original_base64url"], p.runtime.MAX_CAPTURE)
    result = capture.verify(raw, runtime_attempt, scope, rp["trustRoots"], now)
    p.require(runtime["capture_sha256"] == p.sha256(raw) and runtime["result_original"] == p.canonical(result).decode("ascii"))
    grant = p.ca.verify_original(p.ca.COMPLETE, {"actor_id":values["actor_id"], "control_plane_configuration_digest":values["control_plane_configuration_digest"],
        "credential_policy":values["credential_policy"], "enrollment_original":values["enrollment_original"],
        "installation_original":installation["installation_original"], "host_key_id":installation["host_key_id"],
        "observation_original":installation["observation_original"]}, configuration_payload=payload, root_key=root_key, now_epoch_ns=now)
    p.require(intent["policyHash"] == association["policy_hash"] == scope["nativeAssignment"]["policyHash"]
        and intent["principalId"] == scope["principalId"] and intent["credentialId"] == scope["credentialId"]
        and intent["credentialVersion"] == scope["credentialVersion"])
    issuance = p.enrollment.setup.document(p.enrollment.original(intent["authorization"],32768),32768)["payload"]
    keys = {p.ca.key_id(authority(policy[name])) for name in ("hardwareVerifier","proxyVerifier","finalAuthority")}
    p.require(not keys & {issuance["issuerSpkiSha256"],issuance["subjectPublicKeyInfoSha256"],issuance["authorizationKeySpkiDigest"]})
    return policy, scope, intent, runtime_attempt, grant


def verify_quote(values, payload, root_key, now):
    policy, scope, intent, runtime_attempt, grant = verify_inputs(values, payload, root_key, now)
    attempt = p.prepared(values["attempt_original"])
    linked = p.rotation_binding(values)
    p.require(attempt["apiVersion"] == (p.ROTATED_ATTEMPT if linked is not None else p.ATTEMPT))
    if linked is not None:
        p.require(all(attempt[name] == item for name, item in linked.items()))
    p.require(attempt["issuedAtEpochNs"] <= now < attempt["expiresAtEpochNs"] <= min(runtime_attempt["expiresAtEpochNs"],intent["expiresAtEpochNs"],grant["expiresAtEpochNs"])
        and attempt["expiresAtEpochNs"]-attempt["issuedAtEpochNs"] <= policy["maximumAttemptNanos"])
    for name, field in (("associationSha256", "association_original"), ("runtimeSha256", "runtime_original"),
            ("enrollmentSha256", "enrollment_original"), ("installationSha256", "installation_original"), ("scopeSha256", "scope_original")):
        p.require(attempt[name] == p.sha256(values[field].encode("ascii")))
    for name in ("sessionId", "principalId", "routeId", "credentialId", "credentialVersion"):
        p.require(type(attempt[name]) is type(scope[name]) and attempt[name] == scope[name])
    expected = scope["nativeAssignment"]
    p.require(attempt["policyHash"] == expected["policyHash"] and attempt["ownerId"] == values["actor_id"])
    evidence = p.evidence(values["evidence_original"]); statement = evidence["statement"]
    p.require(p.canonical(statement["attempt"]) == p.canonical(attempt)
        and statement["policyOriginalSha256"] == expected["policyHash"] and statement["routePolicyDigest"] == intent["routePolicyDigest"]
        and statement["bootId"] == expected["bootId"] and statement["keyId"] == expected["keyId"]
        and statement["controlPlaneResponseSigningKeyId"] == expected["controlPlaneResponseSigningKeyId"]
        and statement["dataPlaneBinarySha256"] == expected["expectedBinaryDigest"]
        and attempt["issuedAtEpochNs"] <= statement["observedAtEpochNs"] <= now)
    e = capture.r.exact(evidence["nativeKeyEvidence"], {"apiVersion", "attestationDocumentB64", "responseProofPublicKey"})
    p.require(e["apiVersion"] == "serverware.nativeResponseProofKeyEvidence/v1")
    raw_key = p.enrollment.original(e["responseProofPublicKey"], 32); p.require(len(raw_key) == 32 and raw_key != bytes(32))
    key = Ed25519PublicKey.from_public_bytes(raw_key); p.require(p.ca.key_id(key) == expected["keyId"])
    signature = p.enrollment.original(evidence["signature"][8:], 64)
    key.verify(signature, p.STATEMENT.encode("ascii") + b"\0" + p.canonical(statement))
    nonce = hashlib.sha256(p.QUOTE_DOMAIN + p.enrollment.original(attempt["nonce"], 32) + hashlib.sha256(p.canonical(statement)).digest() + signature).digest()
    binding = hashlib.sha256(b"serverware/native-proof-custody-boot/v1\0" + p.enrollment.original(expected["bootId"],32)
        + bytes.fromhex(expected["keyId"][7:]) + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"serverware/enclave-runtime-key-binding/v1\0\x04" + b"".join(bytes.fromhex(expected[name][7:])
        for name in ("releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256", "caPublicKeySpkiSha256"))
    user_data += hashlib.sha256(raw_key).digest() + binding
    p.require(len(user_data) <= 512)
    roots = payload[runtime_policy.FIELD]["trustRoots"]
    trust, crls, certs = runtime_policy.native._trust({**roots, "apiVersion":runtime_policy.native.TRUST_SCHEMA})
    document = p.enrollment.original(e["attestationDocumentB64"],12288)
    attested, _, _, _, _ = nitro._verify_nitro_document_common(document, claims=None, expected_user_data_bytes=user_data,
        challenge=nonce, expected_pcrs=expected["expectedPcrs"], expected_eif=expected["expectedEif"], roots=trust, crls=crls,
        certificate_profile=certs, expected_module_id=expected["expectedModuleId"], now=now//1_000_000_000,
        max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    # Retain the genuine millisecond timestamp; the verifier's legacy seconds
    # projection would discard almost a second on this immediate fixed call.
    # Conservative quantization does not assert an AWS clock-accuracy SLA.
    timestamp=attested["timestamp"]
    p.require(type(timestamp) is int and timestamp>0 and type(attested["public_key"]) is bytes and attested["public_key"] == raw_key
        and attempt["issuedAtEpochNs"] <= (timestamp-1)*1_000_000 and (timestamp+1)*1_000_000 < attempt["expiresAtEpochNs"])
    return policy, attempt, expected, p.sha256(document)


def computed_receipt(values, payload, root_key, now, role):
    p.require(role in p.ROLES)
    policy, attempt, expected, quote = verify_quote(values, payload, root_key, now)
    return _receipt_fields(values,policy,attempt,expected,quote,now,role)


def _receipt_fields(values,policy,attempt,expected,quote,now,role):
    selected = policy["hardwareVerifier" if role == p.ROLES[0] else "proxyVerifier"]
    return {"apiVersion":"serverware.setupNativeIndependentVerification/v1", "purpose":role,
        "resultScope":"enclave-hardware-and-proxy-only", "attemptSha256":p.sha256(values["attempt_original"].encode("ascii")),
        "evidenceSha256":p.sha256(values["evidence_original"].encode("ascii")), "runtimeSha256":attempt["runtimeSha256"],
        "enrollmentSha256":attempt["enrollmentSha256"], "installationSha256":attempt["installationSha256"], "scopeSha256":attempt["scopeSha256"],
        "quoteSha256":quote, "releaseRecordSha256":expected["releaseRecordSha256"], "policyHash":expected["policyHash"],
        "verifierKeyId":p.ca.key_id(authority(selected)), "verifierProvider":selected["provider"], "issuedAtEpochNs":now,
        "expiresAtEpochNs":attempt["expiresAtEpochNs"], "measuredHost":False, "finalSetup":False, "proxyReady":False}


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    values = p.arguments(operation, arguments, typed="businessIntent" in arguments)
    if operation == p.PREPARE:
        return verify_inputs(values, configuration_payload, root_key, now_epoch_ns)
    policy, attempt, expected, quote = verify_quote(values, configuration_payload, root_key, now_epoch_ns)
    for role, field, name in ((p.ROLES[0], "hardware_receipt_original", "hardwareVerifier"), (p.ROLES[1], "proxy_receipt_original", "proxyVerifier")):
        receipt = p.receipt(values[field],role); r = receipt["payload"]
        p.require(attempt["issuedAtEpochNs"] <= r["issuedAtEpochNs"] <= now_epoch_ns < r["expiresAtEpochNs"])
        # Verification never replaces issuance time with arrival time. Only the
        # independently verified result fields, not a caller success projection.
        computed = _receipt_fields(values,policy,attempt,expected,quote,now_epoch_ns,role)
        computed["issuedAtEpochNs"] = r["issuedAtEpochNs"]
        p.require(p.canonical(computed) == p.canonical(r))
        authority(policy[name]).verify(p.enrollment.original(receipt["signature"][8:],64),
            p.RECEIPT_DOMAIN + role.encode("ascii") + b"\0" + p.canonical(r))
    return attempt
