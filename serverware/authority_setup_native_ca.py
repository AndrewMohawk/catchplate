"""Purpose-fixed authenticated host CA readback; never a native host proof."""
import base64
from collections.abc import Mapping

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from serverware import authority_setup_native_enrollment as enrollment
from serverware import authority_setup_native_enrollment_policy as issuer_policy
from serverware import native_ca_installation_authorization as installation

canonical, require, digest, sha256 = enrollment.canonical, enrollment.require, enrollment.digest, enrollment.sha256
PREPARE, COMPLETE = "setup.native-ca.prepare", "setup.native-ca.complete"
OPERATIONS, ASSERTION_OPERATIONS = frozenset({PREPARE, COMPLETE}), frozenset({PREPARE})
TABLE = "setup_native_ca_installations"
FIELD = "setupNativeCaInstallationPolicy"
SCHEMA = "serverware.setupNativeCaInstallationAuthorityPolicy/v1"
HTTP = "serverware.setupNativeCaInstallationRequest/v1"
PREPARED = "serverware.setupNativeCaInstallationPrepared/v1"
OBSERVATION = "serverware.nativeSetupCaInstallObservation/v1"
DOMAIN = b"serverware.nativeSetupCaInstallObservation/v1\0"
POSSESSION_DOMAIN = b"serverware.nativeSetupCaInstallPossession/v1\0"
MAX_ARGUMENT_BYTES, MAX_OBSERVATION = 1800000, 32768
FIELDS = frozenset({"actor_id", "control_plane_configuration_digest", "credential_policy", "enrollment_original",
    "installation_original", "host_key_id", "observation_original"})
ROW_FIELDS = frozenset({"session_id", "revision", "phase", "owner_id", "enrollment_sha256", "installation_original",
    "host_key_id", "prepared_original", "prepared_sha256", "prepare_request_digest", "observation_original",
    "observation_sha256", "complete_request_digest", "configuration_digest", "created_at", "completed_at"})
PREPARED_FIELDS = frozenset({"apiVersion", "attemptId", "sessionId", "enrollmentSha256", "intentSha256", "certificateSha256",
    "associationSha256", "installationAuthorizationSha256", "hostKeyId", "nonceSha256", "issuedAtEpochNs", "expiresAtEpochNs"})
OBSERVATION_FIELDS = frozenset({"apiVersion", "purpose", "trustMode", "preparedSha256", "enrollmentSha256", "certificateSha256",
    "associationSha256", "installationAuthorizationSha256", "nativeSetupSha256", "targetRequestSha256", "runtimeCaCertificateSha256",
    "hostId", "machineIdSha256", "bootId", "namespaceDevice", "namespaceInode", "destinationPath", "destinationIdentity",
    "operationSha256", "reservationSha256", "observedBeforeEpochNs", "observedAfterEpochNs", "hostSigningKeyId", "workloadSpkiSha256"})


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping))
    allowed = FIELDS | ({"businessIntent", "authn_evidence"} if typed else set())
    require(FIELDS <= set(value) <= allowed and (not typed or "businessIntent" in value))
    enrollment.setup.text(value["actor_id"], 1024); require(value["actor_id"].startswith("oidc:"))
    digest(value["control_plane_configuration_digest"]); digest(value["host_key_id"])
    enrollment.hardware.policy(value["credential_policy"])
    row = enrollment.setup.document(value["enrollment_original"].encode("ascii"), enrollment.MAX_ROW_BYTES)
    require(enrollment.row_original(row).decode("ascii") == value["enrollment_original"] and row["phase"] == "certificate_issued"
        and row["owner_id"] == value["actor_id"] and row["configuration_digest"] == value["control_plane_configuration_digest"])
    enrollment.original(value["installation_original"], installation.MAX_BYTES)
    if operation == PREPARE:
        require(value["observation_original"] is None)
    else:
        observation(value["observation_original"])
    result = {name: value[name] for name in FIELDS}
    require(len(canonical(result)) <= MAX_ARGUMENT_BYTES)
    return result


def prepared(text):
    value = enrollment.setup.document(text.encode("ascii"), 8192)
    require(set(value) == PREPARED_FIELDS and value["apiVersion"] == PREPARED)
    enrollment.setup.identifier(value["sessionId"]); enrollment.setup.identifier(value["attemptId"])
    for name in PREPARED_FIELDS - {"apiVersion", "attemptId", "sessionId", "issuedAtEpochNs", "expiresAtEpochNs"}:
        digest(value[name])
    before, after = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    require(type(before) is int and type(after) is int and 0 < before < after <= 9223372036854775807
        and after - before <= 300000000000)
    return value


def observation(text):
    value = enrollment.setup.document(text.encode("ascii"), MAX_OBSERVATION)
    require(set(value) == {"payload", "signature", "workloadSignature"})
    p = value["payload"]
    require(type(p) is dict and set(p) == OBSERVATION_FIELDS and p["apiVersion"] == OBSERVATION
        and p["purpose"] == "setup-ca-installation-readback" and p["trustMode"] == "trusted-host-local")
    for name in OBSERVATION_FIELDS - {"apiVersion", "purpose", "trustMode", "hostId", "bootId", "namespaceDevice",
            "namespaceInode", "destinationPath", "destinationIdentity", "observedBeforeEpochNs", "observedAfterEpochNs"}:
        digest(p[name])
    enrollment.setup.text(p["hostId"], 128); enrollment.setup.identifier(p["bootId"])
    path = p["destinationPath"]; require(type(path) is str and path.startswith("/") and len(path) <= 4096
        and all(part not in {"", ".", ".."} for part in path[1:].split("/")))
    for name in ("namespaceDevice", "namespaceInode", "observedBeforeEpochNs", "observedAfterEpochNs"):
        require(type(p[name]) is int and 0 < p[name] <= 18446744073709551615)
    identity = p["destinationIdentity"]
    require(type(identity) is dict and set(identity) == {"device", "inode", "mode", "uid", "gid", "size", "mtimeSeconds", "mtimeNanos", "ctimeSeconds", "ctimeNanos"})
    require(all(type(x) is int for x in identity.values()) and identity["device"] > 0 and identity["inode"] > 0
        and identity["mode"] == 420 and 0 <= identity["uid"] < 4294967295 and 0 <= identity["gid"] < 4294967295
        and 0 < identity["size"] <= 65536 and 0 <= identity["mtimeNanos"] < 1000000000 and 0 <= identity["ctimeNanos"] < 1000000000)
    signature = value["signature"]; require(type(signature) is str and signature.startswith("ed25519:"))
    require(len(enrollment.original(signature[8:], 64)) == 64)
    signature = value["workloadSignature"]; require(type(signature) is str and signature.startswith("ecdsa-p256-sha256:"))
    encoded = enrollment.original(signature[18:], 80)
    r, s = decode_dss_signature(encoded); require(encode_dss_signature(r, s) == encoded and r > 0 and s > 0)
    return value


def _public(pem):
    require(type(pem) is str and pem.isascii() and 1 <= len(pem) <= 16384)
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    require(isinstance(key, ed25519.Ed25519PublicKey) and key.public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo) == pem.encode("ascii"))
    return key


def key_id(key):
    return sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & OPERATIONS for role in payload["roles"].values())
    if value is None:
        require(not enabled); return None
    require(type(value) is dict and set(value) == {"schema", "installationRootPublicKeyPem", "hosts", "credentialPolicy"}
        and value["schema"] == SCHEMA)
    install_root = _public(value["installationRootPublicKeyPem"])
    issuance = payload.get(issuer_policy.FIELD)
    require(issuance is not None and issuance["credentialPolicy"] == value["credentialPolicy"])
    enrollment.hardware.policy(value["credentialPolicy"])
    forbidden = {key_id(install_root), key_id(_public(issuance["issuerRootPublicKeyPem"]))}
    require(len(forbidden) == 2)
    if root_key is not None:
        require(key_id(root_key) not in forbidden); forbidden.add(key_id(root_key))
    hosts = value["hosts"]; require(type(hosts) is list and 1 <= len(hosts) <= 64)
    previous = ""
    for host in hosts:
        require(type(host) is dict and set(host) == {"hostId", "machineIdSha256", "keyId", "publicKeyBase64url"})
        enrollment.setup.text(host["hostId"], 128); digest(host["machineIdSha256"]); digest(host["keyId"])
        key = ed25519.Ed25519PublicKey.from_public_bytes(enrollment.original(host["publicKeyBase64url"], 32))
        require(key_id(key) == host["keyId"] and previous < host["keyId"] and host["keyId"] not in forbidden)
        previous = host["keyId"]
    return value


def verify_original(operation, arguments_value, *, configuration_payload, root_key, now_epoch_ns):
    values = arguments(operation, arguments_value, typed="businessIntent" in arguments_value)
    policy = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    require(policy is not None and policy["credentialPolicy"] == values["credential_policy"])
    row = enrollment.setup.document(values["enrollment_original"].encode("ascii"), enrollment.MAX_ROW_BYTES)
    selected = enrollment.intent(row["intent_original"])
    # Reverify actual native issuer/CSR/leaf, never a protected-row success flag.
    admitted = issuer_policy.verify_issuer({"intent_original": row["intent_original"], "certificate_original": row["certificate_original"]},
        configuration_payload[issuer_policy.FIELD], now_epoch_ns=now_epoch_ns)
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
    work = _ValidationWork(QueryReadValidationLimits())
    window, deadline = installation.shared._construction_on_work(work)
    root = policy["installationRootPublicKeyPem"].encode("ascii")
    grant_raw = enrollment.original(values["installation_original"], installation.MAX_BYTES)
    grant = installation._verify_on_work(authorization_bytes=grant_raw, root_public_key_bytes=root,
        expected_root_pem_sha256=sha256(root), work=work, live_window=window, transport_deadline_ns=deadline)
    g = enrollment.setup.document(grant.payload_bytes, installation.MAX_BYTES)
    issuance = enrollment.setup.document(enrollment.original(selected["authorization"], 32768), 32768)["payload"]
    require(g["setupSha256"] == issuance["setupSha256"] and g["delegationSha256"] == issuance["delegationSha256"]
        and g["targetRequestSha256"] == issuance["requestSha256"] and g["runtimeCaCertificateSha256"] == issuance["runtimeCaCertificateSha256"]
        and g["runtimeCaSpkiSha256"] == issuance["runtimeCaSpkiSha256"])
    host = next((h for h in policy["hosts"] if h["keyId"] == values["host_key_id"]), None)
    require(host is not None and host["hostId"] == g["networkOwner"]["hostId"] and host["machineIdSha256"] == g["machineIdSha256"]
        and values["host_key_id"] not in {issuance["issuerSpkiSha256"], issuance["subjectPublicKeyInfoSha256"], issuance["authorizationKeySpkiDigest"], g["runtimeCaSpkiSha256"]})
    if operation == COMPLETE:
        observation_value = observation(values["observation_original"]); p = observation_value["payload"]
        for name, expected in {"enrollmentSha256": sha256(values["enrollment_original"].encode("ascii")),
                "certificateSha256": row["certificate_sha256"], "associationSha256": sha256(row["association_original"].encode("ascii")),
                "installationAuthorizationSha256": sha256(grant_raw), "nativeSetupSha256": g["setupSha256"],
                "targetRequestSha256": g["targetRequestSha256"], "runtimeCaCertificateSha256": g["runtimeCaCertificateSha256"],
                "hostId": host["hostId"], "machineIdSha256": host["machineIdSha256"], "bootId": g["networkOwner"]["bootId"],
                "namespaceDevice": g["networkOwner"]["namespaceDevice"], "namespaceInode": g["networkOwner"]["namespaceInode"],
                "destinationPath": g["caInstall"]["destinationPath"], "hostSigningKeyId": host["keyId"],
                "workloadSpkiSha256": admitted.subject_public_key_digest}.items():
            require(p[name] == expected)
        require(p["destinationIdentity"]["uid"] == g["caInstall"]["ownerUid"] and p["destinationIdentity"]["gid"] == g["caInstall"]["ownerGid"]
            and g["issuedAtEpochNs"] <= p["observedBeforeEpochNs"] <= p["observedAfterEpochNs"] <= now_epoch_ns
            and p["observedAfterEpochNs"] < min(g["expiresAtEpochNs"], selected["expiresAtEpochNs"]))
        raw = canonical(p)
        ed25519.Ed25519PublicKey.from_public_bytes(enrollment.original(host["publicKeyBase64url"], 32)).verify(
            enrollment.original(observation_value["signature"][8:], 64), DOMAIN + raw)
        require(isinstance(admitted.public_key, ec.EllipticCurvePublicKey) and isinstance(admitted.public_key.curve, ec.SECP256R1))
        admitted.public_key.verify(enrollment.original(observation_value["workloadSignature"][18:], 80), POSSESSION_DOMAIN + raw, ec.ECDSA(hashes.SHA256()))
    grant.live(); admitted.live()
    return g


def row_original(row):
    require(type(row) is dict and set(row) == ROW_FIELDS)
    p = prepared(row["prepared_original"])
    require(row["session_id"] == p["sessionId"] and row["prepared_sha256"] == sha256(row["prepared_original"].encode("ascii"))
        and row["enrollment_sha256"] == p["enrollmentSha256"] and row["host_key_id"] == p["hostKeyId"]
        and sha256(enrollment.original(row["installation_original"], installation.MAX_BYTES)) == p["installationAuthorizationSha256"]
        and type(row["revision"]) is int and row["revision"] in (0, 1)
        and row["phase"] == ("installation_unknown" if row["revision"] == 0 else "ca_readback_authenticated"))
    for name in ("prepare_request_digest", "configuration_digest"):
        digest(row[name])
    enrollment.setup.text(row["owner_id"], 1024); enrollment.setup.epoch(row["created_at"])
    if row["revision"] == 0:
        require(all(row[n] is None for n in ("observation_original", "observation_sha256", "complete_request_digest", "completed_at")))
    else:
        observation(row["observation_original"]); require(row["observation_sha256"] == sha256(row["observation_original"].encode("ascii")))
        digest(row["complete_request_digest"]); enrollment.setup.epoch(row["completed_at"])
    raw = canonical(row); require(len(raw) <= 131072); return raw


def request_digest(operation, values):
    from serverware import authority_contract as contract, authority_request_commitment as commitment
    values = arguments(operation, values, typed="businessIntent" in values)
    typed = {**values, "businessIntent": contract.synthesize_business_intent(operation, values)}
    return commitment.framed_digest("serverware.policyAuthorityV9Request/v1", canonical({"schema": "serverware.policyAuthorityV9Authorization/v1",
        "operation": operation, "handler": contract.operation_spec(operation)["handler"], "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": commitment._authorization_arguments(typed)}))
