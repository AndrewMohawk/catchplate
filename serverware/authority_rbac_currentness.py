"""Closed RBAC head material; hashes are data, never currentness authority."""
import hashlib
import json
import re
import base64

STATE_SCHEMA = "serverware.rbacAuthenticatedState/v1"
HEAD_SCHEMA = "serverware.rbacWitnessHead/v1"
ROOT_FIELDS = frozenset({"table", "rootRevision", "rootDigest", "leafCount"})
STATE_FIELDS = frozenset({"schema", "generation", "rootRevision", "rootDigest", "leafCount", "manifestDigest"})
MAX_BYTES = 1024 * 1024
ENROLLMENT_SCHEMA = "serverware.rbacWitnessEnrollment/v1"
SIGNED_ENROLLMENT_SCHEMA = "serverware.signedRbacWitnessEnrollment/v1"
STARTUP_SCHEMA = "serverware.rbacWitnessStartup/v1"
ENROLLMENT_V2_SCHEMA = "serverware.rbacWitnessEnrollment/v2"
SIGNED_ENROLLMENT_V2_SCHEMA = "serverware.signedRbacWitnessEnrollment/v2"
STARTUP_V2_SCHEMA = "serverware.rbacWitnessStartup/v2"
LOCAL_ENROLLMENT_SCHEMA = "serverware.trustedHostLocalRbacWitnessEnrollment/v1"
LOCAL_SIGNED_ENROLLMENT_SCHEMA = "serverware.signedTrustedHostLocalRbacWitnessEnrollment/v1"
LOCAL_STARTUP_SCHEMA = "serverware.trustedHostLocalRbacWitnessStartup/v1"
LOCAL_ASSURANCE = {
    "schema": "serverware.trustedHostLocalRbacWitnessAssurance/v1",
    "trustMode": "trusted-host-local", "coLocated": True,
    "hardwareBacked": False, "independentlyAdministered": False,
    "jointRollbackResistant": False, "faultDomainScope": "separate-local-cluster-storage",
}
INTENT_SCHEMA = "serverware.rbacWitnessIntent/v1"
COMPLETION_SCHEMA = "serverware.rbacWitnessCompletion/v1"
TABLES = ("rbac_authority_state", "rbac_role_bindings")


def require(condition, message="RBAC witness original is outside its fixed profile"):
    if not condition: raise ValueError(message)


def integer(value, maximum=2**63-1):
    require(type(value) is int and 0 <= value <= maximum)
    return value


def digest(value):
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None)
    return value


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("ascii")


def sha256(raw):
    require(type(raw) is bytes)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def document(raw, maximum=MAX_BYTES):
    require(type(raw) is bytes and 0 < len(raw) <= maximum)
    def pairs(items):
        value = {}
        for name, item in items:
            require(name not in value); value[name] = item
        return value
    def refuse(_): raise ValueError("RBAC original has a non-integer number")
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=refuse, parse_constant=refuse)
    require(canonical(value) == raw)
    return value


def require_local_development():
    """Additional refusal, never an environment-only authorization path."""
    import os
    from serverware import config
    development = {"dev", "development", "local", "test"}
    require(not config.PRODUCTION_IMAGE
        and os.environ.get("SERVERWARE_PRODUCTION_IMAGE", "0") != "1"
        and config.RELEASE_CHANNEL.strip().lower() in development
        and os.environ.get("SERVERWARE_RELEASE_CHANNEL", "dev").strip().lower() in development,
        "co-located RBAC witness profile is forbidden in production")


def state_material(generation, root, manifest_digest):
    require(type(root) is dict and set(root) == ROOT_FIELDS and root["table"] == "rbac_role_bindings")
    return {"schema": STATE_SCHEMA, "generation": integer(generation),
        "rootRevision": integer(root["rootRevision"]), "rootDigest": digest(root["rootDigest"]),
        "leafCount": integer(root["leafCount"]), "manifestDigest": digest(manifest_digest)}


def state_digest(material):
    require(type(material) is dict and set(material) == STATE_FIELDS and material["schema"] == STATE_SCHEMA)
    return sha256(canonical(material))


def state(value):
    require(type(value) is dict and set(value) == {"generation", "stateDigest", "roots"})
    integer(value["generation"]); digest(value["stateDigest"])
    roots = value["roots"]
    require(type(roots) is list and len(roots) == 2 and all(type(item) is dict for item in roots)
        and [item.get("table") for item in roots] == list(TABLES))
    for root in roots:
        require(type(root) is dict and set(root) == ROOT_FIELDS)
        integer(root["rootRevision"]); integer(root["leafCount"]); digest(root["rootDigest"])
    from serverware import authority_primary_contract as primary
    require(value["stateDigest"] == state_digest(state_material(value["generation"], roots[1], primary.source_query_manifest_digest())),
        "RBAC state is not the actual binding-root recipe for this admitted source")
    return value


def head(value):
    require(type(value) is dict and set(value) == {"schema", "enrollmentSha256", "sequence", "previousHeadSha256", "state"}
        and value["schema"] == HEAD_SCHEMA)
    digest(value["enrollmentSha256"]); integer(value["sequence"])
    if value["previousHeadSha256"] is not None: digest(value["previousHeadSha256"])
    require((value["sequence"] == 0) == (value["previousHeadSha256"] is None))
    state(value["state"])
    return value


def enrollment(raw, root):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    require(isinstance(root, Ed25519PublicKey))
    value = document(raw, 65536)
    require(type(value) is dict and set(value) == {"schema", "payload", "signatureBase64Url"}
        and value["schema"] in {SIGNED_ENROLLMENT_SCHEMA, SIGNED_ENROLLMENT_V2_SCHEMA, LOCAL_SIGNED_ENROLLMENT_SCHEMA})
    payload = value["payload"]
    fields = {"schema", "sourceRevision", "enrollmentId", "databaseId", "deploymentId", "configurationDigests",
        "metadataClusterId", "witnessClusterId", "metadataFaultDomain", "witnessFaultDomain", "reader", "writer",
        "initialState", "issuedAtEpochNs", "expiresAtEpochNs", "maximumRecords", "endpoint", "tlsRootSha256", "metadataDatabase"}
    second = value["schema"] == SIGNED_ENROLLMENT_V2_SCHEMA
    local = value["schema"] == LOCAL_SIGNED_ENROLLMENT_SCHEMA
    require(type(payload) is dict and set(payload) == fields | (
        {"recoveryPublicKeyBase64Url"} if second else {"assurance"} if local else set())
        and payload["schema"] == (ENROLLMENT_V2_SCHEMA if second else LOCAL_ENROLLMENT_SCHEMA if local else ENROLLMENT_SCHEMA))
    if local:
        require(type(payload["assurance"]) is dict and canonical(payload["assurance"]) == canonical(LOCAL_ASSURANCE),
            "local RBAC assurance cannot claim independent administration or joint rollback resistance")
    if second:
        raw_key = payload["recoveryPublicKeyBase64Url"]
        require(type(raw_key) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", raw_key) is not None)
        key_bytes = base64.urlsafe_b64decode(raw_key + "=")
        require(base64.urlsafe_b64encode(key_bytes).rstrip(b"=").decode("ascii") == raw_key)
        from cryptography.hazmat.primitives import serialization
        require(key_bytes != root.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            "RBAC recovery permission requires a separate independently enrolled signing key")
        Ed25519PublicKey.from_public_bytes(key_bytes)
    for name in ("sourceRevision", "enrollmentId", "databaseId", "deploymentId", "metadataFaultDomain", "witnessFaultDomain"):
        require(type(payload[name]) is str and 0 < len(payload[name]) <= 256 and payload[name].isascii()
            and not any(ord(char) <= 32 or ord(char) >= 127 for char in payload[name]))
    for name in ("metadataClusterId", "witnessClusterId"):
        value_id = payload[name]
        require(type(value_id) is str and value_id.isascii() and value_id.isdecimal()
            and str(int(value_id)) == value_id and 0 < int(value_id) < 2**64)
    require(payload["metadataClusterId"] != payload["witnessClusterId"] and payload["metadataFaultDomain"] != payload["witnessFaultDomain"])
    require(type(payload["metadataDatabase"]) is str
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", payload["metadataDatabase"]) is not None)
    require(payload["databaseId"] == sha256(b"serverware/rbac-metadata-identity/v1\0" + canonical({
        "clusterId": payload["metadataClusterId"], "database": payload["metadataDatabase"]})),
        "RBAC stable database identity cannot be retargeted by a deployment/enrollment name")
    import ipaddress
    endpoint = payload["endpoint"]
    require(type(endpoint) is dict and set(endpoint) == {"host", "address", "port", "database"})
    for name in ("host", "database"):
        require(type(endpoint[name]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", endpoint[name]) is not None)
    require(str(ipaddress.ip_address(endpoint["address"])) == endpoint["address"])
    require(type(endpoint["port"]) is int and 1 <= endpoint["port"] <= 65535)
    digest(payload["tlsRootSha256"])
    for name, role in (("reader", "serverware_rbac_witness_reader"), ("writer", "serverware_rbac_witness_writer")):
        entry = payload[name]
        require(type(entry) is dict and set(entry) == {"role", "clientDn", "clientSerial", "issuerDn", "certificateSha256"} and entry["role"] == role)
        digest(entry["certificateSha256"])
        for field in ("clientDn", "clientSerial", "issuerDn"):
            require(type(entry[field]) is str and 0 < len(entry[field]) <= 1024 and "\0" not in entry[field])
    configs = payload["configurationDigests"]
    require(type(configs) is list and 1 <= len(configs) <= 8 and configs == sorted(set(configs)))
    for item in configs: digest(item)
    state(payload["initialState"])
    integer(payload["issuedAtEpochNs"]); integer(payload["expiresAtEpochNs"])
    require(0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= 86_400_000_000_000)
    require(type(payload["maximumRecords"]) is int and 2 <= payload["maximumRecords"] <= 4096)
    signature_text = value["signatureBase64Url"]
    require(type(signature_text) is str and re.fullmatch(r"[A-Za-z0-9_-]{86}", signature_text) is not None)
    signature = base64.urlsafe_b64decode(signature_text + "==")
    require(base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii") == signature_text)
    root.verify(signature, payload["schema"].encode("ascii") + b"\0" + canonical(payload))
    return payload


def sign_enrollment(payload, key):
    """Offline enrollment root only; no runtime owns this signing key.

    Local enrollment has its own signature domain and makes no independent
    administration claim. Its runtime still requires genuine local admission.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    require(isinstance(key, Ed25519PrivateKey))
    require(type(payload) is dict and payload.get("schema") in {ENROLLMENT_SCHEMA, ENROLLMENT_V2_SCHEMA, LOCAL_ENROLLMENT_SCHEMA})
    signature = key.sign(payload["schema"].encode("ascii") + b"\0" + canonical(payload))
    original = canonical({"schema": SIGNED_ENROLLMENT_V2_SCHEMA if payload["schema"] == ENROLLMENT_V2_SCHEMA else
        LOCAL_SIGNED_ENROLLMENT_SCHEMA if payload["schema"] == LOCAL_ENROLLMENT_SCHEMA else SIGNED_ENROLLMENT_SCHEMA, "payload": payload,
        "signatureBase64Url": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")})
    enrollment(original, key.public_key())
    return original


def initial_head(enrollment_sha256, policy):
    return head({"schema": HEAD_SCHEMA, "enrollmentSha256": digest(enrollment_sha256), "sequence": 0,
        "previousHeadSha256": None, "state": state(policy["initialState"])})


def after_head(before, after_state):
    before = head(before); after_state = state(after_state)
    require(after_state["generation"] == before["state"]["generation"] + 1)
    return head({"schema": HEAD_SCHEMA, "enrollmentSha256": before["enrollmentSha256"],
        "sequence": integer(before["sequence"] + 1), "previousHeadSha256": sha256(canonical(before)), "state": after_state})


def binding_after(context, mutation):
    """Recompute from actual primary originals; no population truncation.

    The planner installs these source-owned inputs only after its normal
    membership admission. The existing engine repeats proof/CAS checks here.
    This additional bounded pass calculates a descriptor, not authority.
    """
    from serverware import authority_root_transition as roots
    from serverware import authority_primary_contract as primary
    require(context.operation == "rbac.binding.mutate" and context.rbac_primary_inputs is not None)
    business, authorization, proofs = context.rbac_primary_inputs
    transition = roots.derive_primary_root_transition(operation=context.operation,
        business_before_roots=business, authorization_before_roots=authorization,
        selected_rows=context.selected_rows, before_proofs=proofs, mutations=(mutation,))
    actual = [entry for entry in transition["businessAfterRoots"] if entry["table"] == "rbac_role_bindings"]
    require(len(actual) == 1)
    return actual[0], primary.source_query_manifest_digest()
