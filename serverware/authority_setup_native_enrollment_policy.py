"""Both independent controlled roles reverify original native issuer authority."""
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_setup_native_enrollment as p
from serverware import native_workload_identity_issuance_authorization as issuer
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

FIELD = "setupNativeEnrollmentPolicy"
SCHEMA = "serverware.setupNativeEnrollmentAuthorityPolicy/v1"
FIELDS = frozenset({"schema", "issuerRootPublicKeyPem", "issuerBootstrapSha256", "credentialPolicy"})


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & p.OPERATIONS for role in payload["roles"].values())
    if value is None:
        p.require(not enabled, "native Setup enrollment needs independent cold purpose admission")
        return None
    p.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    original = value["issuerRootPublicKeyPem"]
    p.require(type(original) is str and original.isascii() and 1 <= len(original) <= 16384)
    key = serialization.load_pem_public_key(original.encode("ascii"))
    p.require(isinstance(key, Ed25519PublicKey) and key.public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo) == original.encode("ascii"))
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if root_key is not None:
        p.require(der != root_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    p.digest(value["issuerBootstrapSha256"]); p.hardware.policy(value["credentialPolicy"])
    return value


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    values = p.arguments(operation, arguments, typed="businessIntent" in arguments)
    policy = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    from serverware import authority_policy_canary_policy as configuration
    p.require(policy is not None and values["credential_policy"] == policy["credentialPolicy"]
        and values["control_plane_configuration_digest"] == configuration.full_configuration_digest(configuration_payload))
    return verify_issuer(values, policy, now_epoch_ns=now_epoch_ns)


def verify_issuer(values, policy, *, now_epoch_ns):
    """Fixed pure-public signature verification, no signer/transport/receipt DTO."""
    selected = p.intent(values["intent_original"])
    p.require(selected["issuedAtEpochNs"] <= now_epoch_ns < selected["expiresAtEpochNs"])
    bootstrap = p.original(selected["issuerBootstrap"], 131072)
    p.require(p.sha256(bootstrap) == policy["issuerBootstrapSha256"])
    work = _ValidationWork(QueryReadValidationLimits())
    window, deadline = issuer.bootstrap._construction_on_work(work)
    # This validation interval is bounded by the ORIGINAL intent, never creates
    # a replacement issuer window or grants permission after expiration.
    def current():
        now = issuer.bootstrap.clock._check_on_work(window, work=work)
        p.require(time.monotonic_ns() < deadline and selected["issuedAtEpochNs"] <= now < selected["expiresAtEpochNs"])
        return now
    kwargs = dict(authorization_bytes=p.original(selected["authorization"], 32768),
        packet_bytes=p.original(selected["packet"], 524288), request_bytes=p.original(selected["request"], 65536),
        bootstrap_bytes=bootstrap, root_public_key=serialization.load_pem_public_key(policy["issuerRootPublicKeyPem"].encode("ascii")),
        work=work, live_window=window, transport_deadline_ns=deadline, _current=current)
    current()
    certificate = values["certificate_original"]
    admitted = (issuer._verify_on_work(**kwargs) if certificate is None else
        issuer._verify_certificate_on_work(certificate_bytes=p.original(certificate, 65536), **kwargs))
    # The original signed native grant binds policy/principal/CSR and the exact
    # issuer certificate. The grant's trust mode remains trusted-host-local.
    # Extract only AFTER the full original verifier has admitted the signature.
    import json
    envelope = json.loads(kwargs["authorization_bytes"])
    payload = envelope["payload"]
    p.require(admitted.principal_id == selected["principalId"] and payload["policyHash"] == selected["policyHash"]
        and payload["issuedAtEpochNs"] <= selected["issuedAtEpochNs"] < selected["expiresAtEpochNs"] <= payload["expiresAtEpochNs"])
    current(); admitted.live()
    return admitted
