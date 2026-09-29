"""Independent signed permission for a new, never-executed workload namespace.

These original-only APIs authenticate the grant, not setup/session/host facts.
The native owner must independently re-admit the exact parent originals, actual
same-session proof, dedicated protected token, host and launcher before effects.
Fresh proof/packet and new namespace identities belong to the irreversible
operation association, not an unknowable pre-contact signed commitment. This
profile permits no workload start, attachment, recovery or persistent teardown.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from serverware import native_enrollment_assignment as assignment
from serverware import native_enrollment_bootstrap_setup as setup
from serverware import workload_identity_issuer_bootstrap as shared
from serverware_agent_trust import _workload_signed_packet as packets
from serverware_agent_trust import workload_identity_bootstrap_originals as bootstrap


SCHEMA = "serverware.signedNativeEgressInstallationAuthorization/v1"
PAYLOAD_SCHEMA = "serverware.nativeEgressInstallationAuthorization/v1"
CREATION_SCHEMA = "serverware.signedNativeEgressInstallationAuthorization/v2"
CREATION_PAYLOAD_SCHEMA = "serverware.nativeEgressInstallationAuthorization/v2"
PURPOSE = "native-egress-installation"
WORKLOAD_PROFILE = "native-egress-create-new-workload-v1"
RULESET_PROFILE = "nft-inet-output-tcp-create-v1"
MAX_BYTES = 32 * 1024
MAX_KEY_BYTES = 16 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 6
MAX_LIFETIME_NS = 300_000_000_000
_FIELDS = frozenset({
    "schema", "sourceRevision", "purpose", "trustMode", "authorizationId",
    "setupSha256", "delegationSha256", "targetRequestSha256", "policyRequirementsSha256",
    "releaseRecordSha256", "policyHash", "configurationSha256",
    "runtimeCaCertificateSha256", "runtimeCaSpkiSha256", "ingressLeafCertificateSha256",
    "clientTrustBundleSha256", "clientChallengeSha256", "targetPrincipalId", "targetNonce",
    "targetSpkiSha256", "proxy", "networkOwner", "machineIdSha256", "workload",
    "ruleset", "capability", "journal", "issuedAtEpochNs", "expiresAtEpochNs",
})
_CREATION_FIELDS = _FIELDS | {"creationJournal"}
_DIGEST_FIELDS = (
    "setupSha256", "delegationSha256", "targetRequestSha256", "policyRequirementsSha256",
    "releaseRecordSha256", "policyHash", "configurationSha256",
    "runtimeCaCertificateSha256", "runtimeCaSpkiSha256", "ingressLeafCertificateSha256",
    "clientTrustBundleSha256", "clientChallengeSha256", "targetSpkiSha256", "machineIdSha256",
)
_TABLE = re.compile(r"swnegr_[0-9a-f]{32}\Z")
_CAPABILITY = re.compile(r"[A-Za-z0-9_-]{24,128}\Z")


class NativeEgressInstallationAuthorizationError(ValueError):
    pass


def _fail():
    raise NativeEgressInstallationAuthorizationError("native egress installation authorization is invalid")


@dataclass(frozen=True, slots=True, repr=False)
class _EgressAuthorizationMaterial:
    authorization_bytes: bytes
    authorization_digest: str
    payload_bytes: bytes
    root_pem_digest: str
    root_spki_digest: str
    authorization_id: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple
    deadline_ns: int
    live: object


def _preflight(originals, work, additional, *, producing=False):
    shared.clock.evidence.capture._SharedLedger(work)
    shared._integer(additional, MAX_ORIGINAL_BYTES)
    total = MAX_BYTES if producing else 0
    for original, maximum in originals:
        shared._raw(original, maximum)
        total += len(original)
    if additional + 16 * total + 128 * 1024 > min(
            MAX_ORIGINAL_BYTES, work.limits.max_input_bytes - work.metrics.input_bytes):
        _fail()


def _structure(original, budget):
    """Depth bound before the shared duplicate-refusing canonical JSON parser."""
    shared._raw(original, MAX_BYTES)
    budget.charge(input_bytes=len(original))
    stack = []
    quoted = escaped = False
    for index, byte in enumerate(original):
        if index % 1024 == 0:
            budget.check()
        if not 32 <= byte <= 126:
            _fail()
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (123, 91):
            stack.append(byte)
            if len(stack) > MAX_JSON_DEPTH:
                _fail()
        elif byte in (125, 93):
            if not stack or stack.pop() != (123 if byte == 125 else 91):
                _fail()
    if quoted or escaped or stack:
        _fail()
    budget.check()


def _journal(value):
    shared._object(value, {"path", "device", "inode", "namespace"})
    path = assignment._ascii(value["path"], 4096)
    parts = path[1:].split("/")
    if (not path.startswith("/") or path == "/" or "\\" in path or len(parts) > 64
            or any(part in ("", ".", "..") or len(part) > 255 for part in parts)):
        _fail()
    shared._integer(value["device"], minimum=1)
    shared._integer(value["inode"], minimum=1)
    shared._identifier(value["namespace"])


def _proxy_rules(value, budget):
    # Pure signed-shape checks. Exact equality with genuinely verified setup,
    # delegated endpoint/host and actual held proxy peer is the native owner's job.
    shared._object(value, {"origin", "endpoint", "egressCidrs", "hostAddresses"})
    origin_host, origin_port = setup._origin(value["origin"])
    assignment._endpoint(value["endpoint"])
    endpoint_host, port_text = value["endpoint"].rsplit(":", 1)
    if endpoint_host.startswith("["):
        endpoint_host = endpoint_host[1:-1]
    endpoint = setup._unicast(endpoint_host)
    port = int(port_text)
    if port != origin_port:
        _fail()
    setup._ordered_strings(value["egressCidrs"], 32)
    networks = []
    for original in value["egressCidrs"]:
        budget.check()
        assignment._ascii(original, 80)
        network = ipaddress.ip_network(original, strict=True)
        if (network.prefixlen == 0 or original != assignment._ip_spelling(network.network_address)
                + "/" + str(network.prefixlen)):
            _fail()
        networks.append(network)
    setup._ordered_strings(value["hostAddresses"], 16)
    addresses = [setup._unicast(original) for original in value["hostAddresses"]]
    if endpoint not in addresses or any(not any(address in network for network in networks)
            for address in addresses):
        _fail()
    try:
        origin_ip = ipaddress.ip_address(origin_host)
    except ValueError:
        origin_ip = None
    if origin_ip is not None and (addresses != [endpoint] or origin_ip != endpoint):
        _fail()
    # Mapped addresses produce IPv4 packets. Keep the original signed proxy
    # spelling above, but emit one rule per effective address, without CIDR expansion.
    effective = set()
    for address in addresses:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        effective.add(address)
    budget.check()
    return [{"family": "ipv4" if address.version == 4 else "ipv6",
        "address": str(address), "tcpDestinationPort": port, "verdict": "accept"}
        for address in sorted(effective, key=lambda address: (address.version, address.packed))]


def _payload(value, budget):
    if type(value) is not dict:
        _fail()
    creation = value.get("schema") == CREATION_PAYLOAD_SCHEMA
    shared._object(value, _CREATION_FIELDS if creation else _FIELDS)
    if (value["schema"] not in (PAYLOAD_SCHEMA, CREATION_PAYLOAD_SCHEMA)
            or value["sourceRevision"] != shared.authority.SOURCE_REVISION
            or value["purpose"] != PURPOSE or value["trustMode"] != "trusted-host-local"):
        _fail()
    shared._identifier(value["authorizationId"])
    for name in _DIGEST_FIELDS:
        assignment._digest(value[name])
    bootstrap._expectations(value["targetPrincipalId"], value["targetNonce"])
    setup._network_owner(value["networkOwner"])
    if value["networkOwner"]["ownerUid"] != 0:
        _fail()
    workload = shared._object(value["workload"], {"profile", "launchManifestSha256",
        "launcherBinarySha256", "namespaceMode", "beforeCompletion", "failureMode"})
    if (workload["profile"] != WORKLOAD_PROFILE or workload["namespaceMode"] != "create-new"
            or workload["beforeCompletion"] != "never-executed"
            or workload["failureMode"] != "terminate-before-start"):
        _fail()
    assignment._digest(workload["launchManifestSha256"])
    assignment._digest(workload["launcherBinarySha256"])
    expected_rules = _proxy_rules(value["proxy"], budget)
    ruleset = shared._object(value["ruleset"], {"profile", "tableName", "family", "chainName",
        "chainType", "hook", "priority", "policy", "rules"})
    if (ruleset["profile"] != RULESET_PROFILE or type(ruleset["tableName"]) is not str
            or _TABLE.fullmatch(ruleset["tableName"]) is None or ruleset["family"] != "inet"
            or ruleset["chainName"] != "output" or ruleset["chainType"] != "filter"
            or ruleset["hook"] != "output" or type(ruleset["priority"]) is not int
            or ruleset["priority"] != -10 or ruleset["policy"] != "drop"):
        _fail()
    rules = ruleset["rules"]
    if type(rules) is not list or not 1 <= len(rules) <= 16:
        _fail()
    for rule in rules:
        shared._object(rule, {"family", "address", "tcpDestinationPort", "verdict"})
        shared._integer(rule["tcpDestinationPort"], 65535, 1)
    if rules != expected_rules:
        _fail()
    capability = shared._object(value["capability"],
        {"capabilityId", "capabilityTokenSha256", "expiresAtEpochMs"})
    if type(capability["capabilityId"]) is not str or _CAPABILITY.fullmatch(capability["capabilityId"]) is None:
        _fail()
    assignment._digest(capability["capabilityTokenSha256"])
    expiry_ms = shared._integer(capability["expiresAtEpochMs"], bootstrap.MAX_EPOCH_MS, 1)
    _journal(value["journal"])
    if creation:
        _journal(value["creationJournal"])
        kernel = value["journal"]
        launch = value["creationJournal"]
        if (launch["path"] == kernel["path"]
                or (launch["device"], launch["inode"]) == (kernel["device"], kernel["inode"])
                or launch["namespace"] == kernel["namespace"]):
            _fail()
    issued = shared._integer(value["issuedAtEpochNs"], minimum=1)
    expires = shared._integer(value["expiresAtEpochNs"], minimum=issued + 1)
    if expires - issued > MAX_LIFETIME_NS or expires > expiry_ms * 1_000_000:
        _fail()
    budget.interval(issued, expires)


def _admit(original, public, root_pin, budget):
    _structure(original, budget)
    outer = shared._decode(original, MAX_BYTES, budget)
    shared._object(outer, {"schema", "payload", "signature"})
    if outer["schema"] == SCHEMA:
        schema, payload_schema = SCHEMA, PAYLOAD_SCHEMA
    elif outer["schema"] == CREATION_SCHEMA:
        schema, payload_schema = CREATION_SCHEMA, CREATION_PAYLOAD_SCHEMA
    else:
        _fail()
    payload = shared._signed(original, schema, payload_schema, public, MAX_BYTES, budget)
    _payload(payload, budget)
    result = _EgressAuthorizationMaterial(
        authorization_bytes=original, authorization_digest=packets._digest(original, budget),
        payload_bytes=packets._canonical(payload, MAX_BYTES, budget), root_pem_digest=root_pin,
        root_spki_digest=packets._digest(shared._spki(public, budget), budget),
        authorization_id=payload["authorizationId"], issued_at_epoch_ns=payload["issuedAtEpochNs"],
        expires_at_epoch_ns=payload["expiresAtEpochNs"], window=budget.window,
        deadline_ns=budget.bound, live=budget.current)
    result.live()
    return result


def _verify_on_work(*, authorization_bytes, root_public_key_bytes, expected_root_pem_sha256,
        work, live_window, transport_deadline_ns, _current=None, _additional_original_bytes=0):
    """Authenticate a grant original; never accept an installation/proof verdict."""
    try:
        _preflight(((authorization_bytes, MAX_BYTES), (root_public_key_bytes, MAX_KEY_BYTES)),
            work, _additional_original_bytes)
        budget = shared._Budget(work, live_window, transport_deadline_ns, _current)
        public = assignment._public_key(root_public_key_bytes, expected_root_pem_sha256, budget)
        return _admit(authorization_bytes, public, expected_root_pem_sha256, budget)
    except NativeEgressInstallationAuthorizationError:
        raise
    except Exception:
        raise NativeEgressInstallationAuthorizationError("native egress installation authorization verification failed") from None


def _produce_on_work(*, payload_bytes, root_private_key_bytes, root_public_key_bytes,
        expected_root_pem_sha256, work, live_window, transport_deadline_ns,
        _current=None, _additional_original_bytes=0):
    """Explicit protected canonical PKCS8 original; no files, keygen or network."""
    try:
        _preflight(((payload_bytes, MAX_BYTES), (root_private_key_bytes, MAX_KEY_BYTES),
            (root_public_key_bytes, MAX_KEY_BYTES)), work, _additional_original_bytes, producing=True)
        budget = shared._Budget(work, live_window, transport_deadline_ns, _current)
        public = assignment._public_key(root_public_key_bytes, expected_root_pem_sha256, budget)
        _structure(payload_bytes, budget)
        payload = shared._decode(payload_bytes, MAX_BYTES, budget)
        _payload(payload, budget)
        budget.charge(input_bytes=len(root_private_key_bytes))
        private = serialization.load_pem_private_key(root_private_key_bytes, password=None)
        budget.check()
        if (not isinstance(private, ed25519.Ed25519PrivateKey)
                or private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()) != root_private_key_bytes
                or shared._spki(private.public_key(), budget) != shared._spki(public, budget)):
            _fail()
        schema, payload_schema = ((CREATION_SCHEMA, CREATION_PAYLOAD_SCHEMA)
            if payload["schema"] == CREATION_PAYLOAD_SCHEMA else (SCHEMA, PAYLOAD_SCHEMA))
        original = shared._produce(payload_bytes, schema, payload_schema,
            private, public, MAX_BYTES, budget)
        admitted = _admit(original, public, expected_root_pem_sha256, budget)
        admitted.live()
        budget.check()
        return original
    except NativeEgressInstallationAuthorizationError:
        raise
    except Exception:
        raise NativeEgressInstallationAuthorizationError("native egress installation authorization production failed") from None
