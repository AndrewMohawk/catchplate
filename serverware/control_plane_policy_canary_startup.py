"""Cold public-policy originals and genuine TLS peer for native canary intake.

This owns no authority private key and does not impersonate a private authority
role. The independently admitted verifier/planner still admit the transaction.
"""
import os
import ssl
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import authority_contract as contract
from serverware import authority_policy_canary as profile
from serverware import authority_policy_canary_policy as policy
from serverware import authority_request_commitment as commitment
from serverware import oauth_application_owner as originals

CONFIG_ENVIRONMENT = "SERVERWARE_POLICY_CANARY_INTAKE_CONFIG_FD"
CONFIG_FIELDS = frozenset({"schema", "sourceRevision", "controlPlaneConfigurationDigest", "authorityRootFd", "authorityRootSha256",
    "authorityRootSpkiSha256", "authorityConfigurationFd", "authorityConfigurationSha256", "authorityConfigurationDigest"})
CONFIG_MAX = 16384
AUTHORITY_MAX = contract.MAX_REQUEST_BYTES
AUTHORITY_SCHEMA = "serverware.policyAuthorityServiceConfiguration/v6"
SIGNED_AUTHORITY_SCHEMA = "serverware.signedPolicyAuthorityServiceConfiguration/v6"
PREFIX = "/api/data-plane/policy-canary/controlled-evidence"
PATHS = frozenset({PREFIX, PREFIX + "/inspect"})
PEER_SCOPE = "serverware.policy_canary_intake_peer"
_PID, _LOCK = os.getpid(), threading.RLock()
_state, _owner, _environment_pin = "new", None, None


def _environment():
    return (os.environ.get("SERVERWARE_RELEASE_CHANNEL", "dev").strip().lower(),
        tuple(sorted((name, value) for name, value in os.environ.items() if name.startswith("SERVERWARE_POLICY_CANARY_INTAKE_"))))


def configuration(value):
    profile.require(type(value) is dict and set(value) == CONFIG_FIELDS and value["schema"] == profile.RECEIVER_SCHEMA
        and value["sourceRevision"] == contract.SOURCE_REVISION)
    for name in ("controlPlaneConfigurationDigest", "authorityRootSha256", "authorityRootSpkiSha256",
            "authorityConfigurationSha256", "authorityConfigurationDigest"):
        profile.digest(value[name])
    profile.require(originals._fd(value["authorityRootFd"]) != originals._fd(value["authorityConfigurationFd"]))
    return value


class _Cold:
    def check(self):
        from serverware import control_plane_custody_startup as startup
        from serverware import control_plane_custody_client as custody
        with _LOCK:
            try:
                profile.require(os.getpid() == _PID and _state == "started" and self is _owner and not self.poisoned
                    and _environment() == _environment_pin and startup.require_started() is self.custody
                    and custody._snapshot(self.custody) is self.binding
                    and self.binding.configuration_digest == self.configuration_digest)
                now, mono = custody._receipt_now(self.binding), time.monotonic_ns()
                profile.require(self.now <= now < self.expires and self.mono <= mono < self.deadline)
                for item in self.originals:
                    item.check()
                self.now, self.mono = now, mono
                return now
            except BaseException:
                self.poisoned = True
                raise


def initialize_from_environment():
    global _state, _owner, _environment_pin
    from serverware import control_plane_custody_startup as startup
    from serverware import control_plane_custody_client as custody
    with _LOCK:
        profile.require(os.getpid() == _PID and _state == "new")
        _environment_pin = _environment()
        # The separate cold selector is optional for older products. Its
        # absence disables only this new route; it grants no legacy fallback.
        if not _environment_pin[1]:
            _state = "disabled"
            return
        _state = "admitting"
        try:
            profile.require(set(dict(_environment_pin[1])) == {CONFIG_ENVIRONMENT})
            actual = startup.require_started(); binding = custody._snapshot(actual)
            fd_text = os.environ[CONFIG_ENVIRONMENT]
            profile.require(fd_text.isascii() and fd_text.isdecimal() and str(int(fd_text)) == fd_text)
            fd = originals._fd(int(fd_text))
            profile.require(fd in binding.inherited_descriptors)
            config_original = originals._Original(fd, CONFIG_MAX)
            config = configuration(profile.document(config_original.raw, CONFIG_MAX, exact=False))
            root_fd, payload_fd = config["authorityRootFd"], config["authorityConfigurationFd"]
            profile.require(len({fd, root_fd, payload_fd}) == 3 and {root_fd, payload_fd} <= set(binding.inherited_descriptors)
                and config["controlPlaneConfigurationDigest"] == binding.configuration_digest)
            root_original = originals._Original(root_fd, 4096)
            authority_original = originals._Original(payload_fd, AUTHORITY_MAX)
            profile.require(profile.sha256(root_original.raw) == config["authorityRootSha256"]
                and profile.sha256(authority_original.raw) == config["authorityConfigurationSha256"])
            root = serialization.load_pem_public_key(root_original.raw)
            profile.require(isinstance(root, Ed25519PublicKey) and root.public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo) == root_original.raw)
            root_spki = root.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            profile.require(profile.sha256(root_spki) == config["authorityRootSpkiSha256"]
                and root_spki != binding.runtime_root_public_key.public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo))
            # The exact container bytes are independently pinned above. The
            # authority signature covers the canonical payload, not JSON
            # indentation in its retained signed-envelope container.
            envelope = profile.document(authority_original.raw, AUTHORITY_MAX, exact=False)
            profile.require(type(envelope) is dict and set(envelope) == {"schema", "payload", "signature"}
                and envelope["schema"] == SIGNED_AUTHORITY_SCHEMA and type(envelope["payload"]) is dict)
            payload = envelope["payload"]; raw_payload = profile.canonical(payload)
            profile.require(payload.get("schema") == AUTHORITY_SCHEMA and payload.get("sourceRevision") == contract.SOURCE_REVISION
                and type(payload.get("roles")) is dict and {"verifier", "planner"} <= set(payload["roles"])
                and commitment.framed_digest(AUTHORITY_SCHEMA, raw_payload) == config["authorityConfigurationDigest"])
            root.verify(profile.decoded(envelope["signature"], 64, length=64),
                commitment.framed_digest(SIGNED_AUTHORITY_SCHEMA, raw_payload).encode("ascii"))
            selected_policy = policy.validate_policy(payload.get(policy.FIELD), payload=payload, root_key=root)
            profile.require(selected_policy is not None and selected_policy["controlPlaneConfigurationDigest"] == binding.configuration_digest)
            # enabledOperations belongs to the real planner role. Verifier
            # independently consumes the same signed purpose, not a new field.
            profile.require(profile.OP_INTAKE in payload["roles"]["planner"].get("enabledOperations", ()))
            now, mono = custody._receipt_now(binding), time.monotonic_ns()
            profile.require(selected_policy["issuedAtEpochNs"] <= now < selected_policy["expiresAtEpochNs"])
            owner = _Cold()
            owner.custody, owner.binding, owner.configuration_digest = actual, binding, binding.configuration_digest
            owner.originals, owner.payload, owner.root, owner.policy = (config_original, root_original, authority_original), payload, root, selected_policy
            owner.poisoned, owner.now, owner.mono = False, now, mono
            owner.expires = min(selected_policy["expiresAtEpochNs"], binding.attestation_interval[1])
            owner.deadline = mono + owner.expires - now
            _owner, _state = owner, "started"
            owner.check()
        except BaseException:
            _state = "poisoned"
            raise


def selected():
    with _LOCK:
        profile.require(os.getpid() == _PID)
        current = _environment()
        if _state == "new" and current[0] in originals._DEVELOPMENT and not current[1]:
            return False
        profile.require(current == _environment_pin)
        if _state == "disabled":
            return False
        profile.require(_state == "started")
        _owner.check()
        return True


def close():
    global _state
    with _LOCK:
        profile.require(os.getpid() == _PID)
        if _owner is not None:
            _owner.poisoned = True
        # Borrowed custody/read-only originals remain owned by the runner.
        _state = "closed"


def configure_tls(context):
    if not selected():
        return
    profile.require(isinstance(context, ssl.SSLContext), "native canary intake requires actual control-plane TLS")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cadata="".join(item["workloadCaCertificatePem"] for item in _owner.policy["assignments"]))
    context.verify_mode = ssl.CERT_OPTIONAL
    _owner.check()


class _Peer:
    def __init__(self, transport):
        self.transport, self.tls = transport, transport.get_extra_info("ssl_object")
        profile.require(self.tls is not None and self.tls.version() == "TLSv1.3")
        self.original = self.tls.getpeercert(binary_form=True)
        profile.require(type(self.original) is bytes and 0 < len(self.original) <= 16 * 1024)
        self.check()

    def check(self):
        profile.require(os.getpid() == _PID and not self.transport.is_closing()
            and self.transport.get_extra_info("ssl_object") is self.tls and self.tls.version() == "TLSv1.3"
            and self.tls.getpeercert(binary_form=True) == self.original)


def peer_from_transport(transport):
    if not selected():
        return None
    tls = transport.get_extra_info("ssl_object")
    return None if tls is None or not tls.getpeercert(binary_form=True) else _Peer(transport)


class RequestOwner:
    def __init__(self, request, batch_original, native_evidence, operation):
        from serverware.control_plane_approval_verification import _request_pin
        profile.require(selected() and request.method == "POST" and request.url.path in PATHS
            and not request.scope.get("query_string") and request.headers.get("content-type") == "application/json"
            and operation == (profile.OP_INTAKE if request.url.path == PREFIX else profile.OP_INSPECT))
        peer = request.scope.get(PEER_SCOPE)
        profile.require(type(peer) is _Peer)
        self.owner, self.peer, self.request, self.scope = _owner, peer, request, request.scope
        self.pin, self.pid, self.thread = _request_pin(request), os.getpid(), threading.get_ident()
        self.batch_original, self.evidence_original = batch_original, profile.canonical(native_evidence)
        self.native_evidence = native_evidence
        self.statement = native_evidence["statement"]
        self.operation, self.dispatched = operation, False
        now, self.started = self.owner.check(), time.monotonic_ns()
        peer.check()
        policy.verify_evidence(operation, batch_original, native_evidence, self.owner.configuration_digest,
            configuration_payload=self.owner.payload, root_key=self.owner.root, now_epoch_ns=now, peer_der=peer.original)
        self.expires = self.statement["expiresAtEpochNs"]
        self.deadline = min(self.owner.deadline, self.started + self.expires - now)
        self.check()

    def check(self):
        from serverware.control_plane_approval_verification import _request_pin
        profile.require((os.getpid(), threading.get_ident()) == (self.pid, self.thread) and self.request.scope is self.scope
            and _request_pin(self.request) == self.pin and self.request.scope.get(PEER_SCOPE) is self.peer
            and self.native_evidence["statement"] is self.statement and profile.canonical(self.native_evidence) == self.evidence_original)
        now = self.owner.check(); self.peer.check()
        profile.require(self.started <= time.monotonic_ns() < self.deadline
            and self.statement["issuedAtEpochNs"] <= now < self.expires)
        return now
