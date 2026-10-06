"""One cold, sealed postboot selection. No reload, replacement or authority DTO."""
import os
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_contract as contract
from serverware import authority_credential_currentness as profile
from serverware import authority_credential_currentness_assignment as assignment
from serverware import authority_credential_currentness_policy as native
from serverware import authority_oauth_setup as codec
from serverware import authority_policy_canary_policy as configuration_digest
from serverware import authority_request_commitment as commitment
from serverware import oauth_application_owner as originals

ENV = "SERVERWARE_CURRENTNESS_ASSIGNMENT_CONFIG_FD"
CONFIG_SCHEMA = "serverware.currentnessAssignmentConfiguration/v1"
CONFIG_FIELDS = frozenset({"schema", "sourceRevision", "controlPlaneConfigurationDigest",
    "authorityRootFd", "authorityRootSha256", "authorityRootSpkiSha256",
    "authorityConfigurationFd", "authorityConfigurationSha256", "authorityConfigurationDigest",
    "assignmentFd", "assignmentSha256"})
SIGNED = "serverware.signedPolicyAuthorityServiceConfiguration/v6"
_PID, _LOCK = os.getpid(), threading.RLock()
_state, _cold, _namespace = "new", None, None


def _environment():
    return tuple(sorted((key, value) for key, value in os.environ.items()
        if key.startswith("SERVERWARE_CURRENTNESS_ASSIGNMENT_")))


class _Cold:
    def check(self):
        from serverware import control_plane_custody_startup as startup
        from serverware import control_plane_custody_client as custody
        with _LOCK:
            try:
                profile.require(os.getpid() == _PID and _state == "started" and self is _cold
                    and not self.poisoned and _environment() == _namespace
                    and startup.require_started() is self.custody and custody._snapshot(self.custody) is self.binding
                    and profile.canonical(self.configuration_payload) == self.configuration_original
                    and profile.canonical(self.payload) == self.payload_original
                    and self.policy is self.configuration_payload[native.FIELD]
                    and self.assignment_original.encode("ascii") == self.originals[-1].raw)
                for original in self.originals:
                    original.check()
                now, mono = custody._receipt_now(self.binding), time.monotonic_ns()
                profile.require(self.now <= now < self.expires and self.mono <= mono < self.deadline)
                self.now, self.mono = now, mono
                return now
            except BaseException:
                self.poisoned = True
                raise


def initialize_from_environment():
    global _state, _cold, _namespace
    from serverware import control_plane_custody_startup as startup
    from serverware import control_plane_custody_client as custody
    with _LOCK:
        profile.require(os.getpid() == _PID and _state == "new")
        _namespace = _environment()
        if not _namespace:
            _state = "disabled"
            return
        _state = "admitting"
        try:
            profile.require(set(dict(_namespace)) == {ENV})
            actual = startup.require_started(); binding = custody._snapshot(actual)
            text = os.environ[ENV]
            profile.require(text.isascii() and text.isdecimal() and str(int(text)) == text)
            descriptor = originals._fd(int(text))
            profile.require(descriptor in binding.inherited_descriptors)
            selector = originals._Original(descriptor, 16384)
            config = codec.document(selector.raw, 16384)
            profile.require(type(config) is dict and set(config) == CONFIG_FIELDS
                and config["schema"] == CONFIG_SCHEMA and config["sourceRevision"] == contract.SOURCE_REVISION
                and config["controlPlaneConfigurationDigest"] == binding.configuration_digest)
            fd_fields = {"authorityRootFd", "authorityConfigurationFd", "assignmentFd"}
            for name in CONFIG_FIELDS - fd_fields - {"schema", "sourceRevision"}:
                profile.digest(config[name])
            root_fd, payload_fd, assignment_fd = (originals._fd(config[name]) for name in
                ("authorityRootFd", "authorityConfigurationFd", "assignmentFd"))
            profile.require(len({descriptor, root_fd, payload_fd, assignment_fd}) == 4
                and {root_fd, payload_fd, assignment_fd} <= set(binding.inherited_descriptors))
            root_original = originals._Original(root_fd, 4096)
            authority_original = originals._Original(payload_fd, contract.MAX_REQUEST_BYTES)
            selected_original = originals._Original(assignment_fd, assignment.MAX_ORIGINAL_BYTES)
            profile.require(profile.sha256(root_original.raw) == config["authorityRootSha256"]
                and profile.sha256(authority_original.raw) == config["authorityConfigurationSha256"]
                and profile.sha256(selected_original.raw) == config["assignmentSha256"])
            root = serialization.load_pem_public_key(root_original.raw)
            profile.require(isinstance(root, Ed25519PublicKey)
                and root.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == root_original.raw)
            spki = root.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            profile.require(profile.sha256(spki) == config["authorityRootSpkiSha256"]
                and spki != binding.runtime_root_public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
            envelope = codec.document(authority_original.raw, contract.MAX_REQUEST_BYTES, exact=False)
            profile.require(type(envelope) is dict and set(envelope) == {"schema", "payload", "signature"}
                and envelope["schema"] == SIGNED)
            payload = envelope["payload"]
            profile.require(type(payload) is dict and payload.get("schema") == "serverware.policyAuthorityServiceConfiguration/v6"
                and payload.get("sourceRevision") == contract.SOURCE_REVISION
                and configuration_digest.full_configuration_digest(payload)
                    == config["authorityConfigurationDigest"] == binding.configuration_digest)
            root.verify(profile.encoded(envelope["signature"], 64),
                commitment.framed_digest(SIGNED, profile.canonical(payload)).encode("ascii"))
            original = selected_original.raw.decode("ascii")
            mono = time.monotonic_ns()
            now = custody._receipt_now(binding)
            selected_payload = assignment.verify_original(original, configuration_payload=payload,
                root_key=root, now_epoch_ns=now)
            owner = _Cold()
            owner.custody, owner.binding, owner.configuration_payload, owner.root_key = actual, binding, payload, root
            owner.configuration_digest = binding.configuration_digest
            owner.configuration_original, owner.policy = profile.canonical(payload), payload[native.FIELD]
            owner.assignment_original, owner.payload = original, selected_payload
            owner.payload_original = profile.canonical(selected_payload)
            owner.originals = (selector, root_original, authority_original, selected_original)
            owner.now, owner.mono = now, mono
            owner.expires = min(binding.attestation_interval[1], selected_payload["expiresAtEpochNs"])
            owner.deadline = mono + owner.expires - now
            owner.poisoned = False
            _cold, _state = owner, "started"
            owner.check()
        except BaseException:
            _state = "poisoned"
            raise


def selected():
    with _LOCK:
        profile.require(os.getpid() == _PID)
        if _state == "new" and not _environment():
            return False
        profile.require(_environment() == _namespace)
        if _state == "disabled":
            return False
        profile.require(_state == "started")
        _cold.check()
        return True


def require_selected():
    with _LOCK:
        profile.require(selected(), "Currentness postboot selection was not admitted at startup")
        return _cold


def close():
    global _state
    with _LOCK:
        profile.require(os.getpid() == _PID)
        if _cold is not None:
            _cold.poisoned = True
        _state = "closed"
