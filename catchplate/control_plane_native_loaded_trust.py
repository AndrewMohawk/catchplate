"""Retained cold public originals for read-only native loaded-policy evidence.

The measured-holder assignment authenticates identity/measurements only. No
currentness, OAuth, dispatch or signing permission is obtained by this reader.
"""
import hashlib
import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from catchplate import authority_contract as contract
from catchplate import authority_request_commitment as commitment
from catchplate import authority_credential_currentness_policy as native
from catchplate import authority_policy_canary_policy as configuration_digest
from catchplate import authority_setup_policy as profile
from catchplate import authority_oauth_setup as codec
from catchplate import oauth_application_owner as originals
from catchplate import control_plane_custody_client as custody

ENV = "CATCHPLATE_SETUP_NATIVE_OBSERVATION_CONFIG_FD"
CONFIG_SCHEMA = "catchplate.setupNativePolicyObservationConfiguration/v1"
POSTBOOT_CONFIG_SCHEMA = "catchplate.setupNativePolicyObservationConfiguration/v2"
POSTBOOT_CONFIG_FIELDS = frozenset({"schema", "sourceRevision", "controlPlaneConfigurationDigest", "assignmentSha256"})
CONFIG_FIELDS = frozenset({"schema", "sourceRevision", "controlPlaneConfigurationDigest", "authorityRootFd",
    "authorityRootSha256", "authorityRootSpkiSha256", "authorityConfigurationFd", "authorityConfigurationSha256",
    "authorityConfigurationDigest", "holderId"})
SIGNED = "catchplate.signedPolicyAuthorityServiceConfiguration/v6"
STATEMENT = "catchplate.nativeLoadedPolicyStatement/v1"
QUOTE_DOMAIN = b"catchplate/native-loaded-policy-attestation/v1\0"
STATEMENT_FIELDS = frozenset({"apiVersion", "request", "policyOriginalSha256", "routePolicyDigest", "bootId", "keyId",
    "controlPlaneResponseSigningKeyId", "dataPlaneBinarySha256", "observedAtEpochNs"})


def configuration(value):
    if type(value) is dict and value.get("schema") == POSTBOOT_CONFIG_SCHEMA:
        profile.require(set(value) == POSTBOOT_CONFIG_FIELDS and value["sourceRevision"] == contract.SOURCE_REVISION)
        profile.digest(value["controlPlaneConfigurationDigest"]); profile.digest(value["assignmentSha256"])
        return value
    profile.require(type(value) is dict and set(value) == CONFIG_FIELDS and value["schema"] == CONFIG_SCHEMA
        and value["sourceRevision"] == contract.SOURCE_REVISION)
    for name in CONFIG_FIELDS - {"schema", "sourceRevision", "authorityRootFd", "authorityConfigurationFd"}:
        profile.digest(value[name])
    profile.require(originals._fd(value["authorityRootFd"]) != originals._fd(value["authorityConfigurationFd"]))
    return value


class Trust:
    def __init__(self, owner):
        from catchplate.control_plane_setup_policy import _PostBindOwner, NATIVE_INSTALLED_PATH
        profile.require(type(owner) is _PostBindOwner and owner.request.url.path == NATIVE_INSTALLED_PATH)
        owner.check()
        self.owner, self.binding, self.environment = owner, owner.binding, os.environ.get(ENV, "")
        profile.require(self.environment.isascii() and self.environment.isdecimal()
            and str(int(self.environment)) == self.environment)
        descriptor = originals._fd(int(self.environment))
        profile.require(descriptor in self.binding.inherited_descriptors)
        config_original = originals._Original(descriptor, 16384)
        config = configuration(codec.document(config_original.raw, 16384))
        self.postboot_selection = None
        if config["schema"] == POSTBOOT_CONFIG_SCHEMA:
            from catchplate import control_plane_credential_currentness_assignment as selected
            selection = selected.require_selected()
            profile.require(selection.binding is self.binding
                and selection.configuration_digest == config["controlPlaneConfigurationDigest"] == owner.configuration
                and profile.sha256(selection.assignment_original.encode("ascii")) == config["assignmentSha256"]
                and descriptor not in {item.fd for item in selection.originals})
            self.postboot_selection = selection
            self.root, self.payload, self.policy = selection.root_key, selection.configuration_payload, selection.policy
            self.assignment = selection.payload["assignment"]
            self.originals = (config_original, *selection.originals)
            self.retained = profile.canonical({"payload": self.payload, "assignment": self.assignment})
            owner.clip(min(self.binding.attestation_interval[1], selection.expires))
            self.check()
            return
        root_fd, payload_fd = config["authorityRootFd"], config["authorityConfigurationFd"]
        profile.require(len({descriptor, root_fd, payload_fd}) == 3
            and {root_fd, payload_fd} <= set(self.binding.inherited_descriptors)
            and config["controlPlaneConfigurationDigest"] == owner.configuration)
        root_original = originals._Original(root_fd, 4096)
        payload_original = originals._Original(payload_fd, contract.MAX_REQUEST_BYTES)
        self.originals = (config_original, root_original, payload_original)
        profile.require(profile.sha256(root_original.raw) == config["authorityRootSha256"]
            and profile.sha256(payload_original.raw) == config["authorityConfigurationSha256"])
        self.root = serialization.load_pem_public_key(root_original.raw)
        profile.require(isinstance(self.root, Ed25519PublicKey)
            and self.root.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == root_original.raw)
        der = self.root.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        profile.require(profile.sha256(der) == config["authorityRootSpkiSha256"]
            and der != self.binding.runtime_root_public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        envelope = codec.document(payload_original.raw, contract.MAX_REQUEST_BYTES, exact=False)
        profile.require(type(envelope) is dict and set(envelope) == {"schema", "payload", "signature"} and envelope["schema"] == SIGNED)
        self.payload = envelope["payload"]
        profile.require(type(self.payload) is dict and self.payload.get("schema") == "catchplate.policyAuthorityServiceConfiguration/v6"
            and self.payload.get("sourceRevision") == contract.SOURCE_REVISION
            and configuration_digest.full_configuration_digest(self.payload) == config["authorityConfigurationDigest"] == owner.configuration)
        self.root.verify(native.profile.encoded(envelope["signature"], 64),
            commitment.framed_digest(SIGNED, profile.canonical(self.payload)).encode("ascii"))
        self.policy = native.validate_policy(self.payload.get(native.FIELD), payload=self.payload, root_key=self.root)
        profile.require(self.policy is not None)
        self.assignment = native._holder(self.policy, config["holderId"])
        self.retained = profile.canonical({"payload": self.payload, "assignment": self.assignment})
        # Never renew the enclosing request, cold custody attestation, Setup or
        # continuation expiry. Opening these public originals is not startup.
        owner.clip(self.binding.attestation_interval[1])
        self.check()

    def check(self):
        self.owner.check()
        if self.postboot_selection is not None:
            from catchplate import control_plane_credential_currentness_assignment as selected
            profile.require(selected.require_selected() is self.postboot_selection)
            self.postboot_selection.check()
        profile.require(os.environ.get(ENV, "") == self.environment and self.owner.binding is self.binding
            and custody._snapshot(self.owner.custody) is self.binding
            and profile.canonical({"payload": self.payload, "assignment": self.assignment}) == self.retained)
        for original in self.originals:
            original.check()
        now = custody._receipt_now(self.binding)
        profile.require(now < self.owner.expires and time.monotonic_ns() < self.owner.deadline)
        return now

    def verify(self, envelope, request, *, policy_original_sha256, route_digest):
        now = self.check()
        profile.require(type(envelope) is dict and set(envelope) == {"statement", "signature", "nativeKeyEvidence"})
        statement, expected = envelope["statement"], self.assignment
        profile.require(type(statement) is dict and set(statement) == STATEMENT_FIELDS and statement["apiVersion"] == STATEMENT
            and type(statement["request"]) is dict and profile.canonical(statement["request"]) == profile.canonical(request)
            and statement["policyOriginalSha256"] == policy_original_sha256
            and statement["routePolicyDigest"] == route_digest and request["policyHash"] == expected["policyHash"]
            and type(statement["observedAtEpochNs"]) is int
            and request["issuedAtEpochNs"] <= statement["observedAtEpochNs"] <= now < request["expiresAtEpochNs"])
        if self.postboot_selection is not None:
            selected = self.postboot_selection.payload
            profile.require(selected["issuedAtEpochNs"] <= request["issuedAtEpochNs"]
                < request["expiresAtEpochNs"] <= selected["expiresAtEpochNs"])
        for name in ("bootId", "keyId", "controlPlaneResponseSigningKeyId"):
            profile.require(statement[name] == expected[name])
        profile.require(statement["dataPlaneBinarySha256"] == expected["expectedBinaryDigest"])
        evidence = envelope["nativeKeyEvidence"]
        profile.require(type(evidence) is dict and set(evidence) == {"apiVersion", "attestationDocumentB64", "responseProofPublicKey"}
            and evidence["apiVersion"] == "catchplate.nativeResponseProofKeyEvidence/v1")
        raw_key = native.profile.encoded(evidence["responseProofPublicKey"], 32)
        key = Ed25519PublicKey.from_public_bytes(raw_key)
        profile.require(profile.sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)) == expected["keyId"])
        signature = envelope["signature"]
        profile.require(type(signature) is str and signature.startswith("ed25519:"))
        signature = native.profile.encoded(signature[8:], 64)
        raw = profile.canonical(statement)
        key.verify(signature, STATEMENT.encode("ascii") + b"\0" + raw)
        challenge = hashlib.sha256(QUOTE_DOMAIN + native.profile.encoded(request["challenge"], 32)
            + hashlib.sha256(raw).digest() + signature).digest()
        boot = hashlib.sha256(b"catchplate/native-proof-custody-boot/v1\0" + native.profile.encoded(expected["bootId"], 32)
            + bytes.fromhex(expected["keyId"][7:]) + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
        binding = b"catchplate/enclave-runtime-key-binding/v1\0\x04" + b"".join(bytes.fromhex(expected[name][7:])
            for name in native._SCOPE_DIGESTS[:5]) + hashlib.sha256(raw_key).digest() + boot
        document = native.nitro.b64url_decode(evidence["attestationDocumentB64"], "loaded-policy original role-4 quote", max_bytes=12288)
        roots, crls, certificates = native._trust(self.policy["trustRoots"])
        verified, _, _, _, _ = native.nitro._verify_nitro_document_common(document, claims=None,
            expected_user_data_bytes=binding, challenge=challenge, expected_pcrs=expected["expectedPcrs"],
            expected_eif=expected["expectedEif"], roots=roots, crls=crls, certificate_profile=certificates,
            expected_module_id=expected["expectedModuleId"], now=now // 1_000_000_000,
            max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
        profile.require(type(verified["public_key"]) is bytes and verified["public_key"] == raw_key)
        profile.require(self.check() < request["expiresAtEpochNs"])
