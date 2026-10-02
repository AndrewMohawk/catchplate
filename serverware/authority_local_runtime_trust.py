"""Issue the existing local runtime trust, never observe or launch its owners.

V1 FD rosters are independently selected admission expectations. Explicit local
v2 delegates the relay's post-seal roster to its genuine measured launcher, with
signed role/configuration/generation pins; app exact-list admission is unchanged.
Existing signed verifier evidence is required; this issuer cannot create it.
Local configuration-root delegation implies neither hardware nor off-host trust.
"""
from __future__ import annotations

import os
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_local_configuration as configuration
from serverware import authority_service as service
from serverware import authority_fd_entrypoint as entrypoint
from serverware.authority_local_limits import LOCAL_SETUP_MAX_NS

io, spec, launcher = configuration.io, configuration.spec, configuration.launcher
canonical, document, sha = spec.canonical_json_bytes, configuration.document, configuration.sha
SCHEMA = "serverware.authorityTrustedHostLocalRuntimeTrustApproval/v1"
POST_SEAL_SCHEMA = "serverware.authorityTrustedHostLocalRuntimeTrustApproval/v2"
PURPOSE = "sign-exact-local-runtime-trust"
FIELDS = frozenset({"schema", "purpose", "configurationRootPublicKeyBase64Url",
    "serviceConfigurationOriginal", "serviceConfigurationSha256", "verifierAttestationOriginal",
    "verifierAttestationSha256", "payloadOriginal", "payloadSha256", "generation", "roleManifests",
    "bootIdDigest", "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"})
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "configurationDigest", "operationManifestDigest",
    "relaySocketPath", "relayServiceUid", "relayServiceGid", "verifierSocketPath", "verifierServiceUid",
    "verifierServiceGid", "controlPlaneUid", "controlPlaneGid", "verifierSigningPublicKeyBase64Url",
    "maximumDeadlineNs", "attestationReceiptDigest", "attestationEvidence", "attestationVerificationPolicy",
    "trustMode", "controlPlaneInheritedFileDescriptors", "relayInheritedFileDescriptors"})
POST_SEAL_PAYLOAD_FIELDS = (PAYLOAD_FIELDS - {"relayInheritedFileDescriptors"}) | {"relayDescriptorPolicy"}


def require(condition):
    if not condition:
        raise ValueError("local runtime trust issuance refused")


def signature_message(payload):
    return service._domain_digest(service.SIGNED_RUNTIME_TRUST_SCHEMA, canonical(payload)).encode("ascii")


def _original(selected, name, maximum):
    raw = selected[name + "Original"]
    require(type(raw) is str and raw.isascii())
    raw = raw.encode("ascii")
    require(sha(raw) == selected[name + "Sha256"])
    return raw, document(raw, maximum)


def prepare(raw, *, boot, now_boottime_ns, now_unix_ns):
    """Authenticate public originals; selected FD numbers are not observed FDs."""
    selected = document(raw, io.MAX_PUBLIC)
    require(set(selected) == FIELDS and selected["schema"] in {SCHEMA, POST_SEAL_SCHEMA} and selected["purpose"] == PURPOSE
        and selected["bootIdDigest"] == boot)
    post_seal = selected["schema"] == POST_SEAL_SCHEMA
    spec._require_digest(boot, name="runtime trust boot")
    for name in ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"):
        require(type(selected[name]) is int and 0 < selected[name] < 2**64)
    require(type(now_boottime_ns) is type(now_unix_ns) is int
        and selected["issuedAtBoottimeNs"] <= now_boottime_ns < selected["deadlineBoottimeNs"]
        and selected["issuedAtUnixNanos"] <= now_unix_ns < selected["expiresAtUnixNanos"]
        and selected["deadlineBoottimeNs"] - selected["issuedAtBoottimeNs"] <= LOCAL_SETUP_MAX_NS
        and selected["expiresAtUnixNanos"] - selected["issuedAtUnixNanos"] <= LOCAL_SETUP_MAX_NS)
    public = configuration._public(selected["configurationRootPublicKeyBase64Url"])
    root = Ed25519PublicKey.from_public_bytes(public)
    root_digest = configuration._spki(selected["configurationRootPublicKeyBase64Url"])
    generation = selected["generation"]
    require(type(generation) is dict and set(generation) == configuration.GENERATION_FIELDS
        and generation["trustMode"] == configuration.LOCAL
        and generation["operationManifestDigest"] == service.authority_contract.OPERATION_MANIFEST_DIGEST)
    spec.configuration_generation_binding(generation)
    begin = int(spec._require_timestamp(generation["validFrom"], name="generation start").timestamp()) * 10**9
    end = int(spec._require_timestamp(generation["validUntil"], name="generation end").timestamp()) * 10**9
    require(begin <= selected["issuedAtUnixNanos"] < selected["expiresAtUnixNanos"] <= end)
    roles = selected["roleManifests"]
    bindings = spec.role_binding_digests(roles)
    require(set(bindings) == set(launcher.PROCESS_MODES))
    for row in roles:
        role = row["role"]
        require((row["runtimeUid"], row["runtimeGid"]) == launcher.ROLE_IDENTITIES[role]
            and row["processMode"] == launcher.PROCESS_MODES[role]
            and row["listenerName"] == launcher.ROLE_LISTENER_NAMES[role]
            and row["argv"] == {"schema": spec.LOCAL_ARGUMENTS_SCHEMA}
            and row["credentialNames"] == sorted(launcher.ROLE_CREDENTIAL_DESCRIPTOR_NAMES[role]))
    _, signed = _original(selected, "serviceConfiguration", configuration.MAX_CONFIGURATION)
    require(set(signed) == {"schema", "payload", "signature"} and signed["schema"] == service.SIGNED_CONFIG_SCHEMA)
    root.verify(spec.strict_base64url_decode(signed["signature"], name="service signature", decoded_size=64),
                configuration.signature_message("authority-service", signed["payload"]))
    source = signed["payload"]
    _, source_digest = configuration._validate_payload(source, "authority-service", generation, bindings)
    configuration.generator.genesis_policy.configuration(
        source.get(configuration.generator.genesis_policy.FIELD), root_digest=root_digest)
    require((source["runtimeUid"], source["runtimeGid"]) == launcher.ROLE_IDENTITIES["runtime"])
    for role, row in source["roles"].items():
        peer = {"verifier": "runtime", "planner": "verifier", "planner-writer": "planner",
                "issuer": "verifier", "executor": "verifier"}[role]
        require((row["serviceUid"], row["serviceGid"]) == launcher.ROLE_IDENTITIES[role]
            and (row["peerUid"], row["peerGid"]) == launcher.ROLE_IDENTITIES[peer]
            and row["socketPath"] == launcher.ROLE_SOCKET_PATHS[role]
            and row["responseSigningSpkiDigest"] != root_digest)
    payload_raw, payload = _original(selected, "payload", service.MAX_RUNTIME_TRUST_BYTES)
    require(set(payload) == (POST_SEAL_PAYLOAD_FIELDS if post_seal else PAYLOAD_FIELDS)
        and payload["schema"] == (service.RUNTIME_TRUST_POST_SEAL_SCHEMA if post_seal else service.RUNTIME_TRUST_SCHEMA)
        and payload["sourceRevision"] == service.SOURCE_REVISION and payload["trustMode"] == "trusted-host-local"
        and payload["configurationDigest"] == source_digest
        and payload["operationManifestDigest"] == service.authority_contract.OPERATION_MANIFEST_DIGEST)
    for prefix, role in (("relayService", "runtime"), ("verifierService", "verifier"), ("controlPlane", "control-plane")):
        require(all(type(payload[prefix + suffix]) is int for suffix in ("Uid", "Gid"))
            and (payload[prefix + "Uid"], payload[prefix + "Gid"]) == entrypoint.ROLE_IDENTITIES[role])
    verifier = source["roles"]["verifier"]
    response = payload["verifierSigningPublicKeyBase64Url"]
    require(response == verifier["signingPublicKeyBase64Url"]
        and configuration._spki(response) == verifier["signingSpkiDigest"] == verifier["responseSigningSpkiDigest"]
        and payload["relaySocketPath"] == launcher.ROLE_SOCKET_PATHS["runtime"]
        and payload["verifierSocketPath"] == verifier["socketPath"] == verifier["runtimeSocketPath"]
        and type(payload["maximumDeadlineNs"]) is int
        and type(verifier["maximumEndToEndDeadlineNs"]) is int
        and 1_000_000 <= payload["maximumDeadlineNs"] <= min(30_000_000_000, verifier["maximumEndToEndDeadlineNs"]))
    descriptor_fields = (("controlPlaneInheritedFileDescriptors",) if post_seal
        else ("controlPlaneInheritedFileDescriptors", "relayInheritedFileDescriptors"))
    for field in descriptor_fields:
        descriptors = payload[field]
        require(type(descriptors) is list and 2 <= len(descriptors) <= 4096
            and all(type(fd) is int and 3 <= fd < 2**31 for fd in descriptors)
            and descriptors == sorted(set(descriptors)))
    if post_seal:
        service._require_local_post_seal_descriptor_policy(payload["relayDescriptorPolicy"])
        require(payload["relayDescriptorPolicy"]["roleBindingDigest"] == bindings["runtime"]
            and payload["relayDescriptorPolicy"]["generationBindingDigest"] == source["generationBindingDigest"])
    else:
        require(3 in payload["relayInheritedFileDescriptors"])
    evidence_raw, evidence = _original(selected, "verifierAttestation", configuration.MAX_CONFIGURATION)
    policy = payload["attestationVerificationPolicy"]
    require(type(policy) is dict and type(payload["attestationEvidence"]) is dict
        and canonical(payload["attestationEvidence"]) == evidence_raw
        and policy["rootPublicKeyBase64Url"] == selected["configurationRootPublicKeyBase64Url"]
        and policy["verifierSigningPublicKeyBase64Url"] == response
        and type(policy["maximumReceiptAgeNs"]) is int
        and source["credentialReleaseTrust"]["schema"] == "serverware.trustedHostLocalCredentialReleaseTrust/v1"
        and source["credentialReleaseTrust"]["trustMode"] == "trusted-host-local"
        and type(source["credentialReleaseTrust"]["maximumReceiptAgeNs"]) is int
        and 0 < policy["maximumReceiptAgeNs"] <= source["credentialReleaseTrust"]["maximumReceiptAgeNs"])
    # The existing consumer authenticates the original signature, exact local
    # claims, selected verifier key, identity domain and actual current time.
    service._verify_public_attestation_evidence(evidence=evidence, policy=policy,
        expected_receipt_digest=payload["attestationReceiptDigest"], expected_configuration_digest=source_digest,
        expected_response_spki_digest=verifier["responseSigningSpkiDigest"])
    attested = evidence["payload"]
    claims = dict(trustMode="trusted-host-local", coLocated=True, hardwareBacked=False,
        nativeStageZero=False, hsmBackedKeys=False, teeVerified=False, externalWitnessVerified=False)
    require(all(type(value[name]) is type(expected) and value[name] == expected
        for value in (attested, policy) for name, expected in claims.items()))
    for field in ("launchManifestDigest", "runtimeClosureDigest", "generationDigest",
                  "stageZeroRequestDigest", "artifactPackageDigest", "measurementDigest"):
        spec._require_digest(attested[field], name="signed verifier " + field)
    if post_seal:
        require(all(payload["relayDescriptorPolicy"][field] == attested[field]
            for field in ("generationDigest", "artifactPackageDigest")))
    require(type(attested["issuedAtEpochNs"]) is type(attested["expiresAtEpochNs"]) is int
        and attested["issuedAtEpochNs"] <= selected["issuedAtUnixNanos"] <= now_unix_ns
        and selected["expiresAtUnixNanos"] <= attested["expiresAtEpochNs"]
        and attested["measurementDigest"] == verifier["measurementDigest"]
        and attested["runtimeClosureDigest"] == service._domain_digest(
            "serverware.policyAuthorityRuntimeClosure/v2", attested["launchManifestDigest"].encode("ascii"),
            canonical(source["packageVersions"])))
    require(len(canonical(dict(schema=service.SIGNED_RUNTIME_TRUST_SCHEMA, payload=payload, signature=""))) + 86
            <= service.MAX_RUNTIME_TRUST_BYTES)
    return dict(payload=payload, payloadOriginal=payload_raw, rootPublic=public, selected=selected,
                deadline=selected["deadlineBoottimeNs"], epochLimit=selected["expiresAtUnixNanos"])


class LocalRuntimeTrustIssuer:
    def __init__(self, *, approval_fd, approval_sha256, signing_key_fd):
        io._process()
        require(type(approval_fd) is type(signing_key_fd) is int and approval_fd >= 3
            and signing_key_fd >= 3 and approval_fd != signing_key_fd)
        self._origin = (os.getpid(), threading.get_ident())
        self._fd, self._key_fd = approval_fd, signing_key_fd
        self._identity = io._input(approval_fd, io.MAX_PUBLIC)
        self._raw = io.read_public(approval_fd, io.MAX_PUBLIC)
        require(sha(self._raw) == approval_sha256)
        self._boot = launcher._boot_identity_digest()
        self._last_boot, self._last_unix = io._clock(), time.time_ns()
        self._prepared = prepare(self._raw, boot=self._boot,
            now_boottime_ns=self._last_boot, now_unix_ns=self._last_unix)
        self._key_identity = io._input(signing_key_fd, 32, private=True)
        require(self._key_identity[:2] != self._identity[:2])
        self._used = False
        self.check()

    def check(self):
        require(self._origin == (os.getpid(), threading.get_ident()))
        now_boot, now_unix = io._clock(), time.time_ns()
        require(self._last_boot <= now_boot < self._prepared["deadline"]
            and self._last_unix <= now_unix < self._prepared["epochLimit"]
            and launcher._boot_identity_digest() == self._boot
            and io._input(self._fd, io.MAX_PUBLIC) == self._identity
            and io._input(self._key_fd, 32, private=True) == self._key_identity)
        self._last_boot, self._last_unix = now_boot, now_unix

    def issue(self):
        self.check()
        require(not self._used and io.read_public(self._fd, io.MAX_PUBLIC) == self._raw)
        self._used = True
        # Re-admit the original bytes, not a caller-mutable prepared dictionary,
        # before private access; this also repeats current evidence validity.
        self._prepared = prepare(self._raw, boot=self._boot,
            now_boottime_ns=io._clock(), now_unix_ns=time.time_ns())
        key = io.signing_key(self._key_fd)
        require(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                == self._prepared["rootPublic"])
        payload = self._prepared["payload"]
        message = signature_message(payload)
        signature = key.sign(message)
        key.public_key().verify(signature, message)
        raw = canonical(dict(schema=service.SIGNED_RUNTIME_TRUST_SCHEMA,
            payload=payload, signature=spec.strict_base64url_encode(signature)))
        self.check()
        return raw

    def publish(self):
        io.write_public(self.issue(), deadline_boottime_ns=self._prepared["deadline"], check=self.check)
