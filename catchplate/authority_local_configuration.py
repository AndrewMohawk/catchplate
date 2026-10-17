"""Purpose-fixed local configuration signatures, not launch/DB attestations.

All public policy, role, credential and generation inputs are independently
selected in one protected approval. Actual credential certificate originals are
authenticated before key access. Local root custody is not independent/off-host
or hardware-backed custody; Python key copies are not claimed to be erased.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts.authority import generate_artifact_bundle as generator
from scripts.authority import native_pilot_authority_io as io
from catchplate import authority_artifact_spec as spec
from catchplate import authority_primary_contract as primary
from catchplate import authority_launcher as launcher
from catchplate import authority_recovery_configuration as recovery_configuration
from catchplate import authority_challenge_policy as challenge_maintenance_policy
from catchplate.authority_local_artifacts import sha
from catchplate.authority_local_install import _owning
from catchplate.authority_local_limits import LOCAL_SETUP_MAX_NS

SCHEMA = "catchplate.authorityTrustedHostLocalConfigurationApproval/v1"
PURPOSES = {"authority-service": "sign-exact-local-authority-service-configuration",
            "witness": "sign-exact-local-replay-witness-configuration"}
LOCAL = dict(mode="trusted-host-local", hardwareBacked=False, externalWitnessRequired=False,
             teeQuoteRequired=False, imaAppraisalRequired=False)
SERVICE_ROLES = generator.SERVICE_CONFIGURATION_ROLES
RUNTIME_KEY_ROLES = SERVICE_ROLES | {"witness"}
FIELDS = frozenset({"schema", "purpose", "role", "configurationRootPublicKeyBase64Url",
    "payloadOriginal", "payloadSha256", "generation", "roleManifests", "roleOriginals",
    "runtimePublicKeys", "databaseIssuanceOriginals", "serviceConfigurationOriginal",
    "bootIdDigest", "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"})
GENERATION_FIELDS = frozenset({"generationId", "sequence", "predecessorDigest", "minimumRollbackSequence",
    "validFrom", "validUntil", "operationManifestDigest", "trustMode"})
MAX_CONFIGURATION = generator.authority_contract.MAX_REQUEST_BYTES


def _require(value):
    if not value:
        raise ValueError("local configuration signing refused")


def document(raw, maximum):
    """Canonical configuration JSON, including existing finite timeout numbers."""
    _require(type(raw) is bytes and 0 < len(raw) <= maximum)
    def pairs(rows):
        result = {}
        for name, value in rows:
            _require(name not in result)
            result[name] = value
        return result
    def invalid(_value):
        raise ValueError("nonfinite configuration value")
    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs, parse_constant=invalid)
    _require(type(value) is dict and spec.canonical_json_bytes(value) == raw)
    return value


def _public(value):
    return spec.strict_base64url_decode(value, name="configuration public key", decoded_size=32)


def _spki(value):
    return sha(Ed25519PublicKey.from_public_bytes(_public(value)).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def signature_message(role, payload):
    """The two existing consumer domains deliberately have different framing."""
    raw = spec.canonical_json_bytes(payload)
    if role == "authority-service":
        digest = hashlib.sha256(generator.SERVICE_CONFIGURATION_SCHEMA.encode("ascii") + b"\0"
                                + len(raw).to_bytes(8, "big") + raw)
        return ("sha256:" + digest.hexdigest()).encode("ascii")
    if role == "witness":
        return spec.domain_digest(generator.WITNESS_CONFIGURATION_SCHEMA, raw).encode("ascii")
    raise ValueError("configuration purpose refused")


def _validate_payload(payload, role, generation, bindings, *, root_key=None):
    return generator.validate_configuration_payload(payload, role=role,
        source_revision=generator.authority_contract.SOURCE_REVISION,
        expected_generation_binding=spec.configuration_generation_binding(generation),
        expected_generation_binding_digest=spec.configuration_generation_binding_digest(generation),
        expected_role_bindings=bindings, root_key=root_key)


def _service(payload, selected, *, now_unix):
    """Join real credential originals and static source topology; no live owner."""
    from catchplate.authority_local_database_credentials import issuance

    if challenge_maintenance_policy.FIELD in payload:
        challenge_maintenance_policy._shape(payload[challenge_maintenance_policy.FIELD])
    recovery = recovery_configuration.configuration(payload.get(recovery_configuration.FIELD),
        webauthn=payload["webauthn"])
    _require(recovery_configuration.FIELD not in payload or recovery is not None)
    for manifest in selected["roleManifests"]:
        expected = launcher.ROLE_CREDENTIAL_DESCRIPTOR_NAMES[manifest["role"]]
        if manifest["role"] == "verifier" and recovery is not None:
            expected |= recovery_configuration.CREDENTIAL_NAMES
        _require(manifest["credentialNames"] == sorted(expected))
    originals = selected["databaseIssuanceOriginals"]
    _require(type(originals) is dict and set(originals) == SERVICE_ROLES)
    identities = {}
    targets = set()
    expiry = selected["expiresAtUnixNanos"]
    for role in sorted(SERVICE_ROLES):
        _require(type(originals[role]) is str and originals[role].isascii())
        raw = originals[role].encode("ascii")
        identity = issuance(raw, purpose=role)
        original = document(raw, io.MAX_PUBLIC)
        _require(identity["notBeforeEpochNs"] <= now_unix < identity["expiresAtEpochNs"]
            and original["issuedAtUnixNanos"] <= now_unix
            and original["intendedOwner"] == dict(uid=launcher.ROLE_IDENTITIES[role][0],
                                                  gid=launcher.ROLE_IDENTITIES[role][1]))
        targets.add((original["database"], original["host"], original["port"], original["approvalSha256"]))
        expiry = min(expiry, identity["expiresAtEpochNs"])
        identities[role] = identity
        row = payload["roles"][role]
        _require(all(row[name] == identity[name]
            for name in ("databaseRole", "tlsClientDn", "tlsClientSerial", "tlsIssuerDn")))
        _require((row["serviceUid"], row["serviceGid"]) == launcher.ROLE_IDENTITIES[role]
            and row["socketPath"] == launcher.ROLE_SOCKET_PATHS[role]
            and row["responseSigningSpkiDigest"] == _spki(selected["runtimePublicKeys"][role]))
        peer = {"verifier": "runtime", "planner": "verifier", "planner-writer": "planner",
                "issuer": "verifier", "executor": "verifier"}[role]
        _require((row["peerUid"], row["peerGid"]) == launcher.ROLE_IDENTITIES[peer])
        for field in ("requestTimeoutSeconds", "databaseConnectTimeoutSeconds"):
            _require(type(row[field]) in (int, float) and 0 < row[field] < 2**63)
        for field in ("maximumInternalAgeNs", "capabilityLifetimeNs", "workers", "maximumInFlight", "listenBacklog"):
            _require(type(row[field]) is int and 0 < row[field] < 2**63)
        _require(row["maximumInFlight"] >= row["workers"])
    _require(len({row["databaseRole"] for row in identities.values()}) == 5
        and len({row["certificateSha256"] for row in identities.values()}) == 5
        and len({row["caCertificateSha256"] for row in identities.values()}) == 1 and len(targets) == 1)
    generator.genesis_policy.configuration(payload.get(generator.genesis_policy.FIELD),
        root_digest=_spki(selected["configurationRootPublicKeyBase64Url"]))
    for role in ("verifier", "issuer", "executor"):
        _require(payload[role + "CredentialIssuanceDigest"] == identities[role]["credentialIssuanceDigest"])
    executor = identities["executor"]
    _require(all(payload[outer] == executor[inner] for outer, inner in (
        ("executorRole", "databaseRole"), ("executorTlsClientDn", "tlsClientDn"),
        ("executorTlsClientSerial", "tlsClientSerial"), ("executorTlsIssuerDn", "tlsIssuerDn"))))
    _require((payload["runtimeUid"], payload["runtimeGid"]) == launcher.ROLE_IDENTITIES["runtime"]
        and payload["queryManifestDigest"] == primary.source_query_manifest_digest())
    for role in ("verifier", "planner"):
        row = payload["roles"][role]
        _require(row["signingPublicKeyBase64Url"] == selected["runtimePublicKeys"][role]
                 and row["signingSpkiDigest"] == _spki(selected["runtimePublicKeys"][role]))
    writer = payload["roles"]["planner-writer"]
    _require(writer["responseSigningPublicKeyBase64Url"] == selected["runtimePublicKeys"]["planner-writer"]
        and writer["plannerSigningPublicKeyBase64Url"] == selected["runtimePublicKeys"]["planner"]
        and payload["roles"]["verifier"]["runtimeSocketPath"] == launcher.ROLE_SOCKET_PATHS["verifier"])
    _require(type(payload["roles"]["verifier"]["maximumEndToEndDeadlineNs"]) is int
             and payload["roles"]["verifier"]["maximumEndToEndDeadlineNs"] > 0)
    trust = payload["credentialReleaseTrust"]
    _require(type(trust) is dict and set(trust) == {"schema", "trustMode", "maximumReceiptAgeNs"}
        and trust["schema"] == "catchplate.trustedHostLocalCredentialReleaseTrust/v1"
        and trust["trustMode"] == "trusted-host-local"
        and type(trust["maximumReceiptAgeNs"]) is int and trust["maximumReceiptAgeNs"] > 0)
    replay = payload["replayWitness"]
    _require(type(replay) is dict and set(replay) == {"socketPath", "serviceUid", "serviceGid",
        "requestTimeoutSeconds", "identityDigest", "signingPublicKeyBase64Url"}
        and replay["socketPath"] == launcher.ROLE_SOCKET_PATHS["witness"]
        and (replay["serviceUid"], replay["serviceGid"]) == launcher.ROLE_IDENTITIES["witness"]
        and replay["signingPublicKeyBase64Url"] == selected["runtimePublicKeys"]["witness"]
        and type(replay["requestTimeoutSeconds"]) in (int, float) and replay["requestTimeoutSeconds"] > 0)
    spec._require_digest(replay["identityDigest"], name="selected replay witness identity")
    webauthn = payload["webauthn"]
    _require(type(webauthn) is dict and set(webauthn) == {"rpId", "origin", "challengeLifetimeNs",
        "maximumChallengeAgeNs", "allowedAuthenticatorClasses", "requireAttestationTrusted"}
        and all(type(webauthn[name]) is int and webauthn[name] > 0
                for name in ("challengeLifetimeNs", "maximumChallengeAgeNs")))
    return expiry


def prepare(raw, *, boot, now_boottime_ns, now_unix_ns):
    """Validate exact independently supplied originals before any signing effect."""
    selected = document(raw, io.MAX_PUBLIC)
    _require(set(selected) == FIELDS and selected["schema"] == SCHEMA
        and selected["role"] in PURPOSES and selected["purpose"] == PURPOSES[selected["role"]]
        and selected["bootIdDigest"] == boot)
    spec._require_digest(boot, name="original boot")
    for name in ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"):
        _require(type(selected[name]) is int and 0 < selected[name] < 2**64)
    _require(selected["issuedAtBoottimeNs"] <= now_boottime_ns < selected["deadlineBoottimeNs"]
        and selected["issuedAtUnixNanos"] <= now_unix_ns < selected["expiresAtUnixNanos"]
        and selected["deadlineBoottimeNs"] - selected["issuedAtBoottimeNs"] <= LOCAL_SETUP_MAX_NS
        and selected["expiresAtUnixNanos"] - selected["issuedAtUnixNanos"] <= LOCAL_SETUP_MAX_NS)
    root_public = _public(selected["configurationRootPublicKeyBase64Url"])
    generation = selected["generation"]
    _require(type(generation) is dict and set(generation) == GENERATION_FIELDS
        and generation["trustMode"] == LOCAL
        and generation["operationManifestDigest"] == generator.authority_contract.OPERATION_MANIFEST_DIGEST)
    spec.configuration_generation_binding(generation)
    begin = int(spec._require_timestamp(generation["validFrom"], name="generation start").timestamp()) * 1_000_000_000
    expiry = int(spec._require_timestamp(generation["validUntil"], name="generation expiry").timestamp()) * 1_000_000_000
    _require(begin <= selected["issuedAtUnixNanos"] <= now_unix_ns < selected["expiresAtUnixNanos"] <= expiry)
    roles, originals = selected["roleManifests"], selected["roleOriginals"]
    bindings = spec.role_binding_digests(roles)
    _require(set(bindings) == set(launcher.PROCESS_MODES) and type(originals) is dict and set(originals) == set(bindings))
    for row in roles:
        name = row["role"]
        _require(type(originals[name]) is str and originals[name].isascii()
            and row["sha256"] == sha(originals[name].encode("ascii"))
            and (row["runtimeUid"], row["runtimeGid"]) == launcher.ROLE_IDENTITIES[name]
            and row["processMode"] == launcher.PROCESS_MODES[name]
            and row["listenerName"] == launcher.ROLE_LISTENER_NAMES[name]
            and row["argv"] == {"schema": spec.LOCAL_ARGUMENTS_SCHEMA}
            and (row["credentialNames"] == sorted(launcher.ROLE_CREDENTIAL_DESCRIPTOR_NAMES[name])
                or name == "verifier" and row["credentialNames"] == sorted(
                    launcher.ROLE_CREDENTIAL_DESCRIPTOR_NAMES[name] | recovery_configuration.CREDENTIAL_NAMES)))
    keys = selected["runtimePublicKeys"]
    _require(type(keys) is dict and set(keys) == RUNTIME_KEY_ROLES)
    key_bytes = [_public(keys[name]) for name in sorted(keys)]
    _require(len(set(key_bytes + [root_public])) == len(key_bytes) + 1)
    _require(type(selected["payloadOriginal"]) is str and selected["payloadOriginal"].isascii())
    payload_raw = selected["payloadOriginal"].encode("ascii")
    _require(sha(payload_raw) == selected["payloadSha256"])
    payload = document(payload_raw, MAX_CONFIGURATION)
    role = selected["role"]
    root_key = Ed25519PublicKey.from_public_bytes(root_public)
    payload_schema, payload_digest = _validate_payload(payload, role, generation, bindings, root_key=root_key)
    envelope_schema = (generator.SERVICE_CONFIGURATION_SCHEMA if role == "authority-service"
                       else generator.WITNESS_CONFIGURATION_SCHEMA)
    # A raw64 Ed25519 signature has exactly 86 canonical base64url characters.
    # Bound the final existing envelope before reading any private-key bytes.
    _require(len(spec.canonical_json_bytes(dict(schema=envelope_schema, payload=payload, signature=""))) + 86
             <= MAX_CONFIGURATION)
    if role == "authority-service":
        _require(selected["serviceConfigurationOriginal"] is None)
        expiry = min(expiry, _service(payload, selected, now_unix=now_unix_ns))
    else:
        _require(type(selected["serviceConfigurationOriginal"]) is str
                 and selected["serviceConfigurationOriginal"].isascii())
        service = document(selected["serviceConfigurationOriginal"].encode("ascii"), MAX_CONFIGURATION)
        _require(set(service) == {"schema", "payload", "signature"}
                 and service["schema"] == generator.SERVICE_CONFIGURATION_SCHEMA)
        root_key.verify(
            spec.strict_base64url_decode(service["signature"], name="service signature", decoded_size=64),
            signature_message("authority-service", service["payload"]))
        _, service_digest = _validate_payload(service["payload"], "authority-service", generation, bindings,
            root_key=root_key)
        expiry = min(expiry, _service(service["payload"], selected, now_unix=now_unix_ns))
        _require(payload["authorityConfigurationDigests"] == [service_digest]
            and payload["signingSpkiDigest"] == _spki(keys["witness"])
            and payload["verifierSigningPublicKeyBase64Url"] == keys["verifier"]
            and payload["identityDigest"] == service["payload"]["replayWitness"]["identityDigest"]
            and (payload["serviceUid"], payload["serviceGid"]) == launcher.ROLE_IDENTITIES["witness"]
            and (payload["peerUid"], payload["peerGid"]) == launcher.ROLE_IDENTITIES["verifier"]
            and payload["releaseConsumerPeers"] == {name: dict(uid=launcher.ROLE_IDENTITIES[name][0],
                gid=launcher.ROLE_IDENTITIES[name][1]) for name in SERVICE_ROLES})
        _require(type(payload["requestTimeoutSeconds"]) in (int, float) and payload["requestTimeoutSeconds"] > 0)
        for name in ("listenBacklog", "workers", "maximumInFlight", "maximumRequestAgeNs"):
            _require(type(payload[name]) is int and 0 < payload[name] < 2**63)
        _require(payload["maximumInFlight"] >= payload["workers"] and type(payload["minimumSequence"]) is int
            and payload["minimumSequence"] >= 0)
        if payload["minimumSequence"] == 0:
            _require(payload["minimumReceiptDigest"] is None)
        else:
            spec._require_digest(payload["minimumReceiptDigest"], name="actual prior replay receipt")
    _require(selected["expiresAtUnixNanos"] <= expiry)
    return dict(selected=selected, payload=payload, rootPublic=root_public, payloadSchema=payload_schema,
                payloadDigest=payload_digest, deadline=selected["deadlineBoottimeNs"], epochLimit=selected["expiresAtUnixNanos"])


def _require_current_database_issuances(selected):
    """Fresh signing cannot turn historical v1 credentials into current authority.

    Retained custody still validates its actual historical originals through
    prepare/_service; only acquisition of a new signing owner is v2-only.
    """
    from catchplate.authority_local_database_credentials import issuance

    for role in sorted(SERVICE_ROLES):
        issuance(selected["databaseIssuanceOriginals"][role].encode("ascii"),
                 purpose=role, require_current=True)


class LocalConfigurationIssuer:
    def __init__(self, *, approval_fd, approval_sha256, signing_key_fd):
        io._process()
        self._pid = os.getpid()
        _require(type(approval_fd) is int and type(signing_key_fd) is int
                 and approval_fd >= 3 and signing_key_fd >= 3 and approval_fd != signing_key_fd)
        self._fd, self._key_fd = approval_fd, signing_key_fd
        self._identity = io._input(approval_fd, io.MAX_PUBLIC)
        self._raw = io.read_public(approval_fd, io.MAX_PUBLIC)
        _require(sha(self._raw) == approval_sha256)
        self._boot = launcher._boot_identity_digest()
        self._previous_boot, self._previous_unix = io._clock(), time.time_ns()
        self._prepared = prepare(self._raw, boot=self._boot,
            now_boottime_ns=self._previous_boot, now_unix_ns=self._previous_unix)
        _require_current_database_issuances(self._prepared["selected"])
        key_identity = io._input(signing_key_fd, 32, private=True)
        _require(key_identity[:2] != self._identity[:2])
        self._key_identity = key_identity
        self._used = False
        self._issued_original = None
        self._public_custody_attempted = False
        self.check()

    def check(self):
        now_boot, now_unix = io._clock(), time.time_ns()
        _require(os.getpid() == self._pid
            and self._previous_boot <= now_boot < self._prepared["deadline"]
            and self._previous_unix <= now_unix < self._prepared["epochLimit"]
            and launcher._boot_identity_digest() == self._boot
            and io._input(self._fd, io.MAX_PUBLIC) == self._identity
            and io._input(self._key_fd, 32, private=True) == self._key_identity)
        self._previous_boot, self._previous_unix = now_boot, now_unix

    def issue(self):
        self.check()
        _require(not self._used and io.read_public(self._fd, io.MAX_PUBLIC) == self._raw)
        self._used = True  # No second signature/output attempt after uncertain work.
        signer = io.signing_key(self._key_fd)
        _require(signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                 == self._prepared["rootPublic"])
        selected, payload = self._prepared["selected"], self._prepared["payload"]
        role = selected["role"]
        message = signature_message(role, payload)
        signature = signer.sign(message)
        signer.public_key().verify(signature, message)
        envelope = dict(schema=generator.SERVICE_CONFIGURATION_SCHEMA if role == "authority-service"
            else generator.WITNESS_CONFIGURATION_SCHEMA, payload=payload, signature=spec.strict_base64url_encode(signature))
        self.check()
        raw = spec.canonical_json_bytes(envelope)
        _require(len(raw) <= MAX_CONFIGURATION)
        self._issued_original = raw  # Only a fully successful issue can transfer custody.
        return raw

    def take_public_custody(self):
        """One ownership transfer; callers retain the result under _owning()."""
        return IssuedConfigurationCustody._take(self)

    def publish(self):
        raw = self.issue()
        io.write_public(raw, deadline_boottime_ns=self._prepared["deadline"], check=self.check)


class IssuedConfigurationCustody:
    """Public-only, same-boot custody of an actually issued service configuration.

    The approved verifier issuance authenticates certificate/CA association,
    not possession of TLS files, a database connection, or currentness. This
    owner has no signing key, issuer reference/callback, or signing operation.
    It neither reopens an expired approval nor authorizes a retained restart.
    Complete original authentication occurs at the one-shot transfer. Later
    checks retain its immutable bytes and fixed bounds, not a mutable verdict.
    """

    __slots__ = ("_fd", "_identity", "_raw", "_issued", "_boot", "_pid",
                 "_last_boot", "_last_unix", "_closed", "_admitted", "_admitted_pin")

    def __init__(self):
        raise TypeError("public configuration custody requires a successful issuer transfer")

    @classmethod
    def _take(cls, issuer):
        io._process()
        _require(cls is IssuedConfigurationCustody and type(issuer) is LocalConfigurationIssuer
            and os.getpid() == issuer._pid
            and issuer._issued_original is not None and not issuer._public_custody_attempted
            and issuer._prepared["selected"]["role"] == "authority-service")
        issuer._public_custody_attempted = True  # A failed acquisition is not retryable.
        issuer.check()
        _require(io.read_public(issuer._fd, io.MAX_PUBLIC) == issuer._raw)
        self = object.__new__(cls)
        self._fd, self._identity, self._closed = None, issuer._identity, False
        self._raw, self._issued, self._boot = issuer._raw, issuer._issued_original, issuer._boot
        self._pid = os.getpid()
        self._last_boot, self._last_unix = issuer._previous_boot, issuer._previous_unix
        self._admitted = self._admitted_pin = None
        try:
            with _owning():
                self._fd = fcntl.fcntl(issuer._fd, fcntl.F_DUPFD_CLOEXEC, 3)
            _require(io._input(self._fd, io.MAX_PUBLIC) == issuer._identity == self._identity)
            self._admit()
            self.check()
            issuer.check()
            _require(io.read_public(issuer._fd, io.MAX_PUBLIC) == self._raw)
            return self
        except BaseException:
            self.close()
            raise

    def _admit(self):
        """Authenticate this owner's actual originals once, without a cache API."""
        io._process()
        _require(type(self) is IssuedConfigurationCustody and not self._closed
            and self._admitted is None and self._admitted_pin is None
            and os.getpid() == self._pid and launcher._boot_identity_digest() == self._boot)
        original = self._fd, self._identity, self._raw, self._issued, self._boot, self._pid
        now_boot, now_unix = io._clock(), time.time_ns()
        _require(self._last_boot <= now_boot and self._last_unix <= now_unix
            and io._input(self._fd, io.MAX_PUBLIC) == self._identity
            and io.read_public(self._fd, io.MAX_PUBLIC) == self._raw)
        # Retain the full existing admission, including every credential's
        # actual certificate/CA signatures and the issued service signature.
        prepared = prepare(self._raw, boot=self._boot, now_boottime_ns=now_boot, now_unix_ns=now_unix)
        _require(prepared["selected"]["role"] == "authority-service")
        issued = document(self._issued, MAX_CONFIGURATION)
        _require(set(issued) == {"schema", "payload", "signature"}
            and issued["schema"] == generator.SERVICE_CONFIGURATION_SCHEMA
            and issued["payload"] == prepared["payload"])
        Ed25519PublicKey.from_public_bytes(prepared["rootPublic"]).verify(
            spec.strict_base64url_decode(issued["signature"], name="issued configuration signature", decoded_size=64),
            signature_message("authority-service", issued["payload"]))
        after_boot, after_unix = io._clock(), time.time_ns()
        _require(now_boot <= after_boot < prepared["deadline"]
            and now_unix <= after_unix < prepared["epochLimit"]
            and os.getpid() == self._pid and launcher._boot_identity_digest() == self._boot
            and io._input(self._fd, io.MAX_PUBLIC) == self._identity
            and io.read_public(self._fd, io.MAX_PUBLIC) == self._raw)
        _require(all(current is held for current, held in zip(
            (self._fd, self._identity, self._raw, self._issued, self._boot, self._pid), original, strict=True)))
        selected = prepared["selected"]
        # prepare proves approval expiry <= generation expiry and every
        # credential expiry, and all lower bounds hold at this actual sample.
        # Nondecreasing later epochs preserve those lower bounds. Nothing from
        # the mutable selected/payload/identity graphs escapes into custody.
        admitted = (*original, selected["issuedAtBoottimeNs"], prepared["deadline"],
            selected["issuedAtUnixNanos"], prepared["epochLimit"],
            selected["databaseIssuanceOriginals"]["verifier"].encode("ascii"))
        self._admitted = self._admitted_pin = admitted
        self._last_boot, self._last_unix = after_boot, after_unix

    def check(self):
        io._process()
        admitted = self._admitted
        _require(type(self) is IssuedConfigurationCustody and not self._closed
            and type(admitted) is tuple and len(admitted) == 11 and admitted is self._admitted_pin
            and all(current is held for current, held in zip(
                (self._fd, self._identity, self._raw, self._issued, self._boot, self._pid), admitted[:6], strict=True))
            and os.getpid() == self._pid and launcher._boot_identity_digest() == self._boot)
        now_boot, now_unix = io._clock(), time.time_ns()
        _require(admitted[6] <= self._last_boot <= now_boot < admitted[7]
            and admitted[8] <= self._last_unix <= now_unix < admitted[9]
            and io._input(self._fd, io.MAX_PUBLIC) == self._identity
            and io.read_public(self._fd, io.MAX_PUBLIC) == self._raw)
        after_boot, after_unix = io._clock(), time.time_ns()
        _require(now_boot <= after_boot < admitted[7]
            and now_unix <= after_unix < admitted[9]
            and admitted is self._admitted is self._admitted_pin
            and all(current is held for current, held in zip(
                (self._fd, self._identity, self._raw, self._issued, self._boot, self._pid), admitted[:6], strict=True))
            and os.getpid() == self._pid and launcher._boot_identity_digest() == self._boot
            and io._input(self._fd, io.MAX_PUBLIC) == self._identity
            and io.read_public(self._fd, io.MAX_PUBLIC) == self._raw)
        self._last_boot, self._last_unix = after_boot, after_unix

    def service_original(self):
        self.check()
        return self._issued

    def approval_original(self):
        self.check()
        return self._raw

    def verifier_issuance_original(self):
        self.check()
        return self._admitted[10]

    def close(self):
        """Release only our duplicate, including after expiry or content refusal."""
        if self._closed:
            return
        io._process()
        _require(os.getpid() == self._pid)
        with _owning():
            if self._fd is not None:
                # Content/metadata changes invalidate reads, not ownership of
                # this inode. Never close an FD recycled onto a different inode.
                _require(io._identity(os.fstat(self._fd))[:2] == self._identity[:2])
                fd = self._fd
                self._fd, self._closed = None, True
                os.close(fd)
            else:
                self._closed = True
