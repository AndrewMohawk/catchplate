"""Cold OAuth application enrollment and retained before-contact ownership.

An enrollment assigns an application namespace; it is NOT a global provider
subject reservation or permission to bypass controlled lifecycle writers.
Imports perform no admission. Only unconfigured development preserves the old
environment-backed provider profile. No enrollment, key or directory is created.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import threading
import time


STARTUP_SCHEMA = "serverware.oauthApplicationStartup/v1"
MEASURED_STARTUP_SCHEMA = "serverware.oauthApplicationStartup/v2"
SETUP_STARTUP_SCHEMA = "serverware.oauthApplicationStartup/v3"
RECONNECT_STARTUP_SCHEMA = "serverware.oauthApplicationStartup/v4"
ENVELOPE_SCHEMA = "serverware.signedOAuthApplicationEnrollment/v1"
ENROLLMENT_SCHEMA = "serverware.oauthApplicationEnrollment/v1"
CLIENT_SCHEMA = "serverware.oauthClientMaterial/v1"
ASSOCIATION_SCHEMA = "serverware.oauthApplicationAssociation/v1"
CONFIG_FD_ENVIRONMENT = "SERVERWARE_OAUTH_APPLICATION_CONFIG_FD"
ASSOCIATION_KEY = "oauth_application_owner"
MAX_CONFIG_BYTES = 64 * 1024
MAX_CLIENT_BYTES = 32 * 1024
MAX_ENCRYPTED_CLIENT_BYTES = 64 * 1024
MAX_ROOT_BYTES = 4096
MAX_OPERATION_NS = 30_000_000_000
_PREFIX = "SERVERWARE_OAUTH_APPLICATION_"
_DEVELOPMENT = frozenset({"dev", "development", "local", "test"})
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "configurationDigest",
    "deploymentId", "applicationId", "providerId", "providerFamilyNamespace",
    "providerFamilyGeneration", "clientId", "redirectUri", "clientMaterialSha256",
    "providerConfigurationSha256", "issuedAtEpochNs", "expiresAtEpochNs"})
_ASSOCIATION_FIELDS = frozenset({"schema", "enrollmentSha256", "deploymentId",
    "applicationId", "providerId", "providerFamilyNamespace", "providerFamilyGeneration",
    "clientId", "redirectUri", "providerConfigurationSha256"})
_PID = os.getpid()
_LOCK = threading.RLock()
_state = "new"
_namespace = None
_owner = None


class OAuthApplicationError(ValueError):
    pass


def _require(value):
    if not value:
        raise OAuthApplicationError("OAuth application ownership is unavailable or changed")


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":")).encode("ascii")


def _sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _pairs(values):
    result = {}
    for key, value in values:
        _require(key not in result)
        result[key] = value
    return result


def _json(raw, maximum):
    _require(type(raw) is bytes and 2 <= len(raw) <= maximum)
    value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
        parse_constant=lambda _: _require(False))
    def visit(item, depth=0):
        _require(depth <= 8)
        if type(item) is dict:
            _require(len(item) <= 32)
            for child in item.values():
                visit(child, depth + 1)
        elif type(item) is list:
            _require(len(item) <= 32)
            for child in item:
                visit(child, depth + 1)
        else:
            _require(item is None or type(item) in (str, int, bool))
    visit(value)
    _require(canonical(value) == raw)
    return value


def _text(value, maximum):
    _require(type(value) is str and value and value == value.strip()
        and len(value.encode("utf-8")) <= maximum
        and not any(ord(character) < 32 or ord(character) == 127 for character in value))
    return value


def _digest(value):
    _require(type(value) is str and _DIGEST.fullmatch(value) is not None
        and value != "sha256:" + "0" * 64)
    return value


def _fd(value, minimum=32):
    _require(type(value) is int and minimum <= value <= 1023)
    return value


def _environment():
    return (os.environ.get("SERVERWARE_RELEASE_CHANNEL", "dev").strip().lower(),
        tuple(sorted((key, value) for key, value in os.environ.items() if key.startswith(_PREFIX))))


def _development(namespace):
    return namespace[0] in _DEVELOPMENT and not namespace[1]


def _identity(descriptor, maximum, private):
    metadata = os.fstat(descriptor)
    seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    target = os.readlink("/proc/self/fd/" + str(descriptor))
    required = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    _require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_nlink == 0
        and not metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        and (not private or stat.S_IMODE(metadata.st_mode) == 0o400)
        and 2 <= metadata.st_size <= maximum and seals & required == required
        and target.startswith("/memfd:") and target.endswith(" (deleted)"))
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid,
        metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns, seals, target)


class _Original:
    __slots__ = ("fd", "raw", "identity", "maximum", "private")

    def __init__(self, descriptor, maximum, private=False):
        self.fd, self.maximum, self.private = descriptor, maximum, private
        self.identity = _identity(descriptor, maximum, private)
        raw = bytearray()
        while len(raw) < self.identity[6]:
            piece = os.pread(descriptor, min(4096, self.identity[6] - len(raw)), len(raw))
            _require(piece)
            raw.extend(piece)
        _require(not os.pread(descriptor, 1, len(raw)))
        self.raw = bytes(raw)
        self.check()

    def check(self):
        _require(_identity(self.fd, self.maximum, self.private) == self.identity
            and hmac.compare_digest(os.pread(self.fd, self.maximum + 1, 0), self.raw))


def _payload(value):
    _require(type(value) is dict and set(value) == _PAYLOAD_FIELDS
        and value["schema"] == ENROLLMENT_SCHEMA and value["providerId"] in {"google", "x"})
    _text(value["sourceRevision"], 128)
    for name in ("configurationDigest", "clientMaterialSha256", "providerConfigurationSha256"):
        _digest(value[name])
    for name in ("deploymentId", "applicationId", "providerFamilyNamespace"):
        _require(type(value[name]) is str and _IDENTIFIER.fullmatch(value[name]) is not None)
    _require(type(value["providerFamilyGeneration"]) is int and 1 <= value["providerFamilyGeneration"] <= 2**63 - 1)
    _text(value["clientId"], 2048)
    _text(value["redirectUri"], 4096)
    from urllib.parse import urlsplit
    redirect = urlsplit(value["redirectUri"])
    _require(redirect.scheme == "https" and redirect.hostname and redirect.username is None
        and redirect.password is None and not redirect.fragment)
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        _require(type(value[name]) is int and 0 < value[name] <= 2**63 - 1)
    _require(value["issuedAtEpochNs"] < value["expiresAtEpochNs"])
    return value


def _association(payload, envelope):
    return {"schema": ASSOCIATION_SCHEMA, "enrollmentSha256": _sha(envelope), **{
        name: payload[name] for name in ("deploymentId", "applicationId", "providerId",
            "providerFamilyNamespace", "providerFamilyGeneration", "clientId", "redirectUri",
            "providerConfigurationSha256")}}


def validate_association(value):
    """Closed data check only; callers still need the genuine cold owner."""
    _require(type(value) is dict and set(value) == _ASSOCIATION_FIELDS
        and value["schema"] == ASSOCIATION_SCHEMA and value["providerId"] in {"google", "x"})
    for name in ("enrollmentSha256", "providerConfigurationSha256"):
        _digest(value[name])
    for name in ("deploymentId", "applicationId", "providerFamilyNamespace"):
        _require(type(value[name]) is str and _IDENTIFIER.fullmatch(value[name]) is not None)
    _require(type(value["providerFamilyGeneration"]) is int and 1 <= value["providerFamilyGeneration"] <= 2**63 - 1)
    _text(value["clientId"], 2048)
    _text(value["redirectUri"], 4096)
    _require(len(canonical(value)) <= 8192)
    return value


def sign_enrollment(payload, signing_key):
    """Administrative producer only; possession is not assignment of a root role."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from serverware import authority_contract
    _payload(payload)
    _require(isinstance(signing_key, Ed25519PrivateKey)
        and payload["sourceRevision"] == authority_contract.SOURCE_REVISION)
    original = canonical(payload)
    signature = signing_key.sign(ENROLLMENT_SCHEMA.encode("ascii") + b"\0" + original)
    result = canonical({"schema": ENVELOPE_SCHEMA, "payload": json.loads(original),
        "signatureBase64Url": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")})
    _require(len(result) <= MAX_CONFIG_BYTES)
    return result


def provider_configuration(provider):
    """Exact source endpoint/flow configuration, excluding separately pinned secrets."""
    return {"providerId": provider.id, "authorizationUrl": provider.authorization_url,
        "tokenUrl": provider.token_url, "revocationUrl": provider.revocation_url,
        "identityUrl": provider.identity_url, "tokenAuth": provider.token_auth,
        "defaultScopes": list(provider.default_scopes), "authParams": provider.auth_params,
        "metadataProvider": provider.metadata_provider,
        "tokenResponseScopeOptional": provider.token_response_scope_optional}


class OAuthApplicationOwner:
    __slots__ = ("_custody", "_binding", "_originals", "_applications", "_identity", "_poisoned", "_closed",
        "_epoch", "_mono", "_deadline", "_expires", "_measured", "_setup", "_reconnect")

    def __init__(self):
        raise OAuthApplicationError("OAuth owner requires fixed cold admission")

    def __copy__(self):
        raise OAuthApplicationError("OAuth owner cannot be copied")

    def __deepcopy__(self, memo):
        raise OAuthApplicationError("OAuth owner cannot be copied")

    def check(self):
        _require(os.getpid() == _PID)
        with _LOCK:
            try:
                _require(_owner is self and _state == "started" and not self._closed and not self._poisoned
                    and _environment() == _namespace and (os.geteuid(), os.getegid()) == self._identity)
                from serverware import control_plane_custody_startup as custody
                from serverware import control_plane_custody_client as client
                _require(custody.require_started() is self._custody and client._snapshot(self._custody) is self._binding)
                now = client._receipt_now(self._binding)
                mono = time.monotonic_ns()
                _require(self._epoch <= now < self._expires and self._mono <= mono < self._deadline)
                for original in self._originals:
                    original.check()
                for payload, envelope, material, association in self._applications.values():
                    _require(payload["issuedAtEpochNs"] <= now < payload["expiresAtEpochNs"]
                        and canonical(payload) == canonical(_json(envelope, MAX_CONFIG_BYTES)["payload"])
                        and canonical(_association(payload, envelope)) == association)
                    if self._measured:
                        from serverware import native_oauth_refresh as confidential
                        confidential.application_header(_json(material.raw, MAX_ENCRYPTED_CLIENT_BYTES), payload, _sha(envelope))
                    else:
                        _require(_sha(material.raw) == payload["clientMaterialSha256"])
                closing = client._receipt_now(self._binding)
                closing_mono = time.monotonic_ns()
                _require(now <= closing < self._expires and mono <= closing_mono < self._deadline)
                self._epoch, self._mono = closing, closing_mono
                return now
            except BaseException:
                self._poisoned = True
                raise

    def parameters(self, provider_id):
        self.check()
        item = self._applications.get(provider_id)
        if item is None:
            return "", "", ""
        if self._measured:
            # Public source configuration only. Empty is NOT a synthetic
            # credential; all parent token-form/contact paths refuse below.
            return item[0]["clientId"], "", item[0]["redirectUri"]
        value = _json(item[2].raw, MAX_CLIENT_BYTES)
        return value["clientId"], value["clientSecret"], value["redirectUri"]

    def operation(self, provider):
        self.check()
        from serverware.oauth import OAuthProvider
        _require(type(provider) is OAuthProvider and provider.id in self._applications)
        return _Operation(self, provider)


class _Operation:
    __slots__ = ("owner", "provider", "_provider_original", "_association", "_pid", "_thread",
        "_epoch", "_mono", "deadline_ns", "expires_ns", "_poisoned")

    def __init__(self, owner, provider):
        self.owner, self.provider = owner, provider
        payload, _, _, association = owner._applications[provider.id]
        self._provider_original = canonical(provider_configuration(provider))
        _require(_sha(self._provider_original) == payload["providerConfigurationSha256"])
        self._association = association
        self._pid, self._thread = os.getpid(), threading.get_ident()
        self._epoch, self._mono = time.time_ns(), time.monotonic_ns()
        lifetime = min(MAX_OPERATION_NS, owner._binding.maximum_deadline_ns,
            payload["expiresAtEpochNs"] - self._epoch, owner._binding.attestation_interval[1] - self._epoch,
            owner._deadline - self._mono)
        _require(lifetime > 0)
        self.deadline_ns, self.expires_ns = self._mono + lifetime, self._epoch + lifetime
        self._poisoned = False
        self.check()

    def check(self):
        try:
            _require(not self._poisoned and (os.getpid(), threading.get_ident()) == (self._pid, self._thread))
            mono, epoch = time.monotonic_ns(), time.time_ns()
            _require(self._mono <= mono < self.deadline_ns and self._epoch <= epoch < self.expires_ns)
            self.owner.check()
            _require(canonical(provider_configuration(self.provider)) == self._provider_original
                and self.owner.parameters(self.provider.id) == (self.provider.client_id, self.provider.client_secret, self.provider.redirect_uri)
                and self.owner._applications[self.provider.id][3] == self._association)
            closing_mono, closing_epoch = time.monotonic_ns(), time.time_ns()
            _require(mono <= closing_mono < self.deadline_ns and epoch <= closing_epoch < self.expires_ns)
            self._mono, self._epoch = closing_mono, closing_epoch
        except BaseException:
            self._poisoned = True
            raise

    def association(self):
        self.check()
        return json.loads(self._association)

    def enrollment_original(self):
        self.check()
        return self.owner._applications[self.provider.id][1]

    def custody_owner(self):
        self.check()
        return self.owner._custody

    def require_parent_material(self):
        self.check()
        _require(not self.owner._measured)

    def require_association(self, value):
        self.check()
        validate_association(value)
        _require(hmac.compare_digest(canonical(value), self._association))
        self.check()

    def __copy__(self):
        raise OAuthApplicationError("OAuth operation cannot be copied")

    def __deepcopy__(self, memo):
        raise OAuthApplicationError("OAuth operation cannot be copied")

    def timeout(self, maximum=20):
        self.check()
        remaining = min(self.deadline_ns - time.monotonic_ns(), self.expires_ns - time.time_ns())
        _require(remaining > 0)
        return min(maximum, remaining / 1_000_000_000)


def initialize_from_environment():
    global _state, _namespace, _owner
    _require(os.getpid() == _PID)
    with _LOCK:
        if _state in {"started", "disabled"}:
            return require_started()
        _require(_state == "new")
        _state, _namespace = "initializing", _environment()
        try:
            if _development(_namespace):
                _state = "disabled"
                return None
            settings = _namespace[1]
            _require(len(settings) == 1 and settings[0][0] == CONFIG_FD_ENVIRONMENT)
            text = settings[0][1]
            _require(text.isascii() and text.isdecimal() and str(int(text)) == text)
            descriptor = _fd(int(text), minimum=3)
            from serverware import authority_contract
            from serverware import control_plane_custody_startup as custody
            from serverware import control_plane_custody_client as client
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            actual = custody.require_started()
            binding = client._snapshot(actual)
            _require(descriptor in binding.inherited_descriptors)
            opening = client._receipt_now(binding)
            opening_mono = time.monotonic_ns()
            admission_deadline = opening_mono + min(MAX_OPERATION_NS, binding.maximum_deadline_ns,
                binding.attestation_interval[1] - opening)
            config_original = _Original(descriptor, MAX_CONFIG_BYTES)
            config = _json(config_original.raw, MAX_CONFIG_BYTES)
            _require(type(config) is dict and set(config) == ({"schema", "sourceRevision", "configurationDigest",
                "authorityRootFd", "authorityRootSha256", "applications"} | ({"reconnect"} if config.get("schema") == RECONNECT_STARTUP_SCHEMA else set()))
                and config["schema"] in {STARTUP_SCHEMA, MEASURED_STARTUP_SCHEMA, SETUP_STARTUP_SCHEMA, RECONNECT_STARTUP_SCHEMA} and config["sourceRevision"] == authority_contract.SOURCE_REVISION
                and config["configurationDigest"] == binding.configuration_digest
                and type(config["applications"]) is list and len(config["applications"]) <= 2)
            originals, applications, used = [config_original], {}, {descriptor}
            root = None
            if config["applications"]:
                root_fd = _fd(config["authorityRootFd"])
                _require(root_fd not in used and root_fd in binding.inherited_descriptors)
                used.add(root_fd)
                original = _Original(root_fd, MAX_ROOT_BYTES)
                originals.append(original)
                _require(_sha(original.raw) == _digest(config["authorityRootSha256"]))
                root = serialization.load_pem_public_key(original.raw)
                _require(isinstance(root, Ed25519PublicKey) and root.public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == original.raw)
                root_der = root.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                runtime_der = binding.runtime_root_public_key.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                _require(root_der != runtime_der)
            else:
                _require(config["authorityRootFd"] is None and config["authorityRootSha256"] is None)
            for item in config["applications"]:
                client._receipt_now(binding)
                _require(time.monotonic_ns() < admission_deadline)
                _require(type(item) is dict and set(item) == {"enrollment", "clientMaterialFd"})
                envelope = item["enrollment"]
                _require(type(envelope) is dict and set(envelope) == {"schema", "payload", "signatureBase64Url"}
                    and envelope["schema"] == ENVELOPE_SCHEMA)
                payload = _payload(envelope["payload"])
                _require(payload["sourceRevision"] == authority_contract.SOURCE_REVISION
                    and payload["configurationDigest"] == binding.configuration_digest
                    and payload["issuedAtEpochNs"] <= opening < payload["expiresAtEpochNs"]
                    and payload["providerId"] not in applications)
                signature_text = envelope["signatureBase64Url"]
                _require(type(signature_text) is str and re.fullmatch(r"[A-Za-z0-9_-]{86}", signature_text))
                signature = base64.urlsafe_b64decode(signature_text + "==")
                _require(base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii") == signature_text)
                root.verify(signature, ENROLLMENT_SCHEMA.encode("ascii") + b"\0" + canonical(payload))
                material_fd = _fd(item["clientMaterialFd"])
                _require(material_fd not in used and material_fd in binding.inherited_descriptors)
                used.add(material_fd)
                measured = config["schema"] in {MEASURED_STARTUP_SCHEMA, SETUP_STARTUP_SCHEMA, RECONNECT_STARTUP_SCHEMA}
                material = _Original(material_fd, MAX_ENCRYPTED_CLIENT_BYTES if measured else MAX_CLIENT_BYTES, True)
                originals.append(material)
                raw_envelope = canonical(envelope)
                if measured:
                    from serverware import native_oauth_refresh as confidential
                    confidential.application_header(_json(material.raw, MAX_ENCRYPTED_CLIENT_BYTES), payload, _sha(raw_envelope))
                else:
                    _require(_sha(material.raw) == payload["clientMaterialSha256"])
                    value = _json(material.raw, MAX_CLIENT_BYTES)
                    _require(type(value) is dict and set(value) == {"schema", "providerId", "clientId", "clientSecret", "redirectUri"}
                        and value["schema"] == CLIENT_SCHEMA and value["providerId"] == payload["providerId"]
                        and value["clientId"] == payload["clientId"] and value["redirectUri"] == payload["redirectUri"])
                    _text(value["clientSecret"], 8192)
                association = _association(payload, raw_envelope)
                validate_association(association)
                applications[payload["providerId"]] = (payload, raw_envelope, material, canonical(association))
            reconnect = None
            if config["schema"] == RECONNECT_STARTUP_SCHEMA:
                from serverware.oauth_reconnect_owner import admit
                reconnect = admit(config, binding=binding, used=used, originals=originals, applications=applications,
                    enrollment_key=root, opening=opening, source_revision=authority_contract.SOURCE_REVISION)
            client._receipt_now(binding)
            _require(time.monotonic_ns() < admission_deadline)
            value = object.__new__(OAuthApplicationOwner)
            value._custody, value._binding = actual, binding
            value._originals, value._applications = tuple(originals), applications
            value._measured = config["schema"] in {MEASURED_STARTUP_SCHEMA, SETUP_STARTUP_SCHEMA, RECONNECT_STARTUP_SCHEMA}
            value._setup = config["schema"] == SETUP_STARTUP_SCHEMA
            value._reconnect = reconnect
            value._identity = os.geteuid(), os.getegid()
            value._expires = min([binding.attestation_interval[1]]
                + [entry[0]["expiresAtEpochNs"] for entry in applications.values()])
            value._epoch, value._mono = opening, opening_mono
            value._deadline = opening_mono + value._expires - opening
            value._poisoned = value._closed = False
            _owner, _state = value, "started"
            value.check()
            return value
        except BaseException:
            _state = "failed"
            raise


def require_started():
    _require(os.getpid() == _PID)
    with _LOCK:
        namespace = _environment()
        if _state == "new" and _development(namespace):
            return None
        _require(namespace == _namespace)
        if _state == "disabled":
            _require(_development(namespace))
            return None
        _require(_state == "started" and type(_owner) is OAuthApplicationOwner)
        _owner.check()
        return _owner


def setup_selected(provider_id):
    owner = require_started()
    if owner is None:
        return False
    owner.check()
    return owner._setup and provider_id in owner._applications


def setup_profile_selected():
    owner = require_started()
    if owner is None:
        return False
    owner.check()
    return owner._setup


def measured_selected(provider_id):
    owner = require_started()
    if owner is None:
        return False
    owner.check()
    return owner._measured and provider_id in owner._applications


def require_parent_material(provider_id):
    _require(not measured_selected(provider_id))


def parameters(provider_id, legacy):
    owner = require_started()
    return legacy if owner is None else owner.parameters(provider_id)


def begin(provider, *, association=None):
    owner = require_started()
    if owner is None:
        _require(association is None)
        return None
    operation = owner.operation(provider)
    if association is not None:
        operation.require_association(association)
    return operation


def bound(provider, association, operation=None):
    """Join serialized association to actual cold ownership; data is not authority."""
    owner = require_started()
    if owner is None:
        _require(association is None and operation is None)
        return None
    _require(association is not None)
    if operation is None:
        operation = owner.operation(provider)
    _require(type(operation) is _Operation and operation.owner is owner
        and operation.provider == provider)
    operation.require_association(association)
    return operation


def close():
    global _state
    _require(os.getpid() == _PID)
    with _LOCK:
        if _owner is not None:
            _owner._closed = True
        _state = "closed"
