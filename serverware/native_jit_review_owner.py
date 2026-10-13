"""Purpose-fixed JIT sealing on the retained broker's private FD3 dispatcher.

The broker supplies its existing provisioned key and completed service-token
owner. This constructor does not independently authenticate cold configuration
or admit a native identity. The measured parent must supply those original
owners and authorize this distinct purpose; a caller verdict cannot replace
that admission. Connecting this private channel is not a native-proof or RPC
authorization path.

Only the exact private-v2 JIT request, standalone or derived with its exact
native release.reserve parent, can be sealed. The unsigned preparation is not
attestation, approval, opaque-value evidence, persistence or a commit.
Actual native-caller admission, signing, proof verification and writer
retention remain missing. There is deliberately no open/review/release handler
until authenticated current read authority is implemented. Attempts are never
renewed, reconstructed or retried after uncertain output. Python allocations
do not provide a complete plaintext-erasure guarantee.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from serverware import authority_contract as contract
from serverware import authority_jit_private_request as private
from serverware import authority_jit_request as request_profile
from serverware import authority_release_private_request as release_private
from serverware import native_jit_review_material as material
from serverware import native_oauth_refresh as codec
from serverware.native_oauth_refresh_owner import IDENTITY_FIELDS

CHANNEL = "serverware.nativeJitReviewChannel/v1"
CONFIG = "serverware.nativeJitReviewConfiguration/v1"
MAX_ATTEMPTS = 16
MAX_COMMAND_BYTES = 512 * 1024
_CONFIG_FIELDS = frozenset({"apiVersion", "sourceContractDigest",
    "controlPlaneConfigurationDigest", "deploymentId", "instanceId",
    "secretKekId", "identity", "attemptCapacity"})
_SEAL_FIELDS = frozenset({"apiVersion", "phase", "runtimeInput", "publicRequest",
    "issuedAtEpochNs", "sealExpiresAtEpochNs", "documentExpiresAtEpochNs",
    "deadlineBoottimeNs", "challenge"})
_RELEASE_SEAL_FIELDS = _SEAL_FIELDS | {"parentRequest"}
_RELEASE_FLOAT_ROOTS = tuple(root + (field,)
    for root in (("runtimeInput", "arguments"), ("parentRequest", "arguments"),
        ("parentRequest", "arguments", "businessIntent", "arguments"))
    for field in ("operation_context", "durable_policy_binding", "shared_quotas"))


class OwnerError(ValueError):
    pass


def _require(value):
    if not value:
        raise OwnerError("native JIT review owner unavailable")


def _bounded_json(value, *, private_floats=False, release_pair=False):
    # Shared with the private channel decoder. Public/control fields retain
    # integer-only JSON numbers. Compound release public JSON admits finite
    # floats only at its existing profile's three exact value roots; that is
    # representation preservation, never admission of these public claims.
    _require(type(private_floats) is bool and type(release_pair) is bool)
    _require(type(value) is dict)
    _require(not release_pair or value.get("apiVersion") == CHANNEL
        and value.get("phase") == "seal-release-pair")
    pending, count = [(value, ())], 0
    while pending:
        item, path = pending.pop()
        count += 1
        _require(len(path) <= 32 and count <= 131072)
        if type(item) is dict:
            _require(all(type(key) is str for key in item))
            pending.extend((child, path + (key,)) for key, child in item.items())
        elif type(item) is list:
            pending.extend((child, path + (index,)) for index, child in enumerate(item))
        else:
            _require(item is None or type(item) in (bool, int, str)
                or type(item) is float and math.isfinite(item)
                and (private_floats and path[:3] in (
                    ("runtimeInput", "privateDocuments", "canonical_request"),
                    ("runtimeInput", "privateDocuments", "redacted_display"))
                    or release_pair and any(path[:len(root)] == root for root in _RELEASE_FLOAT_ROOTS)))


def _copy(value, maximum, *, private_floats=False, release_pair=False):
    # Copy only JSON; never retain a caller's mutable graph. The actual private
    # request validators below retain their own depth and aggregate bounds.
    _bounded_json(value, private_floats=private_floats, release_pair=release_pair)
    raw = material.canonical(value)
    _require(0 < len(raw) <= maximum)
    return json.loads(raw)


def _identity(value):
    _require(type(value) is dict and set(value) == IDENTITY_FIELDS)
    boot = codec.decoded(value["bootId"], 32, 32)
    _require(boot != bytes(32))
    for name in IDENTITY_FIELDS - {"bootId"}:
        codec.digest(value[name])
    expected = hashlib.sha256(b"serverware/credential-currentness-holder/v1\0"
        + boot + bytes.fromhex(value["keyId"][7:])).hexdigest()
    _require(value["holderId"] == "sha256:" + expected)


class Owner:
    def __init__(self, broker, value):
        self._poisoned = True
        try:
            broker.require_owner_configuration()
            _require(type(value) is dict
                and set(value) == {"apiVersion", "phase", "configuration"}
                and value["apiVersion"] == CHANNEL and value["phase"] == "configure"
                and type(broker.kek) is AESGCM and broker.rsa is None
                and broker.service_tokens_opened is True)
            config = _copy(value["configuration"], 32768)
            _require(set(config) == _CONFIG_FIELDS and config["apiVersion"] == CONFIG
                and config["sourceContractDigest"] == contract.OPERATION_MANIFEST_DIGEST)
            codec.digest(config["sourceContractDigest"])
            codec.digest(config["controlPlaneConfigurationDigest"])
            codec.digest(broker.commitment)
            _require(config["secretKekId"] == broker.key_id
                == "attested-memory-kek:" + broker.commitment[7:31])
            _require(type(config["deploymentId"]) is str
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", config["deploymentId"]) is not None)
            codec.text(config["instanceId"], 4096)
            _require(config["instanceId"].startswith("spiffe://")
                and not any(ord(char) < 33 or ord(char) == 127 for char in config["instanceId"]))
            codec.integer(config["attemptCapacity"], maximum=MAX_ATTEMPTS)
            _identity(config["identity"])
            self.broker, self.config = broker, config
            self._channel, self._kek, self._key_id = broker.channel, broker.kek, broker.key_id
            self._commitment, self._channel_deadline = broker.commitment, broker.channel.deadline
            codec.integer(self._channel_deadline, maximum=2**64 - 1)
            self._config_original = material.canonical(config)
            self.owner_scope_digest = material.sha256(self._config_original)
            self._pid = os.getpid()
            self._wall_clock, self._boot_clock = time.time_ns, time.clock_gettime_ns
            self._last_wall = self._wall_clock()
            self._last_boot = self._boot_clock(time.CLOCK_BOOTTIME)
            self._spent, self.operation = set(), None
            self._poisoned = False
            self.check()
            self._channel.send({"apiVersion": CHANNEL, "phase": "configured"})
            self.check()
        except BaseException as error:
            self._poisoned = True
            if isinstance(error, Exception):
                raise OwnerError("native JIT review owner unavailable") from None
            raise

    def check(self, deadline=None):
        try:
            return self._check(deadline)
        except BaseException as error:
            self._poisoned = True
            if isinstance(error, Exception):
                raise OwnerError("native JIT review owner unavailable") from None
            raise

    def _check(self, deadline=None):
        _require(not self._poisoned and os.getpid() == self._pid
            and self.broker.channel is self._channel and self.broker.kek is self._kek
            and self.broker.key_id == self._key_id and self.broker.commitment == self._commitment
            and self.broker.rsa is None and self.broker.service_tokens_opened is True
            and self._channel.deadline == self._channel_deadline
            and material.canonical(self.config) == self._config_original
            and self.owner_scope_digest == material.sha256(self._config_original))
        if deadline is not None:
            codec.integer(deadline, maximum=2**64 - 1)
        self._channel.check(deadline)
        wall, boot = self._wall_clock(), self._boot_clock(time.CLOCK_BOOTTIME)
        _require(type(wall) is int and type(boot) is int
            and 0 < self._last_wall <= wall and 0 < self._last_boot <= boot
            and boot < min(self._channel_deadline, deadline or self._channel_deadline))
        self._last_wall, self._last_boot = wall, boot
        return wall, boot

    def handle(self, value):
        try:
            self.check()
            _require(self.operation is None)
            release_pair = type(value) is dict and value.get("phase") == "seal-release-pair"
            self._seal_pair(_copy(value, MAX_COMMAND_BYTES,
                private_floats=True, release_pair=release_pair))
        except BaseException as error:
            # A partial ciphertext reply may already have escaped. Neither
            # expiry, a caught exception nor a missing reply rearms this owner.
            self._poisoned = True
            if isinstance(error, Exception):
                raise OwnerError("native JIT review owner unavailable") from None
            raise

    def _seal_pair(self, value):
        release_pair = value.get("phase") == "seal-release-pair"
        _require(set(value) == (_RELEASE_SEAL_FIELDS if release_pair else _SEAL_FIELDS)
            and value["apiVersion"] == CHANNEL
            and value["phase"] == ("seal-release-pair" if release_pair else "seal-pair")
            and len(self._spent) < self.config["attemptCapacity"])
        parent_bindings = {}
        if release_pair:
            public, documents = release_private.validate_runtime_input(value["runtimeInput"])
            derived = release_private.derive_native_requests(value["runtimeInput"])
            parent, request = derived.parent_request, derived.child_request
            # Keep the complete owned originals. Neither matching a child nor
            # accepting caller-supplied parent digests can replace these joins.
            parent_raw = material.canonical(parent)
            _require(material.canonical(value["parentRequest"]) == parent_raw
                and material.canonical(value["publicRequest"]) == material.canonical(request)
                and parent["operationManifestDigest"] == self.config["sourceContractDigest"])
            parent_bindings = {"parentRequestSha256": material.sha256(parent_raw),
                "parentRequestDigest": parent["requestDigest"], "parentOperationId": parent["operationId"]}
            public = public["jit_approval_request"]
        else:
            public, documents = private.validate_runtime_input(value["runtimeInput"])
            request = value["publicRequest"]
        request_profile.require_public_request(request)
        expected_arguments = {**public,
            "businessIntent": contract.synthesize_business_intent("jit.request", public)}
        _require(material.canonical(request["arguments"]) == material.canonical(expected_arguments)
            and public["policy_hash"] == self.config["identity"]["policyHash"]
            and request["operationManifestDigest"] == self.config["sourceContractDigest"]
            and request["requestDigest"] not in self._spent)
        challenge = codec.decoded(value["challenge"], 32, 32)
        _require(challenge != bytes(32))
        issued = codec.integer(value["issuedAtEpochNs"])
        seal_expires = codec.integer(value["sealExpiresAtEpochNs"])
        document_expires = codec.integer(value["documentExpiresAtEpochNs"])
        requested_deadline = codec.integer(value["deadlineBoottimeNs"], maximum=2**64 - 1)
        wall, boot = self.check()
        _require(issued <= wall < seal_expires <= document_expires
            and seal_expires - issued <= 30_000_000_000
            and document_expires <= issued + public["pending_ttl_seconds"] * 1_000_000_000)
        # Freeze both clocks once. Every later check uses these same bounds;
        # no material call or output can restart the pending TTL or seal window.
        deadline = min(requested_deadline, self._channel_deadline,
            boot + seal_expires - wall, boot + 30_000_000_000)
        _require(boot < deadline)
        document_expires = min(document_expires, wall + self._channel_deadline - boot)
        seal_expires = min(seal_expires, document_expires, wall + deadline - boot)
        scope = {"schema": "serverware.nativeJitReviewScope/v1", "publicRequest": request,
            "sourceContractDigest": self.config["sourceContractDigest"],
            "controlPlaneConfigurationDigest": self.config["controlPlaneConfigurationDigest"],
            "ownerScopeDigest": self.owner_scope_digest, "issuedAtEpochNs": issued,
            "sealExpiresAtEpochNs": seal_expires, "documentExpiresAtEpochNs": document_expires}
        if release_pair:
            scope.update(schema=material.RELEASE_SCOPE_SCHEMA,
                parentRequestSha256=parent_bindings["parentRequestSha256"])
        operation = _Window(self, issued, seal_expires, deadline)
        self.operation = operation
        operation.check()
        # Fence before encryption and the first output byte. A repeated public
        # child is never re-encrypted, including across standalone/compound
        # commands or different parents, even if the first result was uncertain.
        self._spent.add(request["requestDigest"])
        try:
            seal = material.seal_release_pair if release_pair else material.seal_pair
            pair = seal(scope, documents, key_id=self._key_id,
                kek=self._kek, now_epoch_ns=wall)
        finally:
            del documents
        operation.check()
        bindings = {"sourceContractDigest": scope["sourceContractDigest"],
            "controlPlaneConfigurationDigest": scope["controlPlaneConfigurationDigest"],
            "ownerScopeDigest": self.owner_scope_digest,
            "deploymentId": self.config["deploymentId"], "instanceId": self.config["instanceId"],
            "requestDigest": request["requestDigest"], "operationId": request["operationId"],
            "publicRequestSha256": material.sha256(material.canonical(request)),
            "pairSha256": material.sha256(material.canonical(pair)), "secretKekId": self._key_id,
            "challenge": value["challenge"], "issuedAtEpochNs": issued,
            "expiresAtEpochNs": seal_expires, "documentExpiresAtEpochNs": document_expires,
            **self.config["identity"], **parent_bindings}
        self._channel.send({"apiVersion": CHANNEL,
            "phase": "prepared-release-pair" if release_pair else "prepared",
            "operation": "release.reserve" if release_pair else "jit.request",
            "pair": pair, "statementBindings": bindings}, deadline)
        operation.check()
        self.operation = None


class _Window:
    def __init__(self, owner, issued, expires, deadline):
        self.owner, self.issued, self.expires, self.deadline = owner, issued, expires, deadline

    def check(self):
        wall, _ = self.owner.check(self.deadline)
        _require(self.owner.operation is self and self.issued <= wall < self.expires)
