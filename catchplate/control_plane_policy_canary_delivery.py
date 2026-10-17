"""Actual workload-TLS delivery opening and exact signed-original return.

No local SELECT, JSON success flag, lost ACK or fresh request identifier can
authorize contact. The source-selected native consumer must verify the full
purpose response and retain its one-attempt owner before sending intake.
"""
import base64
import os
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import authority_contract as contract
from catchplate import authority_policy_canary_delivery as profile
from catchplate import authority_policy_canary_delivery_policy as policy
from catchplate import authority_policy_canary_delivery_completion as completion
from catchplate import authority_request_commitment as commitment
from catchplate import control_plane_custody_client as custody
from catchplate import control_plane_policy_canary_startup as startup

PATH, MAX_REQUEST = profile.PATH, profile.MAX_ARGUMENT


def _encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class _Opening:
    def __init__(self, request, raw):
        from catchplate.control_plane_approval_verification import _request_pin
        self.owner = startup.delivery_owner()
        profile.require(request.method == "POST" and request.url.path == PATH and not request.scope.get("query_string")
            and request.headers.get("content-type") == "application/json" and type(raw) is bytes and len(raw) <= MAX_REQUEST)
        self.value = profile.document(raw, MAX_REQUEST)
        profile.require(set(self.value) == {"apiVersion", "operation", "request", "nativeEvidence"} and self.value["apiVersion"] == profile.HTTP_SCHEMA)
        self.operation = self.value["operation"]
        self.arguments = profile.arguments(self.operation, {"control_plane_configuration_digest": self.owner.configuration_digest,
            "request": self.value["request"], "native_evidence": self.value["nativeEvidence"]})
        self.request, self.scope, self.pin = request, request.scope, _request_pin(request)
        self.peer = request.scope.get(startup.PEER_SCOPE)
        profile.require(type(self.peer) is startup._Peer)
        self.original, self.arguments_original = raw, profile.canonical(self.arguments)
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.started, now = time.monotonic_ns(), self.owner.check()
        self.signed = self.arguments["native_evidence"]["statement"]
        self.expires = min(self.signed["expiresAtEpochNs"], self.owner.delivery_policy["expiresAtEpochNs"])
        self.deadline = min(self.owner.deadline, self.started + self.expires - now)
        self.dispatched, self.poisoned = False, False
        self.peer.check()
        policy.verify_original(self.operation, self.arguments, configuration_payload=self.owner.payload,
            root_key=self.owner.root, now_epoch_ns=now, peer_der=self.peer.original)
        self.check()

    def check(self):
        from catchplate.control_plane_approval_verification import _request_pin
        try:
            profile.require(not self.poisoned and (os.getpid(), threading.get_ident()) == (self.pid, self.thread)
                and startup.delivery_owner() is self.owner and self.request.scope is self.scope
                and self.scope.get(startup.PEER_SCOPE) is self.peer and _request_pin(self.request) == self.pin
                and self.arguments["native_evidence"]["statement"] is self.signed
                and profile.canonical(self.value) == self.original and profile.canonical(self.arguments) == self.arguments_original)
            now = self.owner.check(); self.peer.check()
            profile.require(self.started <= time.monotonic_ns() < self.deadline and self.signed["issuedAtEpochNs"] <= now < self.expires)
            return now
        except BaseException:
            self.poisoned = True
            raise

    def dispatch(self):
        self.check(); profile.require(not self.dispatched)
        self.dispatched = True
        original_request, original_response = custody.ControlPlaneCustodyClient._request_canary_delivery(self.owner.custody,
            operation=self.operation, input_value={"schema": "catchplate.policyAuthorityControlledWriterInput/v1",
                "handler": contract.operation_spec(self.operation)["handler"], "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
                "arguments": self.arguments}, deadline_ns=self.deadline)
        now = self.check()
        completion.check_emitted_bounds(self.operation, original_request, original_response)
        response = profile.document(original_response, profile.MAX_RESPONSE)
        profile.require(set(response) == completion.RUNTIME_FIELDS and response["schema"] == profile.RESPONSE_SCHEMA
            and response["operation"] == self.operation and response["configurationDigest"] == self.owner.configuration_digest
            and profile.decoded(response["authorityConfigurationOriginal"], startup.AUTHORITY_MAX) == self.owner.originals[2].raw
            and response["issuedAtEpochNs"] <= now)
        # This is the independent public authority-root join missing from the
        # runtime-trust transport. Only its actual retained cold owner supplies
        # these bytes and keys; neither request headers nor JSON select them.
        configuration = profile.document(self.owner.originals[2].raw, startup.AUTHORITY_MAX, exact=False)
        self.owner.root.verify(profile.decoded(configuration["signature"], 64, length=64),
            commitment.framed_digest(startup.SIGNED_AUTHORITY_SCHEMA, profile.canonical(configuration["payload"])).encode("ascii"))
        key = Ed25519PublicKey.from_public_bytes(profile.decoded(self.owner.payload["roles"]["verifier"]["signingPublicKeyBase64Url"], 32, length=32))
        completion._verify_signed(response, key, profile.RESPONSE_SCHEMA)
        result = profile.result(response["result"])
        profile.require(result["requestDigest"] == profile.request_digest(self.operation, self.arguments))
        value = {"apiVersion": profile.HTTP_RESPONSE_SCHEMA, "requestOriginal": _encoded(original_request), "responseOriginal": _encoded(original_response)}
        profile.require(len(profile.canonical(value)) <= profile.MAX_RESPONSE)
        self.check()
        return value


def on_request(request, raw):
    return _Opening(request, raw).dispatch()
