"""Real bounded HTTP owner for pre-subject capture retirement; ciphertext only."""
import os
import threading
import time

from fastapi import Request
from catchplate import authority_contract
from catchplate import authority_oauth_measured_capture_retirement as profile
from catchplate import control_plane_custody_client as client
from catchplate import control_plane_custody_startup as startup
from catchplate.control_plane_approval_verification import _request_pin

MAX_REQUEST, MAX_RESPONSE = profile.MAX_HTTP_REQUEST, profile.MAX_HTTP_RESPONSE


class Opening:
    def __init__(self, request, raw):
        profile.require(type(request) is Request and request.method == "POST"
            and request.url.path == profile.HTTP_PATH and not request.url.query)
        self.request, self.scope, self.pin = request, request.scope, _request_pin(request)
        self.original = raw
        self.value = profile.document(raw, MAX_REQUEST)
        profile.require(set(self.value) == profile.HTTP_REQUEST_FIELDS and self.value["apiVersion"] == profile.HTTP_SCHEMA)
        self.operation = self.value["operation"]
        self.arguments = profile.arguments(self.operation, self.value["arguments"])
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.mono, self.epoch = time.monotonic_ns(), time.time_ns()
        statement = self.arguments["evidence"]["statement"]
        self.expires = min(statement["expiresAtEpochNs"], self.epoch + 30_000_000_000)
        self.deadline = self.mono + self.expires - self.epoch
        self.custody = startup.require_started()
        profile.require(self.custody is not None and startup.credential_broker_selected())
        self.binding = client._snapshot(self.custody)
        profile.require(self.arguments["control_plane_configuration_digest"] == self.binding.configuration_digest)
        self.poisoned, self.dispatched = False, False
        self.check()

    def check(self):
        try:
            mono, epoch = time.monotonic_ns(), time.time_ns()
            profile.require(not self.poisoned and (os.getpid(), threading.get_ident()) == (self.pid, self.thread)
                and self.mono <= mono < self.deadline and self.epoch <= epoch < self.expires
                and self.request.scope is self.scope and _request_pin(self.request) == self.pin
                and profile.canonical(self.value) == self.original and startup.require_started() is self.custody
                and client._snapshot(self.custody) is self.binding
                and self.binding.configuration_digest == self.arguments["control_plane_configuration_digest"])
            client._receipt_now(self.binding)
            self.mono, self.epoch = mono, epoch
        except BaseException:
            self.poisoned = True
            raise

    def dispatch(self):
        self.check(); profile.require(not self.dispatched); self.dispatched = True
        request_original, response_original = client.ControlPlaneCustodyClient._request_measured_capture_retirement(self.custody,
            operation=self.operation, input_value={"schema": "catchplate.policyAuthorityControlledWriterInput/v1",
                "handler": authority_contract.operation_spec(self.operation)["handler"],
                "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST, "arguments": self.arguments},
            deadline_ns=self.deadline)
        self.check()
        response = profile.document(response_original, 6 * 1024 * 1024)
        result = response["result"]
        profile.require(response["schema"] == profile.RUNTIME_RESPONSE and set(result) == profile.RESULT_FIELDS
            and result["ok"] is True and result["operation"] == self.operation and result["idempotentReplay"] is False
            and result["requestDigest"] == profile.request_digest(self.operation, self.arguments))
        barriers = None
        if self.operation == profile.OP_INSPECT:
            payload = result["payload"]
            profile.require(set(payload) == profile.OBSERVATION_FIELDS and payload["status"] == "ready"
                and payload["journalOriginal"] is None and payload["custodyOriginal"] is None and payload["attemptOriginals"] == [])
            from catchplate import control_plane_credential_currentness as currentness
            barriers = currentness.admit_capture_retirement_barriers(self, payload["affectedLineages"])
        self.check()
        value = {"apiVersion": profile.HTTP_RESPONSE, "requestOriginal": profile.b64(request_original),
            "responseOriginal": profile.b64(response_original), "currentnessBarriers": barriers}
        profile.require(set(value) == profile.HTTP_RESPONSE_FIELDS and len(profile.canonical(value)) <= MAX_RESPONSE)
        return value


def on_request(request, raw):
    return Opening(request, raw).dispatch()
