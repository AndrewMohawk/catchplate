"""Actual custody dispatch and bounded read-only succession observations."""
import os
import threading
import time
from fastapi import Request
from catchplate import db
from catchplate import authority_oauth_retirement_succession as p
from catchplate import authority_oauth_retirement_succession_records as rows
from catchplate import authority_oauth_retirement_succession_snapshots as snapshots
from catchplate import authority_oauth_exchange as exchange
from catchplate import control_plane_custody_client as client
from catchplate import control_plane_custody_startup as startup
from catchplate import control_plane_oauth_measured_exchange as measured
from catchplate import control_plane_oauth_activation as activation
from catchplate import oauth_retirement_succession_owner as cold
from catchplate.control_plane_approval_verification import _request_pin

OBSERVATION_SCHEMA = "catchplate.oauthRetiredScopeSuccessionObservation/v1"
HUMAN_RESULT_SCHEMA = "catchplate.oauthRetiredScopeSuccessionResult/v1"
INTENT_RESPONSE = "catchplate.nativeOAuthSuccessionIntentResponse/v1"


def body(request, raw, path):
    p.require(cold.selected() and type(request) is Request and request.method == "POST"
        and request.url.path == path and not request.url.query)
    return p.document(raw, p.MAX_HTTP_REQUEST)


def read(identifier):
    """Acquisition only. Every effect independently re-admits protected rows."""
    p.identifier(identifier)
    with db.connect() as connection:
        journal = connection.execute("SELECT * FROM oauth_retirement_successions WHERE id = ?", (identifier,)).fetchone()
        scope = connection.execute("SELECT * FROM oauth_retirement_scopes WHERE id = ?", (identifier,)).fetchone()
        custody = connection.execute("SELECT * FROM oauth_measured_succession_custody WHERE id = ?", (identifier,)).fetchone()
        exchanged = connection.execute("SELECT * FROM oauth_exchange_reservations WHERE id = ?", (identifier,)).fetchone()
        parts = connection.execute("SELECT * FROM oauth_retirement_succession_snapshots WHERE authorization_id = ? ORDER BY part LIMIT 29", (identifier,)).fetchall()
        claims = connection.execute("SELECT * FROM oauth_retirement_succession_materials WHERE scope_id = ? ORDER BY material_id LIMIT 17", (identifier,)).fetchall()
        attempts = connection.execute("SELECT * FROM oauth_retirement_succession_attempts WHERE scope_id = ? ORDER BY material_id, token_purpose LIMIT 33", (identifier,)).fetchall()
    journal, scope, custody, exchanged = (None if item is None else dict(item) for item in (journal, scope, custody, exchanged))
    p.require(len(parts) <= 28 and len(claims) <= p.MAX_MATERIALS and len(attempts) <= 2 * p.MAX_MATERIALS)
    parts, claims, attempts = ([dict(item) for item in values] for values in (parts, claims, attempts))
    for value, codec in ((journal, rows.journal_original), (scope, rows.scope_original), (custody, rows.custody_original), (exchanged, exchange.row_original)):
        if value is not None:
            codec(value)
    for item in parts:
        snapshots.original(item)
    for item in claims:
        rows.material_original(item)
    for item in attempts:
        rows.attempt_original(item)
    p.require(journal is not None or not parts and scope is None and custody is None and exchanged is None and not claims and not attempts)
    p.require(custody is None or scope is not None and exchanged is not None)
    return journal, scope, custody, exchanged, parts, claims, attempts


def write(owner, operation, arguments):
    owner.check()
    request, response = client.ControlPlaneCustodyClient._request_retired_scope_succession(owner.custody,
        operation=operation, input_value=measured._input(operation, arguments), deadline_ns=owner.deadline)
    owner.check(); signed = p.document(response, p.MAX_RUNTIME_RESPONSE); result = signed["result"]
    p.require(set(result) == rows.RESULT_FIELDS and result["ok"] is True and result["operation"] == operation
        and result["idempotentReplay"] is False and result["requestDigest"] == p.request_digest(operation,
            {key: value for key, value in arguments.items() if key != "authn_evidence"})
        and type(result["originals"]) is dict and set(result["originals"]) == rows.ORIGINALS_FIELDS
        and type(result["observation"]) is dict and set(result["observation"]) == rows.OBSERVATION_FIELDS)
    p.digest(result["auditEventDigest"])
    return request, response, result


def public_result(result, *, snapshot_parts=()):
    observation = result["observation"]
    return {"apiVersion": HUMAN_RESULT_SCHEMA, "ok": True, "operation": result["operation"],
        "requestDigest": result["requestDigest"], "auditEventDigest": result["auditEventDigest"],
        "status": observation["status"], "approval": observation["approval"],
        "materialClosureSha256": observation["closureSha256"], "snapshotParts": list(snapshot_parts)}


class Opening:
    """One same-request native proof; historical applications are not aliases."""
    def __init__(self, request, raw):
        self.value = body(request, raw, p.HTTP_PATH)
        p.require(set(self.value) == {"apiVersion", "operation", "arguments"} and self.value["apiVersion"] == p.HTTP_SCHEMA
            and self.value["operation"] in p.NATIVE_OPERATIONS)
        self.operation = self.value["operation"]; self.arguments = p.arguments(self.operation, self.value["arguments"])
        self.application_owner, self.grant_raw = cold.original(self.arguments["resource_id"])
        p.require(p.encoded(self.grant_raw) == self.arguments["authorization_original"])
        self.request, self.scope, self.pin, self.original = request, request.scope, _request_pin(request), raw
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.mono, self.epoch = time.monotonic_ns(), time.time_ns()
        self.expires = min(self.arguments["native_evidence"]["statement"]["expiresAtEpochNs"], self.epoch + 30_000_000_000)
        self.deadline = self.mono + self.expires - self.epoch
        self.custody = startup.require_started(); p.require(self.custody is not None and startup.credential_broker_selected())
        self.binding = client._snapshot(self.custody); self.sent = self.poisoned = False
        self.check()

    def __copy__(self):
        raise ValueError("native succession request cannot be copied")

    def __deepcopy__(self, memo):
        raise ValueError("native succession request cannot be copied")

    def check(self):
        try:
            mono, epoch = time.monotonic_ns(), time.time_ns()
            actual, raw = cold.original(self.arguments["resource_id"])
            p.require(not self.poisoned and (os.getpid(), threading.get_ident()) == (self.pid, self.thread)
                and self.mono <= mono < self.deadline and self.epoch <= epoch < self.expires
                and actual is self.application_owner and raw == self.grant_raw
                and self.request.scope is self.scope and _request_pin(self.request) == self.pin
                and p.canonical(self.value) == self.original and startup.require_started() is self.custody
                and client._snapshot(self.custody) is self.binding
                and self.binding.configuration_digest == self.arguments["control_plane_configuration_digest"])
            client._receipt_now(self.binding); self.mono, self.epoch = mono, epoch
        except BaseException:
            self.poisoned = True
            raise

    def dispatch(self):
        self.check(); p.require(not self.sent); self.sent = True
        request, response, _ = write(self, self.operation, self.arguments)
        value = {"apiVersion": p.HTTP_RESPONSE, "requestOriginal": p.encoded(request), "responseOriginal": p.encoded(response)}
        p.require(len(p.canonical(value)) <= p.MAX_HTTP_RESPONSE)
        return value


def inspect_on_request(request, identifier):
    p.require(cold.selected()); identity = activation._identity(request, inspection=True)
    p.require("credential_owner" in identity.roles)
    owner, raw = cold.original(identifier); grant = p.grant_document(raw)["payload"]
    journal, scope, custody, _, parts, claims, attempts = read(identifier)
    if journal is not None:
        p.require(journal["authorization_original"].encode("ascii") == raw)
    candidate = None if custody is None or custody["candidate_original_json"] is None else rows.stored(custody["candidate_original_json"], p.MAX_CANDIDATE_BYTES)
    if candidate is not None:
        rows.candidate_original(candidate, grant)
    with db.connect() as connection:
        approval_rows = connection.execute("SELECT * FROM control_plane_approvals WHERE action = ? AND resource_id = ? ORDER BY id LIMIT 65",
            (p.ACTION, identifier)).fetchall()
    p.require(len(approval_rows) <= 64); owner.check()
    return {"apiVersion": OBSERVATION_SCHEMA, "okForAction": False, "authorization": grant,
        "status": "missing-association-outcome-unknown" if journal is None else custody["status"] if custody is not None else journal["status"],
        "snapshotParts": [item["part"] for item in parts], "scopeSha256": None if scope is None else p.sha256(rows.scope_original(scope)),
        "materialClaims": [item["material_id"] for item in claims],
        "contacts": [{"materialId": item["material_id"], "tokenPurpose": item["token_purpose"], "status": item["status"]} for item in attempts],
        "review": None if candidate is None else candidate["review"], "candidateSha256": None if candidate is None else p.sha256(rows.candidate_original(candidate, grant)),
        "approvals": [{name: dict(row)[name] for name in ("id", "requester_id", "approved_by", "status", "expires_at")} for row in approval_rows],
        "continuationAllowed": False}


def recovery_original_on_request(request, raw):
    value = body(request, raw, p.HTTP_PATH + "/original")
    p.require(set(value) == {"apiVersion", "authorizationId"} and value["apiVersion"] == p.RECOVERY_REQUEST)
    owner, grant_raw = cold.original(value["authorizationId"])
    journal, scope, custody, exchanged, _, claims, attempts = read(value["authorizationId"])
    p.require(journal is not None and scope is not None and journal["authorization_original"].encode("ascii") == grant_raw)
    # These raw observations cannot recreate a lost FENCE response, a contact
    # acknowledgement or a processing nonce. Only own signed RECOVER may attest
    # the retained state, and that operation has no provider effect.
    result = {"apiVersion": p.RECOVERY_RESPONSE, "okForAction": False,
        "journalOriginal": rows.journal_original(journal).decode("ascii"), "scopeOriginal": rows.scope_original(scope).decode("ascii"),
        "materialOriginals": [rows.material_original(item).decode("ascii") for item in claims],
        "attemptOriginals": [rows.attempt_original(item).decode("ascii") for item in attempts],
        "exchangeOriginal": None if exchanged is None else exchange.row_original(exchanged).decode("ascii"),
        "custodyOriginal": None if custody is None else rows.custody_original(custody).decode("ascii"),
        "candidateOriginal": None if custody is None else custody["candidate_original_json"]}
    owner.check(); p.require(len(p.canonical(result)) <= p.MAX_KERNEL_RESULT)
    return result
