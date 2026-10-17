"""Real hardware approval, bounded acquisition and one-use native handoff.

There is intentionally no resume-effect endpoint. Observing a committed row
does not reconstruct a lost acknowledgement, private nonce or native permit.
"""
import time
from urllib.parse import urlsplit
from catchplate import db, webauthn
from catchplate import authority_oauth_retirement_succession as p
from catchplate import authority_oauth_retirement_succession_records as rows
from catchplate import authority_oauth_retirement_succession_snapshots as snapshots
from catchplate import authority_oauth_retirement_succession_inventory as inventory
from catchplate import authority_oauth_refresh as refresh
from catchplate import control_plane_oauth_succession as service
from catchplate import control_plane_oauth_exchange as consent
from catchplate import control_plane_oauth_setup as hardware
from catchplate import control_plane_custody_client as client
from catchplate import oauth_retirement_succession_owner as cold
from catchplate.control_plane_approval_verification import _epoch_ns

MFA_FIELD = "oauthRetiredScopeSuccessionProfile"


def _arguments(human, original, operation, request, approval=None):
    grant = p.grant_document(original)["payload"]
    return p.arguments(operation, {"action": p.ACTION, "resource_id": grant["authorizationId"],
        "payload_digest": p.sha256(p.canonical(request)), "actor_id": human.actor, "request": request,
        "approval_id": approval, "credential_policy": human.policy, "enrollment_original": human.encoded_enrollment,
        "authorization_original": p.encoded(original)})


def _assertion(human, value):
    p.require(type(value) is dict and set(value) == {MFA_FIELD, "assertion"}
        and value[MFA_FIELD] == p.OPTIONS_SCHEMA and len(p.canonical(value)) <= 16384)
    item = value["assertion"]; p.require(type(item) is dict)
    human.mfa, human.mfa_original = value, p.canonical(value)
    human.credential = db.get_webauthn_credential(item.get("id"))
    p.require(type(human.credential) is dict and human.credential["user_id"] == human.actor)
    data, _ = webauthn._parse_client_data(item.get("response", {}).get("clientDataJSON"), "webauthn.get")
    challenge = db.get_unused_webauthn_challenge(data["challenge"], challenge_type="policy_authority", user_id=human.actor)
    p.require(challenge is not None)
    human.clip(_epoch_ns(challenge["expires_at"])); human.check()
    return {"challengeId": challenge["id"], "credentialRecordId": human.credential["id"], "assertion": item}


class _Ceremony:
    def __init__(self, request, identifier, operation, approval_id):
        p.require(operation in p.ASSERTION_OPERATIONS)
        self.application_owner, self.original = cold.original(identifier)
        self.grant = p.grant_document(self.original)["payload"]
        self.human = consent._Owner(request, self.grant["providerId"])
        self.human.clip(self.grant["admissionExpiresAtEpochNs"] if operation in {p.OP_AUTHORIZE, p.OP_AUTHORIZE_DECIDE}
            else self.grant["pendingExpiresAtEpochNs"])
        self.custody = self.human.custody; self.binding = client._snapshot(self.custody)
        self.deadline, self.expires = self.human.deadline, self.human.expires
        self.operation, self.sent, self.snapshot_journal = operation, False, None
        journal, scope, custody, _, parts, _, _ = service.read(identifier)
        self.before = (journal, scope, custody)
        if operation == p.OP_AUTHORIZE:
            p.require(journal is None and scope is None and custody is None and not parts and approval_id is None)
            bound = {"authorizationSha256": p.sha256(self.original), "credentialId": self.grant["credentialId"],
                "credentialVersion": self.grant["credentialVersion"]}
        elif operation == p.OP_AUTHORIZE_DECIDE:
            p.require(journal is not None and journal["status"] == "requested" and approval_id == journal["approval_id"]
                and [item["part"] for item in parts] == sorted(p.SNAPSHOT_PARTS))
            bound = {"authorizationSha256": p.sha256(self.original), "authorizationRowSha256": p.sha256(rows.journal_original(journal))}
        else:
            p.require(journal is not None and journal["status"] == "fenced" and scope is not None
                and custody is not None and custody["status"] == "staged" and custody["candidate_original_json"] is not None)
            candidate = rows.stored(custody["candidate_original_json"], p.MAX_CANDIDATE_BYTES)
            raw = rows.candidate_original(candidate, self.grant)
            bound = {"authorizationSha256": p.sha256(self.original), "candidateSha256": p.sha256(raw)}
        if journal is not None:
            p.require(journal["authorization_original"].encode("ascii") == self.original)
        self.arguments = _arguments(self.human, self.original, operation, bound, approval_id)
        self.arguments_original = p.canonical(self.arguments)
        self.check()

    def check(self):
        self.human.check(); actual, original = cold.original(self.grant["authorizationId"])
        p.require(actual is self.application_owner and original == self.original
            and self.human.association["enrollmentSha256"] == self.grant["enrollmentSha256"]
            and self.human.custody is self.custody and client._snapshot(self.custody) is self.binding
            and p.canonical(self.arguments) == self.arguments_original)
        self.deadline, self.expires = min(self.deadline, self.human.deadline), min(self.expires, self.human.expires)
        if not self.sent:
            p.require(service.read(self.grant["authorizationId"])[:3] == self.before)
        if self.snapshot_journal is not None:
            p.require(service.read(self.grant["authorizationId"])[0] == self.snapshot_journal)

    def execute(self, mfa):
        evidence = _assertion(self.human, mfa)
        self.check(); p.require(not self.sent); self.sent = True
        _, _, result = service.write(self, self.operation, {**self.arguments, "authn_evidence": evidence})
        completed = []
        if self.operation == p.OP_AUTHORIZE:
            journal = rows.stored(result["originals"]["journalOriginal"]); rows.journal_original(journal)
            p.require(journal["status"] == "requested" and journal["authorization_original"].encode("ascii") == self.original
                and journal["authorize_request_digest"] == result["requestDigest"])
            self.snapshot_journal = journal
            # Each fixed part is separately protected and create-once. A failed
            # response stops this chain; another HTTP request cannot resume it.
            for part in sorted(p.SNAPSHOT_PARTS):
                operation = "oauth.succession.snapshot." + part
                arguments = _arguments(self.human, self.original, operation,
                    {"authorizationRowSha256": p.sha256(rows.journal_original(journal))})
                self.check()
                _, _, observed = service.write(self, operation, arguments)
                item = rows.stored(observed["observation"]["snapshotOriginal"]); snapshots.original(item)
                p.require(item["authorization_id"] == journal["id"] and item["part"] == part
                    and item["acquisition_request_digest"] == observed["requestDigest"])
                completed.append(part)
        return service.public_result(result, snapshot_parts=completed)


class _Fence:
    """Actual requester and retained approval; no invented new MFA receipt."""
    def __init__(self, request, identifier):
        self.application_owner, self.original = cold.original(identifier)
        self.grant = p.grant_document(self.original)["payload"]
        self.human = consent._Owner(request, self.grant["providerId"])
        self.journal, scope, custody, _, parts, _, _ = service.read(identifier)
        p.require(self.journal is not None and self.journal["status"] == "approved" and scope is None and custody is None
            and self.journal["authorization_original"].encode("ascii") == self.original
            and self.human.actor == self.grant["requesterId"]
            and [item["part"] for item in parts] == sorted(p.SNAPSHOT_PARTS))
        self.human.clip(min(self.grant["admissionExpiresAtEpochNs"], _epoch_ns(self.journal["requester_evidence_expires_at"])))
        self.custody, self.binding = self.human.custody, client._snapshot(self.human.custody)
        self.deadline, self.expires = self.human.deadline, self.human.expires
        self.sent, self.drain_attempted = False, False
        self.check()

    def check(self):
        self.human.check(); owner, original = cold.original(self.grant["authorizationId"])
        p.require(owner is self.application_owner and original == self.original
            and self.human.association["enrollmentSha256"] == self.grant["enrollmentSha256"]
            and client._snapshot(self.custody) is self.binding)
        if not self.sent:
            p.require(service.read(self.grant["authorizationId"])[0] == self.journal)

    def execute(self):
        from catchplate.control_plane_credential_currentness import admit_succession_barriers
        self.check(); p.require(not self.sent and not self.drain_attempted)
        barriers = admit_succession_barriers(self)
        issued = time.time_ns()
        arguments = _arguments(self.human, self.original, p.OP_FENCE,
            {"authorizationRowSha256": p.sha256(rows.journal_original(self.journal)), "currentnessBarriers": barriers,
                "issuedAtEpochNs": issued, "expiresAtEpochNs": self.expires}, self.journal["approval_id"])
        self.check(); self.sent = True
        request, response, result = service.write(self, p.OP_FENCE, arguments)
        final = rows.stored(result["originals"]["journalOriginal"]); rows.journal_original(final)
        scope = rows.stored(result["originals"]["scopeOriginal"]); rows.scope_original(scope)
        p.require(final["status"] == "fenced" and final["authorization_original"].encode("ascii") == self.original
            and final["fence_request_digest"] == result["requestDigest"] == scope["fence_request_digest"]
            and final["scope_original_json"] == rows.scope_original(scope).decode("ascii")
            and service.read(final["id"])[:2] == (final, scope))
        pairs = rows.array(scope["affected_originals_json"])
        targets = [rows.stored(pair["credentialOriginal"], 512 * 1024) for pair in pairs
            if rows.stored(pair["credentialOriginal"], 512 * 1024)["id"] == self.grant["credentialId"]]
        p.require(len(targets) == 1); target = targets[0]; refresh.credential_original(target)
        metadata = inventory.metadata(target)
        intent = p.intent({"schema": p.INTENT_SCHEMA, "providerId": self.grant["providerId"],
            "requesterId": self.human.actor, "credentialName": target["name"], "scopes": self.grant["scopes"],
            "metadata": metadata, "credentialPolicy": self.human.policy, "authorizationOriginal": p.encoded(self.original),
            "scopeRequestOriginal": p.encoded(request), "scopeResponseOriginal": p.encoded(response)})
        uri = urlsplit(self.human.provider.redirect_uri)
        callback = p.material.origin(uri.scheme + "://" + uri.netloc)
        p.require(self.human.provider.redirect_uri == p.material.callback_uri(callback, self.grant["providerId"])
            and callback != webauthn.WEBAUTHN_ORIGIN)
        self.check()
        value = {"apiVersion": service.INTENT_RESPONSE, "callbackOrigin": callback,
            "portalOrigin": webauthn.WEBAUTHN_ORIGIN, "intent": intent}
        p.require(len(p.canonical(value)) <= p.MAX_HTTP_RESPONSE)
        return value


def human_on_request(request, raw):
    path = request.url.path; value = service.body(request, raw, path)
    if path == p.HUMAN_PREFIX + "/inventory":
        p.require(not value); identity = consent._cookie_identity(request)
        return {"apiVersion": service.OBSERVATION_SCHEMA, "okForAction": False,
            "authorizations": cold.inventory_for(identity.user_id)}
    if path == p.HUMAN_PREFIX + "/fence":
        p.require(set(value) == {"authorizationId"})
        return _Fence(request, value["authorizationId"]).execute()
    p.require(path in {p.HUMAN_PREFIX + "/ceremony/options", p.HUMAN_PREFIX + "/ceremony"}
        and set(value) == ({"authorizationId", "operation", "approvalId"} if path.endswith("/options")
            else {"authorizationId", "operation", "approvalId", "mfa"}))
    owner = _Ceremony(request, value["authorizationId"], value["operation"], value["approvalId"])
    if path.endswith("/options"):
        return hardware._options(owner.human, owner.operation, owner.arguments, p.OPTIONS_SCHEMA)
    return owner.execute(value["mfa"])
