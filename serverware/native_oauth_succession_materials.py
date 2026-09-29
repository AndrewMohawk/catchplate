"""Actual claim-gated historical material owner; no generic decrypt operation."""
import os
import threading
import time
import uuid
from serverware import native_oauth_refresh as m
from serverware import native_oauth_exchange as provider
from serverware import native_oauth_succession as p
from serverware import native_oauth_succession_rows as rows
from serverware.native_oauth_cleanup import request as retirement_request, ENDPOINTS
from serverware.native_oauth_succession_tls import Contact


def inspect(operation, result, pin):
    operation.check()
    m.require(operation.verifier.last is result and operation.phase == "inspect"
        and result["operation"] == "oauth.measured-succession.inspect"
        and result["observation"]["contactDisposition"] == "observation-only")
    raw = result["observation"]["materialOriginal"]
    item = rows.stored(raw)
    expected = next(value for value in operation.verifier.originals.inventory["materialOriginals"] if value["pin"] == pin)
    identifier = p.claim_id(operation.identifier, pin["materialId"])
    m.require(item == expected and identifier not in operation.verifier.originals.claims
        and not any(value["material_claim_id"] == identifier for value in operation.verifier.originals.attempts.values()))
    app, original, enrollment, assignment = operation.verifier.material_applications[pin["materialId"]]
    m.require(item["enrollmentOriginal"] is None or item["enrollmentOriginal"].encode("ascii") == original)
    association = provider.association(original, enrollment)
    if pin["sourceKind"] == "credential-current":
        source = rows.stored(item["sourceOriginals"]["credentialOriginal"], 512 * 1024)
        m.require(source["id"] == item["aadCredentialId"] and source["credential_version"] == item["aadCredentialVersion"]
            and m.sha(m.canonical(source)) == pin["sourceRowSha256"]
            and {name: source[name] for name in m.ENVELOPE_FIELDS} == item["tokenEnvelope"]
            and rows.stored(source["metadata"], 32768).get(m.ASSOCIATION) == association)
    # The actual signed scope fixes all source originals/AAD. No plaintext is
    # touched during INSPECT, including for an already accepted old contact.
    return raw, app, original, enrollment, assignment


class ClaimedMaterial:
    def __init__(self, operation, result):
        from serverware.native_oauth_succession_owner import _Operation
        m.require(type(operation) is _Operation and operation.verifier.last is result and operation.phase == "material-claim"
            and result["operation"] == "oauth.measured-succession.material-claim"
            and result["observation"]["contactDisposition"] == "not-contact-authority")
        operation.check()
        self.owner, self.broker = operation, operation.broker
        self.authorization_id, self.material_id = operation.identifier, operation.current_pin["materialId"]
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.original = operation.material_original
        self.material = rows.stored(self.original)
        self.token_envelope = self.material["tokenEnvelope"]
        self.app, self.enrollment_raw, self.enrollment, self.assignment = operation.verifier.material_applications[self.material_id]
        self.application_material = self.app["material"]
        self.claim = operation.verifier.originals.claims[p.claim_id(self.authorization_id, self.material_id)]
        self.claim_original = m.canonical(self.claim)
        m.require(self.claim["material_original_json"] == self.original
            and self.claim["claim_request_digest"] == result["requestDigest"]
            and rows.stored(self.claim["claim_arguments_json"], p.MAX_ARGUMENT) == operation.last_arguments
            and self.claim["owner_nonce_sha256"] == m.sha(operation.material_nonce))
        self.nonce, self.requests, self.completed, self.contacted = operation.material_nonce, [], set(), set()
        self.decrypted, self.response_kek, self.transport = False, None, None

    def __copy__(self):
        raise ValueError("claimed material cannot be copied")

    def __deepcopy__(self, memo):
        raise ValueError("claimed material cannot be copied")

    def check(self):
        self.owner.check()
        m.require((os.getpid(), threading.get_ident()) == (self.pid, self.thread)
            and self.owner.current_material is self and self.owner.current_pin["materialId"] == self.material_id
            and m.canonical(self.material).decode("ascii") == self.original
            and m.canonical(self.claim) == self.claim_original
            and self.owner.verifier.originals.claims[self.claim["id"]] == self.claim)

    def decrypt(self):
        self.check(); m.require(not self.decrypted)
        self.decrypted = True
        token_kek, application_kek = self.broker.historical_keys.claim_keys(self)
        raw = m.open_original(self.material["aadCredentialId"], self.token_envelope, self.material["aadCredentialVersion"],
            self.token_envelope["secret_kek_id"], token_kek)
        pin = self.material["pin"]
        m.require(pin["tokenSecretSha256"] is None or m.sha(raw) == pin["tokenSecretSha256"])
        token = m.document(raw, m.MAX_ORIGINAL)
        m.require(token.get(m.ASSOCIATION) == provider.association(self.enrollment_raw, self.enrollment))
        purposes = [name for name, field in (("access", "access_token"), ("refresh", "refresh_token"))
            if type(token.get(field)) is str and token[field]]
        if self.owner.provider == "google":
            purposes = ["refresh"] if "refresh" in purposes else ["access"] if "access" in purposes else []
        m.require(purposes == pin["tokenPurposes"])
        client = m.open_application(self.application_material, self.enrollment, pin["enrollmentSha256"],
            self.application_material["secretKekId"], application_kek)
        # Pure fixed byte encoding only: this local view is not an old grant.
        # The actual succession claim/contact receipts alone authorize effects.
        configuration = {"revocationUrl": "https://" + ENDPOINTS[self.owner.provider][0] + ENDPOINTS[self.owner.provider][1],
            "tokenAuth": "basic" if self.owner.provider == "x" else "none"}
        # The measured native profile fixes endpoints and confidential X Basic
        # authentication. The historical enrollment's configuration digest is
        # provenance, not a recoverable URL/auth-mode preimage or an override.
        encoding = {"providerId": self.owner.provider, "clientId": self.enrollment["clientId"], "providerConfiguration": configuration,
            "tokenPurposes": [name + "_token" for name in purposes]}
        self.requests = [(name, retirement_request(encoding, client, token[name + "_token"], name + "_token")) for name in purposes]
        self.response_kek = application_kek
        raw = token = client = token_kek = application_kek = None
        self.check()

    def next(self):
        self.check(); m.require(self.decrypted)
        remaining = [(purpose, request) for purpose, request in self.requests if purpose not in self.completed]
        if not remaining:
            self.response_kek = None; self.requests.clear(); self.owner.next_material(); return
        purpose, request = remaining[0]
        m.require(purpose not in self.contacted)
        self.owner.prepare("contact", {"materialId": self.material_id, "materialRowSha256": m.sha(self.claim_original),
            "ownerNonce": m.encoded(self.nonce), "tokenPurpose": purpose, "contactRequestSha256": request[4]}, material_id=self.material_id)

    def receipt(self, result):
        self.check(); m.require(self.owner.verifier.last is result)
        purpose = self.owner.expected["request"]["tokenPurpose"]
        request = dict(self.requests)[purpose]
        attempt = self.owner.verifier.originals.attempts[p.attempt_id(self.claim["id"], purpose)]
        m.require(attempt["material_claim_id"] == self.claim["id"] and attempt["contact_request_sha256"] == request[4])
        if self.owner.phase == "contact":
            m.require(rows.stored(attempt["contact_arguments_json"], p.MAX_ARGUMENT) == self.owner.last_arguments
                and attempt["contact_request_digest"] == result["requestDigest"] and purpose not in self.contacted)
            self.contacted.add(purpose)
            if attempt["status"] == "accepted-existing":
                m.require(result["observation"]["contactDisposition"] == "accepted-existing")
                self.completed.add(purpose); self.next(); return  # Deliberately no POST.
            m.require(attempt["status"] == "contact-claimed" and result["observation"]["contactDisposition"] == "contact-claimed")
            self.owner.contact_check()
            raw, received, status, _body = Contact(channel=self.broker.channel, provider=self.owner.provider, purpose="retirement",
                roots=self.app["tlsRootsPem"], request=request, check=self.owner.contact_check, deadline=self.owner.deadline).run()
            identifier = str(uuid.uuid5(uuid.UUID(attempt["id"]), "serverware.oauthSuccessionTransport/v1"))
            encrypted = m.seal_original(identifier, raw, 1, self.application_material["secretKekId"], self.response_kek, received)
            self.transport = m.canonical({"schema": p.TRANSPORT, "requestSha256": request[4], "status": status,
                "receivedAtEpochNs": received, "rawResponseSha256": m.sha(raw), "rawResponseEnvelope": encrypted})
            rows.transport(self.transport.decode("ascii"), request[4])
            self.owner.prepare("finish", {"materialId": self.material_id, "attemptRowSha256": m.sha(m.canonical(attempt)),
                "ownerNonce": m.encoded(self.nonce), "tokenPurpose": purpose, "transportOriginal": m.encoded(self.transport)}, material_id=self.material_id)
        else:
            m.require(self.owner.phase == "finish" and purpose in self.contacted
                and attempt["transport_original"].encode("ascii") == self.transport
                and rows.stored(attempt["finish_arguments_json"], p.MAX_ARGUMENT) == self.owner.last_arguments
                and attempt["finish_request_digest"] == result["requestDigest"]
                and attempt["status"] == rows.transport(self.transport.decode("ascii"), request[4]))
            if attempt["status"] != "accepted":
                self.owner.done("retirement-" + attempt["status"]); return
            self.completed.add(purpose); self.next()
