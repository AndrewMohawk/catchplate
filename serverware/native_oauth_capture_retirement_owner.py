"""Retained measured helper for independently authorized pre-subject capture retirement.

Only this actual broker child opens client/token/response plaintext. A definite
signed contact claim precedes each POST. Recovery cannot enter that branch.
"""
from __future__ import annotations
import os
import time
from serverware import native_oauth_refresh as m
from serverware import native_oauth_capture_retirement as wire
from serverware import native_oauth_capture_retirement as p
from serverware.native_oauth_refresh_owner import IDENTITY_FIELDS
from serverware.native_oauth_capture_retirement_receipts import Receipts

CHANNEL = wire.CHANNEL


class Owner:
    def __init__(self, broker, value):
        m.require(broker.kek is not None and broker.service_tokens_opened and not broker.operations
            and set(value) == {"apiVersion", "phase", "configuration"} and value["apiVersion"] == CHANNEL and value["phase"] == "configure")
        config = value["configuration"]
        m.require(type(config) is dict and set(config) == {"apiVersion", "sourceRevision", "authorityRootPublicKey", "authorityRootSpkiSha256",
            "controlPlaneConfigurationDigest", "deploymentId", "instanceId", "applications", "targets", "identity"}
            and config["apiVersion"] == wire.CONFIG and set(config["identity"]) == IDENTITY_FIELDS)
        m.digest(config["authorityRootSpkiSha256"]); m.digest(config["controlPlaneConfigurationDigest"])
        m.require(type(config["applications"]) is dict and 1 <= len(config["applications"]) <= 2
            and type(config["targets"]) is list and 1 <= len(config["targets"]) <= 16)
        self.entries = {}
        for target in config["targets"]:
            m.require(type(target) is dict and set(target) == {"authorizationOriginal", "historicalRootOriginal", "recovery"}
                and type(target["recovery"]) is bool)
            grant = p.grant_document(m.decoded(target["authorizationOriginal"], p.MAX_GRANT_BYTES))["payload"]
            m.decoded(target["historicalRootOriginal"], 4096)
            m.require(grant["exchangeId"] not in self.entries and grant["deploymentId"] == config["deploymentId"])
            if not target["recovery"]:
                m.require(grant["holderId"] == config["identity"]["holderId"]
                    and grant["configurationDigest"] == config["controlPlaneConfigurationDigest"]
                    and grant["sourceRevision"] == config["sourceRevision"])
            app = config["applications"][grant["providerId"]]
            m.require(type(app) is dict and set(app) == {"enrollmentOriginal", "material", "tlsRootsPem", "exchangeIds"}
                and type(app["exchangeIds"]) is list and 1 <= len(app["exchangeIds"]) <= 64
                and app["exchangeIds"] == sorted(set(app["exchangeIds"])) and grant["exchangeId"] in app["exchangeIds"])
            for exchange_id in app["exchangeIds"]:
                p.identifier(exchange_id)
            original = m.decoded(app["enrollmentOriginal"], 32768)
            enrollment = m.document(original, 32768, exact=False)["payload"]
            m.application_header(app["material"], enrollment, m.sha(original))
            m.require(app["material"]["secretKekId"] == broker.key_id and m.sha(original) == grant["enrollmentSha256"]
                and m.sha(m.canonical(app["material"])) == grant["applicationMaterialSha256"]
                and type(app["tlsRootsPem"]) is str and app["tlsRootsPem"].isascii()
                and 0 < len(app["tlsRootsPem"]) <= 128 * 1024
                and m.sha(app["tlsRootsPem"].encode("ascii")) == grant["providerTlsRootSha256"])
            self.entries[grant["exchangeId"]] = (target, grant, app)
        self.broker, self.config, self.operation, self.attempted = broker, config, None, set()
        broker.channel.send({"apiVersion": CHANNEL, "phase": "configured"})

    def handle(self, value):
        self.broker.channel.check(); m.require(value.get("apiVersion") == CHANNEL)
        if value.get("phase") == "begin":
            m.require(set(value) == {"apiVersion", "phase", "exchangeId", "deadlineBoottimeNs"}
                and self.operation is None and value["exchangeId"] in self.entries and value["exchangeId"] not in self.attempted)
            self.attempted.add(value["exchangeId"])
            self.operation = _Operation(self, value)
            self.operation.prepare("recover" if self.operation.recovery else "inspect",
                {"issuedAtEpochNs": self.operation.started, "expiresAtEpochNs": self.operation.expires})
        else:
            m.require(set(value) == {"apiVersion", "phase", "originals"} and value["phase"] == "receipt" and self.operation is not None)
            self.operation.receipt(value["originals"])


class _Operation:
    def __init__(self, owner, value):
        self.owner, self.broker, self.config = owner, owner.broker, owner.config
        self.target, self.grant, self.app = owner.entries[value["exchangeId"]]
        self.recovery = self.target["recovery"]
        self.started, boot = time.time_ns(), time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        m.integer(value["deadlineBoottimeNs"], maximum=2**64 - 1)
        remaining = min(30_000_000_000, value["deadlineBoottimeNs"] - boot, self.broker.channel.deadline - boot)
        if not self.recovery:
            m.require(self.grant["issuedAtEpochNs"] <= self.started)
            remaining = min(remaining, self.grant["expiresAtEpochNs"] - self.started)
        m.require(remaining > 0)
        self.deadline, self.expires = boot + remaining, self.started + remaining
        self.verifier, self.nonce = Receipts(self.config), os.urandom(32)
        self.assignment, self.expected, self.phase = None, None, None
        self.requests, self.contacted, self.journal, self.attempt, self.transport = [], set(), None, None, None

    def check(self):
        self.broker.channel.check(self.deadline)
        m.require(self.started <= time.time_ns() < self.expires and self.owner.operation in {None, self})

    def prepare(self, phase, request):
        self.check(); self.phase = phase
        self.expected = {"exchange_id": self.grant["exchangeId"], "authorization_original": self.target["authorizationOriginal"],
            "enrollment_original": self.app["enrollmentOriginal"], "historical_root_original": self.target["historicalRootOriginal"],
            "control_plane_configuration_digest": self.config["controlPlaneConfigurationDigest"],
            "assignment_original": self.assignment, "request": request}
        self.broker.channel.send({"apiVersion": CHANNEL, "phase": "prepared", "operation": "oauth.measured-capture-retirement." + phase,
            "arguments": self.expected, "issuedAtEpochNs": self.started, "expiresAtEpochNs": self.expires}, self.deadline)

    def receipt(self, originals):
        self.check()
        result, assignment, barrier, enrollment = self.verifier.verify(originals, self.expected, started=self.started, expires=self.expires)
        m.require(result["operation"] == "oauth.measured-capture-retirement." + self.phase)
        if self.assignment is None:
            self.assignment = assignment
        m.require(assignment == self.assignment)
        value = result["payload"]
        if self.phase == "recover":
            m.require(type(value) is dict and set(value) == p.OBSERVATION_FIELDS
                and self.recovery and barrier is None and value["status"] in {"no-local-claim", "outcome-unknown", "unknown", "observed-accepted", "observed-rejected"})
            # The authenticated writer observation does not grant another POST.
            self.done(value["status"]); return
        m.require(not self.recovery)
        if self.phase == "inspect":
            m.require(value["status"] == "ready" and value["journalOriginal"] is None
                and value["custodyOriginal"] is None and value["attemptOriginals"] == [])
            self.preflight(value, enrollment)
            p.barriers(barrier, self.grant["affectedLineages"])
            self.barrier = barrier
            self.prepare("claim", {"ownerNonceSha256": m.sha(self.nonce), "currentnessBarriers": barrier})
            return
        m.require(barrier is None and set(value) == {"journalOriginal", "attemptOriginal", "custodyOriginal"})
        journal = m.document(value["journalOriginal"].encode("ascii"), 4 * 1024 * 1024)
        p.journal_original(journal)
        custody = m.document(value["custodyOriginal"].encode("ascii"), 8 * 1024 * 1024)
        p.row_original(custody)
        m.require(journal["id"] == custody["id"] == self.grant["exchangeId"]
            and journal["authorization_original"] == self.target["authorizationOriginal"]
            and journal["authorization_sha256"] == custody["authorization_sha256"] == m.sha(m.decoded(self.target["authorizationOriginal"], p.MAX_GRANT_BYTES))
            and journal["owner_nonce_sha256"] == m.sha(self.nonce)
            and journal["currentness_barriers_json"] == m.canonical(self.barrier).decode("ascii")
            and journal["original_work_json"] == self.work_original
            and journal["original_affected_json"] == m.canonical(self.affected_originals).decode("ascii"))
        self.journal = value["journalOriginal"]
        if self.phase == "claim":
            m.require(journal["status"] == "claimed" and value["attemptOriginal"] is None)
            self.open_retired_material()
            self.next_contact(); return
        purpose = self.expected["request"]["tokenPurpose"]
        attempt = m.document(value["attemptOriginal"].encode("ascii"), 512 * 1024)
        p.attempt_original(attempt)
        request = dict(self.requests)[purpose]
        m.require(attempt["id"] == p.attempt_id(self.grant["exchangeId"], purpose)
            and attempt["exchange_id"] == self.grant["exchangeId"] and attempt["token_purpose"] == purpose
            and attempt["contact_request_sha256"] == request[4])
        if self.phase == "contact":
            m.require(journal["status"] == "claimed" and attempt["status"] == "contact-claimed"
                and attempt["transport_original"] is None and purpose not in self.contacted)
            self.contacted.add(purpose)  # Burn before any TLS/provider byte.
            raw, received, status, _body = wire.Contact(channel=self.broker.channel, provider=self.grant["providerId"],
                roots=self.app["tlsRootsPem"], request=request, check=self.check, deadline=self.deadline).run()
            self.check()
            envelope = m.seal_original(p.response_id(self.grant["exchangeId"], purpose), raw, 1,
                self.broker.key_id, self.broker.kek, received)
            self.transport = m.canonical({"schema": p.TRANSPORT_SCHEMA, "requestSha256": request[4], "status": status,
                "receivedAtEpochNs": received, "rawResponseSha256": m.sha(raw), "rawResponseEnvelope": envelope})
            p.transport(self.transport, request[4])
            self.prepare("finish", {"journalRowSha256": m.sha(self.journal.encode("ascii")), "ownerNonce": m.encoded(self.nonce),
                "attemptRowSha256": m.sha(value["attemptOriginal"].encode("ascii")), "tokenPurpose": purpose,
                "transportOriginal": m.encoded(self.transport)})
        else:
            m.require(self.phase == "finish" and purpose in self.contacted
                and attempt["transport_original"].encode("ascii") == self.transport
                and attempt["transport_sha256"] == m.sha(self.transport) and attempt["status"] == p.transport(self.transport, request[4]))
            if journal["status"] == "claimed":
                self.next_contact()
            else:
                m.require(journal["status"] in {"unknown", "observed-accepted", "observed-rejected"})
                self.done(journal["status"])

    def preflight(self, value, enrollment):
        # Only authenticated ciphertext/public originals before the definite
        # complete-provider claim. No use of subject or a fake pending row.
        grant = self.grant
        m.require(type(value) is dict and set(value) == p.OBSERVATION_FIELDS)
        bindings = {"exchangeOriginal": "exchangeRowSha256", "issuanceCustodyOriginal": "custodyRowSha256",
            "workOriginal": "workRowSha256", "captureArgumentsOriginal": "captureArgumentsSha256"}
        for name, pin in bindings.items():
            m.require(type(value[name]) is str and value[name].isascii() and m.sha(value[name].encode("ascii")) == grant[pin])
        m.require(value["enrollmentOriginal"].encode("ascii") == m.decoded(self.app["enrollmentOriginal"], 32768))
        history = m.document(value["exchangeOriginal"].encode("ascii"), 4 * 1024 * 1024)
        custody = m.document(value["issuanceCustodyOriginal"].encode("ascii"), 4 * 1024 * 1024)
        capture = m.document(value["captureArgumentsOriginal"].encode("ascii"), 2 * 1024 * 1024)
        work = m.document(value["workOriginal"].encode("ascii"), 512 * 1024)
        request = capture["request"]
        m.require(history["id"] == custody["id"] == work["id"] == grant["exchangeId"]
            and history["status"] == "retained" and custody["status"] == "captured"
            and custody["capture_arguments_json"] == value["captureArgumentsOriginal"]
            and custody["pending_original_json"] is None and custody["stage_arguments_json"] is None
            and history["enrollment_original"] == capture["enrollment_original"] == self.app["enrollmentOriginal"]
            and capture["resource_id"] == request["exchangeId"] == grant["exchangeId"]
            and work["source"] == grant["workSource"] and work["status"] == "held" and work["attempts"] == 0
            and request["issuedMaterialEnvelope"] == {name: work[name] for name in m.ENVELOPE_FIELDS}
            and m.canonical(request["issuedMaterialEnvelope"]).decode("ascii") == history["token_envelope_json"]
            and m.sha(m.canonical(request["issuedMaterialEnvelope"])) == grant["tokenEnvelopeSha256"]
            and request["issuedMaterialSha256"] == history["token_secret_sha256"] == grant["tokenSecretSha256"]
            and request["rawResponseSha256"] == history["raw_response_sha256"] == grant["rawResponseSha256"]
            and m.canonical(request["rawResponseEnvelope"]).decode("ascii") == history["raw_response_envelope_json"]
            and m.sha(m.canonical(request["rawResponseEnvelope"])) == grant["rawResponseEnvelopeSha256"]
            and request["rawResponseEnvelope"]["secret_kek_id"] == self.broker.key_id
            and request["issuedMaterialEnvelope"]["secret_kek_id"] == self.broker.key_id)
        if grant["workSource"] == "measured-oauth-setup-exchange/v1":
            m.require(value["setupOriginal"] == custody["setup_started_json"] and custody["setup_final_json"] is None
                and m.sha(value["setupOriginal"].encode("ascii")) == grant["setupCurrentSha256"]
                and m.sha(custody["setup_initial_json"].encode("ascii")) == grant["setupInitialSha256"]
                and m.sha(custody["setup_started_json"].encode("ascii")) == grant["setupStartedSha256"]
                and request["setupBinding"]["sessionId"] == grant["setupSessionId"])
        else:
            m.require(value["setupOriginal"] is None)
        association = {"schema": "serverware.oauthApplicationAssociation/v1", "enrollmentSha256": grant["enrollmentSha256"],
            **{name: enrollment[name] for name in ("deploymentId", "applicationId", "providerId", "providerFamilyNamespace",
                "providerFamilyGeneration", "clientId", "redirectUri", "providerConfigurationSha256")}}
        affected = value["affectedLineages"]
        m.require(type(affected) is list and len(affected) == len(grant["affectedLineages"]))
        for actual, expected in zip(affected, grant["affectedLineages"]):
            m.require(type(actual) is dict and set(actual) == {"credentialOriginal", "generationOriginal"})
            for name, pin in (("credentialOriginal", "credentialRowSha256"), ("generationOriginal", "generationRowSha256")):
                raw = actual[name]
                m.require(type(raw) is str and raw.isascii() and m.sha(raw.encode("ascii")) == expected[pin])
                item = m.document(raw.encode("ascii"), 512 * 1024)
                id_field, version_field = ("id", "credential_version") if name == "credentialOriginal" else ("credential_id", "last_version")
                m.require(item[id_field] == expected["credentialId"] and type(item[version_field]) is int
                    and item[version_field] == expected["credentialVersion"])
        self.work_original, self.affected_originals = value["workOriginal"], affected
        self.capture, self.enrollment, self.association = request, enrollment, association
        self.check()

    def open_retired_material(self):
        m.require(self.phase == "claim" and self.journal is not None and not self.requests)
        from serverware.native_oauth_exchange import artifact_id
        raw = m.open_original(self.grant["exchangeId"], self.capture["issuedMaterialEnvelope"], 1, self.broker.key_id, self.broker.kek)
        m.require(m.sha(raw) == self.grant["tokenSecretSha256"])
        response = m.open_original(artifact_id(self.grant["exchangeId"], "response"),
            self.capture["rawResponseEnvelope"], 1, self.broker.key_id, self.broker.kek)
        m.require(m.sha(response) == self.grant["rawResponseSha256"])
        reply = m.document(response, m.MAX_ORIGINAL)
        m.require(set(reply) == {"status", "rawHeaders", "bodyBase64url"})
        body = m.decoded(reply["bodyBase64url"], m.MAX_REPLY) if reply["bodyBase64url"] else b""
        m.require(raw == m.issued_original(body, self.association))
        token = m.document(raw, m.MAX_ORIGINAL)
        m.require(token.get("oauth_application_owner") == self.association)
        names = [name for name in ("access_token", "refresh_token") if type(token.get(name)) is str and token[name]]
        if self.grant["providerId"] == "google":
            names = ["refresh_token"] if "refresh_token" in names else ["access_token"] if "access_token" in names else []
        m.require(names == self.grant["tokenPurposes"])
        client = m.open_application(self.app["material"], self.enrollment, self.grant["enrollmentSha256"], self.broker.key_id, self.broker.kek)
        self.requests = [(name, wire.request(self.grant, client, token[name], name)) for name in names]
        self.check()

    def next_contact(self):
        pending = [(name, request) for name, request in self.requests if name not in self.contacted]
        m.require(pending)
        purpose, request = pending[0]
        self.prepare("contact", {"journalRowSha256": m.sha(self.journal.encode("ascii")), "ownerNonce": m.encoded(self.nonce),
            "tokenPurpose": purpose, "contactRequestSha256": request[4]})

    def done(self, status):
        self.check()
        self.broker.channel.send({"apiVersion": CHANNEL, "phase": "complete", "exchangeId": self.grant["exchangeId"], "status": status}, self.deadline)
        self.owner.operation = None
