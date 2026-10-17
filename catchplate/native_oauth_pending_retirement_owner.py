"""Retained measured helper for independently authorized staged-pending retirement.

Only this actual broker child opens client/token/response plaintext. A definite
signed contact claim precedes each POST. Recovery cannot enter that branch.
"""
from __future__ import annotations
import os
import time
from catchplate import native_oauth_refresh as m
from catchplate import native_oauth_pending_retirement as wire
from catchplate import native_oauth_pending_retirement as p
from catchplate.native_oauth_refresh_owner import IDENTITY_FIELDS
from catchplate.native_oauth_pending_retirement_receipts import Receipts

CHANNEL = wire.CHANNEL


class Owner:
    def __init__(self, broker, value):
        broker.require_owner_configuration()
        m.require(set(value) == {"apiVersion", "phase", "configuration"} and value["apiVersion"] == CHANNEL and value["phase"] == "configure")
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
            m.require(grant["pendingId"] not in self.entries and grant["deploymentId"] == config["deploymentId"])
            if not target["recovery"]:
                m.require(grant["holderId"] == config["identity"]["holderId"]
                    and grant["configurationDigest"] == config["controlPlaneConfigurationDigest"]
                    and grant["sourceRevision"] == config["sourceRevision"])
            app = config["applications"][grant["providerId"]]
            m.require(type(app) is dict and set(app) == {"enrollmentOriginal", "material", "tlsRootsPem", "pendingIds"}
                and type(app["pendingIds"]) is list and 1 <= len(app["pendingIds"]) <= 64
                and app["pendingIds"] == sorted(set(app["pendingIds"])) and grant["pendingId"] in app["pendingIds"])
            for pending_id in app["pendingIds"]:
                p.identifier(pending_id)
            original = m.decoded(app["enrollmentOriginal"], 32768)
            enrollment = m.document(original, 32768, exact=False)["payload"]
            m.application_header(app["material"], enrollment, m.sha(original))
            m.require(app["material"]["secretKekId"] == broker.key_id and m.sha(original) == grant["enrollmentSha256"]
                and m.sha(m.canonical(app["material"])) == grant["applicationMaterialSha256"]
                and type(app["tlsRootsPem"]) is str and app["tlsRootsPem"].isascii()
                and 0 < len(app["tlsRootsPem"]) <= 128 * 1024
                and m.sha(app["tlsRootsPem"].encode("ascii")) == grant["providerTlsRootSha256"])
            self.entries[grant["pendingId"]] = (target, grant, app)
        self.broker, self.config, self.operation, self.attempted = broker, config, None, set()
        broker.channel.send({"apiVersion": CHANNEL, "phase": "configured"})

    def handle(self, value):
        self.broker.channel.check(); m.require(value.get("apiVersion") == CHANNEL)
        if value.get("phase") == "begin":
            m.require(set(value) == {"apiVersion", "phase", "pendingId", "deadlineBoottimeNs"}
                and self.operation is None and value["pendingId"] in self.entries and value["pendingId"] not in self.attempted)
            self.attempted.add(value["pendingId"])
            self.operation = _Operation(self, value)
            self.operation.prepare("recover" if self.operation.recovery else "inspect",
                {"issuedAtEpochNs": self.operation.started, "expiresAtEpochNs": self.operation.expires})
        else:
            m.require(set(value) == {"apiVersion", "phase", "originals"} and value["phase"] == "receipt" and self.operation is not None)
            self.operation.receipt(value["originals"])


class _Operation:
    def __init__(self, owner, value):
        self.owner, self.broker, self.config = owner, owner.broker, owner.config
        self.target, self.grant, self.app = owner.entries[value["pendingId"]]
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
        self.expected = {"pending_id": self.grant["pendingId"], "authorization_original": self.target["authorizationOriginal"],
            "enrollment_original": self.app["enrollmentOriginal"], "historical_root_original": self.target["historicalRootOriginal"],
            "control_plane_configuration_digest": self.config["controlPlaneConfigurationDigest"],
            "assignment_original": self.assignment, "request": request}
        self.broker.channel.send({"apiVersion": CHANNEL, "phase": "prepared", "operation": "oauth.measured-pending-retirement." + phase,
            "arguments": self.expected, "issuedAtEpochNs": self.started, "expiresAtEpochNs": self.expires}, self.deadline)

    def receipt(self, originals):
        self.check()
        result, assignment, barrier, enrollment = self.verifier.verify(originals, self.expected, started=self.started, expires=self.expires)
        m.require(result["operation"] == "oauth.measured-pending-retirement." + self.phase)
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
        m.require(journal["id"] == custody["id"] == self.grant["pendingId"]
            and journal["authorization_original"] == self.target["authorizationOriginal"]
            and journal["authorization_sha256"] == custody["authorization_sha256"] == m.sha(m.decoded(self.target["authorizationOriginal"], p.MAX_GRANT_BYTES))
            and journal["owner_nonce_sha256"] == m.sha(self.nonce)
            and journal["currentness_barriers_json"] == m.canonical(self.barrier).decode("ascii")
            and journal["original_pending_json"] == self.pending_original
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
        m.require(attempt["id"] == p.attempt_id(self.grant["pendingId"], purpose)
            and attempt["pending_id"] == self.grant["pendingId"] and attempt["token_purpose"] == purpose
            and attempt["contact_request_sha256"] == request[4])
        if self.phase == "contact":
            m.require(journal["status"] == "claimed" and attempt["status"] == "contact-claimed"
                and attempt["transport_original"] is None and purpose not in self.contacted)
            self.contacted.add(purpose)  # Burn before any TLS/provider byte.
            raw, received, status, _body = wire.Contact(channel=self.broker.channel, provider=self.grant["providerId"],
                roots=self.app["tlsRootsPem"], request=request, check=self.check, deadline=self.deadline).run()
            self.check()
            envelope = m.seal_original(p.response_id(self.grant["pendingId"], purpose), raw, 1,
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
        # Authenticate and retain only ciphertext/public originals here.
        # No token/client opening is permitted until the definite claim receipt.
        grant = self.grant
        m.require(type(value) is dict and set(value) == p.OBSERVATION_FIELDS)
        bindings = {"exchangeOriginal": "exchangeRowSha256", "measuredExchangeOriginal": "custodyRowSha256",
            "initialPendingOriginal": "initialPendingRowSha256", "currentPendingOriginal": "currentPendingRowSha256",
            "stageArgumentsOriginal": "stageArgumentsSha256"}
        for name, pin in bindings.items():
            m.require(type(value[name]) is str and value[name].isascii() and m.sha(value[name].encode("ascii")) == grant[pin])
        m.require(type(value["enrollmentOriginal"]) is str and value["enrollmentOriginal"].isascii()
            and value["enrollmentOriginal"].encode("ascii") == m.decoded(self.app["enrollmentOriginal"], 32768)
            and value["normalizedTokenSha256"] == grant["tokenSecretSha256"])
        history = m.document(value["exchangeOriginal"].encode("ascii"), 4 * 1024 * 1024)
        custody = m.document(value["measuredExchangeOriginal"].encode("ascii"), 4 * 1024 * 1024)
        stage = m.document(value["stageArgumentsOriginal"].encode("ascii"), 1024 * 1024)
        initial = m.document(value["initialPendingOriginal"].encode("ascii"), 512 * 1024)
        current = m.document(value["currentPendingOriginal"].encode("ascii"), 512 * 1024)
        envelope = m.document(value["normalizedEnvelopeOriginal"].encode("ascii"), 512 * 1024)
        m.require(history["id"] == custody["id"] == initial["id"] == current["id"] == grant["pendingId"] == grant["exchangeId"]
            and history["status"] == custody["status"] == "staged"
            and custody["pending_original_json"] == value["initialPendingOriginal"]
            and custody["stage_arguments_json"] == value["stageArgumentsOriginal"]
            and stage["resource_id"] == stage["request"]["exchangeId"] == grant["pendingId"]
            and history["enrollment_original"] == stage["enrollment_original"] == self.app["enrollmentOriginal"]
            and stage["request"]["tokenEnvelope"] == envelope == {name: initial[name] for name in m.ENVELOPE_FIELDS}
                == {name: current[name] for name in m.ENVELOPE_FIELDS}
            and m.sha(m.canonical(envelope)) == grant["tokenEnvelopeSha256"]
            and stage["request"]["tokenSecretSha256"] == grant["tokenSecretSha256"]
            and current["credential_version"] == initial["credential_version"] == 1
            and current["target_credential_id"] is None and current["target_credential_version"] is None
            and current["kind"] == initial["kind"] == "oauth2"
            and current["metadata"] == initial["metadata"])
        metadata = m.document(current["metadata"].encode("ascii"), 32768)
        association = {"schema": "catchplate.oauthApplicationAssociation/v1", "enrollmentSha256": grant["enrollmentSha256"],
            **{name: enrollment[name] for name in ("deploymentId", "applicationId", "providerId", "providerFamilyNamespace",
                "providerFamilyGeneration", "clientId", "redirectUri", "providerConfigurationSha256")}}
        m.require(metadata.get("oauth_application_owner") == association and metadata.get("provider_identity_verified") is True
            and metadata.get("provider_id") == grant["providerId"]
            and metadata.get("provider_subject") == grant["familyScope"]["providerSubject"]
            and metadata.get("provider_account") == grant["familyScope"]["providerAccount"])
        affected = value["affectedLineages"]
        m.require(type(affected) is list and len(affected) == len(grant["affectedLineages"]))
        for actual, expected in zip(affected, grant["affectedLineages"]):
            m.require(type(actual) is dict and set(actual) == {"credentialOriginal", "generationOriginal"})
            for original_name, pin in (("credentialOriginal", "credentialRowSha256"), ("generationOriginal", "generationRowSha256")):
                raw = actual[original_name]
                m.require(type(raw) is str and raw.isascii() and m.sha(raw.encode("ascii")) == expected[pin])
                row = m.document(raw.encode("ascii"), 512 * 1024)
                id_field, version_field = ("id", "credential_version") if original_name == "credentialOriginal" else ("credential_id", "last_version")
                m.require(row[id_field] == expected["credentialId"] and type(row[version_field]) is int
                    and row[version_field] == expected["credentialVersion"])
        self.pending_original, self.affected_originals = value["currentPendingOriginal"], affected
        self.envelope, self.enrollment, self.association = envelope, enrollment, association
        self.check()

    def open_retired_material(self):
        # Only called after the exact signed claim has atomically fenced the
        # pending row, complete family and every admitted active lineage.
        m.require(self.phase == "claim" and self.journal is not None and not self.requests)
        raw = m.open_original(self.grant["pendingId"], self.envelope, 1, self.broker.key_id, self.broker.kek)
        m.require(m.sha(raw) == self.grant["tokenSecretSha256"])
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
        self.broker.channel.send({"apiVersion": CHANNEL, "phase": "complete", "pendingId": self.grant["pendingId"], "status": status}, self.deadline)
        self.owner.operation = None
