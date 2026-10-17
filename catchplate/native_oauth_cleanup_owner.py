"""Retained measured helper for independently authorized family retirement.

Only this actual broker child opens client/token/response plaintext. A definite
signed contact claim precedes each POST. Recovery cannot enter that branch.
"""
from __future__ import annotations
import os
import time
from catchplate import native_oauth_refresh as m
from catchplate import native_oauth_cleanup as wire
from catchplate import native_oauth_cleanup as p
from catchplate.native_oauth_refresh_owner import IDENTITY_FIELDS
from catchplate.native_oauth_cleanup_receipts import Receipts

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
            m.require(grant["workId"] not in self.entries and grant["deploymentId"] == config["deploymentId"])
            if not target["recovery"]:
                m.require(grant["holderId"] == config["identity"]["holderId"]
                    and grant["configurationDigest"] == config["controlPlaneConfigurationDigest"])
            app = config["applications"][grant["providerId"]]
            m.require(type(app) is dict and set(app) == {"enrollmentOriginal", "material", "tlsRootsPem", "credentialIds"}
                and grant["credentialId"] in app["credentialIds"])
            original = m.decoded(app["enrollmentOriginal"], 32768)
            enrollment = m.document(original, 32768, exact=False)["payload"]
            m.application_header(app["material"], enrollment, m.sha(original))
            m.require(app["material"]["secretKekId"] == broker.key_id and m.sha(original) == grant["enrollmentSha256"]
                and m.sha(m.canonical(app["material"])) == grant["applicationMaterialSha256"]
                and type(app["tlsRootsPem"]) is str and app["tlsRootsPem"].isascii()
                and 0 < len(app["tlsRootsPem"]) <= 128 * 1024
                and m.sha(app["tlsRootsPem"].encode("ascii")) == grant["providerTlsRootSha256"])
            self.entries[grant["workId"]] = (target, grant, app)
        self.broker, self.config, self.operation, self.attempted = broker, config, None, set()
        broker.channel.send({"apiVersion": CHANNEL, "phase": "configured"})

    def handle(self, value):
        self.broker.channel.check(); m.require(value.get("apiVersion") == CHANNEL)
        if value.get("phase") == "begin":
            m.require(set(value) == {"apiVersion", "phase", "workId", "deadlineBoottimeNs"}
                and self.operation is None and value["workId"] in self.entries and value["workId"] not in self.attempted)
            self.attempted.add(value["workId"])
            self.operation = _Operation(self, value)
            self.operation.prepare("recover" if self.operation.recovery else "inspect",
                {"issuedAtEpochNs": self.operation.started, "expiresAtEpochNs": self.operation.expires})
        else:
            m.require(set(value) == {"apiVersion", "phase", "originals"} and value["phase"] == "receipt" and self.operation is not None)
            self.operation.receipt(value["originals"])


class _Operation:
    def __init__(self, owner, value):
        self.owner, self.broker, self.config = owner, owner.broker, owner.config
        self.target, self.grant, self.app = owner.entries[value["workId"]]
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
        self.expected = {"work_id": self.grant["workId"], "authorization_original": self.target["authorizationOriginal"],
            "enrollment_original": self.app["enrollmentOriginal"], "historical_root_original": self.target["historicalRootOriginal"],
            "control_plane_configuration_digest": self.config["controlPlaneConfigurationDigest"],
            "assignment_original": self.assignment, "request": request}
        self.broker.channel.send({"apiVersion": CHANNEL, "phase": "prepared", "operation": "oauth.measured-refresh-cleanup." + phase,
            "arguments": self.expected, "issuedAtEpochNs": self.started, "expiresAtEpochNs": self.expires}, self.deadline)

    def receipt(self, originals):
        self.check()
        result, assignment, barrier, enrollment = self.verifier.verify(originals, self.expected, started=self.started, expires=self.expires)
        m.require(result["operation"] == "oauth.measured-refresh-cleanup." + self.phase)
        if self.assignment is None:
            self.assignment = assignment
        m.require(assignment == self.assignment)
        value = result["payload"]
        if self.phase == "recover":
            m.require(self.recovery and barrier is None and value["status"] in {"no-local-claim", "outcome-unknown", "unknown", "observed-accepted", "observed-rejected"})
            # The authenticated writer observation does not grant another POST.
            self.done(value["status"]); return
        m.require(not self.recovery)
        if self.phase == "inspect":
            m.require(value["status"] == "ready" and value["journalOriginal"] is None
                and value["custodyOriginal"] is None and value["attemptOriginals"] == [])
            self.preflight(value, enrollment)
            m.digest(barrier)
            self.barrier = barrier
            self.prepare("claim", {"ownerNonceSha256": m.sha(self.nonce), "currentnessBarrierSha256": barrier})
            return
        m.require(barrier is None and set(value) == {"journalOriginal", "attemptOriginal", "custodyOriginal"})
        journal = m.document(value["journalOriginal"].encode("ascii"), 2 * 1024 * 1024)
        p.journal_original(journal)
        custody = m.document(value["custodyOriginal"].encode("ascii"), 4 * 1024 * 1024)
        p.row_original(custody)
        m.require(journal["id"] == custody["id"] == self.grant["workId"]
            and journal["authorization_original"] == self.target["authorizationOriginal"]
            and journal["authorization_sha256"] == custody["authorization_sha256"] == m.sha(m.decoded(self.target["authorizationOriginal"], p.MAX_GRANT_BYTES))
            and journal["owner_nonce_sha256"] == m.sha(self.nonce) and journal["currentness_barrier_sha256"] == self.barrier
            and journal["original_work_json"] == self.work_original and journal["original_credential_json"] == self.credential_original
            and journal["original_generation_json"] == self.generation_original)
        self.journal = value["journalOriginal"]
        if self.phase == "claim":
            m.require(journal["status"] == "claimed" and value["attemptOriginal"] is None)
            self.next_contact(); return
        purpose = self.expected["request"]["tokenPurpose"]
        attempt = m.document(value["attemptOriginal"].encode("ascii"), 512 * 1024)
        p.attempt_original(attempt)
        request = dict(self.requests)[purpose]
        m.require(attempt["id"] == p.attempt_id(self.grant["workId"], purpose)
            and attempt["work_id"] == self.grant["workId"] and attempt["token_purpose"] == purpose
            and attempt["contact_request_sha256"] == request[4])
        if self.phase == "contact":
            m.require(journal["status"] == "claimed" and attempt["status"] == "contact-claimed"
                and attempt["transport_original"] is None and purpose not in self.contacted)
            self.contacted.add(purpose)  # Burn before any TLS/provider byte.
            raw, received, status, _body = wire.Contact(channel=self.broker.channel, provider=self.grant["providerId"],
                roots=self.app["tlsRootsPem"], request=request, check=self.check, deadline=self.deadline).run()
            self.check()
            envelope = m.seal_original(p.response_id(self.grant["workId"], purpose), raw, 1,
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
        grant = self.grant
        self.work_original, self.credential_original, self.generation_original = value["workOriginal"], value["credentialOriginal"], value["generationOriginal"]
        m.require(m.sha(self.work_original.encode("ascii")) == grant["workRowSha256"]
            and m.sha(self.credential_original.encode("ascii")) == grant["credentialRowSha256"]
            and m.sha(self.generation_original.encode("ascii")) == grant["generationRowSha256"]
            and m.sha(value["refreshOriginal"].encode("ascii")) == grant["refreshRowSha256"]
            and m.sha(value["measuredRefreshOriginal"].encode("ascii")) == grant["custodyRowSha256"])
        work = m.document(self.work_original.encode("ascii"), 512 * 1024)
        current = m.document(self.credential_original.encode("ascii"), 512 * 1024)
        history = m.document(value["refreshOriginal"].encode("ascii"), 4 * 1024 * 1024)
        old = m.document(history["credential_original_json"].encode("ascii"), 512 * 1024)
        m.require(work["id"] == grant["workId"] and work["source"] == grant["workSource"] and current["id"] == old["id"] == grant["credentialId"]
            and current["credential_version"] == grant["credentialVersion"] and old["credential_version"] == grant["refreshVersion"])
        envelope = {name: work[name] for name in m.ENVELOPE_FIELDS}
        m.require(m.sha(m.canonical(envelope)) == grant["tokenEnvelopeSha256"])
        raw = m.open_original(work["id"], envelope, 1, self.broker.key_id, self.broker.kek)
        m.require(m.sha(raw) == grant["tokenSecretSha256"])
        token = m.document(raw, m.MAX_ORIGINAL)
        before = m.document(m.open_original(old["id"], {name: old[name] for name in m.ENVELOPE_FIELDS}, old["credential_version"],
            self.broker.key_id, self.broker.kek), m.MAX_ORIGINAL)
        current_raw = m.open_original(current["id"], {name: current[name] for name in m.ENVELOPE_FIELDS}, current["credential_version"],
            self.broker.key_id, self.broker.kek)
        after = m.document(current_raw, m.MAX_ORIGINAL)
        metadata = m.document(current["metadata"].encode("ascii"), 32768)
        association = {"schema": "catchplate.oauthApplicationAssociation/v1", "enrollmentSha256": grant["enrollmentSha256"],
            **{name: enrollment[name] for name in ("deploymentId", "applicationId", "providerId", "providerFamilyNamespace",
                "providerFamilyGeneration", "clientId", "redirectUri", "providerConfigurationSha256")}}
        m.require(all(item.get("oauth_application_owner") == association for item in (token, before, after, metadata))
            and metadata.get("provider_identity_verified") is True and metadata.get("provider_id") == grant["providerId"]
            and metadata.get("provider_subject") == grant["familyScope"]["providerSubject"]
            and metadata.get("provider_account") == grant["familyScope"]["providerAccount"])
        names = [name for name in ("access_token", "refresh_token") if type(token.get(name)) is str and token[name]]
        if grant["workSource"] == p.ISSUED_SOURCE:
            m.require(current == old and history["status"] == "retained")
            names = [name for name in names if name != "refresh_token" or token[name] != before.get(name)]
        else:
            m.require(grant["providerId"] == "x" and history["status"] == "committed"
                and m.sha(current_raw) == history["replacement_secret_sha256"]
                and all(token[name] == before.get(name) and token[name] != after.get(name) for name in names))
        if grant["providerId"] == "google":
            names = ["refresh_token"] if "refresh_token" in names else ["access_token"] if "access_token" in names else []
        m.require(names == grant["tokenPurposes"])
        client = m.open_application(self.app["material"], enrollment, grant["enrollmentSha256"], self.broker.key_id, self.broker.kek)
        self.requests = [(name, wire.request(grant, client, token[name], name)) for name in names]
        self.check()

    def next_contact(self):
        pending = [(name, request) for name, request in self.requests if name not in self.contacted]
        m.require(pending)
        purpose, request = pending[0]
        self.prepare("contact", {"journalRowSha256": m.sha(self.journal.encode("ascii")), "ownerNonce": m.encoded(self.nonce),
            "tokenPurpose": purpose, "contactRequestSha256": request[4]})

    def done(self, status):
        self.check()
        self.broker.channel.send({"apiVersion": CHANNEL, "phase": "complete", "workId": self.grant["workId"], "status": status}, self.deadline)
        self.owner.operation = None
