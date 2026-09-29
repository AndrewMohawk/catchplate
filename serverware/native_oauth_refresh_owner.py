"""Purpose-fixed refresh state machine retained by the genuine broker child.

All token/client/KEK/DEK plaintext is local to this process. Every public output
is either an unsigned exact operation preparation, encrypted retention, or an
observation of an independently authenticated definite commit. There is no
caller-supplied success, decrypt RPC, retry, or contact-on-recovery branch.
"""
from __future__ import annotations

import os
import time
import uuid
from serverware import native_oauth_refresh as m
from serverware.native_oauth_refresh_receipts import Receipts
from serverware.native_oauth_refresh_tls import Contact

CHANNEL = "serverware.nativeOAuthRefreshChannel/v1"
CONFIG = "serverware.nativeOAuthRefreshConfiguration/v1"
IDENTITY_FIELDS = frozenset({"holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId", "releaseRecordSha256",
    "policyHash", "configurationSha256", "caCertificateSha256", "caPublicKeySpkiSha256", "expectedBinaryDigest"})


def refresh_id(credential, version):
    return str(uuid.uuid5(uuid.UUID(credential), "serverware.oauthRefresh/v1:" + str(version)))


def artifact_id(refresh, purpose):
    m.require(purpose in {"response", "issued", "superseded"})
    return str(uuid.uuid5(uuid.UUID(refresh), "serverware.oauthRefreshArtifact/v1:" + purpose))


class Owner:
    def __init__(self, broker, value):
        m.require(broker.kek is not None and broker.service_tokens_opened and not broker.operations
            and set(value) == {"apiVersion", "phase", "configuration"} and value["apiVersion"] == CHANNEL
            and value["phase"] == "configure")
        config = value["configuration"]
        m.require(type(config) is dict and set(config) == {"apiVersion", "sourceRevision", "authorityRootPublicKey",
            "authorityRootSpkiSha256", "controlPlaneConfigurationDigest", "deploymentId", "instanceId", "limits",
            "applications", "recoveryTargets", "identity"} and config["apiVersion"] == CONFIG
            and type(config["identity"]) is dict and set(config["identity"]) == IDENTITY_FIELDS
            and config["limits"] == {"dueWithinSeconds": 60, "operationMaxSeconds": 30, "revocationCapacity": 64})
        m.digest(config["authorityRootSpkiSha256"]); m.digest(config["controlPlaneConfigurationDigest"])
        m.require(type(config["applications"]) is dict and 1 <= len(config["applications"]) <= 2)
        credentials = set()
        for provider, application in config["applications"].items():
            m.require(provider in m.ENDPOINTS and type(application) is dict
                and set(application) == {"enrollmentOriginal", "material", "tlsRootsPem", "credentialIds"})
            raw = m.decoded(application["enrollmentOriginal"], 32768)
            enrollment = m.document(raw, 32768, exact=False)
            m.application_header(application["material"], enrollment["payload"], m.sha(raw))
            m.require(enrollment["payload"]["providerId"] == provider and application["material"]["secretKekId"] == broker.key_id)
            m.text(application["tlsRootsPem"], 128 * 1024)
            ids = application["credentialIds"]
            m.require(type(ids) is list and 1 <= len(ids) <= 64 and ids == sorted(set(ids)))
            for identifier in ids:
                m.require(str(uuid.UUID(identifier)) == identifier and identifier not in credentials)
                credentials.add(identifier)
        targets = config["recoveryTargets"]
        m.require(type(targets) is list and len(targets) <= 64)
        self.targets = set()
        for item in targets:
            m.require(type(item) is dict and set(item) == {"credentialId", "credentialVersion"} and item["credentialId"] in credentials)
            key = (item["credentialId"], m.integer(item["credentialVersion"]))
            m.require(key not in self.targets); self.targets.add(key)
        self.broker, self.config, self.operation = broker, config, None
        self.attempted, self.recovered = set(), set()
        self.broker.channel.send({"apiVersion": CHANNEL, "phase": "configured"})

    def handle(self, value):
        self.broker.channel.check()
        m.require(value.get("apiVersion") == CHANNEL)
        if value.get("phase") == "begin":
            m.require(set(value) == {"apiVersion", "phase", "credentialId", "recoveryVersion", "deadlineBoottimeNs"}
                and self.operation is None)
            key = (value["credentialId"], value["recoveryVersion"])
            if value["recoveryVersion"] is not None:
                m.require(key in self.targets and key not in self.recovered); self.recovered.add(key)
            self.operation = _Operation(self, value)
            self.operation.prepare("inspect", {"issuedAtEpochNs": self.operation.started,
                "expiresAtEpochNs": self.operation.expires, "limits": self.config["limits"],
                "applicationMaterialSha256": self.operation.material_sha, "recoveryVersion": value["recoveryVersion"]})
        else:
            m.require(set(value) == {"apiVersion", "phase", "originals"} and value["phase"] == "receipt" and self.operation is not None)
            self.operation.receipt(value["originals"])


class _Operation:
    def __init__(self, owner, value):
        self.owner, self.broker, self.config = owner, owner.broker, owner.config
        self.credential = value["credentialId"]
        selected = [(provider, app) for provider, app in self.config["applications"].items() if self.credential in app["credentialIds"]]
        m.require(len(selected) == 1)
        self.provider, self.app = selected[0]
        self.material_sha = m.sha(m.canonical(self.app["material"]))
        self.started, boot = time.time_ns(), time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        m.integer(value["deadlineBoottimeNs"], maximum=2**64 - 1)
        self.deadline = min(value["deadlineBoottimeNs"], self.broker.channel.deadline, boot + 30_000_000_000)
        m.require(boot < self.deadline)
        self.expires = self.started + self.deadline - boot
        self.version, self.recovery_version = 0, value["recoveryVersion"]
        self.assignment, self.expected, self.phase = None, None, None
        self.nonce = os.urandom(32)
        self.verifier = Receipts(self.config)
        self.post_attempted, self.recovery_digest = False, None
        self.check()

    def check(self):
        self.broker.channel.check(self.deadline)
        m.require(self.started <= time.time_ns() < self.expires and self.owner.operation in {None, self})

    def prepare(self, phase, request):
        self.check(); self.phase = phase
        self.expected = {"credential_id": self.credential, "enrollment_original": self.app["enrollmentOriginal"],
            "control_plane_configuration_digest": self.config["controlPlaneConfigurationDigest"],
            "assignment_original": self.assignment, "request": request}
        self.broker.channel.send({"apiVersion": CHANNEL, "phase": "prepared", "operation": "oauth.measured-refresh." + phase,
            "arguments": self.expected, "issuedAtEpochNs": self.started, "expiresAtEpochNs": self.expires}, self.deadline)

    def seal(self, purpose, raw):
        return m.seal_original(artifact_id(self.refresh, purpose), raw, 1, self.broker.key_id, self.broker.kek, time.time_ns())

    def open_heads(self, credential_original, generation_original, enrollment):
        self.row = m.document(credential_original.encode("ascii"), 512 * 1024)
        self.head = m.document(generation_original.encode("ascii"), 8192)
        m.require(self.row["id"] == self.head["credential_id"] == self.credential
            and self.row["credential_version"] == self.head["last_version"] == self.version
            and self.row["lifecycle_status"] == "active" and self.row["kind"] == "oauth2"
            and self.row["secret_kek_id"] == self.broker.key_id and self.version < 2**63 - 1)
        self.metadata = m.document(self.row["metadata"].encode("ascii"), 32768)
        self.association = {"schema": "serverware.oauthApplicationAssociation/v1", "enrollmentSha256": m.sha(m.decoded(self.app["enrollmentOriginal"], 32768)),
            **{name: enrollment[name] for name in ("deploymentId", "applicationId", "providerId", "providerFamilyNamespace",
                "providerFamilyGeneration", "clientId", "redirectUri", "providerConfigurationSha256")}}
        raw = m.open_original(self.credential, {name: self.row[name] for name in m.ENVELOPE_FIELDS}, self.version,
            self.broker.key_id, self.broker.kek)
        self.token = m.current(raw, self.metadata, self.association)
        self.client = m.open_application(self.app["material"], enrollment, self.association["enrollmentSha256"], self.broker.key_id, self.broker.kek)
        self.refresh = refresh_id(self.credential, self.version)

    def receipt(self, originals):
        self.check()
        result, assignment, barrier, enrollment = self.verifier.verify(originals, self.expected, started=self.started, expires=self.expires)
        m.require(result["operation"] == "oauth.measured-refresh." + self.phase)
        if self.assignment is None:
            self.assignment = assignment
        m.require(self.assignment == assignment)
        payload = result["payload"]
        if self.phase == "inspect":
            if self.recovery_version is not None:
                m.require(set(payload) == {"mode", "refreshId", "credentialVersion", "custodyRowSha256", "captureInputSha256", "committed"}
                    and payload["mode"] == "recovery" and payload["credentialVersion"] == self.recovery_version)
                self.version = self.recovery_version
                self.refresh = refresh_id(self.credential, self.version)
                m.require(payload["refreshId"] == self.refresh and barrier is None)
                self.prepare("recover", {"expectedVersion": self.version, "custodyRowSha256": payload["custodyRowSha256"],
                    "captureInputSha256": payload["captureInputSha256"], "ownerNonceSha256": m.sha(self.nonce),
                    "issuedAtEpochNs": self.started, "expiresAtEpochNs": self.expires, "limits": self.config["limits"]})
                return
            m.require(set(payload) == {"mode", "credentialOriginal", "generationOriginal", "enrollmentOriginal", "applicationMaterialSha256", "due", "refreshId"}
                and payload["mode"] == "refresh" and type(payload["due"]) is bool
                and payload["enrollmentOriginal"] == self.app["enrollmentOriginal"] and payload["applicationMaterialSha256"] == self.material_sha)
            self.version = m.document(payload["credentialOriginal"].encode("ascii"), 512 * 1024)["credential_version"]
            if not payload["due"]:
                m.require(barrier is None); self.done("current", self.version); return
            self.open_heads(payload["credentialOriginal"], payload["generationOriginal"], enrollment)
            m.require(payload["refreshId"] == self.refresh and (self.credential, self.version) not in self.owner.attempted)
            self.owner.attempted.add((self.credential, self.version))
            m.digest(barrier)
            m.require(enrollment["issuedAtEpochNs"] <= time.time_ns() < enrollment["expiresAtEpochNs"])
            self.expires = min(self.expires, enrollment["expiresAtEpochNs"])
            self.deadline = min(self.deadline, time.clock_gettime_ns(time.CLOCK_BOOTTIME) + self.expires - time.time_ns())
            self.request = m.token_request(self.client, self.token)
            self.claim = {"expectedVersion": self.version, "limits": self.config["limits"],
                "credentialRowSha256": m.sha(payload["credentialOriginal"].encode("ascii")),
                "generationRowSha256": m.sha(payload["generationOriginal"].encode("ascii")), "ownerNonceSha256": m.sha(self.nonce),
                "issuedAtEpochNs": self.started, "contactExpiresAtEpochNs": self.expires, "retentionExpiresAtEpochNs": self.expires,
                "contactRequestSha256": self.request[4], "currentnessBarrierSha256": barrier,
                "applicationMaterialSha256": self.material_sha,
                "reservedIssuedEnvelope": self.seal("issued", m.canonical({"schema": "serverware.nativeRefreshReservation/v1", "purpose": "issued"})),
                "reservedSupersededEnvelope": self.seal("superseded", m.canonical({"schema": "serverware.nativeRefreshReservation/v1", "purpose": "superseded"})) if self.provider == "x" else None}
            self.prepare("claim", self.claim)
        elif self.phase == "claim":
            self.public(payload, "claimed")
            m.require(not self.post_attempted and self.recovery_version is None and barrier is None)
            self.post_attempted = True
            expiry = self.token.get("refresh_token_expires_at_epoch_ms")
            m.require(expiry is None or time.time_ns() < expiry * 1_000_000)
            self.raw, self.received, self.status, self.body = Contact(channel=self.broker.channel, provider=self.provider,
                roots=self.app["tlsRootsPem"], request=self.request, check=self.check, deadline=self.deadline).run()
            issued = m.issued_original(self.body, self.association)
            self.capture = {"expectedVersion": self.version, "limits": self.config["limits"], "refreshRowSha256": payload["refresh"]["rowSha256"],
                "ownerNonce": m.encoded(self.nonce), "receivedAtEpochNs": self.received, "rawResponseSha256": m.sha(self.raw),
                "rawResponseEnvelope": self.seal("response", self.raw), "issuedMaterialSha256": None if issued is None else m.sha(issued),
                "issuedMaterialEnvelope": None if issued is None else self.seal("issued", issued)}
            self.prepare("capture", self.capture)
        elif self.phase == "recover":
            m.require(barrier is None)
            if payload.get("status") == "observed-complete":
                self.public(payload, "committed"); self.done("observed-complete", self.version + 1); return
            m.require(payload.get("status") == "recovery-admitted")
            self.public(payload, "retained")
            self.recovery_digest = result["requestDigest"]
            self.open_heads(payload["credentialOriginal"], payload["generationOriginal"], enrollment)
            self.claim, self.capture = payload["claimRequest"], payload["captureRequest"]
            m.require(m.sha(m.canonical(self.capture)) == self.expected["request"]["captureInputSha256"])
            self.raw = m.open_original(artifact_id(self.refresh, "response"), self.capture["rawResponseEnvelope"], 1, self.broker.key_id, self.broker.kek)
            m.require(m.sha(self.raw) == self.capture["rawResponseSha256"])
            raw = m.document(self.raw, m.MAX_ORIGINAL)
            m.require(set(raw) == {"status", "rawHeaders", "bodyBase64url"})
            self.received, self.status = self.capture["receivedAtEpochNs"], raw["status"]
            self.body = b"" if raw["bodyBase64url"] == "" else m.decoded(raw["bodyBase64url"], m.MAX_REPLY)
            self.prepare_commit(payload)
        elif self.phase == "capture":
            self.public(payload, "retained")
            m.require(barrier is None)
            self.prepare_commit(payload)
        else:
            m.require(self.phase == "commit" and barrier is None)
            self.public(payload, "committed")
            m.require(payload["credentialVersion"] == self.version + 1)
            m.digest(payload["credentialSha256"])
            self.done("committed", self.version + 1)

    def public(self, payload, status):
        refresh, custody = payload["refresh"], payload["custody"]
        m.require(refresh["id"] == custody["id"] == self.refresh and refresh["credentialId"] == self.credential
            and refresh["expectedVersion"] == self.version and refresh["status"] == status
            and custody["status"] == {"claimed": "claimed", "retained": "captured", "committed": "committed"}[status])
        m.digest(refresh["rowSha256"]); m.digest(custody["rowSha256"])

    def prepare_commit(self, payload):
        # This branch is reachable only after a genuine durable capture or a
        # fresh recovery processing receipt over that exact retained capture.
        issued = self.capture["issuedMaterialEnvelope"]
        m.require(issued is not None)
        issued_raw = m.open_original(artifact_id(self.refresh, "issued"), issued, 1, self.broker.key_id, self.broker.kek)
        m.require(m.sha(issued_raw) == self.capture["issuedMaterialSha256"]
            and issued_raw == m.issued_original(self.body, self.association))
        raw, metadata, retired_raw = m.replacement(self.status, self.body, self.received, self.provider, self.token, self.metadata)
        m.require(metadata["expires_at_epoch_ms"] * 1_000_000 > time.time_ns())
        self.prepare("commit", {"expectedVersion": self.version, "limits": self.config["limits"],
            "refreshRowSha256": payload["refresh"]["rowSha256"], "ownerNonce": m.encoded(self.nonce),
            "replacementSecretSha256": m.sha(raw), "replacementEnvelope": m.seal_original(self.credential, raw,
                self.version + 1, self.broker.key_id, self.broker.kek, time.time_ns()), "replacementMetadata": metadata,
            "supersededMaterialSha256": None if retired_raw is None else m.sha(retired_raw),
            "supersededEnvelope": None if retired_raw is None else self.seal("superseded", retired_raw),
            "recoveryRequestDigest": self.recovery_digest})

    def done(self, status, version):
        self.check()
        self.broker.channel.send({"apiVersion": CHANNEL, "phase": "complete", "credentialId": self.credential,
            "credentialVersion": version, "status": status}, self.deadline)
        self.owner.operation = None
