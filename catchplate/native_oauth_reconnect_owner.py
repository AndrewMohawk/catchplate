"""Measured helper's one-use active-family reconnect owner.

No plaintext leaves the private browser/helper channel. Provider contact occurs
only after this owner's exact signed CLAIM receipt, once. Recovery cannot POST.
"""
import hmac
import os
import time
from urllib.parse import parse_qsl
from catchplate import native_oauth_refresh as m
from catchplate import native_oauth_exchange as provider
from catchplate import native_oauth_reconnect as material
from catchplate import native_oauth_reconnect_rows as rows
from catchplate.native_oauth_refresh_owner import IDENTITY_FIELDS
from catchplate.native_oauth_reconnect_receipts import Receipts
from catchplate.native_oauth_reconnect_tls import Contact

CHANNEL = "catchplate.nativeOAuthReconnectChannel/v1"
CONFIG = "catchplate.nativeOAuthReconnectExchangeConfiguration/v1"
MAX_MESSAGE = 8 * 1024 * 1024
WINDOWS = {"contactMaxSeconds": 600, "retentionMaxSeconds": 600, "pendingMaxSeconds": 3600,
    "operationMaxSeconds": 30, "recoveryMaxSeconds": 30}


class Owner:
    def __init__(self, broker, value):
        broker.require_owner_configuration()
        m.require(type(value) is dict and set(value) == {"apiVersion", "phase", "configuration"}
            and value["apiVersion"] == CHANNEL and value["phase"] == "configure"
            and len(m.canonical(value)) <= MAX_MESSAGE)
        config = value["configuration"]
        m.require(type(config) is dict and set(config) == {"apiVersion", "sourceRevision", "authorityRootPublicKey", "authorityRootSpkiSha256",
            "controlPlaneConfigurationDigest", "deploymentId", "instanceId", "limits", "windows", "applications", "recoveryTargets", "identity",
            "callbackOrigin", "portalOrigin", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256", "authorityConfigurationOriginal", "reconnectLimits"}
            and config["apiVersion"] == CONFIG and config["windows"] == WINDOWS and config["reconnectLimits"] == material.LIMITS
            and config["limits"] == {"pendingCapacity": 64, "revocationCapacity": 64}
            and type(config["identity"]) is dict and set(config["identity"]) == IDENTITY_FIELDS)
        for group in ("limits", "windows", "reconnectLimits"):
            m.require(all(type(item) is int for item in config[group].values()))
        provider.origin(config["callbackOrigin"]); provider.origin(config["portalOrigin"])
        m.require(config["callbackOrigin"] != config["portalOrigin"])
        for name in ("authorityRootSpkiSha256", "controlPlaneConfigurationDigest", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256"):
            m.digest(config[name])
        m.require(type(config["applications"]) is dict and 1 <= len(config["applications"]) <= 2)
        for identifier, application in config["applications"].items():
            m.require(identifier in provider.AUTHORIZATION and type(application) is dict
                and set(application) == {"enrollmentOriginal", "material", "tlsRootsPem"})
            original = m.decoded(application["enrollmentOriginal"], 32768)
            envelope = m.document(original, 32768, exact=False)
            m.application_header(application["material"], envelope["payload"], m.sha(original))
            m.require(envelope["payload"]["providerId"] == identifier and application["material"]["secretKekId"] == broker.key_id
                and envelope["payload"]["redirectUri"] == provider.callback_uri(config["callbackOrigin"], identifier))
            m.text(application["tlsRootsPem"], 128 * 1024)
        targets = config["recoveryTargets"]
        m.require(type(targets) is list and len(targets) <= 64 and targets == sorted(set(targets)))
        for identifier in targets:
            provider.identifier(identifier)
        Receipts(config)  # Genuine cold root/configuration admission, no effect permission.
        self.broker, self.config = broker, config
        self.operations, self.seen, self.operation, self.poisoned = {}, set(), None, False
        broker.channel.send({"apiVersion": CHANNEL, "phase": "configured"})

    def __copy__(self):
        raise ValueError("private reconnect owner is not cloneable")

    def __deepcopy__(self, memo):
        raise ValueError("private reconnect owner is not cloneable")

    def handle(self, value):
        try:
            self._handle(value)
        except Exception:
            self.poisoned = True
            raise

    def _handle(self, value):
        self.broker.channel.check()
        m.require(not self.poisoned and type(value) is dict and value.get("apiVersion") == CHANNEL
            and len(m.canonical(value)) <= MAX_MESSAGE)
        phase = value.get("phase")
        if phase == "begin":
            m.require(set(value) == {"apiVersion", "phase", "intent", "deadlineBoottimeNs"}
                and self.operation is None and len(self.seen) < 16)
            intent = material.intent(value["intent"])
            identifier = material.grant(m.decoded(intent["authorizationOriginal"], material.MAX_GRANT))["payload"]["authorizationId"]
            m.require(identifier not in self.seen)
            self.seen.add(identifier)
            operation = _Operation.begin(self, value)
            self.operations[identifier] = self.operation = operation
            operation.prepare("prepare", operation.consent)
        elif phase == "callback":
            m.require(set(value) == {"apiVersion", "phase", "exchangeId", "providerId", "browserNonce", "query", "deadlineBoottimeNs"}
                and self.operation is None)
            operation = self.operations.get(value["exchangeId"])
            m.require(operation is not None and operation.authorized and not operation.terminal and value["providerId"] == operation.provider)
            provider.require_browser(operation.state, value["browserNonce"])
            self.operation = operation
            operation.window(value["deadlineBoottimeNs"], operation.grant["retentionExpiresAtEpochNs"])
            operation.callback(value["query"])
        elif phase == "recover":
            m.require(set(value) == {"apiVersion", "phase", "exchangeId", "journalOriginal", "exchangeOriginal", "custodyOriginal", "candidateOriginal", "deadlineBoottimeNs"}
                and self.operation is None and value["exchangeId"] in self.config["recoveryTargets"] and value["exchangeId"] not in self.seen)
            self.seen.add(value["exchangeId"])
            operation = _Operation.recover(self, value)
            self.operations[operation.identifier] = self.operation = operation
            operation.prepare("recover", operation.recovery_request)
        else:
            m.require(phase == "receipt" and set(value) == {"apiVersion", "phase", "originals"} and self.operation is not None)
            self.operation.receipt(value["originals"])


class _Operation:
    def __init__(self, owner, provider_id):
        self.owner, self.broker, self.config = owner, owner.broker, owner.config
        self.provider, self.app = provider_id, owner.config["applications"][provider_id]
        self.verifier = Receipts(self.config)
        self.phase = self.expected = self.nonce = self.recovery_digest = None
        self.post_attempted = self.identity_attempted = self.callback_spent = self.receipt_spent = False
        self.terminal = self.authorized = self.recovery = False
        self.fence_originals = self.acquired = None

    def window(self, deadline, expiry):
        self.started, boot = time.time_ns(), time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        m.integer(deadline, maximum=2**64 - 1)
        expiry = min(expiry, self.grant["expiresAtEpochNs"])
        self.deadline = min(deadline, self.broker.channel.deadline, boot + 30_000_000_000, boot + expiry - self.started)
        m.require(boot < self.deadline)
        self.expires = self.started + self.deadline - boot
        self.check()

    def check(self):
        self.broker.channel.check(self.deadline)
        m.require(not self.terminal and not self.owner.poisoned and self.started <= time.time_ns() < self.expires
            and time.time_ns() < self.grant["expiresAtEpochNs"] and self.owner.operation in {None, self})

    @classmethod
    def begin(cls, owner, value):
        intent = material.intent(value["intent"])
        operation = cls(owner, intent["providerId"])
        journal, target, operation.grant, operation.assignment, enrollment = operation.verifier.fence(intent)
        operation.identifier = operation.grant["authorizationId"]
        operation.journal_original = operation.verifier.originals.journal_original
        operation.fence_originals = (m.decoded(intent["fenceRequestOriginal"], 2 * 1024 * 1024 + 65536),
            m.decoded(intent["fenceResponseOriginal"], 6 * 1024 * 1024))
        operation.window(value["deadlineBoottimeNs"], operation.grant["contactExpiresAtEpochNs"])
        operation.nonce = os.urandom(32)
        operation.private, operation.browser_nonce = material.prepare(intent, authorization=operation.grant,
            journal_original=operation.journal_original, enrollment_original=operation.verifier.application_original,
            callback_origin=operation.config["callbackOrigin"], portal_origin=operation.config["portalOrigin"],
            limits=operation.config["limits"], issued_ns=operation.started)
        operation.state = material.private_state(operation.private)
        operation.bound = operation.state["reconnectBinding"]
        operation.consent = {name: operation.state[name] for name in ("providerId", "credentialName", "scopes", "metadata", "redirectUri",
            "issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "enrollmentSha256", "limits", "portalOrigin", "callbackOrigin")}
        operation.consent.update(exchangeId=operation.identifier, stateSha256=m.sha(operation.state["state"].encode("ascii")),
            browserNonceSha256=operation.state["browserNonceSha256"], pkceVerifierSha256=m.sha(operation.state["codeVerifier"].encode("ascii")),
            pkceChallenge=m.encoded(bytes.fromhex(m.sha(operation.state["codeVerifier"].encode("ascii"))[7:])),
            stateOriginalSha256=m.sha(operation.private), stateEnvelope=operation.seal("state", operation.private),
            reservedEnvelope=operation.seal(None, m.canonical({"schema": "catchplate.nativeOAuthReconnectReserved/v1", "exchangeId": operation.identifier})),
            fencedRowSha256=operation.bound["fencedRowSha256"])
        return operation

    @classmethod
    def recover(cls, owner, value):
        # Acquired rows are not a current permission. No token/state decrypt,
        # fresh browser entropy or contact occurs before own RECOVER admission.
        journal = rows.stored(value["journalOriginal"])
        grant = material.grant(journal["authorization_original"].encode("ascii"))["payload"]
        operation = cls(owner, grant["providerId"])
        operation.grant, operation.assignment, _ = operation.verifier.admit(m.encoded(journal["authorization_original"].encode("ascii")), grant["providerId"])
        operation.identifier = grant["authorizationId"]
        m.require(value["exchangeId"] == operation.identifier)
        operation.journal_original = value["journalOriginal"]
        operation.verifier.originals.pin_journal(operation.journal_original, grant, operation.verifier.application_original)
        exchanged, custody = rows.stored(value["exchangeOriginal"], 1024 * 1024), rows.stored(value["custodyOriginal"])
        m.require(set(exchanged) == rows.EXCHANGE and set(custody) == rows.CUSTODY
            and exchanged["id"] == custody["id"] == operation.identifier and custody["status"] in {"captured", "staged", "committed"}
            and value["candidateOriginal"] == custody["candidate_original_json"])
        operation.consent = rows.stored(exchanged["consent_json"], 1024 * 1024)
        operation.bound = {"authorizationSha256": m.sha(operation.verifier.grant_raw),
            "fencedRowSha256": m.sha(operation.journal_original.encode("ascii")), **{name: grant[name] for name in
                ("credentialId", "credentialVersion", "providerSubject", "providerAccount", "expiresAtEpochNs")}}
        operation.state = {"requesterId": grant["requesterId"], "credentialPolicy": rows.stored(journal["credential_policy_json"], 8192)}
        operation.recovery, operation.acquired = True, {name: value[name] for name in rows.ORIGINALS}
        operation.window(value["deadlineBoottimeNs"], grant["pendingExpiresAtEpochNs"])
        operation.nonce = os.urandom(32)
        operation.recovery_request = {"exchangeId": operation.identifier, "custodyRowSha256": m.sha(value["custodyOriginal"].encode("ascii")),
            "captureInputSha256": m.sha(custody["capture_arguments_json"].encode("ascii")), "ownerNonceSha256": m.sha(operation.nonce),
            "issuedAtEpochNs": operation.started, "expiresAtEpochNs": operation.expires - 1, "limits": operation.config["limits"]}
        return operation

    def seal(self, purpose, raw):
        identifier = self.identifier if purpose is None else provider.artifact_id(self.identifier, purpose)
        return m.seal_original(identifier, raw, 1, self.broker.key_id, self.broker.kek, time.time_ns())

    def prepare(self, phase, request):
        self.check(); self.phase, self.receipt_spent = phase, False
        request = {**request, "fencedRowSha256": self.bound["fencedRowSha256"]}
        self.expected = {"action": material.ACTION, "resource_id": self.identifier, "payload_digest": m.sha(m.canonical(request)),
            "actor_id": self.grant["requesterId"], "request": request, "approval_id": None, "credential_policy": self.state["credentialPolicy"],
            "enrollment_original": self.app["enrollmentOriginal"], "control_plane_configuration_digest": self.config["controlPlaneConfigurationDigest"],
            "assignment_original": self.assignment, "authorization_original": m.encoded(self.verifier.grant_raw)}
        m.require(len(m.canonical(self.expected)) <= 2 * 1024 * 1024)
        expiry = min(self.expires, self.grant["contactExpiresAtEpochNs"]) if phase in {"prepare", "claim", "cancel"} else self.expires
        self.broker.channel.send({"apiVersion": CHANNEL, "phase": "prepared", "operation": "oauth.measured-reconnect." + phase,
            "arguments": self.expected, "issuedAtEpochNs": self.started, "expiresAtEpochNs": expiry}, self.deadline)

    def callback(self, query):
        self.check()
        m.require(self.authorized and not self.callback_spent and not self.post_attempted and not self.recovery
            and type(query) is str and len(query.encode("ascii")) <= 8192 and time.time_ns() < self.grant["contactExpiresAtEpochNs"])
        self.callback_spent = True
        fields = parse_qsl(query, keep_blank_values=True, strict_parsing=True, max_num_fields=8, encoding="utf-8", errors="strict")
        m.require(len({name for name, _ in fields}) == len(fields))
        callback = dict(fields)
        m.require("state" in callback and hmac.compare_digest(callback["state"], self.state["state"]))
        allowed = {"state", "code", "scope", "authuser", "prompt"} if "code" in callback else {"state", "error", "error_description", "error_uri"}
        m.require(set(callback) <= allowed and ("code" in callback) != ("error" in callback))
        raw = m.canonical({"schema": "catchplate.nativeOAuthReconnectCallbackOriginal/v1", "exchangeId": self.identifier,
            "providerId": self.provider, "query": query, "browserNonceSha256": self.state["browserNonceSha256"]})
        request = {"exchangeId": self.identifier, "exchangeRowSha256": m.sha(m.canonical(self.row)), "callbackSha256": m.sha(raw),
            "callbackEnvelope": self.seal("callback", raw), "limits": self.config["limits"]}
        if "error" in callback:
            provider.text(callback["error"], 256); self.prepare("cancel", request); return
        self.token_request = provider.token_request(self.state, self.client, callback["code"])
        request.update(ownerNonceSha256=m.sha(self.nonce), codeSha256=m.sha(callback["code"].encode("utf-8")), contactRequestSha256=self.token_request[4])
        self.prepare("claim", request)

    def receipt(self, originals):
        self.check(); m.require(not self.receipt_spent); self.receipt_spent = True
        result, retained, assignment, enrollment = self.verifier.verify(originals, self.expected,
            phase=self.phase, started=self.started, expires=self.expires)
        _, self.row, self.custody, candidate, _ = retained
        m.require(assignment == self.assignment)
        if self.phase == "prepare":
            m.require(not self.authorized and not self.recovery and self.custody["status"] == "prepared"
                and self.row["consent_json"].encode("ascii") == m.canonical(self.consent))
            self.client = m.open_application(self.app["material"], enrollment, self.grant["enrollmentSha256"], self.broker.key_id, self.broker.kek)
            self.authorized = True
            self.broker.channel.send({"apiVersion": CHANNEL, "phase": "authorization-redirect", "exchangeId": self.identifier,
                "location": provider.authorization_url(self.state, self.client), "cookieName": provider.cookie_name(self.identifier),
                "cookieValue": self.browser_nonce, "expiresAtEpochNs": self.grant["contactExpiresAtEpochNs"]}, self.deadline)
            self.owner.operation = None
        elif self.phase == "claim":
            m.require(not self.post_attempted and not self.recovery and self.custody["status"] == "claimed")
            self.contact_check(); self.post_attempted = True
            self.raw, self.received, self.status, self.body = Contact(channel=self.broker.channel, provider=self.provider, purpose="token",
                roots=self.app["tlsRootsPem"], request=self.token_request, check=self.contact_check, deadline=self.deadline).run()
            issued = m.issued_original(self.body, self.state[m.ASSOCIATION])
            self.capture = {"exchangeId": self.identifier, "exchangeRowSha256": m.sha(m.canonical(self.row)), "ownerNonce": m.encoded(self.nonce),
                "limits": self.config["limits"], "rawResponseSha256": m.sha(self.raw), "rawResponseEnvelope": self.seal("response", self.raw),
                "issuedMaterialSha256": None if issued is None else m.sha(issued), "issuedMaterialEnvelope": None if issued is None else self.seal(None, issued),
                "receivedAtEpochNs": self.received, "fencedRowSha256": self.bound["fencedRowSha256"]}
            self.prepare("capture", self.capture)
        elif self.phase == "recover":
            m.require(result["originals"]["journalOriginal"] == self.acquired["journalOriginal"]
                and result["originals"]["exchangeOriginal"] == self.acquired["exchangeOriginal"]
                and self.row["consent_json"].encode("ascii") == m.canonical(self.consent))
            if self.custody["status"] in {"staged", "committed"}:
                m.require(result["originals"] == self.acquired); self.done("observed-" + self.custody["status"]); return
            m.require(self.custody["status"] == "captured" and self.custody["recovery_request_digest"] == result["requestDigest"])
            prior = rows.stored(self.acquired["custodyOriginal"])
            changes = {name: self.custody[name] for name in ("recovery_request_digest", "recovery_expires_at_epoch_ns",
                "recovery_arguments_json", "recovery_owner_nonce_sha256", "updated_at")}
            m.require(self.custody == {**prior, **changes} and all(prior[name] is None for name in changes if name != "updated_at"))
            self.recovery_digest = result["requestDigest"]
            self.private = m.open_original(provider.artifact_id(self.identifier, "state"), self.consent["stateEnvelope"], 1, self.broker.key_id, self.broker.kek)
            m.require(m.sha(self.private) == self.consent["stateOriginalSha256"])
            self.state = material.private_state(self.private)
            m.require(self.state["reconnectBinding"] == self.bound and self.state["exchangeId"] == self.identifier
                and self.state["requesterId"] == self.grant["requesterId"]
                and all(self.state[name] == self.consent[name] for name in ("providerId", "credentialName", "scopes", "metadata", "redirectUri",
                    "issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "enrollmentSha256", "limits", "portalOrigin", "callbackOrigin")))
            self.capture = rows.stored(self.custody["capture_arguments_json"], 2 * 1024 * 1024)["request"]
            self.raw = m.open_original(provider.artifact_id(self.identifier, "response"), self.capture["rawResponseEnvelope"], 1, self.broker.key_id, self.broker.kek)
            m.require(m.sha(self.raw) == self.capture["rawResponseSha256"])
            raw = m.document(self.raw, m.MAX_ORIGINAL)
            m.require(set(raw) == {"status", "rawHeaders", "bodyBase64url"})
            self.status, self.received = raw["status"], self.capture["receivedAtEpochNs"]
            self.body = m.decoded(raw["bodyBase64url"], m.MAX_REPLY) if raw["bodyBase64url"] else b""
            self.client = m.open_application(self.app["material"], enrollment, self.grant["enrollmentSha256"], self.broker.key_id, self.broker.kek)
            self.stage()
        elif self.phase == "capture":
            m.require(rows.stored(self.custody["capture_arguments_json"], 2 * 1024 * 1024)["request"] == self.capture)
            self.stage()
        else:
            m.require(self.phase in {"stage", "cancel"})
            self.done(self.custody["status"])

    def contact_check(self):
        self.check()
        m.require(not self.recovery and time.time_ns() < self.grant["contactExpiresAtEpochNs"])

    def stage(self):
        self.check()
        envelope = self.capture["issuedMaterialEnvelope"]
        if envelope is None:
            self.done("captured-unusable"); return
        issued = m.open_original(self.identifier, envelope, 1, self.broker.key_id, self.broker.kek)
        m.require(m.sha(issued) == self.capture["issuedMaterialSha256"] and issued == m.issued_original(self.body, self.state[m.ASSOCIATION]))
        try:
            final_raw, token = provider.token_original(self.status, self.body, self.received, self.state)
        except (ValueError, TypeError, KeyError):
            self.done("captured-unusable"); return
        m.require(not self.identity_attempted and time.time_ns() < self.grant["pendingExpiresAtEpochNs"])
        self.identity_attempted = True
        identity_raw, _, status, body = Contact(channel=self.broker.channel, provider=self.provider, purpose="identity",
            roots=self.app["tlsRootsPem"], request=provider.identity_request(self.provider, token), check=self.check, deadline=self.deadline).run()
        m.require(200 <= status < 300)
        identity = provider.identity_metadata(self.provider, body)
        m.require(identity["provider_subject"] == self.grant["providerSubject"] and identity["provider_account"] == self.grant["providerAccount"]
            and sorted(m.scopes(token["scope"])) == self.grant["scopes"])
        # Preserve the actual target metadata; only the explicit replacement
        # fields vary. Provider display/verification changes are not silently
        # accepted as an unrelated account or metadata authority.
        metadata = {**self.state["metadata"], "scopes": self.grant["scopes"], "token_type": "Bearer", "refreshable": True,
            "provider_identity_verified": True, "expires_at_epoch_ms": token["expires_at_epoch_ms"]}
        metadata.pop("refresh_token_expires_at_epoch_ms", None)
        if "refresh_token_expires_at_epoch_ms" in token:
            metadata["refresh_token_expires_at_epoch_ms"] = token["refresh_token_expires_at_epoch_ms"]
        review = {"credential_type": "oauth2", "provider": self.provider, "provider_subject": self.grant["providerSubject"],
            "provider_account": self.grant["providerAccount"], "scopes": self.grant["scopes"], "credential_name": self.state["credentialName"],
            "metadata_keys": sorted(metadata), "expires_at_epoch_ms": metadata["expires_at_epoch_ms"], m.ASSOCIATION: self.state[m.ASSOCIATION],
            "reconnect_credential_id": self.grant["credentialId"], "reconnect_credential_version": self.grant["credentialVersion"]}
        if self.provider == "x":
            review["x_app_id"] = self.grant["clientId"]
        digest = m.sha(final_raw)
        request = {"exchangeId": self.identifier, "exchangeRowSha256": m.sha(m.canonical(self.row)), "ownerNonce": m.encoded(self.nonce),
            "limits": self.config["limits"], "tokenSecretSha256": digest,
            "tokenEnvelope": m.seal_original(self.grant["credentialId"], final_raw, self.grant["credentialVersion"] + 1,
                self.broker.key_id, self.broker.kek, time.time_ns()),
            "identityRawSha256": m.sha(identity_raw), "identityRawEnvelope": self.seal("identity", identity_raw), "metadata": metadata, "review": review,
            "recoveryRequestDigest": self.recovery_digest, "payloadDigest": m.sha(m.canonical({"action": "credential.oauth.reconnect",
                "authorizationSha256": self.bound["authorizationSha256"], "review": review, "encrypted_token_source_sha256": digest}))}
        self.prepare("stage", request)

    def done(self, status):
        self.check()
        self.broker.channel.send({"apiVersion": CHANNEL, "phase": "complete", "exchangeId": self.identifier, "status": status,
            "custodyRowSha256": m.sha(m.canonical(self.custody))}, self.deadline)
        self.terminal, self.owner.operation = True, None
