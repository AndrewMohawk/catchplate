"""Private Setup-issuance owner inside the admitted broker child.

Browser plaintext enters only from the same enclave's retained HTTPS ingress
over its private child channel. State, cookie, PKCE, authorization code, client
secret, tokens and envelope keys never appear in its public preparations. A
signed store receipt, not a caller result, advances each irreversible phase.
"""
import hmac
import os
import time
from urllib.parse import parse_qsl
from catchplate import native_oauth_refresh as m
from catchplate import native_oauth_exchange as exchange
from catchplate import native_oauth_setup as material
from catchplate.native_oauth_setup_rows import initial_binding, row as setup_row
from catchplate.native_oauth_refresh_owner import IDENTITY_FIELDS
from catchplate.native_oauth_setup_receipts import Receipts
from catchplate.native_oauth_setup_tls import Contact

CHANNEL = "catchplate.nativeOAuthSetupExchangeChannel/v1"
CONFIG = "catchplate.nativeOAuthSetupExchangeConfiguration/v1"
WINDOWS = {"contactMaxSeconds": 600, "retentionMaxSeconds": 600, "pendingMaxSeconds": 3600,
    "operationMaxSeconds": 30, "recoveryMaxSeconds": 30}


class Owner:
    def __init__(self, broker, value):
        broker.require_owner_configuration()
        m.require(set(value) == {"apiVersion", "phase", "configuration"} and value["apiVersion"] == CHANNEL and value["phase"] == "configure")
        config = value["configuration"]
        m.require(type(config) is dict and set(config) == {"apiVersion", "sourceRevision", "authorityRootPublicKey",
            "authorityRootSpkiSha256", "controlPlaneConfigurationDigest", "deploymentId", "instanceId", "limits", "windows",
            "applications", "recoveryTargets", "identity", "callbackOrigin", "portalOrigin", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256",
            "authorityConfigurationOriginal", "setupLimits"}
            and config["apiVersion"] == CONFIG and config["windows"] == WINDOWS
            and config["limits"] == {"pendingCapacity": 64, "revocationCapacity": 64}
            and type(config["identity"]) is dict and set(config["identity"]) == IDENTITY_FIELDS)
        setup_limits = config["setupLimits"]
        m.require(type(setup_limits) is dict and set(setup_limits) == {"setupCapacity", "setupMaxSeconds"}
            and type(setup_limits["setupCapacity"]) is int and setup_limits["setupCapacity"] == 64)
        m.integer(setup_limits["setupMaxSeconds"], minimum=300, maximum=604800)
        exchange.origin(config["callbackOrigin"]); exchange.origin(config["portalOrigin"])
        m.require(config["callbackOrigin"] != config["portalOrigin"])
        for name in ("authorityRootSpkiSha256", "controlPlaneConfigurationDigest", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256"):
            m.digest(config[name])
        m.require(type(config["applications"]) is dict and 1 <= len(config["applications"]) <= 2)
        for provider, application in config["applications"].items():
            m.require(provider in exchange.AUTHORIZATION and type(application) is dict
                and set(application) == {"enrollmentOriginal", "material", "tlsRootsPem"})
            raw = m.decoded(application["enrollmentOriginal"], 32768)
            enrollment = m.document(raw, 32768, exact=False)
            m.application_header(application["material"], enrollment["payload"], m.sha(raw))
            m.require(enrollment["payload"]["providerId"] == provider and application["material"]["secretKekId"] == broker.key_id
                and enrollment["payload"]["redirectUri"] == exchange.callback_uri(config["callbackOrigin"], provider))
            m.text(application["tlsRootsPem"], 128 * 1024)
        targets = config["recoveryTargets"]
        m.require(type(targets) is list and len(targets) <= 64 and targets == sorted(set(targets)))
        for identifier in targets:
            exchange.identifier(identifier)
        self.broker, self.config = broker, config
        self.drafts, self.recovered, self.operation = {}, set(), None
        broker.channel.send({"apiVersion": CHANNEL, "phase": "configured"})

    def handle(self, value):
        self.broker.channel.check()
        m.require(value.get("apiVersion") == CHANNEL)
        phase = value.get("phase")
        if phase == "draft":
            m.require(set(value) == {"apiVersion", "phase", "intent", "deadlineBoottimeNs"}
                and self.operation is None and len(self.drafts) < 16)
            operation = _Operation.draft(self, value)
            self.drafts[operation.identifier] = operation
            self.operation = operation
            operation.prepare("prepare", operation.consent)
        elif phase == "draft-delivered":
            m.require(set(value) == {"apiVersion", "phase", "exchangeId"} and self.operation is not None
                and self.operation.identifier == value["exchangeId"] and self.operation.phase == "prepare")
            # No permission is inferred from browser delivery. The exact draft
            # stays resident until a genuine consent receipt returns with its
            # original native-origin cookie; no reconstructed draft is admitted.
            operation = self.operation
            operation.check()
            operation.draft_delivered = True
            self.operation = None
            self.broker.channel.send({"apiVersion": CHANNEL, "phase": "draft-cookie", "exchangeId": operation.identifier,
                "cookieName": exchange.cookie_name(operation.identifier), "cookieValue": operation.browser_nonce,
                "expiresAtEpochNs": operation.state["contactExpiresAtEpochNs"]})
        elif phase in {"authorize", "callback"}:
            expected = {"apiVersion", "phase", "exchangeId", "browserNonce", "deadlineBoottimeNs"} | ({"originals"} if phase == "authorize" else {"query", "providerId"})
            m.require(set(value) == expected and self.operation is None)
            operation = self.drafts.get(value["exchangeId"])
            m.require(operation is not None and operation.draft_delivered and not operation.terminal)
            m.require(phase != "callback" or value["providerId"] == operation.provider)
            exchange.require_browser(operation.state, value["browserNonce"])
            self.operation = operation
            operation.window(value["deadlineBoottimeNs"], operation.state["retentionExpiresAtEpochNs"])
            if phase == "authorize":
                operation.authorize(value["originals"])
            else:
                operation.callback(value["query"])
        elif phase == "recover":
            m.require(set(value) == {"apiVersion", "phase", "exchangeId", "exchangeOriginal", "custodyOriginal", "setupOriginal", "deadlineBoottimeNs"}
                and self.operation is None and value["exchangeId"] in self.config["recoveryTargets"]
                and value["exchangeId"] not in self.recovered)
            self.recovered.add(value["exchangeId"])
            self.operation = _Operation.recover(self, value)
        else:
            m.require(phase == "receipt" and set(value) == {"apiVersion", "phase", "originals"} and self.operation is not None)
            self.operation.receipt(value["originals"])


class _Operation:
    def __init__(self, owner, provider):
        self.owner, self.broker, self.config = owner, owner.broker, owner.config
        self.provider, self.app = provider, owner.config["applications"][provider]
        self.verifier = Receipts(self.config)
        self.assignment, self.phase, self.expected = None, None, None
        self.nonce, self.recovery_digest = os.urandom(32), None
        self.post_attempted, self.identity_attempted, self.terminal = False, False, False
        self.authorized, self.draft_delivered, self.recovery = False, False, False
        self.callback_spent = False
        self.setup_binding, self.setup, self.acquired_setup_original = None, None, None

    def window(self, deadline, expires):
        self.started, boot = time.time_ns(), time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        m.integer(deadline, maximum=2**64 - 1)
        m.require(self.setup_binding is not None)
        expires = min(expires, self.setup_binding["expiresAtEpochNs"])
        self.deadline = min(deadline, self.broker.channel.deadline, boot + 30_000_000_000, boot + expires - self.started)
        m.require(boot < self.deadline)
        self.expires = self.started + self.deadline - boot
        self.check()

    def check(self):
        self.broker.channel.check(self.deadline)
        m.require(not self.terminal and self.started <= time.time_ns() < self.expires
            and time.time_ns() < self.setup_binding["expiresAtEpochNs"] and self.owner.operation in {None, self})

    @classmethod
    def draft(cls, owner, value):
        intent = material.intent(value["intent"])
        operation = cls(owner, intent["providerId"])
        operation.setup_binding = material.binding(intent["setupBinding"])
        envelope = m.document(m.decoded(operation.app["enrollmentOriginal"], 32768), 32768, exact=False)
        now = time.time_ns()
        end = min(envelope["payload"]["expiresAtEpochNs"], operation.setup_binding["expiresAtEpochNs"])
        contact = min(now + 600_000_000_000, end)
        retention = min(contact + 600_000_000_000, end)
        pending = min(contact + 3600_000_000_000, end)
        m.require(now < contact <= retention <= pending)
        operation.window(value["deadlineBoottimeNs"], contact)
        operation.draft_started, operation.draft_expires = operation.started, operation.expires
        operation.private, operation.browser_nonce = material.prepare(intent,
            enrollment_original=m.decoded(operation.app["enrollmentOriginal"], 32768),
            callback_origin=operation.config["callbackOrigin"], portal_origin=operation.config["portalOrigin"], limits=operation.config["limits"],
            issued_ns=now, contact_expires_ns=contact, retention_expires_ns=retention, pending_expires_ns=pending)
        operation.state = material.private_state(operation.private)
        operation.identifier = operation.state["exchangeId"]
        operation.consent = {name: operation.state[name] for name in ("providerId", "credentialName", "scopes", "metadata", "redirectUri",
            "issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "enrollmentSha256", "limits", "portalOrigin", "callbackOrigin", "setupBinding")}
        operation.consent.update(exchangeId=operation.identifier, stateSha256=m.sha(operation.state["state"].encode("ascii")),
            browserNonceSha256=operation.state["browserNonceSha256"], pkceVerifierSha256=m.sha(operation.state["codeVerifier"].encode("ascii")),
            pkceChallenge=m.encoded(bytes.fromhex(m.sha(operation.state["codeVerifier"].encode("ascii"))[7:])),
            stateOriginalSha256=m.sha(operation.private), stateEnvelope=operation.seal("state", operation.private),
            reservedEnvelope=operation.seal(None, m.canonical({"schema": "catchplate.nativeOAuthSetupReserved/v1", "exchangeId": operation.identifier})))
        return operation

    @classmethod
    def recover(cls, owner, value):
        # These read-only bytes are untrusted acquisition, never permission.
        # No decrypt/provider request occurs before the real recovery receipt.
        row = m.document(value["exchangeOriginal"].encode("ascii"), 1024 * 1024)
        custody = m.document(value["custodyOriginal"].encode("ascii"), 4 * 1024 * 1024)
        m.require(row["id"] == custody["id"] == value["exchangeId"] and custody["status"] in {"captured", "staged"})
        operation = cls(owner, row["provider_id"])
        m.require(row["enrollment_original"] == operation.app["enrollmentOriginal"])
        operation.identifier = value["exchangeId"]
        operation.consent = m.document(row["consent_json"].encode("ascii"), 1024 * 1024)
        operation.setup_binding = initial_binding(custody["setup_initial_json"])
        m.require(operation.consent["setupBinding"] == operation.setup_binding)
        setup_row(value["setupOriginal"])  # Bounded acquisition data, never permission.
        operation.acquired_setup_original = value["setupOriginal"]
        operation.state = {"requesterId": row["requester_id"], "credentialPolicy": m.document(row["credential_policy_json"].encode("ascii"), 8192),
            "setupBinding": operation.setup_binding}
        operation.recovery = True
        operation.window(value["deadlineBoottimeNs"], operation.consent["pendingExpiresAtEpochNs"])
        # The current assignment is delivered from the same independently
        # signed cold configuration. It is rechecked by both authority roles;
        # this historical capture contributes no current assignment permission.
        operation.assignment = operation.verifier.recovery_assignment(operation.provider)
        operation.prepare("recover", {"exchangeId": operation.identifier, "custodyRowSha256": m.sha(value["custodyOriginal"].encode("ascii")),
            "captureInputSha256": m.sha(custody["capture_arguments_json"].encode("ascii")), "ownerNonceSha256": m.sha(operation.nonce),
            "issuedAtEpochNs": operation.started, "expiresAtEpochNs": operation.expires - 1, "limits": operation.config["limits"]})
        return operation

    def seal(self, purpose, raw):
        identifier = self.identifier if purpose is None else exchange.artifact_id(self.identifier, purpose)
        return m.seal_original(identifier, raw, 1, self.broker.key_id, self.broker.kek, time.time_ns())

    def prepare(self, phase, request):
        self.check(); self.phase = phase
        m.require("setupBinding" not in request or request["setupBinding"] == self.setup_binding)
        request = {**request, "setupBinding": self.setup_binding}
        self.expected = {"action": "credential.oauth.measured-setup-consent", "resource_id": self.identifier,
            "payload_digest": m.sha(m.canonical(request)), "actor_id": self.state["requesterId"], "request": request,
            "approval_id": None, "credential_policy": self.state["credentialPolicy"], "enrollment_original": self.app["enrollmentOriginal"],
            "control_plane_configuration_digest": self.config["controlPlaneConfigurationDigest"], "assignment_original": self.assignment}
        expiry = min(self.expires, self.consent["contactExpiresAtEpochNs"]) if phase in {"prepare", "claim", "cancel"} else self.expires
        self.broker.channel.send({"apiVersion": CHANNEL, "phase": "prepared", "operation": "oauth.measured-setup." + phase,
            "arguments": self.expected, "issuedAtEpochNs": self.started, "expiresAtEpochNs": expiry}, self.deadline)

    def authorize(self, originals):
        self.check()
        m.require(not self.authorized and self.phase == "prepare" and not self.post_attempted and not self.recovery)
        result, self.row, self.custody, self.assignment, enrollment, self.setup = self.verifier.verify(originals, self.expected,
            started=self.draft_started, expires=self.draft_expires, processing_expires=self.consent["contactExpiresAtEpochNs"])
        m.require(result["exchange"]["status"] == "prepared" and self.row["consent_json"].encode("ascii") == m.canonical(self.consent))
        self.client = m.open_application(self.app["material"], enrollment, self.consent["enrollmentSha256"], self.broker.key_id, self.broker.kek)
        self.authorized = True
        self.broker.channel.send({"apiVersion": CHANNEL, "phase": "authorization-redirect", "exchangeId": self.identifier,
            "location": exchange.authorization_url(self.state, self.client)}, self.deadline)
        self.owner.operation = None

    def callback(self, query):
        self.check()
        m.require(self.authorized and not self.callback_spent and not self.post_attempted and not self.recovery
            and type(query) is str and len(query.encode("ascii")) <= 8192)
        fields = parse_qsl(query, keep_blank_values=True, strict_parsing=True, max_num_fields=8, encoding="utf-8", errors="strict")
        m.require(len({key for key, _ in fields}) == len(fields))
        callback = dict(fields)
        m.require("state" in callback and hmac.compare_digest(callback["state"], self.state["state"]))
        allowed = {"state", "code", "scope", "authuser", "prompt"} if "code" in callback else {"state", "error", "error_description", "error_uri"}
        m.require(set(callback) <= allowed and ("code" in callback) != ("error" in callback))
        self.callback_spent = True
        raw = m.canonical({"schema": "catchplate.nativeOAuthSetupCallbackOriginal/v1", "exchangeId": self.identifier,
            "providerId": self.provider, "query": query, "browserNonceSha256": self.state["browserNonceSha256"]})
        self.callback_original = raw
        request = {"exchangeId": self.identifier, "exchangeRowSha256": m.sha(m.canonical(self.row)),
            "callbackSha256": m.sha(raw), "callbackEnvelope": self.seal("callback", raw), "limits": self.config["limits"]}
        if "error" in callback:
            exchange.text(callback["error"], 256)
            self.prepare("cancel", request)
            return
        self.token_request = exchange.token_request(self.state, self.client, callback["code"])
        request.update(ownerNonceSha256=m.sha(self.nonce), codeSha256=m.sha(callback["code"].encode("utf-8")),
            contactRequestSha256=self.token_request[4])
        self.prepare("claim", request)

    def receipt(self, originals):
        self.check()
        result, row, custody, assignment, enrollment, setup = self.verifier.verify(originals, self.expected, started=self.started, expires=self.expires)
        m.require(assignment == self.assignment and result["operation"] == "oauth.measured-setup." + self.phase)
        self.row, self.custody, self.setup = row, custody, setup
        if self.phase == "claim":
            m.require(custody["status"] == row["status"] == "claimed" and not self.post_attempted and not self.recovery
                and time.time_ns() < self.consent["contactExpiresAtEpochNs"])
            self.post_attempted = True
            self.raw, self.received, self.status, self.body = Contact(channel=self.broker.channel, provider=self.provider, purpose="token",
                roots=self.app["tlsRootsPem"], request=self.token_request, check=self.contact_check, deadline=self.deadline).run()
            issued = m.issued_original(self.body, self.state["oauth_application_owner"])
            self.capture = {"exchangeId": self.identifier, "exchangeRowSha256": result["exchange"]["exchangeRowSha256"],
                "setupBinding": self.setup_binding,
                "ownerNonce": m.encoded(self.nonce), "limits": self.config["limits"], "rawResponseSha256": m.sha(self.raw),
                "rawResponseEnvelope": self.seal("response", self.raw), "issuedMaterialSha256": None if issued is None else m.sha(issued),
                "issuedMaterialEnvelope": None if issued is None else self.seal(None, issued), "receivedAtEpochNs": self.received}
            self.prepare("capture", self.capture)
        elif self.phase == "recover":
            m.require(m.canonical(setup).decode("ascii") == self.acquired_setup_original)
            if custody["status"] == "staged":
                m.require("pending" in result); self.done("observed-staged"); return
            m.require(custody["status"] == "captured" and custody["recovery_request_digest"] == result["requestDigest"])
            self.recovery_digest = result["requestDigest"]
            self.private = m.open_original(exchange.artifact_id(self.identifier, "state"), self.consent["stateEnvelope"], 1, self.broker.key_id, self.broker.kek)
            m.require(m.sha(self.private) == self.consent["stateOriginalSha256"])
            self.state = material.private_state(self.private)
            m.require(self.state["setupBinding"] == self.setup_binding
                and self.state["requesterId"] == self.row["requester_id"])
            capture = m.document(custody["capture_arguments_json"].encode("ascii"), 2 * 1024 * 1024)
            self.capture = capture["request"]
            self.raw = m.open_original(exchange.artifact_id(self.identifier, "response"), self.capture["rawResponseEnvelope"], 1, self.broker.key_id, self.broker.kek)
            m.require(m.sha(self.raw) == self.capture["rawResponseSha256"])
            raw = m.document(self.raw, m.MAX_ORIGINAL)
            m.require(set(raw) == {"status", "rawHeaders", "bodyBase64url"})
            self.status, self.received = raw["status"], self.capture["receivedAtEpochNs"]
            self.body = m.decoded(raw["bodyBase64url"], m.MAX_REPLY) if raw["bodyBase64url"] else b""
            self.client = m.open_application(self.app["material"], enrollment, self.consent["enrollmentSha256"], self.broker.key_id, self.broker.kek)
            self.stage()
        elif self.phase == "capture":
            m.require(custody["status"] == "captured" and row["status"] == "retained"
                and m.document(custody["capture_arguments_json"].encode("ascii"), 2 * 1024 * 1024)["request"] == self.capture)
            self.stage()
        else:
            m.require(self.phase in {"stage", "cancel"} and custody["status"] == {"stage": "staged", "cancel": "cancelled"}[self.phase])
            if self.phase == "stage":
                pending = m.document(custody["pending_original_json"].encode("ascii"), 1024 * 1024)
                m.require(all(pending[name] == self.expected["request"]["tokenEnvelope"][name] for name in m.ENVELOPE_FIELDS)
                    and pending["payload_digest"] == self.expected["request"]["payloadDigest"])
            self.done(custody["status"])

    def contact_check(self):
        self.check()
        m.require(not self.recovery and time.time_ns() < self.consent["contactExpiresAtEpochNs"])

    def stage(self):
        self.check()
        issued_envelope = self.capture["issuedMaterialEnvelope"]
        if issued_envelope is None:
            self.done("captured-unusable"); return
        issued = m.open_original(self.identifier, issued_envelope, 1, self.broker.key_id, self.broker.kek)
        m.require(m.sha(issued) == self.capture["issuedMaterialSha256"]
            and issued == m.issued_original(self.body, self.state["oauth_application_owner"]))
        try:
            final_raw, token = exchange.token_original(self.status, self.body, self.received, self.state)
        except (ValueError, TypeError, KeyError):
            self.done("captured-unusable"); return
        m.require(not self.identity_attempted and time.time_ns() < self.consent["pendingExpiresAtEpochNs"])
        self.identity_attempted = True
        identity_raw, _received, status, body = Contact(channel=self.broker.channel, provider=self.provider, purpose="identity",
            roots=self.app["tlsRootsPem"], request=exchange.identity_request(self.provider, token), check=self.check, deadline=self.deadline).run()
        m.require(200 <= status < 300)
        identity = exchange.identity_metadata(self.provider, body)
        metadata = {**self.state["metadata"], "oauth": True, "refreshable": True, "provider": self.provider + ".oauth2",
            "provider_id": self.provider, "scopes": sorted(m.scopes(token["scope"])), "token_type": "Bearer",
            "expires_at_epoch_ms": token["expires_at_epoch_ms"], "created_by": self.state["requesterId"],
            "injection_field": "access_token", **identity, "oauth_application_owner": self.state["oauth_application_owner"]}
        if "refresh_token_expires_at_epoch_ms" in token:
            metadata["refresh_token_expires_at_epoch_ms"] = token["refresh_token_expires_at_epoch_ms"]
        metadata["oauth_client_id" if self.provider == "google" else "x_app_id"] = self.client["clientId"]
        review = {"credential_type": "oauth2", "provider": self.provider, "provider_subject": metadata["provider_subject"],
            "provider_account": metadata["provider_account"], "scopes": metadata["scopes"], "credential_name": self.state["credentialName"],
            "metadata_keys": sorted(metadata), "expires_at_epoch_ms": metadata.get("expires_at_epoch_ms"),
            "oauth_application_owner": self.state["oauth_application_owner"]}
        if self.provider == "x":
            review["x_app_id"] = metadata["x_app_id"]
        token_digest = m.sha(final_raw)
        request = {"exchangeId": self.identifier, "exchangeRowSha256": m.sha(m.canonical(self.row)),
            "ownerNonce": m.encoded(self.nonce), "limits": self.config["limits"], "tokenSecretSha256": token_digest,
            "tokenEnvelope": self.seal(None, final_raw), "identityRawSha256": m.sha(identity_raw), "identityRawEnvelope": self.seal("identity", identity_raw),
            "metadata": metadata, "review": review, "recoveryRequestDigest": self.recovery_digest,
            "payloadDigest": m.sha(m.canonical({"action": "credential.oauth.activate", "review": review, "encrypted_token_source_sha256": token_digest}))}
        self.prepare("stage", request)

    def done(self, status):
        self.check()
        self.broker.channel.send({"apiVersion": CHANNEL, "phase": "complete", "exchangeId": self.identifier,
            "status": status, "custodyRowSha256": m.sha(m.canonical(self.custody))}, self.deadline)
        self.terminal = True
        self.owner.operation = None
