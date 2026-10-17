"""Measured succession owner: historical closure before fresh same-account PKCE.

Every effect consumes its own signed protected transition. Recovery observes
only and cannot decrypt, recreate a nonce, resume cleanup, or repeat a POST.
"""
import hmac
import os
import time
from urllib.parse import parse_qsl
from catchplate import native_oauth_refresh as m
from catchplate import native_oauth_exchange as provider
from catchplate import native_oauth_succession as p
from catchplate import native_oauth_succession_rows as rows
from catchplate import native_oauth_succession_materials as retired
from catchplate.native_oauth_refresh_owner import IDENTITY_FIELDS
from catchplate.native_oauth_succession_receipts import Receipts
from catchplate.native_oauth_succession_tls import Contact

WINDOWS = {"contactMaxSeconds": 600, "retentionMaxSeconds": 600, "pendingMaxSeconds": 3600, "operationMaxSeconds": 30, "recoveryMaxSeconds": 30}
CHANNEL = p.CHANNEL
CONFIGURATION_FIELDS = frozenset({"apiVersion", "sourceRevision", "authorityRootPublicKey", "authorityRootSpkiSha256",
    "authorityConfigurationOriginal", "controlPlaneConfigurationDigest", "deploymentId", "instanceId", "limits", "successionLimits",
    "windows", "applications", "historicalApplications", "recoveryTargets", "callbackOrigin", "portalOrigin", "identity",
    "ingressLeafCertificateSha256", "ingressLeafSpkiSha256"})
RECOVERY_FIELDS = frozenset({"apiVersion", "okForAction", "journalOriginal", "scopeOriginal", "materialOriginals", "attemptOriginals",
    "exchangeOriginal", "custodyOriginal", "candidateOriginal"})


class Owner:
    def __init__(self, broker, value):
        broker.require_owner_configuration()
        m.require(broker.historical_keys is not None and broker.historical_keys.finished
            and type(value) is dict and set(value) == {"apiVersion", "phase", "configuration"}
            and value["apiVersion"] == p.CHANNEL and value["phase"] == "configure" and len(m.canonical(value)) <= p.MAX_MESSAGE)
        config = value["configuration"]
        m.require(type(config) is dict and set(config) == CONFIGURATION_FIELDS and config["apiVersion"] == p.CONFIG
            and config["windows"] == WINDOWS and config["successionLimits"] == p.LIMITS
            and config["limits"] == {"pendingCapacity": 64, "revocationCapacity": 64}
            and type(config["identity"]) is dict and set(config["identity"]) == IDENTITY_FIELDS)
        for group in ("limits", "windows", "successionLimits"):
            m.require(all(type(item) is int for item in config[group].values()))
        provider.origin(config["callbackOrigin"]); provider.origin(config["portalOrigin"])
        m.require(config["callbackOrigin"] != config["portalOrigin"])
        for name in ("authorityRootSpkiSha256", "controlPlaneConfigurationDigest", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256"):
            m.digest(config[name])
        m.require(type(config["applications"]) is dict and 1 <= len(config["applications"]) <= 2)
        order, current = [], set()
        def application(app):
            m.require(type(app) is dict and set(app) == {"enrollmentOriginal", "material", "tlsRootsPem"})
            raw = m.decoded(app["enrollmentOriginal"], 32768)
            enrollment = m.document(raw, 32768)["payload"]
            m.application_header(app["material"], enrollment, m.sha(raw)); m.text(app["tlsRootsPem"], 128 * 1024)
            known = {broker.key_id} | set(broker.historical_keys.keys)
            m.require(app["material"]["secretKekId"] in known)
            return raw, enrollment
        for identifier, app in config["applications"].items():
            raw, enrollment = application(app)
            m.require(identifier in provider.AUTHORIZATION and enrollment["providerId"] == identifier
                and app["material"]["secretKekId"] == broker.key_id
                and enrollment["redirectUri"] == provider.callback_uri(config["callbackOrigin"], identifier))
            current.add(m.sha(raw))
        historical = config["historicalApplications"]
        m.require(type(historical) is list and len(historical) <= 16)
        for item in historical:
            m.require(type(item) is dict and set(item) == {"enrollmentSha256", "enrollmentRootSpkiSha256", "application"})
            raw, _ = application(item["application"])
            m.require(m.sha(raw) == item["enrollmentSha256"] and item["enrollmentSha256"] not in current)
            m.digest(item["enrollmentRootSpkiSha256"]); order.append(item["enrollmentSha256"])
        m.require(order == sorted(set(order)))
        targets = config["recoveryTargets"]
        m.require(type(targets) is list and len(targets) <= 64 and targets == sorted(set(targets)))
        for identifier in targets:
            provider.identifier(identifier)
        verifier = Receipts(config)
        for app in config["applications"].values():
            verifier.application(m.sha(m.decoded(app["enrollmentOriginal"], 32768)), historical=False)
        for item in historical:
            verifier.application(item["enrollmentSha256"], historical=True)
        broker.historical_keys.check()
        self.broker, self.config = broker, config
        self.operations, self.seen, self.operation, self.poisoned = {}, set(), None, False
        broker.channel.send({"apiVersion": p.CHANNEL, "phase": "configured"})

    def __copy__(self):
        raise ValueError("succession owner cannot be copied")

    def __deepcopy__(self, memo):
        raise ValueError("succession owner cannot be copied")

    def handle(self, value):
        try:
            self._handle(value)
        except BaseException:
            self.poisoned = True
            raise

    def _handle(self, value):
        self.broker.channel.check()
        m.require(not self.poisoned and type(value) is dict and value.get("apiVersion") == p.CHANNEL and len(m.canonical(value)) <= p.MAX_MESSAGE)
        phase = value.get("phase")
        if phase == "begin":
            m.require(set(value) == {"apiVersion", "phase", "intent", "deadlineBoottimeNs"} and self.operation is None and len(self.seen) < 16)
            intent = p.intent(value["intent"])
            identifier = p.grant(m.decoded(intent["authorizationOriginal"], p.MAX_GRANT))["payload"]["authorizationId"]
            m.require(identifier not in self.seen); self.seen.add(identifier)
            operation = _Operation.begin(self, value)
            self.operations[identifier] = self.operation = operation
            operation.next_material()
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
            m.require(set(value) == {"apiVersion", "phase", "exchangeId", "originals", "deadlineBoottimeNs"}
                and self.operation is None and value["exchangeId"] in self.config["recoveryTargets"] and value["exchangeId"] not in self.seen)
            self.seen.add(value["exchangeId"])
            operation = _Operation.recover(self, value)
            self.operations[operation.identifier] = self.operation = operation
            operation.prepare("recover", {"materialId": None, "custodyRowSha256": None if operation.acquired["custodyOriginal"] is None else
                m.sha(operation.acquired["custodyOriginal"].encode("ascii")), "issuedAtEpochNs": operation.started, "expiresAtEpochNs": operation.expires - 1})
        else:
            m.require(phase == "receipt" and set(value) == {"apiVersion", "phase", "originals"} and self.operation is not None)
            self.operation.receipt(value["originals"])


class _Operation:
    def __init__(self, owner, provider_id):
        self.owner, self.broker, self.config = owner, owner.broker, owner.config
        self.provider, self.app = provider_id, owner.config["applications"][provider_id]
        self.verifier = Receipts(self.config)
        self.phase = self.expected = self.last_arguments = self.nonce = None
        self.terminal = self.authorized = self.recovery = self.post_attempted = self.identity_attempted = self.callback_spent = self.receipt_spent = False
        self.current_material = self.current_pin = self.material_original = self.material_nonce = None
        self.material_index = 0
        self.row = self.custody = self.state = self.acquired = None

    def window(self, deadline, expiry):
        self.started, boot = time.time_ns(), time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        m.integer(deadline, maximum=2**64 - 1)
        self.deadline = min(deadline, self.broker.channel.deadline, boot + 30_000_000_000, boot + min(expiry, self.grant["expiresAtEpochNs"]) - self.started)
        m.require(boot < self.deadline)
        self.expires = self.started + self.deadline - boot
        self.check()

    def check(self):
        self.broker.channel.check(self.deadline)
        m.require(not self.terminal and not self.owner.poisoned and self.started <= time.time_ns() < self.expires
            and time.time_ns() < self.grant["expiresAtEpochNs"] and self.owner.operation in {None, self})

    def contact_check(self):
        self.check(); m.require(not self.recovery and time.time_ns() < self.grant["contactExpiresAtEpochNs"])

    @classmethod
    def begin(cls, owner, value):
        intent = p.intent(value["intent"])
        operation = cls(owner, intent["providerId"])
        journal, scope, target, operation.grant, operation.assignment, _ = operation.verifier.fence(intent)
        operation.identifier, operation.intent = operation.grant["authorizationId"], intent
        operation.scope_original = operation.verifier.originals.scope_original
        operation.scope_sha = m.sha(operation.scope_original.encode("ascii"))
        operation.credential_policy = rows.stored(journal["credential_policy_json"], 8192)
        operation.fence_originals = (m.decoded(intent["scopeRequestOriginal"], p.MAX_REQUEST), m.decoded(intent["scopeResponseOriginal"], p.MAX_RESPONSE))
        operation.window(value["deadlineBoottimeNs"], operation.grant["contactExpiresAtEpochNs"])
        # Check the complete admitted ciphertext key inventory before the first
        # material phase; possession still grants no decryption before CLAIM.
        owner.broker.historical_keys.check()
        known = {owner.broker.key_id} | set(owner.broker.historical_keys.keys)
        m.require(all(item["tokenEnvelope"]["secret_kek_id"] in known
            for item in operation.verifier.originals.inventory["materialOriginals"]))
        return operation

    @classmethod
    def recover(cls, owner, value):
        acquired = value["originals"]
        m.require(type(acquired) is dict and set(acquired) == RECOVERY_FIELDS
            and acquired["apiVersion"] == "catchplate.nativeOAuthSuccessionRecoveryOriginalResponse/v1" and acquired["okForAction"] is False)
        journal = rows.stored(acquired["journalOriginal"])
        grant = p.grant(journal["authorization_original"].encode("ascii"))["payload"]
        operation = cls(owner, grant["providerId"])
        operation.grant, operation.assignment, _ = operation.verifier.admit(m.encoded(journal["authorization_original"].encode("ascii")), grant["providerId"])
        operation.identifier, operation.acquired, operation.recovery = grant["authorizationId"], acquired, True
        m.require(value["exchangeId"] == operation.identifier and journal["scope_original_json"] == acquired["scopeOriginal"])
        operation.scope_original = acquired["scopeOriginal"]
        operation.scope_sha = m.sha(operation.scope_original.encode("ascii"))
        operation.credential_policy = rows.stored(journal["credential_policy_json"], 8192)
        operation.window(value["deadlineBoottimeNs"], grant["expiresAtEpochNs"])
        return operation  # No nonce, PKCE, decrypt, or historical contact owner.

    def prepare(self, phase, request, *, material_id=None):
        self.check(); m.require(phase in p.PHASES)
        self.phase, self.receipt_spent = phase, False
        request = {**request, "scopeRowSha256": self.scope_sha}
        selected = self.verifier.material_applications[material_id] if material_id is not None else (
            self.app, self.verifier.application_original, self.verifier.enrollment, self.assignment)
        _, application_raw, _, assignment = selected
        self.expected = {"action": p.ACTION, "resource_id": self.identifier, "payload_digest": m.sha(m.canonical(request)),
            "actor_id": self.grant["requesterId"], "request": request, "approval_id": None, "credential_policy": self.credential_policy,
            "enrollment_original": m.encoded(application_raw), "control_plane_configuration_digest": self.config["controlPlaneConfigurationDigest"],
            "assignment_original": assignment, "authorization_original": m.encoded(self.verifier.grant_raw)}
        m.require(len(m.canonical(self.expected)) <= p.MAX_ARGUMENT)
        expiry = min(self.expires, self.grant["contactExpiresAtEpochNs"]) if phase in {"inspect", "material-claim", "contact", "prepare", "claim", "cancel"} else self.expires
        self.broker.channel.send({"apiVersion": p.CHANNEL, "phase": "prepared", "operation": "oauth.measured-succession." + phase,
            "arguments": self.expected, "issuedAtEpochNs": self.started, "expiresAtEpochNs": expiry}, self.deadline)

    def next_material(self):
        self.contact_check()
        if self.current_material is not None:
            m.require(len(self.current_material.completed) == len(self.current_pin["tokenPurposes"]))
            self.current_material = None; self.material_index += 1
        if self.material_index < len(self.grant["materials"]):
            self.current_pin = self.grant["materials"][self.material_index]
            self.material_nonce = os.urandom(32)
            self.prepare("inspect", {"materialId": self.current_pin["materialId"], "issuedAtEpochNs": self.started,
                "expiresAtEpochNs": min(self.expires, self.grant["contactExpiresAtEpochNs"]) - 1}, material_id=self.current_pin["materialId"])
            return
        self.current_pin = self.material_nonce = None
        self.closure_sha = self.verifier.originals.closure(self.grant)
        self.private, self.browser_nonce = p.prepare(self.intent, authorization=self.grant, scope_original=self.scope_original,
            closure_sha256=self.closure_sha, enrollment_original=self.verifier.application_original,
            callback_origin=self.config["callbackOrigin"], portal_origin=self.config["portalOrigin"], limits=self.config["limits"], issued_ns=time.time_ns())
        self.state = p.private_state(self.private); self.nonce = os.urandom(32)
        self.consent = {name: self.state[name] for name in ("providerId", "credentialName", "scopes", "metadata", "redirectUri", "issuedAtEpochNs",
            "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "enrollmentSha256", "limits", "portalOrigin", "callbackOrigin")}
        self.consent.update(exchangeId=self.identifier, stateSha256=m.sha(self.state["state"].encode("ascii")), browserNonceSha256=self.state["browserNonceSha256"],
            pkceVerifierSha256=m.sha(self.state["codeVerifier"].encode("ascii")), pkceChallenge=m.encoded(bytes.fromhex(m.sha(self.state["codeVerifier"].encode("ascii"))[7:])),
            stateOriginalSha256=m.sha(self.private), stateEnvelope=self.seal("state", self.private),
            reservedEnvelope=self.seal(None, m.canonical({"schema": "catchplate.nativeOAuthSuccessionReserved/v1", "exchangeId": self.identifier})),
            scopeRowSha256=self.scope_sha)
        self.prepare("prepare", self.consent)

    def seal(self, purpose, raw):
        identifier = self.identifier if purpose is None else provider.artifact_id(self.identifier, purpose)
        return m.seal_original(identifier, raw, 1, self.broker.key_id, self.broker.kek, time.time_ns())

    def receipt(self, originals):
        self.check(); m.require(not self.receipt_spent); self.receipt_spent = True
        result, _, selected = self.verifier.verify(originals, self.expected, phase=self.phase, started=self.started, expires=self.expires)
        # Preserve the actual signed request argument, including own proof.
        frame = m.document(m.decoded(originals["requestOriginal"], p.MAX_REQUEST), p.MAX_REQUEST)
        self.last_arguments = frame["input"]["arguments"]
        if self.phase == "recover":
            m.require(self.recovery and result["observation"]["contactDisposition"] == "observation-only")
            for name in RECOVERY_FIELDS - {"apiVersion", "okForAction"}:
                m.require(result["originals"][name] == self.acquired[name])
            self.custody = None if result["originals"]["custodyOriginal"] is None else rows.stored(result["originals"]["custodyOriginal"])
            status = result["observation"]["status"]
            m.require(status in {"fenced", "prepared", "claimed", "captured", "staged", "cancelled", "committed"})
            self.done("observed-" + status); return
        m.require(not self.recovery)
        if self.phase == "inspect":
            self.material_original, _, _, _, _ = retired.inspect(self, result, self.current_pin)
            self.prepare("material-claim", {"materialId": self.current_pin["materialId"], "materialOriginalSha256": m.sha(self.material_original.encode("ascii")),
                "ownerNonceSha256": m.sha(self.material_nonce)}, material_id=self.current_pin["materialId"]); return
        if self.phase == "material-claim":
            self.current_material = retired.ClaimedMaterial(self, result)
            self.current_material.decrypt(); self.current_material.next(); return
        if self.phase in {"contact", "finish"}:
            m.require(self.current_material is not None); self.current_material.receipt(result); return
        self.row, self.custody, _ = self.verifier.originals.fresh(result, self.last_arguments, self.grant, self.phase)
        if self.phase == "prepare":
            m.require(not self.authorized and self.row["consent_json"].encode("ascii") == m.canonical(self.consent)
                and result["observation"]["closureSha256"] == self.closure_sha)
            self.client = m.open_application(self.app["material"], selected[2], self.grant["enrollmentSha256"], self.broker.key_id, self.broker.kek)
            self.authorized = True
            self.broker.channel.send({"apiVersion": p.CHANNEL, "phase": "authorization-redirect", "exchangeId": self.identifier,
                "location": provider.authorization_url(self.state, self.client), "cookieName": provider.cookie_name(self.identifier),
                "cookieValue": self.browser_nonce, "expiresAtEpochNs": self.grant["contactExpiresAtEpochNs"]}, self.deadline)
            self.owner.operation = None
        elif self.phase == "claim":
            m.require(not self.post_attempted); self.contact_check(); self.post_attempted = True
            self.raw, self.received, self.status, self.body = Contact(channel=self.broker.channel, provider=self.provider, purpose="token",
                roots=self.app["tlsRootsPem"], request=self.token_request, check=self.contact_check, deadline=self.deadline).run()
            issued = m.issued_original(self.body, self.state[m.ASSOCIATION])
            self.capture = {"exchangeId": self.identifier, "exchangeRowSha256": m.sha(m.canonical(self.row)), "ownerNonce": m.encoded(self.nonce),
                "limits": self.config["limits"], "rawResponseSha256": m.sha(self.raw), "rawResponseEnvelope": self.seal("response", self.raw),
                "issuedMaterialSha256": None if issued is None else m.sha(issued), "issuedMaterialEnvelope": None if issued is None else self.seal(None, issued),
                "receivedAtEpochNs": self.received, "scopeRowSha256": self.scope_sha}
            self.prepare("capture", self.capture)
        elif self.phase == "capture":
            m.require(rows.stored(self.custody["capture_arguments_json"], p.MAX_ARGUMENT)["request"] == self.capture)
            self.stage()
        else:
            m.require(self.phase in {"stage", "cancel"}); self.done(self.custody["status"])

    def callback(self, query):
        self.contact_check()
        m.require(self.authorized and not self.callback_spent and not self.post_attempted and type(query) is str and len(query.encode("ascii")) <= 8192)
        self.callback_spent = True
        fields = parse_qsl(query, keep_blank_values=True, strict_parsing=True, max_num_fields=8, encoding="utf-8", errors="strict")
        m.require(len({name for name, _ in fields}) == len(fields))
        callback = dict(fields)
        m.require("state" in callback and hmac.compare_digest(callback["state"], self.state["state"]))
        allowed = {"state", "code", "scope", "authuser", "prompt"} if "code" in callback else {"state", "error", "error_description", "error_uri"}
        m.require(set(callback) <= allowed and ("code" in callback) != ("error" in callback))
        raw = m.canonical({"schema": "catchplate.nativeOAuthSuccessionCallbackOriginal/v1", "exchangeId": self.identifier,
            "providerId": self.provider, "query": query, "browserNonceSha256": self.state["browserNonceSha256"]})
        request = {"exchangeId": self.identifier, "exchangeRowSha256": m.sha(m.canonical(self.row)), "callbackSha256": m.sha(raw),
            "callbackEnvelope": self.seal("callback", raw), "limits": self.config["limits"]}
        if "error" in callback:
            provider.text(callback["error"], 256); self.prepare("cancel", request); return
        self.token_request = provider.token_request(self.state, self.client, callback["code"])
        request.update(ownerNonceSha256=m.sha(self.nonce), codeSha256=m.sha(callback["code"].encode("utf-8")), contactRequestSha256=self.token_request[4])
        self.prepare("claim", request)

    def stage(self):
        self.check()
        if self.capture["issuedMaterialEnvelope"] is None:
            self.done("captured-unusable"); return
        issued = m.open_original(self.identifier, self.capture["issuedMaterialEnvelope"], 1, self.broker.key_id, self.broker.kek)
        m.require(m.sha(issued) == self.capture["issuedMaterialSha256"] and issued == m.issued_original(self.body, self.state[m.ASSOCIATION]))
        try:
            final_raw, token = provider.token_original(self.status, self.body, self.received, self.state)
        except (ValueError, TypeError, KeyError):
            self.done("captured-unusable"); return
        m.require(not self.identity_attempted); self.identity_attempted = True
        identity_raw, _, status, body = Contact(channel=self.broker.channel, provider=self.provider, purpose="identity",
            roots=self.app["tlsRootsPem"], request=provider.identity_request(self.provider, token), check=self.check, deadline=self.deadline).run()
        m.require(200 <= status < 300)
        identity = provider.identity_metadata(self.provider, body)
        m.require(identity["provider_subject"] == self.grant["providerSubject"] and identity["provider_account"] == self.grant["providerAccount"]
            and sorted(m.scopes(token["scope"])) == self.grant["scopes"])
        metadata = {**self.state["metadata"], "scopes": self.grant["scopes"], "token_type": "Bearer", "refreshable": True,
            "provider_identity_verified": True, "expires_at_epoch_ms": token["expires_at_epoch_ms"]}
        metadata.pop("refresh_token_expires_at_epoch_ms", None)
        if "refresh_token_expires_at_epoch_ms" in token:
            metadata["refresh_token_expires_at_epoch_ms"] = token["refresh_token_expires_at_epoch_ms"]
        review = {"credential_type": "oauth2", "provider": self.provider, "provider_subject": self.grant["providerSubject"], "provider_account": self.grant["providerAccount"],
            "scopes": self.grant["scopes"], "credential_name": self.state["credentialName"], "metadata_keys": sorted(metadata),
            "expires_at_epoch_ms": metadata["expires_at_epoch_ms"], m.ASSOCIATION: self.state[m.ASSOCIATION],
            "succession_credential_id": self.grant["credentialId"], "succession_credential_version": self.grant["credentialVersion"],
            "succession_scope_sha256": self.scope_sha, "succession_material_closure_sha256": self.closure_sha}
        if self.provider == "x":
            review["x_app_id"] = self.grant["clientId"]
        digest = m.sha(final_raw)
        request = {"exchangeId": self.identifier, "exchangeRowSha256": m.sha(m.canonical(self.row)), "ownerNonce": m.encoded(self.nonce), "limits": self.config["limits"],
            "tokenSecretSha256": digest, "tokenEnvelope": m.seal_original(self.grant["credentialId"], final_raw, self.grant["credentialVersion"] + 1,
                self.broker.key_id, self.broker.kek, time.time_ns()), "identityRawSha256": m.sha(identity_raw), "identityRawEnvelope": self.seal("identity", identity_raw),
            "metadata": metadata, "review": review, "recoveryRequestDigest": None, "payloadDigest": m.sha(m.canonical({"action": "credential.oauth.retirement-succession",
                "authorizationSha256": m.sha(self.verifier.grant_raw), "review": review, "encrypted_token_source_sha256": digest}))}
        self.prepare("stage", request)

    def done(self, status):
        self.check()
        self.broker.channel.send({"apiVersion": p.CHANNEL, "phase": "complete", "exchangeId": self.identifier, "status": status,
            "custodyRowSha256": None if self.custody is None else m.sha(m.canonical(self.custody))}, self.deadline)
        self.terminal, self.owner.operation = True, None
