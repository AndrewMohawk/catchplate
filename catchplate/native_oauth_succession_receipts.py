"""Purpose-fixed succession admission of real signed writer originals.

The writer remains trusted-host-local; this does not manufacture a TEE custody
receipt. Independent native role-4 proof and independent succession effect
permission remain separate. Historical enrollment expiration is not renewed.
"""
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from catchplate import native_oauth_refresh as m
from catchplate import native_oauth_exchange as provider
from catchplate import native_oauth_succession as material
from catchplate import native_oauth_succession_rows as rows
from catchplate import oauth_retirement_policy_values as scalar
from catchplate.native_oauth_refresh_receipts import domain, spki, CONFIG, SIGNED_CONFIG, REQUEST, INPUT, RESULT, REQUEST_FIELDS, RESPONSE_FIELDS

RESPONSE = "catchplate.policyAuthorityRetiredScopeSuccessionRuntimeResponse/v1"
POLICY = "catchplate.oauthRetiredScopeSuccessionAuthorityPolicy/v1"
POLICY_FIELDS = frozenset({"schema", "enrollmentRootPublicKeyBase64Url", "enrollmentRootSpkiSha256", "controlPlaneConfigurationDigest",
    "deploymentId", "pendingCapacity", "revocationCapacity", "contactMaxSeconds", "retentionMaxSeconds", "pendingMaxSeconds",
    "operationMaxSeconds", "recoveryMaxSeconds", "trustRoots", "assignments", "successionRootPublicKeyBase64Url", "successionRootSpkiSha256",
    "historicalEnrollmentRoots", "materialCapacity", "affectedLineageCapacity", "populationCapacity", "historyCapacity", "authorizationMaxSeconds"})
ASSIGNMENT = scalar.APPLICATION_ASSIGNMENT_FIELDS | {"portalOrigin", "callbackOrigin", "enrollmentRootSpkiSha256"}
CONSUMPTION = "catchplate.trustedHostLocalAuthorityAttestationConsumption/v1"
RESULT_FIELDS = frozenset({"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "originals", "observation"})


class Receipts:
    def __init__(self, config):
        self.config = config
        self.root = Ed25519PublicKey.from_public_bytes(m.decoded(config["authorityRootPublicKey"], 32, 32))
        m.require(spki(self.root) == config["authorityRootSpkiSha256"])
        self.configuration_raw = m.decoded(config["authorityConfigurationOriginal"], 1024 * 1024)
        configuration = m.document(self.configuration_raw, 1024 * 1024, exact=False)
        m.require(set(configuration) == {"schema", "payload", "signature"} and configuration["schema"] == SIGNED_CONFIG)
        self.payload = configuration["payload"]
        self.root.verify(m.decoded(configuration["signature"], 64, 64), domain(SIGNED_CONFIG, m.canonical(self.payload)).encode("ascii"))
        m.require(self.payload["schema"] == CONFIG and self.payload["sourceRevision"] == config["sourceRevision"])
        self.policy = self.payload["oauthRetiredScopeSuccessionPolicy"]
        m.require(type(self.policy) is dict and set(self.policy) == POLICY_FIELDS and self.policy["schema"] == POLICY
            and self.policy["deploymentId"] == config["deploymentId"]
            and self.policy["controlPlaneConfigurationDigest"] == config["controlPlaneConfigurationDigest"]
            and all({name: self.policy[name] for name in config[group]} == config[group] for group in ("limits", "windows", "successionLimits")))
        self.target_root = Ed25519PublicKey.from_public_bytes(m.decoded(self.policy["enrollmentRootPublicKeyBase64Url"], 32, 32))
        self.effect_root = Ed25519PublicKey.from_public_bytes(m.decoded(self.policy["successionRootPublicKeyBase64Url"], 32, 32))
        verifier = self.payload["roles"]["verifier"]
        self.signer = Ed25519PublicKey.from_public_bytes(m.decoded(verifier["signingPublicKeyBase64Url"], 32, 32))
        m.require(spki(self.target_root) == self.policy["enrollmentRootSpkiSha256"]
            and spki(self.effect_root) == self.policy["successionRootSpkiSha256"]
            and spki(self.signer) == verifier["signingSpkiDigest"] == verifier["responseSigningSpkiDigest"]
            and len({spki(self.root), spki(self.target_root), spki(self.effect_root), spki(self.signer), config["identity"]["keyId"],
                config["identity"]["controlPlaneResponseSigningKeyId"]}) == 6)
        forbidden = {spki(self.root), spki(self.target_root)}
        for role in self.payload["roles"].values():
            forbidden.update(item for name, item in role.items() if type(item) is str
                and (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")))
        for name, other in self.payload.items():
            if name != "oauthRetiredScopeSuccessionPolicy" and type(other) is dict:
                forbidden.update(item for field, item in other.items() if type(item) is str
                    and (field.endswith("SpkiDigest") or field.endswith("SpkiSha256")))
        m.require(spki(self.effect_root) not in forbidden)
        self.roots = {spki(self.target_root): self.target_root}
        previous = []
        m.require(type(self.policy["historicalEnrollmentRoots"]) is list and len(self.policy["historicalEnrollmentRoots"]) <= 16)
        for item in self.policy["historicalEnrollmentRoots"]:
            m.require(type(item) is dict and set(item) == {"publicKeyBase64Url", "spkiSha256"})
            key = Ed25519PublicKey.from_public_bytes(m.decoded(item["publicKeyBase64Url"], 32, 32))
            pin = spki(key)
            m.require(pin == item["spkiSha256"] and pin not in self.roots and pin != spki(self.effect_root))
            self.roots[pin] = key; previous.append(pin)
        m.require(previous == sorted(set(previous)))
        scalar.trust_roots(self.policy["trustRoots"])
        assignments = self.policy["assignments"]
        m.require(type(assignments) is list and 1 <= len(assignments) <= 32)
        order = []
        for item in assignments:
            m.require(type(item) is dict and set(item) == ASSIGNMENT)
            scalar.native_assignment({name: item[name] for name in scalar.NATIVE_ASSIGNMENT_FIELDS})
            m.require(item["keyId"] not in forbidden | {spki(self.effect_root)} and item["keyId"] != item["controlPlaneResponseSigningKeyId"]
                and item["enrollmentRootSpkiSha256"] in self.roots and item["providerId"] in provider.AUTHORIZATION)
            m.text(item["instanceId"], 4096); m.require(item["instanceId"].startswith("spiffe://"))
            for name in ("enrollmentSha256", "applicationMaterialSha256", "providerTlsRootSha256"):
                m.digest(item[name])
            provider.origin(item["portalOrigin"]); provider.origin(item["callbackOrigin"])
            m.require(item["portalOrigin"] != item["callbackOrigin"] and type(item["secretKekId"]) is str
                and item["secretKekId"].startswith("attested-memory-kek:") and len(item["secretKekId"]) == 44)
            order.append((item["holderId"], item["enrollmentSha256"]))
        m.require(order == sorted(set(order)))
        self.originals, self.last = rows.Originals(), None
        self.grant_raw = self.grant = self.application_original = self.enrollment = self.assignment = None
        self.material_applications = {}

    def application(self, enrollment_sha256, *, historical):
        candidates = []
        for app in self.config["applications"].values():
            raw = m.decoded(app["enrollmentOriginal"], 32768)
            if m.sha(raw) == enrollment_sha256:
                candidates.append((app, raw, spki(self.target_root)))
        if historical:
            for item in self.config["historicalApplications"]:
                if item["enrollmentSha256"] == enrollment_sha256:
                    raw = m.decoded(item["application"]["enrollmentOriginal"], 32768)
                    candidates.append((item["application"], raw, item["enrollmentRootSpkiSha256"]))
        m.require(len(candidates) == 1)
        app, raw, root_pin = candidates[0]
        envelope = scalar.enrollment_document(raw); enrollment = envelope["payload"]
        m.require(m.sha(raw) == enrollment_sha256 and root_pin in self.roots)
        self.roots[root_pin].verify(m.decoded(envelope["signatureBase64Url"], 64, 64), scalar.ENROLLMENT_SCHEMA.encode("ascii") + b"\0" + m.canonical(enrollment))
        entries = [item for item in self.policy["assignments"] if item["holderId"] == self.config["identity"]["holderId"]
            and item["enrollmentSha256"] == enrollment_sha256]
        m.require(len(entries) == 1)
        assignment = entries[0]
        m.application_header(app["material"], enrollment, enrollment_sha256)
        m.require(all(assignment[name] == self.config["identity"][name] for name in self.config["identity"])
            and assignment["enrollmentRootSpkiSha256"] == root_pin and assignment["providerId"] == enrollment["providerId"]
            and assignment["instanceId"] == self.config["instanceId"] and assignment["callbackOrigin"] == self.config["callbackOrigin"]
            and assignment["portalOrigin"] == self.config["portalOrigin"]
            and assignment["secretKekId"] == app["material"]["secretKekId"]
            and assignment["applicationMaterialSha256"] == m.sha(m.canonical(app["material"]))
            and assignment["providerTlsRootSha256"] == m.sha(app["tlsRootsPem"].encode("ascii")))
        return app, raw, enrollment, assignment

    def admit(self, authorization_original, provider_id):
        raw = m.decoded(authorization_original, material.MAX_GRANT)
        signed = material.grant(raw); grant = signed["payload"]
        self.effect_root.verify(m.decoded(signed["signatureBase64Url"], 64, 64), material.GRANT.encode("ascii") + b"\0" + m.canonical(grant))
        now = time.time_ns()
        m.require(grant["sourceRevision"] == self.config["sourceRevision"] and grant["configurationDigest"] == self.config["controlPlaneConfigurationDigest"]
            and grant["deploymentId"] == self.config["deploymentId"] and grant["providerId"] == provider_id
            and grant["issuedAtEpochNs"] <= now < grant["expiresAtEpochNs"])
        app, original, enrollment, assignment = self.application(grant["enrollmentSha256"], historical=False)
        m.require(enrollment["sourceRevision"] == grant["sourceRevision"] and enrollment["configurationDigest"] == grant["configurationDigest"]
            and enrollment["deploymentId"] == grant["deploymentId"] and enrollment["providerId"] == provider_id
            and enrollment["clientId"] == grant["clientId"] and enrollment["redirectUri"] == provider.callback_uri(self.config["callbackOrigin"], provider_id)
            and enrollment["issuedAtEpochNs"] <= grant["issuedAtEpochNs"] < grant["expiresAtEpochNs"] <= enrollment["expiresAtEpochNs"])
        historical = {}
        for pin in grant["materials"]:
            selected = self.application(pin["enrollmentSha256"], historical=True)
            m.require(selected[2]["providerId"] == provider_id and selected[2]["deploymentId"] == grant["deploymentId"])
            historical[pin["materialId"]] = selected
        if self.grant_raw is not None:
            m.require(raw == self.grant_raw and original == self.application_original and assignment == self.assignment)
        self.grant_raw, self.grant = raw, grant
        self.application_original, self.enrollment, self.assignment = original, enrollment, assignment
        self.material_applications = historical
        return grant, assignment, enrollment

    def _consumption(self, response):
        value = response["attestationConsumptionReceipt"]
        assurance = {"trustMode": "trusted-host-local", "coLocated": True, "hardwareBacked": False, "nativeStageZero": False,
            "hsmBackedKeys": False, "teeVerified": False, "externalWitnessVerified": False}
        m.require(type(value) is dict and set(value) == set(assurance) | {"schema", "role", "configurationDigest", "generationDigest",
            "launchIdentityCertificateDigest", "attestationReceiptDigest", "issuedAtEpochNs", "signerPurpose", "signature"}
            and value["schema"] == CONSUMPTION and value["role"] == "verifier" and value["signerPurpose"] == "verifier-response-key"
            and all(type(value[name]) is type(expected) and value[name] == expected for name, expected in assurance.items())
            and value["configurationDigest"] == response["configurationDigest"] and value["attestationReceiptDigest"] == response["attestationReceiptDigest"]
            and response["attestationConsumptionReceiptDigest"] == domain(CONSUMPTION, m.canonical(value)))
        m.digest(value["generationDigest"]); m.digest(value["launchIdentityCertificateDigest"])
        m.require(m.integer(value["issuedAtEpochNs"]) <= response["issuedAtEpochNs"])
        self.signer.verify(m.decoded(value["signature"], 64, 64), domain(CONSUMPTION,
            m.canonical({name: item for name, item in value.items() if name != "signature"})).encode("ascii"))

    def frame(self, originals, operation, *, earliest, latest, current_expiry):
        m.require(type(originals) is dict and set(originals) == {"requestOriginal", "responseOriginal"})
        request_raw, response_raw = (m.decoded(originals[name], limit) for name, limit in
            (("requestOriginal", material.MAX_REQUEST), ("responseOriginal", material.MAX_RESPONSE)))
        request, response = m.document(request_raw, material.MAX_REQUEST), m.document(response_raw, material.MAX_RESPONSE)
        m.require(set(request) == REQUEST_FIELDS and request["schema"] == REQUEST and set(response) == RESPONSE_FIELDS
            and response["schema"] == RESPONSE and m.decoded(response["authorityConfigurationOriginal"], 1024 * 1024) == self.configuration_raw)
        self.signer.verify(m.decoded(response["signature"], 64, 64), domain(RESPONSE,
            m.canonical({name: item for name, item in response.items() if name != "signature"})).encode("ascii"))
        body = request["input"]
        m.require(type(body) is dict and set(body) == {"schema", "handler", "operationManifestDigest", "arguments"}
            and body["schema"] == INPUT and body["handler"] == "catchplate_policy_authority_" + operation.replace(".", "_").replace("-", "_")
            and body["operationManifestDigest"] == request["operationManifestDigest"]
            and all(operation in self.payload["roles"][role]["enabledOperations"] for role in ("verifier", "planner"))
            and request["operation"] == response["operation"] == operation
            and request["configurationDigest"] == response["configurationDigest"] == domain(CONFIG, m.canonical(self.payload))
            and response["requestId"] == request["requestId"] and response["requestDigest"] == domain(REQUEST, request_raw)
            and response["deadlineMonotonicNs"] == request["deadlineMonotonicNs"])
        m.integer(request["startedMonotonicNs"]); m.integer(request["deadlineMonotonicNs"])
        m.integer(response["issuedAtEpochNs"]); m.integer(response["fence"])
        m.require(0 < request["deadlineMonotonicNs"] - request["startedMonotonicNs"] <= 30_000_000_000
            and earliest <= response["issuedAtEpochNs"] < latest and earliest <= time.time_ns() < current_expiry
            and response["resultDigest"] == domain(RESULT, m.canonical(response["result"])))
        for name in ("operationManifestDigest", "requestId"):
            m.digest(request[name])
        for name in ("commitReceiptDigest", "witnessCommitDigest", "attestationReceiptDigest"):
            m.digest(response[name])
        self._consumption(response)
        result = response["result"]
        m.require(type(result) is dict and set(result) == RESULT_FIELDS and result["ok"] is True and result["idempotentReplay"] is False
            and result["operation"] == operation and len(m.canonical(result)) <= 1024 * 1024
            and type(result["originals"]) is dict and set(result["originals"]) == rows.ORIGINALS
            and type(result["observation"]) is dict and set(result["observation"]) == rows.OBSERVATION)
        m.digest(result["requestDigest"]); m.digest(result["auditEventDigest"])
        return body["arguments"], result, response["issuedAtEpochNs"]

    def fence(self, intent):
        material.intent(intent)
        grant, assignment, enrollment = self.admit(intent["authorizationOriginal"], intent["providerId"])
        arguments, result, issued = self.frame({"requestOriginal": intent["scopeRequestOriginal"], "responseOriginal": intent["scopeResponseOriginal"]},
            "oauth.succession.fence", earliest=grant["issuedAtEpochNs"], latest=grant["admissionExpiresAtEpochNs"], current_expiry=grant["contactExpiresAtEpochNs"])
        original = result["originals"]
        m.require(all(original[name] is None for name in ("exchangeOriginal", "custodyOriginal", "candidateOriginal", "associationOriginal"))
            and original["materialOriginals"] == original["attemptOriginals"] == [])
        journal, scope, target = self.originals.pin_scope(original, grant, self.application_original)
        rows.human(arguments, grant, journal)
        m.require(m.canonical(arguments).decode("ascii") == journal["fence_arguments_json"]
            and result["requestDigest"] == journal["fence_request_digest"] and rows.epoch(scope["created_at"]) <= issued
            and intent["credentialPolicy"] == rows.stored(journal["credential_policy_json"], 8192)
            and intent["metadata"] == rows.stored(target["metadata"], 32768) and intent["credentialName"] == target["name"]
            and intent["metadata"].get(m.ASSOCIATION) == provider.association(self.application_original, enrollment)
            and intent["metadata"].get("oauth_client_id" if grant["providerId"] == "google" else "x_app_id") == grant["clientId"])
        self.last = result
        return journal, scope, target, grant, assignment, enrollment

    def verify(self, originals, expected, *, phase, started, expires):
        m.require(phase in material.PHASES and self.grant is not None)
        grant, _, _ = self.admit(expected["authorization_original"], self.grant["providerId"])
        identifier = expected["request"].get("materialId")
        selected = self.material_applications[identifier] if identifier is not None else (
            self.config["applications"][grant["providerId"]], self.application_original, self.enrollment, self.assignment)
        app, application_raw, enrollment, assignment = selected
        arguments, result, _ = self.frame(originals, "oauth.measured-succession." + phase,
            earliest=started, latest=expires, current_expiry=expires)
        m.require(type(arguments) is dict and set(arguments) == material.ARGUMENT_FIELDS
            and {name: item for name, item in arguments.items() if name != "native_evidence"} == expected
            and expected["assignment_original"] == assignment and expected["enrollment_original"] == m.encoded(application_raw))
        evidence = arguments["native_evidence"]
        m.require(type(evidence) is dict and set(evidence) == {"statement", "signature", "nativeKeyEvidence"})
        proof = evidence["statement"]
        m.require(type(proof) is dict and set(proof) == material.STATEMENT_FIELDS and proof["apiVersion"] == material.STATEMENT
            and proof["phase"] == phase and proof["materialId"] == identifier and proof["inputSha256"] == m.sha(m.canonical(expected))
            and proof["exchangeId"] == grant["authorizationId"] and proof["authorizationSha256"] == m.sha(self.grant_raw)
            and proof["scopeRowSha256"] == expected["request"]["scopeRowSha256"]
            and proof["deploymentId"] == self.config["deploymentId"] and proof["instanceId"] == self.config["instanceId"]
            and proof["providerId"] == grant["providerId"] and proof["enrollmentSha256"] == m.sha(application_raw)
            and all(proof[name] == self.config["identity"][name] for name in ("holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId", "policyHash"))
            and proof["dataPlaneBinarySha256"] == self.config["identity"]["expectedBinaryDigest"]
            and all(proof[name] == self.config[name] for name in ("callbackOrigin", "portalOrigin", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256")))
        m.integer(proof["issuedAtEpochNs"]); m.integer(proof["expiresAtEpochNs"]); m.decoded(proof["challenge"], 32, 32)
        m.require(started <= proof["issuedAtEpochNs"] < proof["expiresAtEpochNs"] <= expires
            and proof["expiresAtEpochNs"] - proof["issuedAtEpochNs"] <= 30_000_000_000)
        native = evidence["nativeKeyEvidence"]
        m.require(type(native) is dict and set(native) == {"apiVersion", "attestationDocumentB64", "responseProofPublicKey"}
            and native["apiVersion"] == "catchplate.nativeResponseProofKeyEvidence/v1"
            and type(evidence["signature"]) is str and evidence["signature"].startswith("ed25519:"))
        m.decoded(native["attestationDocumentB64"], 12288)
        key = Ed25519PublicKey.from_public_bytes(m.decoded(native["responseProofPublicKey"], 32, 32))
        m.require(spki(key) == assignment["keyId"])
        key.verify(m.decoded(evidence["signature"][8:], 64, 64), material.STATEMENT.encode("ascii") + b"\0" + m.canonical(proof))
        journal, scope, target = self.originals.pin_scope(result["originals"], grant, self.application_original, historical=phase == "recover")
        m.require(expected["request"]["scopeRowSha256"] == m.sha(self.originals.scope_original.encode("ascii")))
        self.originals.effects(result["originals"], grant)
        self.last = result
        return result, (journal, scope, target), selected
