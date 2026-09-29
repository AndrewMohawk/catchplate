"""Purpose-fixed enclave verification of signed controlled-writer originals.

The writer's custody classification remains trusted-host-local. Its committed
transaction attests the actual holder-barrier consumption; a barrier digest is
not independently a native drain proof. Native signing and family permission
are separately pinned. This module signs nothing and exposes no verifier RPC.
"""
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import native_oauth_refresh as m
from serverware import native_oauth_exchange as provider
from serverware import native_oauth_reconnect as material
from serverware import native_oauth_reconnect_rows as rows
from serverware.native_oauth_refresh_receipts import domain, spki, CONFIG, SIGNED_CONFIG, REQUEST, INPUT, RESULT, REQUEST_FIELDS, RESPONSE_FIELDS

RESPONSE = "serverware.policyAuthorityMeasuredReconnectRuntimeResponse/v1"
POLICY = "serverware.oauthMeasuredReconnectAuthorityPolicy/v1"
POLICY_FIELDS = frozenset({"schema", "enrollmentRootPublicKeyBase64Url", "enrollmentRootSpkiSha256", "controlPlaneConfigurationDigest",
    "deploymentId", "pendingCapacity", "revocationCapacity", "contactMaxSeconds", "retentionMaxSeconds", "pendingMaxSeconds",
    "operationMaxSeconds", "recoveryMaxSeconds", "trustRoots", "assignments", "familyReplacementRootPublicKeyBase64Url",
    "familyReplacementRootSpkiSha256", "affectedLineageCapacity", "historyCapacity", "authorizationMaxSeconds"})
CONSUMPTION = "serverware.trustedHostLocalAuthorityAttestationConsumption/v1"
RESULT_FIELDS = frozenset({"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "originals"})


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
        self.policy = self.payload["oauthMeasuredReconnectPolicy"]
        m.require(type(self.policy) is dict and set(self.policy) == POLICY_FIELDS
            and self.policy["schema"] == POLICY and self.policy["deploymentId"] == config["deploymentId"]
            and self.policy["controlPlaneConfigurationDigest"] == config["controlPlaneConfigurationDigest"]
            and all({name: self.policy[name] for name in config[group]} == config[group] for group in ("limits", "windows", "reconnectLimits")))
        self.enrollment_key = Ed25519PublicKey.from_public_bytes(m.decoded(self.policy["enrollmentRootPublicKeyBase64Url"], 32, 32))
        self.family_key = Ed25519PublicKey.from_public_bytes(m.decoded(self.policy["familyReplacementRootPublicKeyBase64Url"], 32, 32))
        verifier = self.payload["roles"]["verifier"]
        self.signer = Ed25519PublicKey.from_public_bytes(m.decoded(verifier["signingPublicKeyBase64Url"], 32, 32))
        m.require(spki(self.enrollment_key) == self.policy["enrollmentRootSpkiSha256"]
            and spki(self.family_key) == self.policy["familyReplacementRootSpkiSha256"]
            and spki(self.signer) == verifier["signingSpkiDigest"] == verifier["responseSigningSpkiDigest"]
            and len({spki(self.root), spki(self.enrollment_key), spki(self.family_key), spki(self.signer), config["identity"]["keyId"],
                config["identity"]["controlPlaneResponseSigningKeyId"]}) == 6)
        self.originals = rows.Originals()
        self.grant_raw = self.grant = self.application_original = self.enrollment = self.assignment = None

    def admit(self, authorization_original, provider_id):
        raw = m.decoded(authorization_original, material.MAX_GRANT)
        envelope = material.grant(raw)
        grant = envelope["payload"]
        self.family_key.verify(m.decoded(envelope["signatureBase64Url"], 64, 64), material.GRANT.encode("ascii") + b"\0" + m.canonical(grant))
        now = time.time_ns()
        m.require(grant["sourceRevision"] == self.config["sourceRevision"] and grant["configurationDigest"] == self.config["controlPlaneConfigurationDigest"]
            and grant["deploymentId"] == self.config["deploymentId"] and grant["providerId"] == provider_id
            and grant["issuedAtEpochNs"] <= now < grant["expiresAtEpochNs"]
            and grant["expiresAtEpochNs"] - grant["issuedAtEpochNs"] <= self.policy["authorizationMaxSeconds"] * 1_000_000_000)
        application = self.config["applications"][provider_id]
        application_original = m.decoded(application["enrollmentOriginal"], 32768)
        envelope = m.document(application_original, 32768, exact=False)
        m.require(set(envelope) == {"schema", "payload", "signatureBase64Url"}
            and envelope["schema"] == "serverware.signedOAuthApplicationEnrollment/v1")
        enrollment = envelope["payload"]
        self.enrollment_key.verify(m.decoded(envelope["signatureBase64Url"], 64, 64), b"serverware.oauthApplicationEnrollment/v1\0" + m.canonical(enrollment))
        m.require(enrollment["schema"] == "serverware.oauthApplicationEnrollment/v1" and enrollment["sourceRevision"] == self.config["sourceRevision"]
            and enrollment["configurationDigest"] == grant["configurationDigest"] and enrollment["deploymentId"] == grant["deploymentId"]
            and enrollment["providerId"] == provider_id and enrollment["clientId"] == grant["clientId"]
            and enrollment["redirectUri"] == provider.callback_uri(self.config["callbackOrigin"], provider_id)
            and enrollment["issuedAtEpochNs"] <= grant["issuedAtEpochNs"] <= now < grant["expiresAtEpochNs"] <= enrollment["expiresAtEpochNs"]
            and m.sha(application_original) == grant["enrollmentSha256"])
        identity = self.config["identity"]
        assignments = [item for item in self.policy["assignments"] if item["holderId"] == identity["holderId"]
            and item["providerId"] == provider_id and item["enrollmentSha256"] == grant["enrollmentSha256"]]
        m.require(len(assignments) == 1)
        assignment = assignments[0]
        m.require(all(assignment[name] == identity[name] for name in identity) and assignment["instanceId"] == self.config["instanceId"]
            and assignment["callbackOrigin"] == self.config["callbackOrigin"] and assignment["portalOrigin"] == self.config["portalOrigin"]
            and assignment["secretKekId"] == application["material"]["secretKekId"]
            and assignment["applicationMaterialSha256"] == m.sha(m.canonical(application["material"]))
            and assignment["providerTlsRootSha256"] == m.sha(application["tlsRootsPem"].encode("ascii")))
        if self.grant_raw is not None:
            m.require(raw == self.grant_raw and assignment == self.assignment)
        self.grant_raw, self.grant = raw, grant
        self.application_original, self.enrollment, self.assignment = application_original, enrollment, assignment
        return grant, assignment, enrollment

    def _frame(self, originals, operation, *, earliest, latest, current_expiry):
        m.require(type(originals) is dict and set(originals) == {"requestOriginal", "responseOriginal"})
        request_raw = m.decoded(originals["requestOriginal"], 2 * 1024 * 1024 + 65536)
        response_raw = m.decoded(originals["responseOriginal"], 6 * 1024 * 1024)
        request, response = m.document(request_raw, 3 * 1024 * 1024), m.document(response_raw, 6 * 1024 * 1024)
        m.require(set(request) == REQUEST_FIELDS and request["schema"] == REQUEST
            and set(response) == RESPONSE_FIELDS and response["schema"] == RESPONSE
            and m.decoded(response["authorityConfigurationOriginal"], 1024 * 1024) == self.configuration_raw)
        self.signer.verify(m.decoded(response["signature"], 64, 64), domain(RESPONSE,
            m.canonical({name: item for name, item in response.items() if name != "signature"})).encode("ascii"))
        body = request["input"]
        m.require(type(body) is dict and set(body) == {"schema", "handler", "operationManifestDigest", "arguments"}
            and body["schema"] == INPUT and body["handler"] == "serverware_policy_authority_" + operation.replace(".", "_").replace("-", "_")
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
        m.require(type(result) is dict and set(result) == RESULT_FIELDS and result["ok"] is True
            and result["idempotentReplay"] is False and result["operation"] == operation
            and type(result["originals"]) is dict and set(result["originals"]) == rows.ORIGINALS)
        m.digest(result["requestDigest"]); m.digest(result["auditEventDigest"])
        return body["arguments"], result, response["issuedAtEpochNs"]

    def _consumption(self, response):
        value = response["attestationConsumptionReceipt"]
        assurance = {"trustMode": "trusted-host-local", "coLocated": True, "hardwareBacked": False,
            "nativeStageZero": False, "hsmBackedKeys": False, "teeVerified": False, "externalWitnessVerified": False}
        m.require(type(value) is dict and set(value) == set(assurance) | {"schema", "role", "configurationDigest", "generationDigest",
            "launchIdentityCertificateDigest", "attestationReceiptDigest", "issuedAtEpochNs", "signerPurpose", "signature"}
            and value["schema"] == CONSUMPTION and value["role"] == "verifier" and value["signerPurpose"] == "verifier-response-key"
            and all(type(value[name]) is type(expected) and value[name] == expected for name, expected in assurance.items())
            and value["configurationDigest"] == response["configurationDigest"]
            and value["attestationReceiptDigest"] == response["attestationReceiptDigest"]
            and response["attestationConsumptionReceiptDigest"] == domain(CONSUMPTION, m.canonical(value)))
        m.digest(value["generationDigest"]); m.digest(value["launchIdentityCertificateDigest"])
        m.require(m.integer(value["issuedAtEpochNs"]) <= response["issuedAtEpochNs"])
        self.signer.verify(m.decoded(value["signature"], 64, 64), domain(CONSUMPTION,
            m.canonical({name: item for name, item in value.items() if name != "signature"})).encode("ascii"))
        # The source's role receipt identity is a derived runtime view, not a
        # field of its root-signed configuration payload. Bind the actual signed
        # consumption and runtime response; do not invent a static receipt pin.

    def fence(self, value):
        material.intent(value)
        grant, assignment, enrollment = self.admit(value["authorizationOriginal"], value["providerId"])
        # Authenticate first, then interpret retained journal values. No entropy,
        # decryption, provider contact or currentness renewal happens here.
        originals = {"requestOriginal": value["fenceRequestOriginal"], "responseOriginal": value["fenceResponseOriginal"]}
        arguments, result, issued = self._frame(originals, "oauth.reconnect.fence", earliest=grant["issuedAtEpochNs"],
            latest=grant["contactExpiresAtEpochNs"], current_expiry=grant["contactExpiresAtEpochNs"])
        stored = result["originals"]
        m.require(all(stored[name] is None for name in ("exchangeOriginal", "custodyOriginal", "candidateOriginal")))
        journal, target = self.originals.pin_journal(stored["journalOriginal"], grant, self.application_original)
        rows.human(arguments, grant, journal)
        m.require(m.canonical(arguments).decode("ascii") == journal["fence_arguments_json"]
            and result["requestDigest"] == journal["fence_request_digest"]
            and value["credentialPolicy"] == rows.stored(journal["credential_policy_json"], 8192)
            and value["metadata"] == rows.stored(target["metadata"], 512 * 1024) and value["credentialName"] == target["name"]
            and value["metadata"].get(m.ASSOCIATION) == provider.association(self.application_original, enrollment)
            and value["metadata"].get("oauth_client_id" if grant["providerId"] == "google" else "x_app_id") == grant["clientId"])
        # Check original admission timestamps after their authenticated parsing.
        m.require(rows.epoch(journal["created_at"]) <= issued < rows.epoch(journal["admission_expires_at"]))
        return journal, target, grant, assignment, enrollment

    def verify(self, originals, expected, *, phase, started, expires):
        grant, assignment, enrollment = self.admit(expected["authorization_original"], self.grant["providerId"])
        operation = "oauth.measured-reconnect." + phase
        m.require(phase in {"prepare", "claim", "capture", "stage", "recover", "cancel"})
        arguments, result, _ = self._frame(originals, operation, earliest=started, latest=expires, current_expiry=expires)
        m.require(type(arguments) is dict and set(arguments) == material.ARGUMENT_FIELDS
            and {name: item for name, item in arguments.items() if name != "native_evidence"} == expected)
        evidence = arguments["native_evidence"]
        m.require(type(evidence) is dict and set(evidence) == {"statement", "signature", "nativeKeyEvidence"})
        proof = evidence["statement"]
        m.require(type(proof) is dict and set(proof) == material.STATEMENT_FIELDS and proof["apiVersion"] == material.STATEMENT
            and proof["phase"] == ("draft" if phase == "prepare" else phase)
            and proof["inputSha256"] == m.sha(m.canonical(expected)) and proof["exchangeId"] == grant["authorizationId"]
            and proof["authorizationSha256"] == m.sha(self.grant_raw) and proof["fencedRowSha256"] == expected["request"]["fencedRowSha256"]
            and proof["deploymentId"] == self.config["deploymentId"] and proof["instanceId"] == self.config["instanceId"]
            and proof["providerId"] == grant["providerId"] and proof["enrollmentSha256"] == grant["enrollmentSha256"]
            and all(proof[name] == self.config["identity"][name] for name in ("holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId", "policyHash"))
            and proof["dataPlaneBinarySha256"] == self.config["identity"]["expectedBinaryDigest"]
            and all(proof[name] == self.config[name] for name in ("callbackOrigin", "portalOrigin", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256"))
            and expected["assignment_original"] == assignment)
        m.integer(proof["issuedAtEpochNs"]); m.integer(proof["expiresAtEpochNs"]); m.decoded(proof["challenge"], 32, 32)
        m.require(started <= proof["issuedAtEpochNs"] < proof["expiresAtEpochNs"] <= expires
            and proof["expiresAtEpochNs"] - proof["issuedAtEpochNs"] <= 30_000_000_000)
        native = evidence["nativeKeyEvidence"]
        m.require(type(native) is dict and set(native) == {"apiVersion", "attestationDocumentB64", "responseProofPublicKey"}
            and native["apiVersion"] == "serverware.nativeResponseProofKeyEvidence/v1"
            and type(evidence["signature"]) is str and evidence["signature"].startswith("ed25519:"))
        m.decoded(native["attestationDocumentB64"], 12288)
        key = Ed25519PublicKey.from_public_bytes(m.decoded(native["responseProofPublicKey"], 32, 32))
        m.require(spki(key) == assignment["keyId"])
        key.verify(m.decoded(evidence["signature"][8:], 64, 64), material.STATEMENT.encode("ascii") + b"\0" + m.canonical(proof))
        retained = self.originals.verify(result["originals"], arguments, result, grant, self.application_original)
        return result, retained, assignment, enrollment
