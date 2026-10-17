"""Enclave verifier of genuine initial-issuance controlled-store originals.

The independently pinned configuration root authorizes this new purpose. No
audit/refresh assignment, TLS success, parent callback, or scalar verdict is an
issuance permission. This verifier has no signing or generic export interface.
"""
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from catchplate import native_oauth_refresh as m
from catchplate import native_oauth_exchange as material
from catchplate.native_oauth_refresh_receipts import domain, spki, CONFIG, SIGNED_CONFIG, REQUEST, INPUT, RESULT, REQUEST_FIELDS, RESPONSE_FIELDS

RESPONSE = "catchplate.policyAuthorityMeasuredExchangeRuntimeResponse/v1"
POLICY = "catchplate.oauthMeasuredExchangeAuthorityPolicy/v1"
RESULT_FIELDS = frozenset({"ok", "exchange", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "originals"})
PUBLIC_FIELDS = frozenset({"id", "status", "exchangeRowSha256", "custodyRowSha256",
    "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs"})


class Receipts:
    def __init__(self, config):
        self.config = config
        self.root = Ed25519PublicKey.from_public_bytes(m.decoded(config["authorityRootPublicKey"], 32, 32))
        m.require(spki(self.root) == config["authorityRootSpkiSha256"])
        self.retained_configuration = None

    def recovery_assignment(self, provider):
        """Authenticate the cold proposal; only a fresh store receipt acts.

        In particular this does not admit an archived execution grant or make
        its configuration current. Both live authority roles recheck the exact
        new recovery request against their own admitted current configuration.
        """
        raw = m.decoded(self.config["authorityConfigurationOriginal"], 1024 * 1024)
        original = m.document(raw, 1024 * 1024, exact=False)
        m.require(set(original) == {"schema", "payload", "signature"} and original["schema"] == SIGNED_CONFIG)
        payload = original["payload"]
        self.root.verify(m.decoded(original["signature"], 64, 64), domain(SIGNED_CONFIG, m.canonical(payload)).encode("ascii"))
        m.require(payload["schema"] == CONFIG and payload["sourceRevision"] == self.config["sourceRevision"])
        policy = payload["oauthMeasuredExchangePolicy"]
        m.require(policy["schema"] == POLICY and policy["deploymentId"] == self.config["deploymentId"]
            and policy["controlPlaneConfigurationDigest"] == self.config["controlPlaneConfigurationDigest"])
        enrollment_sha = m.sha(m.decoded(self.config["applications"][provider]["enrollmentOriginal"], 32768))
        assignments = [item for item in policy["assignments"] if item["holderId"] == self.config["identity"]["holderId"]
            and item["enrollmentSha256"] == enrollment_sha and item["providerId"] == provider]
        m.require(len(assignments) == 1 and all(assignments[0][name] == self.config["identity"][name] for name in self.config["identity"])
            and assignments[0]["instanceId"] == self.config["instanceId"]
            and assignments[0]["callbackOrigin"] == self.config["callbackOrigin"]
            and assignments[0]["portalOrigin"] == self.config["portalOrigin"])
        return assignments[0]

    def verify(self, originals, expected, *, started, expires, processing_expires=None):
        m.require(type(originals) is dict and set(originals) == {"requestOriginal", "responseOriginal"})
        request_raw = m.decoded(originals["requestOriginal"], 3 * 1024 * 1024)
        response_raw = m.decoded(originals["responseOriginal"], 6 * 1024 * 1024)
        request = m.document(request_raw, 3 * 1024 * 1024)
        response = m.document(response_raw, 6 * 1024 * 1024)
        m.require(set(request) == REQUEST_FIELDS and request["schema"] == REQUEST
            and set(response) == RESPONSE_FIELDS and response["schema"] == RESPONSE)
        body = request["input"]
        m.require(type(body) is dict and set(body) == {"schema", "handler", "operationManifestDigest", "arguments"} and body["schema"] == INPUT)
        arguments = body["arguments"]
        operation = request["operation"]
        m.require(operation in {"oauth.measured-exchange." + phase for phase in ("prepare", "claim", "capture", "stage", "recover", "cancel")})
        extra = {"native_evidence", "authn_evidence"} if operation.endswith(".prepare") else {"native_evidence"}
        m.require(type(arguments) is dict and set(arguments) == set(expected) | extra
            and {name: item for name, item in arguments.items() if name not in extra} == expected)
        proof = arguments["native_evidence"]["statement"]
        phase = "draft" if operation.endswith(".prepare") else operation.rsplit(".", 1)[1]
        m.require(proof["apiVersion"] == "catchplate.nativeOAuthExchangeStatement/v1" and proof["phase"] == phase
            and proof["inputSha256"] == m.sha(m.canonical(expected)) and proof["exchangeId"] == expected["resource_id"]
            and proof["enrollmentSha256"] == m.sha(m.decoded(expected["enrollment_original"], 32768)))
        configuration_raw = m.decoded(response["authorityConfigurationOriginal"], 1024 * 1024)
        configuration = m.document(configuration_raw, 1024 * 1024, exact=False)
        m.require(set(configuration) == {"schema", "payload", "signature"} and configuration["schema"] == SIGNED_CONFIG)
        payload = configuration["payload"]
        self.root.verify(m.decoded(configuration["signature"], 64, 64), domain(SIGNED_CONFIG, m.canonical(payload)).encode("ascii"))
        m.require(payload["schema"] == CONFIG and payload["sourceRevision"] == self.config["sourceRevision"])
        policy = payload["oauthMeasuredExchangePolicy"]
        m.require(policy["schema"] == POLICY and policy["deploymentId"] == self.config["deploymentId"]
            and policy["controlPlaneConfigurationDigest"] == self.config["controlPlaneConfigurationDigest"]
            and {name: policy[name] for name in self.config["limits"]} == self.config["limits"]
            and {name: policy[name] for name in self.config["windows"]} == self.config["windows"])
        identity = self.config["identity"]
        assignments = [item for item in policy["assignments"] if item["holderId"] == identity["holderId"]
            and item["enrollmentSha256"] == proof["enrollmentSha256"]]
        m.require(len(assignments) == 1)
        assignment = assignments[0]
        m.require(all(assignment[name] == identity[name] for name in identity)
            and assignment["instanceId"] == self.config["instanceId"]
            and assignment["callbackOrigin"] == self.config["callbackOrigin"] == proof["callbackOrigin"]
            and assignment["portalOrigin"] == self.config["portalOrigin"] == proof["portalOrigin"]
            and proof["ingressLeafCertificateSha256"] == self.config["ingressLeafCertificateSha256"]
            and proof["ingressLeafSpkiSha256"] == self.config["ingressLeafSpkiSha256"])
        application = self.config["applications"][assignment["providerId"]]
        m.require(assignment["secretKekId"] == application["material"]["secretKekId"]
            and assignment["applicationMaterialSha256"] == m.sha(m.canonical(application["material"]))
            and assignment["providerTlsRootSha256"] == m.sha(application["tlsRootsPem"].encode("ascii"))
            and assignment["enrollmentSha256"] == m.sha(m.decoded(application["enrollmentOriginal"], 32768))
            and expected["enrollment_original"] == application["enrollmentOriginal"])
        enrollment = m.document(m.decoded(application["enrollmentOriginal"], 32768), 32768, exact=False)
        enrollment_key = Ed25519PublicKey.from_public_bytes(m.decoded(policy["enrollmentRootPublicKeyBase64Url"], 32, 32))
        m.require(spki(enrollment_key) == policy["enrollmentRootSpkiSha256"] and spki(enrollment_key) != spki(self.root))
        enrollment_key.verify(m.decoded(enrollment["signatureBase64Url"], 64, 64),
            b"catchplate.oauthApplicationEnrollment/v1\0" + m.canonical(enrollment["payload"]))
        application_payload = enrollment["payload"]
        m.require(application_payload["configurationDigest"] == self.config["controlPlaneConfigurationDigest"]
            and application_payload["deploymentId"] == self.config["deploymentId"]
            and application_payload["redirectUri"] == material.callback_uri(self.config["callbackOrigin"], assignment["providerId"]))
        verifier = payload["roles"]["verifier"]
        signer = Ed25519PublicKey.from_public_bytes(m.decoded(verifier["signingPublicKeyBase64Url"], 32, 32))
        m.require(spki(signer) == verifier["signingSpkiDigest"] == verifier["responseSigningSpkiDigest"]
            and spki(signer) not in {spki(self.root), spki(enrollment_key), identity["keyId"]})
        unsigned = {name: value for name, value in response.items() if name != "signature"}
        signer.verify(m.decoded(response["signature"], 64, 64), domain(RESPONSE, m.canonical(unsigned)).encode("ascii"))
        m.require(body["handler"] == "catchplate_policy_authority_" + operation.replace(".", "_").replace("-", "_")
            and body["operationManifestDigest"] == request["operationManifestDigest"]
            and all(operation in payload["roles"][role]["enabledOperations"] for role in ("verifier", "planner"))
            and response["operation"] == operation and request["configurationDigest"] == response["configurationDigest"] == domain(CONFIG, m.canonical(payload))
            and response["requestId"] == request["requestId"] and response["requestDigest"] == domain(REQUEST, request_raw)
            and response["deadlineMonotonicNs"] == request["deadlineMonotonicNs"]
            and 0 < request["deadlineMonotonicNs"] - request["startedMonotonicNs"] <= 30_000_000_000
            and started <= response["issuedAtEpochNs"] < expires
            and started <= time.time_ns() < (expires if processing_expires is None else processing_expires)
            and type(response["fence"]) is int and response["fence"] > 0
            and response["resultDigest"] == domain(RESULT, m.canonical(response["result"])))
        for name in ("operationManifestDigest", "requestId"):
            m.digest(request[name])
        for name in ("commitReceiptDigest", "witnessCommitDigest", "attestationReceiptDigest"):
            m.digest(response[name])
        consumption = response["attestationConsumptionReceipt"]
        m.require(type(consumption) is dict and response["attestationConsumptionReceiptDigest"] == domain(consumption["schema"], m.canonical(consumption)))
        result = response["result"]
        m.require(type(result) is dict and RESULT_FIELDS <= set(result) <= RESULT_FIELDS | {"pending"}
            and result["ok"] is True and result["idempotentReplay"] is False and result["operation"] == operation)
        m.digest(result["requestDigest"]); m.digest(result["auditEventDigest"])
        public, stored = result["exchange"], result["originals"]
        m.require(type(public) is dict and set(public) == PUBLIC_FIELDS and public["id"] == expected["resource_id"]
            and type(stored) is dict and set(stored) == {"exchangeOriginal", "custodyOriginal"})
        row_raw, custody_raw = stored["exchangeOriginal"].encode("ascii"), stored["custodyOriginal"].encode("ascii")
        row, custody = m.document(row_raw, 1024 * 1024), m.document(custody_raw, 4 * 1024 * 1024)
        m.require(row["id"] == custody["id"] == public["id"] and custody["status"] == public["status"]
            and m.sha(row_raw) == public["exchangeRowSha256"] and m.sha(custody_raw) == public["custodyRowSha256"]
            and row["enrollment_original"] == expected["enrollment_original"] and row["requester_id"] == expected["actor_id"])
        if self.retained_configuration is None:
            self.retained_configuration = configuration_raw
        m.require(configuration_raw == self.retained_configuration)
        return result, row, custody, assignment, application_payload
