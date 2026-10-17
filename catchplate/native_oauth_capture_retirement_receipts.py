"""Enclave-only validation of exact controlled-writer retirement originals.

The public configuration root is admitted before the helper sees a response.
An observed payload, server TLS certificate, or claimed commit is not a receipt.
This module has no signing key and exports no generic verifier RPC.
"""
from __future__ import annotations

import hashlib
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from catchplate import native_oauth_refresh as m
from catchplate import native_oauth_capture_retirement as retirement

CONFIG = "catchplate.policyAuthorityServiceConfiguration/v6"
SIGNED_CONFIG = "catchplate.signedPolicyAuthorityServiceConfiguration/v6"
REQUEST = "catchplate.policyAuthorityRuntimeRequest/v2"
RESPONSE = "catchplate.policyAuthorityMeasuredCaptureRetirementRuntimeResponse/v1"
INPUT = "catchplate.policyAuthorityControlledWriterInput/v1"
RESULT = "catchplate.policyAuthorityControlledWriterResult/v2"
POLICY = "catchplate.oauthMeasuredCaptureRetirementAuthorityPolicy/v1"
REQUEST_FIELDS = frozenset({"schema", "requestId", "operation", "input", "configurationDigest",
    "operationManifestDigest", "startedMonotonicNs", "deadlineMonotonicNs"})
RESPONSE_FIELDS = frozenset({"schema", "requestId", "operation", "configurationDigest", "requestDigest",
    "issuedAtEpochNs", "deadlineMonotonicNs", "fence", "result", "resultDigest", "commitReceiptDigest",
    "witnessCommitDigest", "attestationReceiptDigest", "attestationConsumptionReceipt",
    "attestationConsumptionReceiptDigest", "authorityConfigurationOriginal", "signature"})


def domain(name, *frames):
    value = hashlib.sha256(name.encode("ascii") + b"\0")
    for frame in frames:
        value.update(len(frame).to_bytes(8, "big")); value.update(frame)
    return "sha256:" + value.hexdigest()


def spki(key):
    return m.sha(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


class Receipts:
    def __init__(self, config):
        self.config = config
        self.root = Ed25519PublicKey.from_public_bytes(m.decoded(config["authorityRootPublicKey"], 32, 32))
        m.require(spki(self.root) == config["authorityRootSpkiSha256"])
        self.retained_configuration = None

    def verify(self, originals, expected, *, started, expires):
        m.require(type(originals) is dict and set(originals) == {"requestOriginal", "responseOriginal", "currentnessBarriers"})
        request_raw = m.decoded(originals["requestOriginal"], 3 * 1024 * 1024)
        response_raw = m.decoded(originals["responseOriginal"], 6 * 1024 * 1024)
        request = m.document(request_raw, 3 * 1024 * 1024)
        response = m.document(response_raw, 6 * 1024 * 1024)
        m.require(set(request) == REQUEST_FIELDS and request["schema"] == REQUEST
            and set(response) == RESPONSE_FIELDS and response["schema"] == RESPONSE)
        arguments = request["input"]["arguments"]
        m.require(type(arguments) is dict and set(arguments) == set(expected) | {"evidence"}
            and {name: value for name, value in arguments.items() if name != "evidence"} == expected)
        proof = arguments["evidence"]["statement"]
        m.require(type(proof) is dict and set(proof) == retirement.STATEMENT_FIELDS
            and proof["apiVersion"] == retirement.STATEMENT
            and proof["phase"] in {"inspect", "claim", "contact", "finish", "recover"}
            and proof["issuedAtEpochNs"] == started and proof["expiresAtEpochNs"] == expires
            and proof["authorizationSha256"] == m.sha(m.decoded(expected["authorization_original"], retirement.MAX_GRANT_BYTES)))
        m.require(proof["inputSha256"] == m.sha(m.canonical(expected))
            and proof["exchangeId"] == expected["exchange_id"]
            and proof["enrollmentSha256"] == m.sha(m.decoded(expected["enrollment_original"], 32768)))
        configuration_raw = m.decoded(response["authorityConfigurationOriginal"], 1024 * 1024)
        configuration = m.document(configuration_raw, 1024 * 1024, exact=False)
        m.require(set(configuration) == {"schema", "payload", "signature"} and configuration["schema"] == SIGNED_CONFIG)
        payload = configuration["payload"]
        self.root.verify(m.decoded(configuration["signature"], 64, 64), domain(SIGNED_CONFIG, m.canonical(payload)).encode("ascii"))
        m.require(payload["schema"] == CONFIG and payload["sourceRevision"] == self.config["sourceRevision"])
        policy = payload["oauthMeasuredCaptureRetirementPolicy"]
        grant_key = retirement.policy_key(policy, payload, self.root)
        m.require(policy["schema"] == POLICY and policy["deploymentId"] == self.config["deploymentId"]
            and policy["controlPlaneConfigurationDigest"] == self.config["controlPlaneConfigurationDigest"])
        grant, enrollment = retirement.verify_grant(expected, key=grant_key,
            configuration_digest=policy["controlPlaneConfigurationDigest"], source_revision=payload["sourceRevision"],
            deployment_id=policy["deploymentId"], now_epoch_ns=time.time_ns(), historical=proof["phase"] == "recover")
        assigned = [entry for entry in policy["assignments"] if entry["holderId"] == proof["holderId"]
            and entry["enrollmentSha256"] == proof["enrollmentSha256"]]
        m.require(len(assigned) == 1)
        assignment = assigned[0]
        identity = self.config["identity"]
        m.require(all(assignment[name] == identity[name] for name in identity)
            and assignment["instanceId"] == self.config["instanceId"] and grant["exchangeId"] in assignment["exchangeIds"]
            and grant["providerId"] == assignment["providerId"])
        m.require(all(proof[name] == identity[name] for name in ("holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId", "policyHash"))
            and proof["dataPlaneBinarySha256"] == identity["expectedBinaryDigest"]
            and proof["deploymentId"] == self.config["deploymentId"] and proof["instanceId"] == self.config["instanceId"]
            and proof["providerId"] == grant["providerId"])
        if proof["phase"] == "recover":
            m.require(m.sha(m.decoded(expected["authorization_original"], retirement.MAX_GRANT_BYTES))
                in assignment["recoveryAuthorizationSha256s"])
        else:
            m.require(grant["holderId"] == assignment["holderId"])
        application = self.config["applications"][assignment["providerId"]]
        m.require(assignment["secretKekId"] == application["material"]["secretKekId"]
            and assignment["applicationMaterialSha256"] == m.sha(m.canonical(application["material"])) == grant["applicationMaterialSha256"]
            and assignment["providerTlsRootSha256"] == m.sha(application["tlsRootsPem"].encode("ascii")) == grant["providerTlsRootSha256"]
            and assignment["enrollmentSha256"] == m.sha(m.decoded(application["enrollmentOriginal"], 32768))
            and expected["enrollment_original"] == application["enrollmentOriginal"]
            and grant["exchangeId"] in application["exchangeIds"])
        verifier = payload["roles"]["verifier"]
        signer = Ed25519PublicKey.from_public_bytes(m.decoded(verifier["signingPublicKeyBase64Url"], 32, 32))
        m.require(spki(signer) == verifier["signingSpkiDigest"] == verifier["responseSigningSpkiDigest"]
            and spki(signer) not in {spki(self.root), spki(grant_key), identity["keyId"]})
        unsigned = {name: value for name, value in response.items() if name != "signature"}
        signer.verify(m.decoded(response["signature"], 64, 64), domain(RESPONSE, m.canonical(unsigned)).encode("ascii"))
        operation = "oauth.measured-capture-retirement." + proof["phase"]
        body = request["input"]
        m.require(type(body) is dict and set(body) == {"schema", "handler", "operationManifestDigest", "arguments"}
            and body["schema"] == INPUT and body["handler"] == "catchplate_policy_authority_" + operation.replace(".", "_").replace("-", "_")
            and body["arguments"] == arguments and body["operationManifestDigest"] == request["operationManifestDigest"])
        m.digest(request["operationManifestDigest"])
        m.require(operation in payload["roles"]["planner"]["enabledOperations"]
            and request["operation"] == response["operation"] == operation
            and request["configurationDigest"] == response["configurationDigest"] == domain(CONFIG, m.canonical(payload))
            and response["requestId"] == request["requestId"]
            and response["requestDigest"] == domain(REQUEST, request_raw)
            and response["deadlineMonotonicNs"] == request["deadlineMonotonicNs"]
            and 0 < request["deadlineMonotonicNs"] - request["startedMonotonicNs"] <= 30_000_000_000
            and started <= response["issuedAtEpochNs"] < expires and started <= time.time_ns() < expires
            and type(response["fence"]) is int and response["fence"] > 0
            and response["resultDigest"] == domain(RESULT, m.canonical(response["result"])))
        for name in ("requestId", "commitReceiptDigest", "witnessCommitDigest", "attestationReceiptDigest"):
            m.digest(response[name])
        consumption = response["attestationConsumptionReceipt"]
        m.require(type(consumption) is dict and response["attestationConsumptionReceiptDigest"] == domain(consumption["schema"], m.canonical(consumption)))
        result = response["result"]
        m.require(type(result) is dict and set(result) == {"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "payload"}
            and result["ok"] is True and result["idempotentReplay"] is False and result["operation"] == operation)
        m.digest(result["requestDigest"]); m.digest(result["auditEventDigest"])
        # All phases of one owner use the exact admitted authority original;
        # a separately fresh recovery owner may admit a newer current config.
        if self.retained_configuration is None:
            self.retained_configuration = configuration_raw
        m.require(configuration_raw == self.retained_configuration)
        return result, assignment, originals["currentnessBarriers"], enrollment
