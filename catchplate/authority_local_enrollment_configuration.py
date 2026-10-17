"""Project explicit first-registration policy into an unsigned local Service6.

The protected selection authorizes only three existing policy fields and two
existing operation names. All prior service policy and original clocks remain
literal. The registration identity comes from a genuinely root-signed,
configuration-independent local attestation, not invented process/receipt pins.
No private key, signer, listener, database, trust grant or hardware ceremony is
created. The output is input to the existing configuration signing owner.
"""
from __future__ import annotations

import os
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import authority_local_configuration as configuration
from catchplate import authority_local_keys as keys
from catchplate import authority_webauthn_enrollment_policy as enrollment
from catchplate import authority_webauthn_evidence_policy as evidence
from catchplate import authority_webauthn_transition_policy as transition
from catchplate import registration_evidence_signer_bootstrap as signer
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

io, spec = configuration.io, configuration.spec
canonical, document, sha = spec.canonical_json_bytes, configuration.document, configuration.sha
SCHEMA = "catchplate.authorityTrustedHostLocalEnrollmentConfigurationApproval/v1"
PURPOSE = "prepare-first-local-hardware-registration-configuration"
FIELDS = frozenset({"schema", "purpose", "configurationApprovalOriginal", "configurationApprovalSha256",
    "pilotKeyInventoryOriginal", "genesisAuditKeyInventoryOriginal", "enrollmentKeyInventoryOriginal",
    "registrationSignerAttestationOriginal", "registrationSignerAttestationSha256", "issuerId",
    "maximumAgeNs", "maximumClockSkewNs", "maximumPlanAgeNs", "attestationMaximumAgeNs"})
OPERATIONS = frozenset({"webauthn.registration.evidence.admit", "webauthn.registration.finalize"})


def require(value):
    if not value:
        raise ValueError("local enrollment configuration preparation refused")


def _original(value, name, maximum=io.MAX_PUBLIC):
    raw = value[name + "Original"]
    require(type(raw) is str and raw.isascii() and 0 < len(raw) <= maximum)
    raw = raw.encode("ascii")
    require(sha(raw) == value[name + "Sha256"])
    return raw


def prepare(raw, *, boot, now_boottime_ns, now_unix_ns):
    """Own bounded public originals; return only a newly validated unsigned input."""
    selected = document(raw, io.MAX_PUBLIC)
    require(set(selected) == FIELDS and selected["schema"] == SCHEMA and selected["purpose"] == PURPOSE)
    base_raw = _original(selected, "configurationApproval")
    base = configuration.prepare(base_raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    original, payload = base["selected"], base["payload"]
    require(original["role"] == "authority-service" and original["serviceConfigurationOriginal"] is None
        and all(field not in payload or payload[field] is None for field in (enrollment.FIELD, evidence.FIELD, transition.FIELD)))
    pilot, _ = keys._pilot_inventory(selected["pilotKeyInventoryOriginal"])
    audit, _ = keys.genesis_audit_inventory(selected["genesisAuditKeyInventoryOriginal"], selected["pilotKeyInventoryOriginal"])
    added, _ = keys.enrollment_inventory(selected["enrollmentKeyInventoryOriginal"],
        selected["pilotKeyInventoryOriginal"], selected["genesisAuditKeyInventoryOriginal"])
    public = {(row["family"], row["purpose"]): row for row in pilot["keys"]}
    require(original["configurationRootPublicKeyBase64Url"] == public[("configuration", "configuration-root")]["publicKeyBase64Url"]
        and original["runtimePublicKeys"] == {name: public[("service", name)]["publicKeyBase64Url"] for name in configuration.RUNTIME_KEY_ROLES}
        and payload.get("policyGenesis", {}).get("auditSignerPublicKeyDigest") == audit["keys"][0]["publicKeySpkiSha256"])
    new_keys = {row["purpose"]: row for row in added["keys"]}
    authorization, registration = new_keys["authorization"], new_keys["registration-evidence"]
    root = Ed25519PublicKey.from_public_bytes(configuration._public(original["configurationRootPublicKeyBase64Url"]))
    receipt_raw = _original(selected, "registrationSignerAttestation", signer.MAX_ATTESTATION_BYTES)
    work = _ValidationWork(QueryReadValidationLimits(max_hashes=32, max_input_bytes=2 * 1024 * 1024, max_json_nodes=16384))
    _envelope, claims, interval, opening, receipt_digest = signer._read_attestation(
        receipt_raw, root, selected["attestationMaximumAgeNs"], work)
    require(claims["signingSpkiDigest"] == registration["publicKeySpkiSha256"]
        and original["expiresAtUnixNanos"] <= interval[1]
        and interval[0] <= now_unix_ns < interval[1])
    identity = {name: claims[name] for name in ("sessionIdentityDigest", "measurementDigest")}
    identity["attestationReceiptDigest"] = receipt_digest
    purpose = dict(operation="webauthn.registration.evidence.admit", purpose="registration-attestation",
        signingPublicKeyBase64Url=registration["publicKeyBase64Url"], signingSpkiDigest=registration["publicKeySpkiSha256"],
        signerIdentity=identity, maximumAgeNs=selected["maximumAgeNs"], maximumClockSkewNs=selected["maximumClockSkewNs"],
        rpId=payload["webauthn"]["rpId"], origin=payload["webauthn"]["origin"])
    require(payload["webauthn"]["requireAttestationTrusted"] is True
        and type(payload["webauthn"]["allowedAuthenticatorClasses"]) is list
        and set(payload["webauthn"]["allowedAuthenticatorClasses"]) <= {"hardware", "yubikey"}
        and payload["webauthn"]["allowedAuthenticatorClasses"])
    payload[evidence.FIELD] = dict(schema=evidence.SCHEMA, registration=purpose, installation=None)
    finalization = dict(purpose)
    finalization.pop("purpose")
    finalization.update(operation="webauthn.registration.finalize", maximumPlanAgeNs=selected["maximumPlanAgeNs"])
    payload[transition.FIELD] = dict(schema=transition.SCHEMA, registration=finalization, stage=None, completion=None)
    payload[enrollment.FIELD] = dict(schema=enrollment.SCHEMA, operation=enrollment.OPERATION, purpose=enrollment.PURPOSE,
        issuerId=selected["issuerId"], signingPublicKeyBase64Url=authorization["publicKeyBase64Url"],
        signingSpkiDigest=authorization["publicKeySpkiSha256"], audienceSigningSpkiDigest=registration["publicKeySpkiSha256"],
        maximumAgeNs=selected["maximumAgeNs"], maximumClockSkewNs=selected["maximumClockSkewNs"])
    enabled = payload["roles"]["planner"]["enabledOperations"]
    require(not OPERATIONS.intersection(enabled))
    payload["roles"]["planner"]["enabledOperations"] = sorted(set(enabled) | OPERATIONS)
    evidence.validate_policy(payload[evidence.FIELD], webauthn=payload["webauthn"])
    transition.validate_policy(payload[transition.FIELD], webauthn=payload["webauthn"])
    enrollment.validate_policy(payload[enrollment.FIELD], payload=payload)
    payload_raw = canonical(payload)
    original.update(payloadOriginal=payload_raw.decode("ascii"), payloadSha256=sha(payload_raw))
    result_raw = canonical(original)
    result = configuration.prepare(result_raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    signer._fresh(interval, selected["attestationMaximumAgeNs"], work, opening)
    return dict(configurationApprovalOriginal=result_raw, deadline=result["deadline"], epochLimit=result["epochLimit"])


class LocalEnrollmentConfigurationBuilder:
    """Borrow one exact protected input; emit a public unsigned approval once."""

    def __init__(self, *, approval_fd, approval_sha256):
        io._process()
        from catchplate import config
        require(not config.PRODUCTION_IMAGE and os.environ.get("CATCHPLATE_RELEASE_CHANNEL") == "dev"
            and os.environ.get("CATCHPLATE_PROCESS_MODE") == "metadata-bootstrap")
        self.pid, self.environment = os.getpid(), tuple(sorted(os.environ.items()))
        self.fd, self.identity = approval_fd, io._input(approval_fd, io.MAX_PUBLIC)
        self.raw = io.read_public(approval_fd, io.MAX_PUBLIC)
        spec._require_digest(approval_sha256, name="local enrollment selection pin")
        require(sha(self.raw) == approval_sha256)
        self.boot = configuration.launcher._boot_identity_digest()
        self.previous_boot, self.previous_unix = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        self.context = prepare(self.raw, boot=self.boot, now_boottime_ns=self.previous_boot, now_unix_ns=self.previous_unix)
        self.used = False
        self.check()

    def check(self):
        io._process()
        require(os.getpid() == self.pid and tuple(sorted(os.environ.items())) == self.environment
            and configuration.launcher._boot_identity_digest() == self.boot
            and io._input(self.fd, io.MAX_PUBLIC) == self.identity and io.read_public(self.fd, io.MAX_PUBLIC) == self.raw)
        boot, unix = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        require(self.previous_boot <= boot < self.context["deadline"] and self.previous_unix <= unix < self.context["epochLimit"])
        self.previous_boot, self.previous_unix = boot, unix

    def build(self):
        require(not self.used)
        self.used = True
        self.check()
        result = prepare(self.raw, boot=self.boot, now_boottime_ns=self.previous_boot, now_unix_ns=self.previous_unix)
        require(result == self.context)
        self.check()
        return result["configurationApprovalOriginal"]

    def publish(self):
        raw = self.build()
        io.write_public(raw, deadline_boottime_ns=self.context["deadline"], check=self.check)
        self.check()
