"""Immutable database pins projected from the process's admitted configuration.

This projection is not configuration or launch admission. The service supplies
its actual MeasuredConfiguration after runtime evidence admission; database
connectors still verify the actual TLS session, privileges and owner closure.
No environment mutation, private key, database connection or clock lives here.
"""
from __future__ import annotations

import base64
import hashlib
import math
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


OWNER_ROLE = "serverware_policy_authority_owner"
ISSUER_ROLE = "serverware_policy_capability_issuer"


class AuthorityDatabaseConfigurationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AuthorityDatabaseConfiguration:
    configuration_digest: str
    executor_pins: tuple
    verifier_pins: tuple
    issuer_pins: tuple
    verifier_public_key_base64url: str
    verifier_spki_digest: str
    verifier_measurement_digest: str
    verifier_attestation_receipt_digest: str
    verifier_credential_issuance_digest: str
    issuer_measurement_digest: str
    issuer_attestation_receipt_digest: str
    issuer_credential_issuance_digest: str
    replay_witness_identity_digest: str
    audit_store_identity_digest: str
    audit_signer_spki_digest: str


def _digest(value):
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise AuthorityDatabaseConfigurationError("database configuration digest is invalid")
    return value


def _pins(value):
    if type(value) is not tuple or len(value) != 5:
        raise AuthorityDatabaseConfigurationError("database identity is not an immutable selection")
    role, dn, serial, issuer, timeout = value
    if (any(type(item) is not str or not item or "\x00" in item for item in value[:4])
            or type(timeout) not in (int, float) or not math.isfinite(timeout)
            or not 1 <= timeout <= 300):
        raise AuthorityDatabaseConfigurationError("database identity is invalid")
    try:
        valid = (len(role.encode("utf-8")) <= 63 and len(dn.encode("utf-8")) <= 4096
            and len(issuer.encode("utf-8")) <= 4096 and len(serial.encode("ascii")) <= 256
            and re.fullmatch(r"[0-9A-Fa-f:]+", serial) is not None)
    except UnicodeError as exc:
        raise AuthorityDatabaseConfigurationError("database identity encoding is invalid") from exc
    if not valid:
        raise AuthorityDatabaseConfigurationError("database identity exceeds its bounds")


def require(value):
    if type(value) is not AuthorityDatabaseConfiguration:
        raise AuthorityDatabaseConfigurationError("admitted database configuration is required")
    for name in value.__dataclass_fields__:
        if name.endswith("_digest"):
            _digest(getattr(value, name))
    for pins in (value.executor_pins, value.verifier_pins, value.issuer_pins):
        _pins(pins)
    if (value.issuer_pins[0] != ISSUER_ROLE
            or len({value.executor_pins[0], value.verifier_pins[0], value.issuer_pins[0], OWNER_ROLE}) != 4
            or len({value.executor_pins[1:4], value.verifier_pins[1:4], value.issuer_pins[1:4]}) != 3):
        raise AuthorityDatabaseConfigurationError("database privilege identities are not distinct")
    encoded = value.verifier_public_key_base64url
    if type(encoded) is not str or re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded) is None:
        raise AuthorityDatabaseConfigurationError("verifier public key is not canonical raw32")
    raw = base64.urlsafe_b64decode(encoded + "=")
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != encoded:
        raise AuthorityDatabaseConfigurationError("verifier public key is not canonical raw32")
    spki = Ed25519PublicKey.from_public_bytes(raw).public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    if "sha256:" + hashlib.sha256(spki).hexdigest() != value.verifier_spki_digest:
        raise AuthorityDatabaseConfigurationError("verifier public key differs from its signed pin")
    return value


def from_measured_configuration(configuration):
    # Lazy import avoids a service import/launch side effect for the data type.
    from serverware.authority_service import MeasuredConfiguration
    from serverware import authority_launch_guard

    if type(configuration) is not MeasuredConfiguration:
        raise AuthorityDatabaseConfigurationError("actual measured configuration is required")
    payload = configuration.payload
    runtime = configuration.runtime_role_identities
    generation = authority_launch_guard.generation()
    if (type(payload) is not dict or payload.get("schema") != "serverware.policyAuthorityServiceConfiguration/v6"
            or type(runtime) is not dict
            or runtime.get("schema") != "serverware.policyAuthorityRuntimeRoleIdentities/v1"
            or runtime.get("configurationDigest") != configuration.digest
            or runtime.get("generationSequence") != payload.get("generationSequence")
            or runtime.get("generationSequence") != generation.get("sequence")
            or runtime.get("generationDigest") != generation.get("digest")
            or payload.get("generationBindingDigest") != generation.get("configurationBindingDigest")):
        raise AuthorityDatabaseConfigurationError("runtime database configuration binding changed")
    try:
        roles = {name: configuration.role(name) for name in ("executor", "verifier", "issuer")}
        for name, role in roles.items():
            identity = runtime["roles"][name]
            if (type(identity) is not dict
                    or set(identity) != {"measurementDigest", "responseSigningSpkiDigest", "attestationReceiptDigest"}
                    or any(identity[field] != role[field] for field in identity)):
                raise AuthorityDatabaseConfigurationError("runtime database role identity changed")
        def pins(role):
            return tuple(role[field] for field in ("databaseRole", "tlsClientDn", "tlsClientSerial",
                "tlsIssuerDn", "databaseConnectTimeoutSeconds"))
        genesis = payload["policyGenesis"]
        if type(genesis) is not dict or set(genesis) != {"auditStoreIdentityDigest", "auditSignerPublicKeyDigest"}:
            raise AuthorityDatabaseConfigurationError("signed database audit pins are unavailable")
        verifier, issuer = roles["verifier"], roles["issuer"]
        return require(AuthorityDatabaseConfiguration(
            configuration.digest, pins(roles["executor"]), pins(verifier), pins(issuer),
            verifier["signingPublicKeyBase64Url"], verifier["signingSpkiDigest"],
            verifier["measurementDigest"], verifier["attestationReceiptDigest"],
            payload["verifierCredentialIssuanceDigest"], issuer["measurementDigest"],
            issuer["attestationReceiptDigest"], payload["issuerCredentialIssuanceDigest"],
            payload["replayWitness"]["identityDigest"], genesis["auditStoreIdentityDigest"],
            genesis["auditSignerPublicKeyDigest"]))
    except (KeyError, TypeError) as exc:
        raise AuthorityDatabaseConfigurationError("signed database configuration is incomplete") from exc
