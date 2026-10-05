"""Closed signed recovery selection and its invocation-local custody mapper.

The optional Service6 block selects independently supplied originals. It does
not provision a root, create a witness, authorize a signature, or admit a DTO.
The real service still owns measured configuration, launch and metadata access.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from serverware import authority_recovery_retention_policy as retention

FIELD = "webauthnRecovery"
SCHEMA = "serverware.policyAuthorityWebAuthnRecoveryCustody/v1"
DESCRIPTORS = {
    "root": "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY_FD",
    "dsn": "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_POSTGRES_DSN_FD",
    "tlsRoot": "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_TLS_ROOT_FD",
    "certificate": "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_CLIENT_CERTIFICATE_FD",
    "key": "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_CLIENT_KEY_FD",
}
CREDENTIAL_NAMES = frozenset(DESCRIPTORS.values())
POLICY_FIELDS = frozenset({"rp_id", "origin", "allowed_authenticator_classes",
    "authorization_policy_digest", "recovery_root_key_id", "recovery_root_provider",
    "recovery_audience"})
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ROLE = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")


class RecoveryConfigurationError(ValueError):
    pass


def require(value):
    if not value:
        raise RecoveryConfigurationError("recovery selection or original custody differs")


def _closed(value, fields):
    require(type(value) is dict and set(value) == set(fields)
        and all(type(name) is str for name in value))
    return value


def _text(value, maximum):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= maximum
        and value == value.strip() and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    return value


def _digest(value):
    require(type(value) is str and _DIGEST.fullmatch(value) is not None
        and value != "sha256:" + "0" * 64)
    return value


def _port(value):
    require(type(value) is int and 1 <= value <= 65535)


def _address(value):
    _text(value, 45)
    require(str(ipaddress.ip_address(value)) == value)


def configuration(value, *, webauthn):
    """Validate shape/joins only; absence never enables recovery implicitly."""
    if value is None:
        return None
    # Existing absent blocks stay disabled. A present older block must be
    # explicitly migrated and re-signed; do not supply ambient retention.
    _closed(value, {"schema", "policy", "rootPublicPemSha256", "metadata", "witness", retention.FIELD})
    require(value["schema"] == SCHEMA)
    try:
        retention._shape(value[retention.FIELD])
    except retention.RecoveryRetentionPolicyError as exc:
        raise RecoveryConfigurationError("recovery retention selection differs") from exc
    _digest(value["rootPublicPemSha256"])
    policy = _closed(value["policy"], POLICY_FIELDS)
    for name in ("authorization_policy_digest", "recovery_root_key_id"):
        _digest(policy[name])
    for name, maximum in (("rp_id", 253), ("origin", 2048),
            ("recovery_root_provider", 128), ("recovery_audience", 512)):
        _text(policy[name], maximum)
    require(len(policy["recovery_root_provider"]) >= 3)
    origin = urlsplit(policy["origin"])
    require(origin.scheme == "https" and origin.hostname
        and origin.username is None and origin.password is None
        and not origin.query and not origin.fragment and origin.path in ("", "/"))
    classes = policy["allowed_authenticator_classes"]
    require(type(classes) is list and 1 <= len(classes) <= 2
        and all(type(item) is str and item in {"hardware", "yubikey"} for item in classes)
        and len(set(classes)) == len(classes))
    require(type(webauthn) is dict and policy["rp_id"] == webauthn["rpId"]
        and policy["origin"] == webauthn["origin"]
        and classes == webauthn["allowedAuthenticatorClasses"]
        and webauthn["requireAttestationTrusted"] is True)
    metadata = _closed(value["metadata"],
        {"database", "clusterId", "serverAddress", "serverPort", "faultDomain"})
    witness = _closed(value["witness"], {"endpoint", "identity", "originals"})
    endpoint = _closed(witness["endpoint"], {"host", "address", "port", "database"})
    identity = _closed(witness["identity"], {"clusterId", "serverAddress", "serverPort",
        "faultDomain", "role", "clientDn", "clientSerial", "issuerDn"})
    for target in (metadata, identity):
        _text(target["clusterId"], 20)
        require(target["clusterId"].isascii() and target["clusterId"].isdecimal()
            and str(int(target["clusterId"])) == target["clusterId"]
            and 0 < int(target["clusterId"]) < 2**64)
        _address(target["serverAddress"])
        _port(target["serverPort"])
        _text(target["faultDomain"], 256)
        require(target["faultDomain"].isascii()
            and not any(c.isspace() for c in target["faultDomain"]))
    _text(metadata["database"], 63)
    _text(endpoint["host"], 253)
    require(endpoint["host"].isascii() and re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", endpoint["host"]) is not None)
    _address(endpoint["address"])
    _port(endpoint["port"])
    _text(endpoint["database"], 63)
    require(type(identity["role"]) is str and _ROLE.fullmatch(identity["role"]) is not None)
    for name in ("clientDn", "issuerDn"):
        _text(identity[name], 2048)
    _text(identity["clientSerial"], 128)
    require(identity["clientSerial"].isascii() and identity["clientSerial"].isdecimal()
        and str(int(identity["clientSerial"])) == identity["clientSerial"]
        and int(identity["clientSerial"]) > 0)
    originals = _closed(witness["originals"],
        {"dsnSha256", "tlsRootSha256", "certificateSha256", "keySha256"})
    for digest in originals.values():
        _digest(digest)
    require(metadata["clusterId"] != identity["clusterId"]
        and metadata["faultDomain"] != identity["faultDomain"]
        and (metadata["serverAddress"], metadata["serverPort"])
            != (identity["serverAddress"], identity["serverPort"]))
    return value


def _recovery_from_configuration_on_work(*, payload, configuration_digest, generation,
        runtime_role_identities, configuration_owner, observed_descriptors,
        metadata_connection, original_deadline_ns, check, work):
    """Borrow actual admitted originals; these parameters cannot grant admission."""
    from serverware import authority_revocation_configuration as measured
    from serverware import authority_recovery_custody as custody

    owned, launch = measured._capture_configuration_on_work(payload=payload,
        configuration_digest=configuration_digest, generation=generation, work=work)
    runtime = measured._capture_runtime_role_identities_on_work(
        runtime_role_identities=runtime_role_identities, owned_payload=owned,
        configuration_digest=configuration_digest, launch=launch, work=work)
    selected = configuration(owned.get(FIELD), webauthn=owned["webauthn"])
    require(selected is not None)
    return custody._RecoveryCustody._borrow(selected=selected, payload=owned,
        configuration_digest=configuration_digest, generation=launch,
        runtime_role_identities=runtime, configuration_owner=configuration_owner,
        observed_descriptors=observed_descriptors, metadata_connection=metadata_connection,
        original_deadline_ns=original_deadline_ns, check=check, work=work)
