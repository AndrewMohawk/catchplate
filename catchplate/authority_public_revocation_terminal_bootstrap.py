"""Additive root-original admission for public revocation terminal owners.

This is a separate sealed launch input, not a field inferred from an HTTP
request or a new interpretation of the old service configuration. Existing
measured verifier/issuer/executor keys keep their identities. New SQL roles,
TLS originals and independently current journal checkpoints are explicit.
Nothing is provisioned and no observed journal head enrolls itself.
"""
from __future__ import annotations

import base64

from catchplate import authority_public_revocation_caller_authorization as caller
from catchplate import control_plane_public_revocation_bootstrap as scope
from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_contract as authority
from catchplate.registration_execution_sql_bootstrap import _database_shape
from catchplate.authority_store.completion_read_sql import COMPLETION_READER_ROLE


SCHEMA = "catchplate.signedPublicWebAuthnRevocationTerminalBootstrap/v1"
PAYLOAD_SCHEMA = "catchplate.publicWebAuthnRevocationTerminalBootstrap/v1"
ENVIRONMENT = "CATCHPLATE_PUBLIC_WEBAUTHN_REVOCATION_BOOTSTRAP_FD"
DESCRIPTOR = 212
MAX_BYTES = 512 * 1024
MAX_AGE_NS = 300_000_000_000
ROLES = {"verifier": 65520, "issuer": 65521, "executor": 65522}
SQL_ROLES = {"issue": authority.SUCCESSOR_ISSUER_ROLE, "execute": authority.SUCCESSOR_EXECUTOR_ROLE,
    "recover": authority.SUCCESSOR_RECOVERY_ROLE, "commit": COMPLETION_READER_ROLE}
DATABASE_PURPOSES = {"verifier": (), "issuer": ("issue",), "executor": ("execute", "recover", "commit")}
FIELDS = frozenset({"schema", "sourceRevision", "role", "configurationDigest", "generationDigest",
    "measurementDigest", "scope", "databaseEndpoint", "sqlRoles", "tlsFiles", "queryManifestDigest",
    "structureManifestDigest", "attemptJournal", "completionJournal", "issuedAtEpochNs", "expiresAtEpochNs"})
JOURNAL_FIELDS = frozenset({"path", "device", "inode", "maximumRecords", "sequence", "headDigest"})
JOURNAL_PATHS = {"attemptJournal": "/var/lib/catchplate/authority-public-revocation/attempts",
    "completionJournal": "/var/lib/catchplate/authority-public-revocation/completion"}
_SQL_FIELDS = frozenset({"connectTimeoutSeconds", "clientDn", "clientSerial", "issuerDn"})


def tls_paths(role):
    result = {} if role == "verifier" else {"ca": "/run/catchplate/public-revocation-tls/ca.pem"}
    for name in DATABASE_PURPOSES[role]:
        result[name + "Certificate"] = "/run/catchplate/public-revocation-tls/" + name + ".crt"
        result[name + "Key"] = "/run/catchplate/public-revocation-tls/" + name + ".key"
    return result


def _shape(payload):
    caller.shape._object(payload, FIELDS, "public revocation terminal bootstrap")
    caller.shape._literal(payload["schema"], PAYLOAD_SCHEMA)
    caller.shape._literal(payload["sourceRevision"], authority.SOURCE_REVISION)
    role = payload["role"]
    if type(role) is not str or role not in ROLES:
        raise scope.PublicRevocationBootstrapError("public revocation terminal role is not source fixed")
    for name in ("configurationDigest", "generationDigest", "measurementDigest", "queryManifestDigest",
            "structureManifestDigest"):
        caller.shape._digest(payload[name])
    if payload["scope"] is None:
        raise scope.PublicRevocationBootstrapError("selected public revocation terminal cannot have a null scope")
    scope._shape(payload["scope"])
    if role == "verifier":
        if payload["databaseEndpoint"] is not None:
            raise scope.PublicRevocationBootstrapError("public verifier cannot select a new database endpoint")
    else:
        _database_shape(payload["databaseEndpoint"])
    caller.shape._object(payload["sqlRoles"], frozenset(DATABASE_PURPOSES[role]), "public terminal SQL roles")
    for value in payload["sqlRoles"].values():
        caller.shape._object(value, _SQL_FIELDS, "public terminal SQL identity")
        caller.shape._integer(value["connectTimeoutSeconds"], 300, minimum=2)
        for name in ("clientDn", "clientSerial", "issuerDn"):
            scope.aggregate._text(value[name], 4096)
    caller.shape._object(payload["tlsFiles"], frozenset(tls_paths(role)), "public terminal TLS originals")
    for name, value in payload["tlsFiles"].items():
        caller.shape._object(value, frozenset({"bytesDigest", "byteCount"}), "public terminal TLS pin")
        caller.shape._digest(value["bytesDigest"])
        caller.shape._integer(value["byteCount"], 16 * 1024 if name.endswith("Key") else 64 * 1024, minimum=2)
    for name, path in JOURNAL_PATHS.items():
        value = payload[name]
        if role != "executor":
            if value is not None:
                raise scope.PublicRevocationBootstrapError("only the real executor owns public terminal journals")
            continue
        caller.shape._object(value, JOURNAL_FIELDS, "public terminal journal original")
        caller.shape._literal(value["path"], path)
        caller.shape._integer(value["device"], 2**64 - 1)
        caller.shape._integer(value["inode"], 2**64 - 1, minimum=1)
        caller.shape._integer(value["maximumRecords"], 4096, minimum=2)
        caller.shape._integer(value["sequence"], value["maximumRecords"])
        caller.shape._digest(value["headDigest"])
    if role == "executor" and (payload["attemptJournal"]["device"], payload["attemptJournal"]["inode"]) == (
            payload["completionJournal"]["device"], payload["completionJournal"]["inode"]):
        raise scope.PublicRevocationBootstrapError("public attempt and completion journals must be distinct")
    caller.authorization._interval(payload, MAX_AGE_NS)


def decode(original, *, root_public_key, work):
    value = caller.authorization.wire._decode_object(original, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=16384, maximum_depth=16)
    caller.shape._object(value, frozenset({"schema", "payload", "signatureBase64Url"}), "public terminal root original")
    caller.shape._literal(value["schema"], SCHEMA)
    _shape(value["payload"])
    caller.authorization._verify_signature(value, SCHEMA, root_public_key, MAX_BYTES, work)
    caller.primitives._unchanged(original, value, MAX_BYTES, work)
    return value["payload"]


def produce_on_work(*, payload, root_private_key, root_public_key, work):
    """Sign independently established cold facts; never inspect/provision them."""
    ledger = caller.capture._SharedLedger(work)
    owned = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit(payload)
    _shape(owned)
    caller.keys._pair_on_work(root_private_key, root_public_key, work)
    unsigned = caller.authorization.capability._wire(owned, ledger, MAX_BYTES, 16384)
    message = caller.plan._frame(SCHEMA, (unsigned,), work).encode("ascii")
    signature = caller.production._sign_and_verify(root_private_key, root_public_key, message, work)
    work.charge(input_bytes=64 + 88 + 86)
    return caller.authorization.capability._wire({"schema": SCHEMA, "payload": owned,
        "signatureBase64Url": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")},
        ledger, MAX_BYTES, 16384)


def database_configurations(payload):
    """Only fixed TLS paths/roles and a closed single-address libpq recipe."""
    _shape(payload)
    endpoint, paths = payload["databaseEndpoint"], tls_paths(payload["role"])
    result = {}
    for name, settings in payload["sqlRoles"].items():
        role = SQL_ROLES[name]
        dsn = ("host=" + endpoint["host"] + " hostaddr=" + endpoint["hostaddr"]
            + " port=" + str(endpoint["port"]) + " dbname=" + endpoint["databaseName"]
            + " user=" + role + " sslmode=verify-full sslrootcert=" + paths["ca"]
            + " sslcert=" + paths[name + "Certificate"] + " sslkey=" + paths[name + "Key"]
            + " passfile=/dev/null gssencmode=disable")
        result[name] = (dsn, settings["connectTimeoutSeconds"], role, settings["clientDn"],
            settings["clientSerial"], settings["issuerDn"], payload["queryManifestDigest"],
            payload["structureManifestDigest"])
    return result
