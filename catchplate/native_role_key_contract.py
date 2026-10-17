"""Closed public role-key provisioning commitments; no key-release authority."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid

CHANNEL = "catchplate.nativeRoleKeyProvisionerChannel/v1"
INVENTORY = "catchplate.nativeGuestRoleKeyInventory/v1"
CIPHERTEXT = "catchplate.nativeGuestRoleKeyCiphertext/v1"
PLAINTEXT = "catchplate.nativeGuestRoleKeyPlaintext/v1"
REQUEST = "catchplate.nativeRoleKeyKmsRecipientRequest/v1"
RESPONSE = "catchplate.nativeRoleKeyKmsRecipientCiphertext/v1"
MATERIAL = "guest-role-key-kek"
UID = 64989
FIRST_FD = 64
MAX_KEYS = 64
MAX_FRAME = 512 * 1024
MAX_CIPHERTEXT = 16384
ROLES = ("custody-router", "state-authority", "credential-transport", "policy-proof-verifier",
         "immutable-artifact-ledger", "release-attestor-publisher", "cleanup-watchdog")
AAD_DOMAIN = b"catchplate/native-guest-role-key-inventory/v1\0"
QUOTE_DOMAIN = b"catchplate/native-role-key-recipient/v1\0"


def require(value):
    if not value:
        raise ValueError("role-key provisioning original refused")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def document(raw, maximum=MAX_FRAME):
    require(type(raw) is bytes and 0 < len(raw) <= maximum)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=lambda _: require(False),
                       parse_constant=lambda _: require(False))
    require(type(value) is dict and canonical(value) == raw)
    return value


def closed(value, fields):
    require(type(value) is dict and set(value) == set(fields))


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def sha(value):
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
            and value[7:] != "0" * 64)
    return value


def encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decoded(value, maximum, exact=None):
    require(type(value) is str and 0 < len(value) <= (maximum * 4 + 2) // 3)
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    require(0 < len(raw) <= maximum and encoded(raw) == value and (exact is None or len(raw) == exact))
    return raw


def integer(value, minimum=1, maximum=2**64 - 1):
    require(type(value) is int and minimum <= value <= maximum)
    return value


def text(value, maximum):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= maximum
            and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value))
    return value


def path(value):
    text(value, 4096)
    require(value.isascii() and value.startswith("/") and not value.startswith("/run/catchplate-response-v2-public/")
            and all(part not in {"", ".", ".."} and len(part) <= 255 for part in value[1:].split("/")))
    return value


def inventory(value):
    closed(value, ("apiVersion", "configurationSha256", "generationId", "generation", "trustCheckpointSha256",
                   "bootId", "deadlineBoottimeNs", "deliveries", "keys"))
    require(value["apiVersion"] == INVENTORY and len(canonical(value)) <= MAX_FRAME)
    sha(value["configurationSha256"]); sha(value["trustCheckpointSha256"])
    text(value["generationId"], 256); integer(value["generation"])
    require(str(uuid.UUID(value["bootId"])) == value["bootId"])
    deadline = value["deadlineBoottimeNs"]
    require(type(deadline) is str and re.fullmatch(r"[1-9][0-9]{0,19}", deadline) is not None)
    integer(int(deadline))
    require(type(value["deliveries"]) is list and len(value["deliveries"]) == len(ROLES))
    for role, delivery in zip(ROLES, value["deliveries"]):
        closed(delivery, ("serviceRole", "deliverySha256"))
        require(delivery["serviceRole"] == role); sha(delivery["deliverySha256"])
    keys = value["keys"]
    require(type(keys) is list and len(ROLES) <= len(keys) <= MAX_KEYS)
    paths, names, owners = set(), [], {}
    for key in keys:
        closed(key, ("serviceRole", "logicalRole", "uid", "gid", "path", "seedSha256", "publicKeySha256"))
        require(key["serviceRole"] in ROLES)
        text(key["logicalRole"], 128); path(key["path"])
        for name in ("uid", "gid"):
            integer(key[name], maximum=2**32-2)
            require(key[name] not in {UID, 64990, 65534})
        identity = (key["uid"], key["gid"])
        require(owners.setdefault(key["serviceRole"], identity) == identity)
        require(key["path"] not in paths); paths.add(key["path"])
        sha(key["seedSha256"]); sha(key["publicKeySha256"])
        names.append((ROLES.index(key["serviceRole"]), key["logicalRole"]))
    require(names == sorted(set(names)) and set(owners) == set(ROLES)
            and len({uid for uid, _gid in owners.values()}) == len(ROLES))
    return value


def encrypted(value, expected_inventory):
    closed(value, ("apiVersion", "inventorySha256", "nonce", "ciphertext"))
    require(value["apiVersion"] == CIPHERTEXT and value["inventorySha256"] == digest(canonical(inventory(expected_inventory))))
    nonce = decoded(value["nonce"], 12, 12)
    raw = decoded(value["ciphertext"], MAX_CIPHERTEXT)
    require(len(raw) > 16)
    return nonce, raw


def request(value):
    closed(value, ("apiVersion", "material", "configurationSha256", "deliveryInventorySha256",
                   "provisionerConfigurationSha256", "helperImageSha256", "bootId", "deadlineBoottimeNs",
                   "kmsKeyId", "ciphertextBlobSha256", "encryptionContext", "recipientPublicKeySha256", "nonce"))
    require(value["apiVersion"] == REQUEST and value["material"] == MATERIAL)
    for name in ("configurationSha256", "deliveryInventorySha256", "provisionerConfigurationSha256",
                 "helperImageSha256", "ciphertextBlobSha256", "recipientPublicKeySha256"):
        sha(value[name])
    require(str(uuid.UUID(value["bootId"])) == value["bootId"])
    require(type(value["deadlineBoottimeNs"]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value["deadlineBoottimeNs"]) is not None)
    integer(int(value["deadlineBoottimeNs"])); text(value["kmsKeyId"], 2048); decoded(value["nonce"], 32, 32)
    context = value["encryptionContext"]
    require(type(context) is dict and 1 <= len(context) <= 32 and len(canonical(context)) <= 8192
            and context.get("catchplatePurpose") == "guest-role-keys/v1")
    for key, item in context.items():
        text(key, 1024); text(item, 1024)
    return value
