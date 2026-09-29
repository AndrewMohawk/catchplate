"""Closed ciphertext delivery grammar; no key or verification authority."""
from __future__ import annotations
import hashlib
from serverware import native_shadow_nitro_profile as p

CHANNEL = "serverware.nativeShadowKeyDeliveryChannel/v1"
REQUEST = "serverware.nativeShadowKeyKmsRecipientRequest/v1"
RESPONSE = "serverware.nativeShadowKeyKmsRecipientCiphertext/v1"
QUOTE_DOMAIN = b"serverware/native-shadow-kms-recipient/v1\0"
AAD_DOMAIN = b"serverware/native-shadow-encrypted-local-keys/v1\0"
OUTPUT_DOMAIN = b"serverware/native-shadow-role-recipient-ciphertext/v1\0"
IMAGE = "/opt/serverware/native-shadow-key-delivery-runtime.squashfs"
MAX_FRAME = 128 * 1024


def inventory(value):
    p.fields(value, ("apiVersion", "fullKeySetRootSha256", "localKeySetRootSha256", "localKeys"))
    p.require(value["apiVersion"] == "serverware.nativeShadowLocalKeyInventory/v1")
    p.digest(value["fullKeySetRootSha256"])
    keys = value["localKeys"]
    p.require(type(keys) is list and 1 <= len(keys) <= 16)
    for key in keys:
        p.public_key(key)
        p.require(key["role"] in p.ROLES[:16])
    roles = [key["role"] for key in keys]
    p.require(roles == sorted(set(roles), key=p.ROLES.index))
    for name in ("keyId", "keySpkiSha256", "keyMaterialSha256"):
        p.require(len({key[name] for key in keys}) == len(keys))
    p.require(p.key_root(keys) == p.digest(value["localKeySetRootSha256"]))
    return value


def transport(value):
    p.fields(value, ("apiVersion", "kmsParentPort", "kmsKeyId", "ciphertextBlobSha256", "encryptionContext",
                     "kekSha256", "helperImage", "encryptedInventorySha256"))
    p.require(value["apiVersion"] == "serverware.nativeShadowKeyKmsTransport/v1")
    p.integer(value["kmsParentPort"], 1024, (1 << 32)-2)
    for name in ("ciphertextBlobSha256", "kekSha256", "encryptedInventorySha256"):
        p.digest(value[name])
    p.require(type(value["kmsKeyId"]) is str and 1 <= len(value["kmsKeyId"]) <= 2048
              and all(ord(c) >= 32 and ord(c) != 127 for c in value["kmsKeyId"]))
    image = p.fields(value["helperImage"], ("profile", "imagePath", "imageSha256", "interpreterSha256", "helperSha256"))
    p.require(image["profile"] == "sealed-memfd-squashfs-v1" and image["imagePath"] == IMAGE)
    for name in ("imageSha256", "interpreterSha256", "helperSha256"):
        p.digest(image[name])
    context = value["encryptionContext"]
    p.require(type(context) is dict and 1 <= len(context) <= 32 and len(p.canonical(context)) <= 8192
              and context.get("serverwarePurpose") == "native-shadow-local-role-keys/v1")
    for key, item in context.items():
        p.require(type(key) is str and type(item) is str and 1 <= len(key) <= 1024 and 1 <= len(item) <= 1024
                  and all(ord(c) >= 32 and ord(c) != 127 for c in key+item))
    return value


def binding(value):
    p.fields(value, ("apiVersion", "guest", "keyAuthorizationSha256", "deliveryAuthorizationSha256", "inventory",
                     "challengeBase64url", "executionClosureManifestSha256", "workerExecutableSha256",
                     "structurallyVerifiedSeccompPolicySha256"))
    p.require(value["apiVersion"] == "serverware.nativeShadowKeyDeliveryBinding/v1")
    p.guest(value["guest"])
    for name in ("keyAuthorizationSha256", "deliveryAuthorizationSha256", "executionClosureManifestSha256",
                 "workerExecutableSha256", "structurallyVerifiedSeccompPolicySha256"):
        p.digest(value[name])
    inventory(value["inventory"])
    p.require(p.decoded(value["challengeBase64url"], size=32) != bytes(32))
    return value


def nonce(value):
    return hashlib.sha256(b"serverware/native-shadow-kms-nonce/v1\0" +
                          p.decoded(value["challengeBase64url"], size=32)).digest()


def request(value):
    p.fields(value, ("apiVersion", "material", "binding", "transport", "recipientPublicKeySha256",
                     "roleRecipientPublicKey", "nonce", "deadlineBoottimeNs"))
    p.require(value["apiVersion"] == REQUEST and value["material"] == "shadow-local-key-kek")
    binding(value["binding"]); transport(value["transport"])
    p.digest(value["recipientPublicKeySha256"])
    p.require(p.decoded(value["roleRecipientPublicKey"], size=32) != bytes(32)
              and p.decoded(value["nonce"], size=32) == nonce(value["binding"])
              and value["deadlineBoottimeNs"] == value["binding"]["guest"]["startupDeadlineBoottimeNs"])
    p.ns(value["deadlineBoottimeNs"])
    return value


def encrypted(value, expected):
    p.fields(value, ("apiVersion", "inventorySha256", "nonce", "ciphertext"))
    p.require(value["apiVersion"] == "serverware.nativeShadowEncryptedLocalKeys/v1"
              and value["inventorySha256"] == p.sha(p.canonical(expected)))
    iv = p.decoded(value["nonce"], size=12)
    ciphertext = p.decoded(value["ciphertext"], maximum=16384)
    p.require(len(ciphertext) > 16)
    return iv, ciphertext
