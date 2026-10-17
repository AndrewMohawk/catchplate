"""Closed ciphertext delivery grammar; no key or verification authority."""
from __future__ import annotations
import hashlib
from catchplate import native_shadow_nitro_profile as p

CHANNEL = "catchplate.nativeShadowKeyDeliveryChannel/v1"
REQUEST = "catchplate.nativeShadowKeyKmsRecipientRequest/v1"
RESPONSE = "catchplate.nativeShadowKeyKmsRecipientCiphertext/v1"
QUOTE_DOMAIN = b"catchplate/native-shadow-kms-recipient/v1\0"
AAD_DOMAIN = b"catchplate/native-shadow-encrypted-local-keys/v1\0"
OUTPUT_DOMAIN = b"catchplate/native-shadow-role-recipient-ciphertext/v1\0"
COMMITMENT_DOMAIN = b"catchplate/native-shadow-request-commitment-secret/v1\0"
IMAGE = "/opt/catchplate/native-shadow-key-delivery-runtime.squashfs"
MAX_FRAME = 128 * 1024


def inventory(value):
    extended = type(value) is dict and value.get("apiVersion") == "catchplate.nativeShadowLocalKeyInventory/v2"
    p.fields(value, ("apiVersion", "fullKeySetRootSha256", "localKeySetRootSha256", "localKeys") +
             (("requestCommitment",) if extended else ()))
    p.require(value["apiVersion"] == ("catchplate.nativeShadowLocalKeyInventory/v2" if extended else
                                      "catchplate.nativeShadowLocalKeyInventory/v1"))
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
    if extended:
        descriptor = commitment(value["requestCommitment"])
        p.require(descriptor["keyId"] not in {key["keyId"] for key in keys})
    return value


def commitment(value):
    p.fields(value, ("keyId", "keyEpoch", "secretSha256"))
    p.digest(value["keyId"]); p.digest(value["secretSha256"])
    p.integer(value["keyEpoch"], 1, (1 << 63)-1)
    return value


def extended(value):
    return value["apiVersion"] == "catchplate.nativeShadowLocalKeyInventory/v2"


def aad(inventory_value):
    return (b"catchplate/native-shadow-encrypted-local-keys/v2\0" if extended(inventory_value)
            else AAD_DOMAIN) + p.canonical(inventory_value)


def seeds(value, inventory_value):
    """Validate secret shape/commitment, never return or authorize a new key."""
    v2 = extended(inventory_value)
    p.fields(value, ("apiVersion", "inventorySha256", "seeds") + (("requestCommitment",) if v2 else ()))
    p.require(value["apiVersion"] == ("catchplate.nativeShadowLocalKeySeeds/v2" if v2 else
                                      "catchplate.nativeShadowLocalKeySeeds/v1")
              and value["inventorySha256"] == p.sha(p.canonical(inventory_value))
              and type(value["seeds"]) is list and len(value["seeds"]) == len(inventory_value["localKeys"]))
    raw_seeds = []
    for item, key in zip(value["seeds"], inventory_value["localKeys"]):
        p.fields(item, ("role", "keyId", "seedBase64url"))
        p.require(item["role"] == key["role"] and item["keyId"] == key["keyId"])
        raw_seeds.append(p.decoded(item["seedBase64url"], size=32))
    if v2:
        supplied = p.fields(value["requestCommitment"], ("keyId", "keyEpoch", "secretBase64url"))
        expected = inventory_value["requestCommitment"]
        secret = p.decoded(supplied["secretBase64url"], size=32)
        p.require(secret != bytes(32) and secret not in raw_seeds
                  and supplied["keyId"] == expected["keyId"] and supplied["keyEpoch"] == expected["keyEpoch"]
                  and p.sha(COMMITMENT_DOMAIN+secret) == expected["secretSha256"])
    return value


def transport(value):
    p.fields(value, ("apiVersion", "kmsParentPort", "kmsKeyId", "ciphertextBlobSha256", "encryptionContext",
                     "kekSha256", "helperImage", "encryptedInventorySha256"))
    p.require(value["apiVersion"] in ("catchplate.nativeShadowKeyKmsTransport/v1", "catchplate.nativeShadowKeyKmsTransport/v2"))
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
              and context.get("catchplatePurpose") == ("native-shadow-local-role-keys-and-request-commitment/v2"
                  if value["apiVersion"] == "catchplate.nativeShadowKeyKmsTransport/v2" else "native-shadow-local-role-keys/v1"))
    for key, item in context.items():
        p.require(type(key) is str and type(item) is str and 1 <= len(key) <= 1024 and 1 <= len(item) <= 1024
                  and all(ord(c) >= 32 and ord(c) != 127 for c in key+item))
    return value


def binding(value):
    p.fields(value, ("apiVersion", "guest", "keyAuthorizationSha256", "deliveryAuthorizationSha256", "inventory",
                     "challengeBase64url", "executionClosureManifestSha256", "workerExecutableSha256",
                     "structurallyVerifiedSeccompPolicySha256"))
    p.require(value["apiVersion"] in ("catchplate.nativeShadowKeyDeliveryBinding/v1", "catchplate.nativeShadowKeyDeliveryBinding/v2"))
    p.guest(value["guest"])
    for name in ("keyAuthorizationSha256", "deliveryAuthorizationSha256", "executionClosureManifestSha256",
                 "workerExecutableSha256", "structurallyVerifiedSeccompPolicySha256"):
        p.digest(value[name])
    inventory(value["inventory"])
    p.require((value["apiVersion"] == "catchplate.nativeShadowKeyDeliveryBinding/v2") == extended(value["inventory"]))
    p.require(p.decoded(value["challengeBase64url"], size=32) != bytes(32))
    return value


def nonce(value):
    domain = (b"catchplate/native-shadow-kms-nonce/v2\0" if extended(value["inventory"])
              else b"catchplate/native-shadow-kms-nonce/v1\0")
    return hashlib.sha256(domain +
                          p.decoded(value["challengeBase64url"], size=32)).digest()


def request(value):
    p.fields(value, ("apiVersion", "material", "binding", "transport", "recipientPublicKeySha256",
                     "roleRecipientPublicKey", "nonce", "deadlineBoottimeNs"))
    binding(value["binding"]); transport(value["transport"])
    v2 = extended(value["binding"]["inventory"])
    p.require(value["apiVersion"] == ("catchplate.nativeShadowKeyKmsRecipientRequest/v2" if v2 else REQUEST)
              and value["material"] == ("shadow-local-key-and-commitment-kek" if v2 else "shadow-local-key-kek")
              and value["transport"]["apiVersion"] == ("catchplate.nativeShadowKeyKmsTransport/v2" if v2 else
                                                       "catchplate.nativeShadowKeyKmsTransport/v1"))
    p.digest(value["recipientPublicKeySha256"])
    p.require(p.decoded(value["roleRecipientPublicKey"], size=32) != bytes(32)
              and p.decoded(value["nonce"], size=32) == nonce(value["binding"])
              and value["deadlineBoottimeNs"] == value["binding"]["guest"]["startupDeadlineBoottimeNs"])
    p.ns(value["deadlineBoottimeNs"])
    return value


def encrypted(value, expected):
    p.fields(value, ("apiVersion", "inventorySha256", "nonce", "ciphertext"))
    p.require(value["apiVersion"] == ("catchplate.nativeShadowEncryptedLocalKeys/v2" if extended(expected) else
                                      "catchplate.nativeShadowEncryptedLocalKeys/v1")
              and value["inventorySha256"] == p.sha(p.canonical(expected)))
    iv = p.decoded(value["nonce"], size=12)
    ciphertext = p.decoded(value["ciphertext"], maximum=16384)
    p.require(len(ciphertext) > 16)
    return iv, ciphertext
