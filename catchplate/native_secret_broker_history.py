"""Private historical KEK custody, selected only by native broker/v2.

Recipient private keys and unwrapped KEKs never leave this measured helper.
Provisioning establishes key custody, not permission to decrypt any material.
Only a genuine succession material-claim owner can consume a matching key use.
"""
import hmac
import os
import threading
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from catchplate import native_oauth_refresh as wire
from catchplate.native_kms_cms import unwrap_broker_kek

CONFIGURATION = "catchplate.nativeSecretBrokerConfiguration/v2"
CHANNEL = "catchplate.nativeHistoricalBrokerChannel/v1"
REQUEST = "catchplate.nativeHistoricalBrokerKmsRecipientRequest/v1"
MAX_CONFIGURATION = 256 * 1024
MAX_KEYS = 16
KEY_FIELDS = frozenset({"kmsKeyId", "ciphertextBlobSha256", "encryptionContext", "kekSha256", "secretKekId"})
CONFIGURATION_FIELDS = KEY_FIELDS | {"apiVersion", "kmsParentPort", "helperImage", "historicalKeys"}
REQUEST_FIELDS = KEY_FIELDS | {"apiVersion", "material", "configurationSha256", "recipientPublicKeySha256", "nonce", "deadlineBoottimeNs"}


def assignment(value):
    wire.require(type(value) is dict and set(value) == KEY_FIELDS)
    wire.text(value["kmsKeyId"], 2048)
    for name in ("ciphertextBlobSha256", "kekSha256"):
        wire.digest(value[name]); wire.require(value[name] != "sha256:" + "0" * 64)
    wire.require(value["secretKekId"] == "attested-memory-kek:" + value["kekSha256"][7:31])
    context = value["encryptionContext"]
    wire.require(type(context) is dict and len(context) <= 32 and len(wire.canonical(context)) <= 8192)
    for key, item in context.items():
        wire.text(key, 1024); wire.text(item, 1024)
    return value


def configuration(raw):
    value = wire.document(raw, MAX_CONFIGURATION)
    wire.require(set(value) == CONFIGURATION_FIELDS and value["apiVersion"] == CONFIGURATION
        and type(value["kmsParentPort"]) is int and 1023 < value["kmsParentPort"] < 2**32 - 1)
    assignment({name: value[name] for name in KEY_FIELDS})
    image = value["helperImage"]
    wire.require(type(image) is dict and set(image) == {"profile", "imagePath", "imageSha256", "interpreterSha256", "helperSha256"}
        and image["profile"] == "sealed-memfd-squashfs-v1" and image["imagePath"] == "/opt/catchplate/native-broker-runtime.squashfs")
    for name in ("imageSha256", "interpreterSha256", "helperSha256"):
        wire.digest(image[name]); wire.require(image[name] != "sha256:" + "0" * 64)
    entries = value["historicalKeys"]
    wire.require(type(entries) is list and len(entries) <= MAX_KEYS)
    digests, ids = [], {value["secretKekId"]}
    for item in entries:
        assignment(item)
        wire.require(item["secretKekId"] not in ids and item["kekSha256"] != value["kekSha256"])
        ids.add(item["secretKekId"]); digests.append(item["kekSha256"])
    wire.require(digests == sorted(set(digests)))
    return value


class HistoricalKeys:
    """One finite inventory in the actual inherited broker channel/lifetime."""
    def __init__(self, broker, value):
        wire.require(type(value) is dict and set(value) == {"apiVersion", "phase", "configurationOriginal", "deadlineBoottimeNs"}
            and value["apiVersion"] == CHANNEL and value["phase"] == "initialize"
            and broker.kek is not None and broker.rsa is None and not broker.service_tokens_opened and not broker.operations)
        self.original = wire.decoded(value["configurationOriginal"], MAX_CONFIGURATION)
        self.configuration = configuration(self.original)
        wire.require(broker.historical_configuration_pin == wire.sha(self.original)
            and self.configuration["kekSha256"] == broker.commitment
            and self.configuration["secretKekId"] == broker.key_id
            and type(value["deadlineBoottimeNs"]) is int and value["deadlineBoottimeNs"] == broker.channel.deadline)
        self.broker, self.deadline = broker, value["deadlineBoottimeNs"]
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.digest = wire.sha(self.original)
        self.keys, self.next, self.pending, self.finished, self.poisoned = {}, 0, None, False, False
        self.material_uses = set()
        self.check()
        broker.channel.send({"apiVersion": CHANNEL, "phase": "initialized", "configurationSha256": self.digest})

    def __copy__(self):
        raise ValueError("historical key custody cannot be copied")

    def __deepcopy__(self, memo):
        raise ValueError("historical key custody cannot be copied")

    def check(self):
        wire.require(not self.poisoned and (os.getpid(), threading.get_ident()) == (self.pid, self.thread)
            and wire.canonical(self.configuration) == self.original and wire.sha(self.original) == self.digest
            and self.broker.channel.deadline == self.deadline
            and time.clock_gettime_ns(time.CLOCK_BOOTTIME) < self.deadline)
        self.broker.channel.check(self.deadline)

    def handle(self, value):
        try:
            self.check()
            wire.require(type(value) is dict and value.get("apiVersion") == CHANNEL and not self.finished
                and not self.broker.service_tokens_opened and not self.broker.operations)
            if value.get("phase") == "recipient":
                wire.require(set(value) == {"apiVersion", "phase", "index", "configurationSha256"}
                    and type(value["index"]) is int and value["index"] == self.next
                    and value["configurationSha256"] == self.digest and self.pending is None
                    and self.next < len(self.configuration["historicalKeys"]))
                item = self.configuration["historicalKeys"][self.next]
                private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                self.check()
                public = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                nonce = os.urandom(32)
                self.pending = (private, public, nonce, wire.canonical(item))
                self.broker.channel.send({"apiVersion": CHANNEL, "phase": "recipient", "index": self.next,
                    "configurationSha256": self.digest, "assignmentSha256": wire.sha(wire.canonical(item)),
                    "recipientPublicKey": wire.encoded(public), "recipientPublicKeySha256": wire.sha(public), "nonce": wire.encoded(nonce)})
            elif value.get("phase") == "provision":
                wire.require(set(value) == {"apiVersion", "phase", "index", "requestOriginal", "ciphertextForRecipient", "ciphertextSha256"}
                    and type(value["index"]) is int and value["index"] == self.next and self.pending is not None)
                private, public, nonce, item_raw = self.pending
                self.pending = None  # The attempt is consumed even if CMS/key admission fails.
                item = self.configuration["historicalKeys"][self.next]
                wire.require(wire.canonical(item) == item_raw)
                raw = wire.decoded(value["requestOriginal"], 32768)
                request = wire.document(raw, 32768)
                wire.require(set(request) == REQUEST_FIELDS and request["apiVersion"] == REQUEST
                    and request["material"] == "historical-broker-kek" and request["configurationSha256"] == self.digest
                    and all(request[name] == item[name] for name in KEY_FIELDS)
                    and request["recipientPublicKeySha256"] == wire.sha(public)
                    and wire.decoded(request["nonce"], 32, 32) == nonce
                    and type(request["deadlineBoottimeNs"]) is int and request["deadlineBoottimeNs"] == self.deadline)
                cms = wire.decoded(value["ciphertextForRecipient"], 65536)
                wire.require(wire.sha(cms) == value["ciphertextSha256"])
                self.check(); key = unwrap_broker_kek(cms, private); private = None
                wire.require(hmac.compare_digest(wire.sha(key), item["kekSha256"]))
                self.keys[item["secretKekId"]] = (item["kekSha256"], AESGCM(key))
                key = None
                self.next += 1; self.check()
                self.broker.channel.send({"apiVersion": CHANNEL, "phase": "provisioned", "index": value["index"],
                    "configurationSha256": self.digest, "requestSha256": wire.sha(raw)})
            else:
                wire.require(set(value) == {"apiVersion", "phase", "configurationSha256"} and value["phase"] == "finish"
                    and value["configurationSha256"] == self.digest and self.pending is None
                    and self.next == len(self.configuration["historicalKeys"]) == len(self.keys))
                self.finished = True; self.check()
                self.broker.channel.send({"apiVersion": CHANNEL, "phase": "finished", "configurationSha256": self.digest,
                    "keyCount": self.next})
        except BaseException:
            self.poisoned = True; self.pending = None; self.keys.clear()
            raise

    def claim_keys(self, claim):
        # No caller-selected descriptor, key identifier or arbitrary decrypt
        # method is accepted. The actual signed claim owner supplies both
        # matched originals and is consumed once before plaintext is opened.
        from catchplate.native_oauth_succession_materials import ClaimedMaterial
        wire.require(type(claim) is ClaimedMaterial and self.finished and claim.broker is self.broker
            and claim.owner.broker.historical_keys is self)
        self.check(); claim.check()
        marker = (claim.authorization_id, claim.material_id)
        wire.require(marker not in self.material_uses)
        self.material_uses.add(marker)
        def selected(identifier):
            if identifier == self.broker.key_id:
                wire.require(self.configuration["secretKekId"] == identifier
                    and self.configuration["kekSha256"] == self.broker.commitment)
                return self.broker.kek
            admitted = self.keys.get(identifier)
            matches = [item for item in self.configuration["historicalKeys"] if item["secretKekId"] == identifier]
            wire.require(admitted is not None and len(matches) == 1 and admitted[0] == matches[0]["kekSha256"])
            return admitted[1]
        token = selected(claim.token_envelope["secret_kek_id"])
        application = selected(claim.application_material["secretKekId"])
        self.check(); claim.check()
        return token, application
