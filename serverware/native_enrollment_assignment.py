"""Independent, exact-packet native enrollment assignment foundation.

This is an explicit operator signing API, not a packet builder or native signer.
It authenticates an independently pinned dedicated authorizer and the digest of
the exact supplied packet bytes. It never parses those packet bytes as trusted
commands, admits their semantics, acquires a native session, or proves that a
runtime matches the assignment. Parsed immutable data is not runtime admission.
There is no key-file lookup, generated key, network call or one-use journal.
The existing enrollment v1 path is deliberately untouched.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import ipaddress
import os
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from serverware import workload_identity_issuer_bootstrap as shared
from serverware_agent_trust import _workload_signed_packet as packets


SCHEMA = "serverware.signedNativeEnrollmentAssignment/v1"
PAYLOAD_SCHEMA = "serverware.nativeEnrollmentAssignment/v1"
SIGNATURE_DOMAIN = b"serverware/native-enrollment-assignment/v1\x00"
MAX_BYTES = MAX_KEY_BYTES = MAX_PAYLOAD_BYTES = 16 * 1024
MAX_PACKET_BYTES = 512 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
MAX_INTERVAL_SECONDS = 300
MAX_EPOCH_SECONDS = min((1 << 53) - 1, ((1 << 63) - 1) // 1_000_000_000)
MAX_PROCESSING_NS = 30_000_000_000
clock = shared.clock
_FIELDS = frozenset({
    "apiVersion", "authorizerKeyId", "assignmentId", "releaseRecordSha256",
    "policyHash", "configurationSha256", "runtimeCaCertificateSha256",
    "runtimeCaSpkiSha256", "ingressLeafCertificateSha256", "clientTrustBundleSha256",
    "principalId", "workloadIssuerCertificateSha256", "workloadIssuerSpkiSha256",
    "clientCertificateSha256", "clientSpkiSha256", "ingressHost", "serverInstanceId",
    "proxyEndpoint", "packetSha256", "clientChallengeBase64url", "notBeforeUnixSeconds",
    "expiresAtUnixSeconds",
})
_DIGEST_FIELDS = (
    "authorizerKeyId", "releaseRecordSha256", "policyHash", "configurationSha256",
    "runtimeCaCertificateSha256", "runtimeCaSpkiSha256", "ingressLeafCertificateSha256",
    "clientTrustBundleSha256", "workloadIssuerCertificateSha256",
    "workloadIssuerSpkiSha256", "clientCertificateSha256", "clientSpkiSha256", "packetSha256",
)
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_SPIFFE_PATH = re.compile(r"[A-Za-z0-9._~!$&'()*+,;=:@%/-]*\Z")


class NativeEnrollmentAssignmentError(ValueError):
    pass


def _fail():
    raise NativeEnrollmentAssignmentError("native enrollment assignment is invalid")


def _construction_on_work(work):
    """Sample the existing real-clock 30-second profile on the supplied ledger."""
    return shared._construction_on_work(work)


class _Lifetime(shared._Budget):
    """Tightening-only real clocks; an ancestor cannot supply the current time."""

    def __init__(self, work, window, bound, ancestor):
        self.failed = False
        self.pid = os.getpid()
        original = clock._validate(window)
        narrowed = shared.windows._narrow(original, deadline_epoch_ns=original[3],
            maximum_lifetime_ns=MAX_PROCESSING_NS, maximum_clock_skew_ns=0)
        shared._integer(bound, original[4], 1)
        super().__init__(work, narrowed, min(bound, narrowed[4]), ancestor)

    def current(self):
        if self.failed or os.getpid() != self.pid:
            self.failed = True
            _fail()
        try:
            # The inherited implementation samples real epoch/monotonic clocks
            # on every call after its optional ancestor. Ancestor output cannot
            # replace those samples or renew their original deadline.
            return super().current()
        except BaseException:
            self.failed = True
            raise


@dataclass(frozen=True, slots=True, repr=False)
class _AssignmentMaterial:
    assignment_digest: str
    authorizer_key_id: str
    assignment_id: str
    release_record_sha256: str
    policy_hash: str
    configuration_sha256: str
    runtime_ca_certificate_sha256: str
    runtime_ca_spki_sha256: str
    ingress_leaf_certificate_sha256: str
    client_trust_bundle_sha256: str
    principal_id: str
    workload_issuer_certificate_sha256: str
    workload_issuer_spki_sha256: str
    client_certificate_sha256: str
    client_spki_sha256: str
    ingress_host: str
    server_instance_id: str
    proxy_endpoint: str
    packet_sha256: str
    client_challenge_base64url: str
    not_before_unix_seconds: int
    expires_at_unix_seconds: int
    window: tuple
    deadline_ns: int
    live: object


def _ascii(value, maximum):
    if (type(value) is not str or not 1 <= len(value) <= maximum
            or any(not 33 <= ord(character) <= 126 for character in value)):
        _fail()
    return value


def _digest(value):
    shared._digest(value)
    if value == "sha256:" + "0" * 64:
        _fail()
    return value


def _base64(value, size):
    if (type(value) is not str or len(value) != (size * 8 + 5) // 6
            or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None):
        _fail()
    raw = base64.b64decode(value + "=" * ((-len(value)) % 4), altchars=b"-_", validate=True)
    if (len(raw) != size
            or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value):
        _fail()
    return raw


def _identifier(value):
    raw = _base64(value, 32)
    if not any(raw):
        _fail()


def _dns(value):
    return (1 <= len(value) <= 253
        and all(_DNS_LABEL.fullmatch(label) is not None for label in value.split(".")))


def _ip_spelling(address):
    # Rust's IpAddr/SocketAddr canonical display retains dotted IPv4 in the
    # mapped-address suffix, unlike Python ipaddress's default hexadecimal tail.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return "::ffff:" + str(address.ipv4_mapped)
    return str(address)


def _host(value):
    _ascii(value, 253)
    if "%" in value:
        _fail()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if not _dns(value):
            _fail()
    else:
        if _ip_spelling(address) != value:
            _fail()


def _instance(value):
    _ascii(value, 256)
    if not value.startswith("spiffe://"):
        _fail()
    authority, separator, suffix = value[9:].partition("/")
    path = separator + suffix
    if not _dns(authority) or _SPIFFE_PATH.fullmatch(path) is None or "//" in path:
        _fail()
    # URL canonicalization removes literal and percent-encoded dot segments.
    # Refuse them rather than normalizing the independently signed identity.
    if any(re.sub(r"%2e", ".", segment, flags=re.IGNORECASE) in (".", "..")
            for segment in path.split("/")):
        _fail()


def _endpoint(value):
    _ascii(value, 64)
    if "%" in value:
        _fail()
    if value.startswith("["):
        host, separator, port_text = value[1:].partition("]:")
        if not separator:
            _fail()
        address = ipaddress.IPv6Address(host)
        spelling = "[" + _ip_spelling(address) + "]"
    else:
        host, separator, port_text = value.rpartition(":")
        if not separator:
            _fail()
        address = ipaddress.IPv4Address(host)
        spelling = str(address)
    if not port_text.isascii() or not port_text.isdecimal() or len(port_text) > 5:
        _fail()
    port = int(port_text)
    if not 1 <= port <= 65535 or value != spelling + ":" + str(port):
        _fail()
    selected = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    selected = address if selected is None else selected
    if (selected.is_unspecified or selected.is_multicast
            or selected == ipaddress.IPv4Address("255.255.255.255")):
        _fail()


def _preflight(originals, additional, work, *, producing=False):
    clock.evidence.capture._SharedLedger(work)
    shared._integer(additional, MAX_ORIGINAL_BYTES)
    total = MAX_BYTES if producing else 0
    for raw, maximum in originals:
        shared._raw(raw, maximum)
        total += len(raw)
    if additional + 16 * total + 256 * 1024 > min(MAX_ORIGINAL_BYTES,
            work.limits.max_input_bytes - work.metrics.input_bytes):
        _fail()


def _public_key(original, expected_pin, budget):
    _digest(expected_pin)
    if packets._digest(original, budget) != expected_pin:
        _fail()
    budget.charge(input_bytes=len(original))
    key = serialization.load_pem_public_key(original)
    budget.check()
    if (not isinstance(key, ed25519.Ed25519PublicKey)
            or key.public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo) != original):
        _fail()
    return key


def _payload(value, public, packet_bytes, budget):
    shared._object(value, _FIELDS)
    if value["apiVersion"] != PAYLOAD_SCHEMA:
        _fail()
    for field in _DIGEST_FIELDS:
        _digest(value[field])
    _identifier(value["assignmentId"])
    _identifier(value["clientChallengeBase64url"])
    _ascii(value["principalId"], 256)
    _host(value["ingressHost"])
    _instance(value["serverInstanceId"])
    _endpoint(value["proxyEndpoint"])
    issued = shared._integer(value["notBeforeUnixSeconds"], MAX_EPOCH_SECONDS, 1)
    expires = shared._integer(value["expiresAtUnixSeconds"], MAX_EPOCH_SECONDS, issued + 1)
    if expires - issued > MAX_INTERVAL_SECONDS:
        _fail()
    budget.interval(issued * 1_000_000_000, expires * 1_000_000_000)
    if (packets._digest(shared._spki(public, budget), budget) != value["authorizerKeyId"]
            or packets._digest(packet_bytes, budget) != value["packetSha256"]):
        _fail()
    budget.check()


def _admit(original, public, packet_bytes, budget):
    # The LF is part of the sole accepted envelope original, not the signed
    # message. Re-encoding below rejects extra LF, whitespace, duplicate keys,
    # escaped alternate spellings and any noncanonical UTF-8 representation.
    if not original.endswith(b"\n"):
        _fail()
    envelope = shared._decode(original[:-1], MAX_BYTES - 1, budget)
    shared._object(envelope, {"apiVersion", "assignment", "signatureBase64url"})
    if envelope["apiVersion"] != SCHEMA or type(envelope["assignment"]) is not dict:
        _fail()
    signature = _base64(envelope["signatureBase64url"], 64)
    value = envelope["assignment"]
    message = SIGNATURE_DOMAIN + packets._canonical(value, MAX_PAYLOAD_BYTES, budget)
    budget.charge(input_bytes=len(message), hashes=1)
    public.verify(signature, message)
    budget.check()
    _payload(value, public, packet_bytes, budget)
    digest = packets._digest(original, budget)
    budget.check()
    return _AssignmentMaterial(digest, value["authorizerKeyId"], value["assignmentId"],
        value["releaseRecordSha256"], value["policyHash"], value["configurationSha256"],
        value["runtimeCaCertificateSha256"], value["runtimeCaSpkiSha256"],
        value["ingressLeafCertificateSha256"], value["clientTrustBundleSha256"],
        value["principalId"], value["workloadIssuerCertificateSha256"],
        value["workloadIssuerSpkiSha256"], value["clientCertificateSha256"],
        value["clientSpkiSha256"], value["ingressHost"], value["serverInstanceId"],
        value["proxyEndpoint"], value["packetSha256"], value["clientChallengeBase64url"],
        value["notBeforeUnixSeconds"], value["expiresAtUnixSeconds"],
        budget.window, budget.bound, budget.current)


def _verify_on_work(*, assignment_bytes, authorizer_public_key_bytes,
        expected_authorizer_pem_sha256, packet_bytes, work, live_window,
        transport_deadline_ns, _current=None, _additional_original_bytes=0):
    """Verify exact originals, never a material object or a caller's current time."""
    try:
        _preflight(((assignment_bytes, MAX_BYTES), (authorizer_public_key_bytes, MAX_KEY_BYTES),
            (packet_bytes, MAX_PACKET_BYTES)), _additional_original_bytes, work)
        budget = _Lifetime(work, live_window, transport_deadline_ns, _current)
        public = _public_key(authorizer_public_key_bytes, expected_authorizer_pem_sha256, budget)
        return _admit(assignment_bytes, public, packet_bytes, budget)
    except NativeEnrollmentAssignmentError:
        raise
    except Exception:
        raise NativeEnrollmentAssignmentError("native enrollment assignment verification failed") from None


def _produce_on_work(*, payload_bytes, authorizer_private_key_bytes,
        authorizer_public_key_bytes, expected_authorizer_pem_sha256, packet_bytes,
        work, live_window, transport_deadline_ns, _current=None, _additional_original_bytes=0):
    """Explicitly authorize exactly these packet bytes with a dedicated key original.

    Payload input is canonical compact JSON without LF and already contains the
    actual packet digest. A mismatch is refused, never silently rewritten. The
    unencrypted canonical PKCS8 original is caller-owned: this API neither loads
    a key path nor promises to erase Python's immutable private-key copies.
    """
    try:
        _preflight(((payload_bytes, MAX_PAYLOAD_BYTES),
            (authorizer_private_key_bytes, MAX_KEY_BYTES),
            (authorizer_public_key_bytes, MAX_KEY_BYTES), (packet_bytes, MAX_PACKET_BYTES)),
            _additional_original_bytes, work, producing=True)
        budget = _Lifetime(work, live_window, transport_deadline_ns, _current)
        public = _public_key(authorizer_public_key_bytes, expected_authorizer_pem_sha256, budget)
        payload = shared._decode(payload_bytes, MAX_PAYLOAD_BYTES, budget)
        _payload(payload, public, packet_bytes, budget)
        budget.charge(input_bytes=len(authorizer_private_key_bytes))
        private = serialization.load_pem_private_key(authorizer_private_key_bytes, password=None)
        budget.check()
        if (not isinstance(private, ed25519.Ed25519PrivateKey)
                or private.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                    != authorizer_private_key_bytes
                or shared._spki(private.public_key(), budget) != shared._spki(public, budget)):
            _fail()
        message = SIGNATURE_DOMAIN + payload_bytes
        budget.charge(input_bytes=len(message), hashes=1)
        signature = private.sign(message)
        budget.check()
        original = packets._canonical({"apiVersion": SCHEMA, "assignment": payload,
            "signatureBase64url": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")},
            MAX_BYTES - 1, budget) + b"\n"
        _admit(original, public, packet_bytes, budget)
        budget.check()
        return original
    except NativeEnrollmentAssignmentError:
        raise
    except Exception:
        raise NativeEnrollmentAssignmentError("native enrollment assignment production failed") from None
