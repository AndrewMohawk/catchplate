"""Public-original workload CSR and direct-issuer verification.

No key generation, file publication, network or issuance permission lives here.
Local and server callers supply their existing budget; the server adapter meters
these same primitives against its inherited authority work and clock window.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, utils
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID
from . import _workload_identity as identity
from . import _workload_signed_packet as packets
from . import _workload_tls as tls
from ._workload_stream import Budget, WorkloadClientError
from .workload_transport import validate_mtls_identity


REQUEST_SCHEMA = "serverware.signedWorkloadIdentityRequest/v1"
PAYLOAD_SCHEMA = "serverware.workloadIdentityRequest/v1"
REQUEST_DOMAIN = PAYLOAD_SCHEMA.encode("ascii") + b"\x00"
MAX_REQUEST_BYTES = 64 * 1024
MAX_CERTIFICATE_BYTES = 64 * 1024
MAX_KEY_BYTES = 64 * 1024
MAX_CSR_BYTES = 16 * 1024
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_PAYLOAD_FIELDS = frozenset({
    "schema", "packetSha256", "packetSigningKeySha256", "principalId", "nonce",
    "issuerCertificateSha256", "issuerSpkiSha256", "subjectPublicKeyInfoSha256",
    "selectedSans", "issuedAtEpochMs", "expiresAtEpochMs", "csr",
})
_LEAF_EXTENSIONS = frozenset({
    ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE,
    ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER, ExtensionOID.SUBJECT_KEY_IDENTIFIER,
})
_CA_EXTENSIONS = frozenset({
    ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE,
    ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    ExtensionOID.SUBJECT_KEY_IDENTIFIER,
})


def _fail(message: str) -> None:
    raise WorkloadClientError(message)


def _digest(raw: bytes, budget=None) -> str:
    return packets._digest(raw, budget)


def _spki(key: object) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _extension(certificate: x509.Certificate, kind: type, *, critical: bool = False):
    try:
        value = certificate.extensions.get_extension_for_class(kind)
    except x509.ExtensionNotFound:
        _fail("workload certificate lacks a required extension")
    if critical and not value.critical:
        _fail("workload certificate constraints must be critical")
    return value.value


def _valid_now(certificate: x509.Certificate, budget: Budget) -> None:
    budget.check()
    now = (datetime.fromtimestamp(budget.current() / 1_000_000_000, timezone.utc)
        if hasattr(budget, "current") else datetime.now(timezone.utc))
    if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
        _fail("workload certificate is outside its original validity interval")
    budget.check()


def _issuer(raw: bytes, budget: Budget):
    packets._charge(budget, input_bytes=len(raw))
    _text, originals = tls._public_certificates(raw, budget, client=True)
    if len(originals) != 1:
        _fail("workload issuance requires exactly one independently pinned issuer")
    original = originals[0]
    certificate = original.certificate
    _valid_now(certificate, budget)
    constraints = _extension(certificate, x509.BasicConstraints, critical=True)
    usage = _extension(certificate, x509.KeyUsage, critical=True)
    if not constraints.ca or not usage.key_cert_sign:
        _fail("workload issuer is not authorized to sign certificates")
    if any(extension.oid not in _CA_EXTENSIONS for extension in certificate.extensions):
        _fail("workload issuer constraints need an unsupported path profile")
    try:
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        eku = None
    if eku is not None and ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
        _fail("workload issuer does not admit client authentication")
    key = certificate.public_key()
    if not (isinstance(key, ed25519.Ed25519PublicKey)
            or isinstance(key, ec.EllipticCurvePublicKey)
            and isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1))
            or isinstance(key, rsa.RSAPublicKey) and 3072 <= key.key_size <= 4096):
        _fail("workload issuer key is outside the direct-issuer profile")
    budget.check()
    return original


def _selected(value: object, selectors: dict[str, object]) -> dict[str, list[str]]:
    if type(value) is not dict or set(value) != {"dnsNames", "uris"}:
        _fail("selected workload SANs require the closed DNS/URI profile")
    selected = {}
    for name in ("dnsNames", "uris"):
        items = value[name]
        if (type(items) is not list or len(items) > 8
                or any(type(item) is not str or not 1 <= len(item) <= 2048 for item in items)
                or items != sorted(set(items))):
            _fail("selected workload SANs must be bounded, unique and sorted")
        selected[name] = list(items)
    if (not 1 <= sum(map(len, selected.values())) <= 8
            or sum(len(item.encode("utf-8")) for items in selected.values() for item in items) > 8192):
        _fail("selected workload SAN inventory exceeds its profile")
    shaped = {"verifiedByTrustedIngress": True}
    if selected["dnsNames"]:
        shaped["sanDnsNames"] = selected["dnsNames"]
    if selected["uris"]:
        shaped["sanUris"] = selected["uris"]
        for uri in selected["uris"]:
            identity._canonical_uri(uri)
    validate_mtls_identity(shaped)
    dns, uris = set(selected["dnsNames"]), set(selected["uris"])
    if (not dns <= set(selectors.get("sanDnsNames", ()))
            or not uris <= set(selectors.get("sanUris", ())) | set(selectors.get("sanSpiffeIds", ()))):
        _fail("selected workload identity was not permitted by the signed packet")
    for field, observed in (("sanDnsNames", dns), ("sanUris", uris),
            ("sanSpiffeIds", {uri for uri in uris if uri.startswith("spiffe://")})):
        if field in selectors and not observed.intersection(selectors[field]):
            _fail("selected workload identity omits a signed SAN constraint")
    return selected


def _names(selected: dict[str, list[str]]) -> list[x509.GeneralName]:
    return ([x509.DNSName(value) for value in selected["dnsNames"]]
        + [x509.UniformResourceIdentifier(value) for value in selected["uris"]])


def _request(raw: bytes, binding: dict, selectors: dict, budget: Budget):
    if not 1 <= len(raw) <= MAX_REQUEST_BYTES:
        _fail("workload identity request exceeds its original bound")
    envelope = packets._parse_packet(raw, budget)
    if (set(envelope) != {"schema", "payload", "signature"}
            or envelope["schema"] != REQUEST_SCHEMA
            or type(envelope["payload"]) is not dict
            or set(envelope["payload"]) != _PAYLOAD_FIELDS):
        _fail("workload identity request has an unsupported schema")
    payload = envelope["payload"]
    if payload["schema"] != PAYLOAD_SCHEMA or any(
            type(payload[name]) is not type(value) or payload[name] != value
            for name, value in binding.items()):
        _fail("workload identity request differs from its independently verified originals")
    if packets._canonical(envelope, MAX_REQUEST_BYTES, budget) != raw:
        _fail("workload identity request is not canonical")
    selected = _selected(payload["selectedSans"], selectors)
    wrapped = payload["csr"]
    if (type(wrapped) is not dict or set(wrapped) != {"pem", "sha256"}
            or type(wrapped["pem"]) is not str):
        _fail("workload request CSR wrapper is invalid")
    csr_raw = wrapped["pem"].encode("ascii")
    if not 1 <= len(csr_raw) <= MAX_CSR_BYTES or _digest(csr_raw, budget) != wrapped["sha256"]:
        _fail("workload CSR original differs from its signed digest")
    budget.check()
    packets._charge(budget, input_bytes=len(csr_raw), hashes=1)
    csr = x509.load_pem_x509_csr(csr_raw)
    budget.check()
    public = csr.public_key()
    if (not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1)
            or csr.subject != x509.Name([]) or len(csr.attributes) != 1
            or len(csr.extensions) != 1 or not csr.is_signature_valid
            or not isinstance(csr.signature_hash_algorithm, hashes.SHA256)
            or csr.public_bytes(serialization.Encoding.PEM) != csr_raw):
        _fail("workload CSR is not the genuine bounded P-256 request profile")
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    if not san.critical or list(san.value) != _names(selected):
        _fail("workload CSR SANs differ from the exact signed request")
    if payload["subjectPublicKeyInfoSha256"] != _digest(_spki(public), budget):
        _fail("workload CSR key differs from the signed request")
    encoded = envelope["signature"]
    prefix = "ecdsa-p256-sha256:"
    if type(encoded) is not str or not encoded.startswith(prefix) or len(encoded) > 128:
        _fail("workload request signature profile differs")
    spelling = encoded[len(prefix):]
    signature = base64.b64decode(spelling + "=" * (-len(spelling) % 4), altchars=b"-_", validate=True)
    r, s = utils.decode_dss_signature(signature)
    if (not 1 <= r < _P256_ORDER or not 1 <= s <= _P256_ORDER // 2
            or utils.encode_dss_signature(r, s) != signature
            or base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=") != spelling):
        _fail("workload request signature is not canonical P-256")
    budget.check()
    packets._charge(budget, hashes=1)
    public.verify(signature, REQUEST_DOMAIN + packets._canonical(payload, MAX_REQUEST_BYTES, budget),
        ec.ECDSA(hashes.SHA256()))
    budget.check()
    return selected, public


def _leaf(raw: bytes, issuer_certificate, selected: dict, public, binding: dict,
        selectors: dict, budget: Budget):
    packets._charge(budget, input_bytes=len(raw))
    _text, originals = tls._public_certificates(raw, budget, client=True)
    if len(originals) != 1:
        _fail("workload reply must contain exactly one directly issued leaf")
    original = originals[0]
    leaf, issuer = original.certificate, issuer_certificate.certificate
    _valid_now(leaf, budget)
    if (leaf.subject != x509.Name([]) or original.spki_der != _spki(public)
            or leaf.serial_number <= 0
            or any(extension.oid not in _LEAF_EXTENSIONS for extension in leaf.extensions)):
        _fail("workload leaf key, subject or extension profile differs")
    constraints = _extension(leaf, x509.BasicConstraints, critical=True)
    usage = _extension(leaf, x509.KeyUsage, critical=True)
    eku = _extension(leaf, x509.ExtendedKeyUsage)
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    if (constraints.ca or constraints.path_length is not None
            or not usage.digital_signature or usage.content_commitment or usage.key_encipherment
            or usage.data_encipherment or usage.key_agreement or usage.key_cert_sign or usage.crl_sign
            or list(eku) != [ExtendedKeyUsageOID.CLIENT_AUTH]
            or not sans.critical or list(sans.value) != _names(selected)):
        _fail("workload leaf identity or client-auth constraints differ")
    if (leaf.not_valid_before_utc < issuer.not_valid_before_utc
            or leaf.not_valid_after_utc > issuer.not_valid_after_utc
            or leaf.not_valid_before_utc.timestamp() * 1000 < binding["issuedAtEpochMs"]
            or leaf.not_valid_after_utc.timestamp() * 1000 > binding["expiresAtEpochMs"]):
        _fail("workload leaf validity exceeds the original requested authority")
    algorithm = leaf.signature_hash_algorithm
    if not (isinstance(issuer.public_key(), ed25519.Ed25519PublicKey) and algorithm is None
            or isinstance(algorithm, (hashes.SHA256, hashes.SHA384, hashes.SHA512))):
        _fail("workload leaf signature algorithm is outside the direct-issuer profile")
    budget.check()
    packets._charge(budget, hashes=1, input_bytes=len(raw))
    leaf.verify_directly_issued_by(issuer)
    budget.check()
    # Meter the actual two selector hashes, and the additional direct issuer
    # relationship/signature plus SPKI hash when that signed selector exists.
    packets._charge(budget, hashes=2, input_bytes=len(original.der) + len(original.spki_der))
    if "issuerSpkiSha256" in selectors:
        packets._charge(budget, hashes=2,
            input_bytes=len(original.der) + len(issuer_certificate.spki_der))
    identity.check_client_selectors((original, issuer_certificate), selectors, budget)
    _valid_now(leaf, budget)
    return original


@dataclass(frozen=True, slots=True, repr=False)
class _RequestOriginals:
    binding: dict
    selectors: dict
    issuer_certificate: object
    selected_sans: tuple
    public_key: object
    request_digest: str
    csr_digest: str
    subject_public_key_digest: str
    policy_hash: str
    runtime_manifest_digest: str


def verify_request_originals(*, packet_bytes, packet_signing_key_bytes,
        issuer_certificate_bytes, request_bytes, expected_principal, expected_nonce,
        budget):
    """Re-admit original signatures; returned data is not issuance authority."""
    packet = packets.verify_signed_workload_packet(packet_bytes, packet_signing_key_bytes,
        expected_principal=expected_principal, expected_nonce=expected_nonce, budget=budget)
    selectors = validate_mtls_identity(packet["identity"].get("mtls"))
    if "certificateSha256" in selectors or "spkiSha256" in selectors:
        _fail("workload issuance requires the fresh-key SAN profile")
    issuer = _issuer(issuer_certificate_bytes, budget)
    issuer_spki = _digest(issuer.spki_der, budget)
    if "issuerSpkiSha256" in selectors and selectors["issuerSpkiSha256"] != issuer_spki:
        _fail("workload independent issuer differs from the signed selector")
    binding = {"packetSha256": _digest(packet_bytes, budget),
        "packetSigningKeySha256": _digest(packet_signing_key_bytes, budget),
        "principalId": packet["principalId"], "nonce": packet["nonce"],
        "issuerCertificateSha256": _digest(issuer_certificate_bytes, budget),
        "issuerSpkiSha256": issuer_spki, "issuedAtEpochMs": packet["issuedAtEpochMs"],
        "expiresAtEpochMs": packet["expiresAtEpochMs"]}
    selected, public = _request(request_bytes, binding, selectors, budget)
    # Re-reading the bounded canonical request yields only the CSR digest. The
    # capability-bearing packet graph is neither returned nor retained.
    request = packets._parse_packet(request_bytes, budget)
    budget.check()
    return _RequestOriginals(binding, selectors, issuer,
        (tuple(selected["dnsNames"]), tuple(selected["uris"])), public,
        _digest(request_bytes, budget), request["payload"]["csr"]["sha256"],
        _digest(_spki(public), budget), packet["pinning"]["policyHash"],
        packet["pinning"]["runtimeManifestDigest"])


def verify_leaf_originals(*, certificate_bytes, packet_bytes, packet_signing_key_bytes,
        issuer_certificate_bytes, request_bytes, expected_principal, expected_nonce,
        budget):
    requested = verify_request_originals(packet_bytes=packet_bytes,
        packet_signing_key_bytes=packet_signing_key_bytes,
        issuer_certificate_bytes=issuer_certificate_bytes, request_bytes=request_bytes,
        expected_principal=expected_principal, expected_nonce=expected_nonce, budget=budget)
    selected = {"dnsNames": list(requested.selected_sans[0]),
        "uris": list(requested.selected_sans[1])}
    leaf = _leaf(certificate_bytes, requested.issuer_certificate, selected,
        requested.public_key, requested.binding, requested.selectors, budget)
    return requested, leaf
