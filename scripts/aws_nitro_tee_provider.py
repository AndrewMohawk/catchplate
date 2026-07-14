#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import cbor2
from cbor2 import CBORTag
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.x509.oid import NameOID


PROVIDER = "aws-nitro-enclaves"
TEE_PLATFORM = "aws-nitro"
COSE_ALG_ES384 = -35
USER_DATA_PREFIX = b"serverware:nitro-claims:v1:"
AUTHORIZED_MATERIALS = {"broker-kek", "decision-gate-ca"}
DEFAULT_FIXTURE_PCRS = {
    0: "11" * 48,
    1: "22" * 48,
    2: "33" * 48,
    8: "88" * 48,
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str, label: str = "base64url value") -> bytes:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except Exception as exc:
        raise SystemExit(f"{label} is invalid base64url") from exc


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def run_json_command(command: str, payload: dict[str, Any], label: str) -> dict[str, Any]:
    timeout = float(os.getenv("SERVERWARE_NITRO_KMS_TIMEOUT_SECONDS", "10"))
    result = subprocess.run(
        shlex.split(command),
        input=(canonical_json(payload) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace") or result.stdout.decode("utf-8", errors="replace")
        raise SystemExit(f"{label} failed with exit {result.returncode}: {detail.strip()}")
    try:
        response = json.loads(result.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{label} returned invalid JSON") from exc
    if not isinstance(response, dict):
        raise SystemExit(f"{label} must return a JSON object")
    return response


def read_stdin() -> dict[str, Any]:
    payload = json.loads(sys.stdin.read() or "{}")
    if not isinstance(payload, dict):
        raise SystemExit("stdin must be a JSON object")
    return payload


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def claims_user_data(claims: dict[str, Any]) -> bytes:
    digest = hashlib.sha256(canonical_json(claims).encode("utf-8")).hexdigest().encode("ascii")
    return USER_DATA_PREFIX + digest


def nitro_attestation_request_payload(claims: dict[str, Any]) -> dict[str, Any]:
    user_data = claims_user_data(claims)
    request = {
        "apiVersion": "serverware.nitroAttestationRequest/v1",
        "kind": "NitroAttestationDocument",
        "provider": PROVIDER,
        "tee_platform": TEE_PLATFORM,
        "claims": claims,
        "user_data_b64": b64e(user_data),
        "user_data_sha256": sha256_prefixed(user_data),
    }
    request["request_digest"] = sha256_prefixed(canonical_json(request).encode("utf-8"))
    return request


def attestation_document_from_command(command: str, claims: dict[str, Any]) -> bytes:
    request = nitro_attestation_request_payload(claims)
    response = run_json_command(command, request, "external Nitro attestation command")
    if response.get("ok") is not True:
        raise SystemExit(f"external Nitro attestation command denied quote generation: {response}")
    if response.get("request_digest") != request["request_digest"]:
        raise SystemExit("external Nitro attestation command response digest mismatch")
    if response.get("provider") and response.get("provider") not in {PROVIDER, "aws-nitro-nsm"}:
        raise SystemExit("external Nitro attestation command returned unexpected provider")
    if response.get("tee_platform") and response.get("tee_platform") != TEE_PLATFORM:
        raise SystemExit("external Nitro attestation command returned unexpected tee_platform")
    raw_b64 = response.get("attestation_document_b64") or response.get("raw_attestation_document_b64")
    if not isinstance(raw_b64, str) or not raw_b64:
        raise SystemExit("external Nitro attestation command missing attestation_document_b64")
    return b64d(raw_b64, "external Nitro attestation command attestation_document_b64")


def cert_not_before(cert: x509.Certificate) -> datetime:
    value = getattr(cert, "not_valid_before_utc", None)
    if value is not None:
        return value
    return cert.not_valid_before.replace(tzinfo=timezone.utc)


def cert_not_after(cert: x509.Certificate) -> datetime:
    value = getattr(cert, "not_valid_after_utc", None)
    if value is not None:
        return value
    return cert.not_valid_after.replace(tzinfo=timezone.utc)


def certificate_sha256(cert: x509.Certificate) -> str:
    return sha256_prefixed(cert.public_bytes(serialization.Encoding.DER))


def load_private_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_cert_pem(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def write_pem_private_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)


def write_pem_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(path, 0o644)


def cert_builder(subject: x509.Name, issuer: x509.Name, public_key: Any, *, ca: bool) -> x509.CertificateBuilder:
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=1 if ca else None), critical=True)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    return builder


def fixture_paths() -> dict[str, Path]:
    default_dir = Path(os.getenv("SERVERWARE_DATA_DIR", "/data")) / "nitro-fixture"
    base = Path(os.getenv("SERVERWARE_NITRO_FIXTURE_DIR", str(default_dir)))
    return {
        "dir": base,
        "root_key": base / "root.key.pem",
        "root_cert": base / "root.cert.pem",
        "intermediate_key": base / "intermediate.key.pem",
        "intermediate_cert": base / "intermediate.cert.pem",
        "leaf_key": base / "leaf.key.pem",
        "leaf_cert": base / "leaf.cert.pem",
        "recipient_key": base / "recipient.key.pem",
    }


def ensure_fixture_chain() -> tuple[Any, x509.Certificate, x509.Certificate, x509.Certificate]:
    paths = fixture_paths()
    paths["dir"].mkdir(parents=True, exist_ok=True)
    if all(paths[name].exists() for name in ("root_key", "root_cert", "intermediate_key", "intermediate_cert", "leaf_key", "leaf_cert")):
        return (
            load_private_key(paths["leaf_key"]),
            load_cert_pem(paths["leaf_cert"]),
            load_cert_pem(paths["intermediate_cert"]),
            load_cert_pem(paths["root_cert"]),
        )

    root_key = ec.generate_private_key(ec.SECP384R1())
    intermediate_key = ec.generate_private_key(ec.SECP384R1())
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    root_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "serverware.fixture.nitro-enclaves"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Serverware Fixture"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "TEE Test Root"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    intermediate_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "serverware.fixture.nitro-intermediate"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Serverware Fixture"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    leaf_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "serverware.fixture.nitro-attestation"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Serverware Fixture"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    root_cert = cert_builder(root_name, root_name, root_key.public_key(), ca=True).sign(root_key, hashes.SHA384())
    intermediate_cert = cert_builder(intermediate_name, root_name, intermediate_key.public_key(), ca=True).sign(
        root_key, hashes.SHA384()
    )
    leaf_cert = cert_builder(leaf_name, intermediate_name, leaf_key.public_key(), ca=False).sign(
        intermediate_key, hashes.SHA384()
    )
    write_pem_private_key(paths["root_key"], root_key)
    write_pem_private_key(paths["intermediate_key"], intermediate_key)
    write_pem_private_key(paths["leaf_key"], leaf_key)
    write_pem_cert(paths["root_cert"], root_cert)
    write_pem_cert(paths["intermediate_cert"], intermediate_cert)
    write_pem_cert(paths["leaf_cert"], leaf_cert)
    return leaf_key, leaf_cert, intermediate_cert, root_cert


def ensure_fixture_recipient_key() -> rsa.RSAPrivateKey:
    path = fixture_paths()["recipient_key"]
    if path.exists():
        key = load_private_key(path)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("fixture recipient key must be RSA")
        return key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    write_pem_private_key(path, key)
    return key


def parse_pcr_json(raw: str) -> dict[int, bytes]:
    if not raw.strip():
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("PCR policy must be a JSON object")
    result: dict[int, bytes] = {}
    for key, value in parsed.items():
        index = int(key)
        if not isinstance(value, str):
            raise ValueError(f"PCR{index} must be a hex string")
        try:
            decoded = bytes.fromhex(value.removeprefix("sha384:"))
        except ValueError as exc:
            raise ValueError(f"PCR{index} is not valid hex") from exc
        if len(decoded) != 48:
            raise ValueError(f"PCR{index} must be 48 bytes for SHA384")
        result[index] = decoded
    return result


def expected_pcrs() -> dict[int, bytes]:
    return parse_pcr_json(os.getenv("SERVERWARE_NITRO_EXPECTED_PCRS", ""))


def fixture_pcrs() -> dict[int, bytes]:
    raw = os.getenv("SERVERWARE_NITRO_FIXTURE_PCRS")
    if raw:
        return parse_pcr_json(raw)
    if env_bool("SERVERWARE_NITRO_FIXTURE_DEBUG"):
        return {index: b"\x00" * 48 for index in DEFAULT_FIXTURE_PCRS}
    return {index: bytes.fromhex(value) for index, value in DEFAULT_FIXTURE_PCRS.items()}


def encode_cose_es384_signature(der_signature: bytes) -> bytes:
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(48, "big") + s.to_bytes(48, "big")


def decode_cose_es384_signature(raw_signature: bytes) -> bytes:
    if len(raw_signature) != 96:
        raise ValueError("ES384 COSE signature must be 96 bytes")
    r = int.from_bytes(raw_signature[:48], "big")
    s = int.from_bytes(raw_signature[48:], "big")
    return encode_dss_signature(r, s)


def make_fixture_attestation_document(claims: dict[str, Any]) -> bytes:
    leaf_key, leaf_cert, intermediate_cert, root_cert = ensure_fixture_chain()
    recipient_key = ensure_fixture_recipient_key()
    payload = {
        "module_id": "serverware-nitro-fixture-module",
        "timestamp": int(time.time() * 1000),
        "digest": "SHA384",
        "pcrs": fixture_pcrs(),
        "certificate": leaf_cert.public_bytes(serialization.Encoding.DER),
        "cabundle": [
            root_cert.public_bytes(serialization.Encoding.DER),
            intermediate_cert.public_bytes(serialization.Encoding.DER),
        ],
        "public_key": recipient_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        "user_data": claims_user_data(claims),
    }
    if claims.get("nonce") is not None:
        payload["nonce"] = str(claims["nonce"]).encode("utf-8")[:1024]
    protected = cbor2.dumps({1: COSE_ALG_ES384})
    payload_bytes = cbor2.dumps(payload)
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload_bytes])
    signature = encode_cose_es384_signature(leaf_key.sign(sig_structure, ec.ECDSA(hashes.SHA384())))
    return cbor2.dumps(CBORTag(18, [protected, {}, payload_bytes, signature]))


def load_attestation_document_bytes(claims: dict[str, Any]) -> bytes | None:
    attestation_command = os.getenv("SERVERWARE_NITRO_ATTESTATION_COMMAND", "").strip()
    if attestation_command:
        return attestation_document_from_command(attestation_command, claims)
    if os.getenv("SERVERWARE_NITRO_ATTESTATION_DOCUMENT_B64"):
        return b64d(os.environ["SERVERWARE_NITRO_ATTESTATION_DOCUMENT_B64"])
    if os.getenv("SERVERWARE_NITRO_ATTESTATION_DOCUMENT"):
        return Path(os.environ["SERVERWARE_NITRO_ATTESTATION_DOCUMENT"]).read_bytes()
    return None


def parse_cose_sign1(raw: bytes) -> tuple[bytes, dict[str, Any], bytes, bytes]:
    value = cbor2.loads(raw)
    if isinstance(value, CBORTag):
        if value.tag != 18:
            raise ValueError("Nitro attestation must be a COSE_Sign1 tag 18 document")
        value = value.value
    if not isinstance(value, list) or len(value) != 4:
        raise ValueError("Nitro attestation COSE_Sign1 must be a four-item array")
    protected, unprotected, payload_bytes, signature = value
    if not isinstance(protected, bytes) or not isinstance(unprotected, dict):
        raise ValueError("Nitro attestation COSE headers are malformed")
    if not isinstance(payload_bytes, bytes) or not isinstance(signature, bytes):
        raise ValueError("Nitro attestation COSE payload/signature are malformed")
    protected_map = cbor2.loads(protected) if protected else {}
    if protected_map.get(1) != COSE_ALG_ES384:
        raise ValueError("Nitro attestation COSE algorithm must be ES384")
    payload = cbor2.loads(payload_bytes)
    if not isinstance(payload, dict):
        raise ValueError("Nitro attestation payload must be a CBOR map")
    return protected, payload, payload_bytes, signature


def load_trusted_root() -> x509.Certificate:
    root_pem = os.getenv("SERVERWARE_NITRO_ROOT_CERT_PEM")
    if root_pem:
        return x509.load_pem_x509_certificate(root_pem.encode("ascii"))
    root_path = os.getenv("SERVERWARE_NITRO_ROOT_CERT")
    if not root_path:
        fixture_root = fixture_paths()["root_cert"]
        if env_bool("SERVERWARE_NITRO_FIXTURE") and fixture_root.exists():
            root_path = str(fixture_root)
    if not root_path:
        raise ValueError("SERVERWARE_NITRO_ROOT_CERT or SERVERWARE_NITRO_ROOT_CERT_PEM is required")
    return load_cert_pem(Path(root_path))


def verify_cert_signature(issuer: x509.Certificate, child: x509.Certificate) -> None:
    if child.issuer != issuer.subject:
        raise ValueError("Nitro attestation certificate issuer/subject chain mismatch")
    public_key = issuer.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
    else:
        raise ValueError("unsupported Nitro attestation certificate key type")


def verify_certificate_chain(payload: dict[str, Any]) -> x509.Certificate:
    cert_der = payload.get("certificate")
    cabundle_der = payload.get("cabundle")
    if not isinstance(cert_der, bytes) or not isinstance(cabundle_der, list) or not cabundle_der:
        raise ValueError("Nitro attestation certificate or cabundle missing")
    leaf = x509.load_der_x509_certificate(cert_der)
    cabundle = [x509.load_der_x509_certificate(item) for item in cabundle_der if isinstance(item, bytes)]
    if len(cabundle) != len(cabundle_der):
        raise ValueError("Nitro attestation cabundle contains non-certificate entries")
    trusted_root = load_trusted_root()
    root = cabundle[0]
    if root.public_bytes(serialization.Encoding.DER) != trusted_root.public_bytes(serialization.Encoding.DER):
        raise ValueError("Nitro attestation root certificate is not the configured trust root")
    expected_root_hash = os.getenv("SERVERWARE_NITRO_ROOT_SHA256", "").strip()
    if expected_root_hash and certificate_sha256(root) != expected_root_hash:
        raise ValueError("Nitro attestation root certificate fingerprint mismatch")
    now = datetime.now(timezone.utc)
    for cert in [*cabundle, leaf]:
        if not (cert_not_before(cert) <= now <= cert_not_after(cert)):
            raise ValueError("Nitro attestation certificate is not currently valid")
    verify_cert_signature(root, root)
    chain = [*cabundle, leaf]
    for issuer, child in zip(chain, chain[1:]):
        verify_cert_signature(issuer, child)
    return leaf


def pcrs_from_payload(payload: dict[str, Any]) -> dict[int, bytes]:
    pcrs = payload.get("pcrs")
    if not isinstance(pcrs, dict) or not pcrs:
        raise ValueError("Nitro attestation PCR map is missing")
    normalized: dict[int, bytes] = {}
    for key, value in pcrs.items():
        index = int(key)
        if not isinstance(value, bytes) or len(value) != 48:
            raise ValueError(f"Nitro PCR{index} must be a 48-byte SHA384 value")
        normalized[index] = value
    return normalized


def pcrs_are_debug(pcrs: dict[int, bytes]) -> bool:
    return any(value == b"\x00" * len(value) for value in pcrs.values())


def verify_payload_semantics(payload: dict[str, Any], claims: dict[str, Any]) -> tuple[dict[int, bytes], bool]:
    for field in ("module_id", "timestamp", "digest", "pcrs", "certificate", "cabundle"):
        if field not in payload:
            raise ValueError(f"Nitro attestation payload missing {field}")
    if payload.get("digest") != "SHA384":
        raise ValueError("Nitro attestation digest must be SHA384")
    timestamp = payload["timestamp"]
    if not isinstance(timestamp, int):
        raise ValueError("Nitro attestation timestamp must be an integer")
    now_ms = int(time.time() * 1000)
    max_age_ms = int(float(os.getenv("SERVERWARE_NITRO_MAX_AGE_SECONDS", "300")) * 1000)
    skew_ms = int(float(os.getenv("SERVERWARE_NITRO_CLOCK_SKEW_SECONDS", "60")) * 1000)
    if timestamp < now_ms - max_age_ms:
        raise ValueError("Nitro attestation is stale")
    if timestamp > now_ms + skew_ms:
        raise ValueError("Nitro attestation timestamp is in the future")
    if payload.get("user_data") != claims_user_data(claims):
        raise ValueError("Nitro attestation user_data does not bind Serverware claims")
    pcrs = pcrs_from_payload(payload)
    debug = pcrs_are_debug(pcrs)
    if debug and not env_bool("SERVERWARE_NITRO_ALLOW_DEBUG"):
        raise ValueError("Nitro debug PCRs are not accepted")
    for index, expected in expected_pcrs().items():
        if pcrs.get(index) != expected:
            raise ValueError(f"Nitro PCR{index} does not match expected value")
    return pcrs, debug


def verify_nitro_document(raw: bytes, claims: dict[str, Any]) -> dict[str, Any]:
    protected, payload, payload_bytes, signature = parse_cose_sign1(raw)
    leaf = verify_certificate_chain(payload)
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload_bytes])
    public_key = leaf.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Nitro attestation leaf signing key must be elliptic-curve")
    try:
        public_key.verify(decode_cose_es384_signature(signature), sig_structure, ec.ECDSA(hashes.SHA384()))
    except InvalidSignature as exc:
        raise ValueError("Nitro attestation COSE signature verification failed") from exc
    pcrs, debug = verify_payload_semantics(payload, claims)
    root = x509.load_der_x509_certificate(payload["cabundle"][0])
    result = {
        "provider": PROVIDER,
        "tee_platform": TEE_PLATFORM,
        "verified": True,
        "debug": debug,
        "module_id": payload.get("module_id"),
        "timestamp": payload.get("timestamp"),
        "digest": payload.get("digest"),
        "pcrs": {str(index): value.hex() for index, value in sorted(pcrs.items())},
        "certificate_sha256": certificate_sha256(leaf),
        "root_sha256": certificate_sha256(root),
        "user_data_sha256": sha256_prefixed(payload["user_data"]),
    }
    recipient_public_key_der = payload.get("public_key")
    if recipient_public_key_der is not None:
        if not isinstance(recipient_public_key_der, bytes) or not 1 <= len(recipient_public_key_der) <= 1024:
            raise ValueError("Nitro attestation public_key must be 1-1024 bytes")
        try:
            recipient_public_key = serialization.load_der_public_key(recipient_public_key_der)
        except ValueError as exc:
            raise ValueError("Nitro attestation public_key is not valid DER") from exc
        if not isinstance(recipient_public_key, rsa.RSAPublicKey):
            raise ValueError("Nitro KMS recipient public_key must be RSA")
        numbers = recipient_public_key.public_numbers()
        if recipient_public_key.key_size < 2048 or recipient_public_key.key_size > 4096 or numbers.e != 65537:
            raise ValueError("Nitro KMS recipient RSA key must be 2048-4096 bits with exponent 65537")
        result.update(
            {
                "recipient_public_key_sha256": sha256_prefixed(recipient_public_key_der),
                "recipient_public_key_algorithm": "RSAES_OAEP_SHA_256",
                "recipient_public_key_bits": recipient_public_key.key_size,
            }
        )
    return result


def raw_quote_for_claims(claims: dict[str, Any]) -> bytes:
    raw = load_attestation_document_bytes(claims)
    if raw is not None:
        return raw
    if not env_bool("SERVERWARE_NITRO_FIXTURE"):
        raise SystemExit(
            "Nitro quote mode requires SERVERWARE_NITRO_ATTESTATION_DOCUMENT[_B64] or SERVERWARE_NITRO_FIXTURE=1"
        )
    return make_fixture_attestation_document(claims)


def quote() -> None:
    payload = read_stdin()
    claims = payload.get("claims")
    if not isinstance(claims, dict):
        raise SystemExit("quote input missing claims")
    raw = raw_quote_for_claims(claims)
    nitro = verify_nitro_document(raw, claims)
    document = {
        "version": 1,
        "provider": PROVIDER,
        "tee_platform": TEE_PLATFORM,
        "issued_at_ms": nitro["timestamp"],
        "debug": nitro["debug"],
        "claims": claims,
        "raw_attestation_document_b64": b64e(raw),
        "nitro": nitro,
    }
    print(canonical_json(document))


def verify() -> None:
    payload = read_stdin()
    quote_doc = (payload.get("attestation") or {}).get("quote") if "attestation" in payload else payload.get("quote")
    if not isinstance(quote_doc, dict):
        raise SystemExit("verify input missing quote")
    if quote_doc.get("provider") != PROVIDER:
        raise SystemExit("quote provider is not aws-nitro-enclaves")
    raw_b64 = quote_doc.get("raw_attestation_document_b64")
    claims = quote_doc.get("claims")
    if not isinstance(raw_b64, str) or not isinstance(claims, dict):
        raise SystemExit("Nitro quote missing raw attestation document or claims")
    raw = b64d(raw_b64, "Nitro quote raw_attestation_document_b64")
    nitro = verify_nitro_document(raw, claims)
    nitro["raw_attestation_document_b64"] = raw_b64
    nitro["raw_attestation_document_sha256"] = sha256_prefixed(raw)
    enriched_claims = json.loads(json.dumps(claims))
    enriched_claims["tee"] = nitro
    print(canonical_json({"ok": True, "provider": PROVIDER, "tee_platform": TEE_PLATFORM, "claims": enriched_claims, "nitro": nitro}))


def expected_field_checks(claims: dict[str, Any], expected: dict[str, Any]) -> None:
    checks = {
        "policy_bundle_digest": "policy_bundle_digest",
        "policy_sequence": "policy_sequence",
        "policy_high_water_digest": "policy_high_water_digest",
        "ca_intermediate_spki_sha256": "ca_intermediate_spki_sha256",
        "rollback_epoch": "rollback_epoch",
        "release_channel": "release_channel",
        "provenance_digest": "provenance_digest",
        "source_tree_digest": "source_tree_digest",
        "response_signing_key_id": "response_signing_key_id",
        "data_plane_binary_digest": "data_plane_binary_digest",
    }
    for expected_key, claim_key in checks.items():
        expected_value = expected.get(expected_key)
        if expected_value is not None and claims.get(claim_key) != expected_value:
            raise SystemExit(f"{claim_key} mismatch")


def kms_request_payload(
    *,
    material: str,
    claims: dict[str, Any],
    expected: dict[str, Any],
    tee: dict[str, Any],
    release_handle: str,
) -> dict[str, Any]:
    request = {
        "apiVersion": "serverware.nitroKmsReleaseRequest/v1",
        "kind": "NitroKmsMaterialRelease",
        "provider": PROVIDER,
        "tee_platform": TEE_PLATFORM,
        "material": material,
        "claims": claims,
        "expected": expected,
        "tee": tee,
        "release_handle": release_handle,
    }
    request["request_digest"] = sha256_prefixed(canonical_json(request).encode("utf-8"))
    return request


def reject_plaintext_material(value: Any, path: str = "$") -> None:
    denied_keys = {
        "plaintext",
        "secret",
        "private_key",
        "private_key_pem",
        "raw_material",
        "material_value",
        "unwrapped_key",
        "decrypted_key",
    }
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in denied_keys:
                raise SystemExit(f"external Nitro KMS release command returned plaintext material field {path}.{key}")
            reject_plaintext_material(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_plaintext_material(child, f"{path}[{index}]")


def invoke_kms_release_command(command: str, request: dict[str, Any]) -> dict[str, Any]:
    response = run_json_command(command, request, "external Nitro KMS release command")
    reject_plaintext_material(response)
    if response.get("ok") is not True:
        raise SystemExit(f"external Nitro KMS release command denied material release: {response}")
    if response.get("request_digest") != request["request_digest"]:
        raise SystemExit("external Nitro KMS release command response digest mismatch")
    response_material = response.get("material")
    if response_material is not None and response_material != request["material"]:
        raise SystemExit("external Nitro KMS release command returned the wrong material")
    if not response.get("provider"):
        raise SystemExit("external Nitro KMS release command must identify its provider")
    key_provider = response.get("key_provider")
    if not isinstance(key_provider, dict) or not key_provider.get("key_id"):
        raise SystemExit("external Nitro KMS release command must bind a key_provider.key_id")
    tee = request.get("tee") or {}
    if response.get("attestation_document_sha256") != tee.get("raw_attestation_document_sha256"):
        raise SystemExit("external Nitro KMS release command attestation document digest mismatch")
    if response.get("recipient_public_key_sha256") != tee.get("recipient_public_key_sha256"):
        raise SystemExit("external Nitro KMS release command recipient public key digest mismatch")
    recipient_ciphertext_b64 = response.get("recipient_ciphertext_b64")
    if not isinstance(recipient_ciphertext_b64, str) or not recipient_ciphertext_b64:
        raise SystemExit("external Nitro KMS release command must return recipient ciphertext")
    try:
        recipient_ciphertext = base64.b64decode(
            recipient_ciphertext_b64 + "=" * (-len(recipient_ciphertext_b64) % 4), validate=True
        )
    except Exception as exc:
        raise SystemExit("external Nitro KMS release command recipient ciphertext is invalid base64") from exc
    recipient_ciphertext_sha256 = sha256_prefixed(recipient_ciphertext)
    if response.get("recipient_ciphertext_sha256") != recipient_ciphertext_sha256:
        raise SystemExit("external Nitro KMS release command recipient ciphertext digest mismatch")
    if response.get("material_handle") != recipient_ciphertext_sha256:
        raise SystemExit("external Nitro KMS release command material handle mismatch")
    return response


def redacted_release_tee(tee: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(tee))
    copied.pop("raw_attestation_document_b64", None)
    return copied


def release() -> None:
    payload = read_stdin()
    claims = payload.get("claims") or {}
    expected = payload.get("expected") or {}
    if not isinstance(claims, dict) or not isinstance(expected, dict):
        raise SystemExit("release input must contain claims and expected objects")
    tee = claims.get("tee") or {}
    if not isinstance(tee, dict) or tee.get("provider") != PROVIDER or tee.get("verified") is not True:
        raise SystemExit("Nitro key release requires a verified aws-nitro-enclaves quote")
    if tee.get("debug") is True and not env_bool("SERVERWARE_NITRO_ALLOW_DEBUG_RELEASE"):
        raise SystemExit("Nitro debug quote is not accepted for material release")
    material = str(payload.get("material") or "")
    allowed = {
        item.strip()
        for item in os.getenv("SERVERWARE_NITRO_ALLOWED_MATERIALS", "broker-kek,decision-gate-ca").split(",")
        if item.strip()
    }
    if allowed != AUTHORIZED_MATERIALS:
        raise SystemExit("Nitro release policy allowed materials must be exactly broker-kek and decision-gate-ca")
    if material not in allowed:
        raise SystemExit(f"material {material} is not allowed by Nitro release policy")
    claim_materials = {
        str(item)
        for item in (claims.get("materials") or [])
        if isinstance(item, str)
    }
    if claim_materials != AUTHORIZED_MATERIALS:
        raise SystemExit("verified Nitro claims must authorize exactly broker-kek and decision-gate-ca")
    if material not in claim_materials:
        raise SystemExit(f"material {material} is not authorized by verified Nitro claims")
    expected_field_checks(claims, expected)
    for index, expected_pcr in expected_pcrs().items():
        if (tee.get("pcrs") or {}).get(str(index)) != expected_pcr.hex():
            raise SystemExit(f"PCR{index} missing from verified Nitro claims")

    kms_command = os.getenv("SERVERWARE_NITRO_KMS_RELEASE_COMMAND", "").strip()
    kms_required = env_bool("SERVERWARE_NITRO_REQUIRE_KMS_COMMAND")
    if kms_required and not kms_command:
        raise SystemExit("SERVERWARE_NITRO_KMS_RELEASE_COMMAND is required by release policy")
    release_handle = sha256_prefixed(canonical_json({"material": material, "claims": claims, "tee": tee}).encode("utf-8"))
    kms_request = None
    kms_release = None
    if kms_command:
        kms_request = kms_request_payload(
            material=material,
            claims=claims,
            expected=expected,
            tee=tee,
            release_handle=release_handle,
        )
        kms_release = invoke_kms_release_command(kms_command, kms_request)
    print(
        canonical_json(
            {
                "ok": True,
                "provider": "aws-nitro-kms-policy",
                "material": material,
                "release_handle": release_handle,
                "kms_command_configured": bool(kms_command),
                "kms_command_required": kms_required,
                "kms_request_digest": kms_request.get("request_digest") if kms_request else None,
                "kms_release": kms_release,
                "tee": redacted_release_tee(tee),
            }
        )
    )


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"quote", "verify", "release"}:
        raise SystemExit("usage: aws_nitro_tee_provider.py quote|verify|release")
    try:
        {"quote": quote, "verify": verify, "release": release}[sys.argv[1]]()
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
