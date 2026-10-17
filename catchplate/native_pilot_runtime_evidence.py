"""Authenticate an existing fleet startup receipt, never manufacture attestation.

The independently approved policy fragment is exact5: receiptOriginal,
generationTrustOriginal, generationTrustSha256, issuer {keyId,keySpkiSha256},
and instanceId. Originals are canonical ASCII, not paths. The trust pin and
issuer selection must come from independent approval, not the receipt itself.

This purpose-specific verifier authenticates Assignment/v2 and the existing
PolicyRuntimeAttestation/v2 signature, then selects exactly one signed fleet
member. It does not admit unrelated generation-trust purposes, verify a quote
or collateral, acquire a genuine receipt, or prove live custody/C9 ownership.
The resulting RuntimeIdentity is the fleet's approved commitment context;
neither its boot nor its instance is the custody driver/guest identity.
Full native generation/trust/attestation admission remains mandatory later.
"""
from __future__ import annotations

import copy
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import native_pilot_assignment as assignment
from catchplate import native_shadow_nitro_profile as p

MAX_TRUST = 2 * 1024 * 1024
MAX_RECEIPT = 65536
MAX_POLICY = MAX_TRUST + MAX_RECEIPT + 65536
RECEIPT_DOMAIN = "catchplate.policyRuntimeAttestation/v2"
FIELDS = ("receiptOriginal", "generationTrustOriginal", "generationTrustSha256", "issuer", "instanceId")
TRUST_FIELDS = ("apiVersion", "trustClass", "selfSigned", "manifestRevision", "issuedAtUnixNanos",
    "expiresAtUnixNanos", "revocationGeneration", "revocationRootSha256", "assignmentSigningKeyId",
    "assignmentSigningKeySpkiSha256", "startupAttestationSigningKeyId", "startupAttestationSigningKeySpkiSha256",
    "runtimeAttestationPolicySha256", "runtimeAttestationVerifierSigningKeyId",
    "runtimeAttestationVerifierSigningKeySpkiSha256", "webauthnVerificationPolicySha256",
    "webauthnVerifierSigningKeyId", "webauthnVerifierSigningKeySpkiSha256", "publicationSigningKeyId",
    "publicationSigningKeySpkiSha256", "publicationReplayStoreSha256", "compiler", "keys")
COMPILER_FIELDS = ("policyCompilerBinarySha256", "policyCompilerConfigurationSha256", "policySchemaSha256",
    "adapterSchemaSha256", "policySemanticModelSha256", "policyPlanSchemaSha256", "requestFactsSchemaSha256")
KEY_FIELDS = ("role", "signatureDomains", "keyId", "keySpkiSha256", "publicKeyPem",
    "notBeforeUnixNanos", "notAfterUnixNanos")
RECORD_FIELDS = ("fleetId", "membershipRevision", "memberOrdinal", "memberId", "instanceId", "bootIdSha256",
    "spiffeId", "teePlatform", "teeEvidenceSha256", "teeMeasurementSha256", "roleKeysDigest")
MEMBER_FIELDS = ("instanceId", "spiffeId", "bootIdSha256", "teePlatform", "teeMeasurementSha256",
    "teeAttestationKeyId", "teeAttestationKeySpkiSha256", "ingressSigningKeyId", "ingressSigningKeySpkiSha256",
    "activeDecisionSigningKeyId", "activeDecisionSigningKeySpkiSha256", "shadowSigningKeyId", "shadowSigningKeySpkiSha256")
KEY_PREFIXES = ("teeAttestation", "ingressSigning", "activeDecisionSigning", "shadowSigning")
PLATFORMS = ("aws-nitro-enclave", "amd-sev-snp", "intel-tdx")


def _original(text, maximum):
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= maximum)
    raw = text.encode("ascii")
    return raw, p.document(raw, maximum)


def _identifier(value, maximum=256):
    p.require(type(value) is str and 1 <= len(value) <= maximum
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@+\-]*", value))


def _spiffe(value):
    p.require(type(value) is str and value.isascii() and len(value) <= 2048 and value.startswith("spiffe://"))
    rest = value[9:]
    p.require("/" in rest)
    domain, path = rest.split("/", 1)
    p.require(1 <= len(domain) <= 253 and path)
    for label in domain.split("."):
        p.require(1 <= len(label) <= 63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label))
    for segment in path.split("/"):
        p.require(segment not in ("", ".", "..") and re.fullmatch(
            r"(?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-F]{2})+", segment))


def _interval(issued, expires, *, zero=False):
    p.integer(issued, minimum=0 if zero else 1); p.integer(expires)
    p.require(issued < expires)


def _trust(raw):
    trust = p.fields(p.document(raw, MAX_TRUST), TRUST_FIELDS)
    p.require(trust["apiVersion"] == "catchplate.policyShadowGenerationTrust/v1"
        and trust["trustClass"] in ("production-pinned", "development-pinned")
        and type(trust["selfSigned"]) is bool)
    # This does not promote development trust to production admission.
    p.integer(trust["manifestRevision"], maximum=p.MAX_U64)
    p.integer(trust["revocationGeneration"], maximum=p.MAX_U64)
    _interval(trust["issuedAtUnixNanos"], trust["expiresAtUnixNanos"], zero=True)
    p.require(trust["expiresAtUnixNanos"] - trust["issuedAtUnixNanos"] <= p.DAY_NS)
    for name in TRUST_FIELDS:
        if name.endswith(("Sha256", "KeyId")):
            p.digest(trust[name])
    for value in p.fields(trust["compiler"], COMPILER_FIELDS).values():
        p.digest(value)
    p.require(type(trust["keys"]) is list and 1 <= len(trust["keys"]) <= 2048)
    selected, previous, seen = {}, None, set()
    domains = {assignment.DOMAINS[2]: "assignment-authority", RECEIPT_DOMAIN: "runtime-attestation-authority"}
    for row in trust["keys"]:
        p.fields(row, KEY_FIELDS)
        _identifier(row["role"], 128)
        order = (row["role"], p.digest(row["keyId"]), p.digest(row["keySpkiSha256"]))
        p.require(previous is None or previous < order)
        previous = order
        p.require(type(row["signatureDomains"]) is list and 1 <= len(row["signatureDomains"]) <= 64
            and all(type(domain) is str and domain.startswith("catchplate.") and len(domain) <= 256
                and re.fullmatch(r"[A-Za-z0-9._:/\-]+", domain) for domain in row["signatureDomains"]))
        p.require(row["signatureDomains"] == sorted(set(row["signatureDomains"])))
        _interval(row["notBeforeUnixNanos"], row["notAfterUnixNanos"], zero=True)
        p.require(row["notBeforeUnixNanos"] <= trust["issuedAtUnixNanos"]
            and trust["expiresAtUnixNanos"] <= row["notAfterUnixNanos"])
        pem = row["publicKeyPem"]
        p.require(type(pem) is str and pem.isascii() and 0 < len(pem) <= 16384)
        public = serialization.load_pem_public_key(pem.encode("ascii"))
        p.require(isinstance(public, Ed25519PublicKey))
        spki = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        digest = p.sha(spki)
        p.require(row["keyId"] == row["keySpkiSha256"] == digest and digest not in seen)
        seen.add(digest)
        for domain in row["signatureDomains"]:
            if domain in domains:
                p.require(row["role"] == domains[domain])
                prefix = "assignment" if domain == assignment.DOMAINS[2] else "startupAttestation"
                if (row["keyId"] == trust[prefix + "SigningKeyId"]
                        and row["keySpkiSha256"] == trust[prefix + "SigningKeySpkiSha256"]):
                    p.require(domain not in selected)
                    selected[domain] = (row, public)
    p.require(set(selected) == set(domains))
    return trust, selected


def _envelope(value, domain, kind, selected):
    p.fields(value, assignment.FIELDS)
    row, public = selected
    p.require(value["apiVersion"] == value["signatureDomain"] == domain and value["kind"] == kind
        and value["canonicalProfile"] == "catchplate.canonicalJson/ascii-integer-v1"
        and value["signatureAlgorithm"] == "Ed25519" and value["signingKeyId"] == row["keyId"]
        and value["signingKeySpkiSha256"] == row["keySpkiSha256"]
        and p.digest(value["payloadSha256"]) == p.sha(p.canonical(value["payload"])))
    public.verify(p.decoded(value["signature"], size=64), p.preimage(domain, value["payload"]))
    return value["payload"]


def _checked(fragment):
    p.fields(fragment, FIELDS)
    p.require(len(p.canonical(fragment)) <= MAX_POLICY)
    _identifier(fragment["instanceId"], 128)
    issuer = p.fields(fragment["issuer"], ("keyId", "keySpkiSha256"))
    for value in issuer.values():
        p.digest(value)
    trust_raw, _ = _original(fragment["generationTrustOriginal"], MAX_TRUST)
    p.require(p.sha(trust_raw) == p.digest(fragment["generationTrustSha256"]))
    trust, selected = _trust(trust_raw)
    p.require(issuer == {"keyId": trust["startupAttestationSigningKeyId"],
        "keySpkiSha256": trust["startupAttestationSigningKeySpkiSha256"]})
    _, receipt = _original(fragment["receiptOriginal"], MAX_RECEIPT)
    payload = _envelope(receipt, RECEIPT_DOMAIN, "PolicyRuntimeAttestation", selected[RECEIPT_DOMAIN])
    p.fields(payload, ("issuedAtEpochNs", "expiresAtEpochNs", "record"))
    _interval(payload["issuedAtEpochNs"], payload["expiresAtEpochNs"])
    record = p.fields(payload["record"], RECORD_FIELDS)
    for name in ("fleetId", "memberId", "bootIdSha256", "teeEvidenceSha256", "teeMeasurementSha256", "roleKeysDigest"):
        p.digest(record[name])
    for name in ("membershipRevision", "memberOrdinal"):
        p.integer(record[name], maximum=p.MAX_U64)
    _identifier(record["instanceId"]); _spiffe(record["spiffeId"])
    p.require(record["instanceId"] == fragment["instanceId"] and record["teePlatform"] in PLATFORMS)
    return trust, selected, payload


def validate_policy(fragment):
    """Check closed pinned public inputs/signature, without clocks or authority."""
    _checked(fragment)
    return copy.deepcopy(fragment)


def _fleet(value, instance_id):
    p.fields(value, ("fleetId", "membershipRevision", "membershipRootSha256", "members"))
    p.digest(value["fleetId"]); p.integer(value["membershipRevision"], maximum=p.MAX_U64)
    members = value["members"]
    p.require(type(members) is list and 1 <= len(members) <= 4096)
    leaves, seen_instances, seen_spiffes, seen_ids, seen_spkis, selected = [], set(), set(), set(), set(), []
    for ordinal, member in enumerate(members, 1):
        p.fields(member, MEMBER_FIELDS)
        _identifier(member["instanceId"]); _spiffe(member["spiffeId"])
        p.require(member["teePlatform"] in PLATFORMS and member["instanceId"] not in seen_instances
            and member["spiffeId"] not in seen_spiffes)
        seen_instances.add(member["instanceId"]); seen_spiffes.add(member["spiffeId"])
        for name in MEMBER_FIELDS:
            if name.endswith(("Sha256", "KeyId")):
                p.digest(member[name])
        for prefix in KEY_PREFIXES:
            key_id, spki = member[prefix + "KeyId"], member[prefix + "KeySpkiSha256"]
            p.require(key_id not in seen_ids and spki not in seen_spkis)
            seen_ids.add(key_id); seen_spkis.add(spki)
        leaves.append(p.raw_digest(p.sha(b"catchplate.policyShadowMerkleLeaf/v1\0"
            + ordinal.to_bytes(8, "big") + p.raw_digest(p.sha(p.canonical(member))))))
        if member["instanceId"] == instance_id:
            selected.append((ordinal, member))
    while len(leaves) > 1:
        leaves = [p.raw_digest(p.sha(b"catchplate.policyShadowMerkleNode/v1\1" + leaves[i] + leaves[i + 1]))
            if i + 1 < len(leaves) else leaves[i] for i in range(0, len(leaves), 2)]
    p.require("sha256:" + leaves[0].hex() == p.digest(value["membershipRootSha256"]) and len(selected) == 1)
    return selected[0]


def runtime(fragment, *, assignment_original, issued_at_unix_ns, expires_at_unix_ns, now_unix_ns):
    """Derive exact RuntimeIdentity14 from authenticated fleet/receipt originals."""
    _interval(issued_at_unix_ns, expires_at_unix_ns)
    p.integer(now_unix_ns)
    p.require(issued_at_unix_ns <= now_unix_ns < expires_at_unix_ns)
    trust, selected, receipt = _checked(fragment)
    envelope = assignment.shape(p.document(assignment_original, assignment.MAX_BYTES))
    p.require(assignment.version(envelope) == 2)
    payload = _envelope(envelope, assignment.DOMAINS[2], "PolicyShadowAssignment", selected[assignment.DOMAINS[2]])
    for start, end in ((trust["issuedAtUnixNanos"], trust["expiresAtUnixNanos"]),
            (payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"]),
            (receipt["issuedAtEpochNs"], receipt["expiresAtEpochNs"])):
        _interval(start, end, zero=True)
        p.require(start <= issued_at_unix_ns < expires_at_unix_ns <= end)
    p.require(now_unix_ns - receipt["issuedAtEpochNs"] <= p.DAY_NS)
    ordinal, member = _fleet(payload["fleet"], fragment["instanceId"])
    record = receipt["record"]
    p.require(record["fleetId"] == payload["fleet"]["fleetId"]
        and record["membershipRevision"] == payload["fleet"]["membershipRevision"]
        and record["memberOrdinal"] == ordinal
        and record["memberId"] == p.sha(b"catchplate.policyShadowFleetMember/v1\0" + p.canonical(member)))
    for name in ("instanceId", "bootIdSha256", "spiffeId", "teePlatform", "teeMeasurementSha256"):
        p.require(record[name] == member[name])
    return copy.deepcopy(member) | {"teeEvidenceSha256": record["teeEvidenceSha256"]}
