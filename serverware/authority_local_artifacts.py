"""Fixed trusted-host-local package signatures and verification receipt.

The protected approval delegates only the exact unsigned package and trust
originals. Existing snapshot, selected closure/roster, provenance, migration, key and
witness originals remain independently authenticated prerequisites. This module
does not issue those originals, commit trust high-water, or install anything.
Python-held signing keys are ordinary colocated custody, not hardware custody.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import time
from datetime import datetime, timezone

from scripts.authority import atomic_provisioner_contract as contract
from scripts.authority import native_pilot_authority_io as io
from serverware import authority_artifact_spec as spec
from serverware import authority_local_artifact_measure as measure
from serverware.authority_launcher import _boot_identity_digest

APPROVAL_SCHEMA = "serverware.authorityTrustedHostLocalArtifactApproval/v1"
PURPOSE = "sign-and-verify-exact-trusted-host-local-artifact-package"
MAX_APPROVAL = 8192
OUTPUTS = ("package.json", "verification.json")
KEY_PURPOSES = ("artifact-bundle", "generation", "artifact-verifier")
FIELDS = frozenset({"schema", "purpose", "unsignedPackageSha256", "trustStateSha256",
                    "signingKeys", "verifierIdentity", "verifierSourceSha256", "verificationValidUntil",
                    "outputDirectory", "bootIdDigest", "issuedAtBoottimeNs", "deadlineBoottimeNs",
                    "issuedAtUnixNanos", "expiresAtUnixNanos"})


def _require(value):
    if not value:
        raise ValueError("local artifact signing refused")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def document(raw, maximum):
    _require(type(raw) is bytes and 0 < len(raw) <= maximum)
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result)
            result[key] = value
        return result
    def invalid(_value):
        raise ValueError("noncanonical artifact number")
    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
                       parse_float=invalid, parse_constant=invalid)
    _require(isinstance(value, dict) and spec.canonical_json_bytes(value) == raw)
    return value


def approval(value, *, unsigned_sha256, trust_sha256, boot, now_boot, now_unix):
    """Closed independent selection; no package-signing authority inferred."""
    _require(isinstance(value, dict) and set(value) == FIELDS
             and value["schema"] == APPROVAL_SCHEMA and value["purpose"] == PURPOSE
             and value["unsignedPackageSha256"] == unsigned_sha256
             and value["trustStateSha256"] == trust_sha256 and value["bootIdDigest"] == boot)
    for name in ("unsignedPackageSha256", "trustStateSha256", "bootIdDigest", "verifierSourceSha256"):
        spec._require_digest(value[name], name=name)
    keys = value["signingKeys"]
    _require(isinstance(keys, dict) and set(keys) == set(KEY_PURPOSES))
    for key in keys.values():
        spec._require_identifier(key, name="selected signer")
    spec._require_identifier(value["verifierIdentity"], name="verifier identity")
    directory = value["outputDirectory"]
    _require(isinstance(directory, dict) and set(directory) == {"device", "inode"})
    for name, minimum in (("device", 0), ("inode", 1)):
        _require(type(directory[name]) is int and minimum <= directory[name] < 2**64)
    for name in ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"):
        _require(type(value[name]) is int and 0 < value[name] < 2**64)
    _require(value["issuedAtBoottimeNs"] <= now_boot < value["deadlineBoottimeNs"]
             and value["issuedAtUnixNanos"] <= now_unix < value["expiresAtUnixNanos"])
    valid_until = spec._require_timestamp(value["verificationValidUntil"], name="receipt expiry")
    expiry_ns = int(valid_until.timestamp()) * 1_000_000_000
    _require(now_unix < expiry_ns <= value["expiresAtUnixNanos"])
    return value


def _key(keys, revoked, key_id, purpose, instant):
    key = keys.get(key_id)
    _require(key is not None and purpose in key.purposes and key_id not in revoked
             and key.not_before <= instant <= key.not_after)
    return key


def authenticate_upstream(unsigned, trust, instant):
    """Verify every existing upstream signature before private key access.

    The existing full package verifier additionally performs all generation and
    replay joins once the two actual package signatures have been produced.
    """
    spec.validate_unsigned_artifact_package(unsigned)
    bundle, generation = unsigned["bundle"], unsigned["generation"]
    _require(bundle["trustMode"] == {"mode": "trusted-host-local", "hardwareBacked": False,
             "externalWitnessRequired": False, "teeQuoteRequired": False, "imaAppraisalRequired": False}
             and bundle["stageZero"]["interfaceSchema"] == spec.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA
             and generation["validFrom"] <= instant <= generation["validUntil"])
    state = spec.validate_trust_state(trust)
    keys, revoked = spec._verify_key_documents(unsigned["trustMaterial"], bundle=bundle,
        generation=generation, trust_state=state, validation_time=instant)
    for field, purpose, domain in (
            ("stableSnapshotReceipt", "stable-snapshot-verifier", "serverware.authorityStableSnapshotReceiptSignature/v1"),
            ("closureReceipt", "closure-verifier", spec.closure_signature_domain(bundle["closureReceipt"]))):
        row = bundle[field]
        _require(row["payload"]["createdAt"] <= instant <= row["payload"]["expiresAt"])
        key = _key(keys, revoked, row["signerKeyId"], purpose, instant)
        spec.verify_ed25519_signature(key.public_key, row["signatureBase64Url"],
            spec._signature_message(domain, row["payload"]), name=field)
    provenance = bundle["provenance"]
    key = _key(keys, revoked, provenance["signerKeyId"], "provenance", instant)
    payload = {name: provenance[name] for name in ("path", "sha256", "predicateType", "mediaType",
        "builderId", "sourceRevision", "sourceCommitDigest", "sourceTreeDigest", "ociRootDigest", "statementDigest")}
    spec.verify_ed25519_signature(key.public_key, provenance["signatureBase64Url"],
        spec._signature_message(spec.PROVENANCE_SIGNATURE_DOMAIN, payload), name="provenance")
    for row in bundle["migrations"]:
        key = _key(keys, revoked, row["receiptSignerKeyId"], "migration-receipt", instant)
        _require(row["receiptPayload"]["signerIdentityDigest"] == spec.domain_digest(
            spec.authority_contract.MIGRATION_SIGNER_IDENTITY_DOMAIN, key.public_key))
        spec.verify_ed25519_signature(key.public_key, row["receiptSignatureBase64Url"],
            spec._signature_message(spec.authority_contract.MIGRATION_RECEIPT_SIGNATURE_DOMAIN,
                                    row["receiptPayload"]), name="migration")
    checkpoint = generation["witnessCheckpoint"]
    witness = state["witness"]
    _require(checkpoint["signerKeyId"] == witness["keyId"]
             and checkpoint["payload"]["identity"] == witness["identity"]
             and checkpoint["payload"]["issuedAt"] <= instant)
    spec.verify_ed25519_signature(witness["publicKey"], checkpoint["signatureBase64Url"],
        spec._signature_message(spec.WITNESS_CHECKPOINT_SIGNATURE_DOMAIN, checkpoint["payload"]),
        name="artifact witness checkpoint")
    return keys, revoked


def _receipt(verified, selected, *, policy_digest, instant, signer):
    package = verified.package
    bundle, generation = package["bundle"], package["generation"]
    signatures = []
    for row in package["signatures"]:
        key = verified.require_key(row["keyId"], row["purpose"], at=instant)
        signatures.append(dict(purpose=row["purpose"], keyId=row["keyId"], algorithm="Ed25519",
            messageDigest=spec.domain_digest("serverware.authoritySignatureMessageDigest/v1",
                spec.package_signature_message(row["purpose"], bundle, generation)),
            signatureDigest=spec.domain_digest("serverware.authoritySignatureBytesDigest/v1",
                spec.strict_base64url_decode(row["signatureBase64Url"], name="signature", decoded_size=64)),
            authorizationDigest=key.authorization_digest,
            revocationCheckpointDigest=verified.key_revocations_digest))
    checkpoint = generation["witnessCheckpoint"]
    key = verified.require_key(selected["signingKeys"]["artifact-verifier"], "artifact-verifier", at=instant)
    local_roster = bundle["closureReceipt"]["schema"] == spec.LOCAL_CLOSURE_RECEIPT_SCHEMA
    receipt = dict(schema=contract.VERIFICATION_RECEIPT_SCHEMA,
        packageDigest=verified.package_digest, artifactBundleDigest=verified.artifact_bundle_digest,
        generationDigest=verified.generation_digest, generationSequence=verified.generation_sequence,
        minimumRollbackSequence=verified.minimum_rollback_sequence, trustMode="trusted-host-local",
        verifiedSignatures=signatures,
        stageZeroVerification=dict(artifactDigest=bundle["stageZero"]["sha256"],
            interfaceSchema=spec.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA,
            interpreterDigest=bundle["stageZero"]["interpreter"]["sha256"],
            interpreterRuntimePath=bundle["stageZero"]["interpreter"]["runtimePath"],
            verifierDigest=selected["verifierSourceSha256"]),
        closureVerification=dict(fileCount=len(bundle["files"]), pythonImportCount=len(bundle["pythonImportClosure"]),
            nativeExecutableCount=len(bundle["nativeClosure"]["executables"]),
            nativeObjectCount=len(bundle["nativeClosure"]["objects"]),
            snapshotIdentityDigest=bundle["sourceTree"]["snapshotIdentityDigest"], complete=not local_roster,
            verifierDigest=selected["verifierSourceSha256"],
            **({"assurance": spec.LOCAL_CLOSURE_ASSURANCE} if local_roster else {})),
        rollbackWitness=dict(identity=checkpoint["payload"]["identity"], sequence=verified.generation_sequence,
            generationDigest=verified.generation_digest, checkpointDigest=verified.witness_checkpoint_digest,
            coLocated=True, hardwareBacked=False,
            signatureDigest=spec.domain_digest("serverware.authoritySignatureBytesDigest/v1",
                spec.strict_base64url_decode(checkpoint["signatureBase64Url"], name="witness signature", decoded_size=64))),
        verifierIdentity=selected["verifierIdentity"], verificationPolicyDigest=policy_digest,
        verifiedAt=instant, validUntil=selected["verificationValidUntil"],
        receiptSignerKeyId=key.key_id, receiptSignerAuthorizationDigest=key.authorization_digest,
        receiptSignatureAlgorithm="Ed25519", receiptSignatureBase64Url="")
    receipt["receiptSignatureBase64Url"] = spec.strict_base64url_encode(
        signer.sign(contract.verification_receipt_signature_message(receipt)))
    contract.verify_verification_receipt(receipt, verified_package=verified,
        validation_time=instant, accepted_receipt_digests=[])
    return receipt


def publish(directory_fd, name, raw, *, check):
    """Complete file visibility; no overwrite, rollback, or automatic retry."""
    _require(name in OUTPUTS and type(raw) is bytes and 0 < len(raw) <= io.MAX_PUBLIC)
    temporary = "." + name + ".pending"
    check()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                 0o600, dir_fd=directory_fd)
    try:
        offset = 0
        while offset < len(raw):
            check()
            count = os.write(fd, memoryview(raw)[offset:offset + 65536])
            _require(count > 0)
            offset += count
        os.fchmod(fd, 0o400)
        os.fsync(fd)
        check()
        os.link(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
        os.fsync(directory_fd)
        os.unlink(temporary, dir_fd=directory_fd)
        os.fsync(directory_fd)
        check()
    finally:
        os.close(fd)


def produce(*, unsigned_fd, unsigned_sha256, trust_fd, trust_sha256,
            approval_fd, approval_sha256, source_root_fd, output_directory_fd,
            artifact_bundle_key_fd, generation_key_fd, verifier_key_fd):
    """Borrow supplied FDs for one fixed local issuance; retain partial files."""
    io._process()
    descriptors = (unsigned_fd, trust_fd, approval_fd, source_root_fd, output_directory_fd,
                   artifact_bundle_key_fd, generation_key_fd, verifier_key_fd)
    _require(all(type(fd) is int and fd >= 3 for fd in descriptors)
             and len(set(descriptors[:5])) == 5 and not set(descriptors[:5]) & set(descriptors[5:]))
    public = []
    values = []
    for fd, expected, maximum in ((unsigned_fd, unsigned_sha256, io.MAX_PUBLIC),
            (trust_fd, trust_sha256, io.MAX_PUBLIC), (approval_fd, approval_sha256, MAX_APPROVAL)):
        raw = io.read_public(fd, maximum)
        _require(sha(raw) == expected)
        public.append((fd, io._input(fd, maximum), maximum, raw))
        values.append(document(raw, maximum))
    unsigned, trust, selected = values
    boot = _boot_identity_digest()
    original_pid = os.getpid()
    previous = [time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()]
    approval(selected, unsigned_sha256=unsigned_sha256, trust_sha256=trust_sha256,
             boot=boot, now_boot=previous[0], now_unix=previous[1])
    source_info = os.fstat(source_root_fd)
    output_info = os.fstat(output_directory_fd)
    _require(stat.S_ISDIR(output_info.st_mode) and output_info.st_uid == output_info.st_gid == 0
             and stat.S_IMODE(output_info.st_mode) == 0o700
             and selected["outputDirectory"] == dict(device=output_info.st_dev, inode=output_info.st_ino)
             and (source_info.st_dev, source_info.st_ino) != (output_info.st_dev, output_info.st_ino))
    with os.scandir(output_directory_fd) as entries:
        _require(next(entries, None) is None)
    code_raw = Path(__file__).read_bytes()
    _require(len(code_raw) <= 1024 * 1024 and sha(code_raw) == selected["verifierSourceSha256"])
    key_fds = (artifact_bundle_key_fd, generation_key_fd, verifier_key_fd)
    key_stamps = [io._input(fd, 32, private=True) for fd in key_fds]
    identities = [(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in descriptors]
    _require(len(set(identities[:5])) == 5 and not set(identities[:5]) & set(identities[5:]))

    def check():
        io._process()
        _require(os.getpid() == original_pid and _boot_identity_digest() == boot)
        now = [time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()]
        _require(now[0] >= previous[0] and now[1] >= previous[1])
        previous[:] = now
        approval(selected, unsigned_sha256=unsigned_sha256, trust_sha256=trust_sha256,
                 boot=boot, now_boot=now[0], now_unix=now[1])
        for fd, identity, maximum, _raw in public:
            _require(io._input(fd, maximum) == identity)
        for fd, identity in zip(key_fds, key_stamps, strict=True):
            _require(io._input(fd, 32, private=True) == identity)
        current = os.fstat(output_directory_fd)
        _require((current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_gid)
                 == (output_info.st_dev, output_info.st_ino, output_info.st_mode, output_info.st_uid, output_info.st_gid))
        _require(measure._identity(os.fstat(source_root_fd)) == measure._identity(source_info))

    def check_originals():
        check()
        for fd, _identity, maximum, original in public:
            _require(io.read_public(fd, maximum) == original)
        check()

    check()
    instant = datetime.fromtimestamp(previous[1] // 1_000_000_000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    keys, revoked = authenticate_upstream(unsigned, trust, instant)
    bundle = unsigned["bundle"]
    expected_root = bundle["stableSnapshotReceipt"]["payload"]["rootIdentity"]
    measured = measure.measure_tree(source_root_fd,
        [{name: row[name] for name in measure.FIELDS} for row in bundle["files"]],
        runtime_path=expected_root["runtimePath"], check=check)
    _require(measured["rootIdentity"] == expected_root and measured["files"] == bundle["files"]
             and measured["treeDigest"] == bundle["sourceTree"]["digest"]
             and measured["enumeratedTreeDigest"] == bundle["stableSnapshotReceipt"]["payload"]["enumeratedTreeDigest"])
    expiry = selected["verificationValidUntil"]
    _require(expiry <= unsigned["generation"]["validUntil"]
             and all(expiry <= bundle[field]["payload"]["expiresAt"] for field in ("stableSnapshotReceipt", "closureReceipt")))
    for request in unsigned["signatureRequests"]:
        _require(request["keyId"] == selected["signingKeys"][request["purpose"]])
    admitted_keys = [_key(keys, revoked, selected["signingKeys"][purpose], purpose, instant) for purpose in KEY_PURPOSES]
    _require(all(expiry <= key.not_after for key in admitted_keys))
    check_originals()
    private_keys = [io.signing_key(fd) for fd in key_fds]
    for private, key in zip(private_keys, admitted_keys, strict=True):
        public_key = private.public_key().public_bytes(spec.serialization.Encoding.Raw, spec.serialization.PublicFormat.Raw)
        _require(public_key == key.public_key)
    signatures = []
    for request, private in zip(unsigned["signatureRequests"], private_keys[:2], strict=True):
        check()
        message = spec.package_signature_message(request["purpose"], bundle, unsigned["generation"])
        signatures.append(dict(purpose=request["purpose"], algorithm="Ed25519", keyId=request["keyId"],
                               signatureBase64Url=spec.strict_base64url_encode(private.sign(message))))
    package = spec.assemble_signed_artifact_package(unsigned, signatures)
    check()
    instant = datetime.fromtimestamp(previous[1] // 1_000_000_000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    verified = spec.verify_signed_artifact_package(package, trust_state=trust, validation_time=instant)
    receipt = _receipt(verified, selected, policy_digest=approval_sha256, instant=instant, signer=private_keys[2])
    del private_keys
    del private
    check_originals()
    _require(measure.root_identity(source_root_fd, expected_root["runtimePath"]) == expected_root)
    package_raw, receipt_raw = spec.canonical_json_bytes(package), spec.canonical_json_bytes(receipt)
    _require(len(package_raw) <= io.MAX_PUBLIC and len(receipt_raw) <= io.MAX_PUBLIC)
    publish(output_directory_fd, OUTPUTS[0], package_raw, check=check)
    publish(output_directory_fd, OUTPUTS[1], receipt_raw, check=check)
    return dict(packageSha256=sha(package_raw), verificationSha256=sha(receipt_raw),
                packageDigest=verified.package_digest, verificationDigest=contract.verification_receipt_digest(receipt),
                disposition=verified.disposition)
