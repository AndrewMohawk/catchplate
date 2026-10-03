"""Signed synthetic contract data for historical-archive regression only.

All signatures, package/trust joins and verifier results below are real. File,
ELF and snapshot descriptions are synthetic fixture data, NOT observations of
an installed tree, a launched process, a database, or a durable witness. This
helper never reads pilot artifacts, installs trust or manufactures a verified
package result; the unchanged package verifier supplies that result.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.test_authority_local_configuration import fixture as configuration_fixture
from serverware import authority_artifact_spec as spec
from serverware import authority_contract as authority
from serverware import authority_local_configuration as configuration
from serverware import authority_local_trust as trust_codec
from serverware import authority_local_trust_commit as trust_commit
from serverware.authority_local_artifacts import sha

canonical = spec.canonical_json_bytes
encoded = spec.strict_base64url_encode


def _time(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_package(*, now_datetime=None):
    now = (now_datetime or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    start, end = _time(now - timedelta(seconds=120)), _time(now + timedelta(seconds=1800))
    selected, payload, root = configuration_fixture()
    generation = deepcopy(selected["generation"])
    generation.update(validFrom=start, validUntil=end)
    payload["generationBindingDigest"] = spec.configuration_generation_binding_digest(generation)
    payload["credentialReleaseTrust"]["maximumReceiptAgeNs"] = 600 * 10**9
    payload[configuration.generator.genesis_policy.FIELD] = dict(
        auditStoreIdentityDigest=sha(b"synthetic-history-audit-store"),
        auditSignerPublicKeyDigest=sha(b"synthetic-history-audit-signer"))
    roles = deepcopy(selected["roleManifests"])
    payload_schema, payload_digest = configuration._validate_payload(
        payload, "authority-service", generation, spec.role_binding_digests(roles))
    service = dict(schema=configuration.generator.SERVICE_CONFIGURATION_SCHEMA, payload=payload,
        signature=encoded(root.sign(configuration.signature_message("authority-service", payload))))

    private = {purpose: Ed25519PrivateKey.from_private_bytes(bytes([index + 101]) * 32)
        for index, purpose in enumerate(trust_codec.PURPOSES)}
    public = {purpose: encoded(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)) for purpose, key in private.items()}
    entries = trust_codec.key_entries(public, not_before=start, not_after=end)
    root_entry = next(row for row in entries if row["purposes"] == [trust_codec.ROOT_PURPOSE])
    operational = [row for row in entries if row is not root_entry]
    witness_entry = next(row for row in entries if row["purposes"] == ["witness-checkpoint"])
    witness = dict(identity="synthetic-history-log", keyId=witness_entry["keyId"],
        publicKeyBase64Url=witness_entry["publicKeyBase64Url"], keyFileSha256=witness_entry["keyFile"]["sha256"],
        authorizationDigest=witness_entry["authorizationDigest"], currentSequence=-1, currentTreeSize=0,
        **trust_codec.empty_witness_anchors(dict(device=1, inode=2), identity="synthetic-history-log",
            key_id=witness_entry["keyId"], key_file_sha256=witness_entry["keyFile"]["sha256"]))
    initial = dict(schema=spec.TRUST_STATE_SCHEMA, currentGenerationSequence=-1,
        currentGenerationDigest=None, currentPackageDigest=None, minimumRollbackSequence=0,
        acceptedPackageDigests=[], acceptedGenerationDigests=[], acceptedEvidenceDigests=[], revokedKeyIds=[],
        rootKeys=[trust_codec.external_key(root_entry)],
        currentKeys=[trust_codec.external_key(row) for row in operational], witness=witness)
    material = json.loads(trust_codec.sign_documents(dict(root=root_entry, entries=operational,
        trust=spec.validate_trust_state(initial)), private[trust_codec.ROOT_PURPOSE], validation_time=start))

    files = []
    def add(path, kind, raw, mode=0o400):
        row = dict(path=path, kind=kind, mode=mode, uid=0, gid=0, size=len(raw), sha256=sha(raw))
        files.append(row)
        return dict(path=path, sha256=row["sha256"])

    service_reference = dict(add("configuration/service.json", "configuration", canonical(service)),
        role="authority-service", name="service", payloadSchema=payload_schema, payloadDigest=payload_digest)
    for row in roles:
        measured = add(row["path"], "role-manifest", selected["roleOriginals"][row["role"]].encode("ascii"))
        assert measured["sha256"] == row["sha256"]
    for row in entries:
        add(row["keyFile"]["path"], "configuration", spec.strict_base64url_decode(
            row["publicKeyBase64Url"], name="synthetic key", decoded_size=32))
    native_bytes = b"synthetic native executable descriptor; never executed\n"
    executable = dict(add("authority.py", "elf-executable", native_bytes, 0o555),
        runtimePath="/runtime/authority.py", elfClass="ELF64", machine=62, ptInterp=None, needed=[])
    stage_bytes = b"# synthetic stage-zero descriptor; never executed\n"
    stage = dict(add("stage0.py", "authority-source", stage_bytes), runtimePath="/runtime/stage0.py",
        size=len(stage_bytes), interfaceSchema=spec.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA,
        interpreter=dict(path=executable["path"], runtimePath=executable["runtimePath"],
            sha256=executable["sha256"], size=len(native_bytes)))
    native = dict(executables=[executable], objects=[])
    imports = [dict(module="synthetic_stage", path=stage["path"], sha256=stage["sha256"], kind="source", isPackage=False)]
    operation = dict(add("operation.json", "operation-manifest", canonical(authority.operation_contract_document())),
        manifestSchema=authority.CONTRACT_SCHEMA, contractDigest=authority.OPERATION_MANIFEST_DIGEST)
    sbom = dict(add("sbom.json", "sbom", b"{}"), format="synthetic", mediaType="application/json")
    provenance_reference = add("provenance.json", "provenance", b'{"synthetic":true}')
    config_media, manifest_media = "application/vnd.oci.image.config.v1+json", "application/vnd.oci.image.manifest.v1+json"
    config_bytes = canonical(dict(architecture="amd64", os="linux", variant=None,
        rootfs=dict(type="layers", diff_ids=[])))
    config_ref = add("oci/config.json", "data", config_bytes)
    manifest_bytes = canonical(dict(schemaVersion=2, mediaType=manifest_media,
        config=dict(mediaType=config_media, digest=config_ref["sha256"], size=len(config_bytes)), layers=[]))
    manifest_ref = add("oci/manifest.json", "data", manifest_bytes)
    oci = dict(reference="synthetic.invalid/history@" + manifest_ref["sha256"],
        rootPath=manifest_ref["path"], rootDigest=manifest_ref["sha256"], rootSize=len(manifest_bytes),
        rootMediaType=manifest_media, rootDocumentBase64Url=encoded(manifest_bytes),
        indexPath=None, indexDigest=None, indexSize=None, indexMediaType=None, indexDocumentBase64Url=None,
        manifestPath=manifest_ref["path"], manifestDigest=manifest_ref["sha256"], manifestSize=len(manifest_bytes),
        manifestMediaType=manifest_media, manifestDocumentBase64Url=encoded(manifest_bytes),
        configPath=config_ref["path"], configDigest=config_ref["sha256"], configSize=len(config_bytes),
        configMediaType=config_media, configDocumentBase64Url=encoded(config_bytes),
        platform=dict(os="linux", architecture="amd64", variant=None), layers=[])
    files.sort(key=lambda row: row["path"])
    tree_digest = spec.domain_digest(spec.SOURCE_TREE_DIGEST_DOMAIN, canonical(files))
    total = sum(row["size"] for row in files)
    root_identity = dict(runtimePath="/synthetic-history-fixture", device=1, inode=2, generation=3,
        mountId=4, mode=0o555, uid=0, gid=0)

    def signed(schema, domain, body, purpose):
        return dict(schema=schema, payload=body, signerKeyId=trust_codec.key_id(purpose), algorithm="Ed25519",
            signatureBase64Url=encoded(private[purpose].sign(spec._signature_message(domain, body))))

    snapshot_body = dict(schema="serverware.authorityStableSnapshotReceiptPayload/v1", rootIdentity=root_identity,
        snapshotKind="content-addressed-cas", readOnly=True, treeAlgorithm="canonical-path-tree-sha256-v1",
        treeDigest=tree_digest, treeEntryCount=len(files), totalBytes=total,
        enumeratedTreeDigest=spec.domain_digest("serverware.authorityEnumeratedTree/v1", canonical(files)),
        createdAt=start, expiresAt=end)
    snapshot_body["receiptId"] = spec.domain_digest("serverware.authorityStableSnapshotReceiptId/v1", canonical(snapshot_body))
    snapshot = signed(spec.SNAPSHOT_RECEIPT_SCHEMA, "serverware.authorityStableSnapshotReceiptSignature/v1",
        snapshot_body, "stable-snapshot-verifier")
    closure_body = dict(schema="serverware.authorityTrustedHostLocalMeasuredRosterPayload/v1",
        snapshotReceiptDigest=spec.snapshot_receipt_digest(snapshot), treeDigest=tree_digest,
        treeEntryCount=len(files), totalBytes=total, pythonImportClosure=imports, nativeClosure=native,
        stageZero=stage, assurance=dict(spec.LOCAL_CLOSURE_CLAIMS), createdAt=start, expiresAt=end)
    closure_body["receiptId"] = spec.domain_digest("serverware.authorityTrustedHostLocalMeasuredRosterId/v1", canonical(closure_body))
    closure = signed(spec.LOCAL_CLOSURE_RECEIPT_SCHEMA, spec.LOCAL_CLOSURE_SIGNATURE_DOMAIN, closure_body, "closure-verifier")
    source_commit = sha(b"synthetic-history-source")
    provenance = dict(provenance_reference, predicateType="serverware.authorityTrustedHostLocalMeasuredArtifacts/v1",
        mediaType="application/json", builderId="synthetic-history-contract-fixture",
        sourceRevision=authority.SOURCE_REVISION, sourceCommitDigest=source_commit,
        sourceTreeDigest=tree_digest, ociRootDigest=manifest_ref["sha256"])
    provenance["statementDigest"] = spec.domain_digest(spec.PROVENANCE_PAYLOAD_DIGEST_DOMAIN, canonical(provenance))
    provenance_signature = encoded(private["provenance"].sign(spec._signature_message(spec.PROVENANCE_SIGNATURE_DOMAIN, provenance)))
    provenance.update(signerKeyId=trust_codec.key_id("provenance"), algorithm="Ed25519", signatureBase64Url=provenance_signature)
    bundle = dict(schema=spec.ARTIFACT_BUNDLE_SCHEMA, bundleVersion=1, authoritySchemaVersion=spec.AUTHORITY_SCHEMA_VERSION,
        sourceRevision=authority.SOURCE_REVISION, sourceCommitDigest=source_commit, trustMode=generation["trustMode"],
        sourceTree=dict(algorithm="canonical-path-tree-sha256-v1", digest=tree_digest, entryCount=len(files),
            snapshotKind="content-addressed-cas", readOnly=True, snapshotIdentityDigest=spec.domain_digest(
                "serverware.authoritySnapshotRootIdentity/v1", canonical(root_identity))),
        stableSnapshotReceipt=snapshot, closureReceipt=closure, files=files, pythonImportClosure=imports,
        nativeClosure=native, schemas=[], migrations=[], configurations=[service_reference], roleManifests=roles,
        sbom=sbom, provenance=provenance, ociImage=oci, stageZero=stage, operationManifest=operation)
    spec.validate_artifact_bundle(bundle)
    generation.update(schema=spec.GENERATION_STATEMENT_SCHEMA, artifactBundleDigest=spec.artifact_bundle_digest(bundle),
        stageZeroDigest=stage["sha256"], stageZeroContract=stage["interfaceSchema"],
        roleSetDigest=spec.domain_digest("serverware.authorityRoleSet/v1", canonical(roles)),
        snapshotReceiptDigest=spec.snapshot_receipt_digest(snapshot), closureReceiptDigest=spec.closure_receipt_digest(closure),
        provenanceStatementDigest=provenance["statementDigest"], sourceTreeDigest=tree_digest,
        ociManifestDigest=manifest_ref["sha256"], migrationReceiptDigests=[],
        roleManifestDigests=sorted(row["sha256"] for row in roles), configurationDigests=[service_reference["sha256"]],
        configurationPayloadBindings=spec.configuration_payload_bindings([service_reference]),
        keyAuthorizationsDigest=spec.trust_document_digest(material["keyAuthorizations"]),
        keyRevocationsDigest=spec.trust_document_digest(material["keyRevocations"]))
    spec.validate_generation_core(generation)
    core_digest = spec.domain_digest(spec.GENERATION_CORE_DIGEST_DOMAIN, canonical(generation))
    leaf = spec.domain_digest(spec.WITNESS_LEAF_DIGEST_DOMAIN, core_digest.encode("ascii"))
    checkpoint_body = dict(schema="serverware.authorityWitnessCheckpointPayload/v1", identity=witness["identity"],
        sequence=0, previousCheckpointDigest=witness["currentCheckpointDigest"], previousRootDigest=witness["currentRootDigest"],
        previousTreeSize=0, treeSize=1, generationCoreDigest=core_digest, leafDigest=leaf,
        rootDigest=spec.domain_digest(spec.WITNESS_CHAIN_ROOT_DOMAIN, witness["currentRootDigest"].encode("ascii"), b"1", leaf.encode("ascii")),
        issuedAt=start, coLocated=True, hardwareBacked=False)
    generation["witnessCheckpoint"] = signed("serverware.signedAuthorityWitnessCheckpoint/v1",
        spec.WITNESS_CHECKPOINT_SIGNATURE_DOMAIN, checkpoint_body, "witness-checkpoint")
    requests, signatures = [], []
    for purpose in ("artifact-bundle", "generation"):
        message = spec.package_signature_message(purpose, bundle, generation)
        row = dict(purpose=purpose, algorithm="Ed25519", keyId=trust_codec.key_id(purpose))
        requests.append(dict(row, messageBase64Url=encoded(message)))
        signatures.append(dict(row, signatureBase64Url=encoded(private[purpose].sign(message))))
    unsigned = dict(schema=spec.UNSIGNED_PACKAGE_SCHEMA, bundle=bundle, generation=generation,
        trustMaterial=material, signatureRequests=requests)
    package = spec.assemble_signed_artifact_package(unsigned, signatures)
    successor = spec.verify_signed_artifact_package(package, trust_state=initial, validation_time=_time(now))
    accepted = json.loads(trust_commit._next_state(initial, successor, validation_time=_time(now)))
    verified = spec.verify_signed_artifact_package(package, trust_state=accepted, validation_time=_time(now))
    assert verified.disposition == "CurrentExactRetry"
    return dict(package=package, trust_state=accepted, verified=verified, configuration=service,
        root=root, now_epoch_ns=int(now.timestamp()) * 10**9)
