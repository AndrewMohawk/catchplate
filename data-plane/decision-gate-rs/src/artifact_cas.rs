#![cfg(target_os = "linux")]

use crate::plan_protocol::{
    canonical_bytes, canonical_sha256, sha256_bytes, ArtifactCasReference,
    CasSealingEvidenceV12, Digest, OciObjectReference, PlanProtocolError,
    PlanResult,
};
use crate::source_cas::{
    AuthenticatedDirectoryInput, DirectoryCasStore,
    FilesystemEntryKind, FilesystemManifestV12, ManifestTrustPolicy,
    PublicationControlV12, PublishedDirectoryCas,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

const ARTIFACT_MANIFEST_VERSION: &str =
    "catchplate/artifact-cas-manifest/v12";
const ARTIFACT_CAS_DOMAIN: &str = "catchplate/artifact-cas/v12";
const ARTIFACT_METADATA_NAME: &str =
    ".catchplate-artifact-cas-v12.json";
const MAX_OCI_OBJECTS: usize = 512;
const MAX_OCI_JSON_BYTES: u64 = 16 * 1024 * 1024;
const MAX_OCI_BLOB_BYTES: u64 = 32 * 1024 * 1024 * 1024;

const OCI_INDEX_MEDIA_TYPE: &str =
    "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST_MEDIA_TYPE: &str =
    "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG_MEDIA_TYPE: &str =
    "application/vnd.oci.image.config.v1+json";
const OCI_LAYER_MEDIA_TYPES: [&str; 4] = [
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
];

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OciBlobDescriptorV12 {
    pub media_type: String,
    pub digest_sha256: Digest,
    pub size: u64,
}

impl OciBlobDescriptorV12 {
    fn validate(&self, accepted_media_types: &[&str]) -> PlanResult<()> {
        if !accepted_media_types
            .iter()
            .any(|accepted| *accepted == self.media_type)
            || self.digest_sha256 == [0; 32]
            || self.size == 0
            || self.size > MAX_OCI_BLOB_BYTES
        {
            return Err(PlanProtocolError::Invalid(
                "OCI blob descriptor is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OciRepositoryMappingV12 {
    pub repository: String,
    pub reference_name: String,
    pub platform: String,
    pub manifest_digest_sha256: Digest,
    pub mapping_sha256: Digest,
}

impl OciRepositoryMappingV12 {
    fn validate(&self, reference: &OciObjectReference) -> PlanResult<()> {
        if self.repository != reference.repository
            || self.platform != reference.platform
            || self.manifest_digest_sha256
                != reference.manifest_digest_sha256
            || self.reference_name.is_empty()
            || self.reference_name.len() > 256
            || self.reference_name.chars().any(char::is_whitespace)
            || !(self.reference_name == self.repository
                || self
                    .reference_name
                    .strip_prefix(&self.repository)
                    .is_some_and(|suffix| {
                        suffix.starts_with(':')
                            && suffix.len() > 1
                            && !suffix[1..]
                                .chars()
                                .any(|character| {
                                    matches!(character, '/' | '@' | ':')
                                })
                    }))
            || self.mapping_sha256 == [0; 32]
        {
            return Err(PlanProtocolError::Invalid(
                "OCI repository mapping is invalid",
            ));
        }
        let mut copy = self.clone();
        copy.mapping_sha256 = [0; 32];
        if canonical_sha256(&copy)? != self.mapping_sha256 {
            return Err(PlanProtocolError::Invalid(
                "OCI repository mapping digest is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArtifactOciObjectV12 {
    pub reference: OciObjectReference,
    pub repository_mapping: OciRepositoryMappingV12,
    pub layout_relative_path: String,
    pub oci_layout_file_sha256: Digest,
    pub index_file_sha256: Digest,
    pub manifest_blob_relative_path: String,
    pub manifest: OciBlobDescriptorV12,
    pub config: OciBlobDescriptorV12,
    pub layers: Vec<OciBlobDescriptorV12>,
    pub full_closure_sha256: Digest,
}

impl ArtifactOciObjectV12 {
    fn validate(
        &self,
        filesystem: &FilesystemManifestV12,
    ) -> PlanResult<()> {
        self.reference.validate()?;
        self.repository_mapping.validate(&self.reference)?;
        validate_relative_path(&self.layout_relative_path)?;
        validate_relative_path(&self.manifest_blob_relative_path)?;
        if self.oci_layout_file_sha256 == [0; 32]
            || self.index_file_sha256 == [0; 32]
            || self.reference.index_digest_sha256
                != Some(self.index_file_sha256)
        {
            return Err(PlanProtocolError::Invalid(
                "OCI layout metadata digest is empty",
            ));
        }
        self.manifest
            .validate(&[OCI_MANIFEST_MEDIA_TYPE])?;
        self.config.validate(&[OCI_CONFIG_MEDIA_TYPE])?;
        if self.layers.is_empty() || self.layers.len() > 4096 {
            return Err(PlanProtocolError::Invalid(
                "OCI layer descriptor set is empty or excessive",
            ));
        }
        let mut layer_digests = BTreeSet::new();
        for layer in &self.layers {
            layer.validate(&OCI_LAYER_MEDIA_TYPES)?;
            if !layer_digests.insert(layer.digest_sha256) {
                return Err(PlanProtocolError::Invalid(
                    "OCI layer descriptors contain a duplicate digest",
                ));
            }
        }
        if self.manifest.digest_sha256
                != self.reference.manifest_digest_sha256
            || self.manifest.size != self.reference.size
            || self.full_closure_sha256 == [0; 32]
        {
            return Err(PlanProtocolError::Invalid(
                "OCI manifest descriptor lost object-reference binding",
            ));
        }
        let layout_metadata = format!(
            "{}/oci-layout",
            self.layout_relative_path
        );
        let index = format!("{}/index.json", self.layout_relative_path);
        let manifest_hex =
            hex_digest(&self.reference.manifest_digest_sha256);
        let expected_manifest = format!(
            "{}/blobs/sha256/{manifest_hex}",
            self.layout_relative_path
        );
        if self.manifest_blob_relative_path != expected_manifest {
            return Err(PlanProtocolError::Invalid(
                "OCI manifest blob path is not digest-derived",
            ));
        }
        require_file(
            filesystem,
            &layout_metadata,
            &self.oci_layout_file_sha256,
        )?;
        require_file(
            filesystem,
            &index,
            &self.index_file_sha256,
        )?;
        require_file(
            filesystem,
            &self.manifest_blob_relative_path,
            &self.manifest.digest_sha256,
        )?;
        require_blob_file(
            filesystem,
            &self.layout_relative_path,
            &self.config,
        )?;
        for layer in &self.layers {
            require_blob_file(
                filesystem,
                &self.layout_relative_path,
                layer,
            )?;
        }
        if oci_closure_digest(self)? != self.full_closure_sha256 {
            return Err(PlanProtocolError::Invalid(
                "OCI full-closure digest is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArtifactManifestV12 {
    pub version: String,
    pub source_manifest_sha256: Digest,
    pub build_plan_sha256: Digest,
    pub build_transcript_sha256: Digest,
    pub filesystem: FilesystemManifestV12,
    pub files_sha256: Digest,
    pub oci_objects: Vec<ArtifactOciObjectV12>,
    pub oci_set_sha256: Digest,
    pub artifact_object_sha256: Digest,
}

impl ArtifactManifestV12 {
    pub fn validate(
        &self,
        control: &PublicationControlV12,
        trust: &ManifestTrustPolicy,
    ) -> PlanResult<()> {
        if self.version != ARTIFACT_MANIFEST_VERSION
            || self.source_manifest_sha256 == [0; 32]
            || self.build_plan_sha256 == [0; 32]
            || self.build_transcript_sha256 == [0; 32]
            || self.files_sha256 == [0; 32]
            || self.oci_set_sha256 == [0; 32]
            || self.artifact_object_sha256 == [0; 32]
            || self.oci_objects.is_empty()
            || self.oci_objects.len() > MAX_OCI_OBJECTS
        {
            return Err(PlanProtocolError::Invalid(
                "artifact manifest envelope is invalid",
            ));
        }
        let context = artifact_context_digest(
            &self.source_manifest_sha256,
            &self.build_plan_sha256,
            &self.build_transcript_sha256,
            &self.files_sha256,
            &self.oci_set_sha256,
        );
        if self.filesystem.context_sha256 != context {
            return Err(PlanProtocolError::Invalid(
                "artifact filesystem lost build/source/OCI binding",
            ));
        }
        self.filesystem
            .validate(ARTIFACT_CAS_DOMAIN, control, trust)?;
        let expected_files = filesystem_content_digest(&self.filesystem);
        if self.files_sha256 != expected_files {
            return Err(PlanProtocolError::Invalid(
                "artifact file-set digest is not canonical",
            ));
        }
        let mut prior: Option<(&str, &str, Digest)> = None;
        let mut identities = BTreeSet::new();
        let mut layout_paths = BTreeSet::new();
        for object in &self.oci_objects {
            object.validate(&self.filesystem)?;
            let identity = (
                object.reference.repository.as_str(),
                object.reference.platform.as_str(),
                object.reference.manifest_digest_sha256,
            );
            if prior.is_some_and(|prior| prior >= identity)
                || !identities.insert((
                    object.reference.repository.clone(),
                    object.reference.platform.clone(),
                    object.reference.manifest_digest_sha256,
                ))
                || !layout_paths.insert(
                    object.layout_relative_path.as_str(),
                )
            {
                return Err(PlanProtocolError::Invalid(
                    "artifact OCI objects are not strictly sorted",
                ));
            }
            prior = Some(identity);
        }
        if canonical_sha256(&self.oci_objects)? != self.oci_set_sha256 {
            return Err(PlanProtocolError::Invalid(
                "artifact OCI set digest is not canonical",
            ));
        }
        let expected_object = artifact_object_digest(
            &self.filesystem.manifest_sha256,
            &context,
        );
        if self.artifact_object_sha256 != expected_object {
            return Err(PlanProtocolError::Invalid(
                "artifact object digest is not canonical",
            ));
        }
        Ok(())
    }

    fn validate_input(
        &self,
        input: &AuthenticatedDirectoryInput,
    ) -> PlanResult<()> {
        let mut repositories = BTreeSet::new();
        for object in &self.oci_objects {
            validate_oci_object_input(
                input,
                &self.filesystem,
                object,
            )?;
            if !repositories.insert(
                object.repository_mapping.repository.as_str(),
            ) {
                return Err(PlanProtocolError::Invalid(
                    "artifact maps one repository more than once",
                ));
            }
        }
        Ok(())
    }

    pub fn reference(
        &self,
        sealing_evidence: CasSealingEvidenceV12,
    ) -> ArtifactCasReference {
        ArtifactCasReference {
            manifest_sha256: self.filesystem.manifest_sha256,
            object_sha256: self.artifact_object_sha256,
            source_manifest_sha256: self.source_manifest_sha256,
            build_plan_sha256: self.build_plan_sha256,
            files_sha256: self.files_sha256,
            oci_objects: self
                .oci_objects
                .iter()
                .map(|object| object.reference.clone())
                .collect(),
            sealing_evidence,
        }
    }
}

pub struct PublishedArtifactCas {
    pub object_fd: OwnedFd,
    pub reference: ArtifactCasReference,
    pub manifest: ArtifactManifestV12,
    pub sealing_evidence: CasSealingEvidenceV12,
    pub published_new: bool,
}

pub struct ArtifactCasStore {
    directory_store: DirectoryCasStore,
    trust: ManifestTrustPolicy,
}

impl ArtifactCasStore {
    pub fn open(
        path: &Path,
        trust: ManifestTrustPolicy,
    ) -> PlanResult<Self> {
        Ok(Self {
            directory_store: DirectoryCasStore::open(path)?,
            trust,
        })
    }

    pub fn publish(
        &self,
        input: AuthenticatedDirectoryInput,
        manifest: ArtifactManifestV12,
        control: &PublicationControlV12,
    ) -> PlanResult<PublishedArtifactCas> {
        manifest.validate(control, &self.trust)?;
        manifest.validate_input(&input)?;
        let metadata = canonical_bytes(&manifest)?;
        let published: PublishedDirectoryCas =
        self.directory_store.publish(
            control,
                &input,
                &manifest.filesystem,
                ARTIFACT_CAS_DOMAIN,
                &self.trust,
                manifest.artifact_object_sha256,
                ARTIFACT_METADATA_NAME,
                &metadata,
            )?;
        let reference = manifest.reference(
            published.sealing_evidence.clone(),
        );
        reference.validate()?;
        Ok(PublishedArtifactCas {
            object_fd: published.object_fd,
            reference,
            manifest,
            sealing_evidence: published.sealing_evidence,
            published_new: published.published_new,
        })
    }

    pub fn load_published(
        &self,
        expected: &ArtifactCasReference,
        control: &PublicationControlV12,
    ) -> PlanResult<PublishedArtifactCas> {
        expected.validate()?;
        let (object_fd, metadata) =
            self.directory_store.open_published_metadata(
                &expected.object_sha256,
                ARTIFACT_METADATA_NAME,
                MAX_OCI_JSON_BYTES,
            )?;
        let manifest: ArtifactManifestV12 =
            serde_json::from_slice(&metadata)?;
        if canonical_bytes(&manifest)? != metadata {
            return Err(PlanProtocolError::Invalid(
                "published artifact metadata is not canonical JSON",
            ));
        }
        manifest.validate(control, &self.trust)?;
        let reference =
            manifest.reference(expected.sealing_evidence.clone());
        if &reference != expected {
            return Err(PlanProtocolError::Invalid(
                "published artifact metadata differs from the logical plan",
            ));
        }
        Ok(PublishedArtifactCas {
            object_fd,
            reference,
            manifest,
            sealing_evidence: expected.sealing_evidence.clone(),
            published_new: false,
        })
    }
}

pub fn artifact_context_digest(
    source_manifest_sha256: &Digest,
    build_plan_sha256: &Digest,
    build_transcript_sha256: &Digest,
    files_sha256: &Digest,
    oci_set_sha256: &Digest,
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"catchplate/artifact-context/v12\0");
    hasher.update(source_manifest_sha256);
    hasher.update(build_plan_sha256);
    hasher.update(build_transcript_sha256);
    hasher.update(files_sha256);
    hasher.update(oci_set_sha256);
    hasher.finalize().into()
}

pub fn artifact_object_digest(
    manifest_sha256: &Digest,
    context_sha256: &Digest,
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(ARTIFACT_CAS_DOMAIN.as_bytes());
    hasher.update([0]);
    hasher.update(manifest_sha256);
    hasher.update(context_sha256);
    hasher.finalize().into()
}

pub fn filesystem_content_digest(
    filesystem: &FilesystemManifestV12,
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"catchplate/artifact-files/v12\0");
    for entry in &filesystem.entries {
        hasher.update(entry.relative_path.as_bytes());
        hasher.update([0]);
        hasher.update([match entry.kind {
            FilesystemEntryKind::Directory => 0,
            FilesystemEntryKind::RegularFile => 1,
        }]);
        hasher.update(entry.mode.to_be_bytes());
        hasher.update(entry.size.to_be_bytes());
        hasher.update(entry.content_sha256);
    }
    hasher.finalize().into()
}

fn oci_closure_digest(
    object: &ArtifactOciObjectV12,
) -> PlanResult<Digest> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Closure<'a> {
        reference: &'a OciObjectReference,
        repository_mapping: &'a OciRepositoryMappingV12,
        layout_relative_path: &'a str,
        oci_layout_file_sha256: &'a Digest,
        index_file_sha256: &'a Digest,
        manifest: &'a OciBlobDescriptorV12,
        config: &'a OciBlobDescriptorV12,
        layers: &'a [OciBlobDescriptorV12],
    }
    canonical_sha256(&Closure {
        reference: &object.reference,
        repository_mapping: &object.repository_mapping,
        layout_relative_path: &object.layout_relative_path,
        oci_layout_file_sha256: &object.oci_layout_file_sha256,
        index_file_sha256: &object.index_file_sha256,
        manifest: &object.manifest,
        config: &object.config,
        layers: &object.layers,
    })
}

fn validate_oci_object_input(
    input: &AuthenticatedDirectoryInput,
    filesystem: &FilesystemManifestV12,
    object: &ArtifactOciObjectV12,
) -> PlanResult<()> {
    let layout_path =
        format!("{}/oci-layout", object.layout_relative_path);
    let index_path =
        format!("{}/index.json", object.layout_relative_path);
    let layout_entry = require_file_entry(
        filesystem,
        &layout_path,
        &object.oci_layout_file_sha256,
    )?;
    let index_entry = require_file_entry(
        filesystem,
        &index_path,
        &object.index_file_sha256,
    )?;
    let layout_bytes = input.read_verified_file(
        &layout_path,
        layout_entry.size,
        &layout_entry.content_sha256,
        MAX_OCI_JSON_BYTES,
    )?;
    let layout_value: JsonValue =
        serde_json::from_slice(&layout_bytes)?;
    let layout = strict_object(
        &layout_value,
        &["imageLayoutVersion"],
        "OCI layout",
    )?;
    if required_string(layout, "imageLayoutVersion")? != "1.0.0" {
        return Err(PlanProtocolError::Invalid(
            "OCI layout version is not 1.0.0",
        ));
    }

    let index_bytes = input.read_verified_file(
        &index_path,
        index_entry.size,
        &index_entry.content_sha256,
        MAX_OCI_JSON_BYTES,
    )?;
    let index_value: JsonValue =
        serde_json::from_slice(&index_bytes)?;
    let index = strict_object(
        &index_value,
        &["schemaVersion", "mediaType", "manifests"],
        "OCI index",
    )?;
    require_schema_two(index, "OCI index")?;
    if required_string(index, "mediaType")? != OCI_INDEX_MEDIA_TYPE {
        return Err(PlanProtocolError::Invalid(
            "OCI index media type is unsupported",
        ));
    }
    let manifests = required_array(index, "manifests")?;
    if manifests.len() != 1 {
        return Err(PlanProtocolError::Invalid(
            "each sealed OCI layout must map exactly one manifest",
        ));
    }
    let parsed_manifest_descriptor =
        parse_index_manifest_descriptor(&manifests[0])?;
    if parsed_manifest_descriptor.descriptor != object.manifest
        || parsed_manifest_descriptor.platform
            != object.reference.platform
        || parsed_manifest_descriptor.reference_name
            != object.repository_mapping.reference_name
    {
        return Err(PlanProtocolError::Invalid(
            "OCI index descriptor differs from declared repository mapping",
        ));
    }

    let manifest_entry = require_file_entry(
        filesystem,
        &object.manifest_blob_relative_path,
        &object.manifest.digest_sha256,
    )?;
    if manifest_entry.size != object.manifest.size {
        return Err(PlanProtocolError::Invalid(
            "OCI manifest blob size differs from descriptor",
        ));
    }
    let manifest_bytes = input.read_verified_file(
        &object.manifest_blob_relative_path,
        manifest_entry.size,
        &manifest_entry.content_sha256,
        MAX_OCI_JSON_BYTES,
    )?;
    let manifest_value: JsonValue =
        serde_json::from_slice(&manifest_bytes)?;
    let manifest = strict_object(
        &manifest_value,
        &[
            "schemaVersion",
            "mediaType",
            "config",
            "layers",
            "annotations",
        ],
        "OCI manifest",
    )?;
    require_schema_two(manifest, "OCI manifest")?;
    if required_string(manifest, "mediaType")?
        != OCI_MANIFEST_MEDIA_TYPE
    {
        return Err(PlanProtocolError::Invalid(
            "OCI manifest media type is unsupported",
        ));
    }
    if let Some(annotations) = manifest.get("annotations") {
        validate_string_map(annotations, "OCI manifest annotations")?;
    }
    let parsed_config =
        parse_blob_descriptor(required_value(manifest, "config")?)?;
    if parsed_config != object.config {
        return Err(PlanProtocolError::Invalid(
            "OCI config descriptor differs from declared closure",
        ));
    }
    let layer_values = required_array(manifest, "layers")?;
    if layer_values.len() != object.layers.len() {
        return Err(PlanProtocolError::Invalid(
            "OCI layer count differs from declared closure",
        ));
    }
    for (value, expected) in
        layer_values.iter().zip(&object.layers)
    {
        if parse_blob_descriptor(value)? != *expected {
            return Err(PlanProtocolError::Invalid(
                "OCI layer descriptor differs from declared closure",
            ));
        }
    }

    let config_path = blob_relative_path(
        &object.layout_relative_path,
        &object.config.digest_sha256,
    );
    let config_entry = require_file_entry(
        filesystem,
        &config_path,
        &object.config.digest_sha256,
    )?;
    if config_entry.size != object.config.size {
        return Err(PlanProtocolError::Invalid(
            "OCI config blob size differs from descriptor",
        ));
    }
    let config_bytes = input.read_verified_file(
        &config_path,
        config_entry.size,
        &config_entry.content_sha256,
        MAX_OCI_JSON_BYTES,
    )?;
    validate_oci_image_config(
        &config_bytes,
        &object.reference.platform,
        object.layers.len(),
    )?;
    for layer in &object.layers {
        let layer_path = blob_relative_path(
            &object.layout_relative_path,
            &layer.digest_sha256,
        );
        let entry = require_file_entry(
            filesystem,
            &layer_path,
            &layer.digest_sha256,
        )?;
        if entry.size != layer.size {
            return Err(PlanProtocolError::Invalid(
                "OCI layer blob size differs from descriptor",
            ));
        }
    }
    validate_exact_oci_subtree(filesystem, object)
}

#[derive(Debug, Eq, PartialEq)]
struct ParsedIndexManifestDescriptor {
    descriptor: OciBlobDescriptorV12,
    platform: String,
    reference_name: String,
}

fn parse_index_manifest_descriptor(
    value: &JsonValue,
) -> PlanResult<ParsedIndexManifestDescriptor> {
    let object = strict_object(
        value,
        &["mediaType", "digest", "size", "platform", "annotations"],
        "OCI index descriptor",
    )?;
    let descriptor = OciBlobDescriptorV12 {
        media_type: required_string(object, "mediaType")?.to_string(),
        digest_sha256: parse_sha256_digest(
            required_string(object, "digest")?,
        )?,
        size: required_u64(object, "size")?,
    };
    descriptor.validate(&[OCI_MANIFEST_MEDIA_TYPE])?;
    let platform = parse_platform(required_value(object, "platform")?)?;
    let annotations = strict_object(
        required_value(object, "annotations")?,
        &["org.opencontainers.image.ref.name"],
        "OCI index descriptor annotations",
    )?;
    let reference_name = required_string(
        annotations,
        "org.opencontainers.image.ref.name",
    )?
    .to_string();
    if reference_name.is_empty() || reference_name.len() > 256 {
        return Err(PlanProtocolError::Invalid(
            "OCI reference-name annotation is invalid",
        ));
    }
    Ok(ParsedIndexManifestDescriptor {
        descriptor,
        platform,
        reference_name,
    })
}

fn parse_blob_descriptor(
    value: &JsonValue,
) -> PlanResult<OciBlobDescriptorV12> {
    let object = value.as_object().ok_or(
        PlanProtocolError::Invalid(
            "OCI descriptor is not an object",
        ),
    )?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "mediaType" | "digest" | "size" | "annotations"
        ) {
            return Err(PlanProtocolError::Invalid(
                "OCI blob descriptor contains an unsupported field",
            ));
        }
    }
    if let Some(annotations) = object.get("annotations") {
        validate_string_map(annotations, "OCI descriptor annotations")?;
    }
    Ok(OciBlobDescriptorV12 {
        media_type: required_string(object, "mediaType")?.to_string(),
        digest_sha256: parse_sha256_digest(
            required_string(object, "digest")?,
        )?,
        size: required_u64(object, "size")?,
    })
}

fn parse_platform(value: &JsonValue) -> PlanResult<String> {
    let object = strict_object(
        value,
        &["architecture", "os", "variant"],
        "OCI platform",
    )?;
    let os = required_string(object, "os")?;
    let architecture = required_string(object, "architecture")?;
    let variant = object
        .get("variant")
        .map(|value| {
            value.as_str().ok_or(
                PlanProtocolError::Invalid(
                    "OCI platform variant is not a string",
                ),
            )
        })
        .transpose()?;
    if os != "linux"
        || architecture.is_empty()
        || architecture.len() > 64
        || variant.is_some_and(|value| {
            value.is_empty() || value.len() > 32
        })
    {
        return Err(PlanProtocolError::Invalid(
            "OCI platform is invalid",
        ));
    }
    Ok(match variant {
        Some(variant) => format!("{os}/{architecture}/{variant}"),
        None => format!("{os}/{architecture}"),
    })
}

fn validate_oci_image_config(
    bytes: &[u8],
    expected_platform: &str,
    layer_count: usize,
) -> PlanResult<()> {
    let value: JsonValue = serde_json::from_slice(bytes)?;
    let object = strict_object(
        &value,
        &[
            "architecture",
            "os",
            "variant",
            "created",
            "author",
            "config",
            "rootfs",
            "history",
            "os.version",
            "os.features",
        ],
        "OCI image config",
    )?;
    let architecture = required_string(object, "architecture")?;
    let os = required_string(object, "os")?;
    let variant = object
        .get("variant")
        .and_then(JsonValue::as_str);
    let actual_platform = match variant {
        Some(variant) => format!("{os}/{architecture}/{variant}"),
        None => format!("{os}/{architecture}"),
    };
    if actual_platform != expected_platform {
        return Err(PlanProtocolError::Invalid(
            "OCI config platform differs from index platform",
        ));
    }
    if let Some(config) = object.get("config") {
        validate_oci_runtime_config(config)?;
    }
    let rootfs = strict_object(
        required_value(object, "rootfs")?,
        &["type", "diff_ids"],
        "OCI rootfs",
    )?;
    if required_string(rootfs, "type")? != "layers" {
        return Err(PlanProtocolError::Invalid(
            "OCI rootfs type is unsupported",
        ));
    }
    let diff_ids = required_array(rootfs, "diff_ids")?;
    if diff_ids.len() != layer_count {
        return Err(PlanProtocolError::Invalid(
            "OCI rootfs diff-id count differs from layer count",
        ));
    }
    let mut unique_diff_ids = BTreeSet::new();
    for diff_id in diff_ids {
        let digest = parse_sha256_digest(
            diff_id.as_str().ok_or(
                PlanProtocolError::Invalid(
                    "OCI rootfs diff-id is not a string",
                ),
            )?,
        )?;
        if !unique_diff_ids.insert(digest) {
            return Err(PlanProtocolError::Invalid(
                "OCI rootfs diff-id set contains a duplicate",
            ));
        }
    }
    if let Some(history) = object.get("history") {
        let history = history.as_array().ok_or(
            PlanProtocolError::Invalid(
                "OCI history is not an array",
            ),
        )?;
        if history.len() > 65_536 {
            return Err(PlanProtocolError::Invalid(
                "OCI history is excessive",
            ));
        }
        for entry in history {
            let entry = strict_object(
                entry,
                &[
                    "created",
                    "created_by",
                    "author",
                    "comment",
                    "empty_layer",
                ],
                "OCI history entry",
            )?;
            if let Some(empty) = entry.get("empty_layer") {
                if !empty.is_boolean() {
                    return Err(PlanProtocolError::Invalid(
                        "OCI history empty_layer is not boolean",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_oci_runtime_config(value: &JsonValue) -> PlanResult<()> {
    let object = strict_object(
        value,
        &[
            "User",
            "ExposedPorts",
            "Env",
            "Entrypoint",
            "Cmd",
            "Volumes",
            "WorkingDir",
            "Labels",
            "StopSignal",
            "ArgsEscaped",
            "OnBuild",
            "Shell",
            "Healthcheck",
        ],
        "OCI runtime config",
    )?;
    let canonical = serde_json::to_vec(object)?;
    if canonical.len() > MAX_OCI_JSON_BYTES as usize {
        return Err(PlanProtocolError::Invalid(
            "OCI runtime config is excessive",
        ));
    }
    for key in ["Env", "Entrypoint", "Cmd", "OnBuild", "Shell"] {
        if let Some(value) = object.get(key) {
            let values = value.as_array().ok_or(
                PlanProtocolError::Invalid(
                    "OCI runtime string vector is not an array",
                ),
            )?;
            if values.len() > 65_536
                || values.iter().any(|value| {
                    value.as_str().is_none_or(|value| {
                        value.len() > 64 * 1024
                            || value.as_bytes().contains(&0)
                    })
                })
            {
                return Err(PlanProtocolError::Invalid(
                    "OCI runtime string vector is invalid",
                ));
            }
        }
    }
    Ok(())
}

fn validate_exact_oci_subtree(
    filesystem: &FilesystemManifestV12,
    object: &ArtifactOciObjectV12,
) -> PlanResult<()> {
    let prefix = format!("{}/", object.layout_relative_path);
    let mut expected_files = BTreeSet::from([
        format!("{}oci-layout", prefix),
        format!("{}index.json", prefix),
        object.manifest_blob_relative_path.clone(),
        blob_relative_path(
            &object.layout_relative_path,
            &object.config.digest_sha256,
        ),
    ]);
    for layer in &object.layers {
        expected_files.insert(blob_relative_path(
            &object.layout_relative_path,
            &layer.digest_sha256,
        ));
    }
    let actual_files: BTreeSet<String> = filesystem
        .entries
        .iter()
        .filter(|entry| {
            entry.kind == FilesystemEntryKind::RegularFile
                && entry.relative_path.starts_with(&prefix)
        })
        .map(|entry| entry.relative_path.clone())
        .collect();
    if actual_files != expected_files {
        return Err(PlanProtocolError::Invalid(
            "OCI layout contains undeclared or missing blobs",
        ));
    }
    let expected_directories = BTreeSet::from([
        object.layout_relative_path.clone(),
        format!("{}/blobs", object.layout_relative_path),
        format!("{}/blobs/sha256", object.layout_relative_path),
    ]);
    let actual_directories: BTreeSet<String> = filesystem
        .entries
        .iter()
        .filter(|entry| {
            entry.kind == FilesystemEntryKind::Directory
                && (entry.relative_path == object.layout_relative_path
                    || entry.relative_path.starts_with(&prefix))
        })
        .map(|entry| entry.relative_path.clone())
        .collect();
    if actual_directories != expected_directories {
        return Err(PlanProtocolError::Invalid(
            "OCI layout directory closure is not canonical",
        ));
    }
    Ok(())
}

fn require_file_entry<'a>(
    filesystem: &'a FilesystemManifestV12,
    path: &str,
    digest: &Digest,
) -> PlanResult<&'a crate::source_cas::FilesystemEntryV12> {
    let entry = filesystem
        .entries
        .binary_search_by(|entry| entry.relative_path.as_str().cmp(path))
        .ok()
        .and_then(|index| filesystem.entries.get(index))
        .ok_or(PlanProtocolError::Invalid(
            "OCI layout references an undeclared file",
        ))?;
    if entry.kind != FilesystemEntryKind::RegularFile
        || &entry.content_sha256 != digest
    {
        return Err(PlanProtocolError::Invalid(
            "OCI layout file digest differs from artifact manifest",
        ));
    }
    Ok(entry)
}

fn require_blob_file(
    filesystem: &FilesystemManifestV12,
    layout: &str,
    descriptor: &OciBlobDescriptorV12,
) -> PlanResult<()> {
    let path = blob_relative_path(layout, &descriptor.digest_sha256);
    let entry =
        require_file_entry(filesystem, &path, &descriptor.digest_sha256)?;
    if entry.size != descriptor.size {
        return Err(PlanProtocolError::Invalid(
            "OCI blob size differs from descriptor",
        ));
    }
    Ok(())
}

fn blob_relative_path(layout: &str, digest: &Digest) -> String {
    format!("{layout}/blobs/sha256/{}", hex_digest(digest))
}

fn strict_object<'a>(
    value: &'a JsonValue,
    allowed: &[&str],
    description: &'static str,
) -> PlanResult<&'a JsonMap<String, JsonValue>> {
    let object = value.as_object().ok_or(
        PlanProtocolError::InvalidOwned(format!(
            "{description} is not an object",
        )),
    )?;
    if object.keys().any(|key| {
        !allowed.iter().any(|allowed| key == allowed)
    }) {
        return Err(PlanProtocolError::InvalidOwned(format!(
            "{description} contains an unsupported field",
        )));
    }
    Ok(object)
}

fn required_value<'a>(
    object: &'a JsonMap<String, JsonValue>,
    key: &'static str,
) -> PlanResult<&'a JsonValue> {
    object.get(key).ok_or(
        PlanProtocolError::InvalidOwned(format!(
            "OCI object lacks required {key}",
        )),
    )
}

fn required_string<'a>(
    object: &'a JsonMap<String, JsonValue>,
    key: &'static str,
) -> PlanResult<&'a str> {
    required_value(object, key)?
        .as_str()
        .ok_or(PlanProtocolError::InvalidOwned(format!(
            "OCI {key} is not a string",
        )))
}

fn required_u64(
    object: &JsonMap<String, JsonValue>,
    key: &'static str,
) -> PlanResult<u64> {
    required_value(object, key)?
        .as_u64()
        .ok_or(PlanProtocolError::InvalidOwned(format!(
            "OCI {key} is not an unsigned integer",
        )))
}

fn required_array<'a>(
    object: &'a JsonMap<String, JsonValue>,
    key: &'static str,
) -> PlanResult<&'a Vec<JsonValue>> {
    required_value(object, key)?
        .as_array()
        .ok_or(PlanProtocolError::InvalidOwned(format!(
            "OCI {key} is not an array",
        )))
}

fn require_schema_two(
    object: &JsonMap<String, JsonValue>,
    description: &'static str,
) -> PlanResult<()> {
    if required_u64(object, "schemaVersion")? != 2 {
        return Err(PlanProtocolError::InvalidOwned(format!(
            "{description} schemaVersion is not 2",
        )));
    }
    Ok(())
}

fn validate_string_map(
    value: &JsonValue,
    description: &'static str,
) -> PlanResult<()> {
    let object = value.as_object().ok_or(
        PlanProtocolError::InvalidOwned(format!(
            "{description} is not an object",
        )),
    )?;
    if object.len() > 4096
        || object.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > 1024
                || value.as_str().is_none_or(|value| {
                    value.len() > 64 * 1024
                        || value.as_bytes().contains(&0)
                })
        })
    {
        return Err(PlanProtocolError::InvalidOwned(format!(
            "{description} is invalid or excessive",
        )));
    }
    Ok(())
}

fn parse_sha256_digest(value: &str) -> PlanResult<Digest> {
    let encoded = value.strip_prefix("sha256:").ok_or(
        PlanProtocolError::Invalid(
            "OCI digest algorithm is not sha256",
        ),
    )?;
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(PlanProtocolError::Invalid(
            "OCI sha256 digest is not canonical lowercase hexadecimal",
        ));
    }
    let mut digest = [0u8; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        *output = (hex_nibble(encoded.as_bytes()[index * 2])? << 4)
            | hex_nibble(encoded.as_bytes()[index * 2 + 1])?;
    }
    if digest == [0; 32] {
        return Err(PlanProtocolError::Invalid(
            "OCI sha256 digest is empty",
        ));
    }
    Ok(digest)
}

fn hex_nibble(value: u8) -> PlanResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(PlanProtocolError::Invalid(
            "OCI digest contains a non-hexadecimal nibble",
        )),
    }
}

fn require_file(
    filesystem: &FilesystemManifestV12,
    path: &str,
    digest: &Digest,
) -> PlanResult<()> {
    let entry = filesystem
        .entries
        .binary_search_by(|entry| entry.relative_path.as_str().cmp(path))
        .ok()
        .and_then(|index| filesystem.entries.get(index))
        .ok_or(PlanProtocolError::Invalid(
            "OCI layout references an undeclared file",
        ))?;
    if entry.kind != FilesystemEntryKind::RegularFile
        || &entry.content_sha256 != digest
    {
        return Err(PlanProtocolError::Invalid(
            "OCI layout file digest differs from artifact manifest",
        ));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> PlanResult<()> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4096
        || path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
        })
    {
        return Err(PlanProtocolError::Invalid(
            "artifact path is not canonical and relative",
        ));
    }
    Ok(())
}

fn hex_digest(digest: &Digest) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
