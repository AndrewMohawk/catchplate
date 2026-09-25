//! Exact generic payload inventory, not an output publisher or proof token.
//!
//! The actual reader must derive every byte count and hash from retained files
//! under the admitted output mount. This pure codec joins those observations
//! to the signed payload-path set. Controller streams, manifest and terminal
//! result are outside that set, so neither manifest nor result hashes itself.
//! Their actual storage still counts against the same signed output capacity.

use super::{canonical_bytes, sha256_bytes, Digest, PlanProtocolError, PlanResult};
use serde::Serialize;
use std::collections::BTreeSet;

pub const CONTROL_DIRECTORY: &str = ".serverware-controller-output-v12";
pub const STDOUT_NAME: &str = "stdout.bin";
pub const STDERR_NAME: &str = "stderr.bin";
pub const MANIFEST_NAME: &str = "manifest.json";
const CONTROL_PREFIX: &str = ".serverware-controller-";
const MANIFEST_SCHEMA: &str = "serverware.controllerBodyOutputs/v12";
const MAX_PATHS: usize = 256;
const MAX_PATH_BYTES: usize = 4096;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_COMPONENTS: usize = 32;
const MIB: u64 = 1024 * 1024;

/// Ordinary measured file data; accepting this value does not admit its origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputFileV12 {
    pub path: String,
    pub sha256: Digest,
    pub bytes: u64,
}

fn invalid(message: &'static str) -> PlanProtocolError {
    PlanProtocolError::Invalid(message)
}

/// Validate literal paths without normalizing or reordering the signed list.
pub fn validate_output_paths(paths: &[String]) -> PlanResult<()> {
    if paths.len() > MAX_PATHS {
        return Err(invalid("body output path set is excessive"));
    }
    let mut unique = BTreeSet::new();
    for path in paths {
        if path.is_empty() || path.len() > MAX_PATH_BYTES || !path.is_ascii()
            || path.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(invalid("body output path is not bounded printable ASCII"));
        }
        for (index, component) in path.split('/').enumerate() {
            if index >= MAX_COMPONENTS || component.is_empty()
                || component.len() > MAX_COMPONENT_BYTES
                || matches!(component, "." | "..")
                || (index == 0 && component.starts_with(CONTROL_PREFIX))
            {
                return Err(invalid("body output path is noncanonical or enters controller storage"));
            }
        }
        if !unique.insert(path.as_str()) {
            return Err(invalid("body output path set contains a duplicate"));
        }
    }
    for path in paths {
        for (index, _) in path.match_indices('/') {
            if unique.contains(&path[..index]) {
                return Err(invalid("body output file is an ancestor of another output"));
            }
        }
    }
    Ok(())
}

// These declaration orders are the exact sorted-key ASCII wire recipe. The
// native PostgreSQL subset uses these same record meanings, but retains its
// existing bare-array digest rather than this versioned generic envelope.
#[derive(Serialize)]
struct ManifestFile<'a> {
    bytes: u64,
    path: &'a str,
    sha256: String,
}

#[derive(Serialize)]
struct Manifest<'a> {
    files: Vec<ManifestFile<'a>>,
    schema: &'static str,
}

fn digest_text(digest: &Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for &byte in digest {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 15) as usize] as char);
    }
    value
}

/// Encode exactly the independently signed payload set and actual file data.
///
/// `maximum_bytes` is the caller's independently admitted aggregate capacity,
/// never a value learned from a manifest. The actual collector must also count
/// excluded controller files and enforce the signed mount/inode capacities.
pub fn manifest_bytes(paths: &[String], files: &[OutputFileV12],
    maximum_bytes: u64) -> PlanResult<Vec<u8>> {
    validate_output_paths(paths)?;
    if files.len() != paths.len() {
        return Err(invalid("body output observations differ from the signed path count"));
    }
    let mut expected: Vec<_> = paths.iter().map(String::as_str).collect();
    expected.sort_unstable();
    let mut observed: Vec<_> = files.iter().collect();
    observed.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    let mut total = 0u64;
    let mut records = Vec::with_capacity(observed.len());
    for (file, expected_path) in observed.into_iter().zip(expected) {
        if file.path != expected_path || file.sha256 == [0; 32] {
            return Err(invalid("body output lacks an exact signed path or actual file digest"));
        }
        total = total.checked_add(file.bytes)
            .ok_or_else(|| invalid("body output byte count overflows"))?;
        if total > maximum_bytes {
            return Err(invalid("body output originals exceed their signed byte capacity"));
        }
        records.push(ManifestFile {
            bytes: file.bytes,
            path: &file.path,
            sha256: digest_text(&file.sha256),
        });
    }
    // canonical_bytes applies the shared 4 MiB frame ceiling. Every key is
    // fixed and sorted; ASCII path values use serde's unique compact escaping.
    canonical_bytes(&Manifest { files: records, schema: MANIFEST_SCHEMA })
}

/// Project the exact native inventory from the same generic file observations.
/// This preserves the native bare-array recipe; it does not reconcile reports
/// or establish prepared-source, process, runtime or file-origin authority.
pub fn native_subset_sha256(files: &[OutputFileV12]) -> PlanResult<Digest> {
    if files.len() > MAX_PATHS
        || files.windows(2).any(|pair| pair[0].path >= pair[1].path)
    {
        return Err(invalid("native projection requires bounded sorted unique output observations"));
    }
    let expected = super::native_postgres_contract_v12::expected_output_paths();
    let selected: Vec<_> = files.iter().filter(|file|
        file.path == "native-postgres" || file.path.starts_with("native-postgres/")
    ).collect();
    if expected.len() != 33 || selected.len() != expected.len() {
        return Err(invalid("native projection lacks its exact source-owned 33-file subtree"));
    }
    let mut records = Vec::with_capacity(expected.len());
    for (file, path) in selected.into_iter().zip(&expected) {
        if &file.path != path || file.sha256 == [0; 32] {
            return Err(invalid("native projection contains an absent, extra or unmeasured source path"));
        }
        records.push(ManifestFile {
            bytes: file.bytes,
            path: &file.path,
            sha256: digest_text(&file.sha256),
        });
    }
    Ok(sha256_bytes(&canonical_bytes(&records)?))
}

/// Independent per-stream ceiling within the existing signed output capacity.
pub fn stream_byte_limit(output_bytes: u64) -> PlanResult<u64> {
    if output_bytes < 16 * MIB {
        return Err(invalid("body stream capacity is below the runner output minimum"));
    }
    Ok((output_bytes / 4).min(32 * MIB))
}
