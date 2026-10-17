//! Fixed native PostgreSQL originals, read only through retained directory FDs.
//!
//! Prepared source pins come from the independently admitted runner contract.
//! Output reports are cooperative observations: their actual bytes/log hashes
//! do not replace the controller's process, courier, runtime or destruction
//! proofs. No path, source inventory, work allowance or deadline is supplied by
//! a report. Logs are streamed, not accumulated into one aggregate allocation.

use super::{canonical_json_bytes_v12, digest_hex, ControllerError, Digest, Result};
use super::body_output_files_v12::{live, Directory, Leaf, Policy};
use super::native_postgres_reports_v12::{self as reports, NativePostgresFileV12};
use crate::plan_protocol::native_postgres_contract_v12::{
    self as contract, NativePostgresContractV12, MAX_LOG_BYTES,
    MAX_MANIFEST_BYTES, MAX_REPORT_BYTES, MAX_SOURCE_BYTES, MAX_SUMMARY_BYTES, SUITES,
};
use serde_json::json;
use std::os::fd::RawFd;

const MANIFEST_NAME: &str = "native-postgres-sources-v1.json";
const MANIFEST_SCHEMA: &str = "catchplate.nativePostgresPreparedSources/v1";
const RUNTIME_NAME: &str = "runtime-result.json";

fn rejected(message: &'static str) -> ControllerError {
    ControllerError::Rejected(message)
}

/// Re-admit the fixed prepared manifest and all actual source scripts.
pub(super) fn admit_prepared(artifact_root: RawFd, source_root: RawFd,
    contract: &NativePostgresContractV12, deadline: u64) -> Result<()> {
    live(deadline)?;
    contract.validate().map_err(|error| ControllerError::InvalidOwned(error.to_string()))?;
    let artifacts = Directory::root(artifact_root, Policy::Prepared, deadline)?;
    let sources = Directory::root(source_root, Policy::Prepared, deadline)?;
    let scripts = sources.child("scripts", deadline)?;
    let mut manifest = Leaf::open(&artifacts, MANIFEST_NAME, 2, MAX_MANIFEST_BYTES, deadline)?;
    let (manifest_digest, original) = manifest.read(true, deadline)?;
    if manifest_digest != contract.prepared_sources_sha256 {
        return Err(rejected("native prepared manifest differs from its independent signed pin"));
    }
    let rows: Vec<_> = SUITES.iter().zip(&contract.source_sha256).map(|(suite, digest)|
        json!({"path": suite.script, "sha256": format!("sha256:{}", digest_hex(digest))})).collect();
    // Construct the one permitted canonical document instead of accepting a
    // parsed manifest's inventory. All strings here are fixed ASCII or hex.
    live(deadline)?;
    let expected = canonical_json_bytes_v12(&json!({"schema": MANIFEST_SCHEMA, "scripts": rows}))?;
    if expected.len() > MAX_MANIFEST_BYTES || original != expected {
        return Err(rejected("native prepared manifest is not the exact canonical source inventory"));
    }
    live(deadline)?;
    let mut retained = Vec::with_capacity(SUITES.len());
    for (suite, expected) in SUITES.iter().zip(&contract.source_sha256) {
        live(deadline)?;
        let name = suite.script.strip_prefix("scripts/")
            .ok_or_else(|| rejected("native suite escaped its fixed scripts directory"))?;
        let mut source = Leaf::open(&scripts, name, 1, MAX_SOURCE_BYTES, deadline)?;
        let (observed, _) = source.read(false, deadline)?;
        if observed != *expected {
            return Err(rejected("native actual script differs from its independent prepared pin"));
        }
        retained.push(source);
    }
    for source in &retained { source.verify(deadline)?; }
    manifest.verify(deadline)?;
    scripts.verify(deadline)?;
    sources.verify(deadline)?;
    artifacts.verify(deadline)?;
    live(deadline)
}

/// Read actual fixed originals, reconcile them, and commit their exact inventory.
pub(super) fn collect(output_root: RawFd, uid: u32, gid: u32,
    contract: &NativePostgresContractV12, deadline: u64) -> Result<Digest> {
    live(deadline)?;
    contract.validate().map_err(|error| ControllerError::InvalidOwned(error.to_string()))?;
    if uid == 0 || gid == 0 { return Err(rejected("native output requires an admitted nonroot owner")); }
    let root = Directory::root(output_root, Policy::Output { uid, gid }, deadline)?;
    let native = root.child("native-postgres", deadline)?;
    let report_dir = native.child("reports", deadline)?;
    let log_dir = native.child("logs", deadline)?;
    let native_names = vec!["runtime-result.json".to_owned(), "reports".to_owned(), "logs".to_owned()];
    let report_names: Vec<_> = (0..SUITES.len()).map(|index| format!("{index:02}.json")).collect();
    let paths = contract::expected_output_paths();
    let log_names: Vec<_> = paths.iter().filter_map(|path|
        path.strip_prefix("native-postgres/logs/").map(str::to_owned)).collect();
    if paths.len() != 33 || report_names.len() != 15 || log_names.len() != 17 {
        return Err(rejected("native source output inventory cardinality changed"));
    }
    native.inventory(&native_names, deadline)?;
    report_dir.inventory(&report_names, deadline)?;
    log_dir.inventory(&log_names, deadline)?;
    let mut retained = Vec::with_capacity(paths.len());
    let mut files = Vec::with_capacity(paths.len());
    let mut runtime = Leaf::open(&native, RUNTIME_NAME, 2, MAX_SUMMARY_BYTES, deadline)?;
    let (digest, summary) = runtime.read(true, deadline)?;
    files.push(NativePostgresFileV12 { path: format!("native-postgres/{RUNTIME_NAME}"),
        sha256: digest, bytes: runtime.byte_count() });
    retained.push(runtime);
    let mut originals = Vec::with_capacity(SUITES.len());
    for name in &report_names {
        let mut report = Leaf::open(&report_dir, name, 2, MAX_REPORT_BYTES, deadline)?;
        let (digest, bytes) = report.read(true, deadline)?;
        files.push(NativePostgresFileV12 { path: format!("native-postgres/reports/{name}"),
            sha256: digest, bytes: report.byte_count() });
        originals.push(bytes);
        retained.push(report);
    }
    for name in &log_names {
        // Empty logs are genuine files with the actual SHA256(empty), not
        // absent observations. Only this one bounded chunk buffer is used.
        let mut log = Leaf::open(&log_dir, name, 0, MAX_LOG_BYTES, deadline)?;
        let (digest, _) = log.read(false, deadline)?;
        files.push(NativePostgresFileV12 { path: format!("native-postgres/logs/{name}"),
            sha256: digest, bytes: log.byte_count() });
        retained.push(log);
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    live(deadline)?;
    let result = reports::reconcile(contract, &summary, &originals, &files)?;
    live(deadline)?;
    for original in &retained { original.verify(deadline)?; }
    native.inventory(&native_names, deadline)?;
    report_dir.inventory(&report_names, deadline)?;
    log_dir.inventory(&log_names, deadline)?;
    log_dir.verify(deadline)?;
    report_dir.verify(deadline)?;
    native.verify(deadline)?;
    root.verify(deadline)?;
    live(deadline)?;
    Ok(result)
}
