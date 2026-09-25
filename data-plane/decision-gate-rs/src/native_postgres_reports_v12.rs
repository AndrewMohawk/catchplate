//! Pure bounded success reconciliation of the fixed native PostgreSQL reports.
//!
//! Original reports are cooperative observations, not controller, execution or
//! destruction authority. The fixed FD owner must first authenticate the pinned
//! prepared manifest, remeasure all fifteen scripts, and collect the exact
//! stable output files/log hashes. This module never accepts a success token in
//! place of those original report bytes. Outer process/courier/runtime proofs
//! and complete generation destruction remain independent obligations.
//!
//! The original cluster report has only version and system identifier. The
//! closed PG settings are checked by the source-pinned runner/probe before that
//! report is made; they are not independently re-observed or invented here.

use super::{digest_hex, sha256, ControllerError, Digest, Result};
use crate::plan_protocol::native_postgres_contract_v12::{
    self as contract, NativePostgresContractV12, MAX_LOG_BYTES, MAX_REPORT_BYTES,
    MAX_SUMMARY_BYTES, SUITES, TOTAL_TESTS,
};
use serde_json::{json, Map, Value};

const MAX_JSON_DEPTH: usize = 16;
const MAX_JSON_NODES: usize = 16_384;
const MAX_COUNT: u64 = (1u64 << 31) - 1;
const RUNTIME_PATH: &str = "native-postgres/runtime-result.json";
const REPORT_SCHEMA: &str = "serverware.nativePostgresFixtureResult/v1";
const RUNTIME_SCHEMA: &str = "serverware.nativePostgresRuntimeResult/v1";
const COUNT_FIELDS: [&str; 17] = ["expected", "started", "stopped", "passed",
    "failed", "errored", "skipped", "expectedFailures", "unexpectedSuccesses",
    "incomplete", "notRun", "subtestsPassed", "subtestsFailed", "subtestsErrored",
    "subtestsSkipped", "auxiliaryErrors", "protocolErrors"];

#[derive(Clone, Debug)]
pub struct NativePostgresFileV12 {
    pub path: String,
    pub sha256: Digest,
    pub bytes: u64,
}

fn rejected(message: &'static str) -> ControllerError {
    ControllerError::Rejected(message)
}

fn require(condition: bool, message: &'static str) -> Result<()> {
    if !condition { return Err(rejected(message)); }
    Ok(())
}

fn object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Map<String, Value>> {
    let map = value.as_object().ok_or_else(|| rejected("native report object is absent"))?;
    require(map.len() == fields.len() && fields.iter().all(|name| map.contains_key(*name)),
        "native report object has missing or unknown fields")?;
    Ok(map)
}

fn array(value: &Value, count: usize) -> Result<&Vec<Value>> {
    let values = value.as_array().ok_or_else(|| rejected("native report array is absent"))?;
    require(values.len() == count, "native report inventory cardinality differs")?;
    Ok(values)
}

fn text(value: &Value, expected: &str) -> Result<()> {
    require(value.as_str() == Some(expected), "native report source identity or status differs")
}

fn count(value: &Value) -> Result<u64> {
    let value = value.as_u64().ok_or_else(|| rejected("native report count is not an exact integer"))?;
    require(value <= MAX_COUNT, "native report count exceeds its source bound")?;
    Ok(value)
}

fn true_value(value: &Value) -> Result<()> {
    require(value.as_bool() == Some(true), "native report requires exact successful lifecycle evidence")
}

fn digest_text(value: &Value, expected: &Digest) -> Result<()> {
    text(value, &format!("sha256:{}", digest_hex(expected)))
}

fn ascii_string(value: &str, output: &mut Vec<u8>) -> Result<()> {
    require(value.is_ascii(), "native report contains non-ASCII decoded text")?;
    output.push(b'"');
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in value.bytes() {
        match byte {
            b'"' => output.extend_from_slice(b"\\\""),
            b'\\' => output.extend_from_slice(b"\\\\"),
            b'\x08' => output.extend_from_slice(b"\\b"),
            b'\x0c' => output.extend_from_slice(b"\\f"),
            b'\n' => output.extend_from_slice(b"\\n"),
            b'\r' => output.extend_from_slice(b"\\r"),
            b'\t' => output.extend_from_slice(b"\\t"),
            0x20..=0x7e => output.push(byte),
            _ => {
                output.extend_from_slice(b"\\u00");
                output.push(HEX[(byte >> 4) as usize]);
                output.push(HEX[(byte & 15) as usize]);
            }
        }
    }
    output.push(b'"');
    Ok(())
}

fn canonical_into(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            let integer = number.as_u64().ok_or_else(|| rejected("native success report has a noninteger number"))?;
            output.extend_from_slice(integer.to_string().as_bytes());
        }
        Value::String(value) => ascii_string(value, output)?,
        Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 { output.push(b','); }
                canonical_into(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut names: Vec<_> = values.keys().collect();
            names.sort_unstable();
            for (index, name) in names.iter().enumerate() {
                if index != 0 { output.push(b','); }
                ascii_string(name, output)?;
                output.push(b':');
                canonical_into(&values[*name], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    canonical_into(value, &mut output)?;
    Ok(output)
}

fn original(raw: &[u8], maximum: usize) -> Result<Value> {
    require(!raw.is_empty() && raw.len() <= maximum && raw.is_ascii(),
        "native report originals are absent, oversized or non-ASCII")?;
    // Bound structural allocations before serde parsing. Delimiters in quoted
    // strings do not count. This is an upper bound on nodes, not a JSON parser.
    let (mut quoted, mut escaped, mut depth, mut nodes) = (false, false, 0usize, 1usize);
    for &byte in raw {
        if quoted {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { quoted = false; }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => { depth += 1; nodes += 1; }
                b'}' | b']' => {
                    depth = depth.checked_sub(1)
                        .ok_or_else(|| rejected("native report structure is unbalanced"))?;
                }
                b',' | b':' => nodes += 1,
                _ => {},
            }
            require(depth <= MAX_JSON_DEPTH && nodes <= MAX_JSON_NODES,
                "native report structure exceeds its source bound")?;
        }
    }
    require(!quoted && depth == 0, "native report structure is incomplete")?;
    let value: Value = serde_json::from_slice(raw)
        .map_err(|_| rejected("native report originals are not valid JSON"))?;
    // Exact reconstruction rejects duplicate keys as well as whitespace,
    // alternate escapes/numbers, and order drift. Success schemas use only
    // exact nonnegative integers and ASCII, matching Python's canonical form.
    require(canonical(&value)? == raw, "native report originals are not canonical or repeat keys")?;
    Ok(value)
}

fn file<'a>(files: &'a [NativePostgresFileV12], path: &str) -> Result<&'a NativePostgresFileV12> {
    files.iter().find(|item| item.path == path)
        .ok_or_else(|| rejected("native output file is absent from the actual fixed inventory"))
}

fn raw_file(files: &[NativePostgresFileV12], path: &str, raw: &[u8]) -> Result<()> {
    let observed = file(files, path)?;
    require(observed.bytes == raw.len() as u64 && observed.sha256 == sha256(raw),
        "native original report differs from its actual file observation")
}

fn fixture(index: usize, raw: &[u8], expected_source: &Digest) -> Result<()> {
    let value = original(raw, MAX_REPORT_BYTES)?;
    let report = object(&value, &["schema", "script", "sourceSha256", "expectedTestIds", "tests",
        "suiteStatus", "counts", "auxiliaryErrors", "protocolErrors"])?;
    let suite = &SUITES[index];
    text(&report["schema"], REPORT_SCHEMA)?;
    text(&report["script"], suite.script)?;
    digest_text(&report["sourceSha256"], expected_source)?;
    text(&report["suiteStatus"], "PASS")?;
    array(&report["auxiliaryErrors"], 0)?;
    array(&report["protocolErrors"], 0)?;
    let ids = array(&report["expectedTestIds"], suite.test_ids.len())?;
    let rows = array(&report["tests"], suite.test_ids.len())?;
    let mut subtests_passed = 0u64;
    for (position, expected_id) in suite.test_ids.iter().enumerate() {
        text(&ids[position], expected_id)?;
        let row = object(&rows[position], &["id", "started", "stopped", "status", "subtests"])?;
        text(&row["id"], expected_id)?;
        true_value(&row["started"])?;
        true_value(&row["stopped"])?;
        text(&row["status"], "PASS")?;
        let subtests = object(&row["subtests"], &["passed", "failed", "errored", "skipped"])?;
        subtests_passed = subtests_passed.checked_add(count(&subtests["passed"])? )
            .ok_or_else(|| rejected("native subtest count overflows"))?;
        for name in ["failed", "errored", "skipped"] {
            require(count(&subtests[name])? == 0, "native passing report contains negative subtests")?;
        }
    }
    let counts = object(&report["counts"], &COUNT_FIELDS)?;
    for name in COUNT_FIELDS {
        let expected = match name {
            "expected" | "started" | "stopped" | "passed" => suite.test_ids.len() as u64,
            "subtestsPassed" => subtests_passed,
            _ => 0,
        };
        require(count(&counts[name])? == expected, "native report count differs from original rows")?;
    }
    Ok(())
}

fn cluster(value: &Value) -> Result<()> {
    let cluster = object(value, &["server_version_num", "system_identifier"])?;
    let version = count(&cluster["server_version_num"])?;
    require((160_000..170_000).contains(&version), "native observed cluster is not PG16")?;
    let identifier = cluster["system_identifier"].as_str()
        .ok_or_else(|| rejected("native cluster identifier is not text"))?;
    require(!identifier.is_empty() && identifier.len() <= 20 && !identifier.starts_with('0')
        && identifier.bytes().all(|byte| byte.is_ascii_digit())
        && identifier.parse::<u64>().is_ok(), "native cluster identifier is not a canonical nonzero u64")
}

/// Reconcile original native success only; return the fixed-file inventory hash.
///
/// `files` are the FD reader's exact sorted 33 observations, not a proof token.
/// Its prepared manifest/source remeasurement and the actual generic outer
/// execution result remain mandatory. No lifecycle observation is fabricated.
pub fn reconcile(contract: &NativePostgresContractV12, summary: &[u8], reports: &[Vec<u8>],
    files: &[NativePostgresFileV12]) -> Result<Digest> {
    contract.validate().map_err(|error| ControllerError::InvalidOwned(error.to_string()))?;
    require(reports.len() == SUITES.len() && SUITES.len() == 15
        && SUITES.iter().map(|suite| suite.test_ids.len()).sum::<usize>() == TOTAL_TESTS,
        "native source suite or original report inventory differs")?;
    let paths = contract::expected_output_paths();
    require(files.len() == 33 && paths.len() == files.len(), "native output inventory is not exact33")?;
    for (observed, expected) in files.iter().zip(&paths) {
        require(&observed.path == expected, "native output files are missing, extra, duplicated or reordered")?;
        let maximum = if expected == RUNTIME_PATH { MAX_SUMMARY_BYTES }
            else if expected.starts_with("native-postgres/reports/") { MAX_REPORT_BYTES }
            else { MAX_LOG_BYTES };
        require(observed.bytes <= maximum as u64 && (observed.bytes > 0 || expected.ends_with(".log")),
            "native output actual file exceeds its source bound")?;
    }
    raw_file(files, RUNTIME_PATH, summary)?;
    let value = original(summary, MAX_SUMMARY_BYTES)?;
    let runtime = object(&value, &["schema", "runtimeStatus", "tests", "observedCluster", "sourceSha256",
        "sourceUnchanged", "processLogs", "fixtureProcesses", "postmasterCleanStopObserved",
        "directChildrenReaped", "externalDestructionRequired", "errors"])?;
    text(&runtime["schema"], RUNTIME_SCHEMA)?;
    text(&runtime["runtimeStatus"], "COMPLETE")?;
    for name in ["sourceUnchanged", "postmasterCleanStopObserved", "directChildrenReaped",
        "externalDestructionRequired"] { true_value(&runtime[name])?; }
    array(&runtime["errors"], 0)?;
    cluster(&runtime["observedCluster"])?;
    let sources = array(&runtime["sourceSha256"], SUITES.len())?;
    let processes = array(&runtime["fixtureProcesses"], SUITES.len())?;
    let batch = object(&runtime["tests"], &["tests_status", "expected_tests", "stopped_tests", "fixtures"])?;
    text(&batch["tests_status"], "PASS")?;
    require(count(&batch["expected_tests"])? == TOTAL_TESTS as u64
        && count(&batch["stopped_tests"])? == TOTAL_TESTS as u64,
        "native runtime does not account for every source test")?;
    let summaries = array(&batch["fixtures"], SUITES.len())?;
    for (index, suite) in SUITES.iter().enumerate() {
        let expected_source = &contract.source_sha256[index];
        digest_text(&sources[index], expected_source)?;
        let report_path = format!("native-postgres/reports/{index:02}.json");
        let log_path = format!("native-postgres/logs/{index:02}.log");
        raw_file(files, &report_path, &reports[index])?;
        fixture(index, &reports[index], expected_source)?;
        let process = object(&processes[index], &["script", "termination", "exitCode"])?;
        text(&process["script"], suite.script)?;
        text(&process["termination"], "exited")?;
        require(count(&process["exitCode"])? == 0, "native fixture process did not exit successfully")?;
        let item = object(&summaries[index], &["script", "tests_status", "stopped_tests",
            "source_sha256", "report_sha256", "log_sha256", "log_bytes"])?;
        text(&item["script"], suite.script)?;
        text(&item["tests_status"], "PASS")?;
        require(count(&item["stopped_tests"])? == suite.test_ids.len() as u64,
            "native fixture summary stopped count differs")?;
        digest_text(&item["source_sha256"], expected_source)?;
        digest_text(&item["report_sha256"], &file(files, &report_path)?.sha256)?;
        let log = file(files, &log_path)?;
        digest_text(&item["log_sha256"], &log.sha256)?;
        require(count(&item["log_bytes"])? == log.bytes, "native fixture summary log count differs")?;
    }
    let logs = array(&runtime["processLogs"], 17)?;
    for (index, item) in logs.iter().enumerate() {
        let path = if index == 0 { "logs/initdb.log".to_owned() }
            else if index == 16 { "logs/postgres.log".to_owned() }
            else { format!("logs/{:02}.log", index - 1) };
        let log = object(item, &["path", "sha256", "bytes", "complete"])?;
        text(&log["path"], &path)?;
        true_value(&log["complete"])?;
        let observed = file(files, &format!("native-postgres/{path}"))?;
        digest_text(&log["sha256"], &observed.sha256)?;
        require(count(&log["bytes"])? == observed.bytes, "native complete process log count differs")?;
    }
    let inventory: Vec<Value> = files.iter().map(|item| json!({
        "path": item.path, "sha256": format!("sha256:{}", digest_hex(&item.sha256)), "bytes": item.bytes,
    })).collect();
    // Exact canonical ASCII array, source-sorted paths and original file-byte
    // hashes/counts. This is an observation commitment, not a runtime receipt.
    Ok(sha256(&canonical(&Value::Array(inventory))?))
}
