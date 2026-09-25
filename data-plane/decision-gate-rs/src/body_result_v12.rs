//! Shared bounded original-byte body result codec; not an execution observer.
//!
//! Wire JSON has sorted ASCII object keys and integer numbers. The historical
//! terminal commitment deliberately keeps typed field order with only its own
//! digest zeroed. The separate acyclic body-claims projection replaces runtime
//! evidence with its ordinary-claims digest and excludes the terminal digest.
//! Its join to an observer claim does not verify that observer's signature or
//! establish any process observation; the actual configured consumer must still
//! independently admit runtime authority, scope and all static measurements.

use crate::plan_protocol::{
    sha256_bytes, Digest, LogicalLane, OciObjectReference, PlanProtocolError,
    PlanResult, MAX_FRAME_BYTES, MAX_OCI_OBJECTS,
};
use crate::runtime_evidence::{RunnerRuntimeEvidenceV12, StaticExecutableEvidenceV12};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;

pub const BODY_RESULT_VERSION_V12: &str = "serverware/controller-plan-executor-result/v12";
pub const MAX_BODY_RESULT_BYTES_V12: usize = MAX_FRAME_BYTES;
const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 1_000_000;
// Match the actual runtime evidence's fixed mapping/path limits. These are
// allocation bounds, not a replacement for its measured/signature admission.
const MAX_MAPPINGS: usize = 4096;
const MAX_MAPPING_PATH_BYTES: usize = 4096;

// Preserve this exact order: the existing terminal recipe is typed JSON, not
// the independently checked sorted-key wire representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BodyExecutionResultV12 {
    pub version: String,
    pub plan_id: Digest,
    pub lane: LogicalLane,
    pub body_sha256: Digest,
    pub command_sha256: Digest,
    pub exit_status: i32,
    pub stdout_sha256: Digest,
    pub stderr_sha256: Digest,
    pub output_manifest_sha256: Digest,
    pub runner_static_evidence: StaticExecutableEvidenceV12,
    pub courier_static_evidence: StaticExecutableEvidenceV12,
    pub runner_evidence: RunnerRuntimeEvidenceV12,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_postgres_output_sha256: Option<Digest>,
    pub terminal_sha256: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BodyClaimsV12<'a> {
    version: &'a str,
    plan_id: &'a Digest,
    lane: LogicalLane,
    body_sha256: &'a Digest,
    command_sha256: &'a Digest,
    exit_status: i32,
    stdout_sha256: &'a Digest,
    stderr_sha256: &'a Digest,
    output_manifest_sha256: &'a Digest,
    runner_static_evidence: &'a StaticExecutableEvidenceV12,
    courier_static_evidence: &'a StaticExecutableEvidenceV12,
    runner_evidence: Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    native_postgres_output_sha256: Option<Digest>,
}

fn invalid(message: &'static str) -> PlanProtocolError {
    PlanProtocolError::Invalid(message)
}

// Reject the next write before reserving memory. serde_json::to_vec would
// allocate the entire supplied graph before its caller could check the cap.
struct BoundedOutput { bytes: Vec<u8> }

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let needed = self.bytes.len().checked_add(bytes.len())
            .filter(|length| *length <= MAX_BODY_RESULT_BYTES_V12)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData,
                "body result encoding exceeds its fixed frame bound"))?;
        if needed > self.bytes.capacity() {
            let target = needed.max(self.bytes.capacity().max(4096)
                .saturating_mul(2).min(MAX_BODY_RESULT_BYTES_V12));
            self.bytes.try_reserve_exact(target - self.bytes.len())
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other,
                    "body result bounded allocation failed"))?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

fn typed_bytes<T: Serialize>(value: &T) -> PlanResult<Vec<u8>> {
    let mut output = BoundedOutput { bytes: Vec::new() };
    serde_json::to_writer(&mut output, value)?;
    preflight(&output.bytes)?;
    Ok(output.bytes)
}

fn bounded_text(value: &str, maximum: usize, total: &mut usize) -> PlanResult<()> {
    if value.len() > maximum {
        return Err(invalid("body result string exceeds its structural bound"));
    }
    *total = total.checked_add(value.len())
        .filter(|length| *length <= MAX_BODY_RESULT_BYTES_V12)
        .ok_or_else(|| invalid("body result aggregate strings exceed the frame bound"))?;
    Ok(())
}

fn bounded_oci(value: &OciObjectReference, total: &mut usize) -> PlanResult<()> {
    bounded_text(&value.repository, 256, total)?;
    // Existing platform grammar: linux/architecture[/variant], with 64/32
    // byte components. This bound does not interpret or admit that grammar.
    bounded_text(&value.platform, 5 + 1 + 64 + 1 + 32, total)
}

fn preflight(bytes: &[u8]) -> PlanResult<()> {
    if bytes.is_empty() || bytes.len() > MAX_BODY_RESULT_BYTES_V12 {
        return Err(invalid("body result original exceeds the fixed frame bound"));
    }
    let (mut quoted, mut escaped, mut primitive) = (false, false, false);
    let (mut depth, mut nodes) = (0usize, 0usize);
    for &byte in bytes {
        if quoted {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { quoted = false; }
            continue;
        }
        match byte {
            b'"' => { quoted = true; primitive = false; nodes += 1; }
            b'{' | b'[' => { depth += 1; nodes += 1; primitive = false; }
            b'}' | b']' => {
                depth = depth.checked_sub(1)
                    .ok_or_else(|| invalid("body result JSON delimiters are unbalanced"))?;
                primitive = false;
            }
            b',' | b':' | b' ' | b'\t' | b'\r' | b'\n' => primitive = false,
            _ => {
                if !primitive { nodes += 1; primitive = true; }
            }
        }
        if depth > MAX_DEPTH || nodes > MAX_NODES {
            return Err(invalid("body result JSON structure exceeds its fixed bound"));
        }
    }
    if quoted || depth != 0 {
        return Err(invalid("body result original has incomplete JSON structure"));
    }
    Ok(())
}

fn write_wire(value: &Value, output: &mut BoundedOutput) -> PlanResult<()> {
    match value {
        Value::Null => output.write_all(b"null")?,
        Value::Bool(true) => output.write_all(b"true")?,
        Value::Bool(false) => output.write_all(b"false")?,
        Value::Number(number) => {
            if let Some(integer) = number.as_u64() {
                output.write_all(integer.to_string().as_bytes())?;
            } else if let Some(integer) = number.as_i64() {
                output.write_all(integer.to_string().as_bytes())?;
            } else {
                return Err(invalid("body result wire forbids floating-point numbers"));
            }
        }
        Value::String(value) => serde_json::to_writer(&mut *output, value)?,
        Value::Array(values) => {
            output.write_all(b"[")?;
            for (index, item) in values.iter().enumerate() {
                if index != 0 { output.write_all(b",")?; }
                write_wire(item, output)?;
            }
            output.write_all(b"]")?;
        }
        Value::Object(values) => {
            let mut names: Vec<_> = values.keys().collect();
            if names.iter().any(|name| !name.is_ascii()) {
                return Err(invalid("body result wire requires ASCII object field names"));
            }
            names.sort_unstable();
            output.write_all(b"{")?;
            for (index, name) in names.iter().enumerate() {
                if index != 0 { output.write_all(b",")?; }
                serde_json::to_writer(&mut *output, *name)?;
                output.write_all(b":")?;
                write_wire(&values[*name], output)?;
            }
            output.write_all(b"}")?;
        }
    }
    Ok(())
}

fn wire_bytes(value: &Value) -> PlanResult<Vec<u8>> {
    let mut output = BoundedOutput { bytes: Vec::new() };
    write_wire(value, &mut output)?;
    Ok(output.bytes)
}

impl BodyExecutionResultV12 {
    // Closed nested types have no recursive or caller-defined map shape. Own
    // every variable-length bound before serialization, cloning or Value
    // construction; the shared preflight additionally bounds depth and nodes.
    fn bounded_structure(&self) -> PlanResult<()> {
        let runtime = &self.runner_evidence;
        let observer = &runtime.observer;
        if runtime.executable_mappings.len() > MAX_MAPPINGS
            || observer.mappings.len() > MAX_MAPPINGS
            || runtime.artifacts.as_ref().is_some_and(|value| value.oci_objects.len() > MAX_OCI_OBJECTS) {
            return Err(invalid("body result collection exceeds its structural bound"));
        }
        let mut total = 0;
        bounded_text(&self.version, BODY_RESULT_VERSION_V12.len(), &mut total)?;
        bounded_oci(&runtime.runner, &mut total)?;
        if let Some(artifacts) = &runtime.artifacts {
            for object in &artifacts.oci_objects { bounded_oci(object, &mut total)?; }
        }
        for mapping in &runtime.executable_mappings {
            if let Some(path) = &mapping.path {
                bounded_text(path, MAX_MAPPING_PATH_BYTES, &mut total)?;
            }
        }
        bounded_text(&observer.version,
            crate::runtime_evidence::AuthoritativeObserverEvidenceV12::VERSION.len(), &mut total)?;
        bounded_text(&observer.observer_key_id, 128, &mut total)?;
        bounded_text(&observer.observer_signature_b64, 88, &mut total)?;
        for mapping in &observer.mappings { bounded_text(&mapping.permissions, 4, &mut total)?; }
        Ok(())
    }

    /// Encode already supplied evidence without fixing or manufacturing any
    /// claim. The absent native option is omitted, exactly as in parse_original.
    /// Signature, process and static-executable admission remain independent.
    pub fn original_bytes(&self) -> PlanResult<Vec<u8>> {
        self.bounded_structure()?;
        let typed = typed_bytes(self)?;
        self.validate_terminal()?;
        let value: Value = serde_json::from_slice(&typed)?;
        wire_bytes(&value)
    }

    /// Admit bounded closed original wire, without accepting re-encoded input.
    pub fn parse_original(bytes: &[u8]) -> PlanResult<Self> {
        preflight(bytes)?;
        let value: Value = serde_json::from_slice(bytes)?;
        // A duplicate key cannot survive this exact comparison: its original
        // repeated member is absent from the reconstructed sorted-key object.
        if wire_bytes(&value)? != bytes {
            return Err(invalid("body result original is noncanonical or contains duplicate fields"));
        }
        let result: Self = serde_json::from_value(value)?;
        // Also reject ignored/defaulted spellings, such as explicit null for a
        // field whose typed canonical contract omits its absent value.
        if wire_bytes(&serde_json::to_value(&result)?)? != bytes {
            return Err(invalid("body result original differs from its exact typed wire"));
        }
        Ok(result)
    }

    /// Hash every ordinary body claim without introducing the observer cycle.
    pub fn claims_sha256(&self) -> PlanResult<Digest> {
        self.bounded_structure()?;
        // The runtime claims method preserves its own typed recipe. Bound its
        // complete original graph before that method's existing serialization.
        drop(typed_bytes(&self.runner_evidence)?);
        let projection = BodyClaimsV12 {
            version: &self.version,
            plan_id: &self.plan_id,
            lane: self.lane,
            body_sha256: &self.body_sha256,
            command_sha256: &self.command_sha256,
            exit_status: self.exit_status,
            stdout_sha256: &self.stdout_sha256,
            stderr_sha256: &self.stderr_sha256,
            output_manifest_sha256: &self.output_manifest_sha256,
            runner_static_evidence: &self.runner_static_evidence,
            courier_static_evidence: &self.courier_static_evidence,
            runner_evidence: self.runner_evidence.claims_sha256()?,
            native_postgres_output_sha256: self.native_postgres_output_sha256,
        };
        Ok(sha256_bytes(&typed_bytes(&projection)?))
    }

    /// Join acyclic observer claims and the unchanged typed terminal recipe.
    /// This is not observer signature verification or execution authorization.
    pub fn validate_terminal(&self) -> PlanResult<()> {
        if self.version != BODY_RESULT_VERSION_V12 || self.terminal_sha256 == [0; 32] {
            return Err(invalid("body result version or terminal digest is absent"));
        }
        let claims = self.claims_sha256()?;
        if claims == [0; 32] || self.runner_evidence.observer.body_claims_sha256 != claims {
            return Err(invalid("body result differs from its observer-bound ordinary claims"));
        }
        let mut copy = self.clone();
        copy.terminal_sha256 = [0; 32];
        if sha256_bytes(&typed_bytes(&copy)?) != self.terminal_sha256 {
            return Err(invalid("body result terminal digest is not canonical"));
        }
        Ok(())
    }
}
