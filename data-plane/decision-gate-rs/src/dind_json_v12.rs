//! Bounded canonical integer JSON for the v12 lifecycle's owned values.
//!
//! Object keys use UTF-16 ordering and strings use serde's JSON encoding.
//! Only exact i64/u64 numbers are accepted: this is a purpose-specific
//! integer profile, not an arbitrary floating-point RFC 8785/JCS encoder.
//! Values and object keys together are limited to one million nodes; the
//! root has depth zero and at most 64 nesting edges are permitted. A size
//! preflight precedes sorting and output allocation. This does not parse
//! original bytes or replace any caller's smaller source-specific bound.

use super::{ControllerError, Result};
use serde_json::{Number, Value};
use std::io::{self, Write};

const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 1_000_000;

struct Budget {
    bytes: usize,
    nodes: usize,
}

impl Budget {
    fn add_bytes(&mut self, count: usize) -> Result<()> {
        self.bytes = self.bytes.checked_add(count).filter(|total| *total <= MAX_BYTES)
            .ok_or(ControllerError::Rejected("v12 canonical JSON exceeds its byte bound"))?;
        Ok(())
    }

    fn node(&mut self, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH || self.nodes >= MAX_NODES {
            return Err(ControllerError::Rejected(
                "v12 canonical JSON exceeds its depth or node bound",
            ));
        }
        self.nodes += 1;
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<()> {
        // Escaping never shortens UTF-8. Reject oversized strings before
        // serde scans them; its bounded counting sink allocates no copy.
        if value.len().checked_add(2)
            .and_then(|size| self.bytes.checked_add(size))
            .filter(|total| *total <= MAX_BYTES).is_none()
        {
            return Err(ControllerError::Rejected(
                "v12 canonical JSON string exceeds its byte bound",
            ));
        }
        serde_json::to_writer(self, value).map_err(|_| ControllerError::Rejected(
            "v12 canonical JSON string exceeds its encoding bound",
        ))
    }
}

impl Write for Budget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.add_bytes(bytes.len()).map_err(|_| io::Error::new(
            io::ErrorKind::InvalidData, "v12 canonical JSON byte bound",
        ))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn integer(number: &Number) -> Result<String> {
    if let Some(value) = number.as_i64() {
        return Ok(value.to_string());
    }
    if let Some(value) = number.as_u64() {
        return Ok(value.to_string());
    }
    Err(ControllerError::Rejected(
        "v12 canonical JSON permits only exact i64 or u64 integers",
    ))
}

fn measure(value: &Value, depth: usize, budget: &mut Budget) -> Result<()> {
    budget.node(depth)?;
    match value {
        Value::Null => budget.add_bytes(4),
        Value::Bool(true) => budget.add_bytes(4),
        Value::Bool(false) => budget.add_bytes(5),
        Value::Number(number) => budget.add_bytes(integer(number)?.len()),
        Value::String(value) => budget.string(value),
        Value::Array(values) => {
            budget.add_bytes(2)?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 { budget.add_bytes(1)?; }
                measure(value, depth + 1, budget)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            budget.add_bytes(2)?;
            for (index, (key, value)) in object.iter().enumerate() {
                if index != 0 { budget.add_bytes(1)?; }
                budget.node(depth + 1)?;
                budget.string(key)?;
                budget.add_bytes(1)?;
                measure(value, depth + 1, budget)?;
            }
            Ok(())
        }
    }
}

fn write_string(value: &str, output: &mut Vec<u8>) -> Result<()> {
    serde_json::to_writer(output, value).map_err(|_| ControllerError::Invalid(
        "v12 canonical JSON string serialization failed",
    ))
}

fn write_value(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => output.extend_from_slice(integer(number)?.as_bytes()),
        Value::String(value) => write_string(value, output)?,
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 { output.push(b','); }
                write_value(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            // The complete preflight bounds this allocation and every key.
            // Iterator comparison avoids allocating UTF-16 copies per sort.
            let mut entries: Vec<_> = object.iter().collect();
            entries.sort_unstable_by(|(left, _), (right, _)| {
                left.encode_utf16().cmp(right.encode_utf16())
            });
            output.push(b'{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 { output.push(b','); }
                write_string(key, output)?;
                output.push(b':');
                write_value(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

pub(super) fn canonical_json_bytes_v12(value: &Value) -> super::Result<Vec<u8>> {
    let mut budget = Budget { bytes: 0, nodes: 0 };
    measure(value, 0, &mut budget)?;
    let mut output = Vec::with_capacity(budget.bytes);
    write_value(value, &mut output)?;
    if output.len() != budget.bytes {
        return Err(ControllerError::Invalid(
            "v12 canonical JSON measured and encoded sizes differ",
        ));
    }
    Ok(output)
}
