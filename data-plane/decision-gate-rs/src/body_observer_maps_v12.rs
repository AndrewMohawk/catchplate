//! Bounded parsing of complete, original Linux `/proc/PID/maps` bytes.
//!
//! This module does not read a process, authorize a mapping, resolve a pathname,
//! or construct runtime evidence. Every row survives, including non-executable
//! and unsupported mappings. Display names are not backing-file identities:
//! `\\012` and ` (deleted)` are ambiguous kernel display conventions and remain
//! unchanged. A caller acquiring executable backing must use the actual inode
//! and mapping range, not this module's descriptive label classification.

use crate::plan_protocol::{PlanProtocolError, PlanResult};

pub(super) const MAX_MAPS_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_MAPPINGS: usize = 4096;
pub(super) const MAX_MAPPING_PATH_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MappingPermissionsV12 {
    pub(super) readable: bool,
    pub(super) writable: bool,
    pub(super) executable: bool,
    pub(super) shared: bool,
}

/// A label only. Even a recognized kernel-looking name is not an admission of
/// kernel provenance, anonymous backing, deletion state or executable safety.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum MappingKindV12 {
    Anonymous,
    Heap,
    Stack,
    ThreadStack,
    Vdso,
    Vvar,
    VvarVclock,
    Vsyscall,
    NamedAnonymous,
    NamedSharedAnonymous,
    Filesystem,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProcMappingV12 {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) offset: u64,
    pub(super) device_major: u32,
    pub(super) device_minor: u32,
    pub(super) inode: u64,
    pub(super) permissions: MappingPermissionsV12,
    pub(super) pathname: Vec<u8>,
    pub(super) kind: MappingKindV12,
}

fn invalid(message: &'static str) -> PlanProtocolError {
    PlanProtocolError::Invalid(message)
}

fn number(bytes: &[u8], radix: u64, maximum_digits: usize) -> PlanResult<u64> {
    if bytes.is_empty() || bytes.len() > maximum_digits {
        return Err(invalid("process maps numeric field exceeds its source width"));
    }
    let mut value = 0u64;
    for byte in bytes {
        let digit = match *byte {
            b'0'..=b'9' => (*byte - b'0') as u64,
            b'a'..=b'f' if radix == 16 => (*byte - b'a' + 10) as u64,
            _ => return Err(invalid("process maps numeric field has invalid syntax")),
        };
        value = value.checked_mul(radix).and_then(|old| old.checked_add(digit))
            .ok_or_else(|| invalid("process maps numeric field overflows"))?;
    }
    Ok(value)
}

fn pair(bytes: &[u8], separator: u8) -> PlanResult<(&[u8], &[u8])> {
    let at = bytes.iter().position(|byte| *byte == separator)
        .ok_or_else(|| invalid("process maps paired field lacks its separator"))?;
    // Empty or additional components are rejected by the numeric parser.
    Ok((&bytes[..at], &bytes[at + 1..]))
}

fn field<'a>(remaining: &mut &'a [u8]) -> PlanResult<&'a [u8]> {
    let bytes = *remaining;
    let end = bytes.iter().position(|byte| *byte == b' ')
        .ok_or_else(|| invalid("process maps row lacks a complete field separator"))?;
    if end == 0 {
        return Err(invalid("process maps header has an empty field"));
    }
    *remaining = &bytes[end + 1..];
    Ok(&bytes[..end])
}

fn permissions(bytes: &[u8]) -> PlanResult<MappingPermissionsV12> {
    if bytes.len() != 4
        || !matches!(bytes[0], b'r' | b'-')
        || !matches!(bytes[1], b'w' | b'-')
        || !matches!(bytes[2], b'x' | b'-')
        || !matches!(bytes[3], b'p' | b's') {
        return Err(invalid("process maps permissions have invalid syntax"));
    }
    Ok(MappingPermissionsV12 {
        readable: bytes[0] == b'r', writable: bytes[1] == b'w',
        executable: bytes[2] == b'x', shared: bytes[3] == b's',
    })
}

fn named(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes.starts_with(prefix) && bytes.len() > prefix.len() && bytes.ends_with(b"]")
}

fn kind(pathname: &[u8]) -> MappingKindV12 {
    match pathname {
        b"" => MappingKindV12::Anonymous,
        b"[heap]" => MappingKindV12::Heap,
        b"[stack]" => MappingKindV12::Stack,
        b"[vdso]" => MappingKindV12::Vdso,
        b"[vvar]" => MappingKindV12::Vvar,
        b"[vvar_vclock]" => MappingKindV12::VvarVclock,
        b"[vsyscall]" => MappingKindV12::Vsyscall,
        _ if named(pathname, b"[stack:")
            && pathname[b"[stack:".len()..pathname.len() - 1]
                .iter().all(u8::is_ascii_digit)
            && pathname.len() > b"[stack:]".len() => MappingKindV12::ThreadStack,
        _ if named(pathname, b"[anon:") => MappingKindV12::NamedAnonymous,
        _ if named(pathname, b"[anon_shmem:") => MappingKindV12::NamedSharedAnonymous,
        _ if pathname.starts_with(b"/") => MappingKindV12::Filesystem,
        _ => MappingKindV12::Unsupported,
    }
}

fn row(original: &[u8]) -> PlanResult<ProcMappingV12> {
    let mut remaining = original;
    let (start, end) = pair(field(&mut remaining)?, b'-')?;
    let start = number(start, 16, 16)?;
    let end = number(end, 16, 16)?;
    if start >= end {
        return Err(invalid("process maps range is empty or reversed"));
    }
    let permissions = permissions(field(&mut remaining)?)?;
    let offset = number(field(&mut remaining)?, 16, 16)?;
    let (major, minor) = pair(field(&mut remaining)?, b':')?;
    let device_major = u32::try_from(number(major, 16, 8)?)
        .map_err(|_| invalid("process maps device major overflows"))?;
    let device_minor = u32::try_from(number(minor, 16, 8)?)
        .map_err(|_| invalid("process maps device minor overflows"))?;
    let inode = number(field(&mut remaining)?, 10, 20)?;
    // show_vma_header_prefix emits literal single-space separators, including
    // after the inode even when no name follows. seq_pad may then align the
    // pathname using additional spaces. Do not treat tabs or any bytes within
    // the remaining display pathname as whitespace to normalize or unescape.
    let path_start = remaining.iter().position(|byte| *byte != b' ')
        .unwrap_or(remaining.len());
    let pathname = &remaining[path_start..];
    if pathname.len() > MAX_MAPPING_PATH_BYTES {
        return Err(invalid("process maps pathname exceeds its source bound"));
    }
    Ok(ProcMappingV12 {
        start, end, offset, device_major, device_minor, inode, permissions,
        kind: kind(pathname), pathname: pathname.to_vec(),
    })
}

/// Parse every row, not merely executable rows. A final newline is required so
/// a size-limited or otherwise truncated last row cannot look complete. All
/// returned data is ordinary observation data, not proof of process identity,
/// stable mappings, file custody, closure membership or continuous coverage.
pub(super) fn parse_maps_original(original: &[u8]) -> PlanResult<Vec<ProcMappingV12>> {
    if original.is_empty() || original.len() > MAX_MAPS_BYTES
        || original.last() != Some(&b'\n') || original.contains(&0) {
        return Err(invalid("process maps original is incomplete or exceeds its source bound"));
    }
    let mut mappings: Vec<ProcMappingV12> = Vec::new();
    for line in original[..original.len() - 1].split(|byte| *byte == b'\n') {
        if mappings.len() == MAX_MAPPINGS {
            return Err(invalid("process maps row count exceeds its source bound"));
        }
        let mapping = row(line)?;
        if mappings.last().is_some_and(|previous| mapping.start < previous.end) {
            return Err(invalid("process maps rows are unordered or overlap"));
        }
        mappings.push(mapping);
    }
    Ok(mappings)
}
