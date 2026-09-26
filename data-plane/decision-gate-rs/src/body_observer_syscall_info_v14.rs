//! Read-only syscall metadata for the actual same-thread owned initial stop.
//!
//! The only target is namespace PID 1 admitted by the opaque wait owner. This
//! module cannot construct that owner, attach, resume, inspect tracee memory or
//! modify registers. Returned values are unsigned observations, not a complete
//! syscall history or proof that an operation has executed.
//!
//! Fixed ABI sources: Linux v6.6 include/uapi/linux/ptrace.h and kernel/ptrace.c
//! (ptrace_get_syscall_info*). The kernel returns the available prefix size,
//! excluding trailing union padding: NONE=24, ENTRY=80, EXIT=33, SECCOMP=84.
//! https://raw.githubusercontent.com/torvalds/linux/v6.6/include/uapi/linux/ptrace.h
//! https://raw.githubusercontent.com/torvalds/linux/v6.6/kernel/ptrace.c
//! https://man7.org/linux/man-pages/man2/ptrace.2.html

use super::body_observer_wait_acquire_v14::InitialNamespaceStopV14;
use crate::plan_protocol::{PlanProtocolError, PlanResult};
use std::mem::{offset_of, size_of};

const GET_SYSCALL_INFO: libc::c_uint = 0x420e;
const INFO_NONE: u8 = 0;
const INFO_ENTRY: u8 = 1;
const INFO_EXIT: u8 = 2;
const INFO_SECCOMP: u8 = 3;
const HEADER_BYTES: usize = 24;
const BUFFER_BYTES: usize = 88;

// Explicit padding gives the fixed buffer a wholly initialized byte view. The
// meaningful UAPI field offsets are independent of the tracee's audit ABI;
// syscall numbers and arguments remain uninterpreted kernel values.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawEntry {
    number: u64,
    arguments: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawExit {
    return_value: i64,
    is_error: u8,
    padding: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawSeccomp {
    number: u64,
    arguments: [u64; 6],
    ret_data: u32,
    padding: [u8; 4],
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
union RawPayload {
    entry: RawEntry,
    exit: RawExit,
    seccomp: RawSeccomp,
    bytes: [u8; 64],
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct RawInfo {
    operation: u8,
    // Linux v6.6 calls these pad[3]; newer UAPI names them reserved and flags.
    // Neither extension is admitted by this fixed reader: all three are zero.
    reserved: [u8; 3],
    audit_architecture: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    payload: RawPayload,
}

#[repr(C)]
union RawBuffer {
    info: RawInfo,
    bytes: [u8; BUFFER_BYTES],
}

// These are compile-time ABI joins, not runtime verification or a test result.
const _: [(); BUFFER_BYTES] = [(); size_of::<RawInfo>()];
const _: [(); BUFFER_BYTES] = [(); size_of::<RawBuffer>()];
const _: [(); HEADER_BYTES] = [(); offset_of!(RawInfo, payload)];
const _: [(); 4] = [(); offset_of!(RawInfo, audit_architecture)];
const _: [(); 8] = [(); offset_of!(RawInfo, instruction_pointer)];
const _: [(); 16] = [(); offset_of!(RawInfo, stack_pointer)];
const _: [(); 8] = [(); offset_of!(RawEntry, arguments)];
const _: [(); 8] = [(); offset_of!(RawExit, is_error)];
const _: [(); 56] = [(); offset_of!(RawSeccomp, ret_data)];

#[derive(Debug, Eq, PartialEq)]
pub(super) enum SyscallOperationV14 {
    None,
    Entry { number: u64, arguments: [u64; 6] },
    Exit { return_value: i64, is_error: bool },
    Seccomp { number: u64, arguments: [u64; 6], ret_data: u32 },
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct SyscallInfoV14 {
    pub(super) returned_bytes: usize,
    // Exact native kernel header bytes, including the checked reserved bytes.
    pub(super) raw_header: [u8; HEADER_BYTES],
    pub(super) audit_architecture: u32,
    pub(super) instruction_pointer: u64,
    pub(super) stack_pointer: u64,
    pub(super) operation: SyscallOperationV14,
}

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

pub(super) fn observe(stop: &InitialNamespaceStopV14, deadline: u64) -> PlanResult<SyscallInfoV14> {
    let deadline = deadline.min(stop.deadline());
    // The owner rechecks the creating process/TID, active target PID namespace,
    // live held parent/target pidfds and the real current initial ptrace stop.
    stop.verify_stopped(deadline)?;
    let mut buffer = RawBuffer { bytes: [0u8; BUFFER_BYTES] };
    let returned = unsafe {
        libc::ptrace(
            GET_SYSCALL_INFO as _,
            1,
            BUFFER_BYTES as *mut libc::c_void,
            (&mut buffer as *mut RawBuffer).cast::<libc::c_void>(),
        )
    };
    let error = (returned < 0).then(std::io::Error::last_os_error);
    // Recheck even on syscall failure. ESRCH, unsupported kernels and all other
    // errors deny; they do not prove final exit or justify a retry/fallback.
    stop.verify_stopped(deadline)?;
    if let Some(error) = error { return Err(error.into()); }
    let returned_bytes = usize::try_from(returned)
        .map_err(|_| invalid("syscall-info returned size does not fit its bounded buffer"))?;
    if !(HEADER_BYTES..=BUFFER_BYTES).contains(&returned_bytes) {
        return Err(invalid("syscall-info header is truncated or the kernel ABI exceeds its fixed buffer"));
    }
    // Every storage byte was initialized before the kernel wrote its prefix;
    // every typed field below is an integer or an explicitly padded union.
    let bytes = unsafe { buffer.bytes };
    let info = unsafe { buffer.info };
    let expected_bytes = match info.operation {
        INFO_NONE => HEADER_BYTES,
        INFO_ENTRY => HEADER_BYTES + size_of::<RawEntry>(),
        INFO_EXIT => HEADER_BYTES + offset_of!(RawExit, is_error) + size_of::<u8>(),
        INFO_SECCOMP => HEADER_BYTES + offset_of!(RawSeccomp, ret_data) + size_of::<u32>(),
        _ => return Err(invalid("syscall-info operation is outside the fixed kernel ABI")),
    };
    if returned_bytes != expected_bytes || info.reserved != [0u8; 3]
        || bytes[returned_bytes..].iter().any(|byte| *byte != 0) {
        return Err(invalid("syscall-info returned prefix, reserved bytes or untouched tail is inconsistent"));
    }
    let operation = match info.operation {
        INFO_NONE => SyscallOperationV14::None,
        INFO_ENTRY => {
            let entry = unsafe { info.payload.entry };
            SyscallOperationV14::Entry { number: entry.number, arguments: entry.arguments }
        }
        INFO_EXIT => {
            let exit = unsafe { info.payload.exit };
            if exit.is_error > 1 {
                return Err(invalid("syscall-info error flag is not the kernel Boolean"));
            }
            SyscallOperationV14::Exit { return_value: exit.return_value, is_error: exit.is_error == 1 }
        }
        INFO_SECCOMP => {
            let seccomp = unsafe { info.payload.seccomp };
            SyscallOperationV14::Seccomp {
                number: seccomp.number, arguments: seccomp.arguments, ret_data: seccomp.ret_data,
            }
        }
        _ => return Err(invalid("syscall-info operation changed after fixed ABI admission")),
    };
    let mut raw_header = [0u8; HEADER_BYTES];
    raw_header.copy_from_slice(&bytes[..HEADER_BYTES]);
    // Arch/IP/SP are meaningful observations, not admitted policy identities.
    // Zero is not invented as an invalid value, and syscall-number parity or
    // return-value sign is never used to infer the operation/error Boolean.
    let observed = SyscallInfoV14 { returned_bytes, raw_header,
        audit_architecture: info.audit_architecture,
        instruction_pointer: info.instruction_pointer, stack_pointer: info.stack_pointer, operation };
    stop.verify_stopped(deadline)?;
    Ok(observed)
}
