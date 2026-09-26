//! Pure, closed classification of Linux waitpid status words.
//!
//! The caller must own an actual successful wait observation and its namespace
//! TID. These ordinary values do not prove a wait occurred or authorize any
//! process operation. In particular PTRACE_EVENT_EXIT is an early live stop,
//! never a final exit; an eventless SIGTRAP is not a proven syscall stop; and
//! stopping-signal candidates need real acquisition metadata to disambiguate.
//! No syscall, I/O, serde, signal injection, resume, signing or lifecycle
//! transition is performed here.
//!
//! Encoding references: Linux include/uapi/linux/ptrace.h, glibc
//! bits/waitstatus.h, and ptrace(2)/wait(2). Unknown future event encodings are
//! rejected, not folded into an existing supported class.

use crate::plan_protocol::{PlanProtocolError, PlanResult};

const STOP_MARKER: u32 = 0x7f;
const CONTINUED_STATUS: u32 = 0xffff;
const CORE_FLAG: u32 = 0x80;
const MAX_SIGNAL: u32 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(super) enum PtraceEventV14 {
    Fork = 1,
    Vfork = 2,
    Clone = 3,
    Exec = 4,
    VforkDone = 5,
    /// The tracee has not yet completed its exit. GETEVENTMSG is metadata,
    /// not a replacement for a later genuine final wait status.
    Exit = 6,
    Seccomp = 7,
    /// Interrupt, automatically attached child, or seized group-stop candidate.
    Stop = 128,
}

impl PtraceEventV14 {
    pub(super) fn kernel_code(self) -> u32 { self as u32 }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WaitKindV14 {
    Exited { code: u8 },
    /// core_dumped preserves the status bit, not custody of any core artifact.
    Signaled { signal: u32, core_dumped: bool },
    PtraceEvent { event: PtraceEventV14, stop_signal: u32 },
    /// TRACESYSGOOD encoding only; entry/exit direction is not in this word.
    SyscallStop,
    /// SIGTRAP can also denote a breakpoint or an unmarked syscall stop.
    /// Only the four stopping signals can be group-stop candidates.
    SignalStopCandidate { signal: u32, may_be_group_stop: bool },
    Continued,
}

/// Opaque construction preserves the exact original integer and namespace TID.
/// This is intentionally not a serializable or independently trusted receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WaitObservationV14 {
    namespace_tid: u32,
    original_status: i32,
    kind: WaitKindV14,
}

impl WaitObservationV14 {
    pub(super) fn namespace_tid(&self) -> u32 { self.namespace_tid }
    pub(super) fn original_status(&self) -> i32 { self.original_status }
    pub(super) fn kind(&self) -> WaitKindV14 { self.kind }
}

/// A waitpid WNOHANG return of zero has no observation and must never reach
/// this function with a substituted TID. Status zero with an actual positive
/// wait return is instead a legitimate final exit code zero.
pub(super) fn classify_wait_status(namespace_tid: u32, original_status: i32)
    -> PlanResult<WaitObservationV14> {
    if !(1..=i32::MAX as u32).contains(&namespace_tid) {
        return Err(invalid("wait observation has an invalid namespace TID"));
    }
    if original_status < 0 {
        return Err(invalid("wait observation has a negative or unsupported high-bit status"));
    }
    let raw = original_status as u32;
    // Supported final/continued statuses occupy the low 16 bits. Ptrace adds
    // only one closed event byte at bits 16..23; no other bits are ignored.
    if raw & 0xff00_0000 != 0 {
        return Err(invalid("wait observation contains unsupported status bits"));
    }
    let kind = if raw == CONTINUED_STATUS {
        WaitKindV14::Continued
    } else if raw & 0xff == STOP_MARKER {
        classify_stop(raw)?
    } else if raw & 0xff == 0 {
        if raw & !0xff00 != 0 {
            return Err(invalid("final exit status contains non-exit bits"));
        }
        WaitKindV14::Exited { code: ((raw >> 8) & 0xff) as u8 }
    } else {
        // Final signal status has only its seven-bit signal and optional core
        // flag. In particular a zero signal plus a core flag is not an exit.
        let signal = raw & 0x7f;
        if raw & !0xff != 0 || !(1..=MAX_SIGNAL).contains(&signal) {
            return Err(invalid("final signal status contains an invalid outcome or extra bits"));
        }
        WaitKindV14::Signaled { signal, core_dumped: raw & CORE_FLAG != 0 }
    };
    Ok(WaitObservationV14 { namespace_tid, original_status, kind })
}

fn classify_stop(raw: u32) -> PlanResult<WaitKindV14> {
    let signal = (raw >> 8) & 0xff;
    let event_code = raw >> 16;
    if event_code != 0 {
        let event = match event_code {
            1 => PtraceEventV14::Fork,
            2 => PtraceEventV14::Vfork,
            3 => PtraceEventV14::Clone,
            4 => PtraceEventV14::Exec,
            5 => PtraceEventV14::VforkDone,
            6 => PtraceEventV14::Exit,
            7 => PtraceEventV14::Seccomp,
            128 => PtraceEventV14::Stop,
            _ => return Err(invalid("wait observation contains an unsupported ptrace event")),
        };
        if signal != libc::SIGTRAP as u32
            && !(event == PtraceEventV14::Stop && stopping_signal(signal)) {
            return Err(invalid("ptrace event status has an incompatible stop signal"));
        }
        return Ok(WaitKindV14::PtraceEvent { event, stop_signal: signal });
    }
    if signal == (libc::SIGTRAP as u32 | 0x80) {
        return Ok(WaitKindV14::SyscallStop);
    }
    // SIGKILL never produces signal-delivery-stop. Its eventual final wait
    // status, or an earlier PTRACE_EVENT_EXIT, has a different closed shape.
    if !(1..=MAX_SIGNAL).contains(&signal) || signal == libc::SIGKILL as u32 {
        return Err(invalid("wait stop contains an invalid or unsupported signal encoding"));
    }
    Ok(WaitKindV14::SignalStopCandidate { signal, may_be_group_stop: stopping_signal(signal) })
}

fn stopping_signal(signal: u32) -> bool {
    signal == libc::SIGSTOP as u32 || signal == libc::SIGTSTP as u32
        || signal == libc::SIGTTIN as u32 || signal == libc::SIGTTOU as u32
}

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }
