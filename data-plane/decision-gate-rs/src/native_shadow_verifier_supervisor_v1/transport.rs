//! Fixed external connection entry; public evidence never supplies authority.
use super::{ensure, exchange::PendingExchange, execute, inputs::{Inputs, PendingSeed},
    parent_security, RuntimeAdmission, Watchdog};

fn attempt() -> Result<(), String> {
    ensure(std::env::args_os().count() == 1,
        "verifier transport supervisor accepts no arguments")?;
    parent_security()?;
    // Retain both inherited originals before any policy/image open. Taking the
    // seed does not allocate another descriptor. PendingExchange also requires
    // FD5 absent and moves only its actual inherited FD6 above child slots.
    let seed = PendingSeed::take()?;
    let pending = PendingExchange::take()?;
    let admission = RuntimeAdmission::open()?;
    let watch = Watchdog::arm(&admission)?;
    // The kernel timer is already armed from the independent original window.
    // Network receive cannot select a policy, replace time or extend this bound.
    let (exchange, evidence) = pending.receive(&admission,&watch)?;
    let mut inputs = Inputs::from_transport(seed,evidence)?;
    inputs.bind(&admission)?;
    exchange.check(&watch)?;
    // This shared private operation returns only after actual retained-original
    // terminal checks, same-PIDFD reap, successful mount retirement and exit0.
    // Any failure takes the original cleanup path and produces no result frame.
    let raw = execute(admission,&inputs,&watch)?;
    inputs.check()?; exchange.check(&watch)?;
    exchange.publish(&raw,&watch)
}

pub(super) fn run() -> ! {
    let status = if attempt().is_ok() { 0 } else { 1 };
    // No secret-bearing error text, output-pipe fallback or second exchange.
    // Partial publication is not a success claim; the guest requires its full
    // frame/EOF and independently admits the unchanged signed result original.
    unsafe { libc::_exit(status) }
}
