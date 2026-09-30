//! One-shot independent generation-origin launch. Its signed origin is not a parent
//! reap/retirement receipt; exit zero separately requires actual full cleanup.
use super::{child, ensure, interrupted, nonblocking, parent_security, pipe, release_gate,
    spawn, stop_and_retire, time_inputs::Inputs, Watchdog};
use crate::native_shadow_verifier_runtime_v1::{RuntimeAdmission, RunningRuntime};
use std::os::fd::{AsFd, AsRawFd, RawFd};

fn terminal(owner: &RunningRuntime, input: &Inputs, output: RawFd, watch: &Watchdog) -> Result<(), String> {
    let mut eof = false;
    loop {
        watch.check()?; input.check()?;
        let mut events = [libc::pollfd { fd: owner.child_pidfd().as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: if eof { -1 } else { output }, events: libc::POLLIN, revents: 0 }];
        let result = unsafe { libc::poll(events.as_mut_ptr(), events.len() as libc::nfds_t, 25) };
        if result < 0 { if interrupted() { continue; } return Err("issuer terminal poll failed".to_owned()); }
        watch.check()?; input.check()?;
        ensure(events.iter().all(|event| event.revents & (libc::POLLERR | libc::POLLNVAL) == 0),
            "issuer terminal owner/channel changed")?;
        if !eof && events[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let mut byte = 0u8;
            let count = unsafe { libc::read(output, (&mut byte as *mut u8).cast(), 1) };
            if count < 0 && (interrupted() || super::would_block()) { continue; }
            ensure(count == 0, "issuer stdout is not an output/secret channel")?;
            eof = true;
        }
        if eof && events[0].revents & libc::POLLIN != 0 {
            owner.check_after_exit()?; input.check()?; return watch.check();
        }
    }
}
fn execute(admission: RuntimeAdmission, input: &Inputs, watch: &Watchdog) -> Result<(), String> {
    let mut runtime = admission.prepare()?;
    watch.check()?; runtime.check()?; input.check_connected()?;
    let (output_read, output_write) = pipe()?; let (gate_read, gate_write) = pipe()?;
    nonblocking(output_read.as_raw_fd())?; nonblocking(gate_write.as_raw_fd())?;
    let prepared = {
        let inherited = runtime.inheritance()?;
        child::PreparedChild::prepare_origin(&inherited, input.seed(), input.socket(), output_write.as_fd(), gate_read.as_fd())?
    };
    let (pidfd, pid) = spawn(&prepared, watch)?;
    drop(prepared); drop(output_write); drop(gate_read);
    let owner = match runtime.bind_child(pidfd, pid) {
        Ok(owner) => owner,
        Err(failure) => {
            let _ = stop_and_retire(failure.into_cleanup(), watch);
            return Err("issuer child binding failed".to_owned());
        }
    };
    let observed = (|| {
        owner.check()?; watch.check()?; input.check_connected()?;
        release_gate(gate_write.as_raw_fd(), watch)?; drop(gate_write);
        terminal(&owner, input, output_read.as_raw_fd(), watch)
    })();
    if let Err(error) = observed { let _ = stop_and_retire(owner, watch); return Err(error); }
    let retired = match owner.retire() {
        Ok(retired) => retired,
        Err(failure) => {
            let _ = stop_and_retire(failure.into_cleanup(), watch);
            return Err("issuer actual child/root retirement failed".to_owned());
        }
    };
    ensure(retired.code() == libc::CLD_EXITED && retired.status() == 0, "issuer child did not exit successfully")?;
    input.check()?; watch.check()
}
fn attempt() -> Result<(), String> {
    ensure(std::env::args_os().count() == 1 && std::env::vars_os().next().is_none(),
        "issuer supervisor accepts no arguments or environment")?;
    parent_security()?;
    // Actual FD4/5 slots retained before admission can occupy an unused slot.
    let mut input = Inputs::take()?;
    let admission = RuntimeAdmission::open_origin_issuer()?;
    let watch = Watchdog::arm(&admission)?;
    input.bind_origin(&admission)?;
    execute(admission, &input, &watch)
}
pub(super) fn run() -> ! {
    let status = if attempt().is_ok() { 0 } else { 1 };
    // No sensitive text, automatic restart, renewed allowance or cleanup
    // receipt inferred from a failure. The original timer stays armed.
    unsafe { libc::_exit(status) }
}
