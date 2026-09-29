//! Consuming first-exec release and read-only continuation of the same child.
//! Neither a positive event nor the returned observations grant a second exec.

use super::{alive, boottime, identity, require, BlockedChild, ExecAcknowledgement,
    PTRACE_EVENT_EXEC, PTRACE_EVENT_STOP};
use super::super::{guardian::Guardian, network::NetworkReady};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

/// Fixed-memory output accounting. Raw application bytes are never included
/// in the control-plane observation or printed into the launcher's terminal.
pub(super) struct OutputState {
    digests: [Sha256; 2],
    lengths: [u64; 2],
    eof: [bool; 2],
    failed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in super::super) struct OutputObservation {
    stdout_bytes: u64,
    stdout_sha256: String,
    stderr_bytes: u64,
    stderr_sha256: String,
    complete: bool,
}

impl OutputState {
    pub(super) fn new() -> Self {
        Self { digests: [Sha256::new(), Sha256::new()], lengths: [0; 2], eof: [false; 2], failed: false }
    }

    pub(super) fn drain(&mut self, fds: [BorrowedFd<'_>; 2], remaining: &Cell<u64>)
        -> Result<bool, String>
    {
        require(!std::mem::replace(&mut self.failed, true), "native output accounting is stopped")?;
        let mut bytes = [0u8; 4096];
        // One bounded read from each stream; continuous stdout cannot starve
        // stderr, process observation, network checks or the absolute clock.
        for (index, fd) in fds.into_iter().enumerate() {
            if self.eof[index] { continue; }
            let count = unsafe { libc::read(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
            if count < 0 {
                require(std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN),
                    "native child bounded output read failed")?;
            } else if count == 0 {
                self.eof[index] = true;
            } else {
                let count = count as usize;
                remaining.set(remaining.get().checked_sub(count as u64)
                    .ok_or("native child exceeded signed combined output limit")?);
                self.lengths[index] = self.lengths[index].checked_add(count as u64)
                    .ok_or("native output byte counter overflow")?;
                self.digests[index].update(&bytes[..count]);
            }
        }
        self.failed = false;
        Ok(self.eof.iter().all(|value| *value))
    }

    fn observation(&self) -> Result<OutputObservation, String> {
        require(!self.failed && self.eof.iter().all(|value| *value),
            "native output is incomplete or exceeded its bound")?;
        Ok(OutputObservation { stdout_bytes: self.lengths[0],
            stdout_sha256: format!("sha256:{:x}", self.digests[0].clone().finalize()),
            stderr_bytes: self.lengths[1],
            stderr_sha256: format!("sha256:{:x}", self.digests[1].clone().finalize()), complete: true })
    }
}

impl BlockedChild {
    /// Only continuation of the positively acknowledged first executable.
    /// Signed stop is retained, not computed from now or borrowed from cleanup.
    pub(in super::super) fn check_continuation(&self) -> Result<(), String> {
        require(!self.continuation_stopped.replace(true) && self.release_attempted.get()
            && self.executed.get() && !self.cleanup_attempted.get(),
            "native child lacks live consumed-execution ownership")?;
        self.containment.check_continuation(self.leader.pid)?;
        self.leader.check()?;
        require(identity(self.launcher.as_fd())? == self.launcher_identity,
            "native running creator-thread pidfd changed")?;
        alive(self.launcher.as_fd())?;
        require(self.namespaces.len() == 5, "native running namespace originals are incomplete")?;
        for namespace in &self.namespaces { namespace.check(&self.leader)?; }
        require(boottime()? < self.stop_boottime_ns(), "native child signed stop boundary ended")?;
        self.continuation_stopped.set(false);
        Ok(())
    }

    pub(in super::super) fn stop_boottime_ns(&self) -> u64 {
        self.containment.owner().stop_boottime_ns()
    }

    pub(in super::super) fn finish_output(&self) -> Result<OutputObservation, String> {
        require(self.cleanup_attempted.get() && self.leader.reaped.get(),
            "native output completion requires the exact workload leader reap")?;
        let deadline = self.containment.owner().cleanup_boottime_ns();
        loop {
            require(boottime()? < deadline, "native output drain missed its original cleanup deadline")?;
            if self.drain_output()? {
                require(boottime()? < deadline, "native closing output missed cleanup deadline")?;
                return self.output.try_borrow().map_err(|_| "native output owner already borrowed")?
                    .observation();
            }
            self.wait_output_or_exit(deadline)?;
        }
    }

    fn wait_output_or_exit(&self, deadline: u64) -> Result<(), String> {
        let now = boottime()?;
        require(now < deadline, "native execution observation deadline ended")?;
        let output = self.output.try_borrow().map_err(|_| "native output owner already borrowed")?;
        let mut fds = [
            libc::pollfd { fd: if self.leader.reaped.get() { -1 } else { self.leader.pidfd.as_raw_fd() },
                events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: if output.eof[0] { -1 } else { self.stdout.as_raw_fd() },
                events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: if output.eof[1] { -1 } else { self.stderr.as_raw_fd() },
                events: libc::POLLIN, revents: 0 },
        ];
        drop(output);
        let timeout = libc::timespec { tv_sec: 0, tv_nsec: (deadline - now).min(20_000_000) as libc::c_long };
        require(unsafe { libc::ppoll(fds.as_mut_ptr(), fds.len() as libc::nfds_t,
            &timeout, std::ptr::null()) } >= 0
            && fds.iter().all(|fd| fd.revents & (libc::POLLNVAL | libc::POLLERR) == 0),
            "native execution bounded wait failed")?;
        require(boottime()? < deadline, "native execution closing wait exceeded original deadline")
    }

    fn abort_execution(&self, guardian: &Guardian) {
        self.continuation_stopped.set(true);
        guardian.request_stop();
        let _ = self.containment.attempt_emergency_kill();
        self.leader.emergency_kill();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in super::super) struct ExitObservation {
    operation_sha256: String,
    exec_observed_boottime_ns: u64,
    exit_observed_boottime_ns: u64,
    code: i32,
    status: i32,
    firewall_semantic_sha256: String,
    firewall_evidence_sha256: String,
    attachment_semantic_sha256: String,
    attachment_evidence_sha256: String,
}

impl ExitObservation {
    pub(in super::super) fn code(&self) -> i32 { self.code }
    pub(in super::super) fn status(&self) -> i32 { self.status }
}

/// The enclosing run-and-cleanup scope owns the consumed permit. This private
/// borrow cannot clone/serialize it and leaves its owners retained for cleanup.
pub(in super::super) struct Execution<'child, 'ready, 'network, 'network_child> {
    child: &'child BlockedChild,
    guardian: &'child Guardian,
    network: &'ready mut NetworkReady<'network, 'network_child>,
    acknowledgement: ExecAcknowledgement,
    terminal: bool,
}

impl<'child, 'ready, 'network, 'network_child> Execution<'child, 'ready, 'network, 'network_child> {
    pub(in super::super) fn begin(child: &'child BlockedChild, guardian: &'child Guardian,
        network: &'ready mut NetworkReady<'network, 'network_child>) -> Result<Self, String>
    {
        let result = (|| {
            child.check()?;
            guardian.require_child(child)?;
            network.require_child(child)?;
            network.check()?;
            guardian.require_child(child)?;
            child.check()?;
            // Burn before the sole send and first continue. Every uncertainty
            // permanently consumes this child, even if no bytes were accepted.
            require(!child.release_attempted.replace(true), "native child execution release was consumed")?;
            child.admission()?;
            require(child.leader.event(libc::WSTOPPED | libc::WEXITED)?
                == Some((libc::CLD_TRAPPED, libc::SIGTRAP | (PTRACE_EVENT_STOP << 8))),
                "native release did not consume the exact retained initial stop")?;
            guardian.check_live()?;
            child.admission()?;
            require(unsafe { libc::send(child.gate.as_raw_fd(), b"X".as_ptr().cast(), 1,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) } == 1,
                "native exec release send failed or is uncertain; no retry")?;
            child.admission()?;
            guardian.check_live()?;
            require(unsafe { libc::ptrace(libc::PTRACE_CONT, child.leader.pid,
                std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) } == 0,
                "native first exec continue failed or is uncertain; no retry")?;
            let acknowledgement = child.observe_exec()?;
            child.executed.set(true);
            // The first real executable is still stopped before user code.
            // Re-read actual network ownership, not an earlier success label.
            network.check_running()?;
            guardian.check_live()?;
            child.admission()?;
            require(child.leader.event(libc::WSTOPPED | libc::WEXITED)?
                == Some((libc::CLD_TRAPPED, libc::SIGTRAP | (PTRACE_EVENT_EXEC << 8))),
                "native exec handoff lost its positive original EXEC event")?;
            child.admission()?;
            guardian.check_live()?;
            // Normal applications must not remain ptraced or have their
            // signals intercepted. The retained guardian owns whole-leaf stop.
            require(unsafe { libc::ptrace(libc::PTRACE_DETACH, child.leader.pid,
                std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) } == 0,
                "native executed-child detach failed or is uncertain; no retry")?;
            Ok(acknowledgement)
        })();
        match result {
            Ok(acknowledgement) => Ok(Self { child, guardian, network, acknowledgement, terminal: false }),
            Err(error) => { child.abort_execution(guardian); Err(error) }
        }
    }

    fn poll_once(&mut self) -> Result<Option<ExitObservation>, String> {
        require(!self.terminal, "native execution terminal observation already consumed")?;
        let now = boottime()?;
        require(now < self.child.stop_boottime_ns(), "native execution reached its signed stop boundary")?;
        // Observe exact exit before live-only namespace/socket checks. Leave
        // WNOWAIT custody for the independent mandatory cleanup/reap phase.
        if let Some((code, status)) = self.child.leader.event(libc::WEXITED | libc::WSTOPPED | libc::WNOWAIT)? {
            require(matches!(code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED),
                "native running leader stopped without a terminal exit")?;
            self.child.drain_output()?;
            let observed = boottime()?;
            require(observed >= now && observed < self.child.stop_boottime_ns(),
                "native terminal observation missed signed stop")?;
            self.terminal = true;
            return Ok(Some(ExitObservation {
                operation_sha256: format!("sha256:{}", self.acknowledgement.operation.iter()
                    .map(|byte| format!("{byte:02x}")).collect::<String>()),
                exec_observed_boottime_ns: self.acknowledgement.observed_boottime_ns,
                exit_observed_boottime_ns: observed, code, status,
                firewall_semantic_sha256: digest_text(self.network.firewall_semantic_sha256()),
                firewall_evidence_sha256: digest_text(self.network.firewall_evidence_sha256()),
                attachment_semantic_sha256: digest_text(self.network.attachment_semantic_sha256()),
                attachment_evidence_sha256: digest_text(self.network.attachment_evidence_sha256()) }));
        }
        self.child.check_continuation()?;
        self.network.check_running()?;
        self.guardian.check_live()?;
        self.child.drain_output()?;
        self.child.wait_output_or_exit(self.child.stop_boottime_ns())?;
        Ok(None)
    }

    pub(in super::super) fn wait(mut self) -> Result<ExitObservation, String> {
        loop {
            match self.poll_once() {
                Ok(Some(observed)) => return Ok(observed),
                Ok(None) => {},
                Err(error) => { self.child.abort_execution(self.guardian); return Err(error); },
            }
        }
    }
}

impl Drop for Execution<'_, '_, '_, '_> {
    fn drop(&mut self) {
        // Even a normal leader exit does not authorize surviving descendants.
        // The owning composition must subsequently observe reap + both empties.
        self.child.abort_execution(self.guardian);
    }
}

fn digest_text(value: [u8; 32]) -> String {
    format!("sha256:{}", value.iter().map(|byte| format!("{byte:02x}")).collect::<String>())
}
