//! Only the actual pre-drop worker constructor can install this process owner.
//! Every peer use requires a fresh reply from that retained privileged worker;
//! no successful DTO, host descriptor or ambient fallback is exposed.
use super::super::{Delivery, ServiceRunnerError, Sha256Digest};
use super::wire::{Request, Reply, API, MAX_IPC};
use crate::policy_shadow::canonical_json_bytes;
use crate::policy_shadow::policy_custody::services::common::{
    decode_canonical_frame, ExpectedPeerCredentials, ServiceError,
};
use crate::policy_shadow::policy_custody::services::guest::native_guest::retrieval_peer as packet;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::{Arc, Mutex, OnceLock};
use std::sync::atomic::Ordering;

static INSTALLED: OnceLock<Arc<Session>> = OnceLock::new();

fn refused() -> ServiceError { ServiceError::Invalid("ordinary retained peer inspection unavailable") }
fn require(value: bool) -> Result<(), ServiceError> { if value { Ok(()) } else { Err(refused()) } }
fn now() -> Result<u64, ServiceError> {
    crate::policy_shadow::policy_custody::boottime::boottime_now_nanos().map_err(|_| refused())
}
fn identity(fd: BorrowedFd<'_>) -> Result<(u64, u64), ServiceError> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    require(unsafe { libc::fstat(fd.as_raw_fd(), &mut value) } == 0
        && value.st_mode & libc::S_IFMT == libc::S_IFSOCK && value.st_ino != 0)?;
    Ok((value.st_dev, value.st_ino))
}

struct State { sequence: u64, socket: Option<(u64, u64)>, failed: bool }

pub(in crate::policy_shadow::policy_custody::services) struct Session {
    channel: OwnedFd,
    helper_pidfd: OwnedFd,
    helper_pid: i32,
    process: i32,
    expected: ExpectedPeerCredentials,
    owner: Arc<Delivery>,
    state: Mutex<State>,
}

/// Private to the worker module. Called in the original service parent after
/// the genuine fork, while C9 is admitted but no private service key was read.
pub(super) fn install(channel: OwnedFd, helper_pidfd: OwnedFd, helper_pid: i32,
    expected: ExpectedPeerCredentials, owner: Arc<Delivery>) -> Result<(), ServiceRunnerError> {
    owner.check_originals()?;
    require(unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0
        && helper_pid > 1 && helper_pid != unsafe { libc::getpid() } && INSTALLED.get().is_none())?;
    expected.validate_claim()?;
    packet::configure(channel.as_fd()).map_err(|_| refused())?;
    packet::same_process(helper_pidfd.as_fd(), helper_pid).map_err(|_| refused())?;
    let session = Arc::new(Session { channel, helper_pidfd, helper_pid,
        process: unsafe { libc::getpid() }, expected, owner,
        state: Mutex::new(State { sequence: 0, socket: None, failed: false }) });
    INSTALLED.set(session).map_err(|_| refused())?;
    Ok(())
}

pub(in crate::policy_shadow::policy_custody::services) fn bind_if_enabled(
    socket: BorrowedFd<'_>, expected: &ExpectedPeerCredentials, peer_pidfd: BorrowedFd<'_>,
) -> Result<Option<Arc<Session>>, ServiceError> {
    let Some(owner) = INSTALLED.get() else { return Ok(None); };
    // An installed profile can never fall back to unprivileged /proc reads or
    // inspect a different identity selected by a later service caller.
    require(&owner.expected == expected)?;
    owner.revalidate(socket, peer_pidfd)?;
    Ok(Some(Arc::clone(owner)))
}

impl Session {
    fn current(&self, deadline: u64) -> Result<(), ServiceError> {
        require(unsafe { libc::getpid() } == self.process && now()? < deadline
            && deadline <= self.owner.lifetime)?;
        self.owner.check().map_err(|_| refused())?;
        packet::same_process(self.helper_pidfd.as_fd(), self.helper_pid).map_err(|_| refused())
    }

    pub(in crate::policy_shadow::policy_custody::services) fn revalidate(
        &self, socket: BorrowedFd<'_>, peer_pidfd: BorrowedFd<'_>,
    ) -> Result<(), ServiceError> {
        // Never wait behind another request with an unbounded mutex timeout.
        let mut state = self.state.try_lock().map_err(|_| refused())?;
        require(!state.failed)?;
        state.failed = true; // Any partial send/lost reply is terminal, no resend.
        let deadline = if self.owner.ready.load(Ordering::Acquire) {
            self.owner.lifetime
        } else { self.owner.startup };
        self.current(deadline)?;
        let observed = identity(socket)?;
        require(state.socket.map_or(true, |prior| prior == observed))?;
        packet::same_process(peer_pidfd, self.expected.pid).map_err(|_| refused())?;
        let sequence = state.sequence.checked_add(1).ok_or_else(refused)?;
        let request = Request { api_version: API.into(), sequence,
            socket_device: observed.0, socket_inode: observed.1,
            process_identity_sha256: self.expected.process_identity_sha256.clone(),
            deadline_boottime_ns: deadline.to_string(),
            runtime_configuration_sha256: self.owner.payload.runtime_config.sha256.clone() };
        let raw = canonical_json_bytes(&request).map_err(|_| refused())?;
        require(raw.len() <= MAX_IPC)?;
        let digest = Sha256Digest::compute(&raw);
        loop {
            self.current(deadline)?;
            packet::same_process(peer_pidfd, self.expected.pid).map_err(|_| refused())?;
            if packet::send(self.channel.as_fd(), &raw, &[socket, peer_pidfd]).map_err(|_| refused())? { break; }
            wait(self.channel.as_fd(), libc::POLLOUT, deadline)?;
        }
        loop {
            self.current(deadline)?;
            if let Some(reply) = packet::receive(self.channel.as_fd(), MAX_IPC, 0).map_err(|_| refused())? {
                // The socketpair's pre-fork SO_PEERCRED names the original
                // service, not the helper. Actual per-packet kernel identity
                // must instead match the retained fork child and its PIDFD.
                require(reply.credentials.pid == self.helper_pid && reply.credentials.uid == 0
                    && reply.credentials.gid == 0)?;
                packet::same_process(reply.pidfd.as_fd(), self.helper_pid).map_err(|_| refused())?;
                let response: Reply = decode_canonical_frame(&reply.bytes)?;
                require(response.api_version == API && response.sequence == sequence
                    && response.request_sha256 == digest
                    && response.process_identity_sha256 == self.expected.process_identity_sha256)?;
                packet::same_process(peer_pidfd, self.expected.pid).map_err(|_| refused())?;
                self.current(deadline)?;
                require(identity(socket)? == observed)?;
                state.socket = Some(observed); state.sequence = sequence; state.failed = false;
                return Ok(());
            }
            wait(self.channel.as_fd(), libc::POLLIN, deadline)?;
        }
    }
}

fn wait(fd: BorrowedFd<'_>, events: i16, deadline: u64) -> Result<(), ServiceError> {
    require(now()? < deadline)?;
    let mut poll = libc::pollfd { fd: fd.as_raw_fd(), events, revents: 0 };
    let count = unsafe { libc::poll(&mut poll, 1, 1) };
    require(count >= 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR))?;
    require(poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0 && now()? < deadline)
}
