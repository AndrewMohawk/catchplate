//! Host-only observation after actual child/guardian cleanup and pin release.
//! No mutation message, namespace entry, permission constructor or renewed clock.

use super::{AttachmentBackend, Socket, identity, socket_address, file, NSFS_MAGIC, NS_GET_NSTYPE, SIOCGSKNS};
use super::super::{attachment_wire::{self as wire, AttachmentPlan, DumpKind},
    attachment_readback::RetirementLinks, attachment_reservation::CleanupBridgeLock,
    ExecutionParents};
use super::super::super::execution::child::{ChildNetworkBorrow, NetworkPinsReleased};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

const MAX_BYTES: usize = 1024 * 1024;
const MAX_MESSAGES: usize = 256;
const MAX_QUERIES: u32 = 16;

fn require(value: bool, reason: &str) -> Result<(), String> {
    if value { Ok(()) } else { Err(reason.to_owned()) }
}
fn now() -> Result<u64, String> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    require(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } == 0
        && value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec),
        "cleanup host clock unavailable")?;
    (value.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(value.tv_nsec as u64)).ok_or("cleanup host clock overflow".to_owned())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in super::super::super) struct HostVethAbsence {
    namespace_device: u64, namespace_inode: u64, ifindex: u32, name: String,
    bridge_ifindex: u32, observed_boottime_ns: u64, evidence_sha256: String,
}

/// Retains only HOST namespace/socket pins and the actual shared bridge flock.
/// Parents retain authenticated originals but no child namespace. Construction
/// is private to the actual fully installed backend while admission is live.
pub(in super::super::super) struct HostRetirement {
    host: Socket, lock: CleanupBridgeLock, parents: Arc<ExecutionParents>,
    links: RetirementLinks, operation: [u8; 32], child_namespace: (u64, u64),
    plan_sha256: [u8; 32], host_index: u32, next_sequence: u32,
    deadline: u64, pid: u32, thread: libc::c_long,
    transcript: Vec<u8>, messages: usize, queries: u32, attempted: bool,
}

impl AttachmentBackend<'_, '_> {
    pub(in super::super) fn prepare_retirement(&mut self, child: &ChildNetworkBorrow<'_>, plan: &AttachmentPlan,
        links: RetirementLinks) -> Result<HostRetirement, String> {
        self.current()?;
        child.check()?;
        require(self.submitted && self.plan_sha256 == Some(plan.sha256())
            && child.retirement_requested(), "cleanup host owner lacks actual retiring installation")?;
        plan.require_source(self.guard.egress(), self.phase)?;
        // Reserve a disjoint range on the SAME socket. The source backend can
        // still perform its one final pre-detach readback after this handoff.
        let first_sequence = self.next_sequence[0];
        self.next_sequence[0] = first_sequence.checked_add(MAX_QUERIES)
            .ok_or("cleanup host sequence reservation overflow")?;
        let host = Socket { file: self.host.file.try_clone().map_err(|_| "cleanup host socket duplicate failed")?,
            identity: self.host.identity, namespace: self.host.namespace.try_clone()
                .map_err(|_| "cleanup host namespace duplicate failed")?,
            namespace_identity: self.host.namespace_identity, port: self.host.port };
        let mut transcript = b"SWNATCL1".to_vec();
        transcript.extend_from_slice(&child.operation_sha256());
        transcript.extend_from_slice(&plan.sha256());
        let owner = HostRetirement { host, lock: self.lock.cleanup_hold()?,
            parents: Arc::clone(child.parents()), links, operation: child.operation_sha256(),
            child_namespace: self.child.namespace_identity, plan_sha256: plan.sha256(),
            host_index: plan.host_index(), next_sequence: first_sequence,
            deadline: child.cleanup_boottime_ns(), pid: std::process::id(),
            thread: unsafe { libc::syscall(libc::SYS_gettid) },
            transcript, messages: 0, queries: 0, attempted: false };
        owner.check()?;
        self.current()?; child.check()?;
        Ok(owner)
    }
}

impl HostRetirement {
    fn check(&self) -> Result<(), String> {
        require(self.pid == std::process::id() && self.thread > 0
            && self.thread == unsafe { libc::syscall(libc::SYS_gettid) }
            && unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0
            && unsafe { libc::getgid() } == 0 && unsafe { libc::getegid() } == 0,
            "cleanup host owner crossed its process boundary")?;
        self.lock.check()?;
        require(now()? < self.deadline, "cleanup host observation deadline missed")?;
        require(identity(&self.host.file.metadata().map_err(|_| "cleanup host socket unavailable")?) == self.host.identity
            && socket_address(&self.host.file).map_err(|_| "cleanup host port unavailable")? == self.host.port,
            "cleanup host socket original changed")?;
        for (option, expected) in [(libc::SO_DOMAIN, libc::AF_NETLINK), (libc::SO_TYPE, libc::SOCK_RAW),
            (libc::SO_PROTOCOL, libc::NETLINK_ROUTE)] {
            let mut value = 0i32; let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
            require(unsafe { libc::getsockopt(self.host.file.as_raw_fd(), libc::SOL_SOCKET, option,
                (&mut value as *mut i32).cast(), &mut length) } == 0
                && length as usize == std::mem::size_of::<i32>() && value == expected,
                "cleanup host socket type changed")?;
        }
        let actual = file(unsafe { libc::ioctl(self.host.file.as_raw_fd(), SIOCGSKNS as _) })
            .map_err(|_| "cleanup host socket namespace unavailable")?;
        for fd in [&actual, &self.host.namespace] {
            let metadata = fd.metadata().map_err(|_| "cleanup host namespace unavailable")?;
            let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
            require((metadata.dev(), metadata.ino()) == self.host.namespace_identity
                && metadata.uid() == 0 && metadata.gid() == 0
                && unsafe { libc::fstatfs(fd.as_raw_fd(), &mut fs) } == 0 && fs.f_type as libc::c_long == NSFS_MAGIC
                && unsafe { libc::ioctl(fd.as_raw_fd(), NS_GET_NSTYPE as _) } == libc::CLONE_NEWNET,
                "cleanup host namespace original changed")?;
        }
        let flags = unsafe { libc::fcntl(self.host.file.as_raw_fd(), libc::F_GETFL) };
        let descriptor = unsafe { libc::fcntl(self.host.file.as_raw_fd(), libc::F_GETFD) };
        require(flags >= 0 && flags & libc::O_NONBLOCK != 0 && descriptor >= 0
            && descriptor & libc::FD_CLOEXEC != 0, "cleanup host socket flags changed")?;
        self.lock.check()?;
        require(now()? < self.deadline, "cleanup host closing deadline missed")
    }

    fn event(&mut self, tag: u8, raw: &[u8]) -> Result<(), String> {
        require(!raw.is_empty() && self.transcript.len().checked_add(raw.len() + 5)
            .map_or(false, |v| v <= MAX_BYTES), "cleanup host transcript budget exhausted")?;
        self.transcript.push(tag);
        self.transcript.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        self.transcript.extend_from_slice(raw);
        Ok(())
    }

    fn dump(&mut self) -> Result<Vec<Vec<u8>>, String> {
        self.check()?;
        require(self.queries < MAX_QUERIES, "cleanup host query budget exhausted")?;
        self.queries += 1;
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).ok_or("cleanup host sequence exhausted")?;
        let request = wire::dump_request(DumpKind::Links, sequence, self.host.port)?;
        // Before-send original records an attempt, not a claimed send. No
        // effect request or retry-on-send-failure exists in this owner.
        self.event(1, &request)?;
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        self.check()?;
        let written = unsafe { libc::sendto(self.host.file.as_raw_fd(), request.as_ptr().cast(), request.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL, (&address as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t) };
        self.check()?;
        require(written == request.len() as isize, "cleanup host dump send failed; no resubmit")?;
        let mut payloads = Vec::new();
        loop {
            self.check()?;
            let mut raw = vec![0u8; wire::MAX_DATAGRAM];
            let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut iov = libc::iovec { iov_base: raw.as_mut_ptr().cast(), iov_len: raw.len() };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_name = (&mut sender as *mut libc::sockaddr_nl).cast();
            message.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            message.msg_iov = &mut iov; message.msg_iovlen = 1;
            let received = unsafe { libc::recvmsg(self.host.file.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
            let error = io::Error::last_os_error();
            self.check()?;
            if received < 0 {
                require(error.kind() == io::ErrorKind::WouldBlock, "cleanup host receive lost originals")?;
                let remaining = self.deadline.checked_sub(now()?).filter(|v| *v != 0)
                    .ok_or("cleanup host receive deadline missed")?;
                let mut poll = libc::pollfd { fd: self.host.file.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                let result = unsafe { libc::poll(&mut poll, 1,
                    ((remaining.min(100_000_000) + 999_999) / 1_000_000) as i32) };
                self.check()?;
                require(result >= 0 && poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0,
                    "cleanup host poll failed")?;
                continue;
            }
            require(received > 0 && received as usize <= raw.len() && message.msg_flags == 0
                && message.msg_namelen as usize == std::mem::size_of::<libc::sockaddr_nl>()
                && sender.nl_family == libc::AF_NETLINK as u16 && sender.nl_pid == 0 && sender.nl_groups == 0,
                "cleanup host datagram is not an intact kernel original")?;
            raw.truncate(received as usize);
            self.event(2, &raw)?;
            let mut done = false;
            for frame in wire::frames(&raw)? {
                self.messages += 1;
                require(self.messages <= MAX_MESSAGES && !done && frame.flags == 2
                    && frame.sequence == sequence && frame.port_id == self.host.port,
                    "cleanup host dump framing interrupted or mismatched")?;
                if frame.message_type == 3 {
                    require(frame.payload == [0, 0, 0, 0], "cleanup host dump did not finish cleanly")?;
                    done = true;
                } else {
                    require(frame.message_type == 16 && frame.payload.len() >= 16 && frame.payload[0] == 0,
                        "cleanup host dump contains an unexpected message")?;
                    payloads.push(frame.payload.to_vec());
                }
            }
            if done { self.check()?; return Ok(payloads); }
        }
    }

    /// The sealed token exists only after exact leader/guardian cleanup and
    /// explicit closure of this child's original socket/namespace inventory.
    pub(in super::super::super) fn observe(&mut self, released: &NetworkPinsReleased)
        -> Result<HostVethAbsence, String> {
        require(!std::mem::replace(&mut self.attempted, true), "cleanup host observation already consumed")?;
        released.require(self.operation, self.child_namespace, self.deadline)?;
        self.check()?;
        // Includes signed/actual operation association, not a caller status.
        require(self.plan_sha256.iter().any(|b| *b != 0), "cleanup host plan association absent")?;
        loop {
            let originals = self.dump()?;
            let refs = originals.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let authority = self.parents.attachment_pending().authorization();
            if self.links.observe(&refs, authority, self.host_index)? {
                // A separate full closing dump prevents success from an
                // incomplete walk or a name/ifindex replacement during it.
                let closing = self.dump()?;
                let refs = closing.iter().map(Vec::as_slice).collect::<Vec<_>>();
                require(self.links.observe(&refs, self.parents.attachment_pending().authorization(), self.host_index)?,
                    "cleanup host veth reappeared during observation")?;
                self.check()?;
                let authority = self.parents.attachment_pending().authorization();
                let observed = now()?;
                require(observed < self.deadline, "cleanup host absence deadline missed")?;
                return Ok(HostVethAbsence { namespace_device: self.host.namespace_identity.0,
                    namespace_inode: self.host.namespace_identity.1, ifindex: self.host_index,
                    name: authority.attachment.host_veth_name.clone(), bridge_ifindex: authority.bridge.ifindex,
                    observed_boottime_ns: observed, evidence_sha256: format!("sha256:{:x}", Sha256::digest(&self.transcript)) });
            }
            // Namespace teardown is asynchronous. Waiting is bounded by the
            // original cleanup deadline AND total query/message/byte limits.
            self.check()?;
            let remaining = self.deadline.checked_sub(now()?).filter(|v| *v != 0)
                .ok_or("cleanup host disappearance deadline missed")?;
            require(unsafe { libc::poll(std::ptr::null_mut(), 0,
                ((remaining.min(100_000_000) + 999_999) / 1_000_000) as i32) } >= 0,
                "cleanup host observation wait interrupted")?;
        }
    }
}
