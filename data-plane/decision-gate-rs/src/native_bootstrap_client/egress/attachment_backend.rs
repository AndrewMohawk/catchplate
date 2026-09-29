//! One-shot typed RTNL attachment through actual retained namespace sockets.
//! A private journal claim precedes every mutation attempt; errors are sticky.
//! No namespace switching, external descriptors, raw-message API or resends.

use super::{attachment::PreattachmentGuard,
    owners::{AttachmentOwner, Owner, OwnerIdentity, Phase},
    attachment_reservation::{AttachmentBackendLock, AttachmentReservation},
    attachment_wire::{self as wire, AttachmentPlan, DumpKind, Side}, attachment_readback, EgressGuard};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

const MAX_TRANSCRIPT: usize = 1024 * 1024;
const MAX_EVENTS: u32 = 512;
const MAX_MESSAGES: usize = 256;
const SIOCGSKNS: libc::c_ulong = 0x894c;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const NSFS_MAGIC: libc::c_long = 0x6e736673;

fn require(value: bool) -> Result<(), String> {
    if value { Ok(()) } else { Err("native attachment transport refused or outcome uncertain".to_owned()) }
}
fn file(fd: i32) -> io::Result<File> {
    if fd < 0 { Err(io::Error::last_os_error()) } else { Ok(unsafe { File::from_raw_fd(fd) }) }
}
type Identity = (u64, u64, u32, u32, u32);
fn identity(value: &std::fs::Metadata) -> Identity { (value.dev(), value.ino(), value.mode(), value.uid(), value.gid()) }

pub(super) struct ReplyOriginals {
    side: Side, sequence: u32, port_id: u32, request: Vec<u8>, datagrams: Vec<Vec<u8>>,
}
impl ReplyOriginals {
    pub(super) fn side(&self) -> Side { self.side }
    pub(super) fn sequence(&self) -> u32 { self.sequence }
    pub(super) fn port_id(&self) -> u32 { self.port_id }
    pub(super) fn request(&self) -> &[u8] { &self.request }
    pub(super) fn datagrams(&self) -> &[Vec<u8>] { &self.datagrams }
}

pub(super) struct Snapshot {
    owner: OwnerIdentity,
    plan_sha256: Option<[u8; 32]>,
    transcript_sha256: [u8; 32],
    originals: BTreeMap<(Side, DumpKind), ReplyOriginals>,
    closing: [ReplyOriginals; 2],
}
impl Snapshot {
    pub(super) fn require_owner(&self, owner: &EgressGuard, plan: &AttachmentPlan,
        transcript: &AttachmentTranscript) -> Result<(), String> {
        self.require_source(Owner::Diagnostic(owner), plan, transcript, Phase::Admission)
    }
    pub(super) fn require_source(&self, owner: Owner<'_>, plan: &AttachmentPlan,
        transcript: &AttachmentTranscript, phase: Phase) -> Result<(), String> {
        transcript.require_source(owner, plan, phase)?;
        require(self.owner == owner.identity()
            && self.plan_sha256 == Some(plan.sha256())
            && self.transcript_sha256 == transcript.sha256())
    }
    pub(super) fn get(&self, side: Side, kind: DumpKind) -> Result<&ReplyOriginals, String> {
        self.originals.get(&(side, kind)).ok_or_else(|| "native attachment snapshot kind absent".to_owned())
    }
    pub(super) fn closing_links(&self, side: Side) -> &ReplyOriginals {
        &self.closing[if side == Side::Host { 0 } else { 1 }]
    }
}

pub(super) struct AttachmentTranscript { owner: OwnerIdentity, plan_sha256: [u8; 32], original: Vec<u8> }
impl AttachmentTranscript {
    pub(super) fn original(&self) -> &[u8] { &self.original }
    pub(super) fn sha256(&self) -> [u8; 32] { Sha256::digest(&self.original).into() }
    pub(super) fn require_owner(&self, owner: &EgressGuard, plan: &AttachmentPlan) -> Result<(), String> {
        self.require_source(Owner::Diagnostic(owner), plan, Phase::Admission)
    }
    pub(super) fn require_source(&self, owner: Owner<'_>, plan: &AttachmentPlan, phase: Phase) -> Result<(), String> {
        plan.require_source(owner, phase)?;
        require(self.owner == owner.identity() && self.plan_sha256 == plan.sha256())
    }
    pub(super) fn owner_identity(&self) -> OwnerIdentity { self.owner }
    pub(super) fn plan_sha256(&self) -> [u8; 32] { self.plan_sha256 }
}

struct Socket {
    file: File, identity: Identity, namespace: File, namespace_identity: (u64, u64), port: u32,
}

pub(super) struct AttachmentBackend<'guard, 'egress> {
    guard: AttachmentOwner<'guard, 'egress>,
    phase: Phase,
    lock: AttachmentBackendLock<'guard, 'egress>,
    host: Socket, child: Socket,
    next_sequence: [u32; 2],
    plan_sha256: Option<[u8; 32]>, attempted: bool, submitted: bool, stopped: Cell<bool>,
    transcript: Vec<u8>, events: u32, messages: usize,
}

impl<'guard, 'egress> AttachmentBackend<'guard, 'egress> {
    pub(super) fn open(guard: &'guard PreattachmentGuard<'egress>,
        reservation: &AttachmentReservation<'guard, 'egress>) -> Result<Self, String> {
        Self::open_owner(AttachmentOwner::Diagnostic(guard), reservation)
    }
    pub(super) fn open_owner(guard: AttachmentOwner<'guard, 'egress>,
        reservation: &AttachmentReservation<'guard, 'egress>) -> Result<Self, String> {
        guard.check()?;
        let lock = reservation.backend_lock()?;
        lock.require_owner(&guard)?;
        let descriptors = guard.egress().duplicate_attachment()?;
        guard.check()?; lock.check()?;
        let host_file = file(unsafe { libc::socket(libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, libc::NETLINK_ROUTE) })
            .map_err(|_| "native host route socket unavailable")?;
        guard.check()?; lock.check()?;
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        let result = unsafe { libc::bind(host_file.as_raw_fd(), (&address as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t) };
        guard.check()?; lock.check()?; require(result == 0)?;
        let host_port = socket_address(&host_file).map_err(|_| "native host route socket address unavailable")?;
        guard.check()?; lock.check()?;
        let host_identity = identity(&host_file.metadata().map_err(|_| "native host socket metadata unavailable")?);
        guard.check()?; lock.check()?;
        let child_identity = identity(&descriptors.child_route.metadata().map_err(|_| "native child socket metadata unavailable")?);
        guard.check()?; lock.check()?;
        require(child_identity.0 == descriptors.route_socket_device && child_identity.1 == descriptors.route_socket_inode)?;
        let mut transcript = Vec::with_capacity(MAX_TRANSCRIPT);
        transcript.extend_from_slice(b"SWNATBE1"); transcript.extend_from_slice(&0u32.to_be_bytes());
        let owner = Self { guard, lock, phase: Phase::Admission,
            host: Socket { file: host_file, identity: host_identity, namespace: descriptors.host_namespace,
                namespace_identity: (descriptors.host_namespace_device, descriptors.host_namespace_inode), port: host_port },
            child: Socket { file: descriptors.child_route, identity: child_identity, namespace: descriptors.child_namespace,
                namespace_identity: (descriptors.child_namespace_device, descriptors.child_namespace_inode), port: descriptors.route_port_id },
            next_sequence: [1, 1], plan_sha256: None, attempted: false, submitted: false, stopped: Cell::new(false),
            transcript, events: 0, messages: 0 };
        owner.current()?;
        for side in [Side::Host, Side::Child] {
            for (option, value) in [(10, 1i32), (11, 0), (5, 0), (12, 1)] {
                let fd = owner.socket(side).file.as_raw_fd();
                owner.io(|| {
                    if unsafe { libc::setsockopt(fd, libc::SOL_NETLINK, option,
                        (&value as *const i32).cast(), std::mem::size_of::<i32>() as libc::socklen_t) } == 0 { Ok(()) }
                    else { Err(io::Error::last_os_error()) }
                })?;
                require(owner.option(side, libc::SOL_NETLINK, option)? == value)?;
            }
            owner.quiet(side)?;
        }
        owner.current()?; Ok(owner)
    }

    fn socket(&self, side: Side) -> &Socket { if side == Side::Host { &self.host } else { &self.child } }
    fn source(&self) -> Result<(), String> { self.guard.check_phase(self.phase)?; self.lock.check_phase(self.phase) }
    pub(super) fn enter_continuation(&mut self) -> Result<(), String> {
        require(self.submitted && !self.stopped.get())?;
        self.guard.check_phase(Phase::Continuation)?;
        self.phase = Phase::Continuation;
        self.current()
    }
    fn io<T>(&self, operation: impl FnOnce() -> io::Result<T>) -> Result<T, String> {
        self.source()?; let result = operation(); self.source()?;
        result.map_err(|_| "native attachment IO failed or outcome uncertain".to_owned())
    }
    fn option(&self, side: Side, level: i32, option: i32) -> Result<i32, String> {
        self.io(|| {
            let mut value = 0i32; let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
            if unsafe { libc::getsockopt(self.socket(side).file.as_raw_fd(), level, option,
                (&mut value as *mut i32).cast(), &mut length) } == 0 && length as usize == std::mem::size_of::<i32>() { Ok(value) }
            else { Err(io::Error::last_os_error()) }
        })
    }

    /// Original owner/descriptor checks only; no new routing dump or allowance.
    pub(super) fn current(&self) -> Result<(), String> {
        require(!self.stopped.get())?;
        let result = self.check_originals();
        if result.is_err() { self.stopped.set(true); }
        result
    }
    fn check_originals(&self) -> Result<(), String> {
        self.source()?;
        for side in [Side::Host, Side::Child] {
            let socket = self.socket(side);
            require(identity(&self.io(|| socket.file.metadata())?) == socket.identity
                && self.option(side, libc::SOL_SOCKET, libc::SO_DOMAIN)? == libc::AF_NETLINK
                && self.option(side, libc::SOL_SOCKET, libc::SO_TYPE)? == libc::SOCK_RAW
                && self.option(side, libc::SOL_SOCKET, libc::SO_PROTOCOL)? == libc::NETLINK_ROUTE)?;
            let actual = self.io(|| file(unsafe { libc::ioctl(socket.file.as_raw_fd(), SIOCGSKNS as _) }))?;
            for namespace in [&actual, &socket.namespace] {
                let meta = self.io(|| namespace.metadata())?;
                require((meta.dev(), meta.ino()) == socket.namespace_identity && meta.uid() == 0 && meta.gid() == 0)?;
                let (magic, kind) = self.io(|| {
                    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
                    if unsafe { libc::fstatfs(namespace.as_raw_fd(), &mut stat) } != 0 { return Err(io::Error::last_os_error()); }
                    let kind = unsafe { libc::ioctl(namespace.as_raw_fd(), NS_GET_NSTYPE as _) };
                    if kind < 0 { Err(io::Error::last_os_error()) } else { Ok((stat.f_type as libc::c_long, kind)) }
                })?;
                require(magic == NSFS_MAGIC && kind == libc::CLONE_NEWNET)?;
            }
            require(self.io(|| socket_address(&socket.file))? == socket.port)?;
            let (descriptor, status) = self.io(|| {
                let descriptor = unsafe { libc::fcntl(socket.file.as_raw_fd(), libc::F_GETFD) };
                let status = unsafe { libc::fcntl(socket.file.as_raw_fd(), libc::F_GETFL) };
                if descriptor < 0 || status < 0 { Err(io::Error::last_os_error()) } else { Ok((descriptor, status)) }
            })?;
            require(descriptor & libc::FD_CLOEXEC != 0 && status & libc::O_NONBLOCK != 0)?;
        }
        self.source()
    }

    fn begin(&mut self) -> Result<(), String> {
        require(!self.stopped.replace(true))?; self.check_originals()
    }
    fn event(&mut self, tag: u8, side: Side, raw: &[u8]) -> Result<(), String> {
        let count = self.events.checked_add(1).ok_or("native attachment event overflow")?;
        require(matches!(tag, 1..=3) && !raw.is_empty() && raw.len() <= wire::MAX_DATAGRAM
            && count <= MAX_EVENTS && self.transcript.len() + 6 + raw.len() <= MAX_TRANSCRIPT)?;
        self.transcript.extend_from_slice(&[tag, side.tag()]);
        self.transcript.extend_from_slice(&(raw.len() as u32).to_be_bytes()); self.transcript.extend_from_slice(raw);
        self.events = count; self.transcript[8..12].copy_from_slice(&count.to_be_bytes()); Ok(())
    }
    fn quiet(&self, side: Side) -> Result<(), String> {
        let (count, events) = self.io(|| {
            let mut poll = libc::pollfd { fd: self.socket(side).file.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let count = unsafe { libc::poll(&mut poll, 1, 0) };
            if count < 0 { Err(io::Error::last_os_error()) } else { Ok((count, poll.revents)) }
        })?;
        require(count == 0 && events == 0)
    }
    fn send(&mut self, side: Side, tag: u8, raw: &[u8]) -> Result<(), String> {
        self.check_originals()?; self.quiet(side)?;
        self.event(tag, side, raw)?; // Retained attempt, never a claim of delivery.
        let count = self.io(|| {
            let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            address.nl_family = libc::AF_NETLINK as u16;
            let mut vector = libc::iovec { iov_base: raw.as_ptr() as *mut libc::c_void, iov_len: raw.len() };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_name = (&mut address as *mut libc::sockaddr_nl).cast();
            message.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            message.msg_iov = &mut vector; message.msg_iovlen = 1;
            let count = unsafe { libc::sendmsg(self.socket(side).file.as_raw_fd(), &message, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
            if count < 0 { Err(io::Error::last_os_error()) } else { Ok(count as usize) }
        })?;
        require(count == raw.len())?; self.check_originals()
    }
    fn receive(&mut self, side: Side) -> Result<Vec<u8>, String> {
        let mut raw = vec![0u8; wire::MAX_DATAGRAM];
        loop {
            self.check_originals()?;
            let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut vector = libc::iovec { iov_base: raw.as_mut_ptr().cast(), iov_len: raw.len() };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_name = (&mut address as *mut libc::sockaddr_nl).cast();
            message.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            message.msg_iov = &mut vector; message.msg_iovlen = 1;
            let count = unsafe { libc::recvmsg(self.socket(side).file.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
            let error = if count < 0 { Some(io::Error::last_os_error()) } else { None };
            if let Some(error) = error {
                self.source()?;
                if error.kind() != io::ErrorKind::WouldBlock { return Err("native attachment receive lost data".to_owned()); }
                let timeout = self.guard.deadline(self.phase)?.checked_duration_since(Instant::now())
                    .ok_or("native attachment original deadline expired")?.as_millis().min(25) as i32;
                let events = self.io(|| {
                    let mut poll = libc::pollfd { fd: self.socket(side).file.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                    if unsafe { libc::poll(&mut poll, 1, timeout) } < 0 { Err(io::Error::last_os_error()) } else { Ok(poll.revents) }
                })?;
                require(events & !libc::POLLIN == 0)?; continue;
            }
            let valid = count > 0 && count as usize <= raw.len()
                && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
                && message.msg_namelen as usize == std::mem::size_of::<libc::sockaddr_nl>()
                && address.nl_family as i32 == libc::AF_NETLINK && address.nl_pid == 0 && address.nl_groups == 0;
            if !valid { self.source()?; return Err("native attachment datagram provenance or extent refused".to_owned()); }
            raw.truncate(count as usize);
            let retained = self.event(3, side, &raw); let closing = self.source();
            retained?; closing?; return Ok(raw);
        }
    }
    fn account(&mut self, count: usize) -> Result<(), String> {
        self.messages = self.messages.checked_add(count).ok_or("native attachment message count overflow")?;
        require(self.messages <= MAX_MESSAGES)
    }
    fn query(&mut self, side: Side, kind: DumpKind) -> Result<ReplyOriginals, String> {
        let at = if side == Side::Host { 0 } else { 1 };
        let sequence = self.next_sequence[at];
        self.next_sequence[at] = sequence.checked_add(1).ok_or("native attachment sequence exhausted")?;
        let port = self.socket(side).port;
        let request = wire::dump_request(kind, sequence, port)?;
        self.send(side, 1, &request)?;
        let mut datagrams = Vec::new();
        loop {
            let raw = self.receive(side)?; let frames = wire::frames(&raw)?;
            self.account(frames.len())?;
            let mut done = false;
            for (index, frame) in frames.iter().enumerate() {
                require(frame.sequence == sequence && frame.port_id == port && frame.flags == 2)?;
                if frame.message_type == 3 {
                    require(index + 1 == frames.len() && frame.payload == 0i32.to_ne_bytes())?; done = true;
                } else { require(frame.message_type == kind.reply_type())?; }
            }
            drop(frames); datagrams.push(raw); if done { break; }
        }
        self.check_originals()?; self.quiet(side)?;
        Ok(ReplyOriginals { side, sequence, port_id: port, request, datagrams })
    }
    fn collect(&mut self) -> Result<Snapshot, String> {
        let mut originals = BTreeMap::new();
        for side in [Side::Host, Side::Child] {
            for kind in [DumpKind::Links, DumpKind::AddressV4, DumpKind::AddressV6, DumpKind::NeighborV4, DumpKind::NeighborV6] {
                originals.insert((side, kind), self.query(side, kind)?);
            }
            if side == Side::Child {
                for kind in [DumpKind::RouteV4, DumpKind::RouteV6] { originals.insert((side, kind), self.query(side, kind)?); }
            }
        }
        let closing = [self.query(Side::Host, DumpKind::Links)?, self.query(Side::Child, DumpKind::Links)?];
        Ok(Snapshot { owner: self.guard.egress().identity(),
            plan_sha256: self.plan_sha256, transcript_sha256: Sha256::digest(&self.transcript).into(),
            originals, closing })
    }
    pub(super) fn plan(&mut self) -> Result<AttachmentPlan, String> {
        require(self.phase == Phase::Admission)?; self.guard.check()?;
        self.begin()?; require(self.plan_sha256.is_none() && !self.attempted)?;
        let originals = self.collect()?;
        let preflight = attachment_readback::preflight(self.guard.authority(), &originals)?;
        let plan = wire::build_source(self.guard.egress(), self.guard.authority(), preflight.host_index(), preflight.child_index(),
            self.child.namespace.as_raw_fd(), self.host.port, self.child.port, self.next_sequence[0], self.next_sequence[1],
            self.host.namespace_identity, self.child.namespace_identity)?;
        self.next_sequence = [plan.last_sequence(Side::Host).checked_add(1).ok_or("native host sequence exhausted")?,
            plan.last_sequence(Side::Child).checked_add(1).ok_or("native child sequence exhausted")?];
        self.plan_sha256 = Some(plan.sha256()); self.check_originals()?; self.stopped.set(false); Ok(plan)
    }
    pub(super) fn submit_once(&mut self, plan: &AttachmentPlan,
        reservation: &AttachmentReservation<'guard, 'egress>) -> Result<(), String> {
        require(self.phase == Phase::Admission)?; self.guard.check()?;
        self.begin()?; plan.require_source(self.guard.egress(), Phase::Admission)?;
        require(!self.attempted && self.plan_sha256 == Some(plan.sha256()))?;
        reservation.require_source_claim(self.guard.egress(), plan)?; self.attempted = true;
        for operation in plan.operations() {
            reservation.require_source_claim(self.guard.egress(), plan)?;
            self.send(operation.side, 2, &operation.original)?;
            let raw = self.receive(operation.side)?; let frames = wire::frames(&raw)?;
            self.account(frames.len())?; require(frames.len() == 1)?;
            let frame = &frames[0];
            require(frame.message_type == 2 && frame.flags == 0x100
                && frame.sequence == u32::from_ne_bytes(operation.original[8..12].try_into().unwrap())
                && frame.port_id == self.socket(operation.side).port
                && frame.payload.len() == 20 && frame.payload[..4] == 0i32.to_ne_bytes()
                && frame.payload[4..] == operation.original[..16])?;
            self.quiet(operation.side)?;
        }
        self.check_originals()?; self.submitted = true; self.stopped.set(false); Ok(())
    }
    pub(super) fn snapshot(&mut self) -> Result<Snapshot, String> {
        self.begin()?; require(self.submitted)?;
        let result = self.collect()?; self.check_originals()?; self.stopped.set(false); Ok(result)
    }
    /// Raw originals remain available on failure; copying them cannot revive IO.
    pub(super) fn transcript(&self) -> Result<AttachmentTranscript, String> {
        require(self.transcript.len() <= MAX_TRANSCRIPT && self.events <= MAX_EVENTS)?;
        Ok(AttachmentTranscript { owner: self.guard.egress().identity(),
            plan_sha256: self.plan_sha256.ok_or("native attachment intent not prepared")?, original: self.transcript.clone() })
    }
}

fn socket_address(socket: &File) -> io::Result<u32> {
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    if unsafe { libc::getsockname(socket.as_raw_fd(), (&mut address as *mut libc::sockaddr_nl).cast(), &mut length) } == 0
        && length as usize == std::mem::size_of::<libc::sockaddr_nl>()
        && address.nl_family as i32 == libc::AF_NETLINK && address.nl_groups == 0 && address.nl_pid != 0 {
        Ok(address.nl_pid)
    } else { Err(io::Error::last_os_error()) }
}
