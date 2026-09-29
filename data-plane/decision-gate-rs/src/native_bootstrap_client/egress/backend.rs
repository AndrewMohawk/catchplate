//! Fixed native netfilter transport over the retained child's actual socket.
//!
//! No namespace switching, external socket, arbitrary request bytes, retries
//! of requests, or successful caller DTOs. A private typed transaction may be
//! attempted once, only after its exact original is durably claimed. Every
//! error poisons this owner; raw IO events remain data for uncertainty custody.

use super::{authority::Ruleset, kernel_reservation::{BackendLock, KernelReservation},
    wire::{self, DumpKind, Transaction}, EgressGuard};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

const MAX_TRANSCRIPT: usize = 1024 * 1024;
const MAX_MESSAGES: usize = 256;
const MAX_EVENTS: u32 = 512;
const TRANSCRIPT_MAGIC: &[u8; 8] = b"SWNEGBE1";
const READ_REQUEST: u8 = 1;
const MUTATION_ATTEMPT: u8 = 2;
const KERNEL_DATAGRAM: u8 = 3;
const NETLINK_NO_ENOBUFS: i32 = 5;
const NETLINK_CAP_ACK: i32 = 10;
const NETLINK_EXT_ACK: i32 = 11;
const SIOCGSKNS: libc::c_ulong = 0x894c;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const NSFS_MAGIC: libc::c_long = 0x6e736673;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const MULTI: u16 = 2;
const APPEND: u16 = 0x800;
const CAPPED: u16 = 0x100;

fn require(value: bool) -> Result<(), String> {
    if value { Ok(()) } else { Err("native egress backend refused or outcome uncertain".to_owned()) }
}

fn digest(raw: &[u8]) -> [u8; 32] { Sha256::digest(raw).into() }

/// Source-produced IO originals only. No Clone, Deserialize or public fields;
/// semantic/generation admission belongs to the separate original parser.
pub(super) struct ReplyOriginals {
    sequence: u32,
    port_id: u32,
    request: Vec<u8>,
    datagrams: Vec<Vec<u8>>,
}
impl ReplyOriginals {
    pub(super) fn sequence(&self) -> u32 { self.sequence }
    pub(super) fn port_id(&self) -> u32 { self.port_id }
    pub(super) fn request(&self) -> &[u8] { &self.request }
    pub(super) fn datagrams(&self) -> &[Vec<u8>] { &self.datagrams }
}

pub(super) struct AckOriginals {
    request: Vec<u8>,
    datagrams: Vec<Vec<u8>>,
}
impl AckOriginals {
    pub(super) fn request(&self) -> &[u8] { &self.request }
    pub(super) fn datagrams(&self) -> &[Vec<u8>] { &self.datagrams }
}

struct Prepared { sha256: [u8; 32], first_sequence: u32, last_sequence: u32 }
type Identity = (u64, u64, u32, u32, u32);

pub(super) struct Backend<'a> {
    guard: &'a EgressGuard,
    lock: BackendLock<'a>,
    socket: File,
    socket_identity: Identity,
    namespace_device: u64,
    namespace_inode: u64,
    port_id: u32,
    next_sequence: u32,
    prepared: Option<Prepared>,
    attempted_mutation: bool,
    stopped: bool,
    messages: usize,
    events: u32,
    transcript: Vec<u8>,
    received: Vec<Vec<u8>>,
}

impl<'a> Backend<'a> {
    /// Journal lock must already be held, but no intended transaction or claim
    /// is needed yet. The independent backend lock is retained through root's
    /// subsequent durable completion, without borrowing the journal owner.
    pub(super) fn open(guard: &'a EgressGuard, reservation: &KernelReservation<'a>)
        -> Result<Self, String>
    {
        guard.check()?;
        let lock = reservation.backend_lock()?;
        lock.require_guard(guard)?;
        let socket = guard.duplicate_backend()?;
        lock.check()?;
        let meta = socket.metadata();
        guard.check()?;
        lock.check()?;
        let meta = meta.map_err(|_| "native backend socket metadata failed")?;
        let (namespace_device, namespace_inode, port_id, device, inode) = {
            let workload = guard.workload.try_borrow().map_err(|_| "native workload already borrowed")?;
            let actual = workload.identity();
            (actual.namespace_device, actual.namespace_inode, actual.backend_port_id,
                actual.backend_socket_device, actual.backend_socket_inode)
        };
        require(meta.dev() == device && meta.ino() == inode && port_id != 0)?;
        let mut transcript = Vec::with_capacity(MAX_TRANSCRIPT);
        transcript.extend_from_slice(TRANSCRIPT_MAGIC);
        transcript.extend_from_slice(&0u32.to_be_bytes());
        let mut owner = Self { guard, lock, socket,
            socket_identity: (meta.dev(), meta.ino(), meta.mode(), meta.uid(), meta.gid()),
            namespace_device, namespace_inode, port_id, next_sequence: 1,
            prepared: None, attempted_mutation: false, stopped: true, messages: 0,
            events: 0, transcript, received: Vec::new() };
        owner.current()?;
        // Deterministic compact ACKs; never suppress ENOBUFS, and reject any
        // platform that cannot establish the exact fixed socket options.
        for (option, value) in [(NETLINK_CAP_ACK, 1i32), (NETLINK_EXT_ACK, 0), (NETLINK_NO_ENOBUFS, 0)] {
            owner.io(|| {
                if unsafe { libc::setsockopt(owner.socket.as_raw_fd(), libc::SOL_NETLINK, option,
                    (&value as *const i32).cast(), std::mem::size_of::<i32>() as libc::socklen_t) } == 0 {
                    Ok(())
                } else { Err(io::Error::last_os_error()) }
            })?;
            require(owner.option(libc::SOL_NETLINK, option)? == value)?;
        }
        owner.quiet()?;
        owner.current()?;
        owner.stopped = false;
        Ok(owner)
    }

    fn source(&self) -> Result<(), String> {
        self.guard.check()?;
        self.lock.check()
    }

    // Private internal bracketing only; no callback crosses an API boundary.
    fn io<T>(&self, operation: impl FnOnce() -> io::Result<T>) -> Result<T, String> {
        self.source()?;
        let result = operation();
        self.source()?;
        result.map_err(|_| "native backend IO failed; outcome may be uncertain".to_owned())
    }

    fn option(&self, level: i32, name: i32) -> Result<i32, String> {
        self.io(|| {
            let mut value = 0i32;
            let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
            let result = unsafe { libc::getsockopt(self.socket.as_raw_fd(), level, name,
                (&mut value as *mut i32).cast(), &mut length) };
            if result == 0 && length as usize == std::mem::size_of::<i32>() { Ok(value) }
            else { Err(io::Error::last_os_error()) }
        })
    }

    fn current(&self) -> Result<(), String> {
        let meta = self.io(|| self.socket.metadata())?;
        require((meta.dev(), meta.ino(), meta.mode(), meta.uid(), meta.gid()) == self.socket_identity)?;
        let flags = self.io(|| {
            let flags = unsafe { libc::fcntl(self.socket.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 { Err(io::Error::last_os_error()) } else { Ok(flags) }
        })?;
        let descriptor_flags = self.io(|| {
            let flags = unsafe { libc::fcntl(self.socket.as_raw_fd(), libc::F_GETFD) };
            if flags < 0 { Err(io::Error::last_os_error()) } else { Ok(flags) }
        })?;
        require(flags & libc::O_NONBLOCK != 0 && descriptor_flags & libc::FD_CLOEXEC != 0
            && self.option(libc::SOL_SOCKET, libc::SO_DOMAIN)? == libc::AF_NETLINK
            && self.option(libc::SOL_SOCKET, libc::SO_TYPE)? == libc::SOCK_RAW
            && self.option(libc::SOL_SOCKET, libc::SO_PROTOCOL)? == libc::NETLINK_NETFILTER)?;
        let ns = self.io(|| {
            let fd = unsafe { libc::ioctl(self.socket.as_raw_fd(), SIOCGSKNS as _) };
            if fd < 0 { Err(io::Error::last_os_error()) }
            else { Ok(unsafe { File::from_raw_fd(fd) }) }
        })?;
        let meta = self.io(|| ns.metadata())?;
        require(meta.dev() == self.namespace_device && meta.ino() == self.namespace_inode
            && meta.uid() == 0 && meta.gid() == 0)?;
        let filesystem_type = self.io(|| {
            let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatfs(ns.as_raw_fd(), &mut stat) } == 0 { Ok(stat.f_type as libc::c_long) }
            else { Err(io::Error::last_os_error()) }
        })?;
        let namespace_type = self.io(|| {
            let value = unsafe { libc::ioctl(ns.as_raw_fd(), NS_GET_NSTYPE as _) };
            if value < 0 { Err(io::Error::last_os_error()) } else { Ok(value) }
        })?;
        require(filesystem_type == NSFS_MAGIC && namespace_type == libc::CLONE_NEWNET)?;
        let address = self.io(|| {
            let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut length = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            if unsafe { libc::getsockname(self.socket.as_raw_fd(),
                (&mut address as *mut libc::sockaddr_nl).cast(), &mut length) } == 0
                && length as usize == std::mem::size_of::<libc::sockaddr_nl>() { Ok(address) }
            else { Err(io::Error::last_os_error()) }
        })?;
        require(address.nl_family as i32 == libc::AF_NETLINK && address.nl_groups == 0
            && address.nl_pid == self.port_id)?;
        self.source()
    }

    fn begin(&mut self) -> Result<(), String> {
        require(!std::mem::replace(&mut self.stopped, true))?;
        self.current()
    }

    fn sequence(&mut self) -> Result<u32, String> {
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).ok_or("native netlink sequence exhausted")?;
        require(sequence != 0)?;
        Ok(sequence)
    }

    fn event(&mut self, tag: u8, raw: &[u8]) -> Result<(), String> {
        let events = self.events.checked_add(1).ok_or("native transcript event overflow")?;
        let length = self.transcript.len().checked_add(5).and_then(|length| length.checked_add(raw.len()))
            .ok_or("native transcript size overflow")?;
        require(matches!(tag, READ_REQUEST | MUTATION_ATTEMPT | KERNEL_DATAGRAM)
            && !raw.is_empty() && raw.len() <= wire::MAX_BATCH_BYTES
            && (tag != READ_REQUEST || raw.len() <= wire::MAX_MESSAGE_BYTES)
            && events <= MAX_EVENTS && length <= MAX_TRANSCRIPT)?;
        self.transcript.push(tag);
        self.transcript.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        self.transcript.extend_from_slice(raw);
        self.events = events;
        self.transcript[8..12].copy_from_slice(&events.to_be_bytes());
        Ok(())
    }

    fn quiet(&self) -> Result<(), String> {
        let (result, events) = self.io(|| {
            let mut poll = libc::pollfd { fd: self.socket.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let result = unsafe { libc::poll(&mut poll, 1, 0) };
            if result < 0 { Err(io::Error::last_os_error()) } else { Ok((result, poll.revents)) }
        })?;
        require(result == 0 && events == 0)
    }

    fn send_once(&mut self, tag: u8, raw: &[u8]) -> Result<(), String> {
        self.current()?;
        self.quiet()?;
        self.event(tag, raw)?; // An attempt is retained, never asserted as sent.
        let count = self.io(|| {
            let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            address.nl_family = libc::AF_NETLINK as u16; // kernel port/groups stay zero
            let mut vector = libc::iovec { iov_base: raw.as_ptr() as *mut libc::c_void, iov_len: raw.len() };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_name = (&mut address as *mut libc::sockaddr_nl).cast();
            message.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            message.msg_iov = &mut vector;
            message.msg_iovlen = 1;
            let result = unsafe { libc::sendmsg(self.socket.as_raw_fd(), &message,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
            if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result as usize) }
        })?;
        require(count == raw.len())?; // Including EAGAIN/partial: never resubmit.
        self.current()
    }

    fn receive(&mut self) -> Result<Vec<u8>, String> {
        let mut raw = vec![0u8; wire::MAX_BATCH_BYTES];
        loop {
            self.current()?;
            let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut vector = libc::iovec { iov_base: raw.as_mut_ptr().cast(), iov_len: raw.len() };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_name = (&mut address as *mut libc::sockaddr_nl).cast();
            message.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            message.msg_iov = &mut vector;
            message.msg_iovlen = 1;
            let count = unsafe { libc::recvmsg(self.socket.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
            let error = if count < 0 { Some(io::Error::last_os_error()) } else { None };
            if let Some(error) = error {
                self.source()?;
                if error.kind() != io::ErrorKind::WouldBlock {
                    return Err("native netlink receive failed or lost data".to_owned());
                }
                let timeout = self.guard.deadline()?.checked_duration_since(Instant::now())
                    .ok_or("native backend original deadline expired")?.as_millis().min(25) as i32;
                let events = self.io(|| {
                    let mut poll = libc::pollfd { fd: self.socket.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                    if unsafe { libc::poll(&mut poll, 1, timeout) } < 0 { Err(io::Error::last_os_error()) }
                    else { Ok(poll.revents) }
                })?;
                require(events & !(libc::POLLIN) == 0)?;
                continue; // Wait for this same response; no request retry.
            }
            // Only complete, correctly sourced kernel datagrams become tag3.
            // A truncation is uncertainty, never a fabricated complete original.
            let valid = count > 0 && count as usize <= raw.len()
                && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
                && message.msg_namelen as usize == std::mem::size_of::<libc::sockaddr_nl>()
                && address.nl_family as i32 == libc::AF_NETLINK && address.nl_pid == 0 && address.nl_groups == 0;
            if !valid { self.source()?; return Err("native netlink datagram provenance or extent refused".to_owned()); }
            raw.truncate(count as usize);
            let recorded = self.event(KERNEL_DATAGRAM, &raw);
            if recorded.is_ok() { self.received.push(raw.clone()); }
            let closing = self.source();
            recorded?;
            closing?;
            return Ok(raw);
        }
    }

    fn frames<'b>(&mut self, raw: &'b [u8]) -> Result<Vec<wire::Frame<'b>>, String> {
        let frames = wire::frames(raw)?;
        self.messages = self.messages.checked_add(frames.len()).ok_or("native reply count overflow")?;
        require(self.messages <= MAX_MESSAGES)?;
        Ok(frames)
    }

    fn query(&mut self, sequence: u32, request: Vec<u8>, kind: Option<DumpKind>) -> Result<ReplyOriginals, String> {
        self.send_once(READ_REQUEST, &request)?;
        let mut datagrams = Vec::new();
        loop {
            let raw = self.receive()?;
            let frames = self.frames(&raw)?;
            let mut done = false;
            for (index, frame) in frames.iter().enumerate() {
                require(frame.sequence == sequence && frame.port_id == self.port_id)?;
                match kind {
                    None => {
                        require(frames.len() == 1 && frame.message_type == wire::GENERATION_REPLY_TYPE
                            && frame.flags == 0)?;
                        done = true;
                    }
                    Some(kind) => {
                        if frame.message_type == NLMSG_DONE {
                            require(index + 1 == frames.len() && frame.flags == MULTI
                                && frame.payload == 0i32.to_ne_bytes())?;
                            done = true;
                        } else {
                            let expected_flags = if kind == DumpKind::Rules { MULTI | APPEND } else { MULTI };
                            require(frame.message_type == kind.reply_type() && frame.flags == expected_flags)?;
                        }
                    }
                }
            }
            drop(frames);
            datagrams.push(raw);
            if done { break; }
        }
        self.current()?;
        self.quiet()?;
        Ok(ReplyOriginals { sequence, port_id: self.port_id, request, datagrams })
    }

    pub(super) fn generation(&mut self) -> Result<ReplyOriginals, String> {
        self.begin()?;
        let sequence = self.sequence()?;
        let request = wire::get_generation_request(self.port_id, sequence)?;
        let originals = self.query(sequence, request, None)?;
        self.stopped = false;
        Ok(originals)
    }

    pub(super) fn dump(&mut self, kind: DumpKind, table: &str) -> Result<ReplyOriginals, String> {
        self.begin()?;
        require(table == self.guard.authorization.ruleset.table_name)?;
        let sequence = self.sequence()?;
        let request = wire::dump_request(kind, table, self.port_id, sequence)?;
        let originals = self.query(sequence, request, Some(kind))?;
        self.stopped = false;
        Ok(originals)
    }

    pub(super) fn transaction(&mut self, ruleset: &Ruleset, generation: u32) -> Result<Transaction, String> {
        self.begin()?;
        require(self.prepared.is_none() && !self.attempted_mutation
            && std::ptr::eq(ruleset, &self.guard.authorization.ruleset))?;
        let first_sequence = self.next_sequence;
        let transaction = Transaction::build(ruleset, generation, self.port_id, first_sequence)?;
        let last_sequence = transaction.last_sequence();
        require(last_sequence >= first_sequence && transaction.bytes().len() <= wire::MAX_BATCH_BYTES
            && !transaction.expected_acks().is_empty())?;
        self.next_sequence = last_sequence.checked_add(1).ok_or("native transaction sequence exhausted")?;
        self.prepared = Some(Prepared { sha256: digest(transaction.bytes()), first_sequence, last_sequence });
        self.current()?;
        self.stopped = false;
        Ok(transaction)
    }

    pub(super) fn submit_once(&mut self, transaction: &Transaction, reservation: &KernelReservation<'a>)
        -> Result<AckOriginals, String>
    {
        self.begin()?;
        require(!self.attempted_mutation)?;
        let prepared = self.prepared.as_ref().ok_or("native transaction was not prepared by this backend")?;
        let intended = digest(transaction.bytes());
        require(intended == prepared.sha256 && transaction.last_sequence() == prepared.last_sequence
            && transaction.expected_acks().iter().all(|ack|
                (prepared.first_sequence..=prepared.last_sequence).contains(&ack.sequence)))?;
        reservation.require_backend_claim(self.guard, intended)?;
        self.attempted_mutation = true;
        self.send_once(MUTATION_ATTEMPT, transaction.bytes())?;
        let mut seen = BTreeSet::new();
        let mut datagrams = Vec::new();
        while seen.len() < transaction.expected_acks().len() {
            let raw = self.receive()?;
            let frames = self.frames(&raw)?;
            for frame in &frames {
                let ack = transaction.expected_acks().iter().find(|ack| ack.sequence == frame.sequence)
                    .ok_or("native ACK sequence was not requested")?;
                require(frame.message_type == NLMSG_ERROR && frame.flags == CAPPED && frame.port_id == self.port_id
                    && frame.payload.len() == 20 && frame.payload[..4] == 0i32.to_ne_bytes()
                    && frame.payload[4..] == ack.expected_header
                    && u16::from_ne_bytes([ack.expected_header[4], ack.expected_header[5]]) == ack.message_type
                    && seen.insert(frame.sequence))?;
            }
            drop(frames);
            datagrams.push(raw);
        }
        require(seen.len() == transaction.expected_acks().len())?;
        self.current()?;
        self.quiet()?;
        self.stopped = false;
        Ok(AckOriginals { request: transaction.bytes().to_vec(), datagrams })
    }

    /// Fixed data-only raw custody remains available after failure. Neither
    /// copying it nor a caller's digest can revive this backend or its claim.
    pub(super) fn transcript_bytes(&self) -> Result<Vec<u8>, String> {
        require(self.transcript.len() <= MAX_TRANSCRIPT && self.events <= MAX_EVENTS)?;
        Ok(self.transcript.clone())
    }

    pub(super) fn received_originals(&self) -> &[Vec<u8>] { &self.received }
}
