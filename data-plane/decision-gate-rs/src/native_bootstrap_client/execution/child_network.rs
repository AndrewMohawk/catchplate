//! Originals created by the executable child itself, not a diagnostic owner.

pub(in super::super) use super::child::ChildNetworkBorrow;
use std::fs::File;
use std::mem::{size_of, size_of_val, zeroed};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

pub(super) const SOCKETS: &[u8; 8] = b"SWNENS01";
pub(super) const LISTENER: &[u8;8] = b"SWNEAP01";
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const SIOCGSKNS: libc::c_ulong = 0x894c;

fn require(ok: bool) -> Result<(), String> {
    if ok { Ok(()) } else { Err("native executable network originals differ".to_owned()) }
}

type Identity = (u64, u64, u32, u32, u32);
fn identity(file: &File) -> Result<Identity, String> {
    let m = file.metadata().map_err(|_| "native child socket original is unavailable")?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    require(flags >= 0 && flags & libc::FD_CLOEXEC != 0)?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}

fn namespace(fd: BorrowedFd<'_>) -> Result<(u64, u64), String> {
    let mut stat: libc::stat = unsafe { zeroed() };
    let mut fs: libc::statfs = unsafe { zeroed() };
    require(unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } == 0
        && unsafe { libc::fstatfs(fd.as_raw_fd(), &mut fs) } == 0
        && fs.f_type == 0x6e73_6673 && stat.st_uid == 0 && stat.st_gid == 0
        && unsafe { libc::ioctl(fd.as_raw_fd(), NS_GET_NSTYPE) } == libc::CLONE_NEWNET)?;
    Ok((stat.st_dev, stat.st_ino))
}

fn option(file: &File, name: i32) -> Result<i32, String> {
    let mut value = 0;
    let mut length = size_of::<i32>() as libc::socklen_t;
    require(unsafe { libc::getsockopt(file.as_raw_fd(), libc::SOL_SOCKET, name,
        (&mut value as *mut i32).cast(), &mut length) } == 0 && length as usize == size_of::<i32>())?;
    Ok(value)
}

struct Socket { file: File, identity: Identity, protocol: i32, port: u32 }
impl Socket {
    fn open(file: File, protocol: i32) -> Result<Self, String> {
        let mut address: libc::sockaddr_nl = unsafe { zeroed() };
        let mut length = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        require(unsafe { libc::getsockname(file.as_raw_fd(), (&mut address as *mut libc::sockaddr_nl).cast(),
            &mut length) } == 0 && length as usize == size_of::<libc::sockaddr_nl>()
            && address.nl_family == libc::AF_NETLINK as u16 && address.nl_pid != 0 && address.nl_groups == 0)?;
        let result = Self { identity: identity(&file)?, file, protocol, port: address.nl_pid };
        result.check_socket()?;
        Ok(result)
    }
    fn check_socket(&self) -> Result<(), String> {
        require(identity(&self.file)? == self.identity && self.identity.3 == 0 && self.identity.4 == 0
            && option(&self.file, libc::SO_DOMAIN)? == libc::AF_NETLINK
            && option(&self.file, libc::SO_TYPE)? == libc::SOCK_RAW
            && option(&self.file, libc::SO_PROTOCOL)? == self.protocol)?;
        let mut address: libc::sockaddr_nl = unsafe { zeroed() };
        let mut length = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        let flags = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFL) };
        require(flags >= 0 && flags & libc::O_NONBLOCK != 0
            && unsafe { libc::getsockname(self.file.as_raw_fd(), (&mut address as *mut libc::sockaddr_nl).cast(),
                &mut length) } == 0 && length as usize == size_of::<libc::sockaddr_nl>()
            && address.nl_family == libc::AF_NETLINK as u16 && address.nl_pid == self.port
            && address.nl_groups == 0)
    }
    fn check(&self, actual_namespace: BorrowedFd<'_>) -> Result<(), String> {
        self.check_socket()?;
        let raw = unsafe { libc::ioctl(self.file.as_raw_fd(), SIOCGSKNS) };
        require(raw >= 0)?;
        let held = unsafe { File::from_raw_fd(raw) };
        require(namespace(held.as_fd())? == namespace(actual_namespace)?)?;
        self.check_socket()
    }
    fn duplicate(&self, actual_namespace: BorrowedFd<'_>) -> Result<File, String> {
        self.check(actual_namespace)?;
        let file = duplicate(self.file.as_fd())?;
        require(identity(&file)? == self.identity)?;
        self.check(actual_namespace)?;
        Ok(file)
    }
}

pub(super) fn duplicate(fd: BorrowedFd<'_>) -> Result<File, String> {
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    require(raw >= 0)?;
    Ok(unsafe { File::from_raw_fd(raw) })
}

pub(super) struct Sockets { filter: Socket, route: Socket }
impl Sockets {
    pub(super) fn check(&self, namespace: BorrowedFd<'_>) -> Result<(), String> {
        self.filter.check(namespace)?;
        self.route.check(namespace)
    }
    pub(super) fn filter(&self, namespace: BorrowedFd<'_>) -> Result<File, String> {
        self.filter.duplicate(namespace)
    }
    pub(super) fn route(&self, namespace: BorrowedFd<'_>) -> Result<File, String> {
        self.route.duplicate(namespace)
    }
    pub(super) fn filter_identity(&self) -> (u64, u64, u32) {
        (self.filter.identity.0, self.filter.identity.1, self.filter.port)
    }
    pub(super) fn route_identity(&self) -> (u64, u64, u32) {
        (self.route.identity.0, self.route.identity.1, self.route.port)
    }
}

pub(super) struct Listener { file:File, identity:Identity }
impl Listener {
    fn open(file:File)->Result<Self,String> {
        Ok(Self{identity:identity(&file)?,file})
    }
    pub(super) fn check(&self, ns:BorrowedFd<'_>, port:u16)->Result<(),String> {
        require(identity(&self.file)?==self.identity && self.identity.3==0 && self.identity.4==0
            && option(&self.file,libc::SO_DOMAIN)?==libc::AF_INET
            && option(&self.file,libc::SO_TYPE)?==libc::SOCK_STREAM
            && option(&self.file,libc::SO_PROTOCOL)?==libc::IPPROTO_TCP
            && option(&self.file,libc::SO_ACCEPTCONN)?==1)?;
        let flags=unsafe{libc::fcntl(self.file.as_raw_fd(),libc::F_GETFL)};
        require(flags>=0 && flags & libc::O_NONBLOCK !=0)?;
        let mut address:libc::sockaddr_in=unsafe{zeroed()};let mut length=size_of::<libc::sockaddr_in>() as libc::socklen_t;
        require(unsafe{libc::getsockname(self.file.as_raw_fd(),(&mut address as *mut libc::sockaddr_in).cast(),&mut length)}==0
            && length as usize==size_of::<libc::sockaddr_in>() && address.sin_family==libc::AF_INET as u16
            && address.sin_addr.s_addr.to_ne_bytes()==[127,0,0,1] && u16::from_be(address.sin_port)==port)?;
        let raw=unsafe{libc::ioctl(self.file.as_raw_fd(),SIOCGSKNS)};require(raw>=0)?;
        let held=unsafe{File::from_raw_fd(raw)};require(namespace(held.as_fd())?==namespace(ns)?)
    }
    pub(super) fn duplicate(&self,ns:BorrowedFd<'_>,port:u16)->Result<std::net::TcpListener,String> {
        self.check(ns,port)?;let copy=duplicate(self.file.as_fd())?;
        require(identity(&copy)?==self.identity)?;self.check(ns,port)?;
        Ok(std::net::TcpListener::from(std::os::fd::OwnedFd::from(copy)))
    }
}
pub(super) enum Message { Originals(Sockets), Listener(Listener), Ready }

pub(super) fn receive(gate: BorrowedFd<'_>) -> Result<Message, String> {
    let mut bytes = [0u8; 9];
    let mut control = [0usize; 8];
    let mut iov = libc::iovec { iov_base: bytes.as_mut_ptr().cast(), iov_len: bytes.len() };
    let mut header: libc::msghdr = unsafe { zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = size_of_val(&control);
    let count = unsafe { libc::recvmsg(gate.as_raw_fd(), &mut header,
        libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT) };
    let mut descriptors = Vec::new();
    let mut valid_control = true;
    // Retain every delivered FD before rejecting a malformed/truncated record.
    let mut current = unsafe { libc::CMSG_FIRSTHDR(&header) };
    while !current.is_null() {
        let h = unsafe { &*current };
        let base = unsafe { libc::CMSG_LEN(0) } as usize;
        if h.cmsg_level != libc::SOL_SOCKET || h.cmsg_type != libc::SCM_RIGHTS
            || h.cmsg_len < base || (h.cmsg_len - base) % size_of::<i32>() != 0 {
            valid_control = false;
            break;
        }
        let length = (h.cmsg_len - base) / size_of::<i32>();
        for index in 0..length {
            let raw = unsafe { *(libc::CMSG_DATA(current).cast::<i32>().add(index)) };
            require(raw >= 0)?;
            descriptors.push(unsafe { File::from_raw_fd(raw) });
        }
        current = unsafe { libc::CMSG_NXTHDR(&header, current) };
    }
    require(count == 8 && valid_control && header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0)?;
    if &bytes[..8] == super::child_trampoline::READY {
        require(descriptors.is_empty() && header.msg_controllen == 0)?;
        return Ok(Message::Ready);
    }
    if &bytes[..8] == LISTENER {
        require(descriptors.len()==1 && header.msg_controllen==unsafe{libc::CMSG_SPACE(4)} as usize)?;
        return Ok(Message::Listener(Listener::open(descriptors.pop().ok_or("child listener absent")?)?));
    }
    require(&bytes[..8] == SOCKETS && descriptors.len() == 2
        && header.msg_controllen == unsafe { libc::CMSG_SPACE(8) } as usize)?;
    let route = descriptors.pop().ok_or("native child route original absent")?;
    let filter = descriptors.pop().ok_or("native child filter original absent")?;
    Ok(Message::Originals(Sockets { filter: Socket::open(filter, libc::NETLINK_NETFILTER)?,
        route: Socket::open(route, libc::NETLINK_ROUTE)? }))
}
