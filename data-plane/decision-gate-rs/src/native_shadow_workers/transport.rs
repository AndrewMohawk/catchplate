//! Kernel-authenticated private packets; unexpected descriptors are owned/closed.
use super::wire::{require, now, MAX_FRAME};
use std::{mem::{size_of, zeroed}, os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd}};
const SO_PASSPIDFD: i32 = 76;
const SCM_PIDFD: i32 = 4;
pub(super) use crate::response_observation_v2::custody::peer_measurement::{open_peer_pidfd, prove_owned_process, ensure_pidfd_alive};

pub(super) fn pair() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [-1; 2];
    require(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) } == 0)?;
    let a = unsafe { OwnedFd::from_raw_fd(fds[0]) }; let b = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    for fd in [&a, &b] { for option in [libc::SO_PASSCRED, SO_PASSPIDFD] {
        let yes = 1i32;
        require(unsafe { libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, option, (&yes as *const i32).cast(), size_of::<i32>() as _) } == 0)?;
    } }
    Ok((a,b))
}
pub(super) fn inherited(fd: RawFd) -> Result<OwnedFd, String> {
    require(unsafe { libc::fcntl(fd, libc::F_GETFD) } == 0
        && unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == 0)?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
pub(super) fn require_channel(fd: RawFd) -> Result<(), String> {
    for (option, expected) in [(libc::SO_TYPE,libc::SOCK_SEQPACKET), (libc::SO_DOMAIN,libc::AF_UNIX),
        (libc::SO_PASSCRED,1), (SO_PASSPIDFD,1)] {
        let mut value=0i32; let mut length=size_of::<i32>() as libc::socklen_t;
        require(unsafe {libc::getsockopt(fd,libc::SOL_SOCKET,option,(&mut value as *mut i32).cast(),&mut length)}==0
            && length as usize==size_of::<i32>() && value==expected)?;
    }
    let flags=unsafe {libc::fcntl(fd,libc::F_GETFL)};
    require(flags>=0 && flags & libc::O_NONBLOCK != 0)
}
pub(super) fn duplicate(fd: RawFd) -> Result<OwnedFd, String> {
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 20) };
    require(copy >= 20)?; Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}
pub(super) fn wait(socket: RawFd, events: i16, peer: &OwnedFd, deadline: u64) -> Result<(), String> {
    loop {
        require(now()? < deadline)?;
        ensure_pidfd_alive(peer).map_err(|_| "native shadow peer exited")?;
        let mut fds = [libc::pollfd {fd:socket,events,revents:0}, libc::pollfd {fd:peer.as_raw_fd(),events:libc::POLLIN,revents:0}];
        let sampled=now()?; require(sampled<deadline)?;
        let timeout = ((deadline - sampled) / 1_000_000).min(25).max(1) as i32;
        let result = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { continue; }
        require(result >= 0 && fds[1].revents == 0 && (fds[0].revents & !events) == 0)?;
        if fds[0].revents == events { require(now()? < deadline)?; return Ok(()); }
    }
}
pub(super) fn send(socket: RawFd, bytes: &[u8], descriptor: Option<RawFd>) -> Result<(), String> {
    require(!bytes.is_empty() && bytes.len() <= MAX_FRAME)?;
    let mut control = [0usize; 4];
    let mut vector = libc::iovec {iov_base:bytes.as_ptr() as *mut _, iov_len:bytes.len()};
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector; message.msg_iovlen = 1;
    if let Some(fd) = descriptor {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<i32>() as _) } as usize;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        require(!header.is_null())?;
        unsafe { (*header).cmsg_level = libc::SOL_SOCKET; (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as _) as usize;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), fd); }
    }
    require(unsafe { libc::sendmsg(socket, &message, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) } == bytes.len() as isize)
}
pub(super) struct Packet { pub(super) bytes:Vec<u8>, pub(super) descriptor:Option<OwnedFd>, pub(super) sender:OwnedFd, pub(super) credentials:libc::ucred }
pub(super) fn receive(socket: RawFd, expected_rights: usize) -> Result<Packet, String> {
    let mut bytes = [0u8; MAX_FRAME]; let mut control = [0usize; 64];
    let mut vector = libc::iovec {iov_base:bytes.as_mut_ptr().cast(),iov_len:bytes.len()};
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov=&mut vector; message.msg_iovlen=1;
    message.msg_control=control.as_mut_ptr().cast(); message.msg_controllen=size_of::<[usize;64]>();
    let length=unsafe {libc::recvmsg(socket,&mut message,libc::MSG_DONTWAIT|libc::MSG_CMSG_CLOEXEC)};
    require(length>=0)?;
    let mut bad=length==0 || length as usize>bytes.len() || message.msg_flags&(libc::MSG_TRUNC|libc::MSG_CTRUNC)!=0;
    let mut rights=Vec::new(); let mut senders=Vec::new(); let mut credentials=None;
    let mut header=unsafe {libc::CMSG_FIRSTHDR(&message)};
    while !header.is_null() {
        let item=unsafe {&*header}; let base=unsafe {libc::CMSG_LEN(0)} as usize;
        if item.cmsg_len<base || (header as usize).checked_sub(message.msg_control as usize)
            .and_then(|n|n.checked_add(item.cmsg_len)).is_none_or(|n|n>message.msg_controllen) {bad=true;break;}
        let count=item.cmsg_len-base; let data=unsafe {libc::CMSG_DATA(header)};
        if item.cmsg_level==libc::SOL_SOCKET && matches!(item.cmsg_type,libc::SCM_RIGHTS|SCM_PIDFD) {
            if count%size_of::<i32>()!=0 {bad=true;}
            for i in 0..count/size_of::<i32>() {
                let raw=unsafe {std::ptr::read_unaligned(data.add(i*size_of::<i32>()).cast::<i32>())};
                if raw<0 {bad=true;continue;}
                let fd=unsafe {OwnedFd::from_raw_fd(raw)};
                if unsafe {libc::fcntl(raw,libc::F_GETFD)}!=libc::FD_CLOEXEC {bad=true;}
                if item.cmsg_type==SCM_PIDFD {senders.push(fd);} else {rights.push(fd);}
            }
        } else if item.cmsg_level==libc::SOL_SOCKET && item.cmsg_type==libc::SCM_CREDENTIALS
            && count==size_of::<libc::ucred>() && credentials.is_none() {
            credentials=Some(unsafe {std::ptr::read_unaligned(data.cast::<libc::ucred>())});
        } else {bad=true;}
        header=unsafe {libc::CMSG_NXTHDR(&message,header)};
    }
    require(!bad && rights.len()==expected_rights && expected_rights<=1 && senders.len()==1 && credentials.is_some())?;
    Ok(Packet {bytes:bytes[..length as usize].to_vec(),descriptor:rights.pop(),sender:senders.pop().ok_or("shadow packet PIDFD absent")?,
        credentials:credentials.ok_or("shadow packet credentials absent")?})
}
