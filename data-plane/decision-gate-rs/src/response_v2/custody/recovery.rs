use ring::rand::{SecureRandom as _, SystemRandom};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::Digest as _;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use super::V2RuntimeError;

pub(crate) const MAX_SERVICE_FRAME_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy)]
pub(crate) struct BootDeadline {
    absolute_ns: u64,
}

impl BootDeadline {
    pub(crate) fn new(
        absolute_ns: u64,
    ) -> Result<Self, V2RuntimeError> {
        if absolute_ns == 0 || absolute_ns <= boottime_ns()? {
            return Err(V2RuntimeError::new(
                "custody_service_deadline_expired",
                "service deadline is absent or expired",
            ));
        }
        Ok(Self { absolute_ns })
    }

    pub(crate) fn absolute_ns(self) -> u64 {
        self.absolute_ns
    }

    pub(crate) fn remaining(
        self,
    ) -> Result<Duration, V2RuntimeError> {
        let now = boottime_ns()?;
        if now >= self.absolute_ns {
            return Err(V2RuntimeError::new(
                "custody_service_deadline_expired",
                "service deadline expired",
            ));
        }
        Ok(Duration::from_nanos(self.absolute_ns - now))
    }

    fn poll_timeout_ms(self) -> Result<i32, V2RuntimeError> {
        let remaining = self.remaining()?;
        let millis = remaining
            .as_millis()
            .clamp(1, i32::MAX as u128);
        Ok(millis as i32)
    }
}

pub(crate) struct ServiceConnection {
    stream: UnixStream,
    deadline: BootDeadline,
    max_frame_bytes: usize,
}

impl ServiceConnection {
    pub(crate) fn connect(
        path: &Path,
        deadline: BootDeadline,
        max_frame_bytes: usize,
    ) -> Result<Self, V2RuntimeError> {
        if !path.is_absolute()
            || max_frame_bytes == 0
            || max_frame_bytes > MAX_SERVICE_FRAME_BYTES
        {
            return Err(V2RuntimeError::new(
                "custody_service_connection_invalid",
                "service socket path or frame limit is invalid",
            ));
        }
        let fd = connect_nonblocking(path, deadline)?;
        let stream = UnixStream::from(fd);
        stream.set_nonblocking(true).map_err(|_| {
            V2RuntimeError::new(
                "custody_service_socket_configuration_failed",
                "set service socket nonblocking",
            )
        })?;
        Ok(Self {
            stream,
            deadline,
            max_frame_bytes,
        })
    }

    pub(crate) fn from_accepted(
        stream: UnixStream,
        deadline: BootDeadline,
        max_frame_bytes: usize,
    ) -> Result<Self, V2RuntimeError> {
        if max_frame_bytes == 0
            || max_frame_bytes > MAX_SERVICE_FRAME_BYTES
        {
            return Err(V2RuntimeError::new(
                "custody_service_connection_invalid",
                "accepted service frame limit is invalid",
            ));
        }
        stream.set_nonblocking(true).map_err(|_| {
            V2RuntimeError::new(
                "custody_service_socket_configuration_failed",
                "set accepted service socket nonblocking",
            )
        })?;
        Ok(Self {
            stream,
            deadline,
            max_frame_bytes,
        })
    }

    pub(crate) fn into_stream(self) -> UnixStream {
        self.stream
    }

    pub(crate) fn peer_credentials(
        &self,
    ) -> Result<libc::ucred, V2RuntimeError> {
        let mut credentials: libc::ucred = unsafe { zeroed() };
        let mut length =
            size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                self.stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut credentials as *mut libc::ucred
                    as *mut libc::c_void,
                &mut length,
            )
        } != 0
            || length as usize != size_of::<libc::ucred>()
            || credentials.pid <= 0
        {
            return Err(V2RuntimeError::new(
                "custody_service_peer_credentials_failed",
                "read connected service peer credentials",
            ));
        }
        Ok(credentials)
    }

    pub(crate) fn send<T: Serialize>(
        &mut self,
        value: &T,
    ) -> Result<(), V2RuntimeError> {
        let bytes = crate::canonical_json_bytes(value).map_err(|_| {
            V2RuntimeError::new(
                "custody_service_frame_invalid",
                "service frame cannot be canonicalized",
            )
        })?;
        if bytes.is_empty() || bytes.len() > self.max_frame_bytes {
            return Err(V2RuntimeError::new(
                "custody_service_frame_out_of_bounds",
                "service frame exceeds its signed bound",
            ));
        }
        let length = u32::try_from(bytes.len())
            .map_err(|_| {
                V2RuntimeError::new(
                    "custody_service_frame_out_of_bounds",
                    "service frame length is not representable",
                )
            })?
            .to_be_bytes();
        write_all_nonblocking(
            &self.stream,
            &length,
            self.deadline,
        )?;
        write_all_nonblocking(
            &self.stream,
            &bytes,
            self.deadline,
        )
    }

    pub(crate) fn send_with_fds<T: Serialize>(
        &mut self,
        value: &T,
        raw_fds: &[RawFd],
    ) -> Result<(), V2RuntimeError> {
        if raw_fds.is_empty() || raw_fds.len() > 1 {
            return Err(V2RuntimeError::new(
                "custody_service_exact_object_count_invalid",
                "exact-object service response must carry exactly one descriptor",
            ));
        }
        let bytes = crate::canonical_json_bytes(value).map_err(|_| {
            V2RuntimeError::new(
                "custody_service_frame_invalid",
                "service frame cannot be canonicalized",
            )
        })?;
        if bytes.is_empty() || bytes.len() > self.max_frame_bytes {
            return Err(V2RuntimeError::new(
                "custody_service_frame_out_of_bounds",
                "service frame exceeds its signed bound",
            ));
        }
        let length = u32::try_from(bytes.len())
            .map_err(|_| {
                V2RuntimeError::new(
                    "custody_service_frame_out_of_bounds",
                    "service frame length is not representable",
                )
            })?
            .to_be_bytes();
        let mut frame = Vec::with_capacity(4 + bytes.len());
        frame.extend_from_slice(&length);
        frame.extend_from_slice(&bytes);
        send_frame_with_fds(
            &self.stream,
            &frame,
            raw_fds,
            self.deadline,
        )
    }

    pub(crate) fn receive<T: DeserializeOwned>(
        &mut self,
    ) -> Result<T, V2RuntimeError> {
        let mut length = [0u8; 4];
        read_exact_nonblocking(
            &self.stream,
            &mut length,
            self.deadline,
        )?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > self.max_frame_bytes {
            return Err(V2RuntimeError::new(
                "custody_service_frame_out_of_bounds",
                "received service frame exceeds its signed bound",
            ));
        }
        let mut bytes = vec![0u8; length];
        read_exact_nonblocking(
            &self.stream,
            &mut bytes,
            self.deadline,
        )?;
        let immutable_bytes = bytes.into_boxed_slice();
        crate::decode_canonical_json(&immutable_bytes).map_err(|_| {
            V2RuntimeError::new(
                "custody_service_frame_invalid",
                "received service frame is not a canonical closed DTO",
            )
        })
    }

    pub(crate) fn receive_with_fds<T: DeserializeOwned>(
        &mut self,
        max_fds: usize,
    ) -> Result<(T, Vec<OwnedFd>), V2RuntimeError> {
        if max_fds == 0 || max_fds > 1 {
            return Err(V2RuntimeError::new(
                "custody_service_exact_object_count_invalid",
                "service exact-object receive bound is invalid",
            ));
        }
        let mut length = [0u8; 4];
        let (prefix_bytes, fds) = receive_prefix_with_fds(
            &self.stream,
            &mut length,
            max_fds,
            self.deadline,
        )?;
        if prefix_bytes < length.len() {
            read_exact_nonblocking(
                &self.stream,
                &mut length[prefix_bytes..],
                self.deadline,
            )?;
        }
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > self.max_frame_bytes {
            return Err(V2RuntimeError::new(
                "custody_service_frame_out_of_bounds",
                "received service frame exceeds its signed bound",
            ));
        }
        let mut bytes = vec![0u8; length];
        read_exact_nonblocking(
            &self.stream,
            &mut bytes,
            self.deadline,
        )?;
        let immutable_bytes = bytes.into_boxed_slice();
        let value =
            crate::decode_canonical_json(&immutable_bytes).map_err(|_| {
                V2RuntimeError::new(
                    "custody_service_frame_invalid",
                    "received service frame is not a canonical closed DTO",
                )
            })?;
        Ok((value, fds))
    }
}

pub(crate) fn random_challenge_nonce(
) -> Result<String, V2RuntimeError> {
    let mut bytes = [0u8; 32];
    SystemRandom::new().fill(&mut bytes).map_err(|_| {
        V2RuntimeError::new(
            "custody_service_random_failed",
            "generate service handshake challenge",
        )
    })?;
    Ok(format!("sha256:{:x}", sha2::Sha256::digest(bytes)))
}

pub(crate) fn boottime_ns() -> Result<u64, V2RuntimeError> {
    let mut value: libc::timespec = unsafe { zeroed() };
    if unsafe {
        libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value)
    } != 0
        || value.tv_sec < 0
        || value.tv_nsec < 0
    {
        return Err(V2RuntimeError::new(
            "custody_boottime_unavailable",
            "read CLOCK_BOOTTIME",
        ));
    }
    u64::try_from(value.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|base| {
            u64::try_from(value.tv_nsec)
                .ok()
                .and_then(|nanos| base.checked_add(nanos))
        })
        .ok_or_else(|| {
            V2RuntimeError::new(
                "custody_boottime_overflow",
                "CLOCK_BOOTTIME is not representable",
            )
        })
}

pub(crate) fn kernel_boot_id() -> Result<String, V2RuntimeError> {
    let value = std::fs::read_to_string(
        "/proc/sys/kernel/random/boot_id",
    )
    .map_err(|_| {
        V2RuntimeError::new(
            "custody_boot_id_unavailable",
            "read the kernel boot ID",
        )
    })?;
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_hexdigit() || byte == b'-'
        })
    {
        return Err(V2RuntimeError::new(
            "custody_boot_id_invalid",
            "kernel boot ID is not canonical",
        ));
    }
    Ok(value.to_owned())
}

fn connect_nonblocking(
    path: &Path,
    deadline: BootDeadline,
) -> Result<OwnedFd, V2RuntimeError> {
    let path_bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    if path_bytes.is_empty()
        || path_bytes.len() >= address.sun_path.len()
        || path_bytes.contains(&0)
    {
        return Err(V2RuntimeError::new(
            "custody_service_socket_path_invalid",
            "service socket path is invalid or too long",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address
        .sun_path
        .iter_mut()
        .zip(path_bytes.iter().copied())
    {
        *target = source as libc::c_char;
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM
                | libc::SOCK_NONBLOCK
                | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return Err(V2RuntimeError::new(
            "custody_service_socket_failed",
            "create service socket",
        ));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let address_length = (size_of::<libc::sa_family_t>()
        + path_bytes.len()
        + 1) as libc::socklen_t;
    let result = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            &address as *const libc::sockaddr_un
                as *const libc::sockaddr,
            address_length,
        )
    };
    if result == 0 {
        return Ok(fd);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::EINPROGRESS) {
        return Err(V2RuntimeError::new(
            "custody_service_connect_failed",
            "connect to service socket",
        ));
    }
    poll_fd(
        fd.as_raw_fd(),
        libc::POLLOUT,
        deadline,
    )?;
    let mut socket_error = 0;
    let mut error_length =
        size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut socket_error as *mut libc::c_int
                as *mut libc::c_void,
            &mut error_length,
        )
    } != 0
        || socket_error != 0
    {
        return Err(V2RuntimeError::new(
            "custody_service_connect_failed",
            "service socket did not complete a deadline-bounded connection",
        ));
    }
    Ok(fd)
}

fn send_frame_with_fds(
    stream: &UnixStream,
    frame: &[u8],
    raw_fds: &[RawFd],
    deadline: BootDeadline,
) -> Result<(), V2RuntimeError> {
    let payload_bytes = raw_fds
        .len()
        .checked_mul(size_of::<RawFd>())
        .and_then(|value| libc::c_uint::try_from(value).ok())
        .ok_or_else(|| {
            V2RuntimeError::new(
                "custody_service_ancillary_overflow",
                "service descriptor ancillary size overflowed",
            )
        })?;
    let ancillary_bytes =
        usize::try_from(unsafe { libc::CMSG_SPACE(payload_bytes) })
            .map_err(|_| {
                V2RuntimeError::new(
                    "custody_service_ancillary_overflow",
                    "service descriptor ancillary size is unsupported",
                )
            })?;
    let word_size = size_of::<usize>();
    let mut ancillary =
        vec![0usize; ancillary_bytes.div_ceil(word_size)];
    let mut iovec = libc::iovec {
        iov_base: frame.as_ptr().cast_mut().cast(),
        iov_len: frame.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = ancillary_bytes;
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(V2RuntimeError::new(
            "custody_service_ancillary_invalid",
            "construct service SCM_RIGHTS header",
        ));
    }
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len =
            usize::try_from(libc::CMSG_LEN(payload_bytes))
                .expect("CMSG_LEN fits usize");
        std::ptr::copy_nonoverlapping(
            raw_fds.as_ptr(),
            libc::CMSG_DATA(header).cast::<RawFd>(),
            raw_fds.len(),
        );
    }
    let sent = loop {
        poll_fd(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
        let sent = unsafe {
            libc::sendmsg(
                stream.as_raw_fd(),
                &message,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if sent > 0 {
            break sent;
        }
        if sent < 0
            && matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR) | Some(libc::EAGAIN)
            )
        {
            continue;
        }
        return Err(V2RuntimeError::new(
            "custody_service_write_failed",
            "send service frame with exact-object descriptor",
        ));
    };
    let sent = usize::try_from(sent).map_err(|_| {
        V2RuntimeError::new(
            "custody_service_write_failed",
            "service frame write length is invalid",
        )
    })?;
    if sent < frame.len() {
        write_all_nonblocking(
            stream,
            &frame[sent..],
            deadline,
        )?;
    }
    Ok(())
}

fn receive_prefix_with_fds(
    stream: &UnixStream,
    prefix: &mut [u8; 4],
    max_fds: usize,
    deadline: BootDeadline,
) -> Result<(usize, Vec<OwnedFd>), V2RuntimeError> {
    poll_fd(stream.as_raw_fd(), libc::POLLIN, deadline)?;
    let payload_bytes = max_fds
        .checked_mul(size_of::<RawFd>())
        .and_then(|value| libc::c_uint::try_from(value).ok())
        .ok_or_else(|| {
            V2RuntimeError::new(
                "custody_service_ancillary_overflow",
                "service receive ancillary size overflowed",
            )
        })?;
    let ancillary_bytes =
        usize::try_from(unsafe { libc::CMSG_SPACE(payload_bytes) })
            .map_err(|_| {
                V2RuntimeError::new(
                    "custody_service_ancillary_overflow",
                    "service receive ancillary size is unsupported",
                )
            })?;
    let word_size = size_of::<usize>();
    let mut ancillary =
        vec![0usize; ancillary_bytes.div_ceil(word_size)];
    let mut iovec = libc::iovec {
        iov_base: prefix.as_mut_ptr().cast(),
        iov_len: prefix.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = ancillary_bytes;
    let received = unsafe {
        libc::recvmsg(
            stream.as_raw_fd(),
            &mut message,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if received <= 0
        || message.msg_flags & libc::MSG_CTRUNC != 0
        || message.msg_controllen > ancillary_bytes
    {
        return Err(V2RuntimeError::new(
            "custody_service_ancillary_receive_failed",
            "receive service frame and exact-object descriptor",
        ));
    }
    let received = usize::try_from(received).map_err(|_| {
        V2RuntimeError::new(
            "custody_service_read_failed",
            "service frame prefix length is invalid",
        )
    })?;
    let fds = parse_rights_ancillary(
        ancillary.as_ptr().cast::<u8>(),
        message.msg_controllen,
        max_fds,
    )?;
    Ok((received, fds))
}

fn parse_rights_ancillary(
    base: *const u8,
    returned_length: usize,
    max_fds: usize,
) -> Result<Vec<OwnedFd>, V2RuntimeError> {
    if returned_length == 0 {
        return Ok(Vec::new());
    }
    if base.is_null()
        || (base as usize) % std::mem::align_of::<libc::cmsghdr>() != 0
    {
        return Err(V2RuntimeError::new(
            "custody_service_ancillary_invalid",
            "service ancillary region is absent or misaligned",
        ));
    }
    let header = unsafe { &*(base.cast::<libc::cmsghdr>()) };
    let data_offset =
        usize::try_from(unsafe { libc::CMSG_LEN(0) }).map_err(|_| {
            V2RuntimeError::new(
                "custody_service_ancillary_invalid",
                "service ancillary header length is unsupported",
            )
        })?;
    if header.cmsg_level != libc::SOL_SOCKET
        || header.cmsg_type != libc::SCM_RIGHTS
        || header.cmsg_len < data_offset
        || header.cmsg_len > returned_length
    {
        return Err(V2RuntimeError::new(
            "custody_service_ancillary_invalid",
            "service ancillary record is not exact SCM_RIGHTS",
        ));
    }
    let payload_length = header.cmsg_len - data_offset;
    let descriptor_count = payload_length / size_of::<RawFd>();
    let expected_space = usize::try_from(unsafe {
        libc::CMSG_SPACE(
            libc::c_uint::try_from(payload_length).map_err(|_| {
                V2RuntimeError::new(
                    "custody_service_ancillary_invalid",
                    "service SCM_RIGHTS payload length is unsupported",
                )
            })?,
        )
    })
    .map_err(|_| {
        V2RuntimeError::new(
            "custody_service_ancillary_invalid",
            "service SCM_RIGHTS padded length is unsupported",
        )
    })?;
    if payload_length == 0
        || payload_length % size_of::<RawFd>() != 0
        || descriptor_count > max_fds
        || returned_length != expected_space
    {
        return Err(V2RuntimeError::new(
            "custody_service_ancillary_invalid",
            "service SCM_RIGHTS payload has the wrong descriptor count",
        ));
    }
    let raw = unsafe {
        std::slice::from_raw_parts(
            base.add(data_offset).cast::<RawFd>(),
            descriptor_count,
        )
    };
    if raw.iter().any(|fd| *fd < 0) {
        return Err(V2RuntimeError::new(
            "custody_service_ancillary_invalid",
            "service SCM_RIGHTS payload contains an invalid descriptor",
        ));
    }
    Ok(raw
        .iter()
        .copied()
        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
        .collect())
}

fn write_all_nonblocking(
    stream: &UnixStream,
    mut bytes: &[u8],
    deadline: BootDeadline,
) -> Result<(), V2RuntimeError> {
    while !bytes.is_empty() {
        poll_fd(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
        let count = unsafe {
            libc::send(
                stream.as_raw_fd(),
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if count > 0 {
            bytes = &bytes[count as usize..];
        } else if count < 0
            && matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR) | Some(libc::EAGAIN)
            )
        {
            continue;
        } else {
            return Err(V2RuntimeError::new(
                "custody_service_write_failed",
                "write service frame",
            ));
        }
    }
    Ok(())
}

fn read_exact_nonblocking(
    stream: &UnixStream,
    mut bytes: &mut [u8],
    deadline: BootDeadline,
) -> Result<(), V2RuntimeError> {
    while !bytes.is_empty() {
        poll_fd(stream.as_raw_fd(), libc::POLLIN, deadline)?;
        let count = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                bytes.as_mut_ptr() as *mut libc::c_void,
                bytes.len(),
                0,
            )
        };
        if count > 0 {
            let (_, remaining) =
                bytes.split_at_mut(count as usize);
            bytes = remaining;
        } else if count < 0
            && matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR) | Some(libc::EAGAIN)
            )
        {
            continue;
        } else {
            return Err(V2RuntimeError::new(
                "custody_service_read_failed",
                "read service frame",
            ));
        }
    }
    Ok(())
}

fn poll_fd(
    fd: libc::c_int,
    events: libc::c_short,
    deadline: BootDeadline,
) -> Result<(), V2RuntimeError> {
    loop {
        let mut pollfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe {
            libc::poll(
                &mut pollfd,
                1,
                deadline.poll_timeout_ms()?,
            )
        };
        if result > 0
            && pollfd.revents
                & (libc::POLLERR
                    | libc::POLLHUP
                    | libc::POLLNVAL)
                != 0
        {
            return Err(V2RuntimeError::new(
                "custody_service_socket_closed",
                "service socket closed or faulted",
            ));
        }
        if result > 0 && pollfd.revents & events != 0 {
            return Ok(());
        }
        if result == 0 {
            return Err(V2RuntimeError::new(
                "custody_service_deadline_expired",
                "service I/O exceeded CLOCK_BOOTTIME deadline",
            ));
        }
        if result < 0
            && io::Error::last_os_error().raw_os_error()
                == Some(libc::EINTR)
        {
            continue;
        }
        if result < 0 {
            return Err(V2RuntimeError::new(
                "custody_service_poll_failed",
                "poll service socket",
            ));
        }
    }
}
