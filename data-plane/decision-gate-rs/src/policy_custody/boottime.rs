use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::os::fd::{
    AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd,
};
use std::ptr;
use std::rc::Rc;

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const MAX_POLL_TARGETS: usize = 1_024;
const BOOT_ID_PATH: &[u8] =
    b"/proc/sys/kernel/random/boot_id\0";
const TIME_NAMESPACE_PATH: &[u8] = b"/proc/self/ns/time\0";
const BOOT_ID_TEXT_LENGTH: usize = 36;
const MAX_BOOT_ID_BYTES: usize = 64;

pub(super) type BoottimeResult<T> = Result<T, BoottimeError>;

#[derive(Debug)]
pub(super) enum BoottimeError {
    UnsupportedPlatform,
    Invalid(&'static str),
    Overflow(&'static str),
    DeadlineExpired {
        deadline_nanos: u64,
        observed_nanos: u64,
    },
    DomainMismatch {
        expected: BoottimeDomain,
        observed: BoottimeDomain,
    },
    InvalidDescriptor {
        index: usize,
    },
    SystemCall {
        operation: &'static str,
        source: io::Error,
    },
}

impl fmt::Display for BoottimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("CLOCK_BOOTTIME requires Linux")
            }
            Self::Invalid(message) | Self::Overflow(message) => {
                formatter.write_str(message)
            }
            Self::DeadlineExpired {
                deadline_nanos,
                observed_nanos,
            } => write!(
                formatter,
                "CLOCK_BOOTTIME deadline {deadline_nanos} expired at {observed_nanos}"
            ),
            Self::DomainMismatch { expected, observed } => write!(
                formatter,
                "CLOCK_BOOTTIME domain mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::InvalidDescriptor { index } => {
                write!(formatter, "poll target {index} is invalid")
            }
            Self::SystemCall { operation, source } => {
                write!(formatter, "{operation} failed: {source}")
            }
        }
    }
}

impl std::error::Error for BoottimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SystemCall { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn system_call_error(operation: &'static str) -> BoottimeError {
    BoottimeError::SystemCall {
        operation,
        source: io::Error::last_os_error(),
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct LinuxTimeNamespaceIdentity {
    device: u64,
    inode: u64,
}

impl LinuxTimeNamespaceIdentity {
    pub(super) fn from_expected(
        device: u64,
        inode: u64,
    ) -> BoottimeResult<Self> {
        if device == 0 || inode == 0 {
            return Err(BoottimeError::Invalid(
                "time namespace identity must be nonzero",
            ));
        }
        Ok(Self { device, inode })
    }

    pub(super) fn device(self) -> u64 {
        self.device
    }

    pub(super) fn inode(self) -> u64 {
        self.inode
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct BoottimeDomain {
    authority_boot_id: [u8; 16],
    time_namespace: LinuxTimeNamespaceIdentity,
}

impl BoottimeDomain {
    pub(super) fn from_expected(
        authority_boot_id: [u8; 16],
        time_namespace_device: u64,
        time_namespace_inode: u64,
    ) -> BoottimeResult<Self> {
        if authority_boot_id == [0_u8; 16] {
            return Err(BoottimeError::Invalid(
                "authority boot ID must be nonzero",
            ));
        }
        Ok(Self {
            authority_boot_id,
            time_namespace: LinuxTimeNamespaceIdentity::from_expected(
                time_namespace_device,
                time_namespace_inode,
            )?,
        })
    }

    #[cfg(target_os = "linux")]
    pub(super) fn current() -> BoottimeResult<Self> {
        let authority_boot_id = read_authority_boot_id()?;
        let time_namespace = read_time_namespace_identity()?;
        if read_authority_boot_id()? != authority_boot_id
            || read_time_namespace_identity()? != time_namespace
        {
            return Err(BoottimeError::Invalid(
                "BOOTTIME domain changed during observation",
            ));
        }
        Ok(Self {
            authority_boot_id,
            time_namespace,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn current() -> BoottimeResult<Self> {
        Err(BoottimeError::UnsupportedPlatform)
    }

    pub(super) fn authority_boot_id(self) -> [u8; 16] {
        self.authority_boot_id
    }

    pub(super) fn time_namespace(
        self,
    ) -> LinuxTimeNamespaceIdentity {
        self.time_namespace
    }

    pub(super) fn require_current(self) -> BoottimeResult<()> {
        let observed = Self::current()?;
        if observed != self {
            return Err(BoottimeError::DomainMismatch {
                expected: self,
                observed,
            });
        }
        Ok(())
    }

    pub(super) fn require_same_current(
        self,
        expected: Self,
    ) -> BoottimeResult<()> {
        if self != expected {
            return Err(BoottimeError::DomainMismatch {
                expected,
                observed: self,
            });
        }
        expected.require_current()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[must_use]
pub(super) struct BoottimeDeadline {
    domain: BoottimeDomain,
    absolute_nanos: u64,
}

impl BoottimeDeadline {
    pub(super) fn from_absolute_in_expected_domain(
        expected_domain: BoottimeDomain,
        absolute_nanos: u64,
    ) -> BoottimeResult<Self> {
        expected_domain.require_current()?;
        if absolute_nanos == 0 {
            return Err(BoottimeError::Invalid(
                "CLOCK_BOOTTIME deadline must be nonzero",
            ));
        }
        checked_timespec_from_nanos(absolute_nanos)?;
        Ok(Self {
            domain: expected_domain,
            absolute_nanos,
        })
    }

    pub(super) fn domain(self) -> BoottimeDomain {
        self.domain
    }

    pub(super) fn absolute_nanos(self) -> u64 {
        self.absolute_nanos
    }

    pub(super) fn remaining_nanos(self) -> BoottimeResult<u64> {
        self.domain.require_current()?;
        Ok(self
            .absolute_nanos
            .saturating_sub(boottime_now_nanos()?))
    }

    pub(super) fn expired(self) -> BoottimeResult<bool> {
        self.domain.require_current()?;
        Ok(boottime_now_nanos()? >= self.absolute_nanos)
    }

    pub(super) fn require_live(self) -> BoottimeResult<()> {
        self.live_observation().map(|_| ())
    }

    pub(super) fn require_expected_domain(
        self,
        expected_domain: BoottimeDomain,
    ) -> BoottimeResult<()> {
        self.domain.require_same_current(expected_domain)
    }

    pub(super) fn mutation_token(
        self,
    ) -> BoottimeResult<DeadlineOperationToken> {
        self.operation_token(DeadlineOperation::Mutation)
    }

    pub(super) fn signature_token(
        self,
    ) -> BoottimeResult<DeadlineOperationToken> {
        self.operation_token(DeadlineOperation::Signature)
    }

    pub(super) fn release_token(
        self,
    ) -> BoottimeResult<DeadlineOperationToken> {
        self.operation_token(DeadlineOperation::Release)
    }

    fn operation_token(
        self,
        operation: DeadlineOperation,
    ) -> BoottimeResult<DeadlineOperationToken> {
        let opened_at_nanos = self.live_observation()?;
        Ok(DeadlineOperationToken {
            deadline: self,
            operation,
            opened_at_nanos,
            _same_thread: PhantomData,
        })
    }

    fn derived_at(self, absolute_nanos: u64) -> BoottimeResult<Self> {
        if absolute_nanos == 0
            || absolute_nanos > self.absolute_nanos
        {
            return Err(BoottimeError::Invalid(
                "derived deadline exceeds its authority deadline",
            ));
        }
        checked_timespec_from_nanos(absolute_nanos)?;
        Ok(Self {
            domain: self.domain,
            absolute_nanos,
        })
    }

    fn live_observation(self) -> BoottimeResult<u64> {
        self.domain.require_current()?;
        let observed_nanos = boottime_now_nanos()?;
        if observed_nanos >= self.absolute_nanos {
            return Err(BoottimeError::DeadlineExpired {
                deadline_nanos: self.absolute_nanos,
                observed_nanos,
            });
        }
        Ok(observed_nanos)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DeadlineOperation {
    Mutation,
    Signature,
    Release,
}

#[derive(Debug)]
#[must_use = "operation tokens must be consumed at the protected boundary"]
pub(super) struct DeadlineOperationToken {
    deadline: BoottimeDeadline,
    operation: DeadlineOperation,
    opened_at_nanos: u64,
    _same_thread: PhantomData<Rc<()>>,
}

impl DeadlineOperationToken {
    /// The closure must contain only the final nonblocking atomic action.
    pub(super) fn execute_nonblocking<T, E>(
        self,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<DeadlineOperationResult<T>, DeadlineOperationError<E>> {
        let authorized_at_nanos = self
            .deadline
            .live_observation()
            .map_err(DeadlineOperationError::Authority)?;
        let value = action().map_err(DeadlineOperationError::Action)?;
        self.deadline
            .domain
            .require_current()
            .map_err(DeadlineOperationError::Authority)?;
        let completed_at_nanos = boottime_now_nanos()
            .map_err(DeadlineOperationError::Authority)?;
        Ok(DeadlineOperationResult {
            deadline: self.deadline,
            operation: self.operation,
            token_opened_at_nanos: self.opened_at_nanos,
            authorized_at_nanos,
            completed_at_nanos,
            value,
        })
    }
}

#[derive(Debug)]
pub(super) enum DeadlineOperationError<E> {
    Authority(BoottimeError),
    Action(E),
}

impl<E: fmt::Display> fmt::Display for DeadlineOperationError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => error.fmt(formatter),
            Self::Action(error) => error.fmt(formatter),
        }
    }
}

impl<E> std::error::Error for DeadlineOperationError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Action(error) => Some(error),
        }
    }
}

#[derive(Debug)]
#[must_use = "protected operation results must be checked before use"]
pub(super) struct DeadlineOperationResult<T> {
    deadline: BoottimeDeadline,
    operation: DeadlineOperation,
    token_opened_at_nanos: u64,
    authorized_at_nanos: u64,
    completed_at_nanos: u64,
    value: T,
}

impl<T> DeadlineOperationResult<T> {
    pub(super) fn deadline(&self) -> BoottimeDeadline {
        self.deadline
    }

    pub(super) fn operation(&self) -> DeadlineOperation {
        self.operation
    }

    pub(super) fn token_opened_at_nanos(&self) -> u64 {
        self.token_opened_at_nanos
    }

    pub(super) fn authorized_at_nanos(&self) -> u64 {
        self.authorized_at_nanos
    }

    pub(super) fn completed_at_nanos(&self) -> u64 {
        self.completed_at_nanos
    }

    pub(super) fn completed_before_deadline(&self) -> bool {
        self.completed_at_nanos < self.deadline.absolute_nanos()
    }

    pub(super) fn into_value(self) -> T {
        self.value
    }
}

#[cfg(target_os = "linux")]
fn read_authority_boot_id() -> BoottimeResult<[u8; 16]> {
    let descriptor = open_owned_descriptor(
        BOOT_ID_PATH,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        "open(authority boot ID)",
    )?;
    let mut bytes = [0_u8; MAX_BOOT_ID_BYTES];
    let mut length = 0_usize;
    loop {
        if length == bytes.len() {
            return Err(BoottimeError::Invalid(
                "authority boot ID exceeds its bounded representation",
            ));
        }
        let read = unsafe {
            libc::read(
                descriptor.as_raw_fd(),
                bytes[length..].as_mut_ptr().cast(),
                bytes.len() - length,
            )
        };
        if read == 0 {
            break;
        }
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(BoottimeError::SystemCall {
                operation: "read(authority boot ID)",
                source: error,
            });
        }
        length = length.checked_add(read as usize).ok_or(
            BoottimeError::Overflow(
                "authority boot ID read length overflow",
            ),
        )?;
    }

    while length > 0 && bytes[length - 1].is_ascii_whitespace() {
        length -= 1;
    }
    parse_boot_id(&bytes[..length])
}

#[cfg(target_os = "linux")]
fn parse_boot_id(bytes: &[u8]) -> BoottimeResult<[u8; 16]> {
    if bytes.len() != BOOT_ID_TEXT_LENGTH
        || bytes[8] != b'-'
        || bytes[13] != b'-'
        || bytes[18] != b'-'
        || bytes[23] != b'-'
    {
        return Err(BoottimeError::Invalid(
            "authority boot ID is not a canonical UUID",
        ));
    }

    let mut result = [0_u8; 16];
    let mut source = 0_usize;
    let mut destination = 0_usize;
    while source < bytes.len() {
        if matches!(source, 8 | 13 | 18 | 23) {
            source += 1;
            continue;
        }
        let high = decode_hex_nibble(bytes[source])?;
        let low = decode_hex_nibble(bytes[source + 1])?;
        result[destination] = (high << 4) | low;
        source += 2;
        destination += 1;
    }
    if destination != result.len() || result == [0_u8; 16] {
        return Err(BoottimeError::Invalid(
            "authority boot ID is invalid",
        ));
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
fn decode_hex_nibble(byte: u8) -> BoottimeResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(BoottimeError::Invalid(
            "authority boot ID contains non-hex data",
        )),
    }
}

#[cfg(target_os = "linux")]
fn read_time_namespace_identity(
) -> BoottimeResult<LinuxTimeNamespaceIdentity> {
    let descriptor = open_owned_descriptor(
        TIME_NAMESPACE_PATH,
        libc::O_RDONLY | libc::O_CLOEXEC,
        "open(time namespace)",
    )?;
    loop {
        let mut metadata = MaybeUninit::<libc::stat>::uninit();
        let status = unsafe {
            libc::fstat(descriptor.as_raw_fd(), metadata.as_mut_ptr())
        };
        if status == 0 {
            let metadata = unsafe { metadata.assume_init() };
            let device = u64::try_from(metadata.st_dev).map_err(|_| {
                BoottimeError::Overflow(
                    "time namespace device identity overflow",
                )
            })?;
            let inode = u64::try_from(metadata.st_ino).map_err(|_| {
                BoottimeError::Overflow(
                    "time namespace inode identity overflow",
                )
            })?;
            return LinuxTimeNamespaceIdentity::from_expected(
                device, inode,
            );
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(BoottimeError::SystemCall {
                operation: "fstat(time namespace)",
                source: error,
            });
        }
    }
}

#[cfg(target_os = "linux")]
fn open_owned_descriptor(
    nul_terminated_path: &[u8],
    flags: libc::c_int,
    operation: &'static str,
) -> BoottimeResult<OwnedFd> {
    if nul_terminated_path.last() != Some(&0) {
        return Err(BoottimeError::Invalid(
            "kernel path is not NUL terminated",
        ));
    }
    loop {
        let raw = unsafe {
            libc::open(
                nul_terminated_path.as_ptr().cast(),
                flags,
            )
        };
        if raw >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(raw) });
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(BoottimeError::SystemCall {
                operation,
                source: error,
            });
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn boottime_now_nanos() -> BoottimeResult<u64> {
    loop {
        let mut value = MaybeUninit::<libc::timespec>::uninit();
        let status = unsafe {
            libc::clock_gettime(libc::CLOCK_BOOTTIME, value.as_mut_ptr())
        };
        if status == 0 {
            let value = unsafe { value.assume_init() };
            if value.tv_sec < 0
                || value.tv_nsec < 0
                || value.tv_nsec >= 1_000_000_000
            {
                return Err(BoottimeError::Invalid(
                    "CLOCK_BOOTTIME returned an invalid timespec",
                ));
            }
            let seconds = u64::try_from(value.tv_sec).map_err(|_| {
                BoottimeError::Overflow(
                    "CLOCK_BOOTTIME seconds conversion overflow",
                )
            })?;
            let fraction = u64::try_from(value.tv_nsec).map_err(|_| {
                BoottimeError::Overflow(
                    "CLOCK_BOOTTIME nanoseconds conversion overflow",
                )
            })?;
            return seconds
                .checked_mul(NANOS_PER_SECOND)
                .and_then(|nanos| nanos.checked_add(fraction))
                .ok_or(BoottimeError::Overflow(
                    "CLOCK_BOOTTIME value overflow",
                ));
        }

        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(BoottimeError::SystemCall {
                operation: "clock_gettime(CLOCK_BOOTTIME)",
                source: error,
            });
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn boottime_now_nanos() -> BoottimeResult<u64> {
    Err(BoottimeError::UnsupportedPlatform)
}

fn checked_timespec_from_nanos(
    absolute_nanos: u64,
) -> BoottimeResult<libc::timespec> {
    let seconds = absolute_nanos / NANOS_PER_SECOND;
    let fraction = absolute_nanos % NANOS_PER_SECOND;
    Ok(libc::timespec {
        tv_sec: libc::time_t::try_from(seconds).map_err(|_| {
            BoottimeError::Overflow(
                "CLOCK_BOOTTIME deadline seconds overflow",
            )
        })?,
        tv_nsec: libc::c_long::try_from(fraction).map_err(|_| {
            BoottimeError::Overflow(
                "CLOCK_BOOTTIME deadline nanoseconds overflow",
            )
        })?,
    })
}

#[derive(Debug)]
#[must_use]
pub(super) struct BoottimeTimer {
    descriptor: OwnedFd,
    deadline: BoottimeDeadline,
}

impl BoottimeTimer {
    #[cfg(target_os = "linux")]
    pub(super) fn arm(deadline: BoottimeDeadline) -> BoottimeResult<Self> {
        deadline.domain().require_current()?;
        let raw = unsafe {
            libc::timerfd_create(
                libc::CLOCK_BOOTTIME,
                libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
            )
        };
        if raw < 0 {
            return Err(system_call_error(
                "timerfd_create(CLOCK_BOOTTIME)",
            ));
        }
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        let specification = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: checked_timespec_from_nanos(
                deadline.absolute_nanos(),
            )?,
        };

        loop {
            let status = unsafe {
                libc::timerfd_settime(
                    descriptor.as_raw_fd(),
                    libc::TFD_TIMER_ABSTIME,
                    &specification,
                    ptr::null_mut(),
                )
            };
            if status == 0 {
                return Ok(Self {
                    descriptor,
                    deadline,
                });
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(BoottimeError::SystemCall {
                    operation: "timerfd_settime(TFD_TIMER_ABSTIME)",
                    source: error,
                });
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn arm(
        _deadline: BoottimeDeadline,
    ) -> BoottimeResult<Self> {
        Err(BoottimeError::UnsupportedPlatform)
    }

    pub(super) fn deadline(&self) -> BoottimeDeadline {
        self.deadline
    }

    pub(super) fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }

    #[cfg(target_os = "linux")]
    fn consume_expiration(&self) -> BoottimeResult<u64> {
        loop {
            let mut expirations = 0_u64;
            let read = unsafe {
                libc::read(
                    self.descriptor.as_raw_fd(),
                    (&mut expirations as *mut u64).cast(),
                    std::mem::size_of::<u64>(),
                )
            };
            if read == std::mem::size_of::<u64>() as isize {
                return Ok(expirations);
            }
            if read >= 0 {
                return Err(BoottimeError::Invalid(
                    "timerfd returned a truncated expiration counter",
                ));
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(BoottimeError::SystemCall {
                operation: "read(timerfd)",
                source: error,
            });
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn consume_expiration(&self) -> BoottimeResult<u64> {
        Err(BoottimeError::UnsupportedPlatform)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PollTargetKind {
    Socket,
    EventFd,
    PidFd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PollInterest {
    events: libc::c_short,
}

impl PollInterest {
    pub(super) const READABLE: Self = Self {
        events: libc::POLLIN,
    };
    pub(super) const WRITABLE: Self = Self {
        events: libc::POLLOUT,
    };
    pub(super) const PRIORITY: Self = Self {
        events: libc::POLLPRI,
    };
    pub(super) const READ_WRITE: Self = Self {
        events: libc::POLLIN | libc::POLLOUT,
    };
    pub(super) const READ_PRIORITY: Self = Self {
        events: libc::POLLIN | libc::POLLPRI,
    };
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PollTarget<'fd> {
    descriptor: BorrowedFd<'fd>,
    kind: PollTargetKind,
    interest: PollInterest,
}

impl<'fd> PollTarget<'fd> {
    pub(super) fn socket(
        descriptor: BorrowedFd<'fd>,
        interest: PollInterest,
    ) -> Self {
        Self {
            descriptor,
            kind: PollTargetKind::Socket,
            interest,
        }
    }

    pub(super) fn eventfd(descriptor: BorrowedFd<'fd>) -> Self {
        Self {
            descriptor,
            kind: PollTargetKind::EventFd,
            interest: PollInterest::READABLE,
        }
    }

    pub(super) fn eventfd_with_interest(
        descriptor: BorrowedFd<'fd>,
        interest: PollInterest,
    ) -> Self {
        Self {
            descriptor,
            kind: PollTargetKind::EventFd,
            interest,
        }
    }

    pub(super) fn pidfd(descriptor: BorrowedFd<'fd>) -> Self {
        Self {
            descriptor,
            kind: PollTargetKind::PidFd,
            interest: PollInterest::READABLE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProgressFd {
    index: usize,
    kind: PollTargetKind,
    revents: libc::c_short,
}

impl ProgressFd {
    pub(super) fn index(self) -> usize {
        self.index
    }

    pub(super) fn kind(self) -> PollTargetKind {
        self.kind
    }

    pub(super) fn readable(self) -> bool {
        self.revents & libc::POLLIN != 0
    }

    pub(super) fn writable(self) -> bool {
        self.revents & libc::POLLOUT != 0
    }

    pub(super) fn priority(self) -> bool {
        self.revents & libc::POLLPRI != 0
    }

    pub(super) fn hung_up(self) -> bool {
        self.revents & libc::POLLHUP != 0
    }

    pub(super) fn errored(self) -> bool {
        self.revents & libc::POLLERR != 0
    }
}

#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub(super) enum WaitOutcome {
    /// Readiness permits only another nonblocking progress attempt.
    Progress(Vec<ProgressFd>),
    DeadlineExpired,
}

pub(super) fn poll_until(
    deadline: BoottimeDeadline,
    targets: &[PollTarget<'_>],
) -> BoottimeResult<WaitOutcome> {
    wait_until(deadline, targets)
}

fn wait_until(
    deadline: BoottimeDeadline,
    targets: &[PollTarget<'_>],
) -> BoottimeResult<WaitOutcome> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (deadline, targets);
        return Err(BoottimeError::UnsupportedPlatform);
    }

    #[cfg(target_os = "linux")]
    {
        if targets.len() > MAX_POLL_TARGETS {
            return Err(BoottimeError::Invalid(
                "too many descriptors in BOOTTIME wait",
            ));
        }
        validate_poll_targets(targets)?;
        if deadline.expired()? {
            return Ok(WaitOutcome::DeadlineExpired);
        }

        let timer = BoottimeTimer::arm(deadline)?;
        let capacity = targets
            .len()
            .checked_add(1)
            .ok_or(BoottimeError::Overflow(
                "poll descriptor count overflow",
            ))?;
        let mut descriptors = Vec::with_capacity(capacity);
        descriptors.push(libc::pollfd {
            fd: timer.as_fd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        descriptors.extend(targets.iter().map(|target| libc::pollfd {
            fd: target.descriptor.as_raw_fd(),
            events: target.interest.events,
            revents: 0,
        }));
        let descriptor_count =
            libc::nfds_t::try_from(descriptors.len()).map_err(|_| {
                BoottimeError::Overflow("poll descriptor count overflow")
            })?;

        loop {
            for descriptor in &mut descriptors {
                descriptor.revents = 0;
            }
            if deadline.expired()? {
                return Ok(WaitOutcome::DeadlineExpired);
            }

            let ready = unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptor_count,
                    -1,
                )
            };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(BoottimeError::SystemCall {
                    operation: "poll",
                    source: error,
                });
            }
            if ready == 0 {
                return Err(BoottimeError::Invalid(
                    "indefinite poll returned without readiness",
                ));
            }

            // Authorization expiry wins over simultaneous descriptor readiness.
            if deadline.expired()? {
                if descriptors[0].revents & libc::POLLIN != 0 {
                    timer.consume_expiration()?;
                }
                return Ok(WaitOutcome::DeadlineExpired);
            }

            let timer_events = descriptors[0].revents;
            if timer_events
                & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
                != 0
            {
                return Err(BoottimeError::Invalid(
                    "BOOTTIME timerfd became unavailable",
                ));
            }
            if timer_events & libc::POLLIN != 0 {
                timer.consume_expiration()?;
                return Ok(WaitOutcome::DeadlineExpired);
            }

            let mut events = Vec::new();
            for (index, (target, descriptor)) in targets
                .iter()
                .zip(descriptors.iter().skip(1))
                .enumerate()
            {
                if descriptor.revents & libc::POLLNVAL != 0 {
                    return Err(BoottimeError::InvalidDescriptor { index });
                }
                if descriptor.revents
                    & (target.interest.events
                        | libc::POLLERR
                        | libc::POLLHUP)
                    != 0
                {
                    events.push(ProgressFd {
                        index,
                        kind: target.kind,
                        revents: descriptor.revents,
                    });
                }
            }
            if events.is_empty() {
                return Err(BoottimeError::Invalid(
                    "poll returned an unrecognized event",
                ));
            }
            deadline.require_live()?;
            return Ok(WaitOutcome::Progress(events));
        }
    }
}

fn validate_poll_targets(
    targets: &[PollTarget<'_>],
) -> BoottimeResult<()> {
    if targets.len() > MAX_POLL_TARGETS {
        return Err(BoottimeError::Invalid(
            "too many descriptors in BOOTTIME poll",
        ));
    }
    for (index, target) in targets.iter().enumerate() {
        let descriptor = target.descriptor.as_raw_fd();
        if descriptor < 0 || target.interest.events == 0 {
            return Err(BoottimeError::InvalidDescriptor { index });
        }
        if targets[..index]
            .iter()
            .any(|prior| prior.descriptor.as_raw_fd() == descriptor)
        {
            return Err(BoottimeError::Invalid(
                "duplicate descriptor in BOOTTIME wait",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(super) struct BoottimeBackoff {
    initial_delay_nanos: u64,
    current_delay_nanos: u64,
    maximum_delay_nanos: u64,
    multiplier: u32,
    completed_retries: u64,
}

impl BoottimeBackoff {
    pub(super) fn new(
        initial_delay_nanos: u64,
        maximum_delay_nanos: u64,
        multiplier: u32,
    ) -> BoottimeResult<Self> {
        if initial_delay_nanos == 0
            || maximum_delay_nanos < initial_delay_nanos
            || multiplier == 0
        {
            return Err(BoottimeError::Invalid(
                "invalid BOOTTIME retry backoff",
            ));
        }
        Ok(Self {
            initial_delay_nanos,
            current_delay_nanos: initial_delay_nanos,
            maximum_delay_nanos,
            multiplier,
            completed_retries: 0,
        })
    }

    pub(super) fn current_delay_nanos(&self) -> u64 {
        self.current_delay_nanos
    }

    pub(super) fn completed_retries(&self) -> u64 {
        self.completed_retries
    }

    pub(super) fn reset(&mut self) {
        self.current_delay_nanos = self.initial_delay_nanos;
        self.completed_retries = 0;
    }

    pub(super) fn wait_poll(
        &mut self,
        authorization_deadline: BoottimeDeadline,
        wake_targets: &[PollTarget<'_>],
    ) -> BoottimeResult<BackoffOutcome> {
        self.wait(authorization_deadline, wake_targets)
    }

    fn wait(
        &mut self,
        authorization_deadline: BoottimeDeadline,
        wake_targets: &[PollTarget<'_>],
    ) -> BoottimeResult<BackoffOutcome> {
        authorization_deadline.domain().require_current()?;
        let now_nanos = boottime_now_nanos()?;
        if now_nanos >= authorization_deadline.absolute_nanos() {
            return Ok(BackoffOutcome::AuthorizationExpired);
        }
        let retry_at_nanos = now_nanos
            .checked_add(self.current_delay_nanos)
            .unwrap_or(authorization_deadline.absolute_nanos());
        let wake_at_nanos =
            retry_at_nanos.min(authorization_deadline.absolute_nanos());
        let wake_deadline =
            authorization_deadline.derived_at(wake_at_nanos)?;

        match wait_until(wake_deadline, wake_targets)? {
            WaitOutcome::Progress(events) => {
                Ok(BackoffOutcome::Progress(events))
            }
            WaitOutcome::DeadlineExpired => {
                if authorization_deadline.expired()? {
                    return Ok(BackoffOutcome::AuthorizationExpired);
                }
                self.advance()?;
                Ok(BackoffOutcome::RetryDue {
                    attempt: self.completed_retries,
                    scheduled_at_nanos: wake_at_nanos,
                })
            }
        }
    }

    fn advance(&mut self) -> BoottimeResult<()> {
        self.completed_retries =
            self.completed_retries.checked_add(1).ok_or(
                BoottimeError::Overflow("BOOTTIME retry count overflow"),
            )?;
        let multiplier = u64::from(self.multiplier);
        self.current_delay_nanos =
            if self.current_delay_nanos >= self.maximum_delay_nanos
                || self.current_delay_nanos
                    > self.maximum_delay_nanos / multiplier
            {
                self.maximum_delay_nanos
            } else {
                self.current_delay_nanos
                    .checked_mul(multiplier)
                    .ok_or(BoottimeError::Overflow(
                        "BOOTTIME retry delay overflow",
                    ))?
            };
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub(super) enum BackoffOutcome {
    RetryDue {
        attempt: u64,
        scheduled_at_nanos: u64,
    },
    /// Readiness permits only another nonblocking progress attempt.
    Progress(Vec<ProgressFd>),
    AuthorizationExpired,
}

#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub(super) struct AbsolutePollOutcome {
    pub(super) progress: Vec<ProgressFd>,
    pub(super) timer_expired: bool,
}

/// A stable epoll descriptor that aggregates retained descriptors and one
/// absolute CLOCK_BOOTTIME timer. Callers may poll `progress_fd()` and then
/// retry their nonblocking operation without introducing relative waits.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(super) struct LinuxAbsoluteBoottimePoller {
    epoll: OwnedFd,
    timer: OwnedFd,
    registered: Vec<RawFd>,
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub(super) struct LinuxAbsoluteBoottimePoller {
    _unsupported: (),
}

impl LinuxAbsoluteBoottimePoller {
    #[cfg(target_os = "linux")]
    pub(super) fn new() -> BoottimeResult<Self> {
        let epoll = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll < 0 {
            return Err(system_call_error("epoll_create1"));
        }
        let epoll = unsafe { OwnedFd::from_raw_fd(epoll) };
        let timer = unsafe {
            libc::timerfd_create(
                libc::CLOCK_BOOTTIME,
                libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
            )
        };
        if timer < 0 {
            return Err(system_call_error(
                "timerfd_create(CLOCK_BOOTTIME)",
            ));
        }
        Ok(Self {
            epoll,
            timer: unsafe { OwnedFd::from_raw_fd(timer) },
            registered: Vec::new(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn new() -> BoottimeResult<Self> {
        Err(BoottimeError::UnsupportedPlatform)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn progress_fd(&self) -> BorrowedFd<'_> {
        self.epoll.as_fd()
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn progress_fd(&self) -> BorrowedFd<'_> {
        panic!("LinuxAbsoluteBoottimePoller is unavailable")
    }

    /// Configure one absolute wake and attempt one zero-timeout observation.
    /// `None` means the stable epoll descriptor must be polled before retry.
    #[cfg(target_os = "linux")]
    pub(super) fn try_poll_absolute_nonblocking(
        &mut self,
        wake_at_boottime_nanos: u64,
        authorization_deadline: BoottimeDeadline,
        targets: &[PollTarget<'_>],
    ) -> BoottimeResult<Option<AbsolutePollOutcome>> {
        authorization_deadline.domain().require_current()?;
        authorization_deadline.require_live()?;
        if wake_at_boottime_nanos == 0
            || wake_at_boottime_nanos
                > authorization_deadline.absolute_nanos()
        {
            return Err(BoottimeError::Invalid(
                "absolute poll wake exceeds its BOOTTIME authority",
            ));
        }
        validate_poll_targets(targets)?;
        let observed = boottime_now_nanos()?;
        if observed >= wake_at_boottime_nanos {
            return Ok(Some(AbsolutePollOutcome {
                progress: Vec::new(),
                timer_expired: true,
            }));
        }
        self.arm_timer_absolute(wake_at_boottime_nanos)?;
        self.replace_registrations(targets, true)?;
        self.try_collect_nonblocking(targets, true)
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn try_poll_absolute_nonblocking(
        &mut self,
        _wake_at_boottime_nanos: u64,
        _authorization_deadline: BoottimeDeadline,
        _targets: &[PollTarget<'_>],
    ) -> BoottimeResult<Option<AbsolutePollOutcome>> {
        Err(BoottimeError::UnsupportedPlatform)
    }

    /// Install only progress targets. This is used after an eventfd or UDS
    /// operation returned EAGAIN; the outer exact-deadline driver owns expiry.
    #[cfg(target_os = "linux")]
    pub(super) fn arm_progress(
        &mut self,
        targets: &[PollTarget<'_>],
    ) -> BoottimeResult<()> {
        validate_poll_targets(targets)?;
        self.disarm_timer()?;
        self.replace_registrations(targets, false)
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn arm_progress(
        &mut self,
        _targets: &[PollTarget<'_>],
    ) -> BoottimeResult<()> {
        Err(BoottimeError::UnsupportedPlatform)
    }

    #[cfg(target_os = "linux")]
    fn replace_registrations(
        &mut self,
        targets: &[PollTarget<'_>],
        include_timer: bool,
    ) -> BoottimeResult<()> {
        for descriptor in self.registered.drain(..) {
            let status = unsafe {
                libc::epoll_ctl(
                    self.epoll.as_raw_fd(),
                    libc::EPOLL_CTL_DEL,
                    descriptor,
                    ptr::null_mut(),
                )
            };
            if status != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ENOENT) {
                    return Err(BoottimeError::SystemCall {
                        operation: "epoll_ctl(DEL)",
                        source: error,
                    });
                }
            }
        }
        if include_timer {
            self.register(
                self.timer.as_raw_fd(),
                libc::EPOLLIN as u32,
                0,
            )?;
        }
        for (index, target) in targets.iter().enumerate() {
            let descriptor = target.descriptor.as_raw_fd();
            if descriptor == self.epoll.as_raw_fd()
                || descriptor == self.timer.as_raw_fd()
            {
                return Err(BoottimeError::Invalid(
                    "poll target aliases the progress authority",
                ));
            }
            let token = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(BoottimeError::Overflow(
                    "epoll progress token overflow",
                ))?;
            self.register(
                descriptor,
                poll_interest_to_epoll(target.interest),
                token,
            )?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn register(
        &mut self,
        descriptor: RawFd,
        events: u32,
        token: u64,
    ) -> BoottimeResult<()> {
        let mut event = libc::epoll_event { events, u64: token };
        let status = unsafe {
            libc::epoll_ctl(
                self.epoll.as_raw_fd(),
                libc::EPOLL_CTL_ADD,
                descriptor,
                &mut event,
            )
        };
        if status != 0 {
            return Err(system_call_error("epoll_ctl(ADD)"));
        }
        self.registered.push(descriptor);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn try_collect_nonblocking(
        &self,
        targets: &[PollTarget<'_>],
        timer_registered: bool,
    ) -> BoottimeResult<Option<AbsolutePollOutcome>> {
        const MAX_EPOLL_EVENTS: usize = MAX_POLL_TARGETS + 1;
        let mut events: [libc::epoll_event; MAX_EPOLL_EVENTS] =
            unsafe { MaybeUninit::zeroed().assume_init() };
        let ready = loop {
            let ready = unsafe {
                libc::epoll_wait(
                    self.epoll.as_raw_fd(),
                    events.as_mut_ptr(),
                    i32::try_from(events.len()).map_err(|_| {
                        BoottimeError::Overflow(
                            "epoll event bound overflow",
                        )
                    })?,
                    0,
                )
            };
            if ready >= 0 {
                break usize::try_from(ready).map_err(|_| {
                    BoottimeError::Overflow(
                        "epoll result count overflow",
                    )
                })?;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(BoottimeError::SystemCall {
                    operation: "epoll_wait",
                    source: error,
                });
            }
        };
        if ready == 0 {
            return Ok(None);
        }
        let mut timer_expired = false;
        let mut progress = Vec::with_capacity(ready);
        for event in events.into_iter().take(ready) {
            if event.u64 == 0 {
                if !timer_registered {
                    return Err(BoottimeError::Invalid(
                        "unregistered BOOTTIME timer reported progress",
                    ));
                }
                consume_counter_fd(
                    self.timer.as_raw_fd(),
                    "read(absolute BOOTTIME timerfd)",
                )?;
                timer_expired = true;
                continue;
            }
            let index = usize::try_from(event.u64 - 1).map_err(|_| {
                BoottimeError::Overflow("epoll target index overflow")
            })?;
            let target = targets.get(index).ok_or(
                BoottimeError::Invalid(
                    "epoll returned an unknown progress token",
                ),
            )?;
            progress.push(ProgressFd {
                index,
                kind: target.kind,
                revents: epoll_to_poll_revents(event.events),
            });
        }
        if progress.is_empty() && !timer_expired {
            return Err(BoottimeError::Invalid(
                "epoll returned no recognized progress",
            ));
        }
        Ok(Some(AbsolutePollOutcome {
            progress,
            timer_expired,
        }))
    }

    #[cfg(target_os = "linux")]
    fn arm_timer_absolute(
        &self,
        absolute_nanos: u64,
    ) -> BoottimeResult<()> {
        let specification = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: checked_timespec_from_nanos(absolute_nanos)?,
        };
        loop {
            let status = unsafe {
                libc::timerfd_settime(
                    self.timer.as_raw_fd(),
                    libc::TFD_TIMER_ABSTIME,
                    &specification,
                    ptr::null_mut(),
                )
            };
            if status == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(BoottimeError::SystemCall {
                    operation:
                        "timerfd_settime(TFD_TIMER_ABSTIME)",
                    source: error,
                });
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn disarm_timer(&self) -> BoottimeResult<()> {
        let specification: libc::itimerspec =
            unsafe { MaybeUninit::zeroed().assume_init() };
        loop {
            let status = unsafe {
                libc::timerfd_settime(
                    self.timer.as_raw_fd(),
                    0,
                    &specification,
                    ptr::null_mut(),
                )
            };
            if status == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(BoottimeError::SystemCall {
                    operation: "timerfd_settime(disarm)",
                    source: error,
                });
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn poll_interest_to_epoll(interest: PollInterest) -> u32 {
    let mut events = 0_u32;
    if interest.events & libc::POLLIN != 0 {
        events |= libc::EPOLLIN as u32;
    }
    if interest.events & libc::POLLOUT != 0 {
        events |= libc::EPOLLOUT as u32;
    }
    if interest.events & libc::POLLPRI != 0 {
        events |= libc::EPOLLPRI as u32;
    }
    events
}

#[cfg(target_os = "linux")]
fn epoll_to_poll_revents(events: u32) -> libc::c_short {
    let mut revents = 0;
    if events & libc::EPOLLIN as u32 != 0 {
        revents |= libc::POLLIN;
    }
    if events & libc::EPOLLOUT as u32 != 0 {
        revents |= libc::POLLOUT;
    }
    if events & libc::EPOLLPRI as u32 != 0 {
        revents |= libc::POLLPRI;
    }
    if events & libc::EPOLLERR as u32 != 0 {
        revents |= libc::POLLERR;
    }
    if events & libc::EPOLLHUP as u32 != 0 {
        revents |= libc::POLLHUP;
    }
    revents
}

#[cfg(target_os = "linux")]
fn consume_counter_fd(
    descriptor: RawFd,
    operation: &'static str,
) -> BoottimeResult<u64> {
    loop {
        let mut counter = 0_u64;
        let read = unsafe {
            libc::read(
                descriptor,
                (&mut counter as *mut u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        if read == std::mem::size_of::<u64>() as isize {
            return Ok(counter);
        }
        if read >= 0 {
            return Err(BoottimeError::Invalid(
                "counter descriptor returned a truncated value",
            ));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(BoottimeError::SystemCall {
            operation,
            source: error,
        });
    }
}

#[cfg(target_os = "linux")]
pub(super) fn create_nonblocking_eventfd(
    initial_value: u32,
) -> BoottimeResult<OwnedFd> {
    let descriptor = unsafe {
        libc::eventfd(
            initial_value,
            libc::EFD_CLOEXEC | libc::EFD_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(system_call_error("eventfd"));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

#[cfg(not(target_os = "linux"))]
pub(super) fn create_nonblocking_eventfd(
    _initial_value: u32,
) -> BoottimeResult<OwnedFd> {
    Err(BoottimeError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
pub(super) fn try_read_eventfd_nonblocking(
    descriptor: BorrowedFd<'_>,
) -> BoottimeResult<Option<u64>> {
    loop {
        let mut counter = 0_u64;
        let read = unsafe {
            libc::read(
                descriptor.as_raw_fd(),
                (&mut counter as *mut u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        if read == std::mem::size_of::<u64>() as isize {
            if counter == 0 {
                return Err(BoottimeError::Invalid(
                    "eventfd returned a zero counter",
                ));
            }
            return Ok(Some(counter));
        }
        if read >= 0 {
            return Err(BoottimeError::Invalid(
                "eventfd returned a truncated counter",
            ));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Ok(None),
            _ => {
                return Err(BoottimeError::SystemCall {
                    operation: "read(eventfd)",
                    source: error,
                });
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn try_read_eventfd_nonblocking(
    _descriptor: BorrowedFd<'_>,
) -> BoottimeResult<Option<u64>> {
    Err(BoottimeError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
pub(super) fn try_write_eventfd_nonblocking(
    descriptor: BorrowedFd<'_>,
    value: u64,
) -> BoottimeResult<Option<()>> {
    if value == 0 || value == u64::MAX {
        return Err(BoottimeError::Invalid(
            "eventfd publish value is invalid",
        ));
    }
    loop {
        let written = unsafe {
            libc::write(
                descriptor.as_raw_fd(),
                (&value as *const u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        if written == std::mem::size_of::<u64>() as isize {
            return Ok(Some(()));
        }
        if written >= 0 {
            return Err(BoottimeError::Invalid(
                "eventfd write was truncated",
            ));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Ok(None),
            _ => {
                return Err(BoottimeError::SystemCall {
                    operation: "write(eventfd)",
                    source: error,
                });
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn try_write_eventfd_nonblocking(
    _descriptor: BorrowedFd<'_>,
    _value: u64,
) -> BoottimeResult<Option<()>> {
    Err(BoottimeError::UnsupportedPlatform)
}
