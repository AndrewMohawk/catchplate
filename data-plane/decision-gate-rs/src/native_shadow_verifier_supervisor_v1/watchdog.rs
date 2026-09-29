//! Kernel-enforced original deadline, armed before image/root preparation.
use super::ensure;
use crate::native_shadow_verifier_runtime_v1::RuntimeAdmission;

pub(super) fn now() -> Result<u64, String> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME,&mut value) } == 0
        && value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec),
        "verifier supervisor BOOTTIME unavailable")?;
    (value.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(value.tv_nsec as u64)).ok_or_else(|| "verifier clock overflow".into())
}
pub(super) struct Watchdog {
    timer: libc::timer_t, creator: libc::pid_t, issued: u64, deadline: u64,
}
impl Watchdog {
    pub(super) fn arm(admission: &RuntimeAdmission) -> Result<Self, String> {
        admission.check()?;
        let issued = admission.issued_boottime_ns();
        let deadline = admission.deadline_boottime_ns();
        let mut event: libc::sigevent = unsafe { std::mem::zeroed() };
        event.sigev_notify = libc::SIGEV_SIGNAL;
        event.sigev_signo = libc::SIGKILL;
        let mut timer: libc::timer_t = unsafe { std::mem::zeroed() };
        ensure(unsafe { libc::timer_create(libc::CLOCK_BOOTTIME,&mut event,&mut timer) } == 0,
            "verifier kernel deadline timer unavailable")?;
        let expiry = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: (deadline / 1_000_000_000) as libc::time_t,
                tv_nsec: (deadline % 1_000_000_000) as libc::c_long },
        };
        // No relative timer, service thread, inherited renewed allowance or
        // disarm method exists. Only one-shot process exit destroys this timer.
        ensure(unsafe { libc::timer_settime(timer,libc::TIMER_ABSTIME,&expiry,std::ptr::null_mut()) } == 0,
            "verifier original absolute timer could not be armed")?;
        let owner = Self { timer, creator: unsafe { libc::getpid() }, issued, deadline };
        owner.check()?; admission.check()?; Ok(owner)
    }
    pub(super) fn check(&self) -> Result<(), String> {
        ensure(unsafe { libc::getpid() } == self.creator, "verifier watchdog crossed its supervisor")?;
        let current = now()?;
        let mut remaining: libc::itimerspec = unsafe { std::mem::zeroed() };
        ensure(self.issued <= current && current < self.deadline
            && unsafe { libc::timer_gettime(self.timer,&mut remaining) } == 0
            && remaining.it_interval.tv_sec == 0 && remaining.it_interval.tv_nsec == 0
            && remaining.it_value.tv_sec >= 0
            && (0..1_000_000_000).contains(&remaining.it_value.tv_nsec)
            && (remaining.it_value.tv_sec > 0 || remaining.it_value.tv_nsec > 0),
            "verifier original kernel deadline is over or disarmed")
    }
}
// Deliberately no Drop/disarm: every caller is inside the fixed process-exiting
// entrypoint. Failure/partial cleanup cannot remove its independent watchdog.
