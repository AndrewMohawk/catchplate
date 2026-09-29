//! One nonrenewable, creator-process lifetime for native scoped workers.
//!
//! This owner coordinates cancellation; it is not attestation or authority.
//! The caller must stop the cohort before leaving thread::scope, which then
//! joins every spawned task. Checks cannot interrupt an in-flight blocking
//! library/kernel operation: those still need their own bounded IO/watchdog.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{Builder, Scope};
use std::time::Duration;

const MAX_FAILURE_BYTES: usize = 512;
const MAX_TASK_NAME_BYTES: usize = 96;
const WAIT_SLICE_NS: u64 = 100_000_000;

struct State {
    failure: Option<String>,
}

pub(super) struct NativeRuntimeLifetimeV1 {
    deadline: u64,
    creator_pid: libc::pid_t,
    stopped: AtomicBool,
    state: Mutex<State>,
    wake: Condvar,
    serving_privileges: Option<Arc<serverware_decision_gate::native_serving_privileges::Owner>>,
    guest_inspector: Option<Arc<serverware_decision_gate::InitializedGuestInspector>>,
}

fn now() -> Result<u64, &'static str> {
    let mut sample: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut sample) } != 0 {
        return Err("native runtime boottime clock failed");
    }
    if sample.tv_sec < 0 || !(0..1_000_000_000).contains(&sample.tv_nsec) {
        return Err("native runtime boottime sample is invalid");
    }
    (sample.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(sample.tv_nsec as u64))
        .ok_or("native runtime boottime sample overflow")
}

fn bounded_failure(reason: &str) -> String {
    let mut end = reason.len().min(MAX_FAILURE_BYTES);
    while !reason.is_char_boundary(end) { end -= 1; }
    reason[..end].to_owned()
}

impl NativeRuntimeLifetimeV1 {
    pub(super) fn new(deadline: u64) -> Result<Arc<Self>, String> {
        let creator_pid = unsafe { libc::getpid() };
        if creator_pid <= 0 || deadline <= now()? {
            return Err("native runtime original deadline or process is invalid".to_owned());
        }
        Ok(Arc::new(Self {
            deadline, creator_pid, stopped: AtomicBool::new(false),
            state: Mutex::new(State { failure: None }), wake: Condvar::new(),
            serving_privileges: None,
            guest_inspector: None,
        }))
    }

    pub(super) fn bind_serving_privileges(owner: &mut Arc<Self>,
        privileges: Arc<serverware_decision_gate::native_serving_privileges::Owner>) -> Result<(), String> {
        owner.require_creator()?;
        privileges.check()?;
        let actual = Arc::get_mut(owner).ok_or("native lifetime shared before privilege attachment")?;
        if actual.serving_privileges.is_some() || actual.deadline != privileges.deadline() {
            return Err("native lifetime privilege owner or original deadline differs".to_owned());
        }
        if let Some(inspector) = &actual.guest_inspector { inspector.require_serving(&privileges)?; }
        actual.serving_privileges = Some(privileges);
        actual.require_creator()
    }

    pub(super) fn deadline(&self) -> u64 { self.deadline }

    pub(super) fn bind_guest_inspector(owner: &mut Arc<Self>,
        inspector: Arc<serverware_decision_gate::InitializedGuestInspector>) -> Result<(), String> {
        owner.require_creator()?;
        inspector.check()?;
        let actual = Arc::get_mut(owner).ok_or("native lifetime shared before inspector attachment")?;
        if actual.guest_inspector.is_some() || actual.serving_privileges.is_some()
            || actual.deadline != inspector.deadline_boottime_ns() {
            return Err("native inspector lost its original pre-drop lifetime".into());
        }
        actual.guest_inspector = Some(inspector);
        Ok(())
    }

    pub(super) fn require_serving_privileges(&self,
        owner: Option<&Arc<serverware_decision_gate::native_serving_privileges::Owner>>) -> Result<(), String> {
        self.check()?;
        match (&self.serving_privileges, owner) {
            (Some(held), Some(actual)) if Arc::ptr_eq(held, actual) => Ok(()),
            (None, None) if self.guest_inspector.is_none() => Ok(()),
            _ => Err("native serving lifetime privilege owner differs".into()),
        }
    }

    pub(super) fn finish_guest_inspector(&self) -> Result<(), String> {
        if unsafe { libc::getpid() } != self.creator_pid { return Err("inspector finish crossed creator".into()); }
        match &self.guest_inspector { Some(owner) => owner.stop_and_reap(), None => Ok(()) }
    }

    // Do not touch an inherited Mutex/Condvar after fork: another thread may
    // have held that lock when the process split. No operation resumes it.
    fn require_creator(&self) -> Result<(), String> {
        if unsafe { libc::getpid() } != self.creator_pid {
            self.stopped.store(true, Ordering::Release);
            return Err("native runtime lifetime crossed its creator process".to_owned());
        }
        if let Some(owner) = &self.serving_privileges {
            if let Err(error) = owner.check() {
                self.stopped.store(true, Ordering::Release);
                if let Some(inspector) = &self.guest_inspector { inspector.request_stop(); }
                return Err(error);
            }
        }
        if let Some(inspector) = &self.guest_inspector {
            if self.stopped.load(Ordering::Acquire) { return Ok(()); }
            if let Err(error) = inspector.check() {
                if self.stopped.load(Ordering::Acquire) { return Ok(()); }
                if let Ok(mut state) = self.lock() {
                    self.fail_locked(&mut state, "native guest inspector lifetime failed");
                }
                inspector.request_stop();
                return Err(error);
            }
        }
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, String> {
        match self.state.lock() {
            Ok(state) => Ok(state),
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                self.fail_locked(&mut state, "native runtime lifetime lock poisoned");
                Err(state.failure.clone().unwrap_or_else(|| "native runtime lifetime lock poisoned".to_owned()))
            }
        }
    }

    fn fail_locked(&self, state: &mut State, reason: &str) {
        if state.failure.is_none() { state.failure = Some(bounded_failure(reason)); }
        self.stopped.store(true, Ordering::Release);
        self.wake.notify_all();
    }

    fn live_sample_locked(&self, state: &mut State) -> Result<u64, String> {
        let sample = match now() {
            Ok(sample) if sample < self.deadline => sample,
            Ok(_) => {
                self.fail_locked(state, "native runtime original deadline expired");
                return Err("native runtime original deadline expired".to_owned());
            }
            Err(reason) => {
                self.fail_locked(state, reason);
                return Err(reason.to_owned());
            }
        };
        Ok(sample)
    }

    pub(super) fn check(&self) -> Result<(), String> {
        self.remaining().map(|_| ())
    }

    pub(super) fn remaining(&self) -> Result<Duration, String> {
        self.require_creator()?;
        let mut state = self.lock()?;
        // Sample after acquiring the lock, not before potentially waiting.
        let sample = self.live_sample_locked(&mut state)?;
        if self.stopped.load(Ordering::Acquire) {
            return Err(state.failure.clone().unwrap_or_else(|| "native runtime is stopped".to_owned()));
        }
        Ok(Duration::from_nanos(self.deadline - sample))
    }

    pub(super) fn is_stopped(&self) -> bool {
        (unsafe { libc::getpid() }) != self.creator_pid || self.stopped.load(Ordering::Acquire)
    }

    pub(super) fn stopped_flag(&self) -> &AtomicBool { &self.stopped }

    pub(super) fn stop(&self) {
        // Emergency cancellation is not conditional on unexpired admission.
        if unsafe { libc::getpid() } != self.creator_pid { return; }
        self.stopped.store(true, Ordering::Release);
        if let Some(inspector) = &self.guest_inspector { inspector.request_stop(); }
        if let Ok(_state) = self.lock() {
            // The same mutex guards wait's condition, preventing a lost wake.
            self.stopped.store(true, Ordering::Release);
            self.wake.notify_all();
        }
    }

    pub(super) fn fail(&self, reason: &'static str) { self.record_failure(reason); }

    fn record_failure(&self, reason: &str) {
        if self.require_creator().is_err() { return; }
        if let Ok(mut state) = self.lock() { self.fail_locked(&mut state, reason); }
    }

    pub(super) fn failure(&self) -> Option<String> {
        if let Err(reason) = self.require_creator() { return Some(reason); }
        match self.lock() {
            Ok(state) => state.failure.clone(),
            Err(reason) => Some(reason),
        }
    }

    /// Zero is a supported nonblocking liveness/cancellation check. Expiry
    /// observed while live records failure and stops before returning Err.
    /// Already-observed cancellation returns false, never permission to work.
    pub(super) fn wait(&self, interval: Duration) -> Result<bool, String> {
        self.require_creator()?;
        let mut state = self.lock()?;
        if self.stopped.load(Ordering::Acquire) { return Ok(false); }
        let started = self.live_sample_locked(&mut state)?;
        let interval_ns = interval.as_nanos().min(u64::MAX as u128) as u64;
        let until = started.saturating_add(interval_ns).min(self.deadline);
        loop {
            if self.stopped.load(Ordering::Acquire) { return Ok(false); }
            let sample = self.live_sample_locked(&mut state)?;
            if sample >= until { return Ok(true); }
            // Condvar's clock need not include suspend. Short slices and a new
            // CLOCK_BOOTTIME sample preserve the original bound after resume.
            let slice = Duration::from_nanos((until - sample).min(WAIT_SLICE_NS));
            state = match self.wake.wait_timeout(state, slice) {
                Ok((state, _)) => state,
                Err(poisoned) => {
                    let (mut state, _) = poisoned.into_inner();
                    self.fail_locked(&mut state, "native runtime wait lock poisoned");
                    return Err("native runtime wait lock poisoned".to_owned());
                }
            };
        }
    }
}

impl Drop for NativeRuntimeLifetimeV1 {
    fn drop(&mut self) {
        if unsafe { libc::getpid() } == self.creator_pid {
            if let Some(inspector) = &self.guest_inspector { inspector.request_stop(); }
        }
    }
}

/// Spawn only within the caller's lexical scope. Dropping ScopedJoinHandle
/// here does not detach: Scope retains and joins the task. The caller owns a
/// stop-before-join guard, including early returns and unwinding.
pub(super) fn spawn_task<'scope, 'env: 'scope, F>(
    scope: &'scope Scope<'scope, 'env>,
    lifetime: &Arc<NativeRuntimeLifetimeV1>,
    name: String,
    task: F,
) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String> + Send + 'scope,
{
    lifetime.check()?;
    if name.is_empty() || name.len() > MAX_TASK_NAME_BYTES
        || !name.bytes().all(|byte| (0x20..0x7f).contains(&byte)) {
        lifetime.fail("native runtime task name is invalid");
        return Err("native runtime task name is invalid".to_owned());
    }
    let owner = Arc::clone(lifetime);
    let task_name = name.clone();
    let spawned = Builder::new().name(name).spawn_scoped(scope, move || {
        if owner.check().is_err() { return; }
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(task));
        let failure = match outcome {
            Ok(Ok(())) if !owner.is_stopped() => Some("returned before cancellation"),
            Ok(Err(_)) if !owner.is_stopped() => Some("failed before cancellation"),
            Err(_) => Some("panicked"),
            _ => None,
        };
        if let Some(reason) = failure {
            // Error/panic payloads can carry request or credential contents.
            // Retain the bounded source-owned task name and failure class.
            owner.record_failure(&format!("native task {task_name} {reason}"));
        }
    });
    match spawned {
        Ok(_handle) => {
            lifetime.check()?;
            Ok(())
        }
        Err(_) => {
            lifetime.fail("native runtime scoped task spawn failed");
            Err("native runtime scoped task spawn failed".to_owned())
        }
    }
}
