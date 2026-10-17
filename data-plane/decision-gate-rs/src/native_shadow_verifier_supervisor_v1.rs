//! Fixed external verifier process. No key generation or generic exec;
//! the separate public transport is selected only by its fixed entrypoint.
mod child;
mod exchange;
mod inputs;
mod transport;
mod time_inputs;
mod time_issuer;
mod origin_issuer;
mod setup_issuer;
mod setup_installed;
mod watchdog;
#[path = "native_verifier/json.rs"]
mod json;
use crate::native_shadow_verifier_runtime_v1::{RuntimeAdmission, RunningRuntime};
use crate::native_response_profile_v1::canonical_ascii_bytes;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use watchdog::Watchdog;

const MAX_RESULT: usize = 32 * 1024;
fn ensure(value: bool, message: &str) -> Result<(), String> {
    if value { Ok(()) } else { Err(message.to_owned()) }
}
fn interrupted() -> bool { std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) }
fn would_block() -> bool {
    matches!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EAGAIN))
}
fn nonblocking(fd: RawFd) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd,libc::F_GETFL) };
    ensure(flags >= 0 && unsafe { libc::fcntl(fd,libc::F_SETFL,flags | libc::O_NONBLOCK) } == 0,
        "verifier parent pipe could not be bounded")
}
fn pipe() -> Result<(OwnedFd,OwnedFd), String> {
    let mut fds = [-1;2];
    ensure(unsafe { libc::pipe2(fds.as_mut_ptr(),libc::O_CLOEXEC) } == 0,
        "verifier private pipe unavailable")?;
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]),OwnedFd::from_raw_fd(fds[1])) })
}
fn parent_security() -> Result<(), String> {
    let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    ensure(unsafe { libc::setrlimit(libc::RLIMIT_CORE,&limit) } == 0
        && unsafe { libc::prctl(libc::PR_SET_DUMPABLE,0,0,0,0) } == 0,
        "verifier supervisor could not disable dumps")?;
    // No inherited SIGCHLD ignore/SA_NOCLDWAIT may discard the owned zombie.
    // SIGPIPE is an ordinary checked I/O failure, not a cleanup bypass.
    for (signal,handler) in [(libc::SIGCHLD,libc::SIG_DFL),(libc::SIGPIPE,libc::SIG_IGN)] {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = handler;
        ensure(unsafe { libc::sigemptyset(&mut action.sa_mask) } == 0
            && unsafe { libc::sigaction(signal,&action,std::ptr::null_mut()) } == 0,
            "verifier supervisor signal ownership failed")?;
    }
    Ok(())
}
#[repr(C)]
struct CloneArgs {
    flags: u64, pidfd: u64, child_tid: u64, parent_tid: u64, exit_signal: u64,
    stack: u64, stack_size: u64, tls: u64, set_tid: u64, set_tid_size: u64, cgroup: u64,
}
fn spawn(prepared: &child::PreparedChild, watch: &Watchdog) -> Result<(OwnedFd,libc::pid_t), String> {
    watch.check()?;
    let mut pidfd: i32 = -1;
    let args = CloneArgs { flags: libc::CLONE_PIDFD as u64,
        pidfd: (&mut pidfd as *mut i32) as u64, child_tid: 0, parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64, stack: 0, stack_size: 0, tls: 0,
        set_tid: 0, set_tid_size: 0, cgroup: 0 };
    let pid = unsafe { libc::syscall(libc::SYS_clone3,&args,std::mem::size_of::<CloneArgs>()) };
    if pid == 0 {
        // No allocation, Rust unwinding, destructor or parent-owner method in
        // this branch. The source-fixed child gate/hardening leads only to exec
        // or _exit. CLONE_VM/FILES/SIGHAND/THREAD are never selected.
        unsafe { prepared.enter() }
    }
    ensure(pid > 1 && pid <= i32::MAX as libc::c_long && pidfd >= 0,
        "verifier exact clone/PIDFD creation failed; no numeric-PID fallback")?;
    Ok((unsafe { OwnedFd::from_raw_fd(pidfd) },pid as libc::pid_t))
}
fn release_gate(fd: RawFd, watch: &Watchdog) -> Result<(), String> {
    loop {
        watch.check()?;
        let byte = [0xa5u8];
        let written = unsafe { libc::write(fd,byte.as_ptr().cast(),1) };
        if written == 1 { return watch.check(); }
        if written < 0 && interrupted() { continue; }
        return Err("verifier child gate was not released".into());
    }
}
fn collect(owner: &RunningRuntime, input: &inputs::Inputs, pipe: RawFd,
    watch: &Watchdog) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(MAX_RESULT);
    let mut eof = false;
    loop {
        watch.check()?; input.check()?;
        let mut polls = [
            libc::pollfd { fd: owner.child_pidfd().as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: if eof { -1 } else { pipe }, events: libc::POLLIN, revents: 0 },
        ];
        let rc = unsafe { libc::poll(polls.as_mut_ptr(),polls.len() as libc::nfds_t,25) };
        if rc < 0 { if interrupted() { continue; } return Err("verifier result poll failed".into()); }
        watch.check()?;
        ensure(polls.iter().all(|p| p.revents & (libc::POLLERR | libc::POLLNVAL) == 0),
            "verifier original child/result channel failed")?;
        if !eof && polls[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            loop {
                watch.check()?;
                let mut bytes = [0u8;4096];
                let count = unsafe { libc::read(pipe,bytes.as_mut_ptr().cast(),bytes.len()) };
                if count == 0 { eof = true; break; }
                if count < 0 {
                    if interrupted() { continue; }
                    if would_block() { break; }
                    return Err("verifier result read failed".into());
                }
                ensure(output.len().checked_add(count as usize).is_some_and(|size| size <= MAX_RESULT),
                    "verifier result exceeds its fixed output bound")?;
                output.extend_from_slice(&bytes[..count as usize]);
            }
        }
        if polls[0].revents & libc::POLLIN != 0 && eof {
            ensure(!output.is_empty(), "verifier exited without an original result")?;
            input.check()?; watch.check()?; return Ok(output);
        }
    }
}
fn result_shape(raw: &[u8],purpose:crate::native_shadow_verifier_runtime_v1::ResultPurpose) -> Result<(), String> {
    let value = json::parse(raw,MAX_RESULT)?;
    ensure(canonical_ascii_bytes(&value)? == raw, "verifier output is not original canonical ASCII")?;
    let outer = value.as_object().ok_or("verifier output is not an object")?;
    if purpose==crate::native_shadow_verifier_runtime_v1::ResultPurpose::BridgeAdmission {
        ensure(outer.len()==3 && value["apiVersion"]=="catchplate.nativeShadowBridgeAdmissionVerifierResult/v1",
            "verifier combined output purpose differs")?;
        let context=value["contextResultOriginal"].as_str().ok_or("combined context original absent")?;
        let production=value["productionResultOriginal"].as_str().ok_or("combined production original absent")?;
        ensure(context.is_ascii() && production.is_ascii(),"combined originals encoding differs")?;
        let context_value=json::parse(context.as_bytes(),MAX_RESULT)?;
        ensure(canonical_ascii_bytes(&context_value)?==context.as_bytes(),"combined context original not canonical")?;
        let original=context_value.as_object().ok_or("combined context envelope absent")?;
        let payload=context_value["payload"].as_object().ok_or("combined context payload absent")?;
        let names=["apiVersion","purpose","statementSha256","quoteSha256","nativeContextSha256","admissionAuthorizationSha256",
            "keyAuthorizationSha256","fullKeySetRootSha256","localKeySetRootSha256","measurementSha256","endorsementEvidenceSha256",
            "endorsementRootSha256","collateralPolicySha256","revocationSourceSha256","collateralRevocationGeneration",
            "collateralRevocationRootSha256","trustCheckpointId","trustRevocationGeneration","trustRevocationRootSha256",
            "verifiedAtUnixNanos","expiresAtUnixNanos","signingKeyId","signingKeySpkiSha256","productionConfigurationBindingSha256"];
        ensure(original.len()==3 && context_value["apiVersion"]=="catchplate.nativeShadowBridgeContextVerifierResult/v1"
            && context_value["signature"].is_string() && payload.len()==names.len()
            && names.iter().all(|name|payload.contains_key(*name))
            && payload["apiVersion"]=="catchplate.nativeShadowBridgeContextResult/v1"
            && payload["purpose"]=="native-shadow-context-and-production-admission","combined context fields differ")?;
        return result_shape(production.as_bytes(),crate::native_shadow_verifier_runtime_v1::ResultPurpose::Production);
    }
    if purpose==crate::native_shadow_verifier_runtime_v1::ResultPurpose::KeyAdmission {
        ensure(outer.len()==3 && value["apiVersion"]=="catchplate.nativeShadowKeyAdmissionVerifierResult/v1"
            && value["signature"].is_string(),"verifier admission output purpose differs")?;
        let payload=value["payload"].as_object().ok_or("verifier admission payload absent")?;
        let names=["apiVersion","purpose","statementSha256","quoteSha256","nativeContextSha256","admissionAuthorizationSha256",
            "keyAuthorizationSha256","fullKeySetRootSha256","localKeySetRootSha256","measurementSha256","endorsementEvidenceSha256",
            "endorsementRootSha256","collateralPolicySha256","revocationSourceSha256","collateralRevocationGeneration",
            "collateralRevocationRootSha256","trustCheckpointId","trustRevocationGeneration","trustRevocationRootSha256",
            "verifiedAtUnixNanos","expiresAtUnixNanos","signingKeyId","signingKeySpkiSha256"];
        return ensure(payload.len()==names.len() && names.iter().all(|name|payload.contains_key(*name))
            && value["payload"]["apiVersion"]=="catchplate.nativeShadowKeyAdmissionResult/v1"
            && value["payload"]["purpose"]=="native-shadow-key-admission","verifier admission fields differ");
    }
    ensure(outer.len() == 2 && value["apiVersion"] == "catchplate.nativeShadowNitroVerifierResult/v1",
        "verifier output purpose differs")?;
    let result = value["result"].as_object().ok_or("verifier result is not an object")?;
    let names = ["platform","quoteSha256","endorsementEvidenceSha256","endorsementRootSha256",
        "collateralPolicySha256","revocationSourceSha256","collateralRevocationGeneration",
        "collateralRevocationRootSha256","measurementSha256","productionConfigurationBindingSha256",
        "workerExecutableSha256","executionClosureManifestSha256","structurallyVerifiedSeccompPolicySha256",
        "quoteBoundCustodyKeySetRootSha256","verifiedAtUnixNanos","expiresAtUnixNanos","trustCheckpointId",
        "trustRevocationGeneration","trustRevocationRootSha256","signingKeyId","signingKeySpkiSha256","signature"];
    ensure(result.len() == names.len() && names.iter().all(|name| result.contains_key(*name)),
        "verifier output result fields differ")
    // This is framing only. Actual signature/assignment/current-trust admission
    // remains the existing genuine guest consumer, never a shape-based verdict.
}
fn stop_and_retire(mut owner: RunningRuntime, watch: &Watchdog) -> Result<(), String> {
    let rc = unsafe { libc::syscall(libc::SYS_pidfd_send_signal,owner.child_pidfd().as_raw_fd(),
        libc::SIGKILL,std::ptr::null::<libc::siginfo_t>(),0) };
    ensure(rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
        "verifier owned child stop failed")?;
    loop {
        // No cleanup allowance extends the original operation. The independently
        // armed timer remains active even if kernel stop/reap/detach blocks.
        watch.check()?;
        let mut poll = libc::pollfd { fd: owner.child_pidfd().as_raw_fd(),events: libc::POLLIN,revents: 0 };
        let rc = unsafe { libc::poll(&mut poll,1,25) };
        if rc < 0 { if interrupted() { continue; } return Err("verifier stop poll failed".into()); }
        ensure(poll.revents & (libc::POLLERR | libc::POLLNVAL) == 0, "verifier stop PIDFD changed")?;
        if poll.revents & (libc::POLLIN | libc::POLLHUP) == 0 { continue; }
        match owner.retire() {
            Ok(_) => return Ok(()),
            Err(failure) => {
                // RetireFailure retains the same child and, if already reaped,
                // the actual kernel reap. Retrying cleanup is never new work.
                owner = failure.into_cleanup();
            }
        }
    }
}
fn publish(output: &inputs::Output, input: &inputs::Inputs, bytes: &[u8], watch: &Watchdog) -> Result<(), String> {
    let mut offset = 0;
    while offset < bytes.len() {
        watch.check()?; output.check()?; input.check()?;
        let count = unsafe { libc::write(output.fd().as_raw_fd(),bytes[offset..].as_ptr().cast(),bytes.len()-offset) };
        if count > 0 { offset += count as usize; continue; }
        if count < 0 && interrupted() { continue; }
        if count < 0 && would_block() {
            let mut poll = libc::pollfd { fd: output.fd().as_raw_fd(),events: libc::POLLOUT,revents: 0 };
            let rc = unsafe { libc::poll(&mut poll,1,25) };
            if rc < 0 && interrupted() { continue; }
            ensure(rc >= 0 && poll.revents & (libc::POLLERR|libc::POLLHUP|libc::POLLNVAL) == 0,
                "verifier public output pipe failed")?;
            continue;
        }
        return Err("verifier public output write failed".into());
    }
    output.check()?; input.check()?; watch.check()
}
fn execute(admission: RuntimeAdmission, inputs: &inputs::Inputs, watch: &Watchdog)
    -> Result<Vec<u8>, String> {
    // The same protected admission survives across watchdog arming. No copied
    // deadline/configuration can create a fresh image/root operation.
    let profile = admission.profile();
    let purpose = match profile {
        crate::native_shadow_verifier_runtime_v1::Profile::Setup(_) => None,
        _ => Some(admission.result_purpose()?),
    };
    let mut runtime = admission.prepare()?;
    watch.check()?; runtime.check()?; inputs.check()?;
    let (result_read,result_write) = pipe()?;
    let (gate_read,gate_write) = pipe()?;
    nonblocking(result_read.as_raw_fd())?; nonblocking(gate_write.as_raw_fd())?;
    let child = {
        let inheritance = runtime.inheritance()?;
        if matches!(profile, crate::native_shadow_verifier_runtime_v1::Profile::Setup(_)) {
            child::PreparedChild::prepare_setup(&inheritance,inputs.seed(),inputs.evidence(),
                result_write.as_fd(),gate_read.as_fd())?
        } else {
            child::PreparedChild::prepare(&inheritance,inputs.seed(),inputs.evidence(),
                result_write.as_fd(),gate_read.as_fd())?
        }
    };
    // Every failure after inheritance ends this one-shot supervisor process.
    // No caller-supplied no-child cancellation authorizes mount reuse.
    let (pidfd,pid) = spawn(&child,watch)?;
    drop(child); drop(result_write); drop(gate_read);
    let owner = match runtime.bind_child(pidfd,pid) {
        Ok(owner) => owner,
        Err(failure) => {
            let _ = stop_and_retire(failure.into_cleanup(),watch);
            return Err("verifier child admission failed".into());
        }
    };
    let collected = (|| {
        owner.check()?; watch.check()?; inputs.check()?;
        release_gate(gate_write.as_raw_fd(),watch)?;
        drop(gate_write);
        let raw = collect(&owner,inputs,result_read.as_raw_fd(),watch)?;
        match profile {
            crate::native_shadow_verifier_runtime_v1::Profile::Setup(role) => setup_issuer::shape(&raw,role)?,
            _ => result_shape(&raw,purpose.ok_or("verifier result purpose absent")?)?,
        }
        owner.check_after_exit()?; inputs.check()?; watch.check()?;
        Ok::<_,String>(raw)
    })();
    let raw = match collected {
        Ok(raw) => raw,
        Err(error) => { let _ = stop_and_retire(owner,watch); return Err(error); }
    };
    let retired = match owner.retire() {
        Ok(retired) => retired,
        Err(failure) => {
            let _ = stop_and_retire(failure.into_cleanup(),watch);
            return Err("verifier original root/child retirement failed".into());
        }
    };
    ensure(retired.code() == libc::CLD_EXITED && retired.status() == 0,
        "verifier child did not exit successfully")?;
    watch.check()?; inputs.check()?;
    Ok(raw)
}
fn attempt() -> Result<(), String> {
    ensure(std::env::args_os().count() == 1, "verifier supervisor accepts no arguments")?;
    parent_security()?;
    let mut inputs = inputs::Inputs::take()?;
    let output = inputs::Output::take()?;
    let admission = RuntimeAdmission::open()?;
    let watch = Watchdog::arm(&admission)?;
    inputs.bind(&admission)?;
    let raw = execute(admission,&inputs,&watch)?;
    publish(&output,&inputs,&raw,&watch)
}
/// Only fixed one-shot process entry, never an embeddable launch/retry API.
pub fn run() -> ! {
    let status = if attempt().is_ok() { 0 } else { 1 };
    // No secret-bearing error text. Exit also closes every failure-retained
    // namespace/descriptor; it does not claim explicit successful cleanup.
    unsafe { libc::_exit(status) }
}
/// Separate fixed binary selection, never inferred from an inherited socket.
pub fn run_transport() -> ! { transport::run() }
/// Fixed external issuer only; no profile inference from socket/config bytes.
pub fn run_time_issuer() -> ! { time_issuer::run() }
/// Independent origin authority only; not installed in the claimant image.
pub fn run_origin_issuer() -> ! { origin_issuer::run() }
pub fn run_setup_hardware() -> ! { setup_issuer::run(crate::native_shadow_verifier_runtime_v1::setup_issuer::Role::Hardware) }
pub fn run_setup_proxy() -> ! { setup_issuer::run(crate::native_shadow_verifier_runtime_v1::setup_issuer::Role::Proxy) }
pub fn run_setup_final() -> ! { setup_issuer::run(crate::native_shadow_verifier_runtime_v1::setup_issuer::Role::Final) }
pub fn run_installed_setup_hardware() -> ! { setup_installed::run(crate::native_shadow_verifier_runtime_v1::setup_issuer::Role::Hardware) }
pub fn run_installed_setup_proxy() -> ! { setup_installed::run(crate::native_shadow_verifier_runtime_v1::setup_issuer::Role::Proxy) }
pub fn run_installed_setup_final() -> ! { setup_installed::run(crate::native_shadow_verifier_runtime_v1::setup_issuer::Role::Final) }
