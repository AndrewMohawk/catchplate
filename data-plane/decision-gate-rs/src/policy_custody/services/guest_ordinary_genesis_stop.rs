//! One actual cold ordinary owner, one parent stop and one helper reap.
//! This is process cleanup evidence, never a business-operation result.
use super::*;
use std::cell::RefCell;
use std::os::fd::AsRawFd;

const STOP:&str="serverware.custodyGenesisOrdinaryStop/v1";
const TERMINAL:&str="serverware.custodyGenesisOrdinaryTerminal/v1";

thread_local! {
    static SERVING:RefCell<Option<Arc<Delivery>>>=const {RefCell::new(None)};
}

struct WaitGuard;
impl Drop for WaitGuard {fn drop(&mut self){SERVING.with(|slot|{slot.borrow_mut().take();});}}

/// Only the actual InspectedGenesis entry installs this main-thread guard.
/// Other profiles and durability threads retain their existing wait behavior.
pub(in crate::policy_shadow::policy_custody::services) fn check_wait()->Result<(),ServiceRunnerError> {
    SERVING.with(|slot| {
        let held=slot.borrow();
        if let Some(owner)=held.as_ref() {
            owner.process.check()?;
            if owner.parent.genesis_stop_pending()? {
                return Err(fail("cold ordinary serving stopped by pending parent control"));
            }
        }
        Ok(())
    })
}

/// The same main-thread guard retains this descriptor throughout the poll;
/// no descriptor is transferred and no caller can install a raw-FD owner.
pub(in crate::policy_shadow::policy_custody::services) fn wait_descriptor()->Option<i32> {
    SERVING.with(|slot|slot.borrow().as_ref().map(|owner|owner.parent.genesis_stop_descriptor().as_raw_fd()))
}

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Stop {api_version:String,delivery_sha256:Sha256Digest,service_role:Role,
    invocation_id:String,deadline_boottime_ns:String}

#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Helper {pid:i32,start_time_ticks:u64,exit_code:i32,exit_status:i32,reaped_at_boottime_ns:String}

#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Terminal<'a> {api_version:&'static str,delivery_sha256:&'a Sha256Digest,service_role:Role,
    invocation_id:&'a str,deadline_boottime_ns:&'a str,stop_sha256:Sha256Digest,helper:Helper,
    service_result:&'static str,service_exit_status:i32}

fn retained(owner:&Delivery)->Result<(),ServiceRunnerError> {
    owner.process.check()?;owner.parent.check_genesis_parent()?;
    owner.configuration.check()?;owner.envelope.check()?;owner.runtime.check()?;
    for (_,original) in owner.credentials.values() {original.check()?;}
    let held=owner.ordinary_lifetime.lock().map_err(|_|fail("cold ordinary lifetime lock poisoned"))?;
    held.as_ref().ok_or_else(||fail("cold ordinary lifetime owner missing"))?.check()?;
    let (mut real,mut effective,mut saved)=(0u32,0u32,0u32);
    require(unsafe{libc::getresuid(&mut real,&mut effective,&mut saved)}==0
        && [real,effective,saved]==[owner.payload.uid;3])?;
    require(unsafe{libc::getresgid(&mut real,&mut effective,&mut saved)}==0
        && [real,effective,saved]==[owner.payload.gid;3])?;
    require(owner.ready.load(Ordering::Acquire) && now()?<owner.lifetime)
}

fn finish(owner:&Arc<Delivery>,worker:&mut super::super::ordinary_inspection::Worker,
    serving_ok:bool)->Result<i32,ServiceRunnerError> {
    // A connection closing before the operator asks to stop is not permission
    // to discard either lifetime or the real inspection child owner.
    let raw=loop {
        retained(owner)?;
        if let Some(raw)=owner.parent.receive_genesis_stop()? {break raw;}
        std::thread::sleep(std::time::Duration::from_millis(1));
    };
    let stop:Stop=exact(&raw)?;
    require(stop.api_version==STOP && stop.delivery_sha256==owner.delivery_sha256
        && stop.service_role==owner.payload.service_role && stop.invocation_id==owner.payload.invocation_id
        && stop.deadline_boottime_ns==owner.payload.lifetime_deadline_boottime_ns
        && ns(&stop.deadline_boottime_ns)?==owner.lifetime)?;
    retained(owner)?;owner.parent.check()?;
    let reaped=worker.stop_and_reap()?;
    require(reaped.exit_code()==libc::CLD_EXITED && reaped.exit_status()==0
        && reaped.reaped_at_boottime_ns()<owner.lifetime)?;
    retained(owner)?;owner.parent.check()?;
    let status=if serving_ok {0}else{1};
    let value=Terminal{api_version:TERMINAL,delivery_sha256:&owner.delivery_sha256,
        service_role:owner.payload.service_role,invocation_id:&owner.payload.invocation_id,
        deadline_boottime_ns:&owner.payload.lifetime_deadline_boottime_ns,
        stop_sha256:Sha256Digest::compute(&raw),helper:Helper{pid:reaped.pid(),start_time_ticks:reaped.start_time_ticks(),
            exit_code:reaped.exit_code(),exit_status:reaped.exit_status(),reaped_at_boottime_ns:reaped.reaped_at_boottime_ns().to_string()},
        service_result:if serving_ok {"ok"}else{"error"},service_exit_status:status};
    let bytes=canonical_json_bytes(&value).map_err(|_|fail("cold terminal encoding failed"))?;
    require(bytes.len()<=4096)?;
    owner.parent.send(&bytes,owner.lifetime)?;
    retained(owner)?;owner.parent.check()?;
    Ok(status)
}

pub(super) fn run(delivery:PreparedGuestServiceDelivery,worker:&mut super::super::ordinary_inspection::Worker)
    ->Result<(),ServiceRunnerError> {
    let owner=Arc::clone(&delivery.owner);
    require(matches!(owner.payload.service_role,Role::DurableRecoveryStore|Role::CurrentSignatureAuthority))?;
    owner.parent.configure_genesis_stop()?;
    SERVING.with(|slot| {
        require(slot.borrow().is_none())?;
        *slot.borrow_mut()=Some(Arc::clone(&owner));
        Ok::<(),ServiceRunnerError>(())
    })?;
    let guard=WaitGuard;
    let result=delivery.run_after_drop();
    drop(guard); // No selected control hook escapes the actual serving stack.
    let status=finish(&owner,worker,result.is_ok())?;
    // Both genuine owners and original kernel timers remain alive until the
    // real process exit. The parent still must consume its service PIDFD reap.
    unsafe{libc::_exit(status)}
}
