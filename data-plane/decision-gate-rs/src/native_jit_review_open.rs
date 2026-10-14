//! Combined-v27 browser listener. Public byte inputs never construct an actual
//! accepted TLS request; private review bytes remain inside the library owner.
use super::*;
use serverware_decision_gate::{native_jit_review_open_v1 as opening,
    native_jit_review_browser_v1::Accepted,native_secret_broker_v1 as broker,
    enclave_vsock_v1::VsockShutdownV1};

pub(super) struct Owner { admitted:opening::Owner,listener:Option<VsockListenerV1> }
pub(super) fn prepare(config:opening::Configuration,assignment:&[u8],inputs:&GateStateInputs,
    broker:&mut broker::Owner,identity:&mut EnclaveRuntimeIdentityV1,signer:&CustodyResponseProofSigner,
    binary:&str,deadline:u64)->Result<Owner,String>{
    config.validate()?;
    if inputs.server_instance_id.as_deref()!=Some(config.instance_id())
        || inputs.credential_currentness.as_ref().map(|v|v.deployment_id.as_str())!=Some(config.deployment_id())
        || !matches!(&inputs.service_tokens,native_service_tokens::Source::Installed){
        return Err("opening requires actual encrypted service and instance owners".into());
    }
    let admitted=signer.transport.configure_jit_review_open(config,assignment,broker,identity,binary,deadline)?;
    let listener=VsockListenerV1::bind(admitted.browser_vsock_port(),3,deadline).map_err(|_|"opening fixed-parent listener unavailable")?;
    Ok(Owner{admitted,listener:Some(listener)})
}
fn purpose_guard(lock:&Mutex<()>)->Result<Option<std::sync::MutexGuard<'_,()>>,String>{
    match lock.try_lock() {
        Ok(guard)=>Ok(Some(guard)),
        Err(std::sync::TryLockError::WouldBlock)=>Ok(None),
        Err(std::sync::TryLockError::Poisoned(_))=>Err("native purpose lock poisoned".into()),
    }
}
fn browser(state:&GateState,owner:&mut Owner,mut request:Accepted)->Result<(),String>{
    native_service_remaining(state)?;
    let ResponseProofSigner::Custody(signer)=&state.response_proof_signer else{return Err("opening native signer absent".into());};
    let Some(_serial)=purpose_guard(&state.native_oauth_serial)? else{return Ok(());};
    // Same retained owner/lock order as JIT sealing; no DB/currentness locks
    // remain held while the private child or actual NSM signer is executing.
    let mut broker=state.native_secret_broker.as_ref().ok_or("opening broker absent")?.lock().map_err(|_|"opening broker poisoned")?;
    let mut authority=state.mitm_authority.as_ref().ok_or("opening native CA absent")?.lock().map_err(|_|"opening identity poisoned")?;
    let MitmAuthority::Native(identity)=&mut *authority else{return Err("opening refuses imported CA".into());};
    signer.transport.handle_jit_review_open(&mut owner.admitted,&mut broker,identity,&mut request,&state.binary_digest)
}
pub(super) fn start<'scope,'env:'scope>(scope:&'scope thread::Scope<'scope,'env>,state:Arc<GateState>,
    lifetime:Arc<NativeRuntimeLifetimeV1>)->Result<(),String>{
    let Some(owner)=&state.native_jit_review_open else{return Ok(());};
    let (listener,ingress,port)={
        let mut owner=owner.lock().map_err(|_|"opening listener poisoned")?;
        (owner.listener.take().ok_or("opening listener spent")?,owner.admitted.browser_ingress(),owner.admitted.browser_vsock_port())
    };
    let active:Arc<Mutex<Option<VsockShutdownV1>>>=Arc::new(Mutex::new(None));
    let stopping=Arc::clone(&lifetime);let shutdown=Arc::clone(&active);
    native_runtime_lifetime::spawn_task(scope,&lifetime,"native-review-browser-cancellation".into(),move||{
        while !stopping.is_stopped(){if !stopping.wait(Duration::from_millis(25))?{break;}}
        if let Some(stream)=shutdown.lock().map_err(|_|"opening shutdown poisoned")?.as_ref(){let _=stream.shutdown();}Ok(())
    })?;
    let serving=Arc::clone(&lifetime);
    native_runtime_lifetime::spawn_task(scope,&lifetime,"native-review-browser".into(),move||{
        while !serving.is_stopped(){
            serving.check()?;
            let stream=match listener.accept_cancellable(serving.deadline(),serving.stopped_flag()){
                Ok(stream)=>stream,Err(_) if serving.is_stopped()=>return Ok(()),Err(_)=>return Err("opening browser accept failed".into()),
            };
            let deadline=broker::now()?.checked_add(30_000_000_000).ok_or("opening socket clock overflow")?.min(serving.deadline());
            stream.verify_accepted_local_port(port,deadline).map_err(|_|"opening listener identity changed")?;
            *active.lock().map_err(|_|"opening shutdown poisoned")?=Some(stream.shutdown_handle().map_err(|_|"opening shutdown unavailable")?);
            if serving.is_stopped(){
                if let Some(handle)=active.lock().map_err(|_|"opening shutdown poisoned")?.take(){let _=handle.shutdown();}return Ok(());
            }
            let result=match Accepted::accept(stream,Arc::clone(&ingress),deadline){
                Ok(request)=>{
                    let mut owner=state.native_jit_review_open.as_ref().ok_or("opening owner lost")?.lock().map_err(|_|"opening owner poisoned")?;
                    browser(&state,&mut owner,request)
                },Err(_)=>Ok(()),
            };
            active.lock().map_err(|_|"opening shutdown poisoned")?.take();
            if serving.is_stopped(){return Ok(());}result?;
        }Ok(())
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn busy_purpose_refuses_one_connection_but_poison_is_terminal() {
        let lock=std::sync::Mutex::new(());
        let held=lock.lock().unwrap();
        assert!(super::purpose_guard(&lock).unwrap().is_none());
        drop(held);
        assert!(super::purpose_guard(&lock).unwrap().is_some());
        let lock=std::sync::Arc::new(std::sync::Mutex::new(()));
        let other=std::sync::Arc::clone(&lock);
        assert!(std::thread::spawn(move||{let _held=other.lock().unwrap();panic!("synthetic poison");}).join().is_err());
        assert!(super::purpose_guard(&lock).is_err());
        assert!(super::purpose_guard(&lock).is_err());
    }
    #[test]
    fn ordinary_gate_has_no_opening_or_sealing_owner() {
        let state=crate::tests::test_gate_state(crate::tests::test_snapshot(1));
        assert!(state.native_jit_review_open.is_none());
        assert!(state.native_jit_review.is_none());
        assert!(state.native_secret_broker.is_none());
    }
}
