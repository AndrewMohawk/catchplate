//! Same-account active-family reconnect, selected only by the native cold owner.
//! PREPARE follows the independently verified family fence and returns the one
//! provider redirect; every contact follows its distinct committed receipt.
use super::*;
use catchplate_decision_gate::native_oauth_browser_v1::{Accepted,Kind};
use catchplate_decision_gate::native_oauth_reconnect_v1::{self as wire,BrowserTls,Configuration,Prepared,Reply};
use catchplate_decision_gate::native_secret_broker_v1 as broker;
use catchplate_decision_gate::enclave_vsock_v1::VsockShutdownV1;

pub(super) struct Owner {
    config:Configuration, endpoint:String, recovery_endpoint:String, ingress:Arc<BrowserTls>,
    listener:Option<VsockListenerV1>, poisoned:bool,
}

pub(super) fn prepare(config:Configuration,inputs:&GateStateInputs,actual:&mut broker::Owner,
    identity:&mut EnclaveRuntimeIdentityV1,signer:&CustodyResponseProofSigner,binary:&str,deadline:u64)->Result<Owner,String>{
    config.validate()?;
    if inputs.server_instance_id.as_deref()!=Some(config.instance_id.as_str())
        || inputs.credential_currentness.as_ref().map(|value|value.deployment_id.as_str())!=Some(config.deployment_id.as_str())
        || !matches!(&inputs.service_tokens,native_service_tokens::Source::Installed) {
        return Err("reconnect requires actual encrypted service, instance and currentness owners".to_owned());
    }
    signer.transport.verify_native_identity(identity,deadline)?;
    let mut endpoint=Url::parse(inputs.credential_lease_url.as_deref().ok_or("reconnect CP origin absent")?)
        .map_err(|_|"reconnect CP origin invalid")?;
    if endpoint.scheme()!="https" || endpoint.path()!="/api/data-plane/credential-leases"
        || endpoint.query().is_some() || endpoint.fragment().is_some() || !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err("reconnect requires the original fixed credential service origin".to_owned());
    }
    let ingress=identity.prepare_browser_ingress(&config.callback_origin,OffsetDateTime::now_utc(),deadline)?;
    let listener=VsockListenerV1::bind(config.browser_vsock_port,2,deadline)
        .map_err(|_|"reconnect fixed-parent browser listener unavailable")?;
    actual.configure_reconnect(config.clone(),Arc::clone(&ingress),identity,&signer.boot_id,&signer.key_id,
        &signer.control_plane_response_signing_key_id,binary,deadline)?;
    endpoint.set_path("/api/data-plane/oauth-reconnect"); let effect=endpoint.to_string();
    endpoint.set_path("/api/data-plane/oauth-reconnect/original");
    Ok(Owner{config,endpoint:effect,recovery_endpoint:endpoint.to_string(),ingress,listener:Some(listener),poisoned:false})
}

fn evidence(state:&GateState,prepared:&Prepared,deadline:u64)->Result<Value,String>{
    native_service_remaining(state)?;
    let ResponseProofSigner::Custody(signer)=&state.response_proof_signer else{return Err("reconnect native signer absent".to_owned());};
    let mut held=state.mitm_authority.as_ref().ok_or("reconnect actual CA absent")?.lock().map_err(|_|"reconnect identity owner poisoned")?;
    let MitmAuthority::Native(identity)=&mut *held else{return Err("reconnect refuses imported CA".to_owned());};
    signer.transport.reconnect_evidence(identity,prepared,&state.binary_digest,deadline)
}

fn post(state:&GateState,url:&str,body:Vec<u8>,deadline:u64)->Result<Value,String>{
    native_service_remaining(state)?;
    if body.len()>3*1024*1024{return Err("reconnect complete HTTP request bound".to_owned());}
    let remaining=deadline.checked_sub(broker::now()?).filter(|value|*value>0).ok_or("reconnect original operation interval expired")?;
    let mut response=state.credential_lease_client.post(url).header("X-Catchplate-Data-Plane-Token",
        state.credential_lease_token.as_deref().ok_or("reconnect service token absent")?)
        .header("Content-Type","application/json").body(body).timeout(Duration::from_nanos(remaining))
        .send().map_err(|_|"reconnect writer response uncertain; no resubmission")?;
    if !response.status().is_success(){return Err("reconnect writer refused; no fallback or retry".to_owned());}
    let raw=read_bounded_control_plane_response_body(&mut response,8*1024*1024,"native reconnect")?;
    if broker::now()?>=deadline{return Err("reconnect writer response arrived after original operation interval".to_owned());}
    catchplate_decision_gate::native_oauth_refresh_v1::response_document(&raw)
}

fn receipt(state:&GateState,owner:&Owner,helper:&mut broker::Owner,prepared:&Prepared,deadline:u64)->Result<Reply,String>{
    owner.ingress.check(deadline)?; native_service_remaining(state)?;
    let body=catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&prepared.wire(evidence(state,prepared,deadline)?)?)?;
    let mut originals=post(state,&owner.endpoint,body,deadline)?;
    if originals["apiVersion"]!=wire::HTTP_RESPONSE || originals.as_object().is_none_or(|value|value.len()!=3
        || !["apiVersion","requestOriginal","responseOriginal"].iter().all(|name|value.contains_key(*name))) {
        return Err("reconnect writer originals differ".to_owned());
    }
    originals.as_object_mut().ok_or("reconnect originals object")?.remove("apiVersion");
    // This is not a successful-effect DTO. The same private owner verifies the
    // exact signed request/result before decrypting or advancing its protocol.
    helper.reconnect_receipt(originals,prepared,deadline,state.native_upstream_relays.as_ref().ok_or("reconnect relays absent")?)
}

fn complete(state:&GateState,owner:&Owner,helper:&mut broker::Owner,mut reply:Reply,deadline:u64,recovery:bool)->Result<Reply,String>{
    let mut exchange:Option<String>=None;
    let mut expected:Option<&str>=if recovery{Some("oauth.measured-reconnect.recover")}else{None};
    let mut last:Option<String>=None;
    // Callback: CLAIM -> CAPTURE -> STAGE; cancellation is one phase.
    // Recovery: RECOVER -> optional STAGE. No phase can repeat or renew time.
    for _ in 0..4 {
        owner.ingress.check(deadline)?; native_service_remaining(state)?;
        match reply {
            Reply::Prepared(prepared)=>{
                let operation=prepared.operation();
                let id=prepared.exchange_id()?.to_owned();
                if exchange.as_ref().is_some_and(|old|old!=&id)
                    || match expected {
                        Some(value)=>operation!=value,
                        None=>last.is_some() || !matches!(operation,"oauth.measured-reconnect.claim"|"oauth.measured-reconnect.cancel"),
                    } {
                    return Err("reconnect phase sequence or retained exchange differs".to_owned());
                }
                expected=match operation {
                    "oauth.measured-reconnect.claim"=>Some("oauth.measured-reconnect.capture"),
                    "oauth.measured-reconnect.capture"|"oauth.measured-reconnect.recover"=>Some("oauth.measured-reconnect.stage"),
                    "oauth.measured-reconnect.stage"|"oauth.measured-reconnect.cancel"=>None,
                    _=>return Err("reconnect phase cannot enter terminal driver".to_owned()),
                };
                last=Some(operation.to_owned()); exchange=Some(id);
                reply=receipt(state,owner,helper,&prepared,deadline)?;
            },
            Reply::Complete{ref exchange_id,ref status,..}=>{
                let valid=match last.as_deref(){
                    Some("oauth.measured-reconnect.cancel")=>!recovery && status=="cancelled",
                    Some("oauth.measured-reconnect.capture")=>!recovery && status=="captured-unusable",
                    Some("oauth.measured-reconnect.stage")=>status=="staged",
                    Some("oauth.measured-reconnect.recover")=>recovery && matches!(status.as_str(),"observed-staged"|"observed-committed"|"captured-unusable"),
                    _=>false,
                };
                if exchange.as_ref()!=Some(exchange_id) || !valid{return Err("reconnect terminal observation differs from its actual phase".to_owned());}
                return Ok(reply);
            },
            _=>return Err("reconnect terminal driver received a browser redirect".to_owned()),
        }
    }
    Err("reconnect finite phase bound exceeded".to_owned())
}

fn browser(state:&GateState,owner:&mut Owner,mut request:Accepted)->Result<(),String>{
    if owner.poisoned{return Err("reconnect browser owner poisoned".to_owned());}
    if matches!(request.kind(),Kind::BeginPage) {
        let (page,csp)=native_oauth_browser_pages::reconnect_page(&owner.config.portal_origin)?;
        return request.respond("text/html; charset=utf-8",&page,None,&csp);
    }
    let _serial=state.native_oauth_serial.try_lock().map_err(|_|"another original OAuth operation is live")?;
    let relays=state.native_upstream_relays.as_ref().ok_or("reconnect fixed relays absent")?;
    // Local serialization is not family permission or a holder-drain proof.
    // The actual helper independently re-admits retained fence originals.
    let mut helper=state.native_secret_broker.as_ref().ok_or("reconnect helper absent")?.lock().map_err(|_|"reconnect helper poisoned")?;
    let result=(||{
        let deadline=request.deadline();
        let reply=helper.reconnect_browser(&request,relays)?;
        match reply {
            Reply::Prepared(prepared) if matches!(request.kind(),Kind::Begin)=>{
                if prepared.operation()!="oauth.measured-reconnect.prepare" {return Err("reconnect begin yielded a different machine phase".to_owned());}
                // PREPARE is sent once here, not returned to a second browser
                // draft ceremony. Its statement phase is the frozen `draft`.
                let Reply::Redirect{exchange_id,location,name,value,expires}=receipt(state,owner,&mut helper,&prepared,deadline)?
                    else{return Err("reconnect PREPARE did not produce its same-owner redirect and cookie".to_owned());};
                let url=Url::parse(&location).map_err(|_|"reconnect redirect invalid")?;
                let provider_matches=match prepared.provider()? {
                    "google"=>url.host_str()==Some("accounts.google.com") && url.path()=="/o/oauth2/v2/auth",
                    "x"=>url.host_str()==Some("twitter.com") && url.path()=="/i/oauth2/authorize",
                    _=>false,
                };
                if exchange_id!=prepared.exchange_id()? || !provider_matches{return Err("reconnect redirect owner/provider differs".to_owned());}
                let epoch=u64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos()).map_err(|_|"reconnect cookie clock invalid")?;
                let max_age=expires.checked_sub(epoch).filter(|value|*value>=1_000_000_000).ok_or("reconnect original cookie expired")?/1_000_000_000;
                let cookie=format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}");
                let body=catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&json!({
                    "apiVersion":"catchplate.nativeOAuthReconnectAuthorizationRedirect/v1","exchangeId":exchange_id,"location":location}))?;
                if body.len()>64*1024{return Err("reconnect redirect response bound".to_owned());}
                owner.ingress.check(deadline)?;
                request.respond("application/json",&body,Some(&cookie),"default-src 'none'; frame-ancestors 'none'")
            },
            reply if matches!(request.kind(),Kind::Callback)=>{
                let Reply::Complete{exchange_id,status,..}=complete(state,owner,&mut helper,reply,deadline,false)?
                    else{return Err("reconnect callback did not terminate".to_owned());};
                let page=native_oauth_browser_pages::terminal(&status,&owner.config.portal_origin)?;
                let cookie=format!("__Host-catchplate-native-oauth-{}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",exchange_id.replace('-',""));
                request.respond("text/html; charset=utf-8",&page,Some(&cookie),"default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            },
            _=>Err("reconnect native browser/helper phase mismatch".to_owned()),
        }
    })();
    if result.is_err(){owner.poisoned=true;} result
}

pub(super) fn initialize(state:&GateState)->Result<(),String>{
    let Some(owner)=&state.measured_reconnect else{return Ok(());};
    let mut owner=owner.lock().map_err(|_|"reconnect recovery owner poisoned")?;
    let _serial=state.native_oauth_serial.try_lock().map_err(|_|"reconnect recovery operation overlaps")?;
    let targets=owner.config.recovery_targets.clone();
    let result=(||{
        for id in targets {
            // This bounds only fresh observation/verification. The private
            // owner clips recovery to retained original grant/capture expiry.
            let deadline=broker::now()?.checked_add(30_000_000_000).ok_or("reconnect recovery interval overflow")?.min(owner.ingress.deadline());
            let original=post(state,&owner.recovery_endpoint,catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes(
                &json!({"apiVersion":"catchplate.nativeOAuthReconnectRecoveryOriginalRequest/v1","exchangeId":id}))?,deadline)?;
            let relays=state.native_upstream_relays.as_ref().ok_or("reconnect recovery relays absent")?;
            let mut helper=state.native_secret_broker.as_ref().ok_or("reconnect recovery helper absent")?.lock().map_err(|_|"reconnect recovery helper poisoned")?;
            let reply=helper.recover_reconnect(&id,original,deadline,relays)?;
            complete(state,&owner,&mut helper,reply,deadline,true)?;
        }
        Ok(())
    })();
    if result.is_err(){owner.poisoned=true;} result
}

pub(super) fn start<'scope,'env:'scope>(scope:&'scope thread::Scope<'scope,'env>,state:Arc<GateState>,
    lifetime:Arc<NativeRuntimeLifetimeV1>)->Result<(),String>{
    let Some(owner)=&state.measured_reconnect else{return Ok(());};
    let (listener,ingress,port)={let mut held=owner.lock().map_err(|_|"reconnect browser owner poisoned")?;
        if held.poisoned{return Err("reconnect browser owner unavailable".to_owned());}
        (held.listener.take().ok_or("reconnect listener already consumed")?,Arc::clone(&held.ingress),held.config.browser_vsock_port)};
    let active:Arc<Mutex<Option<VsockShutdownV1>>>=Arc::new(Mutex::new(None));
    let stopping=Arc::clone(&lifetime); let shutdown=Arc::clone(&active);
    native_runtime_lifetime::spawn_task(scope,&lifetime,"native-oauth-reconnect-browser-cancellation".to_owned(),move||{
        while !stopping.is_stopped(){if !stopping.wait(Duration::from_millis(25))?{break;}}
        if let Some(stream)=shutdown.lock().map_err(|_|"reconnect shutdown owner poisoned")?.as_ref(){let _=stream.shutdown();}
        Ok(())
    })?;
    let serving=Arc::clone(&lifetime);
    native_runtime_lifetime::spawn_task(scope,&lifetime,"native-oauth-reconnect-browser".to_owned(),move||{
        while !serving.is_stopped(){
            serving.check()?;
            let stream=match listener.accept_cancellable(serving.deadline(),serving.stopped_flag()) {
                Ok(value)=>value,Err(_) if serving.is_stopped()=>return Ok(()),Err(_)=>return Err("reconnect browser accept failed".to_owned()),
            };
            let deadline=broker::now()?.checked_add(30_000_000_000).ok_or("reconnect browser interval overflow")?.min(serving.deadline());
            stream.verify_accepted_local_port(port,deadline).map_err(|_|"reconnect original listener changed")?;
            *active.lock().map_err(|_|"reconnect shutdown owner poisoned")?=Some(stream.shutdown_handle().map_err(|_|"reconnect shutdown original unavailable")?);
            let outcome=match Accepted::accept_reconnect(stream,Arc::clone(&ingress),deadline){
                Ok(request)=>{let mut owner=state.measured_reconnect.as_ref().ok_or("reconnect original owner lost")?.lock().map_err(|_|"reconnect browser owner poisoned")?;
                    browser(&state,&mut owner,request)},
                // The private helper/provider has not been entered. Malformed
                // inbound TLS/HTTP closes without constructing effect authority.
                Err(_)=>Ok(()),
            };
            active.lock().map_err(|_|"reconnect shutdown owner poisoned")?.take();
            if serving.is_stopped(){return Ok(());} outcome?;
        }
        Ok(())
    })
}
