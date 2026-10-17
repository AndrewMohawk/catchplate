//! Independently authorized retired-scope succession with finite material steps.
//! Signed FENCE precedes cleanup; complete accepted closure precedes fresh PKCE.
//! Original scope, holder drains and purpose-specific native custody stay live.
use super::*;
use catchplate_decision_gate::native_oauth_browser_v1::{Accepted,Kind};
use catchplate_decision_gate::native_oauth_succession_v1::{self as wire,BrowserTls,Configuration,Prepared,Reply};
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
        return Err("succession requires actual encrypted service, instance and currentness owners".to_owned());
    }
    signer.transport.verify_native_identity(identity,deadline)?;
    let mut endpoint=Url::parse(inputs.credential_lease_url.as_deref().ok_or("succession CP origin absent")?)
        .map_err(|_|"succession CP origin invalid")?;
    if endpoint.scheme()!="https" || endpoint.path()!="/api/data-plane/credential-leases"
        || endpoint.query().is_some() || endpoint.fragment().is_some() || !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err("succession requires the original fixed credential service origin".to_owned());
    }
    let ingress=identity.prepare_browser_ingress(&config.callback_origin,OffsetDateTime::now_utc(),deadline)?;
    let listener=VsockListenerV1::bind(config.browser_vsock_port,2,deadline)
        .map_err(|_|"succession fixed-parent browser listener unavailable")?;
    actual.configure_succession(config.clone(),Arc::clone(&ingress),identity,&signer.boot_id,&signer.key_id,
        &signer.control_plane_response_signing_key_id,binary,deadline)?;
    endpoint.set_path("/api/data-plane/oauth-succession"); let effect=endpoint.to_string();
    endpoint.set_path("/api/data-plane/oauth-succession/original");
    Ok(Owner{config,endpoint:effect,recovery_endpoint:endpoint.to_string(),ingress,listener:Some(listener),poisoned:false})
}

fn evidence(state:&GateState,prepared:&Prepared,deadline:u64)->Result<Value,String>{
    native_service_remaining(state)?;
    let ResponseProofSigner::Custody(signer)=&state.response_proof_signer else{return Err("succession native signer absent".to_owned());};
    let mut held=state.mitm_authority.as_ref().ok_or("succession actual CA absent")?.lock().map_err(|_|"succession identity owner poisoned")?;
    let MitmAuthority::Native(identity)=&mut *held else{return Err("succession refuses imported CA".to_owned());};
    signer.transport.succession_evidence(identity,prepared,&state.binary_digest,deadline)
}

fn post(state:&GateState,url:&str,body:Vec<u8>,deadline:u64)->Result<Value,String>{
    native_service_remaining(state)?;
    if body.len()>3*1024*1024{return Err("succession complete HTTP request bound".to_owned());}
    let remaining=deadline.checked_sub(broker::now()?).filter(|value|*value>0).ok_or("succession original operation interval expired")?;
    let mut response=state.credential_lease_client.post(url).header("X-Catchplate-Data-Plane-Token",
        state.credential_lease_token.as_deref().ok_or("succession service token absent")?)
        .header("Content-Type","application/json").body(body).timeout(Duration::from_nanos(remaining))
        .send().map_err(|_|"succession writer response uncertain; no resubmission")?;
    if !response.status().is_success(){return Err("succession writer refused; no fallback or retry".to_owned());}
    let raw=read_bounded_control_plane_response_body(&mut response,8*1024*1024,"native succession")?;
    if broker::now()?>=deadline{return Err("succession writer response arrived after original operation interval".to_owned());}
    catchplate_decision_gate::native_oauth_refresh_v1::response_document(&raw)
}

fn receipt(state:&GateState,owner:&Owner,helper:&mut broker::Owner,prepared:&Prepared,deadline:u64)->Result<Reply,String>{
    owner.ingress.check(deadline)?; native_service_remaining(state)?;
    let body=catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&prepared.wire(evidence(state,prepared,deadline)?)?)?;
    let mut originals=post(state,&owner.endpoint,body,deadline)?;
    if originals["apiVersion"]!=wire::HTTP_RESPONSE || originals.as_object().is_none_or(|value|value.len()!=3
        || !["apiVersion","requestOriginal","responseOriginal"].iter().all(|name|value.contains_key(*name))) {
        return Err("succession writer originals differ".to_owned());
    }
    originals.as_object_mut().ok_or("succession originals object")?.remove("apiVersion");
    // This is not a successful-effect DTO. The same private owner verifies the
    // exact signed request/result before decrypting or advancing its protocol.
    helper.succession_receipt(originals,prepared,deadline,state.native_upstream_relays.as_ref().ok_or("succession relays absent")?)
}

fn complete(state:&GateState,owner:&Owner,helper:&mut broker::Owner,mut reply:Reply,deadline:u64,recovery:bool)->Result<Reply,String>{
    let mut exchange:Option<String>=None;
    let mut expected:Option<&str>=if recovery{Some("oauth.measured-succession.recover")}else{None};
    let mut last:Option<String>=None;
    // Callback: CLAIM -> CAPTURE -> STAGE; cancellation is one phase.
    // Recovery is exactly RECOVER -> observation, with no STAGE or contact.
    for _ in 0..4 {
        owner.ingress.check(deadline)?; native_service_remaining(state)?;
        match reply {
            Reply::Prepared(prepared)=>{
                let operation=prepared.operation();
                let id=prepared.exchange_id()?.to_owned();
                if exchange.as_ref().is_some_and(|old|old!=&id)
                    || match expected {
                        Some(value)=>operation!=value,
                        None=>last.is_some() || !matches!(operation,"oauth.measured-succession.claim"|"oauth.measured-succession.cancel"),
                    } {
                    return Err("succession phase sequence or retained exchange differs".to_owned());
                }
                expected=match operation {
                    "oauth.measured-succession.claim"=>Some("oauth.measured-succession.capture"),
                    "oauth.measured-succession.capture"=>Some("oauth.measured-succession.stage"),
                    "oauth.measured-succession.recover"|"oauth.measured-succession.stage"|"oauth.measured-succession.cancel"=>None,
                    _=>return Err("succession phase cannot enter terminal driver".to_owned()),
                };
                last=Some(operation.to_owned()); exchange=Some(id);
                reply=receipt(state,owner,helper,&prepared,deadline)?;
            },
            Reply::Complete{ref exchange_id,ref status,..}=>{
                let valid=match last.as_deref(){
                    Some("oauth.measured-succession.cancel")=>!recovery && status=="cancelled",
                    Some("oauth.measured-succession.capture")=>!recovery && status=="captured-unusable",
                    Some("oauth.measured-succession.stage")=>status=="staged",
                    Some("oauth.measured-succession.recover")=>recovery && matches!(status.as_str(),"observed-fenced"|"observed-prepared"|"observed-claimed"
                        |"observed-captured"|"observed-staged"|"observed-cancelled"|"observed-committed"),
                    _=>false,
                };
                if exchange.as_ref()!=Some(exchange_id) || !valid{return Err("succession terminal observation differs from its actual phase".to_owned());}
                return Ok(reply);
            },
            _=>return Err("succession terminal driver received a browser redirect".to_owned()),
        }
    }
    Err("succession finite phase bound exceeded".to_owned())
}

fn begin(state:&GateState,owner:&Owner,helper:&mut broker::Owner,mut reply:Reply,deadline:u64)->Result<Reply,String>{
    let mut exchange:Option<String>=None;
    let mut provider:Option<String>=None;
    let mut last=String::new();
    let mut current_material:Option<String>=None;
    let mut current_purpose:Option<String>=None;
    let mut material_count=0usize;
    let mut seen=std::collections::BTreeSet::new();
    // 16*(INSPECT+MATERIAL-CLAIM+2*(CONTACT+FINISH)) + PREPARE,
    // plus the terminal response. This is a finite one-deadline protocol.
    for _ in 0..98 {
        owner.ingress.check(deadline)?; native_service_remaining(state)?;
        match reply {
            Reply::Prepared(prepared)=>{
                let phase=prepared.operation().strip_prefix("oauth.measured-succession.").ok_or("succession purpose differs")?.to_owned();
                let id=prepared.exchange_id()?.to_owned();
                let selected_provider=prepared.provider()?.to_owned();
                if exchange.as_ref().is_some_and(|old|old!=&id) || provider.as_ref().is_some_and(|old|old!=&selected_provider)
                    || !matches!((last.as_str(),phase.as_str()),("","inspect"|"prepare")|("inspect","material-claim")
                        |("material-claim","contact")|("contact","finish"|"contact"|"inspect"|"prepare")|("finish","contact"|"inspect"|"prepare")) {
                    return Err("succession finite historical phase changed".to_owned());
                }
                let material=prepared.material_id().map(str::to_owned);
                let purpose=prepared.token_purpose().map(str::to_owned);
                if !seen.insert((material.clone(),phase.clone(),purpose.clone())){return Err("succession phase cannot repeat".to_owned());}
                if phase=="inspect"{
                    let value=material.as_ref().ok_or("succession material absent")?;
                    if current_material.as_ref().is_some_and(|old|old>=value){return Err("succession material order differs".to_owned());}
                    material_count+=1;
                    if material_count>16{return Err("succession material capacity exceeded".to_owned());}
                    current_material=material; current_purpose=None;
                }else if phase=="prepare"{
                    if material.is_some(){return Err("succession fresh issue cannot use historical material".to_owned());}
                }else{
                    if material!=current_material{return Err("succession material owner changed".to_owned());}
                    if phase=="finish" && purpose!=current_purpose{return Err("succession contact purpose changed".to_owned());}
                    if phase=="contact"{current_purpose=purpose;}
                }
                last=phase; exchange=Some(id); provider=Some(selected_provider);
                reply=receipt(state,owner,helper,&prepared,deadline)?;
            },
            Reply::Redirect{ref exchange_id,ref location,..}=>{
                let url=Url::parse(location).map_err(|_|"succession redirect invalid")?;
                let matches=match provider.as_deref(){
                    Some("google")=>url.host_str()==Some("accounts.google.com") && url.path()=="/o/oauth2/v2/auth",
                    Some("x")=>url.host_str()==Some("twitter.com") && url.path()=="/i/oauth2/authorize",
                    _=>false,
                };
                if last!="prepare" || exchange.as_ref()!=Some(exchange_id) || !matches{return Err("succession redirect is not its completed fresh prepare".to_owned());}
                return Ok(reply);
            },
            Reply::Complete{ref exchange_id,ref status,..}=>{
                if last!="finish" || exchange.as_ref()!=Some(exchange_id) || !matches!(status.as_str(),"retirement-rejected"|"retirement-unknown"){
                    return Err("succession cleanup terminal differs".to_owned());
                }
                return Ok(reply);
            },
        }
    }
    Err("succession historical protocol bound exhausted without a terminal observation".to_owned())
}

fn browser(state:&GateState,owner:&mut Owner,mut request:Accepted)->Result<(),String>{
    if owner.poisoned{return Err("succession browser owner poisoned".to_owned());}
    if matches!(request.kind(),Kind::BeginPage) {
        let (page,csp)=native_oauth_browser_pages::succession_page(&owner.config.portal_origin)?;
        return request.respond("text/html; charset=utf-8",&page,None,&csp);
    }
    let _serial=state.native_oauth_serial.try_lock().map_err(|_|"another original OAuth operation is live")?;
    let relays=state.native_upstream_relays.as_ref().ok_or("succession fixed relays absent")?;
    // Local serialization is not family permission or a holder-drain proof.
    // The actual helper independently re-admits retained fence originals.
    let mut helper=state.native_secret_broker.as_ref().ok_or("succession helper absent")?.lock().map_err(|_|"succession helper poisoned")?;
    let result=(||{
        let deadline=request.deadline();
        let reply=helper.succession_browser(&request,relays)?;
        match reply {
            Reply::Prepared(prepared) if matches!(request.kind(),Kind::Begin)=>{
                let reply=begin(state,owner,&mut helper,Reply::Prepared(prepared),deadline)?;
                if let Reply::Complete{exchange_id,status,..}=reply {
                    let body=catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&json!({
                        "apiVersion":"catchplate.nativeOAuthSuccessionTerminalObservation/v1","exchangeId":exchange_id,"status":status}))?;
                    return request.respond("application/json",&body,None,"default-src 'none'; frame-ancestors 'none'");
                }
                let Reply::Redirect{exchange_id,location,name,value,expires}=reply else{return Err("succession begin has no terminal handoff".to_owned());};
                let epoch=u64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos()).map_err(|_|"succession cookie clock invalid")?;
                let max_age=expires.checked_sub(epoch).filter(|value|*value>=1_000_000_000).ok_or("succession original cookie expired")?/1_000_000_000;
                let cookie=format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}");
                let body=catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&json!({
                    "apiVersion":"catchplate.nativeOAuthSuccessionAuthorizationRedirect/v1","exchangeId":exchange_id,"location":location}))?;
                if body.len()>64*1024{return Err("succession redirect response bound".to_owned());}
                owner.ingress.check(deadline)?;
                request.respond("application/json",&body,Some(&cookie),"default-src 'none'; frame-ancestors 'none'")
            },
            reply if matches!(request.kind(),Kind::Callback)=>{
                let Reply::Complete{exchange_id,status,..}=complete(state,owner,&mut helper,reply,deadline,false)?
                    else{return Err("succession callback did not terminate".to_owned());};
                let page=native_oauth_browser_pages::terminal(&status,&owner.config.portal_origin)?;
                let cookie=format!("__Host-catchplate-native-oauth-{}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",exchange_id.replace('-',""));
                request.respond("text/html; charset=utf-8",&page,Some(&cookie),"default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            },
            _=>Err("succession native browser/helper phase mismatch".to_owned()),
        }
    })();
    if result.is_err(){owner.poisoned=true;} result
}

pub(super) fn initialize(state:&GateState)->Result<(),String>{
    let Some(owner)=&state.measured_succession else{return Ok(());};
    let mut owner=owner.lock().map_err(|_|"succession recovery owner poisoned")?;
    let _serial=state.native_oauth_serial.try_lock().map_err(|_|"succession recovery operation overlaps")?;
    let targets=owner.config.recovery_targets.clone();
    let result=(||{
        for id in targets {
            // This bounds only fresh observation/verification. The private
            // owner clips recovery to retained original grant/capture expiry.
            let deadline=broker::now()?.checked_add(30_000_000_000).ok_or("succession recovery interval overflow")?.min(owner.ingress.deadline());
            let original=post(state,&owner.recovery_endpoint,catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes(
                &json!({"apiVersion":"catchplate.nativeOAuthSuccessionRecoveryOriginalRequest/v1","authorizationId":id}))?,deadline)?;
            let relays=state.native_upstream_relays.as_ref().ok_or("succession recovery relays absent")?;
            let mut helper=state.native_secret_broker.as_ref().ok_or("succession recovery helper absent")?.lock().map_err(|_|"succession recovery helper poisoned")?;
            let reply=helper.recover_succession(&id,original,deadline,relays)?;
            complete(state,&owner,&mut helper,reply,deadline,true)?;
        }
        Ok(())
    })();
    if result.is_err(){owner.poisoned=true;} result
}

pub(super) fn start<'scope,'env:'scope>(scope:&'scope thread::Scope<'scope,'env>,state:Arc<GateState>,
    lifetime:Arc<NativeRuntimeLifetimeV1>)->Result<(),String>{
    let Some(owner)=&state.measured_succession else{return Ok(());};
    let (listener,ingress,port)={let mut held=owner.lock().map_err(|_|"succession browser owner poisoned")?;
        if held.poisoned{return Err("succession browser owner unavailable".to_owned());}
        (held.listener.take().ok_or("succession listener already consumed")?,Arc::clone(&held.ingress),held.config.browser_vsock_port)};
    let active:Arc<Mutex<Option<VsockShutdownV1>>>=Arc::new(Mutex::new(None));
    let stopping=Arc::clone(&lifetime); let shutdown=Arc::clone(&active);
    native_runtime_lifetime::spawn_task(scope,&lifetime,"native-oauth-succession-browser-cancellation".to_owned(),move||{
        while !stopping.is_stopped(){if !stopping.wait(Duration::from_millis(25))?{break;}}
        if let Some(stream)=shutdown.lock().map_err(|_|"succession shutdown owner poisoned")?.as_ref(){let _=stream.shutdown();}
        Ok(())
    })?;
    let serving=Arc::clone(&lifetime);
    native_runtime_lifetime::spawn_task(scope,&lifetime,"native-oauth-succession-browser".to_owned(),move||{
        while !serving.is_stopped(){
            serving.check()?;
            let stream=match listener.accept_cancellable(serving.deadline(),serving.stopped_flag()) {
                Ok(value)=>value,Err(_) if serving.is_stopped()=>return Ok(()),Err(_)=>return Err("succession browser accept failed".to_owned()),
            };
            let deadline=broker::now()?.checked_add(30_000_000_000).ok_or("succession browser interval overflow")?.min(serving.deadline());
            stream.verify_accepted_local_port(port,deadline).map_err(|_|"succession original listener changed")?;
            *active.lock().map_err(|_|"succession shutdown owner poisoned")?=Some(stream.shutdown_handle().map_err(|_|"succession shutdown original unavailable")?);
            let outcome=match Accepted::accept_succession(stream,Arc::clone(&ingress),deadline){
                Ok(request)=>{let mut owner=state.measured_succession.as_ref().ok_or("succession original owner lost")?.lock().map_err(|_|"succession browser owner poisoned")?;
                    browser(&state,&mut owner,request)},
                // The private helper/provider has not been entered. Malformed
                // inbound TLS/HTTP closes without constructing effect authority.
                Err(_)=>Ok(()),
            };
            active.lock().map_err(|_|"succession shutdown owner poisoned")?.take();
            if serving.is_stopped(){return Ok(());} outcome?;
        }
        Ok(())
    })
}
