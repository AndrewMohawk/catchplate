//! Actual Setup-selected native browser and same-helper issuance lifetime. Every
//! contact follows a genuine definite writer receipt; recovery uses only the
//! fixed encrypted acquisition route and never re-enters the token POST.
use super::*;
use serverware_decision_gate::native_oauth_setup_v1::{self as wire, BrowserTls, Configuration, Prepared, Reply};
use serverware_decision_gate::native_oauth_browser_v1::{Accepted,Kind};
use serverware_decision_gate::native_secret_broker_v1 as broker;
use serverware_decision_gate::enclave_vsock_v1::VsockShutdownV1;
use std::collections::BTreeSet;

pub(super) struct Owner {
    config:Configuration, endpoint:String, recovery_endpoint:String, ingress:Arc<BrowserTls>,
    listener:Option<VsockListenerV1>, poisoned:bool,
}

pub(super) fn prepare(config:Configuration,inputs:&GateStateInputs,actual:&mut broker::Owner,
    identity:&mut EnclaveRuntimeIdentityV1,signer:&CustodyResponseProofSigner,binary:&str,deadline:u64)->Result<Owner,String>{
    config.validate()?;
    if inputs.server_instance_id.as_deref()!=Some(config.instance_id.as_str())
        || inputs.credential_currentness.as_ref().map(|v|v.deployment_id.as_str())!=Some(config.deployment_id.as_str())
        || !matches!(&inputs.service_tokens,native_service_tokens::Source::Installed) {
        return Err("Setup issuance requires actual encrypted service, instance and currentness owners".to_owned());
    }
    signer.transport.verify_native_identity(identity,deadline)?;
    let mut endpoint=Url::parse(inputs.credential_lease_url.as_deref().ok_or("Setup issuance CP origin absent")?)
        .map_err(|_|"Setup issuance CP origin invalid")?;
    if endpoint.scheme()!="https" || endpoint.path()!="/api/data-plane/credential-leases"
        || endpoint.query().is_some() || endpoint.fragment().is_some() || !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err("Setup issuance requires the original fixed credential service origin".to_owned());
    }
    let ingress=identity.prepare_browser_ingress(&config.callback_origin,OffsetDateTime::now_utc(),deadline)?;
    let listener=VsockListenerV1::bind(config.browser_vsock_port,2,deadline)
        .map_err(|_|"native browser fixed-parent listener unavailable")?;
    actual.configure_setup(config.clone(),Arc::clone(&ingress),identity,&signer.boot_id,&signer.key_id,
        &signer.control_plane_response_signing_key_id,binary,deadline)?;
    endpoint.set_path("/api/data-plane/oauth-setup-issuance"); let issuance=endpoint.to_string();
    endpoint.set_path("/api/data-plane/oauth-setup-issuance/original");
    Ok(Owner{config,endpoint:issuance,recovery_endpoint:endpoint.to_string(),ingress,listener:Some(listener),poisoned:false})
}

fn evidence(state:&GateState,prepared:&Prepared,deadline:u64)->Result<Value,String>{
    native_service_remaining(state)?;
    let ResponseProofSigner::Custody(signer)=&state.response_proof_signer else{return Err("Setup native signer absent".to_owned());};
    let mut held=state.mitm_authority.as_ref().ok_or("Setup actual CA absent")?.lock().map_err(|_|"Setup identity owner poisoned")?;
    let MitmAuthority::Native(identity)=&mut *held else{return Err("Setup issuance refuses imported CA".to_owned());};
    signer.transport.setup_evidence(identity,prepared,&state.binary_digest,deadline)
}

fn post(state:&GateState,url:&str,body:Vec<u8>,deadline:u64)->Result<Value,String>{
    native_service_remaining(state)?;
    let remaining=deadline.checked_sub(broker::now()?).filter(|v|*v>0).ok_or("Setup request interval expired")?;
    let mut response=state.credential_lease_client.post(url).header("X-Serverware-Data-Plane-Token",
        state.credential_lease_token.as_deref().ok_or("Setup service token absent")?)
        .header("Content-Type","application/json").body(body).timeout(Duration::from_nanos(remaining))
        .send().map_err(|_|"Setup writer response uncertain; no resubmission")?;
    if !response.status().is_success(){return Err("Setup writer refused; no fallback or retry".to_owned());}
    let raw=read_bounded_control_plane_response_body(&mut response,8*1024*1024,"native Setup issuance")?;
    if broker::now()?>=deadline{return Err("Setup writer response arrived after original interval".to_owned());}
    serverware_decision_gate::native_oauth_refresh_v1::response_document(&raw)
}

fn complete(state:&GateState,owner:&Owner,helper:&mut broker::Owner,mut reply:Reply,deadline:u64,recovery:bool)->Result<Reply,String>{
    let relays=state.native_upstream_relays.as_ref().ok_or("Setup relays absent")?;
    let mut attempted=BTreeSet::new(); let mut exchange=None;
    loop {
        owner.ingress.check(deadline)?; native_service_remaining(state)?;
        match reply {
            Reply::Prepared(prepared)=>{
                let id=prepared.exchange_id()?.to_owned();
                if exchange.as_ref().is_some_and(|old|old!=&id) || !attempted.insert(prepared.operation().to_owned())
                    || attempted.len()>4 || prepared.operation()=="oauth.measured-setup.prepare"
                    || recovery && matches!(prepared.operation(),"oauth.measured-setup.claim"|"oauth.measured-setup.capture"|"oauth.measured-setup.cancel") {
                    return Err("Setup issuance cannot repeat a phase, change owner or replay token contact".to_owned());
                }
                exchange=Some(id);
                let body=serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&prepared.wire(evidence(state,&prepared,deadline)?)?)?;
                let mut originals=post(state,&owner.endpoint,body,deadline)?;
                if originals["apiVersion"]!=wire::HTTP_RESPONSE || originals.as_object().is_none_or(|v|v.len()!=3
                    || !["apiVersion","requestOriginal","responseOriginal"].iter().all(|name|v.contains_key(*name))) {
                    return Err("Setup writer originals differ".to_owned());
                }
                originals.as_object_mut().ok_or("Setup originals object")?.remove("apiVersion");
                // Helper verifies actual signer/config/input/commit originals
                // before contacting, acknowledging capture or opening recovery.
                reply=helper.setup_receipt(originals,&prepared,deadline,relays)?;
            },
            Reply::Complete{ref exchange_id,ref status,..}=>{
                if exchange.as_ref()!=Some(exchange_id) || !recovery && status=="observed-staged" {
                    return Err("Setup terminal observation differs from actual operation".to_owned());
                }
                return Ok(reply);
            },
            _=>return Err("Setup effect loop received a browser navigation phase".to_owned()),
        }
    }
}

fn browser(state:&GateState,owner:&mut Owner,mut request:Accepted)->Result<(),String>{
    if owner.poisoned{return Err("native browser owner poisoned".to_owned());}
    if matches!(request.kind(),Kind::BeginPage|Kind::AuthorizePage) {
        let (page,csp)=native_oauth_browser_pages::setup_page(matches!(request.kind(),Kind::AuthorizePage),&owner.config.portal_origin)?;
        return request.respond("text/html; charset=utf-8",&page,None,&csp);
    }
    let _serial=state.native_oauth_serial.try_lock().map_err(|_|"another original OAuth operation is live")?;
    let relays=state.native_upstream_relays.as_ref().ok_or("Setup fixed relays absent")?;
    // No barrier is acquired by Setup issuance. Holding the actual helper
    // through its one callback prevents unrelated credential/refresh commands
    // from interleaving with its private TLS and capture protocol.
    let mut helper=state.native_secret_broker.as_ref().ok_or("Setup helper absent")?.lock().map_err(|_|"Setup helper poisoned")?;
    let result=(||{
        let deadline=request.deadline();
        let reply=helper.setup_browser(&request,relays)?;
        match reply {
            Reply::Prepared(prepared) if matches!(request.kind(),Kind::Draft)=>{
                if prepared.operation()!="oauth.measured-setup.prepare" {return Err("draft yielded an effect phase".to_owned());}
                let public=prepared.wire(evidence(state,&prepared,deadline)?)?;
                let body=serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&json!({
                    "apiVersion":"serverware.nativeOAuthSetupDraft/v1","arguments":public["arguments"],
                    "callbackOrigin":owner.config.callback_origin,"portalOrigin":owner.config.portal_origin}))?;
                if body.len()>512*1024{return Err("native draft browser bound exceeded".to_owned());}
                let Reply::DraftCookie{exchange_id,name,value,expires}=helper.setup_draft_delivered(&prepared,deadline,relays)?
                    else{return Err("draft lacked same-owner cookie".to_owned());};
                if exchange_id!=prepared.exchange_id()? {return Err("native cookie exchange differs".to_owned());}
                let epoch=u64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos()).map_err(|_|"native cookie clock invalid")?;
                let max_age=expires.checked_sub(epoch).filter(|v|*v>0).ok_or("native cookie expired")?/1_000_000_000;
                let cookie=format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}");
                request.respond("application/json",&body,Some(&cookie),"default-src 'none'; frame-ancestors 'none'")
            },
            Reply::Redirect{exchange_id,location} if matches!(request.kind(),Kind::Authorize)=>{
                let body=serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&json!({
                    "apiVersion":"serverware.nativeOAuthSetupAuthorizationRedirect/v1","exchangeId":exchange_id,"location":location}))?;
                request.respond("application/json",&body,None,"default-src 'none'; frame-ancestors 'none'")
            },
            reply if matches!(request.kind(),Kind::Callback)=>{
                let Reply::Complete{exchange_id,status,..}=complete(state,owner,&mut helper,reply,deadline,false)?
                    else{return Err("callback did not terminate".to_owned());};
                let page=native_oauth_browser_pages::terminal(&status,&owner.config.portal_origin)?;
                let cookie=format!("__Host-serverware-native-oauth-{}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",exchange_id.replace('-',""));
                request.respond("text/html; charset=utf-8",&page,Some(&cookie),"default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            },
            _=>Err("native browser/helper phase mismatch".to_owned()),
        }
    })();
    if result.is_err(){owner.poisoned=true;} result
}

pub(super) fn initialize(state:&GateState)->Result<(),String>{
    let Some(owner)=&state.measured_setup else{return Ok(());};
    let mut owner=owner.lock().map_err(|_|"Setup recovery owner poisoned")?;
    let _serial=state.native_oauth_serial.try_lock().map_err(|_|"Setup recovery operation overlaps")?;
    let targets=owner.config.recovery_targets.clone();
    let result=(||{
        for id in targets {
            let deadline=broker::now()?.checked_add(30_000_000_000).ok_or("Setup recovery interval overflow")?.min(owner.ingress.deadline());
            let original=post(state,&owner.recovery_endpoint,serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes(
                &json!({"apiVersion":"serverware.nativeOAuthSetupRecoveryOriginalRequest/v1","exchangeId":id}))?,deadline)?;
            let relays=state.native_upstream_relays.as_ref().ok_or("Setup recovery fixed relays absent")?;
            let mut helper=state.native_secret_broker.as_ref().ok_or("Setup recovery helper absent")?.lock().map_err(|_|"Setup recovery helper poisoned")?;
            let reply=helper.recover_setup(&id,original,deadline,relays)?;
            complete(state,&owner,&mut helper,reply,deadline,true)?;
        }
        Ok(())
    })();
    if result.is_err(){owner.poisoned=true;} result
}

pub(super) fn start<'scope,'env:'scope>(scope:&'scope thread::Scope<'scope,'env>,state:Arc<GateState>,
    lifetime:Arc<NativeRuntimeLifetimeV1>)->Result<(),String>{
    let Some(owner)=&state.measured_setup else{return Ok(());};
    let (listener,ingress,port)={let mut held=owner.lock().map_err(|_|"native browser owner poisoned")?;
        if held.poisoned{return Err("native browser owner unavailable".to_owned());}
        (held.listener.take().ok_or("native browser listener already consumed")?,Arc::clone(&held.ingress),held.config.browser_vsock_port)};
    let active:Arc<Mutex<Option<VsockShutdownV1>>>=Arc::new(Mutex::new(None));
    let stopping=Arc::clone(&lifetime); let shutdown=Arc::clone(&active);
    native_runtime_lifetime::spawn_task(scope,&lifetime,"native-oauth-setup-browser-cancellation".to_owned(),move||{
        while !stopping.is_stopped(){if !stopping.wait(Duration::from_millis(25))?{break;}}
        if let Some(stream)=shutdown.lock().map_err(|_|"browser shutdown owner poisoned")?.as_ref(){let _=stream.shutdown();}
        Ok(())
    })?;
    let serving=Arc::clone(&lifetime);
    native_runtime_lifetime::spawn_task(scope,&lifetime,"native-oauth-setup-browser".to_owned(),move||{
        while !serving.is_stopped(){
            serving.check()?;
            let stream=match listener.accept_cancellable(serving.deadline(),serving.stopped_flag()) {
                Ok(value)=>value,Err(_) if serving.is_stopped()=>return Ok(()),Err(_)=>return Err("native browser accept failed".to_owned()),
            };
            let deadline=broker::now()?.checked_add(30_000_000_000).ok_or("native browser interval overflow")?.min(serving.deadline());
            stream.verify_accepted_local_port(port,deadline).map_err(|_|"browser original listener changed")?;
            *active.lock().map_err(|_|"browser shutdown owner poisoned")?=Some(stream.shutdown_handle().map_err(|_|"browser shutdown original unavailable")?);
            let outcome=match Accepted::accept_setup(stream,Arc::clone(&ingress),deadline){
                Ok(request)=>{let mut owner=state.measured_setup.as_ref().ok_or("browser original owner lost")?.lock().map_err(|_|"browser owner poisoned")?;
                    browser(&state,&mut owner,request)},
                // No private helper or provider was entered. Malformed TLS or
                // HTTP is closed locally and cannot manufacture an effect.
                Err(_)=>Ok(()),
            };
            active.lock().map_err(|_|"browser shutdown owner poisoned")?.take();
            if serving.is_stopped(){return Ok(());} outcome?;
        }
        Ok(())
    })
}
