//! Real single-owner continuation: C9 -> time -> closure -> one encrypted key
//! admission/NSM quote -> inspected proof clients -> actual bridge constructor.
use super::*;
use super::super::super::super as guest;
use inputs::original;

pub(super) fn run(mut prepared:Prepared,identity:driver_identity::Owner,
    observation:driver_identity::Observation,phase:PhaseTwo,mut rights:Vec<OwnedFd>)->Result<(),ShadowError>{
    prepared.check_final()?;identity.check()?;
    let mut resources=prepared.continuation.take().ok_or(ShadowError::BindingDrift)?;
    let operation=Operation::parse(&phase)?;
    // This final extra FD was created by the genuine root parent's fixed
    // Inspector::prepare_selected, not by the public operation descriptor list.
    let inspection=rights.pop().ok_or(ShadowError::BindingDrift)?;
    retrieval_peer::configure(inspection.as_fd())?;
    let peer=retrieval_peer::credentials(inspection.as_fd())?;
    require(peer.pid==prepared.parent && peer.uid==0 && peer.gid==0)?;
    retrieval_peer::same_process(retrieval_peer::peer_pidfd(inspection.as_fd())?.as_fd(),prepared.parent)?;
    let mut rights=operation.take(rights)?;
    let launch=original(&mut rights,"launch",operation.launch_pin(),0,0,32768)?;
    let launch_bytes=launch.read(32768).map_err(fail)?.to_vec();
    let (selected,service)=selection(&launch_bytes)?;
    let (time_pin,commitment_bridge,spool_bridge)=match service {
        SelectedService::ProofBridge(p)=>(p,false,false),SelectedService::CommitmentBridge(p)=>(p,true,false),
        SelectedService::SpoolBridge(p)=>(p,true,true),
        _=>return Err(ShadowError::BindingDrift),
    };
    require(selected.delivery_configuration.sha256==prepared.cold.config.delivery_configuration.sha256
        && selected.delivery_configuration.path==prepared.cold.config.delivery_configuration.path)?;
    let configuration=original(&mut rights,"c9-configuration",&selected.delivery_configuration,0,0,65536)?;
    let envelope=original(&mut rights,"c9-delivery",&selected.delivery,0,0,65536)?;
    let wire:guest::Envelope=exact(&envelope.read(65536).map_err(fail)?)?;
    let source:Originals=exact(&read_file(&phase.bundle,MAX_BUNDLE)?)?;
    require(envelope.read(65536).map_err(fail)?.as_slice()==source.delivery_original.as_bytes())?;
    // PhaseTwo already independently verified this exact C9 signed original,
    // same real boot/process/drop and unchanged window. Repeat bound work rules
    // before reading any credential or performing any NSM/network operation.
    let mut p=wire.payload;
    require(p.service_role==guest::Role::ProductionBridge && !p.credentials.is_empty()
        && p.credentials.len()<=guest::MAX_CREDENTIALS && !p.activation.is_empty()
        && p.activation.len()<=guest::MAX_ACTIVATION_FDS)?;
    let runtime_pin=Pin{path:p.runtime_config.path.clone(),sha256:p.runtime_config.sha256.clone()};
    let runtime=original(&mut rights,"c9-runtime",&runtime_pin,0,0,guest::MAX_CONFIG_BYTES)?;
    require(runtime.read(guest::MAX_CONFIG_BYTES).map_err(fail)?.as_slice()==source.runtime_original.as_bytes())?;
    let binding=GuestClosureBinding{configuration_sha256:p.configuration_sha256.clone(),
        delivery_sha256:selected.delivery.sha256.clone(),runtime_configuration_sha256:p.runtime_config.sha256.clone(),
        service_role:"production-bridge".into(),uid:p.uid,gid:p.gid,boot_id_base64url:p.boot_id_base64url.clone(),
        time_namespace_device:p.time_namespace_device,time_namespace_inode:p.time_namespace_inode,
        issued_at_boottime_ns:p.issued_at_boottime_ns.clone(),startup_deadline_boottime_ns:p.startup_deadline_boottime_ns.clone(),
        lifetime_deadline_boottime_ns:p.lifetime_deadline_boottime_ns.clone(),invocation_id:p.invocation_id.clone()};
    let parent=guest::Parent::from_retained(retrieval_peer::duplicate(prepared.channel.as_fd())?).map_err(fail)?;
    let startup=prepared.cold.startup;let lifetime=prepared.cold.lifetime;
    let retained=Arc::new(Retained{prepared,identity,observation,phase,guest:binding,operation,
        public_admission:std::sync::Mutex::new(None)});
    retained.check_startup()?;
    let mut total=0u64;let mut credentials=BTreeMap::new();
    for entry in std::mem::take(&mut p.credentials){
        guest::validate_credential_name(&entry.name).map_err(fail)?;
        total=total.checked_add(entry.length).ok_or(ShadowError::CounterOverflow)?;
        require(entry.length>0 && entry.length<=guest::MAX_CONFIG_BYTES as u64
            && total<=guest::MAX_TOTAL_CREDENTIAL_BYTES)?;
        let fd=rights.remove(&format!("credential:{}",entry.name)).ok_or(ShadowError::BindingDrift)?;
        let file=Original::from_parent_file(File::from(fd),p.uid,p.gid,entry.length as usize,entry.original.sha256.clone()).map_err(fail)?;
        require(credentials.insert(entry.name.clone(),(entry,file)).is_none())?;
    }
    let mut activation=BTreeMap::new();
    for (index,entry) in p.activation.iter().enumerate(){
        guest::validate_fd_name(&entry.name).map_err(fail)?;require(entry.fd==6+index as i32)?;
        let fd=rights.remove(&format!("activation:{}",entry.name)).ok_or(ShadowError::BindingDrift)?;
        let stat=guest::descriptor_stat(fd.as_fd()).map_err(fail)?;
        require((stat.st_dev,stat.st_ino,stat.st_mode,stat.st_uid,stat.st_gid)==(entry.device,entry.inode,entry.mode,entry.uid,entry.gid)
            && (stat.st_dev,stat.st_ino)!=parent.identity()
            && [libc::S_IFDIR,libc::S_IFSOCK].contains(&(stat.st_mode&libc::S_IFMT))
            && activation.insert(entry.name.clone(),fd).is_none())?;
    }
    let delivery_sha256=selected.delivery.sha256.clone();
    let owner=Arc::new(guest::Delivery{configuration,envelope,runtime,credentials,process:Process::capture().map_err(fail)?,
        parent,payload:p,delivery_sha256,startup,lifetime,ready:std::sync::atomic::AtomicBool::new(false),
        ordinary_lifetime:std::sync::Mutex::new(None),native_continuation:Some(Arc::clone(&retained))});
    let mut delivery=PreparedGuestServiceDelivery{owner,activation};
    delivery.owner.check_startup().map_err(fail)?;
    let lifetime=process::Lifetime::adopt_late(&delivery)?;
    let closure_original=original(&mut rights,"closure",&selected.closure,0,0,1024*1024)?;
    let closure_configuration:ClosureConfiguration=exact(&closure_original.read(1024*1024).map_err(fail)?)?;
    let prekey=PrekeyExecutable::from_late_owner(&closure_configuration,&delivery,&retained)?;
    let trust_original=original(&mut rights,"trust",&selected.trust,0,0,1024*1024)?;
    let time_original=original(&mut rights,"time",&selected.time_bootstrap,0,0,65536)?;
    let assignment_original=original(&mut rights,"assignment",&selected.assignment,0,0,4*1024*1024)?;
    let keys_original=original(&mut rights,"keys",&selected.keys,0,0,65536)?;
    let encrypted_original=original(&mut rights,"encrypted",&selected.encrypted_keys,0,0,65536)?;
    let admission_original=original(&mut rights,"admission",&selected.admission,0,0,65536)?;
    let time_grant=original(&mut rights,"time-grant",&time_pin,0,0,65536)?;
    let (path,digest)=selected.verifier_transport.retained_pin()?;
    let verifier=original(&mut rights,"verifier",&Pin{path:path.into(),sha256:digest.clone()},0,0,32768)?;
    require(rights.is_empty())?;
    let notice=canonical_json_bytes(&serde_json::json!({"apiVersion":"serverware.nativeShadowDriverPhaseTwoRetained/v1",
        "observationSha256":Sha256Digest::compute(&canonical_json_bytes(&retained.observation)?),
        "scopeSha256":Sha256Digest::compute(retained.phase.scope())}))?;
    require(retrieval_peer::send(retained.prepared.channel.as_fd(),&notice,&[])?)?;
    let time_nsm=resources.time.take().ok_or(ShadowError::BindingDrift)?;
    let (trust,time)=authority::Trust::open_late(trust_original,time_original,&delivery,&prekey,time_nsm)?;
    let assignment=trust.verify_assignment(&assignment_original.read(4*1024*1024).map_err(fail)?)?;
    let closure=PreparedNativeCustodyClosure::bind_late(closure_configuration,&assignment,&trust,time.as_ref(),&delivery,&retained,&prekey)?;
    drop(prekey);
    let settings=&retained.operation.production;
    let native_configuration=ProductionCustodyConfiguration::from_native_closure_with_settlement_authority(
        &assignment,&trust,time.as_ref(),Sha256Digest::compute(retained.guest.invocation_id.as_bytes()),
        Sha256Digest::compute(&decode::<16>(&retained.guest.boot_id_base64url)?),closure.clone(),
        settings.signer_backend_sha256.clone(),settings.persistence_backend_sha256.clone(),settings.retrieval_backend_sha256.clone(),
        settings.dispatcher_protocol_set_sha256.clone(),retained.observation.driver.clone(),settings.maximum_rpc_nanos,
        settings.cleanup_reserve_nanos,settings.maximum_in_flight_calls,settings.maximum_async_durability_nanos)?;
    require(native_configuration.production_configuration_binding_sha256()==&settings.expected_configuration_binding_sha256)?;
    let keys_configuration:NativeCustodyKeyConfiguration=exact(&keys_original.read(65536).map_err(fail)?)?;
    let encrypted_configuration:NativeShadowEncryptedKeysConfiguration=exact(&encrypted_original.read(65536).map_err(fail)?)?;
    // The bridge itself never acquires the endpoint's request-commitment HMAC.
    require(!encrypted_configuration.has_commitment())?;
    let authorization:admission::Authorization=exact(&admission_original.read(65536).map_err(fail)?)?;
    let mut keys=PreparedNativeCustodyKeys::open_encrypted_late(keys_configuration,encrypted_configuration,&assignment,&trust,time.as_ref(),&delivery,resources)?;
    keys.prepare_late_verifier(verifier,&trust,time.as_ref())?;
    let context=process::ContextOwner::bind(&delivery,closure.clone())?;
    let full=retained.bridge_admission_selected();
    let mut keys=if full {keys.bind_bridge_admission(authorization,context,&closure,native_configuration.clone(),&trust,time.as_ref())?}
        else{keys.bind_admission(authorization,context,&closure,&trust,time.as_ref())?};
    keys.admit_external(&trust,time.as_ref())?;
    // Only explicit cold v3 receives an activated configuration from the actual
    // combined-purpose owner after both independent signatures were verified.
    let native_configuration=if full {keys.admitted_bridge_configuration(&trust,time.as_ref())?.clone()}
        else{native_configuration};
    retained.publish_public_admission(&keys,&closure_original,&assignment_original,&trust,time.as_ref())?;
    let (proof_client,time_grant)=proof_client::Prepared::open_late(&mut delivery,inspection,time_grant,commitment_bridge,spool_bridge)?;
    let bridge_activation=std::sync::Mutex::new(Some(std::mem::take(&mut delivery.activation)));
    let owner=AdmittedGuest{_delivery:delivery,lifetime,keys,trust,time,launch,launch_bytes,
        originals:vec![assignment_original,closure_original,keys_original,encrypted_original,admission_original],
        retrieval:None,activation:None,persistence:None,retrieval_client:None,bridge_selected:true,trusted_time:None,
        proof_client:Some(proof_client),generation:None,time_grant:Some(time_grant),proof_bridge:true,
        commit_request:None,commitment_bridge,spool_bridge,ledger_retrieval:None,spool_signer:None,
        bridge_activation,native_configuration:Some(native_configuration)};
    owner.check()?;
    owner.time_grant.as_ref().ok_or(ShadowError::BindingDrift)?.check(&owner.keys,&owner.time_endpoint()?,&owner.trust,owner.time.as_ref())?;
    owner.hold()
}
