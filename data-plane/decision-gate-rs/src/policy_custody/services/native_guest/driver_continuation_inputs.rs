//! Purpose-fixed descriptor transfer. Old endpoint framing remains unchanged.
use super::*;
use std::mem::{size_of,size_of_val,zeroed};
use super::super::super::super as guest;
const MAX_RIGHTS:usize=96;

#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) struct DescriptorOriginal {
    name:String,device:u64,inode:u64,mode:u32,uid:u32,gid:u32,length:u64,
}
impl DescriptorOriginal {
    fn require(&self,fd:BorrowedFd<'_>)->Result<(),ShadowError>{
        let mut s:libc::stat=unsafe{zeroed()};
        require(unsafe{libc::fstat(fd.as_raw_fd(),&mut s)}==0
            && (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size as u64)
                ==(self.device,self.inode,self.mode,self.uid,self.gid,self.length))
    }
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Production {
    pub(super) signer_backend_sha256:Sha256Digest,pub(super) persistence_backend_sha256:Sha256Digest,
    pub(super) retrieval_backend_sha256:Sha256Digest,pub(super) dispatcher_protocol_set_sha256:Sha256Digest,
    pub(super) maximum_rpc_nanos:u64,pub(super) cleanup_reserve_nanos:u64,
    pub(super) maximum_in_flight_calls:u16,pub(super) maximum_async_durability_nanos:u64,
    pub(super) expected_configuration_binding_sha256:Sha256Digest,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) struct Operation {
    api_version:String,launch:Pin,descriptors:Vec<DescriptorOriginal>,pub(super) production:Production,
}
impl Operation {
    pub(super) fn parse(phase:&PhaseTwo)->Result<Self,ShadowError>{
        phase.check()?;let signed:SignedScope=exact(phase.scope())?;
        require(signed.payload.api_version=="serverware.nativeShadowDriverScope/v2")?;
        let value=signed.payload.operation.ok_or(ShadowError::BindingDrift)?;
        require(value.api_version=="serverware.nativeShadowDriverOperation/v1"
            && !value.descriptors.is_empty() && value.descriptors.len()<=MAX_RIGHTS-2
            && value.descriptors.windows(2).all(|p|p[0].name<p[1].name))?;
        Ok(value)
    }
    pub(super) fn take(&self,rights:Vec<OwnedFd>)->Result<BTreeMap<String,OwnedFd>,ShadowError>{
        require(rights.len()==self.descriptors.len())?;
        let mut result=BTreeMap::new();let mut identities=BTreeSet::new();
        for (record,fd) in self.descriptors.iter().zip(rights) {
            record.require(fd.as_fd())?;
            require(identities.insert((record.device,record.inode))
                && result.insert(record.name.clone(),fd).is_none())?;
        }
        Ok(result)
    }
    pub(super) fn launch_pin(&self)->&Pin{&self.launch}
}
pub(super) fn original(rights:&mut BTreeMap<String,OwnedFd>,name:&str,pin:&Pin,
    uid:u32,gid:u32,bound:usize)->Result<Original,ShadowError>{
    let fd=rights.remove(name).ok_or(ShadowError::BindingDrift)?;
    let owner=Original::from_parent_file(File::from(fd),uid,gid,bound,pin.sha256.clone()).map_err(fail)?;
    owner.read(bound).map_err(fail)?;Ok(owner)
}
fn parent_file(rights:&BTreeMap<String,OwnedFd>,name:&str,pin:&Pin,uid:u32,gid:u32,bound:usize)
    ->Result<Vec<u8>,ShadowError>{
    let actual=Original::open(&pin.path,uid,gid,bound,pin.sha256.clone()).map_err(fail)?;
    let fd=rights.get(name).ok_or(ShadowError::BindingDrift)?;
    let mut s:libc::stat=unsafe{zeroed()};
    require(unsafe{libc::fstat(fd.as_raw_fd(),&mut s)}==0 && (s.st_dev,s.st_ino)==actual.identity())?;
    let copy=Original::from_parent_file(File::from(retrieval_peer::duplicate(fd.as_fd())?),uid,gid,bound,pin.sha256.clone()).map_err(fail)?;
    let bytes=actual.read(bound).map_err(fail)?.to_vec();
    require(copy.read(bound).map_err(fail)?.as_slice()==bytes.as_slice())?;Ok(bytes)
}
pub(super) fn verify_parent(cold:&Cold,phase:&PhaseTwo,rights:&[OwnedFd])->Result<(),ShadowError>{
    cold.check()?;let operation=Operation::parse(phase)?;
    let duplicates=rights.iter().map(|v|retrieval_peer::duplicate(v.as_fd())).collect::<Result<Vec<_>,_>>()?;
    let rights=operation.take(duplicates)?;
    let raw=parent_file(&rights,"launch",&operation.launch,0,0,32768)?;
    let (launch,service)=selection(&raw)?;
    let time_grant=match service {SelectedService::ProofBridge(p)|SelectedService::CommitmentBridge(p)=>p,
        _=>return Err(ShadowError::BindingDrift)};
    require(launch.delivery_configuration.sha256==cold.config.delivery_configuration.sha256
        && launch.delivery_configuration.path==cold.config.delivery_configuration.path)?;
    parent_file(&rights,"c9-configuration",&launch.delivery_configuration,0,0,65536)?;
    let delivery_raw=parent_file(&rights,"c9-delivery",&launch.delivery,0,0,65536)?;
    let original:Originals=exact(&read_file(&phase.bundle,MAX_BUNDLE)?)?;
    require(delivery_raw==original.delivery_original.as_bytes())?;
    let envelope:guest::Envelope=exact(&delivery_raw)?;let p=&envelope.payload;
    require(p.service_role==guest::Role::ProductionBridge && !p.credentials.is_empty()
        && p.credentials.len()<=guest::MAX_CREDENTIALS && !p.activation.is_empty()
        && p.activation.len()<=guest::MAX_ACTIVATION_FDS)?;
    let mut total=0u64;
    for entry in &p.credentials {
        guest::validate_credential_name(&entry.name).map_err(fail)?;
        total=total.checked_add(entry.length).ok_or(ShadowError::CounterOverflow)?;
        require(entry.length>0 && entry.length<=guest::MAX_CONFIG_BYTES as u64
            && total<=guest::MAX_TOTAL_CREDENTIAL_BYTES)?;
    }
    let runtime_pin=Pin{path:p.runtime_config.path.clone(),sha256:p.runtime_config.sha256.clone()};
    require(parent_file(&rights,"c9-runtime",&runtime_pin,0,0,guest::MAX_CONFIG_BYTES)?==original.runtime_original.as_bytes())?;
    let pins=[("trust",&launch.trust,1024*1024),("time",&launch.time_bootstrap,65536),
        ("assignment",&launch.assignment,4*1024*1024),("closure",&launch.closure,1024*1024),
        ("keys",&launch.keys,65536),("encrypted",&launch.encrypted_keys,65536),
        ("admission",&launch.admission,65536),("time-grant",&time_grant,65536)];
    let mut names=BTreeSet::from(["launch".to_owned(),"c9-configuration".into(),"c9-delivery".into(),"c9-runtime".into(),"verifier".into()]);
    for (name,pin,bound) in pins {parent_file(&rights,name,pin,0,0,bound)?;names.insert(name.into());}
    let (path,digest)=launch.verifier_transport.retained_pin()?;
    let pin=Pin{path:path.into(),sha256:digest.clone()};
    parent_file(&rights,"verifier",&pin,0,0,32768)?;
    for entry in &p.credentials {
        let name=format!("credential:{}",entry.name);names.insert(name.clone());
        // Root only opens/compares credential originals. Contents are consumed
        // by the assigned post-drop owner, not read to populate a proof DTO.
        let original=Original::open(&entry.original.path,p.uid,p.gid,entry.length as usize,entry.original.sha256.clone()).map_err(fail)?;
        let fd=rights.get(&name).ok_or(ShadowError::BindingDrift)?;let mut stat:libc::stat=unsafe{zeroed()};
        require(unsafe{libc::fstat(fd.as_raw_fd(),&mut stat)}==0 && (stat.st_dev,stat.st_ino)==original.identity())?;
        Original::from_parent_file(File::from(retrieval_peer::duplicate(fd.as_fd())?),p.uid,p.gid,
            entry.length as usize,entry.original.sha256.clone()).map_err(fail)?.check().map_err(fail)?;
    }
    for entry in &p.activation {
        guest::validate_fd_name(&entry.name).map_err(fail)?;
        let name=format!("activation:{}",entry.name);names.insert(name.clone());
        let fd=rights.get(&name).ok_or(ShadowError::BindingDrift)?;let mut stat:libc::stat=unsafe{zeroed()};
        require(unsafe{libc::fstat(fd.as_raw_fd(),&mut stat)}==0
            && (stat.st_dev,stat.st_ino,stat.st_mode,stat.st_uid,stat.st_gid)==(entry.device,entry.inode,entry.mode,entry.uid,entry.gid))?;
    }
    require(names==rights.keys().cloned().collect())?;cold.check()
}

pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) struct ParentInputs {
    files:guest::FileAdmission,inspector:proof_client::Inspector,
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) channel:OwnedFd,
}
impl ParentInputs {
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) fn open(cold:&Cold,phase:&PhaseTwo,rights:&[OwnedFd])->Result<Self,ShadowError>{
        verify_parent(cold,phase,rights)?;
        let operation=Operation::parse(phase)?;
        let owned=operation.take(rights.iter().map(|v|retrieval_peer::duplicate(v.as_fd())).collect::<Result<Vec<_>,_>>()?)?;
        let launch_raw=parent_file(&owned,"launch",&operation.launch,0,0,32768)?;
        let (launch,selection)=selection(&launch_raw)?;
        let commitment=matches!(selection,SelectedService::CommitmentBridge(_));
        let files=guest::admit_files(&launch.delivery_configuration.path,launch.delivery_configuration.sha256,
            &launch.delivery.path,launch.delivery.sha256).map_err(fail)?;
        let activation=files.payload.activation.iter().map(|entry|{
            let fd=owned.get(&format!("activation:{}",entry.name)).ok_or(ShadowError::BindingDrift)?;
            Ok((entry.name.clone(),retrieval_peer::duplicate(fd.as_fd())?))
        }).collect::<Result<BTreeMap<_,_>,ShadowError>>()?;
        let (inspector,channel)=proof_client::Inspector::prepare_selected(&files,&activation,commitment)?;
        Ok(Self{files,inspector,channel})
    }
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) fn progress(&mut self,child:&super::super::super::parent::child::Child)->Result<(),ShadowError>{
        self.inspector.progress(child,&self.files)
    }
}

/// Fixed successor-only bound. Ordinary endpoint send/receive stay unchanged.
pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) fn receive_operational(fd:BorrowedFd<'_>,maximum:usize)->Result<Option<retrieval_peer::Packet>,ShadowError>{
    require(maximum>0 && maximum<=65536)?;
    let mut bytes=vec![0;maximum];let mut control=[0usize;80];
    let mut iov=libc::iovec{iov_base:bytes.as_mut_ptr().cast(),iov_len:bytes.len()};
    let mut header:libc::msghdr=unsafe{zeroed()};header.msg_iov=&mut iov;header.msg_iovlen=1;
    header.msg_control=control.as_mut_ptr().cast();header.msg_controllen=size_of_val(&control);
    let count=unsafe{libc::recvmsg(fd.as_raw_fd(),&mut header,libc::MSG_DONTWAIT|libc::MSG_CMSG_CLOEXEC)};
    if count<0 {let error=std::io::Error::last_os_error();
        if matches!(error.raw_os_error(),Some(libc::EAGAIN)|Some(libc::EINTR)){return Ok(None);}return Err(fail(error));}
    let mut valid=count>0 && header.msg_flags&(libc::MSG_TRUNC|libc::MSG_CTRUNC)==0;
    let mut credentials=None;let mut pidfd=None;let mut rights=Vec::new();
    let mut item=unsafe{libc::CMSG_FIRSTHDR(&header)};
    while !item.is_null(){let c=unsafe{&*item};let base=unsafe{libc::CMSG_LEN(0)} as usize;
        if c.cmsg_len<base{valid=false;break;}let length=c.cmsg_len-base;let data=unsafe{libc::CMSG_DATA(item)};
        if c.cmsg_level==libc::SOL_SOCKET && (c.cmsg_type==libc::SCM_RIGHTS || c.cmsg_type==4){
            valid &= length%size_of::<i32>()==0;
            for i in 0..length/size_of::<i32>(){let raw=unsafe{std::ptr::read_unaligned(data.add(i*size_of::<i32>()).cast::<i32>())};
                if raw<0{valid=false;continue;}let owned=unsafe{OwnedFd::from_raw_fd(raw)};
                if c.cmsg_type==4{if pidfd.is_some() || length!=size_of::<i32>(){valid=false;}else{pidfd=Some(owned);}}
                else{rights.push(owned);}}
        }else if c.cmsg_level==libc::SOL_SOCKET && c.cmsg_type==libc::SCM_CREDENTIALS
            && length==size_of::<libc::ucred>() && credentials.is_none(){credentials=Some(unsafe{std::ptr::read_unaligned(data.cast::<libc::ucred>())});}
        else{valid=false;}item=unsafe{libc::CMSG_NXTHDR(&header,item)};
    }
    require(valid && !rights.is_empty() && rights.len()<=MAX_RIGHTS)?;bytes.truncate(count as usize);
    Ok(Some(retrieval_peer::Packet{bytes,credentials:credentials.ok_or(ShadowError::BindingDrift)?,
        pidfd:pidfd.ok_or(ShadowError::BindingDrift)?,rights}))
}
pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) fn send_operational(fd:BorrowedFd<'_>,bytes:&[u8],rights:&[BorrowedFd<'_>])->Result<(),ShadowError>{
    require(!rights.is_empty() && rights.len()<=MAX_RIGHTS && !bytes.is_empty() && bytes.len()<=65536)?;
    let mut iov=libc::iovec{iov_base:bytes.as_ptr() as *mut _,iov_len:bytes.len()};
    let mut header:libc::msghdr=unsafe{zeroed()};header.msg_iov=&mut iov;header.msg_iovlen=1;
    let mut control=[0usize;64];header.msg_control=control.as_mut_ptr().cast();
    header.msg_controllen=unsafe{libc::CMSG_SPACE((size_of::<i32>()*rights.len()) as u32)} as usize;
    let item=unsafe{libc::CMSG_FIRSTHDR(&header)};
    unsafe{(*item).cmsg_level=libc::SOL_SOCKET;(*item).cmsg_type=libc::SCM_RIGHTS;
        (*item).cmsg_len=libc::CMSG_LEN((size_of::<i32>()*rights.len()) as u32) as usize;
        for (i,fd) in rights.iter().enumerate(){std::ptr::write_unaligned(libc::CMSG_DATA(item).cast::<i32>().add(i),fd.as_raw_fd());}}
    // Once attempted, no EINTR/EAGAIN retry and no manufactured ACK.
    require(unsafe{libc::sendmsg(fd.as_raw_fd(),&header,libc::MSG_DONTWAIT|libc::MSG_NOSIGNAL)}==bytes.len() as isize)
}
