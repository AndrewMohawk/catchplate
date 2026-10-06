//! Fixed private worker entry. The caller cannot choose an executable or UID.
use super::{image::Sealed,identity,job,transport as ipc,wire::{self,require,now}};
use std::{fs::File,os::fd::AsRawFd,os::unix::fs::FileExt};

/// Invoked only by the fixed image. Successful initialization describes this
/// owned process, not any generation/TEE/verifier/publication authorization.
pub fn run()->Result<(),String> {
    require(std::env::args_os().count()==1 && std::env::vars_os().next().is_none())?;
    let publication_descriptors=unsafe {libc::fcntl(9,libc::F_GETFD)}==0;
    let runtime_descriptors=unsafe {libc::fcntl(12,libc::F_GETFD)}==0;
    for fd in 0..128 {
        let flags=unsafe {libc::fcntl(fd,libc::F_GETFD)};
        require(if matches!(fd,0|1|2|3|5|6|7|8) || publication_descriptors && matches!(fd,9|10|11)
            || runtime_descriptors && matches!(fd,12|13|14)
            {flags==0} else {flags<0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EBADF)})?;
    }
    // Fixed null stdio exists across exec/startup, never a parent log pipe.
    // Close it before processing any private request or command output.
    for fd in [0,1,2] {
        let mut m:libc::stat=unsafe {std::mem::zeroed()};
        require(unsafe {libc::fstat(fd,&mut m)}==0 && m.st_mode&libc::S_IFMT==libc::S_IFCHR
            && libc::major(m.st_rdev)==1 && libc::minor(m.st_rdev)==3 && m.st_uid==0 && m.st_gid==0)?;
        require(unsafe {libc::close(fd)}==0)?;
    }
    let channel=ipc::inherited(3)?;let bootstrap=File::from(ipc::inherited(5)?);
    ipc::require_channel(channel.as_raw_fd())?;
    let parent=unsafe {libc::getppid()};
    let parent_pidfd=ipc::open_peer_pidfd(channel.as_raw_fd()).map_err(|_|"shadow actual parent PIDFD absent")?;
    ipc::prove_owned_process(&parent_pidfd,&parent_pidfd,parent).map_err(|_|"shadow endpoint is not actual parent")?;
    let meta=bootstrap.metadata().map_err(|_|"shadow bootstrap metadata absent")?;
    require(meta.len()>0 && meta.len()<=16*1024)?;
    let mut raw=vec![0;meta.len() as usize];bootstrap.read_exact_at(&mut raw,0).map_err(|_|"shadow bootstrap read failed")?;
    let bootstrap=Sealed::receive(bootstrap,0,meta.len(),&wire::sha(&raw),false)?;
    let selected:wire::WorkerBootstrap=wire::decode(&raw)?;selected.validate()?;
    require(publication_descriptors==selected.publication().is_some())?;
    require(runtime_descriptors==selected.runtime().is_some())?;
    let admitted=selected.worker();
    let mut held=Vec::new();
    for i in 0..3 {
        let file=File::from(ipc::inherited(6+i as i32)?);
        let length=file.metadata().map_err(|_|"shadow inherited executable absent")?.len();
        let image=Sealed::receive(file,0,length,&admitted.executable_sha256[i],true)?;
        super::elf::validate_static_amd64_elf_verifier(&image.bytes()?)?;held.push(image);
    }
    // Resource admission occurs while this exact cold child is still root;
    // neither inherited descriptor presence nor a job request selects authority.
    let publication=selected.publication().map(|expected|
        super::publication_resources::WorkerResources::admit(expected,admitted.deadline_boottime_ns)).transpose()?;
    let runtime=selected.runtime().map(|expected|
        super::runtime_resources::WorkerResources::admit(expected,admitted.deadline_boottime_ns)).transpose()?;
    let identity=identity::enter(parent)?;
    bootstrap.check()?;identity.check()?;
    if let Some(resources)=&publication {resources.check()?;}
    if let Some(resources)=&runtime {resources.check()?;}
    let initialized=wire::Initialized {api_version:"serverware.nativeShadowWorkerInitialized/v1".into(),
        channel_nonce:admitted.channel_nonce.clone(),bootstrap_sha256:bootstrap.sha256().to_owned()};
    ipc::wait(channel.as_raw_fd(),libc::POLLOUT,&parent_pidfd,admitted.deadline_boottime_ns)?;
    ipc::send(channel.as_raw_fd(),&wire::encode(&initialized)?,None)?;
    let mut sequence=0u64;
    loop {
        identity.check()?;bootstrap.check()?;
        if let Some(resources)=&publication {resources.check()?;}
        if let Some(resources)=&runtime {resources.check()?;}
        ipc::wait(channel.as_raw_fd(),libc::POLLIN,&parent_pidfd,admitted.deadline_boottime_ns)?;
        let packet=ipc::receive(channel.as_raw_fd(),1)?;
        require(packet.credentials.pid==parent && packet.credentials.uid==crate::native_serving_privileges::UID
            && packet.credentials.gid==crate::native_serving_privileges::GID)?;
        ipc::prove_owned_process(&parent_pidfd,&packet.sender,parent).map_err(|_|"shadow packet changed native parent")?;
        let request:wire::Request=wire::decode(&packet.bytes)?;
        require(request.sequence==sequence.checked_add(1).ok_or("shadow sequence exhausted")?
            && request.channel_nonce==admitted.channel_nonce && request.bootstrap_sha256==bootstrap.sha256()
            && request.deadline_boottime_ns<=admitted.deadline_boottime_ns
            && request.deadline_boottime_ns>now()?
            && request.deadline_boottime_ns<=now()?.checked_add(wire::WINDOW).ok_or("shadow deadline overflow")?)?;
        sequence=request.sequence;
        let input=wire::input(&request,File::from(packet.descriptor.ok_or("shadow request input absent")?),crate::native_serving_privileges::UID)?;
        let document:serde_json::Value=wire::decode(&input.bytes()?)?;request.purpose.input(&document)?;drop(document);
        let index=request.purpose.index();identity.check()?;
        let publication_transfer=if request.purpose==super::Purpose::Publication {
            publication.as_ref().map(|resources|resources.job(request.deadline_boottime_ns)).transpose()?
        } else {None};
        let runtime_transfer=if request.purpose==super::Purpose::Runtime {
            runtime.as_ref().map(|resources|resources.job(request.deadline_boottime_ns,&request.input_sha256)).transpose()?
        } else {None};
        require(publication_transfer.is_none() || runtime_transfer.is_none())?;
        let transfer=publication_transfer.as_ref().map(|v|&v.descriptors)
            .or_else(||runtime_transfer.as_ref().map(|v|&v.descriptors));
        let output=job::run(&held[index],&input,&admitted.executable_path[index],&parent_pidfd,channel.as_raw_fd(),
            request.deadline_boottime_ns,admitted.deadline_boottime_ns,request.purpose.maximum(),transfer)?;
        drop(publication_transfer);drop(runtime_transfer);
        if let Some(resources)=&publication {resources.check()?;}
        if let Some(resources)=&runtime {resources.check()?;}
        identity.check()?;bootstrap.check()?;input.check()?;
        ipc::prove_owned_process(&parent_pidfd,&packet.sender,parent).map_err(|_|"shadow original parent changed during command")?;
        let output=Sealed::new(&output,false)?;
        let result=wire::ResultWire {status:"process-exited-zero".into(),output_sha256:output.sha256().to_owned(),output_bytes:output.length()};
        let response=wire::Response {api_version:"serverware.nativeShadowWorkerResponse/v1".into(),request,result};
        ipc::wait(channel.as_raw_fd(),libc::POLLOUT,&parent_pidfd,response.request.deadline_boottime_ns)?;
        if let Some(resources)=&publication {resources.check()?;}
        if let Some(resources)=&runtime {resources.check()?;}
        require(now()?<response.request.deadline_boottime_ns)?;
        ipc::send(channel.as_raw_fd(),&wire::encode(&response)?,Some(output.file.as_raw_fd()))?;
    }
}
