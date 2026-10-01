//! Explicit fixed proof-cohort ownership. All original children, executable
//! inodes, activation FDs and watchdog survive post-create signed assignment.
use super::*;
use std::fs::File;
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd,OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::mem::{size_of,size_of_val,zeroed};
#[path="proof_cohort_inputs.rs"]
pub(super) mod inputs;
#[path="proof_cohort_cleanup.rs"]
mod cleanup;
#[path="proof_cohort_driver.rs"]
mod external_driver;
const MAX_WIRE:usize=32768;
const LAUNCH_PATH:&str="/etc/serverware/native-shadow-guest-launch.json";
const IMAGE_PATH:&str="/opt/serverware/native-shadow-custody-runtime.squashfs";
const SOURCE_API:&str="serverware.nativeShadowProofCohortOriginals/v1";

struct Control {socket:OwnedFd,peer:libc::ucred,pidfd:OwnedFd}
impl Control {
    fn inherited()->Result<Self,ShadowError> {
        require(cfg!(target_arch="x86_64") && std::env::args_os().count()==1 && std::env::vars_os().next().is_none()
            && unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0
            && unsafe{libc::getgid()}==0 && unsafe{libc::getegid()}==0)?;
        // Inspect before opens can occupy an absent input slot.
        let mut present=BTreeSet::new();
        for entry in std::fs::read_dir("/proc/self/fd").map_err(fail)? {
            present.insert(entry.map_err(fail)?.file_name().to_str().ok_or(ShadowError::BindingDrift)?
                .parse::<i32>().map_err(fail)?);
        }
        require(present.contains(&3))?;
        for fd in present {if unsafe{libc::fcntl(fd,libc::F_GETFD)}>=0 {require(fd<=3)?;}}
        let socket=unsafe{OwnedFd::from_raw_fd(3)};
        retrieval_peer::configure(socket.as_fd())?;
        let peer=retrieval_peer::credentials(socket.as_fd())?;let pidfd=retrieval_peer::peer_pidfd(socket.as_fd())?;
        require(peer.pid>1 && peer.uid==0 && peer.gid==0 && peer.pid!=unsafe{libc::getpid()})?;
        let status=std::fs::read_to_string("/proc/self/status").map_err(fail)?;
        let threads:Vec<_>=status.lines().filter_map(|v|v.strip_prefix("Threads:")).collect();
        require(threads.len()==1 && threads[0].trim()=="1")?;
        let core=libc::rlimit{rlim_cur:0,rlim_max:0};
        require(unsafe{libc::setrlimit(libc::RLIMIT_CORE,&core)}==0 && unsafe{libc::prctl(libc::PR_SET_DUMPABLE,0)}==0)?;
        let mut action:libc::sigaction=unsafe{zeroed()};action.sa_sigaction=libc::SIG_IGN;
        require(unsafe{libc::sigemptyset(&mut action.sa_mask)}==0
            && unsafe{libc::sigaction(libc::SIGPIPE,&action,std::ptr::null_mut())}==0)?;
        let owner=Self{socket,peer,pidfd};owner.check()?;Ok(owner)
    }
    fn check(&self)->Result<(),ShadowError> {
        retrieval_peer::same_process(self.pidfd.as_fd(),self.peer.pid)?;
        require(retrieval_peer::same_credentials(&retrieval_peer::credentials(self.socket.as_fd())?,&self.peer))
    }
    fn check_released(&self)->Result<(),ShadowError> {
        self.check()?;
        let mut byte=0u8;
        let count=unsafe{libc::recv(self.socket.as_raw_fd(),(&mut byte as *mut u8).cast(),1,
            libc::MSG_PEEK|libc::MSG_DONTWAIT)};
        // The one release packet was already consumed. EOF, another packet
        // or any error other than an empty queue cancels the actual cohort.
        require(count<0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EAGAIN))
    }
    fn cleanup_request(&self)->Result<Option<Vec<u8>>,ShadowError>{
        self.check()?;
        let Some(packet)=retrieval_peer::receive(self.socket.as_fd(),MAX_WIRE,0)? else{return Ok(None);};
        require(retrieval_peer::same_credentials(&packet.credentials,&self.peer))?;
        retrieval_peer::same_process(packet.pidfd.as_fd(),self.peer.pid)?;
        self.check()?;Ok(Some(packet.bytes))
    }
    fn terminal_response(&self,raw:&[u8],cohort:&Cohort,journal:&cleanup::Owner,deadline:u64)->Result<(),ShadowError>{
        require(!raw.is_empty() && raw.len()<=MAX_WIRE)?;
        loop {
            self.check_released()?;cohort.check_resources()?;journal.check()?;require(now()?<deadline)?;
            if retrieval_peer::send(self.socket.as_fd(),raw,&[])?{return Ok(());}
            wait(self.socket.as_fd(),libc::POLLOUT)?;
        }
    }
    fn send(&self,bytes:&[u8],cohort:&Cohort)->Result<(),ShadowError> {
        require(!bytes.is_empty() && bytes.len()<=MAX_WIRE)?;
        loop {
            cohort.check_startup()?;self.check()?;
            if retrieval_peer::send(self.socket.as_fd(),bytes,&[])? {return Ok(());}
            wait(self.socket.as_fd(),libc::POLLOUT)?;
        }
    }
    fn driver(&self,admission:&inputs::Admission)->Result<external_driver::Owner,ShadowError>{
        let config=admission.external_driver().ok_or(ShadowError::BindingDrift)?;
        loop {
            admission.check_startup()?;self.check()?;
            if let Some(packet)=retrieval_peer::receive(self.socket.as_fd(),MAX_WIRE,3)? {
                require(retrieval_peer::same_credentials(&packet.credentials,&self.peer) && packet.rights.len()==3)?;
                retrieval_peer::same_process(packet.pidfd.as_fd(),self.peer.pid)?;
                let owner=external_driver::Owner::admit(config,&packet.bytes,packet.rights,self.peer.pid,admission)?;
                self.check()?;return Ok(owner);
            }
            wait(self.socket.as_fd(),libc::POLLIN)?;
        }
    }
    fn receive(&self,cohort:&Cohort)->Result<(Vec<u8>,Vec<OwnedFd>),ShadowError> {
        loop {
            cohort.check_startup()?;self.check()?;
            let mut bytes=vec![0;MAX_WIRE];let mut control=[0usize;96];
            let mut iov=libc::iovec{iov_base:bytes.as_mut_ptr().cast(),iov_len:bytes.len()};
            let mut message:libc::msghdr=unsafe{zeroed()};message.msg_iov=&mut iov;message.msg_iovlen=1;
            message.msg_control=control.as_mut_ptr().cast();message.msg_controllen=size_of_val(&control).try_into().map_err(fail)?;
            let count=unsafe{libc::recvmsg(self.socket.as_raw_fd(),&mut message,libc::MSG_DONTWAIT|libc::MSG_CMSG_CLOEXEC)};
            if count<0 {
                let error=std::io::Error::last_os_error();
                require(matches!(error.raw_os_error(),Some(libc::EINTR)|Some(libc::EAGAIN)))?;
                wait(self.socket.as_fd(),libc::POLLIN)?;continue;
            }
            let mut good=count>0 && message.msg_flags&(libc::MSG_TRUNC|libc::MSG_CTRUNC)==0;
            let mut credentials=None;let mut pidfd=None;let mut rights=Vec::new();let mut rights_seen=false;
            let mut item=unsafe{libc::CMSG_FIRSTHDR(&message)};
            while !item.is_null() {
                let c=unsafe{&*item};let base=unsafe{libc::CMSG_LEN(0)} as usize;
                let Ok(cmsg_len)=usize::try_from(c.cmsg_len) else{good=false;break;};
                if cmsg_len<base {good=false;break;}
                let length=cmsg_len-base;let data=unsafe{libc::CMSG_DATA(item)};
                if c.cmsg_level==libc::SOL_SOCKET && (c.cmsg_type==libc::SCM_RIGHTS||c.cmsg_type==4) {
                    good &= length%size_of::<i32>()==0;
                    if c.cmsg_type==libc::SCM_RIGHTS {good &= !rights_seen;rights_seen=true;}
                    for index in 0..length/size_of::<i32>() {
                        let raw=unsafe{std::ptr::read_unaligned(data.cast::<i32>().add(index))};
                        if raw<0 {good=false;continue;}
                        let fd=unsafe{OwnedFd::from_raw_fd(raw)};
                        if c.cmsg_type==4 {
                            if pidfd.is_some() || length!=size_of::<i32>() {good=false;}else{pidfd=Some(fd);}
                        } else {rights.push(fd);}
                    }
                } else if c.cmsg_level==libc::SOL_SOCKET && c.cmsg_type==libc::SCM_CREDENTIALS
                    && credentials.is_none() && length==size_of::<libc::ucred>() {
                    credentials=Some(unsafe{std::ptr::read_unaligned(data.cast::<libc::ucred>())});
                } else {good=false;}
                item=unsafe{libc::CMSG_NXTHDR(&message,item)};
            }
            require(good && rights_seen && (cohort.admission.roles().len()..=128).contains(&rights.len())
                && retrieval_peer::same_credentials(&credentials.ok_or(ShadowError::BindingDrift)?,&self.peer))?;
            retrieval_peer::same_process(pidfd.ok_or(ShadowError::BindingDrift)?.as_fd(),self.peer.pid)?;
            bytes.truncate(count as usize);cohort.check_startup()?;self.check()?;return Ok((bytes,rights));
        }
    }
}
fn wait(fd:BorrowedFd<'_>,events:i16)->Result<(),ShadowError> {
    let mut p=libc::pollfd{fd:fd.as_raw_fd(),events,revents:0};
    let value=unsafe{libc::poll(&mut p,1,10)};
    require((value>=0 && p.revents&(libc::POLLERR|libc::POLLHUP|libc::POLLNVAL)==0)
        || (value<0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR)))
}

// The two fixed mount targets are empty or old protected files, never an
// admitted configuration. Only genuine held post-create originals cover them.
struct Target {file:File,path:&'static str,identity:(u64,u64,u32,u32,u32)}
impl Target {
    fn open(path:&'static str)->Result<Self,ShadowError> {
        let mut file=File::open("/").map_err(fail)?;
        for component in path[1..].split('/') {
            let m=file.metadata().map_err(fail)?;
            require(m.is_dir() && m.uid()==0 && m.gid()==0 && m.mode()&0o022==0)?;
            let name=std::ffi::CString::new(component).map_err(fail)?;
            let raw=unsafe{libc::openat(file.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_CLOEXEC|libc::O_NOFOLLOW|libc::O_NONBLOCK)};
            require(raw>=0)?;file=unsafe{File::from_raw_fd(raw)};
        }
        let m=file.metadata().map_err(fail)?;
        require(m.is_file() && m.uid()==0 && m.gid()==0 && m.mode()&0o7777==0o400 && m.nlink()==1)?;
        Ok(Self{file,path,identity:(m.dev(),m.ino(),m.mode(),m.uid(),m.gid())})
    }
    fn check(&self)->Result<(),ShadowError> {
        let m=self.file.metadata().map_err(fail)?;let current=std::fs::symlink_metadata(self.path).map_err(fail)?;
        require((m.dev(),m.ino(),m.mode(),m.uid(),m.gid())==self.identity
            && (current.dev(),current.ino(),current.mode(),current.uid(),current.gid())==self.identity)
    }
}
struct View<'a>{target:&'a Target,mounted:bool}
impl<'a> View<'a> {
    fn bind(target:&'a Target,source:&Original)->Result<Self,ShadowError> {
        target.check()?;source.check().map_err(fail)?;
        let src=std::ffi::CString::new(format!("/proc/self/fd/{}",source.descriptor().as_raw_fd())).map_err(fail)?;
        let dst=std::ffi::CString::new(target.path).map_err(fail)?;
        require(unsafe{libc::mount(src.as_ptr(),dst.as_ptr(),std::ptr::null(),libc::MS_BIND,std::ptr::null())}==0)?;
        let owner=Self{target,mounted:true};
        require(unsafe{libc::mount(std::ptr::null(),dst.as_ptr(),std::ptr::null(),
            libc::MS_BIND|libc::MS_REMOUNT|libc::MS_RDONLY|libc::MS_NOSUID|libc::MS_NODEV|libc::MS_NOEXEC,std::ptr::null())}==0)?;
        source.check().map_err(fail)?;Ok(owner)
    }
    fn retire(mut self)->Result<(),ShadowError> {self.unmount()?;self.target.check()}
    fn unmount(&mut self)->Result<(),ShadowError> {
        if self.mounted {
            let dst=std::ffi::CString::new(self.target.path).map_err(fail)?;
            // The admitted image retains an actual source FD through this
            // bind mount. Detach only our path; that held mount reference
            // remains owned through child reap, not claimed destroyed here.
            require(unsafe{libc::umount2(dst.as_ptr(),libc::MNT_DETACH)}==0)?;self.mounted=false;
        }Ok(())
    }
}
impl Drop for View<'_>{fn drop(&mut self){if self.unmount().is_err(){unsafe{libc::_exit(1);}}}}

#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct ChildOriginal {process_id:i32,start_time_ticks:u64,executable:inputs::ExecutableObservation}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Observations {api_version:&'static str,configuration_sha256:Sha256Digest,precreation_sha256:Sha256Digest,
    invocation_id:String,retrieval:ChildOriginal,persistence:ChildOriginal,trusted_time:ChildOriginal,
    generation_install:ChildOriginal,
    #[serde(skip_serializing_if="Option::is_none")]
    bridge:Option<ChildOriginal>,
    #[serde(skip_serializing_if="Option::is_none")]
    external_driver:Option<external_driver::BindingOriginal>,
    #[serde(skip_serializing_if="Option::is_none")]
    commit_request:Option<ChildOriginal>,
    #[serde(skip_serializing_if="Option::is_none")]
    ingress_admission:Option<ChildOriginal>,
    #[serde(skip_serializing_if="Option::is_none")]
    terminal_append:Option<ChildOriginal>,
    #[serde(skip_serializing_if="Option::is_none")]
    dispatch_barrier:Option<ChildOriginal>,
    #[serde(skip_serializing_if="Option::is_none")]
    active_effect_barrier:Option<ChildOriginal>,
    #[serde(skip_serializing_if="Option::is_none")]
    active_effect_commit:Option<ChildOriginal>}
struct Program {launch:Original,launch_bytes:Vec<u8>,image_original:Original,image:image::Image,
    files:FileAdmission,activation:BTreeMap<String,OwnedFd>,inspection:Inspection,remote:OwnedFd}
struct Cohort {
    // Explicit Drop signals the COMPLETE selected cohort before any wait.
    // Images/originals remain until same-PIDFD terminal evidence and all reaps.
    children:Vec<child::Child>,programs:Vec<Program>,executables:Vec<inputs::Executable>,
    launch_target:Target,image_target:Target,admission:inputs::Admission,_watchdog:Watchdog,
    cleanup:Option<cleanup::Owner>,
    external_driver:Option<external_driver::Owner>,
}
impl Cohort {
    fn prepare(control:&Control)->Result<Self,ShadowError> {
        let admission=inputs::Admission::open()?;let watchdog=Watchdog::arm_proof_cohort(&admission)?;
        let cleanup=admission.cleanup()?;
        // The foreign driver is already measured by its own supervisor. Admit
        // its real descriptors before creating any owned endpoint children.
        let external_driver=if admission.endpoint_only(){Some(control.driver(&admission)?)}else{None};
        if let Some(driver)=&external_driver {
            for index in 0..admission.roles().len(){
                let role=admission.role_identity(index)?;
                require(role.0!=driver.identity().0 && role.1!=driver.identity().1)?;
            }
        }
        let launch_target=Target::open(LAUNCH_PATH)?;let image_target=Target::open(IMAGE_PATH)?;
        let mut executables=Vec::with_capacity(admission.roles().len());
        for _ in admission.roles() {executables.push(inputs::Executable::create(&admission)?);}
        process::isolate_mounts()?;
        let mut owner=Self{children:Vec::new(),programs:Vec::new(),executables,launch_target,image_target,admission,_watchdog:watchdog,cleanup,external_driver};
        for executable in &owner.executables {
            owner.admission.check_startup()?;
            owner.children.push(child::Child::precreate(executable.fd(),owner.launch_target.file.as_fd(),
                owner.image_target.file.as_fd(),owner.admission.startup(),owner.admission.lifetime())?);
        }
        owner.check_startup()?;Ok(owner)
    }
    fn check_startup(&self)->Result<(),ShadowError> {
        self.admission.check_startup()?;self.check()?;
        require(now()?.checked_add(REAP_RESERVE_NS).is_some_and(|v|v<self.admission.lifetime()))
    }
    fn check(&self)->Result<(),ShadowError> {
        self.check_owned()?;
        if let Some(driver)=&self.external_driver {driver.check_active()?;}
        Ok(())
    }
    // Cleanup checks only owned children. Foreign death cancels serving, but
    // must not prevent the endpoint parent's own terminal/reap operation.
    fn check_owned(&self)->Result<(),ShadowError> {
        self.check_resources()?;
        for child in &self.children {require(child.check()?)?;}
        Ok(())
    }
    fn external_driver_sha256(&self)->Result<Option<Sha256Digest>,ShadowError>{
        self.external_driver.as_ref().map(external_driver::Owner::binding_sha256).transpose()
    }
    fn check_resources(&self)->Result<(),ShadowError> {
        self.admission.check()?;self.launch_target.check()?;self.image_target.check()?;
        if let Some(driver)=&self.external_driver {driver.check_retained()?;}
        for executable in &self.executables {executable.check()?;}
        if let Some(owner)=&self.cleanup {owner.check()?;}
        for program in &self.programs {
            program.files.check().map_err(fail)?;program.image.check(&program.files)?;
            program.image_original.check().map_err(fail)?;
            require(program.launch.read(MAX_WIRE).map_err(fail)?.as_slice()==program.launch_bytes.as_slice())?;
            check_activation(&program.files,&program.activation)?;
        }Ok(())
    }
    fn observations(&self)->Result<Vec<u8>,ShadowError> {
        self.check_startup()?;require(self.children.len()==self.admission.roles().len() && self.programs.is_empty())?;
        let child=|index:usize|->Result<ChildOriginal,ShadowError> {
            let index=if self.admission.endpoint_only(){external_driver::owned_index(index).ok_or(ShadowError::BindingDrift)?}else{index};
            let identity=self.children[index].parked_identity()?;
            Ok(ChildOriginal{process_id:identity.0,start_time_ticks:identity.1,executable:self.executables[index].observation()?})
        };
        let endpoint=self.admission.endpoint_only();
        let original=Observations{api_version:if endpoint{"serverware.nativeShadowProofCohortOriginals/v6"}else if self.admission.eleven(){"serverware.nativeShadowProofCohortOriginals/v5"}else if self.admission.eight(){"serverware.nativeShadowProofCohortOriginals/v4"}else if self.admission.seven(){"serverware.nativeShadowProofCohortOriginals/v3"}else if self.admission.six(){"serverware.nativeShadowProofCohortOriginals/v2"}else{SOURCE_API},configuration_sha256:self.admission.configuration_sha256(),
            precreation_sha256:self.admission.precreation_sha256(),invocation_id:self.admission.invocation_id().into(),
            retrieval:child(0)?,persistence:child(1)?,trusted_time:child(2)?,generation_install:child(3)?,bridge:if endpoint{None}else{Some(child(4)?)},
            external_driver:self.external_driver.as_ref().map(external_driver::Owner::original).transpose()?,
            commit_request:if endpoint||self.admission.six(){Some(child(5)?)}else{None},
            ingress_admission:if endpoint||self.admission.seven(){Some(child(6)?)}else{None},
            terminal_append:if endpoint||self.admission.eight(){Some(child(7)?)}else{None},
            dispatch_barrier:if endpoint||self.admission.eleven(){Some(child(8)?)}else{None},
            active_effect_barrier:if endpoint||self.admission.eleven(){Some(child(9)?)}else{None},
            active_effect_commit:if endpoint||self.admission.eleven(){Some(child(10)?)}else{None}};
        let bytes=canonical_json_bytes(&original)?;self.check_startup()?;Ok(bytes)
    }
    fn release(&mut self,bytes:&[u8],observed:&[u8],rights:Vec<OwnedFd>)->Result<(),ShadowError> {
        require(self.observations()?==observed)?;
        let external=self.external_driver_sha256()?;
        let releases=self.admission.release(bytes,observed,external.as_ref())?;
        let mut rights=rights.into_iter();let mut all=BTreeSet::new();
        for (index,release) in releases.into_iter().enumerate() {
            self.check_startup()?;
            let launch=release.launch.open(MAX_WIRE)?;let launch_bytes=launch.read(MAX_WIRE).map_err(fail)?.to_vec();
            let (selected,service)=selection(&launch_bytes)?;
            let files=admit_files(&selected.delivery_configuration.path,selected.delivery_configuration.sha256.clone(),
                &selected.delivery.path,selected.delivery.sha256.clone()).map_err(fail)?;
            self.admission.join(index,&selected,&files)?;
            let endpoint=self.admission.endpoint_only();
            let logical=if endpoint{external_driver::logical_index(index)?}else{index};
            require_role(logical,&service,endpoint||self.admission.six(),endpoint||self.admission.seven(),endpoint||self.admission.eight(),endpoint||self.admission.eleven())?;
            if service.endpoint_runtime_role().is_some(){
                service.check_endpoint_runtime(&files.retrieval_client_runtime().map_err(fail)?)?;
            }
            let mut activation=BTreeMap::new();
            for (slot,entry) in files.payload.activation.iter().enumerate() {
                require(entry.fd==6+slot as i32)?;
                let fd=rights.next().ok_or(ShadowError::BindingDrift)?;
                let mut stat:libc::stat=unsafe{zeroed()};
                require(unsafe{libc::fstat(fd.as_raw_fd(),&mut stat)}==0
                    && (stat.st_dev,stat.st_ino,stat.st_mode,stat.st_uid,stat.st_gid)==(entry.device,entry.inode,entry.mode,entry.uid,entry.gid)
                    && ([libc::S_IFDIR,libc::S_IFSOCK].contains(&(stat.st_mode&libc::S_IFMT))
                        || (matches!(&service,SelectedService::PersistenceLocked(_)) && slot==2
                            && entry.name=="persistence-lock" && stat.st_mode&libc::S_IFMT==libc::S_IFREG)
                        || (matches!(&service,SelectedService::LedgerRetrieval(_)|SelectedService::CompletionRetrieval(_)|SelectedService::EffectRetrieval(_)) && slot==3
                            && entry.name=="ledger-spool-lock" && stat.st_mode&libc::S_IFMT==libc::S_IFREG))
                    && all.insert((stat.st_dev,stat.st_ino))
                    && activation.insert(entry.name.clone(),fd).is_none())?;
            }
            let peers=assigned_peers(&service,&files)?;
            for (other,peer) in peers {
                if endpoint && other==4 {
                    self.external_driver.as_ref().ok_or(ShadowError::BindingDrift)?.require_peer(&peer)?;
                    continue;
                }
                let other=if endpoint{external_driver::owned_index(other).ok_or(ShadowError::BindingDrift)?}else{other};
                let actual=self.children[other].parked_identity()?;
                require((peer.pid,peer.start_time_ticks)==actual)?;
                self.executables[other].require_peer(&peer)?;
                // Future UID/GID/cgroup/label expectations are independently
                // assigned, NOT measurements of these still-root trampolines.
                require((peer.uid,peer.gid)==self.admission.role_identity(other)?)?;
            }
            let closure_set_role=service.closure_set_role();
            let (inspection,remote)=prepare_inspection(service,&files,&activation)?;
            let image_original=release.image.open(512*1024*1024)?;
            image_original.read(512*1024*1024).map_err(fail)?;
            let view=View::bind(&self.image_target,&image_original)?;
            let image=image::Image::prepare_pair_selected(&selected.closure,&files,self.executables[index].fd(),
                &release.image.sha256,self.admission.executable_sha256(),closure_set_role)?;
            view.retire()?;
            self.programs.push(Program{launch,launch_bytes,image_original,image,files,activation,inspection,remote});
        }
        require(rights.next().is_none() && self.programs.len()==self.admission.roles().len())?;
        self.check_startup()?;
        // All selected signed originals and actual parked targets are joined
        // before the first effect. A partial send kills/reaps the WHOLE cohort;
        // it is not an atomic process-readiness claim.
        for index in 0..self.admission.roles().len() {
            self.check_startup()?;
            let p=&self.programs[index];
            let ordered=p.files.payload.activation.iter().map(|e|
                p.activation.get(&e.name).map(AsFd::as_fd).ok_or(ShadowError::BindingDrift)).collect::<Result<Vec<_>,_>>()?;
            self.children[index].release_pair(p.launch.descriptor(),p.image_original.descriptor(),p.remote.as_fd(),&ordered)?;
        }
        Ok(())
    }
    fn hold(&mut self,control:&Control,observed:&[u8],release:&[u8])->Result<bool,ShadowError> {
        loop {
            if now()?>=self.admission.lifetime()-REAP_RESERVE_NS {return Ok(false);}
            if self.cleanup.is_some() {
                if let Some(raw)=control.cleanup_request()? {
                    let owner=self.cleanup.take().ok_or(ShadowError::BindingDrift)?;
                    let (owner,response,deadline)=owner.perform(&raw,self,observed,release,control)?;
                    control.terminal_response(&response,self,&owner,deadline)?;
                    self.cleanup=Some(owner);return Ok(true);
                }
            } else {control.check_released()?;}
            self.check()?;
            for (program,child) in self.programs.iter_mut().zip(&self.children) {
                program.inspection.progress(child,&program.files)?;
            }
            let result=unsafe{libc::poll(std::ptr::null_mut(),0,10)};
            require(result==0 || (result<0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR)))?;
        }
    }
}
// The exact slot does not create a service. Unknown or not-yet-connected
// selectors refuse before ANY child is released.
fn require_role(index:usize,service:&SelectedService,six:bool,seven:bool,eight:bool,eleven:bool)->Result<(),ShadowError> {
    require(match (index,service) {
        (0,SelectedService::Retrieval(_))=>!seven,
        (0,SelectedService::LedgerRetrieval(_))=>seven&&!eight,
        (0,SelectedService::CompletionRetrieval(_))=>eight&&!eleven,
        (0,SelectedService::EffectRetrieval(_))=>eleven,
        (1,SelectedService::Persistence(_))|(1,SelectedService::PersistenceLocked(_))|
        (2,SelectedService::TrustedTime(_))|(3,SelectedService::Generation(_))=>true,
        (4,SelectedService::ProofBridge(_))=>!six,
        (4,SelectedService::CommitmentBridge(_))|(5,SelectedService::CommitRequest(_))=>six&&!seven,
        (4,SelectedService::SpoolBridge(_))|(5,SelectedService::LedgerSpool(_))=>seven&&!eight,
        (6,SelectedService::Ingress(_))=>seven,
        (4,SelectedService::TerminalBridge(_))=>eight&&!eleven,
        (5,SelectedService::CompletionLedgerSpool(_))|(7,SelectedService::TerminalSpool(_))=>eight,
        (4,SelectedService::ActiveEffectBridge(_))|(4,SelectedService::InitialHistoryBridge(..))|(8,SelectedService::DispatchSpool(_))|
        (9,SelectedService::ActiveEffectBarrier(_))|(10,SelectedService::ActiveEffectCommit(_))=>eleven,
        _=>false,
    })
}
fn assigned_peers(service:&SelectedService,files:&FileAdmission)
    ->Result<Vec<(usize,super::super::super::super::ExpectedPeerCredentialV3)>,ShadowError> {
    match service {
        SelectedService::DispatchSpool(pin)|SelectedService::ActiveEffectBarrier(pin)|SelectedService::ActiveEffectCommit(pin)=>{
            let original=pin.open(admission::spool_signer::MAX_CONFIGURATION)?;let grant:admission::spool_signer::Configuration=exact(&original.read(admission::spool_signer::MAX_CONFIGURATION).map_err(fail)?)?;
            let kind=match service{SelectedService::DispatchSpool(_)=>admission::spool_signer::Kind::DispatchBarrier,
                SelectedService::ActiveEffectBarrier(_)=>admission::spool_signer::Kind::ActiveEffectBarrier,
                _=>admission::spool_signer::Kind::ActiveEffectCommit};
            require(grant.kind()?==kind)?;grant.validate_shape()?;Ok(vec![(4,grant.expected_peer().clone())])
        }
        SelectedService::LedgerSpool(pin)|SelectedService::CompletionLedgerSpool(pin)|SelectedService::Ingress(pin)|SelectedService::TerminalSpool(pin)=>{
            let original=pin.open(admission::spool_signer::MAX_CONFIGURATION)?;let grant:admission::spool_signer::Configuration=exact(&original.read(admission::spool_signer::MAX_CONFIGURATION).map_err(fail)?)?;
            let kind=match service{SelectedService::Ingress(_)=>admission::spool_signer::Kind::Ingress,
                SelectedService::TerminalSpool(_)=>admission::spool_signer::Kind::Terminal,_=>admission::spool_signer::Kind::Ledger};
            require(grant.completion_selected()==matches!(service,SelectedService::CompletionLedgerSpool(_)|SelectedService::TerminalSpool(_)))?;
            require(grant.kind()?==kind)?;grant.validate_shape()?;Ok(vec![(4,grant.expected_peer().clone())])
        }
        SelectedService::LedgerRetrieval(pin)|SelectedService::CompletionRetrieval(pin)|SelectedService::EffectRetrieval(pin)=>{
            let original=pin.open(65536)?;let grant:admission::ledger_retrieval::Configuration=exact(&original.read(65536).map_err(fail)?)?;
            require(grant.completion_selected()==matches!(service,SelectedService::CompletionRetrieval(_)|SelectedService::EffectRetrieval(_))
                && grant.effects_selected()==matches!(service,SelectedService::EffectRetrieval(_)))?;
            grant.validate_shape()?;Ok(vec![(4,grant.expected_peer().clone())])
        }
        SelectedService::CommitRequest(pin)=>{
            let original=pin.open(admission::commit_request::MAX_CONFIGURATION)?;
            let grant:admission::commit_request::Configuration=exact(&original.read(admission::commit_request::MAX_CONFIGURATION).map_err(fail)?)?;
            grant.validate_shape()?;Ok(vec![(4,grant.expected_peer().clone())])
        }
        SelectedService::Generation(pin)=>{
            let original=pin.open(admission::generation_install::MAX_CONFIGURATION)?;
            let grant:admission::generation_install::Configuration=exact(&original.read(admission::generation_install::MAX_CONFIGURATION).map_err(fail)?)?;
            grant.validate_shape()?;Ok(vec![(4,grant.expected_peer().clone())])
        }
        SelectedService::Retrieval(pin)=>{
            let original=pin.open(65536)?;
            let grant:admission::retrieval::Configuration=exact(&original.read(65536).map_err(fail)?)?;
            grant.validate_shape()?;Ok(vec![(4,grant.expected_peer().clone())])
        }
        SelectedService::Persistence(pin)|SelectedService::PersistenceLocked(pin)=>{
            let original=pin.open(65536)?;
            let grant:admission::persistence::Configuration=exact(&original.read(65536).map_err(fail)?)?;
            grant.validate_shape()?;Ok(vec![(4,grant.expected_peer().clone())])
        }
        SelectedService::TrustedTime(pin)=>{
            let original=pin.open(65536)?;
            let grant:admission::trusted_time::Configuration=exact(&original.read(65536).map_err(fail)?)?;
            grant.validate_shape()?;Ok(vec![(4,grant.expected_peer().clone())])
        }
        SelectedService::ProofBridge(_)|SelectedService::CommitmentBridge(_)|SelectedService::SpoolBridge(_)|SelectedService::TerminalBridge(_)|SelectedService::ActiveEffectBridge(_)|SelectedService::InitialHistoryBridge(..)=>{
            let initial_history=matches!(service,SelectedService::InitialHistoryBridge(..));
            let helper_initial=matches!(service,SelectedService::InitialHistoryBridge(_,true,_));
            let native_terminal=matches!(service,SelectedService::InitialHistoryBridge(_,_,true));
            let effects=matches!(service,SelectedService::ActiveEffectBridge(_)|SelectedService::InitialHistoryBridge(..));
            let terminal=matches!(service,SelectedService::TerminalBridge(_)|SelectedService::ActiveEffectBridge(_)|SelectedService::InitialHistoryBridge(..));
            let spool=matches!(service,SelectedService::SpoolBridge(_)|SelectedService::TerminalBridge(_)|SelectedService::ActiveEffectBridge(_)|SelectedService::InitialHistoryBridge(..));
            let commitment=matches!(service,SelectedService::CommitmentBridge(_)|SelectedService::SpoolBridge(_)|SelectedService::TerminalBridge(_)|SelectedService::ActiveEffectBridge(_)|SelectedService::InitialHistoryBridge(..));
            let mut assigned=if initial_history{proof_client::assigned_peers_initial_history(files,helper_initial,native_terminal)?}else if effects{proof_client::assigned_peers_effects(files)?}else if terminal{proof_client::assigned_peers_terminal(files)?}else if spool{proof_client::assigned_peers_spool(files)?}else if commitment {proof_client::assigned_peers_selected(files,true)?}
                else {proof_client::assigned_peers(files)?};
            let mut peers=Vec::new();
            for (index,kind) in [retrieval_peer::EndpointKind::Retrieval,retrieval_peer::EndpointKind::Persistence,
                retrieval_peer::EndpointKind::TrustedTime,retrieval_peer::EndpointKind::GenerationInstallEnvelope].into_iter().enumerate() {
                peers.push((index,assigned.remove(&kind).ok_or(ShadowError::BindingDrift)?));
            }
            if commitment {peers.push((5,assigned.remove(&retrieval_peer::EndpointKind::CommitRequest).ok_or(ShadowError::BindingDrift)?));}
            if spool{peers.push((6,assigned.remove(&retrieval_peer::EndpointKind::IngressAdmission).ok_or(ShadowError::BindingDrift)?));}
            if terminal{peers.push((7,assigned.remove(&retrieval_peer::EndpointKind::TerminalAppend).ok_or(ShadowError::BindingDrift)?));}
            if effects{for (index,kind) in [(8,retrieval_peer::EndpointKind::DispatchBarrier),(9,retrieval_peer::EndpointKind::ActiveEffectBarrier),
                (10,retrieval_peer::EndpointKind::ActiveEffectCommit)]{peers.push((index,assigned.remove(&kind).ok_or(ShadowError::BindingDrift)?));}}
            require(assigned.is_empty())?;Ok(peers)
        }
        _=>Err(ShadowError::CustodyUnavailable),
    }
}
pub(super) fn prepare_inspection(service:SelectedService,files:&FileAdmission,activation:&BTreeMap<String,OwnedFd>)
    ->Result<(Inspection,OwnedFd),ShadowError> {
    match service {
        selected @ (SelectedService::DispatchSpool(_)|SelectedService::ActiveEffectBarrier(_)|SelectedService::ActiveEffectCommit(_))=>{
            let (pin,kind,endpoint)=match selected {
                SelectedService::DispatchSpool(pin)=>(pin,admission::spool_signer::Kind::DispatchBarrier,retrieval_peer::EndpointKind::DispatchBarrier),
                SelectedService::ActiveEffectBarrier(pin)=>(pin,admission::spool_signer::Kind::ActiveEffectBarrier,retrieval_peer::EndpointKind::ActiveEffectBarrier),
                SelectedService::ActiveEffectCommit(pin)=>(pin,admission::spool_signer::Kind::ActiveEffectCommit,retrieval_peer::EndpointKind::ActiveEffectCommit),
                _=>return Err(ShadowError::BindingDrift),
            };
            let original=pin.open(admission::spool_signer::MAX_CONFIGURATION)?;let grant:admission::spool_signer::Configuration=exact(&original.read(admission::spool_signer::MAX_CONFIGURATION).map_err(fail)?)?;
            require(grant.kind()?==kind)?;grant.validate_shape()?;
            require(activation.len()==1)?;let socket=activation.get(endpoint.listener_name()).ok_or(ShadowError::BindingDrift)?;
            let (owner,remote)=retrieval_peer::Inspector::prepare_history_endpoint(original,grant.expected_peer().checked().map_err(fail)?,grant.guest_uid(),socket,endpoint)?;
            Ok((Inspection::Server(owner),remote))
        }
        selected @ (SelectedService::LedgerSpool(_)|SelectedService::CompletionLedgerSpool(_)|SelectedService::Ingress(_)|SelectedService::TerminalSpool(_))=>{
            let (pin,expected_kind,completion)=match selected {
                SelectedService::LedgerSpool(pin)=>(pin,admission::spool_signer::Kind::Ledger,false),
                SelectedService::CompletionLedgerSpool(pin)=>(pin,admission::spool_signer::Kind::Ledger,true),
                SelectedService::Ingress(pin)=>(pin,admission::spool_signer::Kind::Ingress,false),
                SelectedService::TerminalSpool(pin)=>(pin,admission::spool_signer::Kind::Terminal,true),
                _=>return Err(ShadowError::BindingDrift),
            };
            let original=pin.open(admission::spool_signer::MAX_CONFIGURATION)?;let grant:admission::spool_signer::Configuration=exact(&original.read(admission::spool_signer::MAX_CONFIGURATION).map_err(fail)?)?;
            let kind=grant.kind()?;grant.validate_shape()?;
            require(kind==expected_kind && grant.completion_selected()==completion)?;
            let endpoint=match kind{admission::spool_signer::Kind::Ingress=>retrieval_peer::EndpointKind::IngressAdmission,
                admission::spool_signer::Kind::Terminal=>retrieval_peer::EndpointKind::TerminalAppend,
                admission::spool_signer::Kind::Ledger=>retrieval_peer::EndpointKind::CommitRequest,
                _=>return Err(ShadowError::BindingDrift)};
            require(activation.len()==1)?;let socket=activation.get(endpoint.listener_name()).ok_or(ShadowError::BindingDrift)?;
            let (owner,remote)=retrieval_peer::Inspector::prepare_history_endpoint(original,grant.expected_peer().checked().map_err(fail)?,grant.guest_uid(),socket,endpoint)?;
            Ok((Inspection::Server(owner),remote))
        }
        selected @ (SelectedService::LedgerRetrieval(_)|SelectedService::CompletionRetrieval(_)|SelectedService::EffectRetrieval(_))=>{
            let completion=matches!(&selected,SelectedService::CompletionRetrieval(_)|SelectedService::EffectRetrieval(_));
            let effects=matches!(&selected,SelectedService::EffectRetrieval(_));
            let pin=match selected{SelectedService::LedgerRetrieval(pin)|SelectedService::CompletionRetrieval(pin)|SelectedService::EffectRetrieval(pin)=>pin,
                _=>return Err(ShadowError::BindingDrift)};
            require(activation.len()==4 && activation.contains_key("ledger-spool-store") && activation.contains_key("ledger-spool-lock")
                && activation.contains_key("retrieval-objects"))?;
            let original=pin.open(65536)?;let grant:admission::ledger_retrieval::Configuration=exact(&original.read(65536).map_err(fail)?)?;
            require(grant.completion_selected()==completion && grant.effects_selected()==effects)?;
            grant.validate_shape()?;let socket=activation.get("retrieval-listener").ok_or(ShadowError::BindingDrift)?;
            let (owner,remote)=retrieval_peer::Inspector::prepare_endpoint(original,grant.expected_peer().checked().map_err(fail)?,grant.guest_uid(),socket,retrieval_peer::EndpointKind::Retrieval)?;
            Ok((Inspection::Server(owner),remote))
        }
        SelectedService::CommitRequest(pin)=>{
            require(activation.len()==1)?;
            let original=pin.open(admission::commit_request::MAX_CONFIGURATION)?;
            let grant:admission::commit_request::Configuration=exact(&original.read(admission::commit_request::MAX_CONFIGURATION).map_err(fail)?)?;
            grant.validate_shape()?;
            let socket=activation.get("commit-request-listener").ok_or(ShadowError::BindingDrift)?;
            let (owner,remote)=retrieval_peer::Inspector::prepare_history_endpoint(original,
                grant.expected_peer().checked().map_err(fail)?,grant.guest_uid(),socket,retrieval_peer::EndpointKind::CommitRequest)?;
            Ok((Inspection::Server(owner),remote))
        }
        SelectedService::Generation(pin)=>{
            require(activation.len()==2 && activation.contains_key("generation-install-journal"))?;
            let original=pin.open(admission::generation_install::MAX_CONFIGURATION)?;
            let grant:admission::generation_install::Configuration=exact(&original.read(admission::generation_install::MAX_CONFIGURATION).map_err(fail)?)?;
            grant.validate_shape()?;
            let socket=activation.get("shadow-generation-install-listener").ok_or(ShadowError::BindingDrift)?;
            let (owner,remote)=retrieval_peer::Inspector::prepare_history_endpoint(original,
                grant.expected_peer().checked().map_err(fail)?,grant.guest_uid(),socket,retrieval_peer::EndpointKind::GenerationInstallEnvelope)?;
            Ok((Inspection::Server(owner),remote))
        }
        SelectedService::Retrieval(pin)=>{
            let (owner,remote)=retrieval_peer::Inspector::prepare(&pin,activation)?;
            Ok((Inspection::Server(owner),remote))
        }
        SelectedService::Persistence(pin)=>{
            require(activation.len()==2 && activation.contains_key("persistence-journal"))?;
            let original=pin.open(65536)?;
            let grant:admission::persistence::Configuration=exact(&original.read(65536).map_err(fail)?)?;
            grant.validate_shape()?;
            let socket=activation.get("persistence-listener").ok_or(ShadowError::BindingDrift)?;
            let (owner,remote)=retrieval_peer::Inspector::prepare_endpoint(original,
                grant.expected_peer().checked().map_err(fail)?,grant.guest_uid(),socket,retrieval_peer::EndpointKind::Persistence)?;
            Ok((Inspection::Server(owner),remote))
        }
        SelectedService::PersistenceLocked(pin)=>{
            require(activation.len()==3 && activation.contains_key("persistence-journal")
                && activation.contains_key("persistence-lock"))?;
            let original=pin.open(65536)?;
            let grant:admission::persistence::Configuration=exact(&original.read(65536).map_err(fail)?)?;
            grant.validate_shape()?;
            let socket=activation.get("persistence-listener").ok_or(ShadowError::BindingDrift)?;
            let (owner,remote)=retrieval_peer::Inspector::prepare_endpoint(original,
                grant.expected_peer().checked().map_err(fail)?,grant.guest_uid(),socket,retrieval_peer::EndpointKind::Persistence)?;
            Ok((Inspection::Server(owner),remote))
        }
        SelectedService::TrustedTime(pin)=>{
            require(activation.len()==1)?;
            let original=pin.open(65536)?;
            let grant:admission::trusted_time::Configuration=exact(&original.read(65536).map_err(fail)?)?;
            grant.validate_shape()?;
            let socket=activation.get("trusted-time-listener").ok_or(ShadowError::BindingDrift)?;
            let (owner,remote)=retrieval_peer::Inspector::prepare_endpoint(original,
                grant.expected_peer().checked().map_err(fail)?,grant.guest_uid(),socket,retrieval_peer::EndpointKind::TrustedTime)?;
            Ok((Inspection::Server(owner),remote))
        }
        SelectedService::ProofBridge(_)=>{
            let (owner,remote)=proof_client::Inspector::prepare(files,activation)?;
            Ok((Inspection::ProofClient(owner),remote))
        }
        SelectedService::CommitmentBridge(_)=>{
            let (owner,remote)=proof_client::Inspector::prepare_selected(files,activation,true)?;
            Ok((Inspection::ProofClient(owner),remote))
        }
        SelectedService::SpoolBridge(_)=>{
            let (owner,remote)=proof_client::Inspector::prepare_spool(files,activation)?;
            Ok((Inspection::ProofClient(owner),remote))
        }
        SelectedService::TerminalBridge(_)=>{
            let (owner,remote)=proof_client::Inspector::prepare_terminal(files,activation)?;
            Ok((Inspection::ProofClient(owner),remote))
        }
        SelectedService::ActiveEffectBridge(_)=>{
            proof_client::check_runtime_selection(files,false,false,false)?;
            let (owner,remote)=proof_client::Inspector::prepare_effects(files,activation)?;
            Ok((Inspection::ProofClient(owner),remote))
        }
        SelectedService::InitialHistoryBridge(_,helper_initial,native_terminal)=>{
            proof_client::check_runtime_selection(files,true,helper_initial,native_terminal)?;
            let (owner,remote)=proof_client::Inspector::prepare_effects(files,activation)?;
            Ok((Inspection::ProofClient(owner),remote))
        }
        _=>Err(ShadowError::CustodyUnavailable),
    }
}
fn check_activation(files:&FileAdmission,activation:&BTreeMap<String,OwnedFd>)->Result<(),ShadowError> {
    require(activation.len()==files.payload.activation.len())?;
    for e in &files.payload.activation {
        let fd=activation.get(&e.name).ok_or(ShadowError::BindingDrift)?;let mut s:libc::stat=unsafe{zeroed()};
        require(unsafe{libc::fstat(fd.as_raw_fd(),&mut s)}==0
            && (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid)==(e.device,e.inode,e.mode,e.uid,e.gid))?;
    }Ok(())
}
impl Drop for Cohort {
    fn drop(&mut self) {
        let mut good=true;
        for child in &mut self.children {good &= child.request_stop().is_ok();}
        for child in &mut self.children {good &= child.stop_and_reap().is_ok();}
        if !good {unsafe{libc::_exit(1);}}
    }
}
pub(super) fn run()->! {
    let result=(||{
        let control=Control::inherited()?;let mut cohort=Cohort::prepare(&control)?;
        let observations=cohort.observations()?;control.send(&observations,&cohort)?;
        let (release,rights)=control.receive(&cohort)?;
        cohort.release(&release,&observations,rights)?;
        cohort.hold(&control,&observations,&release)
    })();
    let status=if matches!(result,Ok(true)){0}else{1};
    unsafe{libc::_exit(status)}
}
