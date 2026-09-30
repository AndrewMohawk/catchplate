//! Explicit two-phase retrieval pair. The original children, executable
//! inodes, activation FDs and watchdog survive post-create signed assignment.
use super::*;
use std::fs::File;
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd,OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::mem::{size_of,size_of_val,zeroed};
#[path="retrieval_pair_inputs.rs"]
pub(super) mod inputs;
const MAX_WIRE:usize=32768;
const LAUNCH_PATH:&str="/etc/serverware/native-shadow-guest-launch.json";
const IMAGE_PATH:&str="/opt/serverware/native-shadow-custody-runtime.squashfs";
const SOURCE_API:&str="serverware.nativeShadowRetrievalPairOriginals/v1";

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
    fn send(&self,bytes:&[u8],pair:&Pair)->Result<(),ShadowError> {
        require(!bytes.is_empty() && bytes.len()<=MAX_WIRE)?;
        loop {
            pair.check_startup()?;self.check()?;
            if retrieval_peer::send(self.socket.as_fd(),bytes,&[])? {return Ok(());}
            wait(self.socket.as_fd(),libc::POLLOUT)?;
        }
    }
    fn receive(&self,pair:&Pair)->Result<(Vec<u8>,Vec<OwnedFd>),ShadowError> {
        loop {
            pair.check_startup()?;self.check()?;
            let mut bytes=vec![0;MAX_WIRE];let mut control=[0usize;96];
            let mut iov=libc::iovec{iov_base:bytes.as_mut_ptr().cast(),iov_len:bytes.len()};
            let mut message:libc::msghdr=unsafe{zeroed()};message.msg_iov=&mut iov;message.msg_iovlen=1;
            message.msg_control=control.as_mut_ptr().cast();message.msg_controllen=size_of_val(&control);
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
                if c.cmsg_len<base {good=false;break;}
                let length=c.cmsg_len-base;let data=unsafe{libc::CMSG_DATA(item)};
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
            require(good && rights_seen && (3..=128).contains(&rights.len())
                && retrieval_peer::same_credentials(&credentials.ok_or(ShadowError::BindingDrift)?,&self.peer))?;
            retrieval_peer::same_process(pidfd.ok_or(ShadowError::BindingDrift)?.as_fd(),self.peer.pid)?;
            bytes.truncate(count as usize);pair.check_startup()?;self.check()?;return Ok((bytes,rights));
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
    invocation_id:String,server:ChildOriginal,bridge:ChildOriginal}
struct Program {launch:Original,launch_bytes:Vec<u8>,image_original:Original,image:image::Image,
    files:FileAdmission,activation:BTreeMap<String,OwnedFd>,inspection:Inspection,remote:OwnedFd}
struct Pair {
    // Explicit Drop kills BOTH before either wait. Images/originals remain
    // fields until actual same-PIDFD terminal evidence and both reaps.
    children:Vec<child::Child>,programs:Vec<Program>,executables:[inputs::Executable;2],
    launch_target:Target,image_target:Target,admission:inputs::Admission,_watchdog:Watchdog,
}
impl Pair {
    fn prepare()->Result<Self,ShadowError> {
        let admission=inputs::Admission::open()?;let watchdog=Watchdog::arm_pair(&admission)?;
        let launch_target=Target::open(LAUNCH_PATH)?;let image_target=Target::open(IMAGE_PATH)?;
        let executables=[inputs::Executable::create(&admission)?,inputs::Executable::create(&admission)?];
        process::isolate_mounts()?;
        let mut owner=Self{children:Vec::new(),programs:Vec::new(),executables,launch_target,image_target,admission,_watchdog:watchdog};
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
        self.admission.check()?;self.launch_target.check()?;self.image_target.check()?;
        for (child,executable) in self.children.iter().zip(&self.executables) {require(child.check()?)?;executable.check()?;}
        for program in &self.programs {
            program.files.check().map_err(fail)?;program.image.check(&program.files)?;
            program.image_original.check().map_err(fail)?;
            require(program.launch.read(MAX_WIRE).map_err(fail)?.as_slice()==program.launch_bytes.as_slice())?;
            check_activation(&program.files,&program.activation)?;
        }Ok(())
    }
    fn observations(&self)->Result<Vec<u8>,ShadowError> {
        self.check_startup()?;require(self.children.len()==2 && self.programs.is_empty())?;
        let a=self.children[0].parked_identity()?;let b=self.children[1].parked_identity()?;
        let original=Observations{api_version:SOURCE_API,configuration_sha256:self.admission.configuration_sha256(),
            precreation_sha256:self.admission.precreation_sha256(),invocation_id:self.admission.invocation_id().into(),
            server:ChildOriginal{process_id:a.0,start_time_ticks:a.1,executable:self.executables[0].observation()?},
            bridge:ChildOriginal{process_id:b.0,start_time_ticks:b.1,executable:self.executables[1].observation()?}};
        let bytes=canonical_json_bytes(&original)?;self.check_startup()?;Ok(bytes)
    }
    fn release(&mut self,bytes:&[u8],observed:&[u8],rights:Vec<OwnedFd>)->Result<(),ShadowError> {
        require(self.observations()?==observed)?;
        let releases=self.admission.release(bytes,observed)?;
        let mut rights=rights.into_iter();let mut all=BTreeSet::new();
        for (index,release) in releases.into_iter().enumerate() {
            self.check_startup()?;
            let launch=release.launch.open(MAX_WIRE)?;let launch_bytes=launch.read(MAX_WIRE).map_err(fail)?.to_vec();
            let (selected,service)=selection(&launch_bytes)?;
            let files=admit_files(&selected.delivery_configuration.path,selected.delivery_configuration.sha256.clone(),
                &selected.delivery.path,selected.delivery.sha256.clone()).map_err(fail)?;
            self.admission.join(index,&selected,&files)?;
            require((index==0 && matches!(&service,SelectedService::Retrieval(_)))
                || (index==1 && matches!(&service,SelectedService::RetrievalBridge)))?;
            let mut activation=BTreeMap::new();
            for (slot,entry) in files.payload.activation.iter().enumerate() {
                require(entry.fd==6+slot as i32)?;
                let fd=rights.next().ok_or(ShadowError::BindingDrift)?;
                let mut stat:libc::stat=unsafe{zeroed()};
                require(unsafe{libc::fstat(fd.as_raw_fd(),&mut stat)}==0
                    && (stat.st_dev,stat.st_ino,stat.st_mode,stat.st_uid,stat.st_gid)==(entry.device,entry.inode,entry.mode,entry.uid,entry.gid)
                    && [libc::S_IFDIR,libc::S_IFSOCK].contains(&(stat.st_mode&libc::S_IFMT))
                    && all.insert((stat.st_dev,stat.st_ino))
                    && activation.insert(entry.name.clone(),fd).is_none())?;
            }
            let peer=match &service {
                SelectedService::Retrieval(pin)=>{
                    let original=pin.open(65536)?;
                    let grant:super::super::super::native_keys::admission::retrieval::Configuration=exact(&original.read(65536).map_err(fail)?)?;
                    grant.validate_shape()?;grant.expected_peer().clone()
                },
                SelectedService::RetrievalBridge=>{
                    retrieval_client::assigned_peer(&files)?
                },
                _=>return Err(ShadowError::BindingDrift),
            };
            let other=1-index;let actual=self.children[other].parked_identity()?;
            require((peer.pid,peer.start_time_ticks)==actual)?;
            self.executables[other].require_peer(&peer)?;
            // UID/GID, cgroup and SO_PEERSEC are independently assigned future
            // expectations, NOT measurements of this still-root trampoline.
            // Both real serving inspectors enforce the full unchanged peer14.
            let expected_uid=self.admission.role_identity(other)?;
            require((peer.uid,peer.gid)==expected_uid)?;
            let (inspection,remote)=match service {
                SelectedService::Retrieval(pin)=>{
                    let (owner,remote)=retrieval_peer::Inspector::prepare(&pin,&activation)?;
                    (Inspection::Server(owner),remote)
                },
                SelectedService::RetrievalBridge=>{
                    let (owner,remote)=retrieval_client::Inspector::prepare(&files,&activation)?;
                    (Inspection::Client(owner),remote)
                },
                _=>return Err(ShadowError::BindingDrift),
            };
            let image_original=release.image.open(512*1024*1024)?;
            image_original.read(512*1024*1024).map_err(fail)?;
            let view=View::bind(&self.image_target,&image_original)?;
            let image=image::Image::prepare_pair(&selected.closure,&files,self.executables[index].fd(),
                &release.image.sha256,self.admission.executable_sha256())?;
            view.retire()?;
            self.programs.push(Program{launch,launch_bytes,image_original,image,files,activation,inspection,remote});
        }
        require(rights.next().is_none() && self.programs.len()==2)?;
        self.check_startup()?;
        // All signed originals and BOTH parked actual targets are joined
        // before the first effect. Failure of either send kills/reaps both;
        // it cannot be represented as an atomic two-process readiness claim.
        for index in 0..2 {
            self.check_startup()?;
            let p=&self.programs[index];
            let ordered=p.files.payload.activation.iter().map(|e|
                p.activation.get(&e.name).map(AsFd::as_fd).ok_or(ShadowError::BindingDrift)).collect::<Result<Vec<_>,_>>()?;
            self.children[index].release_pair(p.launch.descriptor(),p.image_original.descriptor(),p.remote.as_fd(),&ordered)?;
        }
        Ok(())
    }
    fn hold(&mut self)->Result<(),ShadowError> {
        loop {
            if now()?>=self.admission.lifetime()-REAP_RESERVE_NS {return Ok(());}
            self.check()?;
            for (program,child) in self.programs.iter_mut().zip(&self.children) {
                program.inspection.progress(child,&program.files)?;
            }
            let result=unsafe{libc::poll(std::ptr::null_mut(),0,10)};
            require(result==0 || (result<0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR)))?;
        }
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
impl Drop for Pair {
    fn drop(&mut self) {
        let mut good=true;
        for child in &mut self.children {good &= child.request_stop().is_ok();}
        for child in &mut self.children {good &= child.stop_and_reap().is_ok();}
        if !good {unsafe{libc::_exit(1);}}
    }
}
pub(super) fn run()->! {
    let result=(||{
        let control=Control::inherited()?;let mut pair=Pair::prepare()?;
        let observations=pair.observations()?;control.send(&observations,&pair)?;
        let (release,rights)=control.receive(&pair)?;
        pair.release(&release,&observations,rights)?;
        drop(control);pair.hold()
    })();
    let _:Result<(),ShadowError>=result;
    unsafe{libc::_exit(1)}
}
