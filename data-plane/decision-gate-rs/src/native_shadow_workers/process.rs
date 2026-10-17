//! Owned pre-drop worker clone, no application callback between clone and exec.
use super::{image::Sealed, transport as ipc, wire::{now,require}};
use std::{mem::{size_of,zeroed}, os::fd::{AsRawFd,OwnedFd,FromRawFd},sync::atomic::{AtomicBool,Ordering}};
#[repr(C)]
#[derive(Default)]
struct CloneArgs { flags:u64,pidfd:u64,child_tid:u64,parent_tid:u64,exit_signal:u64,stack:u64,stack_size:u64,tls:u64,set_tid:u64,set_tid_size:u64,cgroup:u64 }
#[repr(C)]
struct Action { handler:usize,flags:usize,restorer:usize,mask:u64 }
unsafe fn child(parent:i32,source:&[OwnedFd;6],webauthn:Option<&OwnedFd>,publication:Option<&[OwnedFd;3]>,runtime:Option<&[OwnedFd;3]>)->! {
    let mut good=unsafe {libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL,0,0,0)}==0 && unsafe {libc::getppid()}==parent;
    for (i,target) in [3,5,6,8].iter().enumerate() {good &= unsafe {libc::dup3(source[i].as_raw_fd(),*target,0)}==*target;}
    if let Some(webauthn)=webauthn {
        good &= unsafe {libc::dup3(webauthn.as_raw_fd(),7,0)}==7;
    } else {
        unsafe {libc::close(7);}
    }
    let action=Action {handler:0,flags:0,restorer:0,mask:0};
    for signal in 1..=64 {if signal!=libc::SIGKILL && signal!=libc::SIGSTOP {
        good &= unsafe {libc::syscall(libc::SYS_rt_sigaction,signal,&action,std::ptr::null::<u8>(),8usize)}==0;
    }}
    let mask=0u64;
    good &= unsafe {libc::syscall(libc::SYS_rt_sigprocmask,libc::SIG_SETMASK,&mask,std::ptr::null::<u8>(),8usize)}==0;
    good &= unsafe {libc::chdir(c"/".as_ptr())}==0;
    for fd in [0,1,2] {good &= unsafe {libc::dup3(source[5].as_raw_fd(),fd,0)}==fd;}
    unsafe {libc::close(4);}
    good &= unsafe {libc::syscall(libc::SYS_close_range,9u32,u32::MAX,4u32)}==0;
    // Only the explicitly admitted publication profile keeps these originals.
    // All duplicated sources are >=20, so fixed targets cannot overwrite them.
    if let Some(resources)=publication {
        for (source,target) in resources.iter().zip([9,10,11]) {
            good &= unsafe {libc::dup3(source.as_raw_fd(),target,0)}==target;
        }
    }
    // Runtime's separate policy/key/roots roster is never selected by a job.
    if let Some(resources)=runtime {
        for (source,target) in resources.iter().zip([12,13,14]) {
            good &= unsafe {libc::dup3(source.as_raw_fd(),target,0)}==target;
        }
    }
    if good {
        let argv=[c"catchplate-native-shadow-worker".as_ptr(),std::ptr::null()];
        let env:[*const libc::c_char;1]=[std::ptr::null()];
        unsafe {libc::syscall(libc::SYS_execveat,source[4].as_raw_fd(),c"".as_ptr(),argv.as_ptr(),env.as_ptr(),libc::AT_EMPTY_PATH);}
    }
    unsafe {libc::syscall(libc::SYS_exit_group,127);}
    loop {std::hint::spin_loop();}
}
pub(super) struct Process {
    pub(super) channel:OwnedFd,pub(super) pidfd:OwnedFd,pub(super) pid:i32,
    creator:i32,deadline:u64,stopped:AtomicBool,reaped:AtomicBool,
}
impl Process {
    pub(super) fn spawn(image:&Sealed,bootstrap:&Sealed,commands:&[Option<&Sealed>;3],prepared:&crate::native_serving_privileges::Prepared,
        publication:Option<&super::publication_resources::ColdResources>,
        runtime:Option<&super::runtime_resources::ColdResources>)->Result<Self,String> {
        prepared.check()?; image.check()?;bootstrap.check()?;
        for command in commands.iter().flatten() {command.check()?;}
        let runtime_command=commands[0].ok_or("runtime command absent")?;
        let publication_command=commands[2].ok_or("publication command absent")?;
        require(commands[1].is_some() || publication.is_some() && runtime.is_some())?;
        let mut disposition:libc::sigaction=unsafe {zeroed()};
        require(unsafe {libc::sigaction(libc::SIGCHLD,std::ptr::null(),&mut disposition)}==0
            && disposition.sa_sigaction==libc::SIG_DFL && disposition.sa_flags&libc::SA_NOCLDWAIT==0)?;
        let (channel,remote)=ipc::pair()?;
        let null=unsafe {libc::open(c"/dev/null".as_ptr(),libc::O_RDWR|libc::O_CLOEXEC|libc::O_NOFOLLOW)};
        require(null>=0)?;let null=unsafe {OwnedFd::from_raw_fd(null)};
        let mut metadata:libc::stat=unsafe {zeroed()};
        require(unsafe {libc::fstat(null.as_raw_fd(),&mut metadata)}==0 && metadata.st_mode&libc::S_IFMT==libc::S_IFCHR
            && libc::major(metadata.st_rdev)==1 && libc::minor(metadata.st_rdev)==3 && metadata.st_uid==0 && metadata.st_gid==0)?;
        let sources=[ipc::duplicate(remote.as_raw_fd())?,ipc::duplicate(bootstrap.file.as_raw_fd())?,
            ipc::duplicate(runtime_command.file.as_raw_fd())?,ipc::duplicate(publication_command.file.as_raw_fd())?,
            ipc::duplicate(image.file.as_raw_fd())?,ipc::duplicate(null.as_raw_fd())?];
        let webauthn=commands[1].map(|command|ipc::duplicate(command.file.as_raw_fd())).transpose()?;
        let publication=publication.map(|resources|resources.descriptors()).transpose()?;
        let runtime=runtime.map(|resources|resources.descriptors()).transpose()?;
        let creator=unsafe {libc::getpid()}; let mut pidfd=-1i32;
        let args=CloneArgs {flags:libc::CLONE_PIDFD as u64,pidfd:(&mut pidfd as *mut i32) as u64,exit_signal:libc::SIGCHLD as u64,..CloneArgs::default()};
        prepared.check()?;
        let pid=unsafe {libc::syscall(libc::SYS_clone3,&args,size_of::<CloneArgs>())};
        if pid==0 {unsafe {child(creator,&sources,webauthn.as_ref(),publication.as_ref(),runtime.as_ref());}}
        require(pid>0 && pidfd>=0)?;
        let process=Self {channel,pidfd:unsafe {OwnedFd::from_raw_fd(pidfd)},pid:pid as i32,creator,deadline:prepared.deadline(),
            stopped:AtomicBool::new(false),reaped:AtomicBool::new(false)};
        drop(sources);drop(webauthn);drop(publication);drop(runtime);drop(remote);
        prepared.check()?; process.check()?; Ok(process)
    }
    pub(super) fn check(&self)->Result<(),String> {
        require(unsafe {libc::getpid()}==self.creator && !self.stopped.load(Ordering::Acquire)
            && !self.reaped.load(Ordering::Acquire) && now()?<self.deadline)?;
        ipc::ensure_pidfd_alive(&self.pidfd).map_err(|_| "native shadow worker exited".into())
    }
    pub(super) fn authenticate(&self,packet:&ipc::Packet)->Result<(),String> {
        self.check()?;
        require(packet.credentials.pid==self.pid && packet.credentials.uid==super::UID && packet.credentials.gid==super::UID)?;
        ipc::prove_owned_process(&self.pidfd,&packet.sender,self.pid).map_err(|_| "shadow packet differs from cloned worker".into())
    }
    pub(super) fn stop(&self) {
        if unsafe {libc::getpid()}!=self.creator || self.stopped.swap(true,Ordering::AcqRel) {return;}
        unsafe {libc::shutdown(self.channel.as_raw_fd(),libc::SHUT_RDWR);
            libc::syscall(libc::SYS_pidfd_send_signal,self.pidfd.as_raw_fd(),libc::SIGKILL,std::ptr::null::<libc::siginfo_t>(),0);}
    }
    fn reap(&self)->Result<bool,String> {
        require(unsafe {libc::getpid()}==self.creator)?;
        if self.reaped.load(Ordering::Acquire) {return Ok(true);}
        let mut info:libc::siginfo_t=unsafe {zeroed()};
        require(unsafe {libc::waitid(libc::P_PIDFD,self.pidfd.as_raw_fd() as _,&mut info,libc::WEXITED|libc::WNOHANG)}==0)?;
        if unsafe {info.si_pid()}==0 {return Ok(false);}
        require(unsafe {info.si_pid()}==self.pid && info.si_signo==libc::SIGCHLD
            && matches!(info.si_code,libc::CLD_EXITED|libc::CLD_KILLED|libc::CLD_DUMPED))?;
        self.reaped.store(true,Ordering::Release);Ok(true)
    }
    pub(super) fn stop_and_reap(&self)->Result<(),String> {
        self.stop();
        loop {
            let reaped=self.reap()?;
            require(now()?<self.deadline)?;
            if reaped {return Ok(());}
            let mut poll=libc::pollfd {fd:self.pidfd.as_raw_fd(),events:libc::POLLIN,revents:0};
            let result=unsafe {libc::poll(&mut poll,1,10)};
            require(result>=0 || std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR))?;
        }
    }
}
impl Drop for Process {fn drop(&mut self) {let _=self.stop_and_reap();}}
