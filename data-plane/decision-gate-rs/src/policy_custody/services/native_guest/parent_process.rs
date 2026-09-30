//! Fixed clone3/execveat trampoline and same-PIDFD terminal/reap ownership.
use super::*;
use std::mem::{size_of,zeroed};
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd,OwnedFd};
#[path="parent_parked.rs"]
mod parked;

fn duplicate(fd:BorrowedFd<'_>)->Result<OwnedFd,ShadowError> {
    let raw=unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_DUPFD_CLOEXEC,128)};
    require(raw>=128)?;Ok(unsafe{OwnedFd::from_raw_fd(raw)})
}
fn pair()->Result<(OwnedFd,OwnedFd),ShadowError> {
    let mut fds=[-1;2];
    require(unsafe{libc::socketpair(libc::AF_UNIX,libc::SOCK_SEQPACKET|libc::SOCK_CLOEXEC,0,fds.as_mut_ptr())}==0)?;
    Ok(unsafe{(OwnedFd::from_raw_fd(fds[0]),OwnedFd::from_raw_fd(fds[1]))})
}
#[repr(C)]
#[derive(Default)]
struct CloneArgs {flags:u64,pidfd:u64,child_tid:u64,parent_tid:u64,exit_signal:u64,stack:u64,
    stack_size:u64,tls:u64,set_tid:u64,set_tid_size:u64,cgroup:u64}
#[repr(C)]
struct Action {handler:usize,flags:usize,restorer:usize,mask:u64}
struct PreparedChild {parent:i32,channel:OwnedFd,gate:OwnedFd,executable:OwnedFd,null:OwnedFd,
    activation:Vec<OwnedFd>,inspection:Option<OwnedFd>}
impl PreparedChild {
    unsafe fn enter(&self)->! {
        let mut good=unsafe{libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)}==0
            && unsafe{libc::getppid()}==self.parent;
        // Close-on-exec every inherited original BEFORE installing the exact
        // unmarked FD3 and signed activation slots. All sources are >=128.
        good &= unsafe{libc::syscall(libc::SYS_close_range,3u32,u32::MAX,4u32)}==0;
        good &= unsafe{libc::dup3(self.channel.as_raw_fd(),3,0)}==3;
        if let Some(fd)=&self.inspection {good &= unsafe{libc::dup3(fd.as_raw_fd(),4,0)}==4;}
        for (index,fd) in self.activation.iter().enumerate() {
            good &= unsafe{libc::dup3(fd.as_raw_fd(),6+index as i32,0)}==6+index as i32;
        }
        for target in [0,1,2] {good &= unsafe{libc::dup3(self.null.as_raw_fd(),target,0)}==target;}
        let action=Action{handler:0,flags:0,restorer:0,mask:0};
        for signal in 1..=64 {if signal!=libc::SIGKILL && signal!=libc::SIGSTOP {
            good &= unsafe{libc::syscall(libc::SYS_rt_sigaction,signal,&action,std::ptr::null::<u8>(),8usize)}==0;
        }}
        let mask=0u64;
        good &= unsafe{libc::syscall(libc::SYS_rt_sigprocmask,libc::SIG_SETMASK,&mask,std::ptr::null::<u8>(),8usize)}==0;
        good &= unsafe{libc::chdir(c"/".as_ptr())}==0;
        // This byte is clone-owner ordering only, never new authority/time.
        let mut byte=0u8;
        good &= unsafe{libc::read(self.gate.as_raw_fd(),(&mut byte as *mut u8).cast(),1)}==1 && byte==0xa5;
        good &= unsafe{libc::getppid()}==self.parent;
        if good {
            let argv=[c"serverware-policy-shadow-custody-guest".as_ptr(),std::ptr::null()];
            let env:[*const libc::c_char;1]=[std::ptr::null()];
            unsafe{libc::syscall(libc::SYS_execveat,self.executable.as_raw_fd(),c"".as_ptr(),
                argv.as_ptr(),env.as_ptr(),libc::AT_EMPTY_PATH);}
        }
        unsafe{libc::syscall(libc::SYS_exit_group,127);}
        loop {std::hint::spin_loop();}
    }
}
pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) struct Child {
    channel:OwnedFd,pidfd:OwnedFd,gate:Option<OwnedFd>,pid:i32,parent:i32,start:Option<u64>,
    deadline:u64,reaped:bool,pair_mode:bool,
}
impl Child {
    pub(super) fn spawn(executable:BorrowedFd<'_>,activation:&[BorrowedFd<'_>],inspection:Option<BorrowedFd<'_>>,
        deadline:u64)->Result<Self,ShadowError> {
        require(cfg!(target_arch="x86_64") && !activation.is_empty() && activation.len()<=64 && now()?<deadline)?;
        let mut disposition:libc::sigaction=unsafe{zeroed()};
        require(unsafe{libc::sigaction(libc::SIGCHLD,std::ptr::null(),&mut disposition)}==0
            && disposition.sa_sigaction==libc::SIG_DFL && disposition.sa_flags&libc::SA_NOCLDWAIT==0)?;
        let (channel,remote)=pair()?;let mut gate=[-1;2];
        require(unsafe{libc::pipe2(gate.as_mut_ptr(),libc::O_CLOEXEC)}==0)?;
        let (read,write)=unsafe{(OwnedFd::from_raw_fd(gate[0]),OwnedFd::from_raw_fd(gate[1]))};
        let raw=unsafe{libc::open(c"/dev/null".as_ptr(),libc::O_RDWR|libc::O_CLOEXEC|libc::O_NOFOLLOW)};
        require(raw>=0)?;let null=unsafe{OwnedFd::from_raw_fd(raw)};
        let mut stat:libc::stat=unsafe{zeroed()};
        require(unsafe{libc::fstat(null.as_raw_fd(),&mut stat)}==0 && stat.st_mode&libc::S_IFMT==libc::S_IFCHR
            && libc::major(stat.st_rdev)==1 && libc::minor(stat.st_rdev)==3 && stat.st_uid==0 && stat.st_gid==0)?;
        let parent=unsafe{libc::getpid()};
        let prepared=PreparedChild{parent,channel:duplicate(remote.as_fd())?,gate:duplicate(read.as_fd())?,
            executable:duplicate(executable)?,null:duplicate(null.as_fd())?,
            activation:activation.iter().map(|fd|duplicate(*fd)).collect::<Result<_,_>>()?,
            inspection:inspection.map(duplicate).transpose()?};
        let mut pidfd=-1i32;
        let args=CloneArgs{flags:libc::CLONE_PIDFD as u64,pidfd:(&mut pidfd as *mut i32) as u64,
            exit_signal:libc::SIGCHLD as u64,..CloneArgs::default()};
        let pid=unsafe{libc::syscall(libc::SYS_clone3,&args,size_of::<CloneArgs>())};
        if pid==0 {unsafe{prepared.enter();}}
        // Positive clone result with no kernel PIDFD is impossible under this
        // fixed ABI; exit fail-closed, never fall back to a numeric PID kill.
        if pid>0 && pidfd<0 {unsafe{libc::_exit(1);}}
        require(pid>0 && pidfd>=0)?;
        Ok(Self{channel,pidfd:unsafe{OwnedFd::from_raw_fd(pidfd)},gate:Some(write),pid:pid as i32,
            parent,start:None,deadline,reaped:false,pair_mode:false})
    }
    fn terminal(&self,consume:bool)->Result<Option<(i32,i32)>,ShadowError> {
        require(unsafe{libc::getpid()}==self.parent && !self.reaped)?;
        let mut info:libc::siginfo_t=unsafe{zeroed()};
        let flags=libc::WEXITED|libc::WNOHANG|(if consume{0}else{libc::WNOWAIT});
        require(unsafe{libc::waitid(libc::P_PIDFD,self.pidfd.as_raw_fd() as _,&mut info,flags)}==0)?;
        if unsafe{info.si_pid()}==0 {return Ok(None);}
        require(unsafe{info.si_pid()}==self.pid && info.si_signo==libc::SIGCHLD
            && matches!(info.si_code,libc::CLD_EXITED|libc::CLD_KILLED|libc::CLD_DUMPED))?;
        Ok(Some((info.si_code,unsafe{info.si_status()})))
    }
    fn identity(&self)->Result<u64,ShadowError> {
        // This selector is the actual clone3 return, never an API input.
        let stat=std::fs::read_to_string(format!("/proc/{}/stat",self.pid)).map_err(fail)?;
        let (pid,_)=stat.split_once(' ').ok_or(ShadowError::BindingDrift)?;
        require(pid.parse::<i32>().map_err(fail)?==self.pid)?;
        let (_,fields)=stat.rsplit_once(") ").ok_or(ShadowError::BindingDrift)?;
        let fields:Vec<_>=fields.split_whitespace().collect();require(fields.len()>=20)?;
        require(fields[1].parse::<i32>().map_err(fail)?==self.parent)?;
        let start=fields[19].parse::<u64>().map_err(fail)?;require(start>0)?;
        let info=std::fs::read_to_string(format!("/proc/self/fdinfo/{}",self.pidfd.as_raw_fd())).map_err(fail)?;
        let pids:Vec<_>=info.lines().filter_map(|v|v.strip_prefix("Pid:")).collect();
        require(pids.len()==1 && pids[0].trim().parse::<i32>().map_err(fail)?==self.pid)?;Ok(start)
    }
    pub(super) fn release(&mut self)->Result<(),ShadowError> {
        require(!self.pair_mode && now()?<self.deadline && self.gate.is_some() && self.start.is_none() && self.terminal(false)?.is_none())?;
        let start=self.identity()?;self.start=Some(start);
        require(self.identity()?==start && self.terminal(false)?.is_none())?;
        let gate=self.gate.take().ok_or(ShadowError::BindingDrift)?;let byte=0xa5u8;
        require(unsafe{libc::write(gate.as_raw_fd(),(&byte as *const u8).cast(),1)}==1)
    }
    pub(super) fn check(&self)->Result<bool,ShadowError> {
        require(now()?<self.deadline && self.start.is_some())?;
        if self.terminal(false)?.is_some(){return Ok(false);}
        require(Some(self.identity()?)==self.start)?;
        let mut poll=libc::pollfd{fd:self.channel.as_raw_fd(),events:libc::POLLIN,revents:0};
        require(unsafe{libc::poll(&mut poll,1,0)}>=0)?;
        // The private lifetime channel has no message/readiness protocol.
        require(poll.revents==0)?;Ok(true)
    }
    pub(super) fn request_stop(&mut self)->Result<(),ShadowError> {
        require(unsafe{libc::getpid()}==self.parent)?;if self.reaped{return Ok(());}
        unsafe{libc::shutdown(self.channel.as_raw_fd(),libc::SHUT_RDWR);}
        self.gate.take();
        let killed=unsafe{libc::syscall(libc::SYS_pidfd_send_signal,self.pidfd.as_raw_fd(),libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),0)};
        require(killed==0 || std::io::Error::last_os_error().raw_os_error()==Some(libc::ESRCH))?;
        Ok(())
    }
    pub(super) fn stop_and_reap(&mut self)->Result<(),ShadowError> {
        require(unsafe{libc::getpid()}==self.parent)?;if self.reaped{return Ok(());}
        self.request_stop()?;
        loop {
            if let Some(expected)=self.terminal(false)? {
                require(self.terminal(true)?==Some(expected))?;self.reaped=true;return Ok(());
            }
            require(now()?<self.deadline)?;
            let mut wait=libc::pollfd{fd:self.pidfd.as_raw_fd(),events:libc::POLLIN,revents:0};
            let result=unsafe{libc::poll(&mut wait,1,1)};
            require(result>=0 || std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR))?;
        }
    }
    pub(super) fn precreate(executable:BorrowedFd<'_>,launch_target:BorrowedFd<'_>,image_target:BorrowedFd<'_>,
        startup:u64,deadline:u64)->Result<Self,ShadowError> {parked::spawn(executable,launch_target,image_target,startup,deadline)}
    pub(super) fn parked_identity(&self)->Result<(i32,u64),ShadowError> {
        require(self.pair_mode && self.gate.is_some() && self.check()?)?;
        Ok((self.pid,self.identity()?))
    }
    pub(super) fn release_pair(&mut self,launch:BorrowedFd<'_>,image:BorrowedFd<'_>,inspection:BorrowedFd<'_>,
        activation:&[BorrowedFd<'_>])->Result<(),ShadowError> {
        self.parked_identity()?;parked::release(self,launch,image,inspection,activation)
    }
    pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) fn require_inspection_sender(
        &self,packet:&retrieval_peer::Packet,uid:u32,gid:u32)->Result<(),ShadowError> {
        require(self.check()? && packet.credentials.pid==self.pid
            && packet.credentials.uid==uid && packet.credentials.gid==gid)?;
        retrieval_peer::same_process(packet.pidfd.as_fd(),self.pid)?;
        // self.identity rechecks the actual clone PIDFD/start/parent original;
        // no wire PID or ready DTO is accepted as child ownership.
        require(Some(self.identity()?)==self.start && self.terminal(false)?.is_none())
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        // Never release a caller's image because a timeout looked like death.
        // The original absolute parent watchdog and PDEATHSIG remain armed.
        if self.stop_and_reap().is_err(){unsafe{libc::_exit(1);}}
    }
}
