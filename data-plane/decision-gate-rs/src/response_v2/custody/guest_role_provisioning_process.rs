//! One boot-only, fixed-image child. Never a serving broker or importable PID.
use super::guest_role_provisioning::{ensure,live,now};
use crate::native_secret_broker_v1::{ImageConfiguration,image::{Image,Purpose}};
use std::{ffi::CString,fs::File,io::{self,Read,Write},os::{fd::{AsRawFd,FromRawFd,OwnedFd,RawFd},
    unix::{net::UnixStream,process::CommandExt}},process::{Child,Command,Stdio}};

const FIRST_FD:i32=64;
const HELPER:&str="/opt/serverware/serverware/native_role_key_provisioner.py";
fn io_error(_:io::Error)->String{"role provisioner original process I/O failed".to_owned()}
fn owned(fd:i32)->Result<OwnedFd,String>{ensure(fd>=0,"role provisioner descriptor unavailable")?;Ok(unsafe{OwnedFd::from_raw_fd(fd)})}
#[repr(C)] struct CapabilityHeader { version:u32,pid:i32 }
#[repr(C)] #[derive(Clone,Copy)] struct CapabilityData {effective:u32,permitted:u32,inheritable:u32}

// Reserve every target number before constructing the child/error pipe. No
// dup2 in the child can overwrite Command's genuine exec-error handshake.
pub(super) struct Slots { files:Vec<OwnedFd> }
impl Slots {
    pub(super) fn reserve(count:usize)->Result<Self,String>{
        ensure((7..=64).contains(&count),"role provisioner slot count differs")?;
        let seed=File::open("/dev/null").map_err(io_error)?;
        let mut files=Vec::new();
        for index in 0..count {
            let target=FIRST_FD+index as i32;
            let fd=owned(unsafe{libc::fcntl(seed.as_raw_fd(),libc::F_DUPFD_CLOEXEC,target)})?;
            ensure(fd.as_raw_fd()==target,"fixed role output descriptor range is occupied")?;
            files.push(fd);
        }
        Ok(Self{files})
    }
}

pub(super) struct Process {
    image:Image, child:Child, pidfd:OwnedFd, channel:UnixStream, creator:libc::pid_t,
    deadline:u64,last:u64,poisoned:bool,reaped:bool,
}
impl Process {
    pub(super) fn spawn(config:&ImageConfiguration,writers:Vec<File>,slots:Slots,deadline:u64)->Result<Self,String>{
        live(deadline)?;
        ensure(unsafe{libc::geteuid()}==0 && unsafe{libc::getegid()}==0
            && writers.len()==slots.files.len(),"role provisioner requires its root-owned output set")?;
        let image=Image::open_for(config,deadline,Purpose::RoleKeyProvisioner)?;
        let mut inherited=Vec::new();
        for file in writers {inherited.push(owned(unsafe{libc::fcntl(file.as_raw_fd(),libc::F_DUPFD_CLOEXEC,256)})?);}
        let sources:Vec<RawFd>=inherited.iter().map(AsRawFd::as_raw_fd).collect();
        let executable=owned(unsafe{libc::fcntl(image.interpreter.as_raw_fd(),libc::F_DUPFD_CLOEXEC,512)})?;
        let executable_fd=executable.as_raw_fd(); let root=image.root.as_raw_fd();
        let (channel,child_channel)=UnixStream::pair().map_err(io_error)?;
        channel.set_nonblocking(true).map_err(io_error)?;
        let child_fd=child_channel.as_raw_fd(); let parent=unsafe{libc::getpid()};
        let args=[CString::new("/usr/local/bin/python3.11").unwrap(),CString::new("-I").unwrap(),
            CString::new("-B").unwrap(),CString::new(HELPER).unwrap()];
        let mut command=Command::new("/role-key-exec-is-source-owned");
        command.env_clear().stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        unsafe{command.pre_exec(move||{
            if libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)!=0 || libc::getppid()!=parent
                || libc::fchdir(root)!=0 || libc::chroot(b".\0".as_ptr().cast())!=0
                || libc::chdir(b"/\0".as_ptr().cast())!=0 || libc::dup2(child_fd,3)!=3
                || libc::setgroups(0,std::ptr::null())!=0 {return Err(io::Error::last_os_error());}
            for (index,source) in sources.iter().enumerate(){
                let target=FIRST_FD+index as i32;
                if libc::dup2(*source,target)!=target{return Err(io::Error::last_os_error());}
            }
            for capability in 0..=40 {if libc::prctl(libc::PR_CAPBSET_DROP,capability,0,0,0)!=0{return Err(io::Error::last_os_error());}}
            for (resource,limit) in [(libc::RLIMIT_CORE,0),(libc::RLIMIT_FSIZE,32),(libc::RLIMIT_NPROC,1),
                (libc::RLIMIT_NOFILE,1024),(libc::RLIMIT_AS,512*1024*1024)] {
                let value=libc::rlimit{rlim_cur:limit,rlim_max:limit};
                if libc::setrlimit(resource,&value)!=0{return Err(io::Error::last_os_error());}
            }
            if libc::setresgid(64989,64989,64989)!=0 || libc::setresuid(64989,64989,64989)!=0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0 || libc::prctl(libc::PR_SET_DUMPABLE,0,0,0,0)!=0
                || libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)!=0 || libc::getppid()!=parent{return Err(io::Error::last_os_error());}
            let header=CapabilityHeader{version:0x2008_0522,pid:0};
            let data=[CapabilityData{effective:0,permitted:0,inheritable:0};2];
            if libc::syscall(libc::SYS_capset,&header,data.as_ptr())!=0
                || libc::syscall(libc::SYS_close_range,3u32,u32::MAX,4u32)!=0
                || libc::fcntl(3,libc::F_SETFD,0)!=0{return Err(io::Error::last_os_error());}
            for index in 0..sources.len(){if libc::fcntl(FIRST_FD+index as i32,libc::F_SETFD,0)!=0{return Err(io::Error::last_os_error());}}
            let argv=[args[0].as_ptr(),args[1].as_ptr(),args[2].as_ptr(),args[3].as_ptr(),std::ptr::null()];
            let env:[*const libc::c_char;1]=[std::ptr::null()];
            libc::syscall(libc::SYS_execveat,executable_fd,b"\0".as_ptr().cast::<libc::c_char>(),argv.as_ptr(),env.as_ptr(),libc::AT_EMPTY_PATH);
            Err(io::Error::last_os_error())
        });}
        // No fallible clock read may escape after spawn but before ownership.
        let started=now()?;ensure(started<deadline,"role helper spawn lost original interval")?;
        let mut child=command.spawn().map_err(io_error)?;
        drop(inherited);drop(executable);drop(child_channel);drop(slots);
        let fd=unsafe{libc::syscall(libc::SYS_pidfd_open,child.id(),0) as RawFd};
        if fd<0 {let _=child.kill();let _=child.try_wait();return Err("role provisioner child PIDFD unavailable; no timely reap claim".into());}
        let mut result=Self{image,child,pidfd:owned(fd)?,channel,creator:parent,deadline,last:started,poisoned:false,reaped:false};
        result.check()?;Ok(result)
    }
    fn check(&mut self)->Result<(),String>{
        ensure(!self.poisoned && !self.reaped && unsafe{libc::getpid()}==self.creator,"role provisioner owner changed")?;
        let current=now()?;ensure(current>=self.last && current<self.deadline,"role provisioner original interval expired")?;
        self.last=current;self.image.check(self.deadline)
    }
    fn wait_io(&mut self,events:i16)->Result<(),String>{
        self.check()?;
        let mut poll=libc::pollfd{fd:self.channel.as_raw_fd(),events,revents:0};
        let result=unsafe{libc::poll(&mut poll,1,25)};
        ensure(result>=0 || io::Error::last_os_error().kind()==io::ErrorKind::Interrupted,"role provisioner channel poll failed")?;
        ensure(poll.revents & (libc::POLLERR|libc::POLLNVAL)==0
            && (poll.revents & libc::POLLHUP==0 || poll.revents & events!=0),"role provisioner channel ended without its exact response")
    }
    fn send(&mut self,mut bytes:&[u8])->Result<(),String>{
        while !bytes.is_empty(){self.wait_io(libc::POLLOUT)?;
            match self.channel.write(&bytes[..bytes.len().min(65536)]) {
                Ok(0)=>return Err("role provisioner channel write incomplete".into()),Ok(n)=>bytes=&bytes[n..],
                Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)=>{},Err(e)=>return Err(io_error(e)),
            }
        }self.check()
    }
    fn receive(&mut self,mut bytes:&mut[u8])->Result<(),String>{
        while !bytes.is_empty(){self.wait_io(libc::POLLIN)?;
            let maximum=bytes.len().min(65536);
            match self.channel.read(&mut bytes[..maximum]){
                Ok(0)=>return Err("role provisioner channel read incomplete".into()),Ok(n)=>bytes=&mut bytes[n..],
                Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)=>{},Err(e)=>return Err(io_error(e)),
            }
        }self.check()
    }
    pub(super) fn exchange(&mut self,raw:&[u8])->Result<Vec<u8>,String>{
        let result=(||{ensure(!raw.is_empty() && raw.len()<=512*1024,"role provisioner frame bound")?;
            self.send(&(raw.len() as u32).to_be_bytes())?;self.send(raw)?;
            let mut size=[0;4];self.receive(&mut size)?;let size=u32::from_be_bytes(size) as usize;
            ensure(size>0 && size<=512*1024,"role provisioner response bound")?;
            let mut result=vec![0;size];self.receive(&mut result)?;Ok(result)})();
        if result.is_err(){self.poisoned=true;self.stop();}result
    }
    pub(super) fn finish(&mut self)->Result<(),String>{
        loop {self.check()?;
            if let Some(status)=self.child.try_wait().map_err(io_error)? {
                self.reaped=true;ensure(status.success(),"role provisioner did not exit successfully")?;return Ok(());
            }
            let mut poll=libc::pollfd{fd:self.pidfd.as_raw_fd(),events:libc::POLLIN,revents:0};
            let result=unsafe{libc::poll(&mut poll,1,25)};
            ensure(result>=0 || io::Error::last_os_error().kind()==io::ErrorKind::Interrupted,"role provisioner reap poll failed")?;
        }
    }
    fn stop(&mut self){if !self.reaped && unsafe{libc::getpid()}==self.creator {
        let _=self.channel.shutdown(std::net::Shutdown::Both);
        unsafe{libc::syscall(libc::SYS_pidfd_send_signal,self.pidfd.as_raw_fd(),libc::SIGKILL,std::ptr::null::<libc::siginfo_t>(),0);}
    }}
    fn stop_and_reap(&mut self)->Result<(),String>{
        self.stop();
        ensure(unsafe{libc::getpid()}==self.creator,"role cleanup crossed process")?;
        while !self.reaped {
            let before=now()?;
            if self.child.try_wait().map_err(io_error)?.is_some(){self.reaped=true;}
            let after=now()?;
            ensure(before<self.deadline&&after<self.deadline,"role cleanup exceeded original bound; no timely reap claim")?;
            if self.reaped{break;}
            let mut poll=libc::pollfd{fd:self.pidfd.as_raw_fd(),events:libc::POLLIN,revents:0};
            let timeout=((self.deadline-after)/1_000_000).clamp(1,25) as i32;
            let result=unsafe{libc::poll(&mut poll,1,timeout)};
            ensure(result>=0||io::Error::last_os_error().kind()==io::ErrorKind::Interrupted,"role cleanup poll failed")?;
        }Ok(())
    }
}
impl Drop for Process {
    fn drop(&mut self){if !self.reaped {let _=self.stop_and_reap();}}
}
