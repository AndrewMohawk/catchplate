//! Private one-shot shadow helper. Shared image mechanism, distinct purpose.
use super::super::{ensure,live,now,image::{Image,Purpose},ImageConfiguration};
use std::{ffi::CString,fs::File,io::{self,Read,Write},os::{fd::{AsRawFd,FromRawFd,OwnedFd},
    unix::{net::UnixStream,process::CommandExt}},process::{Child,Command,Stdio}};
fn error(_:io::Error)->String {"shadow key helper original I/O failed".into()}
#[repr(C)] struct Header {version:u32,pid:i32}
#[repr(C)] #[derive(Clone,Copy)] struct Caps {effective:u32,permitted:u32,inheritable:u32}
pub(super) struct Process {image:Image,child:Child,pidfd:OwnedFd,channel:UnixStream,
    creator:libc::pid_t,uid:u32,gid:u32,deadline:u64,last:u64,reaped:bool,poisoned:bool}
impl Process {
    pub(super) fn open(config:&ImageConfiguration,uid:u32,gid:u32,deadline:u64)->Result<Self,String> {
        live(deadline)?;
        ensure(unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0
            && unsafe{libc::getgid()}==0 && unsafe{libc::getegid()}==0 && uid>0 && gid>0
            && uid!=u32::MAX && gid!=u32::MAX,"shadow key helper requires actual root preparation/final role")?;
        let image=Image::open_for(config,deadline,Purpose::ShadowKeyDelivery)?;
        let fd=unsafe{libc::syscall(libc::SYS_memfd_create,b"shadow-key-bootstrap\0".as_ptr(),libc::MFD_CLOEXEC|libc::MFD_ALLOW_SEALING)} as i32;
        ensure(fd>=0,"shadow key bootstrap memfd unavailable")?;
        let mut bootstrap=unsafe{File::from_raw_fd(fd)};
        let raw=super::super::canonical_ascii_bytes(&serde_json::json!({"apiVersion":"catchplate.nativeShadowKeyHelperBootstrap/v1",
            "uid":uid,"gid":gid,"deadlineBoottimeNs":deadline.to_string()}))?;
        bootstrap.write_all(&raw).map_err(error)?;
        ensure(unsafe{libc::fchmod(fd,0o600)}==0 && unsafe{libc::fcntl(fd,libc::F_ADD_SEALS,15)}==0,
            "shadow key bootstrap sealing failed")?;
        // High, separately held copies prevent fixed-slot dup2 from destroying
        // the root/executable/bootstrap or Command's actual exec-error pipe.
        let duplicate=|source:i32|->Result<OwnedFd,String>{let n=unsafe{libc::fcntl(source,libc::F_DUPFD_CLOEXEC,128)};
            ensure(n>=128,"shadow helper original duplication failed")?;Ok(unsafe{OwnedFd::from_raw_fd(n)})};
        let root=duplicate(image.root.as_raw_fd())?;let executable=duplicate(image.interpreter.as_raw_fd())?;
        let original=duplicate(fd)?;
        let (channel,child_channel)=UnixStream::pair().map_err(error)?;channel.set_nonblocking(true).map_err(error)?;
        let endpoint=duplicate(child_channel.as_raw_fd())?;
        let (root_fd,exec_fd,boot_fd,socket_fd)=(root.as_raw_fd(),executable.as_raw_fd(),original.as_raw_fd(),endpoint.as_raw_fd());
        let parent=unsafe{libc::getpid()};let last=now()?;
        let args=[CString::new(super::super::INTERPRETER_PATH).unwrap(),CString::new("-I").unwrap(),
            CString::new("-B").unwrap(),CString::new(super::HELPER_PATH).unwrap()];
        let mut command=Command::new("/shadow-key-helper-is-source-owned");
        command.env_clear().stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        unsafe{command.pre_exec(move||{
            if libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)!=0 || libc::getppid()!=parent
                || libc::fchdir(root_fd)!=0 || libc::chroot(b".\0".as_ptr().cast())!=0 || libc::chdir(b"/\0".as_ptr().cast())!=0
                || libc::dup2(socket_fd,3)!=3 || libc::dup2(boot_fd,4)!=4 || libc::setgroups(0,std::ptr::null())!=0 {
                return Err(io::Error::last_os_error());
            }
            for cap in 0..=40 {if libc::prctl(libc::PR_CAPBSET_DROP,cap,0,0,0)!=0 {return Err(io::Error::last_os_error());}}
            for (resource,limit) in [(libc::RLIMIT_CORE,0),(libc::RLIMIT_FSIZE,0),(libc::RLIMIT_NPROC,1),
                (libc::RLIMIT_NOFILE,512),(libc::RLIMIT_AS,512*1024*1024)] {
                let value=libc::rlimit{rlim_cur:limit,rlim_max:limit};
                if libc::setrlimit(resource,&value)!=0 {return Err(io::Error::last_os_error());}
            }
            let header=Header{version:0x2008_0522,pid:0};let caps=[Caps{effective:0,permitted:0,inheritable:0};2];
            if libc::setresgid(gid,gid,gid)!=0 || libc::setresuid(uid,uid,uid)!=0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0 || libc::prctl(libc::PR_SET_DUMPABLE,0,0,0,0)!=0
                || libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)!=0 || libc::getppid()!=parent
                || libc::syscall(libc::SYS_capset,&header,caps.as_ptr())!=0
                || libc::syscall(libc::SYS_close_range,3u32,u32::MAX,4u32)!=0
                || libc::fcntl(3,libc::F_SETFD,0)!=0 || libc::fcntl(4,libc::F_SETFD,0)!=0 {return Err(io::Error::last_os_error());}
            let argv=[args[0].as_ptr(),args[1].as_ptr(),args[2].as_ptr(),args[3].as_ptr(),std::ptr::null()];
            let env:[*const libc::c_char;1]=[std::ptr::null()];
            libc::syscall(libc::SYS_execveat,exec_fd,b"\0".as_ptr().cast::<libc::c_char>(),argv.as_ptr(),env.as_ptr(),libc::AT_EMPTY_PATH);
            Err(io::Error::last_os_error())
        });}
        let mut child=command.spawn().map_err(error)?;drop(child_channel);drop(endpoint);
        let pidfd=unsafe{libc::syscall(libc::SYS_pidfd_open,child.id(),0)} as i32;
        if pidfd<0 {let _=child.kill();let _=child.try_wait();return Err("shadow helper PIDFD unavailable; no reap claim".into());}
        let mut owner=Self{image,child,pidfd:unsafe{OwnedFd::from_raw_fd(pidfd)},channel,creator:parent,
            uid,gid,deadline,last,reaped:false,poisoned:false};owner.check()?;Ok(owner)
    }
    pub(super) fn final_identity(&self)->Result<(),String> {
        ensure(unsafe{libc::getuid()}==self.uid && unsafe{libc::geteuid()}==self.uid
            && unsafe{libc::getgid()}==self.gid && unsafe{libc::getegid()}==self.gid,
            "shadow helper cannot deliver before actual final role")
    }
    pub(super) fn check(&mut self)->Result<(),String> {
        self.check_originals()?;
        let mut p=libc::pollfd{fd:self.pidfd.as_raw_fd(),events:libc::POLLIN,revents:0};
        ensure(unsafe{libc::poll(&mut p,1,0)}==0&&p.revents==0,"shadow helper is no longer live")
    }
    fn check_originals(&mut self)->Result<(),String> {
        ensure(!self.poisoned&&!self.reaped&&unsafe{libc::getpid()}==self.creator,"shadow helper owner changed")?;
        let current=now()?;ensure(self.last<=current&&current<self.deadline,"shadow helper original interval expired")?;
        self.last=current;self.image.check(self.deadline)
    }
    fn wait(&mut self,event:i16)->Result<(),String> {
        self.check_originals()?;let mut poll=libc::pollfd{fd:self.channel.as_raw_fd(),events:event,revents:0};
        let rc=unsafe{libc::poll(&mut poll,1,25)};
        ensure(rc>=0||io::Error::last_os_error().kind()==io::ErrorKind::Interrupted,"shadow helper poll failed")?;
        ensure(poll.revents&(libc::POLLERR|libc::POLLNVAL)==0
            && (poll.revents&libc::POLLHUP==0||poll.revents&event!=0),"shadow helper channel closed")
    }
    fn write(&mut self,mut bytes:&[u8])->Result<(),String> {while !bytes.is_empty(){self.wait(libc::POLLOUT)?;
        match self.channel.write(bytes){Ok(0)=>return Err("shadow helper write ended".into()),Ok(n)=>bytes=&bytes[n..],
            Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)=>{},Err(e)=>return Err(error(e))}}
        self.check_originals()}
    fn read(&mut self,mut bytes:&mut[u8])->Result<(),String> {while !bytes.is_empty(){self.wait(libc::POLLIN)?;
        match self.channel.read(bytes){Ok(0)=>return Err("shadow helper read ended".into()),Ok(n)=>bytes=&mut bytes[n..],
            Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)=>{},Err(e)=>return Err(error(e))}}
        self.check_originals()}
    pub(super) fn exchange(&mut self,raw:&[u8])->Result<Vec<u8>,String> {
        let result=(||{self.check()?;ensure(!raw.is_empty()&&raw.len()<=128*1024,"shadow helper request bound")?;
            self.write(&(raw.len() as u32).to_be_bytes())?;self.write(raw)?;let mut size=[0;4];self.read(&mut size)?;
            let n=u32::from_be_bytes(size) as usize;ensure(n>0&&n<=128*1024,"shadow helper response bound")?;
            let mut bytes=vec![0;n];self.read(&mut bytes)?;Ok(bytes)})();
        if result.is_err(){self.poisoned=true;self.stop();}result
    }
    pub(super) fn finish(&mut self)->Result<(),String> {
        loop {self.check_originals()?;if let Some(status)=self.child.try_wait().map_err(error)? {
            self.reaped=true;live(self.deadline)?;return ensure(status.success(),"shadow helper exit was not successful");}
            let mut p=libc::pollfd{fd:self.pidfd.as_raw_fd(),events:libc::POLLIN,revents:0};
            unsafe{libc::poll(&mut p,1,10);}
        }
    }
    fn stop(&mut self) {if !self.reaped&&unsafe{libc::getpid()}==self.creator {
        let _=self.channel.shutdown(std::net::Shutdown::Both);
        unsafe{libc::syscall(libc::SYS_pidfd_send_signal,self.pidfd.as_raw_fd(),libc::SIGKILL,std::ptr::null::<libc::siginfo_t>(),0);}
    }}
}
impl Drop for Process {fn drop(&mut self){self.stop();if unsafe{libc::getpid()}!=self.creator{return;}
    while !self.reaped&&now().is_ok_and(|n|n<self.deadline) {
        match self.child.try_wait(){Ok(Some(_))=>self.reaped=true,Err(_)=>break,Ok(None)=>{
            let mut p=libc::pollfd{fd:self.pidfd.as_raw_fd(),events:libc::POLLIN,revents:0};unsafe{libc::poll(&mut p,1,10);}}}
    }
    // Drop makes no timely-reap claim after the original interval expires.
}}
