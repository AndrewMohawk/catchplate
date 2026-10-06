//! One actual pinned executable, bounded pipes, exact child lifetime and reap.
use super::{image::Sealed, transport as ipc, wire::{now,require}};
use std::{mem::{size_of,zeroed},os::fd::{AsRawFd,OwnedFd,FromRawFd}};
#[repr(C)] #[derive(Default)]
struct CloneArgs {flags:u64,pidfd:u64,child_tid:u64,parent_tid:u64,exit_signal:u64,stack:u64,stack_size:u64,tls:u64,set_tid:u64,set_tid_size:u64,cgroup:u64}

// Only threads may be cloned by a verifier. It cannot create a detached
// process tree or escape its owned process group. Keep
// the existing verifier's file/network semantics; signatures still authorize
// results. The initial exec is fixed, but this pre-exec filter is NOT a proof
// against all later self-exec behavior (FD numbers can be reused). This is not
// a generic egress permission or a new authority role.
fn filter(executable:i32)->Vec<libc::sock_filter> {
    let stmt=|code,k|libc::sock_filter{code,jt:0,jf:0,k};
    let jump=|k,jt,jf|libc::sock_filter{code:0x15,jt,jf,k};
    let deny=0x0005_0000|libc::EPERM as u32;
    let mut out=vec![stmt(0x20,4),jump(0xc000003e,1,0),stmt(0x06,0x80000000),stmt(0x20,0),
        libc::sock_filter{code:0x35,jt:0,jf:1,k:0x40000000},stmt(0x06,0x80000000)];
    for call in [libc::SYS_fork,libc::SYS_vfork,libc::SYS_execve,libc::SYS_setpgid,libc::SYS_setsid,
        libc::SYS_unshare,libc::SYS_setns,libc::SYS_ptrace,libc::SYS_process_vm_readv,libc::SYS_process_vm_writev,
        libc::SYS_mount,libc::SYS_umount2,libc::SYS_pivot_root] {
        out.extend([jump(call as u32,0,1),stmt(0x06,deny)]);
    }
    // libc's normal pthread fallback may use clone after clone3 ENOSYS.
    out.extend([jump(libc::SYS_clone3 as u32,0,1),stmt(0x06,0x0005_0000|libc::ENOSYS as u32),
        jump(libc::SYS_clone as u32,0,4),stmt(0x20,16),stmt(0x54,libc::CLONE_THREAD as u32),
        jump(libc::CLONE_THREAD as u32,1,0),stmt(0x06,deny),stmt(0x20,0),
        jump(libc::SYS_execveat as u32,0,4),stmt(0x20,16),jump(executable as u32,1,0),
        stmt(0x06,deny),stmt(0x06,0x7fff0000),stmt(0x06,0x7fff0000)]);
    out
}
unsafe fn child(parent:i32,image:i32,input:i32,output:i32,discard:i32,argv0:&std::ffi::CStr,filters:&[libc::sock_filter],
    publication:Option<&[OwnedFd;3]>)->! {
    let mut good=unsafe {libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL,0,0,0)}==0
        && unsafe {libc::getppid()}==parent && unsafe {libc::setpgid(0,0)}==0
        && unsafe {libc::lseek(input,0,libc::SEEK_SET)}==0;
    good &= unsafe {libc::dup3(input,0,0)}==0 && unsafe {libc::dup3(output,1,0)}==1;
    good &= unsafe {libc::dup3(discard,2,0)}==2;
    good &= unsafe {libc::syscall(libc::SYS_close_range,3u32,u32::MAX,4u32)}==0;
    // Runtime/WebAuthn and legacy publication jobs keep the original stdio-only
    // roster. Only the fixed selected publication executable receives 3/4/5.
    if let Some(resources)=publication {
        for (source,target) in resources.iter().zip([3,4,5]) {
            good &= unsafe {libc::dup3(source.as_raw_fd(),target,0)}==target;
        }
    }
    let program=libc::sock_fprog {len:filters.len() as u16,filter:filters.as_ptr() as *mut _};
    good &= unsafe {libc::prctl(libc::PR_SET_SECCOMP,2,&program,0,0)}==0;
    if good {
        let argv=[argv0.as_ptr(),std::ptr::null()];
        let environment=[c"LANG=C".as_ptr(),c"LC_ALL=C".as_ptr(),c"TZ=UTC".as_ptr(),std::ptr::null()];
        unsafe {libc::syscall(libc::SYS_execveat,image,c"".as_ptr(),argv.as_ptr(),environment.as_ptr(),libc::AT_EMPTY_PATH);}
    }
    unsafe {libc::syscall(libc::SYS_exit_group,127);}
    loop {std::hint::spin_loop();}
}
struct Job {pid:i32,pidfd:OwnedFd,reaped:bool}
impl Job {
    fn kill(&self) {
        if self.reaped {return;}
        // The owned, unreaped group leader prevents PID/group-number reuse.
        unsafe {libc::kill(-self.pid,libc::SIGKILL);
            libc::syscall(libc::SYS_pidfd_send_signal,self.pidfd.as_raw_fd(),libc::SIGKILL,std::ptr::null::<libc::siginfo_t>(),0);}
    }
    fn reap(&mut self)->Result<Option<bool>,String> {
        require(!self.reaped)?;let mut info:libc::siginfo_t=unsafe {zeroed()};
        require(unsafe {libc::waitid(libc::P_PIDFD,self.pidfd.as_raw_fd() as _,&mut info,libc::WEXITED|libc::WNOHANG)}==0)?;
        if unsafe {info.si_pid()}==0 {return Ok(None);}
        require(unsafe {info.si_pid()}==self.pid && info.si_signo==libc::SIGCHLD
            && matches!(info.si_code,libc::CLD_EXITED|libc::CLD_KILLED|libc::CLD_DUMPED))?;
        self.reaped=true;Ok(Some(info.si_code==libc::CLD_EXITED && unsafe {info.si_status()}==0))
    }
    fn cancel(&mut self,lifetime:u64)->Result<(),String> {
        self.kill();
        loop {
            if self.reaped || self.reap()?.is_some() {require(now()?<lifetime)?;return Ok(());}
            require(now()?<lifetime)?;
            let mut p=libc::pollfd {fd:self.pidfd.as_raw_fd(),events:libc::POLLIN,revents:0};
            let result=unsafe {libc::poll(&mut p,1,10)};
            require(result>=0 || std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR))?;
        }
    }
}
impl Drop for Job {fn drop(&mut self){self.kill();if !self.reaped {let _=self.reap();}}}

pub(super) fn run(image:&Sealed,input:&Sealed,argv0:&str,parent:&OwnedFd,channel:i32,deadline:u64,lifetime:u64,maximum:usize,
    transfer:Option<&super::publication_resources::JobTransfer>)->Result<Vec<u8>,String> {
    image.check()?;input.check()?;require(now()?<deadline && deadline<=lifetime)?;
    let mut pipe=[-1;2];require(unsafe {libc::pipe2(pipe.as_mut_ptr(),libc::O_CLOEXEC)}==0)?;
    let read=unsafe {OwnedFd::from_raw_fd(pipe[0])};let write=unsafe {OwnedFd::from_raw_fd(pipe[1])};
    require(unsafe {libc::fcntl(read.as_raw_fd(),libc::F_SETFL,libc::O_NONBLOCK)}==0)?;
    let image_fd=ipc::duplicate(image.file.as_raw_fd())?;let input_fd=ipc::duplicate(input.file.as_raw_fd())?;
    let output_fd=ipc::duplicate(write.as_raw_fd())?;
    // Preserve the existing verifier's discarded stderr, not a newly closed
    // descriptor. This fixed device is never selected by a request.
    let null=unsafe {libc::open(c"/dev/null".as_ptr(),libc::O_WRONLY|libc::O_CLOEXEC|libc::O_NOFOLLOW)};
    require(null>=0)?;let null=unsafe {OwnedFd::from_raw_fd(null)};
    let mut metadata:libc::stat=unsafe {zeroed()};
    require(unsafe {libc::fstat(null.as_raw_fd(),&mut metadata)}==0 && metadata.st_mode&libc::S_IFMT==libc::S_IFCHR
        && libc::major(metadata.st_rdev)==1 && libc::minor(metadata.st_rdev)==3 && metadata.st_uid==0 && metadata.st_gid==0)?;
    let discard_fd=ipc::duplicate(null.as_raw_fd())?;
    let publication=transfer.map(|resources|->Result<[OwnedFd;3],String> {
        Ok([ipc::duplicate(resources.descriptors[0].as_raw_fd())?,
            ipc::duplicate(resources.descriptors[1].as_raw_fd())?,
            ipc::duplicate(resources.descriptors[2].as_raw_fd())?])
    }).transpose()?;
    let argv0=std::ffi::CString::new(argv0).map_err(|_|"shadow original argv0 invalid")?;
    let filters=filter(image_fd.as_raw_fd());let pid=unsafe {libc::getpid()};let mut child_pidfd=-1;
    let args=CloneArgs {flags:libc::CLONE_PIDFD as u64,pidfd:(&mut child_pidfd as *mut i32) as u64,exit_signal:libc::SIGCHLD as u64,..CloneArgs::default()};
    let child_pid=unsafe {libc::syscall(libc::SYS_clone3,&args,size_of::<CloneArgs>())};
    if child_pid==0 {unsafe {child(pid,image_fd.as_raw_fd(),input_fd.as_raw_fd(),output_fd.as_raw_fd(),discard_fd.as_raw_fd(),&argv0,&filters,publication.as_ref());}}
    require(child_pid>0 && child_pidfd>=0)?;
    let mut job=Job {pid:child_pid as i32,pidfd:unsafe {OwnedFd::from_raw_fd(child_pidfd)},reaped:false};
    drop(write);drop(image_fd);drop(input_fd);drop(output_fd);drop(discard_fd);drop(null);drop(publication);
    let outcome=(|| {
        let mut bytes=Vec::new();let mut eof=false;let mut status=None;
        loop {
            require(now()?<deadline)?;ipc::ensure_pidfd_alive(parent).map_err(|_|"shadow actual parent exited")?;
            let mut fds=[libc::pollfd {fd:read.as_raw_fd(),events:libc::POLLIN,revents:0},
                libc::pollfd {fd:channel,events:libc::POLLIN,revents:0},
                libc::pollfd {fd:parent.as_raw_fd(),events:libc::POLLIN,revents:0}];
            let result=unsafe {libc::poll(fds.as_mut_ptr(),3,10)};
            if result<0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR) {continue;}
            // A second request, shutdown or parent death cancels the one job;
            // neither queued work nor a timeout supplies retry authority.
            require(result>=0 && fds[1].revents==0 && fds[2].revents==0
                && fds[0].revents&!(libc::POLLIN|libc::POLLHUP)==0)?;
            let mut block=[0u8;8192];
            loop {
                let n=unsafe {libc::read(read.as_raw_fd(),block.as_mut_ptr().cast(),block.len())};
                if n==0 {eof=true;break;}
                if n<0 {
                    let error=std::io::Error::last_os_error().raw_os_error();
                    if error==Some(libc::EINTR){continue;}
                    require(error==Some(libc::EAGAIN))?;break;
                }
                require(bytes.len().checked_add(n as usize).is_some_and(|length|length<=maximum))?;
                bytes.extend_from_slice(&block[..n as usize]);
            }
            if status.is_none() {status=job.reap()?;}
            if let Some(ok)=status {if eof {require(ok && !bytes.is_empty() && now()?<deadline)?;return Ok(bytes);}}
        }
    })();
    if outcome.is_err() {job.cancel(lifetime)?;}
    image.check()?;input.check()?;outcome
}
