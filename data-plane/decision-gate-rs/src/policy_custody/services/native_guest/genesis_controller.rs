//! Fixed cold-result controller. Output is evidence, never installation or a
//! claim that another service stopped. Only a real child reap permits exit 0.
use super::*;
use std::os::fd::FromRawFd;
use std::sync::atomic::{AtomicBool,Ordering};

const MAX_OUTPUT:usize=crate::policy_shadow::policy_custody::services::common::MAX_SERVICE_FRAME_BYTES;
const WRITE_CHUNK:usize=4096;
static INTERRUPTED:AtomicBool=AtomicBool::new(false);
const CANCELLATION_SIGNALS:[libc::c_int;3]=[libc::SIGINT,libc::SIGTERM,libc::SIGHUP];

extern "C" fn interrupted(_:libc::c_int){INTERRUPTED.store(true,Ordering::Relaxed);}
pub(super) fn check_interruption()->Result<(),ShadowError>{require(!INTERRUPTED.load(Ordering::Relaxed))}
fn unblock_cancellation_signals()->Result<(),ShadowError>{
    let mut mask:libc::sigset_t=unsafe{std::mem::zeroed()};
    require(unsafe{libc::sigemptyset(&mut mask)}==0)?;
    for signal in CANCELLATION_SIGNALS {require(unsafe{libc::sigaddset(&mut mask,signal)}==0)?;}
    // Install every handler first. Unblocking may immediately deliver an
    // inherited pending cancellation; the next check must observe its flag.
    require(unsafe{libc::sigprocmask(libc::SIG_UNBLOCK,&mask,std::ptr::null_mut())}==0)
}
fn signals()->Result<(),ShadowError>{
    let mut action:libc::sigaction=unsafe{std::mem::zeroed()};
    action.sa_sigaction=interrupted as *const () as usize;
    require(unsafe{libc::sigemptyset(&mut action.sa_mask)}==0)?;
    for signal in CANCELLATION_SIGNALS {
        require(unsafe{libc::sigaction(signal,&action,std::ptr::null_mut())}==0)?;
    }
    unblock_cancellation_signals()
}

fn export_deadline(genesis:u64,lifetime:u64)->Result<u64,ShadowError>{
    genesis.min(lifetime).checked_sub(REAP_RESERVE_NS).filter(|v|*v>0)
        .ok_or(ShadowError::BindingDrift)
}
impl GenesisParent {
    fn export_deadline(&self)->Result<u64,ShadowError>{
        let running=self.running.as_ref().ok_or(ShadowError::BindingDrift)?;
        running.check_originals()?;
        let Some(Inspection::ProofClient(inspector))=running.inspector.as_ref() else{return Err(ShadowError::BindingDrift);};
        let deadline=export_deadline(inspector.genesis_deadline()?,running.files.lifetime())?;
        require(now()?<deadline)?;Ok(deadline)
    }
}

#[derive(PartialEq,Eq)]
struct PipeIdentity {device:u64,inode:u64,mode:u32,uid:u32,gid:u32,flags:i32}
pub(super) struct Output {fd:OwnedFd,identity:PipeIdentity}
impl Output {
    fn identity(fd:i32)->Result<PipeIdentity,ShadowError>{
        let mut stat:libc::stat=unsafe{std::mem::zeroed()};
        require(unsafe{libc::fstat(fd,&mut stat)}==0)?;
        let flags=unsafe{libc::fcntl(fd,libc::F_GETFL)};
        require(stat.st_mode&libc::S_IFMT==libc::S_IFIFO && stat.st_ino>0 && flags>=0
            && flags&(libc::O_ACCMODE|libc::O_NONBLOCK|libc::O_PATH|libc::O_APPEND)
                ==(libc::O_WRONLY|libc::O_NONBLOCK))?;
        // Exclude a pathname-selected FIFO as well as files, sockets and TTYs.
        let path=std::fs::read_link(format!("/proc/self/fd/{fd}")).map_err(fail)?;
        require(path==PathBuf::from(format!("pipe:[{}]",stat.st_ino)))?;
        Ok(PipeIdentity{device:stat.st_dev,inode:stat.st_ino,mode:stat.st_mode,
            uid:stat.st_uid,gid:stat.st_gid,flags})
    }
    fn admit(fd:OwnedFd)->Result<Self,ShadowError>{
        let identity=Self::identity(fd.as_raw_fd())?;Ok(Self{fd,identity})
    }
    fn stdout()->Result<Self,ShadowError>{
        // Validate the actual inherited descriptor before taking ownership;
        // a numeric slot alone is not an OwnedFd construction prerequisite.
        let identity=Self::identity(libc::STDOUT_FILENO)?;
        Ok(Self{fd:unsafe{OwnedFd::from_raw_fd(libc::STDOUT_FILENO)},identity})
    }
    fn check(&self)->Result<(),ShadowError>{require(Self::identity(self.fd.as_raw_fd())?==self.identity)}
    pub(super) fn write(&self,raw:&[u8],deadline:u64,mut check:impl FnMut()->Result<(),ShadowError>)->Result<(),ShadowError>{
        require(!raw.is_empty() && raw.len()<=MAX_OUTPUT)?;
        let mut offset=0;
        while offset<raw.len() {
            check()?;self.check()?;require(now()?<deadline)?;
            let end=(offset+WRITE_CHUNK).min(raw.len());
            let count=unsafe{libc::write(self.fd.as_raw_fd(),raw[offset..end].as_ptr().cast(),end-offset)};
            if count>0 {offset=offset.checked_add(count as usize).ok_or(ShadowError::CounterOverflow)?;continue;}
            require(count<0)?;
            let error=std::io::Error::last_os_error().raw_os_error();
            if error==Some(libc::EINTR){continue;}
            require(error==Some(libc::EAGAIN))?;
            let mut wait=libc::pollfd{fd:self.fd.as_raw_fd(),events:libc::POLLOUT,revents:0};
            let result=unsafe{libc::poll(&mut wait,1,1)};
            require(result>=0 || std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR))?;
            require(wait.revents&(libc::POLLERR|libc::POLLHUP|libc::POLLNVAL)==0)?;
        }
        check()?;self.check()?;require(now()?<deadline)
    }
}

pub(super) fn retain_uncertain(owner:GenesisParent,handoff:Option<Result<Vec<u8>,ShadowError>>)->! {
    // No retry and no synthetic terminal outcome. In particular, do not drop
    // the image, PIDFD or original absolute SIGKILL watchdog on uncertain reap.
    let _retained=std::mem::ManuallyDrop::new((owner,handoff));
    loop {unsafe{libc::pause();}}
}
pub(super) fn run()->! {
    let output=signals().and_then(|()|check_interruption())
        .and_then(|()|Output::stdout());
    let Ok(output)=output else{unsafe{libc::_exit(1)}};
    if std::env::args_os().count()==2
        && std::env::args_os().nth(1).as_deref()==Some(std::ffi::OsStr::new("--parked-genesis-endpoints")){
        return super::genesis_endpoints::run(output);
    }
    if std::env::args_os().count()==2
        && std::env::args_os().nth(1).as_deref()==Some(std::ffi::OsStr::new("--parked-genesis")){
        return super::genesis_parked::run(output);
    }
    // start admits the unchanged fixed protected launch, exact actual C9 FDs,
    // root/one-thread/no-args/empty-environment contract and original lifetime.
    let mut owner=match GenesisParent::start(){Ok(owner)=>owner,Err(_)=>unsafe{libc::_exit(1)}};
    let handoff=owner.run_until_genesis_handoff_checked(check_interruption);
    let result=handoff.as_ref().map_err(|_|ShadowError::BindingDrift).and_then(|bundle|{
        let deadline=owner.export_deadline()?;
        output.write(bundle,deadline,check_interruption)?;
        require(owner.export_deadline()?==deadline)
    });
    if owner.close().is_err(){retain_uncertain(owner,Some(handoff));}
    let status=if result.is_ok() && check_interruption().is_ok(){0}else{1};
    // No envelope, newline, success marker, output path or generated receipt.
    // The caller discards every partial/nonzero-exit export and retains the
    // actual cold immutable core separately for subsequent adoption.
    drop(handoff);drop(output);unsafe{libc::_exit(status)}
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pipe(flags:i32)->(OwnedFd,OwnedFd){
        let mut fds=[-1;2];assert_eq!(unsafe{libc::pipe2(fds.as_mut_ptr(),flags|libc::O_CLOEXEC)},0);
        unsafe{(OwnedFd::from_raw_fd(fds[0]),OwnedFd::from_raw_fd(fds[1]))}
    }
    #[test]
    fn inherited_cancellation_mask_is_unblocked_without_other_changes(){
        struct Restore(libc::sigset_t);
        impl Drop for Restore {
            fn drop(&mut self){assert_eq!(unsafe{libc::sigprocmask(libc::SIG_SETMASK,&self.0,std::ptr::null_mut())},0);}
        }
        let mut original:libc::sigset_t=unsafe{std::mem::zeroed()};
        assert_eq!(unsafe{libc::sigprocmask(libc::SIG_SETMASK,std::ptr::null(),&mut original)},0);
        let _restore=Restore(original);
        let mut blocked:libc::sigset_t=unsafe{std::mem::zeroed()};
        assert_eq!(unsafe{libc::sigemptyset(&mut blocked)},0);
        for signal in CANCELLATION_SIGNALS.into_iter().chain([libc::SIGPIPE]) {
            assert_eq!(unsafe{libc::sigaddset(&mut blocked,signal)},0);
        }
        assert_eq!(unsafe{libc::sigprocmask(libc::SIG_BLOCK,&blocked,std::ptr::null_mut())},0);
        unblock_cancellation_signals().unwrap();
        let mut actual:libc::sigset_t=unsafe{std::mem::zeroed()};
        assert_eq!(unsafe{libc::sigprocmask(libc::SIG_SETMASK,std::ptr::null(),&mut actual)},0);
        for signal in CANCELLATION_SIGNALS {assert_eq!(unsafe{libc::sigismember(&actual,signal)},0);}
        assert_eq!(unsafe{libc::sigismember(&actual,libc::SIGPIPE)},1);
    }
    #[test]
    fn deadlines_only_narrow_originals(){
        assert_eq!(export_deadline(REAP_RESERVE_NS+10,REAP_RESERVE_NS+20).unwrap(),10);
        assert_eq!(export_deadline(REAP_RESERVE_NS+20,REAP_RESERVE_NS+10).unwrap(),10);
        assert!(export_deadline(REAP_RESERVE_NS,u64::MAX).is_err());
        assert!(export_deadline(0,u64::MAX).is_err());
    }
    #[test]
    fn output_requires_actual_nonblocking_write_pipe(){
        let (read,write)=pipe(0);assert!(Output::admit(write).is_err());drop(read);
        let (read,write)=pipe(libc::O_NONBLOCK);assert!(Output::admit(read).is_err());
        assert!(Output::admit(write).is_ok());
    }
    #[test]
    fn changed_pipe_flags_are_refused(){
        let (_read,write)=pipe(libc::O_NONBLOCK);let output=Output::admit(write).unwrap();
        assert_eq!(unsafe{libc::fcntl(output.fd.as_raw_fd(),libc::F_SETFL,0)},0);
        assert!(output.check().is_err());
    }
    #[test]
    fn export_preserves_literal_bytes(){
        let (read,write)=pipe(libc::O_NONBLOCK);let output=Output::admit(write).unwrap();
        let original=b"{\"literal\":\"public evidence only\"}";
        output.write(original,now().unwrap()+1_000_000_000,||Ok(())).unwrap();
        let mut bytes=[0u8;128];let count=unsafe{libc::read(read.as_raw_fd(),bytes.as_mut_ptr().cast(),bytes.len())};
        assert_eq!(count,original.len() as isize);assert_eq!(&bytes[..count as usize],original);
    }
    #[test]
    fn expired_or_cancelled_export_writes_nothing(){
        let (read,write)=pipe(libc::O_NONBLOCK);let output=Output::admit(write).unwrap();
        assert!(output.write(b"x",now().unwrap(),||Ok(())).is_err());
        assert!(output.write(b"x",now().unwrap()+1_000_000_000,||Err(ShadowError::BindingDrift)).is_err());
        let mut byte=0u8;assert_eq!(unsafe{libc::read(read.as_raw_fd(),(&mut byte as *mut u8).cast(),1)},-1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(),Some(libc::EAGAIN));
    }
    #[test]
    fn empty_or_oversize_export_is_refused(){
        let (_read,write)=pipe(libc::O_NONBLOCK);let output=Output::admit(write).unwrap();
        let deadline=now().unwrap()+1_000_000_000;
        assert!(output.write(&[],deadline,||Ok(())).is_err());
        assert!(output.write(&vec![b'x';MAX_OUTPUT+1],deadline,||Ok(())).is_err());
    }
}
