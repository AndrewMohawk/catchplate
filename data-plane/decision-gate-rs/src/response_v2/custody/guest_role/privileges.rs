//! Permanent service identity; no inspection or DAC capabilities.
use std::{io,mem::zeroed};
use super::require;
const VERSION:u32 = 0x2008_0522;
const SECUREBITS:libc::c_ulong = 0xef;
#[repr(C)]
struct Header { version:u32,pid:i32 }
#[repr(C)]
#[derive(Clone,Copy)]
struct Data { effective:u32,permitted:u32,inheritable:u32 }

fn ids() -> io::Result<([u32;3],[u32;3])> {
    let mut uid=[0;3]; let mut gid=[0;3];
    require(unsafe { libc::getresuid(uid.as_mut_ptr(),uid.as_mut_ptr().add(1),uid.as_mut_ptr().add(2)) } == 0
        && unsafe { libc::getresgid(gid.as_mut_ptr(),gid.as_mut_ptr().add(1),gid.as_mut_ptr().add(2)) } == 0,
        "read actual service identities")?;
    Ok((uid,gid))
}
pub(super) fn single_thread() -> io::Result<()> {
    let pid=unsafe { libc::getpid() };
    require(unsafe { libc::syscall(libc::SYS_gettid) } == pid as libc::c_long,"role launch requires initial thread")?;
    let mut tasks=std::fs::read_dir("/proc/self/task")?;
    let first=tasks.next().ok_or_else(|| io::Error::other("missing role task"))??;
    require(first.file_name() == pid.to_string().as_str() && tasks.next().is_none(),"role launch must be single-threaded")
}
fn last_cap() -> io::Result<u32> {
    for n in 0..=64u32 {
        let value=unsafe { libc::prctl(libc::PR_CAPBSET_READ,n as libc::c_ulong,0,0,0) };
        if value < 0 {
            require(n>0 && io::Error::last_os_error().raw_os_error()==Some(libc::EINVAL),"capability ABI unavailable")?;
            return Ok(n-1);
        }
        require(value==0 || value==1,"invalid capability bound")?;
    }
    Err(io::Error::other("capability ABI exceeds fixed bound"))
}
pub(crate) fn require_role(uid:u32,gid:u32) -> io::Result<()> {
    require(uid!=0 && gid!=0 && ![64990,65534].contains(&uid) && ![64990,65534].contains(&gid)
        && ids()?==([uid;3],[gid;3]) && unsafe { libc::getgroups(0,std::ptr::null_mut()) }==0
        && unsafe { libc::prctl(libc::PR_GET_DUMPABLE,0,0,0,0) }==0
        && unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS,0,0,0,0) }==1
        && unsafe { libc::prctl(libc::PR_GET_SECUREBITS,0,0,0,0) }==SECUREBITS as i32,
        "signed final role identity or process restrictions changed")?;
    let mut header=Header { version:VERSION,pid:0 };
    let mut data:[Data;2]=unsafe { zeroed() };
    require(unsafe { libc::syscall(libc::SYS_capget,&mut header,data.as_mut_ptr()) }==0
        && data.iter().all(|v| v.effective==0 && v.permitted==0 && v.inheritable==0),"service retained capabilities")?;
    for n in 0..=last_cap()? {
        require(unsafe { libc::prctl(libc::PR_CAPBSET_READ,n as libc::c_ulong,0,0,0) }==0
            && unsafe { libc::prctl(47,1,n as libc::c_ulong,0,0) }==0,"service capability bound/ambient set is not empty")?;
    }
    Ok(())
}
pub(super) struct Owner { pid:libc::pid_t,parent:libc::pid_t,uid:u32,gid:u32 }
pub(super) fn enter(uid:u32,gid:u32,parent:libc::pid_t) -> io::Result<Owner> {
    single_thread()?;
    require(ids()?==([0;3],[0;3]) && parent>0 && unsafe { libc::getppid() }==parent,"role requires real root launch parent")?;
    let limit=libc::rlimit { rlim_cur:0,rlim_max:0 };
    require(unsafe { libc::setrlimit(libc::RLIMIT_CORE,&limit) }==0
        && unsafe { libc::setgroups(0,std::ptr::null()) }==0
        && unsafe { libc::prctl(47,4,0,0,0) }==0,"clear role groups/core/ambient authority")?;
    for n in 0..=last_cap()? {
        require(unsafe { libc::prctl(libc::PR_CAPBSET_DROP,n as libc::c_ulong,0,0,0) }==0,"drop role capability bound")?;
    }
    require(unsafe { libc::prctl(libc::PR_SET_SECUREBITS,SECUREBITS,0,0,0) }==0
        && unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS,1,0,0,0) }==0
        && unsafe { libc::setresgid(gid,gid,gid) }==0
        && unsafe { libc::setresuid(uid,uid,uid) }==0,"permanent signed role drop")?;
    let header=Header { version:VERSION,pid:0 };
    let data=[Data { effective:0,permitted:0,inheritable:0 };2];
    require(unsafe { libc::syscall(libc::SYS_capset,&header,data.as_ptr()) }==0
        && unsafe { libc::prctl(libc::PR_SET_DUMPABLE,0,0,0,0) }==0
        // Effective credential changes clear PDEATHSIG; bind it afterwards.
        && unsafe { libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL,0,0,0) }==0
        && unsafe { libc::getppid() }==parent,"role capability or parent-death binding")?;
    let owner=Owner { pid:unsafe { libc::getpid() },parent,uid,gid };
    owner.check()?;
    single_thread()?;
    Ok(owner)
}
impl Owner {
    pub(super) fn check(&self) -> io::Result<()> {
        require_role(self.uid,self.gid)?;
        let mut signal=0;
        require(unsafe { libc::getpid() }==self.pid && unsafe { libc::getppid() }==self.parent,
            "role process or original parent binding changed")?;
        // PDEATHSIG belongs to the original thread. Newly created service
        // threads retain no independent parent-death setting to re-admit.
        if unsafe { libc::syscall(libc::SYS_gettid) }==self.pid as libc::c_long {
            require(unsafe { libc::prctl(libc::PR_GET_PDEATHSIG,&mut signal,0,0,0) }==0
                && signal==libc::SIGKILL,"role parent-death signal changed")?;
        }
        Ok(())
    }
}
