//! Permanent dispatcher identity. No DAC, inspection, mount or serving privilege.
use super::{wire::require, UID};
#[repr(C)] struct Header {version:u32,pid:i32}
#[repr(C)] #[derive(Clone,Copy)] struct Data {effective:u32,permitted:u32,inheritable:u32}
const SECUREBITS:libc::c_ulong=0xef;
pub(super) struct Identity {pid:i32,parent:i32,last:u32}
fn ids()->Result<([u32;3],[u32;3]),String> {
    let mut u=[0;3];let mut g=[0;3];
    require(unsafe {libc::getresuid(u.as_mut_ptr(),u.as_mut_ptr().add(1),u.as_mut_ptr().add(2))}==0
        && unsafe {libc::getresgid(g.as_mut_ptr(),g.as_mut_ptr().add(1),g.as_mut_ptr().add(2))}==0)?; Ok((u,g))
}
pub(super) fn enter(parent:i32)->Result<Identity,String> {
    let pid=unsafe {libc::getpid()};
    require(ids()?==([0;3],[0;3]) && parent>0 && unsafe {libc::getppid()}==parent
        && unsafe {libc::syscall(libc::SYS_gettid)}==pid as libc::c_long)?;
    let mut tasks=std::fs::read_dir("/proc/self/task").map_err(|_|"shadow task inventory absent")?;
    let task=tasks.next().ok_or("shadow task inventory empty")?.map_err(|_|"shadow task inventory failed")?;
    require(task.file_name()==pid.to_string().as_str() && tasks.next().is_none())?;
    let mut last=None;
    for cap in 0..=64u32 { let present=unsafe {libc::prctl(libc::PR_CAPBSET_READ,cap as libc::c_ulong,0,0,0)};
        if present<0 {require(cap>0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EINVAL))?;last=Some(cap-1);break;}
        require(present==0 || present==1)?;
    }
    let last=last.ok_or("shadow capability ABI exceeds bound")?;
    for (resource,value) in [(libc::RLIMIT_CORE,0),(libc::RLIMIT_NOFILE,128),(libc::RLIMIT_AS,512*1024*1024)] {
        let limit=libc::rlimit {rlim_cur:value,rlim_max:value};require(unsafe {libc::setrlimit(resource,&limit)}==0)?;
    }
    require(unsafe {libc::setgroups(0,std::ptr::null())}==0 && unsafe {libc::prctl(47,4,0,0,0)}==0)?;
    for cap in 0..=last {require(unsafe {libc::prctl(libc::PR_CAPBSET_DROP,cap as libc::c_ulong,0,0,0)}==0)?;}
    require(unsafe {libc::prctl(libc::PR_SET_SECUREBITS,SECUREBITS,0,0,0)}==0
        && unsafe {libc::prctl(libc::PR_SET_NO_NEW_PRIVS,1,0,0,0)}==0
        && unsafe {libc::setresgid(UID,UID,UID)}==0 && unsafe {libc::setresuid(UID,UID,UID)}==0)?;
    let h=Header {version:0x2008_0522,pid:0};let d=[Data {effective:0,permitted:0,inheritable:0};2];
    require(unsafe {libc::syscall(libc::SYS_capset,&h,d.as_ptr())}==0
        && unsafe {libc::prctl(libc::PR_SET_DUMPABLE,0,0,0,0)}==0
        && unsafe {libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL,0,0,0)}==0
        && unsafe {libc::getppid()}==parent)?;
    let value=Identity {pid,parent,last};value.check()?;Ok(value)
}
impl Identity {
    pub(super) fn check(&self)->Result<(),String> {
        let mut header=Header {version:0x2008_0522,pid:0};let mut data=[Data {effective:0,permitted:0,inheritable:0};2];let mut death=0;
        require(unsafe {libc::getpid()}==self.pid && unsafe {libc::getppid()}==self.parent && ids()?==([UID;3],[UID;3])
            && unsafe {libc::getgroups(0,std::ptr::null_mut())}==0
            && unsafe {libc::prctl(libc::PR_GET_DUMPABLE,0,0,0,0)}==0
            && unsafe {libc::prctl(libc::PR_GET_NO_NEW_PRIVS,0,0,0,0)}==1
            && unsafe {libc::prctl(libc::PR_GET_SECUREBITS,0,0,0,0)}==SECUREBITS as i32
            && unsafe {libc::prctl(libc::PR_GET_PDEATHSIG,&mut death,0,0,0)}==0 && death==libc::SIGKILL
            && unsafe {libc::syscall(libc::SYS_capget,&mut header,data.as_mut_ptr())}==0
            && data.iter().all(|d|d.effective==0 && d.permitted==0 && d.inheritable==0))?;
        for cap in 0..=self.last {require(unsafe {libc::prctl(libc::PR_CAPBSET_READ,cap as libc::c_ulong,0,0,0)}==0
            && unsafe {libc::prctl(47,1,cap as libc::c_ulong,0,0)}==0)?;}
        Ok(())
    }
}
