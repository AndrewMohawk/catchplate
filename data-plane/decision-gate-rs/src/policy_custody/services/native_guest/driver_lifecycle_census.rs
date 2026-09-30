//! Same-parent bounded kernel census. No input PID, inode or closure hash is
//! accepted as proof. Held duplicate capabilities are never exported.
use super::*;
use super::wire::{Descriptor,ProcessOriginal,MAX_DESCRIPTORS,MAX_PROCESSES};
use std::os::unix::fs::MetadataExt;

pub(super) fn process(pid:i32)->Result<(i32,u64),ShadowError>{
    let raw=driver_identity::bounded(&format!("/proc/{pid}/stat"),16384)?;
    let text=std::str::from_utf8(&raw).map_err(fail)?;
    let fields:Vec<_>=text.rsplit_once(") ").ok_or(ShadowError::BindingDrift)?.1.split_whitespace().collect();
    require(fields.len()>=20)?;
    let parent=fields[1].parse::<i32>().map_err(fail)?;let start=fields[19].parse::<u64>().map_err(fail)?;
    require(parent>0 && start>0)?;Ok((parent,start))
}
pub(super) struct HeldProcess {pub(super) pidfd:OwnedFd,pub(super) original:ProcessOriginal}
impl HeldProcess {
    pub(super) fn open(pid:i32)->Result<Self,ShadowError>{
        let before=process(pid)?;
        let raw=unsafe{libc::syscall(libc::SYS_pidfd_open,pid,0)};require(raw>=0)?;
        let pidfd=unsafe{OwnedFd::from_raw_fd(raw as i32)};
        retrieval_peer::same_process(pidfd.as_fd(),pid)?;
        let mut stat:libc::stat=unsafe{std::mem::zeroed()};
        require(unsafe{libc::fstat(pidfd.as_raw_fd(),&mut stat)}==0 && stat.st_ino>0 && process(pid)?==before)?;
        Ok(Self{pidfd,original:ProcessOriginal{process_id:pid,start_time_ticks:before.1,parent_id:before.0,
            pidfd_device:stat.st_dev,pidfd_inode:stat.st_ino}})
    }
    pub(super) fn check(&self)->Result<(),ShadowError>{
        retrieval_peer::same_process(self.pidfd.as_fd(),self.original.process_id)?;
        require(process(self.original.process_id)?==(self.original.parent_id,self.original.start_time_ticks))
    }
}
fn children(pid:i32)->Result<BTreeSet<i32>,ShadowError>{
    let mut children=BTreeSet::new();let mut threads=0usize;
    for entry in std::fs::read_dir(format!("/proc/{pid}/task")).map_err(fail)? {
        threads+=1;require(threads<=256)?;
        let tid=entry.map_err(fail)?.file_name().to_str().ok_or(ShadowError::BindingDrift)?
            .parse::<i32>().map_err(fail)?;require(tid>0)?;
        let mut raw=Vec::new();
        // Empty is genuine for a task with no children.
        use std::io::Read;
        File::open(format!("/proc/{pid}/task/{tid}/children")).map_err(fail)?
            .take(8193).read_to_end(&mut raw).map_err(fail)?;require(raw.len()<=8192)?;
        for item in std::str::from_utf8(&raw).map_err(fail)?.split_whitespace(){
            let child=item.parse::<i32>().map_err(fail)?;require(child>1)?;
            children.insert(child);require(children.len()<=MAX_PROCESSES)?;
        }
    }
    require(threads>0)?;Ok(children)
}
pub(super) fn descendants(parent:i32)->Result<Vec<HeldProcess>,ShadowError>{
    let mut pending=vec![parent];let mut output=BTreeMap::new();
    while let Some(pid)=pending.pop(){
        for child in children(pid)? {
            require(child!=parent && !output.contains_key(&child))?;
            let held=HeldProcess::open(child)?;require(held.original.parent_id==pid)?;
            pending.push(child);output.insert(child,held);require(output.len()<=MAX_PROCESSES)?;
        }
    }
    for value in output.values(){value.check()?;}
    Ok(output.into_values().collect())
}
fn fd_numbers(pid:i32)->Result<Vec<i32>,ShadowError>{
    let mut fds=BTreeSet::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd")).map_err(fail)?{
        let name=entry.map_err(fail)?.file_name();let n=name.to_str().ok_or(ShadowError::BindingDrift)?.parse::<i32>().map_err(fail)?;
        require(n>=0 && fds.insert(n) && fds.len()<=MAX_DESCRIPTORS)?;
    }
    require(!fds.is_empty())?;Ok(fds.into_iter().collect())
}
fn original(pid:i32,n:i32,fd:BorrowedFd<'_>)->Result<Descriptor,ShadowError>{
    let mut stat:libc::stat=unsafe{std::mem::zeroed()};
    require(unsafe{libc::fstat(fd.as_raw_fd(),&mut stat)}==0 && stat.st_ino>0)?;
    let raw=driver_identity::bounded(&format!("/proc/{pid}/fdinfo/{n}"),16384)?;
    let text=std::str::from_utf8(&raw).map_err(fail)?;
    let one=|prefix:&str|->Result<&str,ShadowError>{
        let v:Vec<_>=text.lines().filter_map(|v|v.strip_prefix(prefix)).collect();require(v.len()==1)?;Ok(v[0].trim())};
    let mount_id=one("mnt_id:")?.parse::<u64>().map_err(fail)?;
    let flags=u32::from_str_radix(one("flags:")?,8).map_err(fail)?;
    // FD_CLOEXEC belongs to the target descriptor, not the duplicated OFD.
    let actual=unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_GETFL)};
    require(actual>=0 && flags&!(libc::O_CLOEXEC as u32)==actual as u32 && mount_id>0)?;
    let current=std::fs::metadata(format!("/proc/{pid}/fd/{n}")).map_err(fail)?;
    require((current.dev(),current.ino(),current.mode(),current.uid(),current.gid())
        ==(stat.st_dev,stat.st_ino,stat.st_mode,stat.st_uid,stat.st_gid))?;
    Ok(Descriptor{fd:n,device:stat.st_dev,inode:stat.st_ino,mode:stat.st_mode,uid:stat.st_uid,gid:stat.st_gid,mount_id,flags})
}
pub(super) struct Descriptors {pub(super) originals:Vec<Descriptor>,held:Vec<OwnedFd>,pid:i32}
impl Descriptors {
    pub(super) fn capture(driver:&HeldProcess)->Result<Self,ShadowError>{
        driver.check()?;let pid=driver.original.process_id;let numbers=fd_numbers(pid)?;
        let mut held=Vec::new();let mut originals=Vec::new();
        for n in &numbers{
            let raw=unsafe{libc::syscall(libc::SYS_pidfd_getfd,driver.pidfd.as_raw_fd(),*n,0)};require(raw>=0)?;
            let fd=unsafe{OwnedFd::from_raw_fd(raw as i32)};originals.push(original(pid,*n,fd.as_fd())?);held.push(fd);
        }
        let owner=Self{originals,held,pid};driver.check()?;
        require(fd_numbers(pid)?==numbers)?;owner.check()?;Ok(owner)
    }
    pub(super) fn check(&self)->Result<(),ShadowError>{
        require(fd_numbers(self.pid)?==self.originals.iter().map(|v|v.fd).collect::<Vec<_>>())?;
        for (expected,fd) in self.originals.iter().zip(&self.held){require(original(self.pid,expected.fd,fd.as_fd())?==*expected)?;}
        Ok(())
    }
}

/// Genuine adopted-child reaping; a timeout never produces a terminal record.
/// Only the dedicated subreaper's descendants are in scope, not its independent
/// service peers. The original lifetime remains the absolute cleanup bound.
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
pub(super) struct Reaped {process:ProcessOriginal,terminal_code:i32,terminal_status:i32,reaped_at_boottime_ns:String}
pub(super) fn reap_descendants(parent:i32,deadline:u64)->Result<Vec<Reaped>,ShadowError>{
    let mut reaped=Vec::new();
    loop {
        require(unsafe{libc::getpid()}==parent && now()?<deadline)?;
        let current=children(parent)?;
        if current.is_empty(){return Ok(reaped);}
        for pid in current {
            require(reaped.len()+1<MAX_PROCESSES)?; // Includes the original driver already reaped.
            let before=process(pid)?;require(before.0==parent)?;
            let raw=unsafe{libc::syscall(libc::SYS_pidfd_open,pid,0)};require(raw>=0)?;
            let pidfd=unsafe{OwnedFd::from_raw_fd(raw as i32)};
            let mut stat:libc::stat=unsafe{std::mem::zeroed()};
            require(unsafe{libc::fstat(pidfd.as_raw_fd(),&mut stat)}==0 && process(pid)?==before)?;
            let killed=unsafe{libc::syscall(libc::SYS_pidfd_send_signal,pidfd.as_raw_fd(),libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),0)};
            require(killed==0 || std::io::Error::last_os_error().raw_os_error()==Some(libc::ESRCH))?;
            let (terminal_code,terminal_status)=loop {
                require(now()?<deadline)?;let mut info:libc::siginfo_t=unsafe{std::mem::zeroed()};
                require(unsafe{libc::waitid(libc::P_PIDFD,pidfd.as_raw_fd() as _,&mut info,libc::WEXITED|libc::WNOHANG)}==0)?;
                if unsafe{info.si_pid()}!=0 {
                    require(unsafe{info.si_pid()}==pid && info.si_signo==libc::SIGCHLD
                        && matches!(info.si_code,libc::CLD_EXITED|libc::CLD_KILLED|libc::CLD_DUMPED))?;
                    break (info.si_code,unsafe{info.si_status()});
                }
                let mut wait=libc::pollfd{fd:pidfd.as_raw_fd(),events:libc::POLLIN,revents:0};
                let n=unsafe{libc::poll(&mut wait,1,1)};
                require(n>=0 || std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR))?;
            };
            require(now()?<deadline)?;
            reaped.push(Reaped{process:ProcessOriginal{process_id:pid,start_time_ticks:before.1,parent_id:parent,
                pidfd_device:stat.st_dev,pidfd_inode:stat.st_ino},terminal_code,terminal_status,
                reaped_at_boottime_ns:now()?.to_string()});
        }
    }
}
