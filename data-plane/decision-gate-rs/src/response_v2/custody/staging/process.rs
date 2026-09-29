//! Real self process/cgroup originals retained by the measured gate. No PID,
//! pathname or ownership record is accepted from a request or configuration.
use std::{fs::File,io::Read,os::fd::{FromRawFd,OwnedFd}};
use super::super::peer_measurement as kernel;
use super::wire::ProcessOwner;

pub struct CurrentProcess {
    pid:libc::pid_t,
    pidfd:OwnedFd,
    process:kernel::StableProcessIdentity,
    cgroup_original:Vec<u8>,
    owner:ProcessOwner,
}
fn cgroup()->Result<Vec<u8>,String> {
    let mut bytes=Vec::new();
    File::open("/proc/self/cgroup").map_err(|_|"staging actual self cgroup absent")?.take(16*1024+1)
        .read_to_end(&mut bytes).map_err(|_|"read staging actual cgroup")?;
    if bytes.is_empty()||bytes.len()>16*1024 {return Err("staging actual cgroup original exceeds bound".into());}
    Ok(bytes)
}
impl CurrentProcess {
    pub fn capture()->Result<Self,String> {
        let pid=unsafe {libc::getpid()};
        let raw=unsafe {libc::syscall(libc::SYS_pidfd_open,pid,0)};
        if raw<0 {return Err("staging self PIDFD unavailable".into());}
        let pidfd=unsafe {OwnedFd::from_raw_fd(raw as libc::c_int)};
        let process=kernel::capture_received_pidfd(&pidfd).map_err(|_|"staging process original unavailable")?;
        if process.pid()!=pid||pid<=0 {return Err("staging process original is not self".into());}
        let cgroup_original=cgroup()?;
        let text=std::str::from_utf8(&cgroup_original).map_err(|_|"staging cgroup is not UTF-8")?;
        let mut path=None;
        for line in text.lines() {
            if let Some(value)=line.strip_prefix("0::/") {
                if path.replace(value).is_some() {return Err("staging cgroup-v2 entry repeats".into());}
            }
        }
        let path=path.ok_or("staging actual cgroup-v2 path absent")?;
        if path.is_empty()||path.len()>128||path.split('/').any(|part|part.is_empty()||part=="."||part==".."
            ||!part.bytes().all(|b|(0x21..=0x7e).contains(&b))) {
            return Err("staging requires the actual dedicated concrete cgroup; root/unknown path cannot be invented".into());
        }
        let binding=process.binding_sha256();
        let owner=ProcessOwner {process_id:format!("native-gate:{}",&binding[7..]),pid:pid as u32,
            start_time_ticks:process.start_time_ticks(),cgroup_id:path.into(),process_binding_sha256:binding,
            cgroup_sha256:crate::native_staging_v1::sha256(&cgroup_original)};
        let value=Self {pid,pidfd,process,cgroup_original,owner};value.check()?;Ok(value)
    }
    pub fn check(&self)->Result<(),String> {
        if unsafe {libc::getpid()}!=self.pid
            ||kernel::capture_received_pidfd(&self.pidfd).map_err(|_|"staging retained process exited")?!=self.process
            ||cgroup()?!=self.cgroup_original {return Err("staging actual process/cgroup original changed".into());}
        Ok(())
    }
    pub fn original(&self)->Result<&ProcessOwner,String> {self.check()?;Ok(&self.owner)}
}
