//! Foreign measured bridge retention. This owner never signals or reaps it.
//! Only the genuine DriverBootstrap supervisor owns that child and its image.
use super::*;
use std::os::unix::fs::FileExt;

pub(super) const CONFIG_API:&str="serverware.nativeShadowProofCohortConfiguration/v7";
pub(super) const ROLES:&[&str]=&["retrieval","persistence","trustedTime","generationInstall",
    "commitRequest","ingressAdmission","terminalAppend","dispatchBarrier","activeEffectBarrier","activeEffectCommit"];
pub(super) const RELEASE_API:&str="serverware.nativeShadowProofCohortRelease/v6";
pub(super) const RELEASE_DOMAIN:&[u8]=b"serverware.nativeShadowProofCohortRelease.signature/v6\0";
pub(super) const CLEANUP_API:&str="serverware.nativeShadowProofCohortCleanup/v6";
pub(super) const CLEANUP_DOMAIN:&[u8]=b"serverware.nativeShadowProofCohortCleanup.signature/v6\0";
pub(super) const TERMINAL_API:&str="serverware.nativeShadowProofCohortTerminal/v6";
pub(super) const CLEANUP_RESULT_API:&str="serverware.nativeShadowProofCohortCleanupResult/v6";
const INDEX:[usize;10]=[0,1,2,3,5,6,7,8,9,10];
const MAX_EXECUTABLE:usize=64*1024*1024;
const SEALS:i32=libc::F_SEAL_WRITE|libc::F_SEAL_GROW|libc::F_SEAL_SHRINK|libc::F_SEAL_SEAL;
pub(super) fn logical_index(index:usize)->Result<usize,ShadowError>{
    INDEX.get(index).copied().ok_or(ShadowError::BindingDrift)
}
pub(super) fn owned_index(logical:usize)->Option<usize>{INDEX.iter().position(|v|*v==logical)}

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Configuration {
    configuration_sha256:Sha256Digest,window_sha256:Sha256Digest,
    observation_sha256:Sha256Digest,supervisor_executable_sha256:Sha256Digest,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Input {api_version:String,configuration_original:String,window_original:String,observation_original:String}
#[derive(Clone,Serialize)]
#[serde(rename_all="camelCase")]
struct ProcessOriginal {process_id:i32,start_time_ticks:u64,pidfd_device:u64,pidfd_inode:u64}
#[derive(Clone,Serialize)]
#[serde(rename_all="camelCase")]
struct ExecutableOriginal {device:u64,inode:u64,length:u64,sha256:Sha256Digest}
#[derive(Clone,Serialize)]
#[serde(rename_all="camelCase")]
pub(super) struct BindingOriginal {
    api_version:&'static str,binding_sha256:Sha256Digest,configuration_sha256:Sha256Digest,
    window_sha256:Sha256Digest,observation_sha256:Sha256Digest,
    supervisor:ProcessOriginal,driver:ProcessOriginal,executable:ExecutableOriginal,
}
pub(super) struct Owner {
    cold:driver_bootstrap::Cold,supervisor:OwnedFd,driver:OwnedFd,
    supervisor_executable:File,executable:File,supervisor_executable_identity:(u64,u64,u64),
    caller:i32,observation:driver_identity::Observation,original:BindingOriginal,
}
fn process(pid:i32)->Result<(i32,u64),ShadowError>{
    let raw=driver_identity::bounded(&format!("/proc/{pid}/stat"),16384)?;
    let raw=std::str::from_utf8(&raw).map_err(fail)?;
    let fields:Vec<_>=raw.rsplit_once(") ").ok_or(ShadowError::BindingDrift)?.1.split_whitespace().collect();
    require(fields.len()>19)?;
    let parent=fields[1].parse::<i32>().map_err(fail)?;
    let start=fields[19].parse::<u64>().map_err(fail)?;
    require(pid>1 && parent>1 && start>0)?;Ok((parent,start))
}
fn pidfd_pid(fd:BorrowedFd<'_>)->Result<i32,ShadowError>{
    let raw=driver_identity::bounded(&format!("/proc/self/fdinfo/{}",fd.as_raw_fd()),16384)?;
    let text=std::str::from_utf8(&raw).map_err(fail)?;
    let fields:Vec<_>=text.lines().filter_map(|line|line.strip_prefix("Pid:")).collect();
    require(fields.len()==1)?;let pid=fields[0].trim().parse::<i32>().map_err(fail)?;
    retrieval_peer::same_process(fd,pid)?;Ok(pid)
}
fn pidfd_identity(fd:BorrowedFd<'_>)->Result<(u64,u64),ShadowError>{
    let mut s:libc::stat=unsafe{zeroed()};
    require(unsafe{libc::fstat(fd.as_raw_fd(),&mut s)}==0 && s.st_ino>0)?;
    Ok((s.st_dev,s.st_ino))
}
fn sealed(file:&File)->Result<(u64,u64,u64),ShadowError>{
    let m=file.metadata().map_err(fail)?;let mut fs:libc::statfs=unsafe{zeroed()};
    require(m.is_file() && m.uid()==0 && m.gid()==0 && m.mode()&0o7777==0o500 && m.nlink()==0
        && m.len()>0 && m.len()<=MAX_EXECUTABLE as u64
        && unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GET_SEALS)}==SEALS
        && unsafe{libc::fstatfs(file.as_raw_fd(),&mut fs)}==0 && fs.f_type==0x0102_1994)?;
    Ok((m.dev(),m.ino(),m.len()))
}
fn executable(file:&File,digest:&Sha256Digest)->Result<(u64,u64,u64),ShadowError>{
    let id=sealed(file)?;let mut bytes=vec![0;id.2 as usize];file.read_exact_at(&mut bytes,0).map_err(fail)?;
    require(Sha256Digest::compute(&bytes)==*digest)?;
    serverware_decision_gate::native_shadow_workers::validate_static_amd64_elf_verifier(&bytes).map_err(fail)?;
    require(sealed(file)?==id)?;Ok(id)
}
impl Owner {
    pub(super) fn admit(config:&Configuration,raw:&[u8],rights:Vec<OwnedFd>,caller:i32,
        admission:&inputs::Admission)->Result<Self,ShadowError>{
        require(admission.endpoint_only() && !raw.is_empty() && raw.len()<=MAX_WIRE && rights.len()==3)?;
        let input:Input=exact(raw)?;
        require(input.api_version=="serverware.nativeShadowEndpointDriverBinding/v1"
            && input.configuration_original.is_ascii() && input.window_original.is_ascii() && input.observation_original.is_ascii()
            && Sha256Digest::compute(input.configuration_original.as_bytes())==config.configuration_sha256
            && Sha256Digest::compute(input.window_original.as_bytes())==config.window_sha256
            && Sha256Digest::compute(input.observation_original.as_bytes())==config.observation_sha256)?;
        // Reuse the genuine fixed-file bootstrap authority/shape/window
        // verifier. The caller cannot select another config path or verifier.
        let cold=driver_bootstrap::Cold::open()?;
        require(cold.configuration.read(65536).map_err(fail)?.as_slice()==input.configuration_original.as_bytes()
            && cold.window.read(32768).map_err(fail)?.as_slice()==input.window_original.as_bytes()
            && cold.operational() && cold.bridge_admission_selected() && cold.lifecycle().is_some())?;
        let configuration:serde_json::Value=exact(input.configuration_original.as_bytes())?;
        let delivery_pin:Pin=exact(&canonical_json_bytes(configuration.get("deliveryConfiguration")
            .ok_or(ShadowError::BindingDrift)?)?)?;
        let delivery_configuration=delivery_pin.open(65536)?;
        // Removing the owned bridge slot does not remove its old C9 authority
        // separation/identity checks. Bootstrap and phase-two retain their
        // distinct authorities; all actual C9 service configurations still
        // share the independently admitted cohort delivery authority.
        admission.require_driver_delivery_configuration(&delivery_configuration.read(65536).map_err(fail)?)?;
        let window:serde_json::Value=exact(input.window_original.as_bytes())?;
        let window=window.get("payload").ok_or(ShadowError::BindingDrift)?;
        let cohort_window:serde_json::Value=exact(&admission.window_binding()?)?;
        for name in ["bootIdBase64url","timeNamespaceDevice","timeNamespaceInode","issuedAtBoottimeNs",
            "startupDeadlineBoottimeNs","lifetimeDeadlineBoottimeNs","invocationId"] {
            require(window.get(name).is_some() && window.get(name)==cohort_window.get(name))?;
        }
        let observation:driver_identity::Observation=exact(input.observation_original.as_bytes())?;
        cold.check_observation(&observation)?;
        let mut rights=rights.into_iter();let supervisor=rights.next().ok_or(ShadowError::BindingDrift)?;
        let driver=rights.next().ok_or(ShadowError::BindingDrift)?;
        let file=File::from(rights.next().ok_or(ShadowError::BindingDrift)?);require(rights.next().is_none())?;
        let supervisor_pid=pidfd_pid(supervisor.as_fd())?;
        require(supervisor_pid!=caller && supervisor_pid!=unsafe{libc::getpid()}
            && observation.process_id!=supervisor_pid && observation.process_id!=caller
            && observation.process_id!=unsafe{libc::getpid()})?;
        let (parent,supervisor_start)=process(supervisor_pid)?;require(parent==caller)?;
        require(process(observation.process_id)?==(supervisor_pid,observation.driver.process_start_time_ticks))?;
        let supervisor_executable=File::open(format!("/proc/{supervisor_pid}/exe")).map_err(fail)?;
        let supervisor_executable_identity=executable(&supervisor_executable,&config.supervisor_executable_sha256)?;
        let id=executable(&file,cold.executable_sha256())?;
        observation.require_process(driver.as_fd(),&file)?;
        let supervisor_fd=pidfd_identity(supervisor.as_fd())?;let driver_fd=pidfd_identity(driver.as_fd())?;
        require(supervisor_fd!=driver_fd)?;
        let original=BindingOriginal{api_version:"serverware.nativeShadowEndpointDriverOriginal/v1",
            binding_sha256:Sha256Digest::compute(raw),configuration_sha256:config.configuration_sha256.clone(),
            window_sha256:config.window_sha256.clone(),observation_sha256:config.observation_sha256.clone(),
            supervisor:ProcessOriginal{process_id:supervisor_pid,start_time_ticks:supervisor_start,
                pidfd_device:supervisor_fd.0,pidfd_inode:supervisor_fd.1},
            driver:ProcessOriginal{process_id:observation.process_id,start_time_ticks:observation.driver.process_start_time_ticks,
                pidfd_device:driver_fd.0,pidfd_inode:driver_fd.1},
            executable:ExecutableOriginal{device:id.0,inode:id.1,length:id.2,sha256:cold.executable_sha256().clone()}};
        let owner=Self{cold,supervisor,driver,supervisor_executable,executable:file,supervisor_executable_identity,
            caller,observation,original};
        owner.check_active()?;admission.check_startup()?;Ok(owner)
    }
    /// Used during endpoint cleanup too: no /proc liveness prerequisite and
    /// no foreign waitid. Retained seals/FD identities survive process exit.
    pub(super) fn check_retained(&self)->Result<(),ShadowError>{
        self.cold.check_lifetime()?;
        require(pidfd_identity(self.supervisor.as_fd())?==(self.original.supervisor.pidfd_device,self.original.supervisor.pidfd_inode)
            && pidfd_identity(self.driver.as_fd())?==(self.original.driver.pidfd_device,self.original.driver.pidfd_inode)
            && sealed(&self.supervisor_executable)?==self.supervisor_executable_identity
            && sealed(&self.executable)?==(self.original.executable.device,self.original.executable.inode,self.original.executable.length))
    }
    pub(super) fn check_active(&self)->Result<(),ShadowError>{
        self.check_retained()?;let supervisor=&self.original.supervisor;
        retrieval_peer::same_process(self.supervisor.as_fd(),supervisor.process_id)?;
        require(process(supervisor.process_id)?==(self.caller,supervisor.start_time_ticks)
            && process(self.observation.process_id)?==(supervisor.process_id,self.original.driver.start_time_ticks))?;
        let exe=File::open(format!("/proc/{}/exe",supervisor.process_id)).map_err(fail)?;
        require(sealed(&exe)?==self.supervisor_executable_identity)?;
        let raw=driver_identity::bounded(&format!("/proc/{}/status",supervisor.process_id),65536)?;
        let text=std::str::from_utf8(&raw).map_err(fail)?;
        for name in ["Uid:","Gid:"] {
            let fields:Vec<_>=text.lines().filter_map(|line|line.strip_prefix(name)).collect();
            require(fields.len()==1 && fields[0].split_whitespace().collect::<Vec<_>>()==["0";4])?;
        }
        self.observation.require_process(self.driver.as_fd(),&self.executable)?;
        retrieval_peer::same_process(self.supervisor.as_fd(),supervisor.process_id)
    }
    pub(super) fn identity(&self)->(u32,u32){(self.observation.uid,self.observation.gid)}
    pub(super) fn require_peer(&self,peer:&ExpectedPeerCredentialV3)->Result<(),ShadowError>{
        self.check_active()?;peer.checked().map_err(fail)?;let actual=&self.original;
        require((peer.pid,peer.start_time_ticks)==(actual.driver.process_id,actual.driver.start_time_ticks)
            && (peer.uid,peer.gid)==self.identity()
            && (peer.executable_device,peer.executable_inode,peer.executable_length)
                ==(actual.executable.device,actual.executable.inode,actual.executable.length)
            && peer.executable_sha256==actual.executable.sha256)
    }
    pub(super) fn original(&self)->Result<BindingOriginal,ShadowError>{self.check_retained()?;Ok(self.original.clone())}
    pub(super) fn binding_sha256(&self)->Result<Sha256Digest,ShadowError>{
        self.check_retained()?;Ok(Sha256Digest::compute(&canonical_json_bytes(&self.original)?))
    }
}
