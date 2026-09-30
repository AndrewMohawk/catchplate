//! Actual same-process kernel descriptors. This owner is not deserializable.
use super::*;
use super::super::super::guest_original::Process;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd};
use std::os::unix::fs::{FileExt,MetadataExt};

#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Descriptor {name:String,device:u64,inode:u64,mode:u32,mount_id:u64}
fn descriptor(name:&str,fd:BorrowedFd<'_>)->Result<Descriptor,ShadowError> {
    let mut stat:libc::stat=unsafe{std::mem::zeroed()};
    require(unsafe{libc::fstat(fd.as_raw_fd(),&mut stat)}==0)?;
    let raw=bounded(&format!("/proc/self/fdinfo/{}",fd.as_raw_fd()),16384)?;
    let raw=std::str::from_utf8(&raw).map_err(fail)?;
    let ids:Vec<_>=raw.lines().filter_map(|v|v.strip_prefix("mnt_id:")).collect();
    require(ids.len()==1)?;let mount_id=ids[0].trim().parse::<u64>().map_err(fail)?;
    require(mount_id>0 && stat.st_ino>0)?;
    Ok(Descriptor{name:name.into(),device:stat.st_dev,inode:stat.st_ino,mode:stat.st_mode,mount_id})
}
pub(super) fn bounded(path:&str,maximum:usize)->Result<Vec<u8>,ShadowError> {
    let mut raw=Vec::new();File::open(path).map_err(fail)?.take((maximum+1) as u64).read_to_end(&mut raw).map_err(fail)?;
    require(!raw.is_empty() && raw.len()<=maximum)?;Ok(raw)
}
fn membership()->Result<Vec<u8>,ShadowError> {
    let raw=bounded("/proc/self/cgroup",16384)?;
    let text=std::str::from_utf8(&raw).map_err(fail)?;
    require(text.starts_with("0::/") && text.ends_with('\n') && text.lines().count()==1)?;
    Ok(raw)
}
fn open_cgroup(raw:&[u8])->Result<File,ShadowError> {
    let text=std::str::from_utf8(raw).map_err(fail)?;
    let relative=text.strip_prefix("0::/").and_then(|v|v.strip_suffix('\n')).ok_or(ShadowError::BindingDrift)?;
    require(relative.split('/').all(|v|!v.is_empty() && v!="." && v!=".."))?;
    let root=File::open("/sys/fs/cgroup").map_err(fail)?;
    #[repr(C)]struct How{flags:u64,mode:u64,resolve:u64}
    let path=std::ffi::CString::new(relative).map_err(fail)?;
    let how=How{flags:(libc::O_PATH|libc::O_DIRECTORY|libc::O_CLOEXEC|libc::O_NOFOLLOW) as u64,
        mode:0,resolve:0x08|0x04|0x02};
    let fd=unsafe{libc::syscall(libc::SYS_openat2,root.as_raw_fd(),path.as_ptr(),&how,std::mem::size_of::<How>())};
    require(fd>=0)?;let file=unsafe{File::from_raw_fd(fd as i32)};
    let mut fs:libc::statfs=unsafe{std::mem::zeroed()};
    require(unsafe{libc::fstatfs(file.as_raw_fd(),&mut fs)}==0 && fs.f_type==0x6367_7270)?;
    Ok(file)
}
fn cgroup_handle(fd:BorrowedFd<'_>)->Result<(u64,u64),ShadowError> {
    // Linux kernfs exports FILEID_KERNFS (0xfe), exactly one native u64 ID.
    // Never substitute st_ino or a hash for the kernel cgroup ID.
    #[repr(C)]struct Handle{bytes:u32,kind:i32,id:[u8;8]}
    let mut handle=Handle{bytes:8,kind:0,id:[0;8]};let mut mount=0i32;
    require(unsafe{libc::syscall(libc::SYS_name_to_handle_at,fd.as_raw_fd(),c"".as_ptr(),
        &mut handle,&mut mount,libc::AT_EMPTY_PATH)}==0
        && handle.bytes==8 && handle.kind==0xfe && mount>0)?;
    let id=u64::from_ne_bytes(handle.id);require(id>0)?;Ok((id,mount as u64))
}

#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Observation {
    pub(super) api_version:String,pub(super) configuration_sha256:Sha256Digest,
    pub(super) window_sha256:Sha256Digest,pub(super) invocation_id:String,
    pub(super) process_id:i32,pub(super) uid:u32,pub(super) gid:u32,
    pub(super) cgroup_original_sha256:Sha256Digest,pub(super) root:Descriptor,
    pub(super) seccomp_filter_count:u64,pub(super) descriptors:Vec<Descriptor>,
    pub(super) driver:ProductionCustodyKernelDriverIdentity,
}
impl Observation {
    /// Called only on the retained clone child's SCM_PIDFD/credentials. This
    /// is the privileged parent's observation, not trust in supplied fields.
    pub(super) fn require_child(&self,packet:&retrieval_peer::Packet,executable:&File)->Result<(),ShadowError> {
        require(unsafe{libc::geteuid()}==0 && self.process_id==packet.credentials.pid
            && self.uid==packet.credentials.uid && self.gid==packet.credentials.gid && self.seccomp_filter_count>0)?;
        self.require_process(packet.pidfd.as_fd(),executable)
    }
    /// Independently sample a real retained process descriptor. This does not
    /// assert parent/child ownership or manufacture SCM sender credentials.
    /// The four recorded descriptors are the original measurement inputs,
    /// never a census of descriptors subsequently admitted to the bridge.
    pub(super) fn require_process(&self,pidfd:BorrowedFd<'_>,executable:&File)->Result<(),ShadowError> {
        require(unsafe{libc::geteuid()}==0 && self.seccomp_filter_count>0)?;
        retrieval_peer::same_process(pidfd,self.process_id)?;
        let own_pidfd=descriptor("self-pidfd",pidfd)?;
        let exe=File::open(format!("/proc/{}/exe",self.process_id)).map_err(fail)?;
        let m=exe.metadata().map_err(fail)?;let original=executable.metadata().map_err(fail)?;
        require((m.dev(),m.ino(),m.len())==(original.dev(),original.ino(),original.len()))?;
        let root=File::open(format!("/proc/{}/root",self.process_id)).map_err(fail)?;
        let root_stat=root.metadata().map_err(fail)?;
        require((root_stat.dev(),root_stat.ino())==(self.root.device,self.root.inode))?;
        let group=bounded(&format!("/proc/{}/cgroup",self.process_id),16384)?;
        require(Sha256Digest::compute(&group)==self.cgroup_original_sha256)?;
        let group_fd=open_cgroup(&group)?;let handle=cgroup_handle(group_fd.as_fd())?;
        let group_stat=group_fd.metadata().map_err(fail)?;
        let status=bounded(&format!("/proc/{}/status",self.process_id),65536)?;
        let status=std::str::from_utf8(&status).map_err(fail)?;
        for (label,expected) in [("Uid:",self.uid),("Gid:",self.gid)] {
            let values:Vec<_>=status.lines().filter_map(|v|v.strip_prefix(label)).collect();
            require(values.len()==1)?;
            let ids=values[0].split_whitespace().map(str::parse::<u32>).collect::<Result<Vec<_>,_>>().map_err(fail)?;
            require(ids==[expected;4])?;
        }
        for (label,expected) in [("Threads:","1"),("NoNewPrivs:","1"),("Seccomp:","2"),
            ("CapInh:","0000000000000000"),("CapPrm:","0000000000000000"),
            ("CapEff:","0000000000000000"),("CapBnd:","0000000000000000"),("CapAmb:","0000000000000000")] {
            let values:Vec<_>=status.lines().filter_map(|v|v.strip_prefix(label)).collect();
            require(values.len()==1 && values[0].trim()==expected)?;
        }
        let filters:Vec<_>=status.lines().filter_map(|v|v.strip_prefix("Seccomp_filters:")).collect();
        require(filters.len()==1 && filters[0].trim().parse::<u64>().map_err(fail)?==self.seccomp_filter_count)?;
        let stat=bounded(&format!("/proc/{}/stat",self.process_id),16384)?;
        let stat=std::str::from_utf8(&stat).map_err(fail)?;
        let start=stat.rsplit_once(") ").and_then(|v|v.1.split_whitespace().nth(19))
            .ok_or(ShadowError::BindingDrift)?.parse::<u64>().map_err(fail)?;
        let instance=Sha256Digest::compute(&canonical_json_bytes(&(&self.invocation_id,self.process_id,start,own_pidfd.inode))?);
        require(self.driver.driver_instance_sha256==instance && self.driver.process_start_time_ticks==start && self.driver.pidfd_inode==own_pidfd.inode
            && self.driver.cgroup_id==handle.0 && self.driver.cgroup_mount_id==handle.1 && self.driver.cgroup_inode==group_stat.ino()
            && self.driver.retained_descriptor_manifest_sha256==Sha256Digest::compute(&canonical_json_bytes(&self.descriptors)?)
            && self.descriptors.len()==4 && self.descriptors[0]==own_pidfd
            && self.descriptors[1].name=="executable" && (self.descriptors[1].device,self.descriptors[1].inode)==(m.dev(),m.ino())
            && self.descriptors[2].name=="cgroup" && self.descriptors[2].inode==group_stat.ino()
            && self.descriptors[2].device==group_stat.dev() && self.descriptors[2].mode==group_stat.mode()
            && self.descriptors[2].mount_id==handle.1
            && self.root.name=="root" && self.root.mode==root_stat.mode() && self.descriptors[3]==self.root)?;
        retrieval_peer::same_process(pidfd,self.process_id)
    }
}
pub(super) struct Owner {
    process:Process,executable:File,cgroup:File,root:File,
    executable_sha256:Sha256Digest,cgroup_bytes:Vec<u8>,handle:(u64,u64),
    before:Vec<Descriptor>,observation:Option<Observation>,
}
impl Owner {
    pub(super) fn executable(&self)->Result<File,ShadowError>{self.check()?;self.executable.try_clone().map_err(fail)}
    pub(super) fn prepare(executable_sha256:&Sha256Digest,root:BorrowedFd<'_>)->Result<Self,ShadowError> {
        require(unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0)?;
        let process=Process::capture().map_err(fail)?;
        let executable=File::open("/proc/self/exe").map_err(fail)?;
        let m=executable.metadata().map_err(fail)?;
        let seals=libc::F_SEAL_WRITE|libc::F_SEAL_GROW|libc::F_SEAL_SHRINK|libc::F_SEAL_SEAL;
        require(m.is_file() && m.uid()==0 && m.gid()==0 && m.mode()&0o7777==0o500
            && m.nlink()==0 && m.len()>0 && m.len()<=64*1024*1024
            && unsafe{libc::fcntl(executable.as_raw_fd(),libc::F_GET_SEALS)}==seals)?;
        let mut bytes=vec![0;m.len() as usize];executable.read_exact_at(&mut bytes,0).map_err(fail)?;
        require(Sha256Digest::compute(&bytes)==*executable_sha256)?;
        serverware_decision_gate::native_shadow_workers::validate_static_amd64_elf_verifier(&bytes).map_err(fail)?;
        let cgroup_bytes=membership()?;let cgroup=open_cgroup(&cgroup_bytes)?;
        let handle=cgroup_handle(cgroup.as_fd())?;
        let root=File::from(retrieval_peer::duplicate(root)?);
        let before=vec![descriptor("self-pidfd",process.descriptor())?,descriptor("executable",executable.as_fd())?,
            descriptor("cgroup",cgroup.as_fd())?,descriptor("root",root.as_fd())?];
        require(before[2].mount_id==handle.1)?;
        Ok(Self{process,executable,cgroup,root,executable_sha256:executable_sha256.clone(),
            cgroup_bytes,handle,before,observation:None})
    }
    pub(super) fn measure(&mut self,prepared:&super::driver_bootstrap::Prepared,filters:u64)->Result<&Observation,ShadowError> {
        require(self.observation.is_none())?;prepared.check_final()?;self.check_descriptors()?;
        let current=std::fs::metadata("/").map_err(fail)?;let expected=self.root.metadata().map_err(fail)?;
        require((current.dev(),current.ino())==(expected.dev(),expected.ino()) && filters>0)?;
        let own=self.process.native_binding().map_err(fail)?;
        let domain=self.process.domain();let observed=now()?;
        let descriptor_sha=Sha256Digest::compute(&canonical_json_bytes(&self.before)?);
        let instance=Sha256Digest::compute(&canonical_json_bytes(&(prepared.invocation(),own.0,own.1,own.2))?);
        let driver=ProductionCustodyKernelDriverIdentity::from_verified_kernel_descriptors(instance,
            self.executable_sha256.clone(),Sha256Digest::compute(&domain.authority_boot_id()),
            own.1,own.2,self.handle.0,self.handle.1,self.before[2].inode,descriptor_sha,observed)?;
        self.observation=Some(Observation{api_version:"serverware.nativeShadowDriverObservation/v1".into(),
            configuration_sha256:prepared.configuration_sha256(),window_sha256:prepared.window_sha256(),
            invocation_id:prepared.invocation().into(),process_id:own.0,uid:prepared.uid(),gid:prepared.gid(),
            cgroup_original_sha256:Sha256Digest::compute(&self.cgroup_bytes),root:self.before[3].clone(),
            seccomp_filter_count:filters,descriptors:self.before.clone(),driver});
        prepared.check_final()?;self.check()?;self.observation.as_ref().ok_or(ShadowError::BindingDrift)
    }
    fn check_descriptors(&self)->Result<(),ShadowError> {
        self.process.check().map_err(fail)?;
        require(membership()?==self.cgroup_bytes
            && self.before==vec![descriptor("self-pidfd",self.process.descriptor())?,descriptor("executable",self.executable.as_fd())?,
                descriptor("cgroup",self.cgroup.as_fd())?,descriptor("root",self.root.as_fd())?])
    }
    pub(super) fn check(&self)->Result<(),ShadowError> {
        self.check_descriptors()?;
        if let Some(observation)=&self.observation {
            require(unsafe{libc::getuid()}==observation.uid && unsafe{libc::geteuid()}==observation.uid
                && unsafe{libc::getgid()}==observation.gid && unsafe{libc::getegid()}==observation.gid
                && super::driver_bootstrap::filters()?==observation.seccomp_filter_count)?;
            let actual=std::fs::metadata("/").map_err(fail)?;
            require((actual.dev(),actual.ino())==(observation.root.device,observation.root.inode))?;
        }
        Ok(())
    }
}
