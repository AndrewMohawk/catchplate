//! Actual cold image and sealed static executable, retained until child reap.
use super::*;
use super::FileAdmission;
use serverware_decision_gate::native_secret_broker_v1::shadow_image::ShadowImage;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd};
use std::os::unix::fs::{FileExt,MetadataExt};

const MAX_EXECUTABLE:u64=64*1024*1024;
const SEALS:i32=libc::F_SEAL_WRITE|libc::F_SEAL_GROW|libc::F_SEAL_SHRINK|libc::F_SEAL_SEAL;
pub(super) struct Image {
    image:ShadowImage,configuration:Original,configuration_bytes:Vec<u8>,
    executable:File,identity:(u64,u64,u64),
}
impl Image {
    /// Explicit pair-only continuation: retain the executable allocated before
    /// assignment. Equality is checked against the actual admitted image, not
    /// against a caller assertion about what the child will execute.
    pub(super) fn prepare_pair(pin:&Pin,delivery:&FileAdmission,executable:BorrowedFd<'_>,
        image_sha256:&Sha256Digest,executable_sha256:&Sha256Digest)->Result<Self,ShadowError> {
        delivery.check_preparation().map_err(fail)?;
        let configuration=pin.open(1024*1024)?;
        let configuration_bytes=configuration.read(1024*1024).map_err(fail)?.to_vec();
        let selected:ClosureConfiguration=exact(&configuration_bytes)?;
        selected.require_pair_image(image_sha256,executable_sha256)?;
        let image=selected.prepare_parent_image(delivery)?;
        let source=image.executable();let stat=source.metadata().map_err(fail)?;
        require(stat.is_file() && stat.len()>0 && stat.len()<=MAX_EXECUTABLE)?;
        let raw=unsafe{libc::fcntl(executable.as_raw_fd(),libc::F_DUPFD_CLOEXEC,128)};
        require(raw>=128)?;let executable=unsafe{File::from_raw_fd(raw)};
        require(executable.metadata().map_err(fail)?.len()==stat.len())?;
        let mut expected=vec![0;stat.len() as usize];let mut actual=vec![0;expected.len()];
        source.read_exact_at(&mut expected,0).map_err(fail)?;
        executable.read_exact_at(&mut actual,0).map_err(fail)?;
        require(expected==actual && Sha256Digest::compute(&actual)==*executable_sha256)?;
        let stat=executable.metadata().map_err(fail)?;
        let owner=Self{image,configuration,configuration_bytes,executable,identity:(stat.dev(),stat.ino(),stat.len())};
        owner.check(delivery)?;delivery.check_preparation().map_err(fail)?;Ok(owner)
    }
    pub(super) fn prepare(pin:&Pin,delivery:&FileAdmission)->Result<Self,ShadowError> {
        delivery.check_preparation().map_err(fail)?;
        let configuration=pin.open(1024*1024)?;
        let configuration_bytes=configuration.read(1024*1024).map_err(fail)?.to_vec();
        let selected:ClosureConfiguration=exact(&configuration_bytes)?;
        let image=selected.prepare_parent_image(delivery)?;
        let source=image.executable();let stat=source.metadata().map_err(fail)?;
        require(stat.is_file() && stat.len()>0 && stat.len()<=MAX_EXECUTABLE)?;
        let mut bytes=vec![0;stat.len() as usize];let mut offset=0;
        while offset<bytes.len() {
            let count=source.read_at(&mut bytes[offset..],offset as u64).map_err(fail)?;
            require(count>0)?;offset+=count;
        }
        serverware_decision_gate::native_shadow_workers::validate_static_amd64_elf_verifier(&bytes).map_err(fail)?;
        let raw=unsafe{libc::syscall(libc::SYS_memfd_create,c"native-shadow-guest-executable".as_ptr(),
            libc::MFD_CLOEXEC|libc::MFD_ALLOW_SEALING)};
        require(raw>=0)?;let mut executable=unsafe{File::from_raw_fd(raw as i32)};
        executable.write_all(&bytes).map_err(fail)?;
        require(unsafe{libc::fchown(executable.as_raw_fd(),0,0)}==0
            && unsafe{libc::fchmod(executable.as_raw_fd(),0o500)}==0
            && unsafe{libc::fcntl(executable.as_raw_fd(),libc::F_ADD_SEALS,SEALS)}==0)?;
        let stat=executable.metadata().map_err(fail)?;
        let owner=Self{image,configuration,configuration_bytes,executable,identity:(stat.dev(),stat.ino(),stat.len())};
        // Full copy comparison, not an executable path/name assertion.
        let mut copied=vec![0;bytes.len()];let mut offset=0;
        while offset<copied.len() {
            let count=owner.executable.read_at(&mut copied[offset..],offset as u64).map_err(fail)?;
            require(count>0)?;offset+=count;
        }
        require(copied==bytes)?;owner.check(delivery)?;delivery.check_preparation().map_err(fail)?;Ok(owner)
    }
    pub(super) fn check(&self,delivery:&FileAdmission)->Result<(),ShadowError> {
        delivery.check().map_err(fail)?;self.image.check(delivery.lifetime()).map_err(fail)?;
        require(self.configuration.read(1024*1024).map_err(fail)?.as_slice()==self.configuration_bytes.as_slice())?;
        let stat=self.executable.metadata().map_err(fail)?;
        let mut fs:libc::statfs=unsafe{std::mem::zeroed()};
        require(stat.is_file() && stat.nlink()==0 && stat.uid()==0 && stat.gid()==0 && stat.mode()&0o7777==0o500
            && (stat.dev(),stat.ino(),stat.len())==self.identity
            && unsafe{libc::fcntl(self.executable.as_raw_fd(),libc::F_GET_SEALS)}==SEALS
            && unsafe{libc::fstatfs(self.executable.as_raw_fd(),&mut fs)}==0 && fs.f_type==0x0102_1994)
    }
    pub(super) fn executable(&self)->BorrowedFd<'_> {self.executable.as_fd()}
}
