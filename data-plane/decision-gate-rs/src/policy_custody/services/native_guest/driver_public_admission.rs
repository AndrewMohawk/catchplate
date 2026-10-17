//! Fixed public-original export, only after genuine combined admission. The
//! retained sealed file is data; neither its existence nor its SHA is authority.
use super::*;
use std::io::Write;
use crate::policy_shadow::policy_custody::services::guest::native_guest::driver_lifecycle::wire;

impl Retained {
    pub(super) fn publish_public_admission(&self,keys:&admission::AdmittedKeys,
        closure:&Original,assignment:&Original,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        self.check_startup()?;
        if !self.prepared.cold.lifecycle().is_some_and(|v|v.facade_selected()){return Ok(());}
        let mut held=self.public_admission.try_lock().map_err(fail)?;require(held.is_none())?;
        let (key_configuration_original,admission_authorization_original,evidence_original,combined_result_original)=
            keys.public_bridge_originals(trust,time)?;
        require(evidence_original.len()<=131072 && combined_result_original.len()<=32768)?;
        let text=|bytes:Vec<u8>|->Result<String,ShadowError>{require(bytes.is_ascii())?;String::from_utf8(bytes).map_err(fail)};
        let original=wire::PublicAdmission{api_version:"catchplate.nativeShadowDriverPublicAdmission/v1".into(),
            bootstrap_observation_original:text(canonical_json_bytes(&self.observation)?)?,
            phase_scope_original:text(self.phase.scope().to_vec())?,
            phase_bundle_original:text(self.phase.public_bundle_original()?)?,
            closure_original:text(closure.read(1024*1024).map_err(fail)?.to_vec())?,
            assignment_original:text(assignment.read(4*1024*1024).map_err(fail)?.to_vec())?,
            key_configuration_original,admission_authorization_original,evidence_original,combined_result_original};
        let raw=canonical_json_bytes(&original)?;
        require(!raw.is_empty() && raw.len()<=wire::MAX_ADMISSION_ORIGINALS)?;
        let fd=unsafe{libc::syscall(libc::SYS_memfd_create,c"native-driver-public-admission".as_ptr(),
            libc::MFD_CLOEXEC|libc::MFD_ALLOW_SEALING)};require(fd>=0)?;
        let mut file=unsafe{File::from_raw_fd(fd as i32)};file.write_all(&raw).map_err(fail)?;
        require(unsafe{libc::fchmod(file.as_raw_fd(),0o400)}==0
            && unsafe{libc::fcntl(file.as_raw_fd(),libc::F_ADD_SEALS,super::super::SEALS)}==0)?;
        let notice=wire::AdmissionNotice{api_version:"catchplate.nativeShadowDriverPublicAdmissionNotice/v1".into(),
            observation_sha256:Sha256Digest::compute(original.bootstrap_observation_original.as_bytes()),
            scope_sha256:Sha256Digest::compute(original.phase_scope_original.as_bytes()),
            original_sha256:Sha256Digest::compute(&raw),length:raw.len() as u64};
        // Retain before the single irreversible send, including unknown outcome.
        *held=Some(file);let fd=held.as_ref().ok_or(ShadowError::BindingDrift)?.as_fd();
        require(retrieval_peer::send(self.prepared.channel.as_fd(),&canonical_json_bytes(&notice)?,&[fd])?)?;
        self.check_startup()
    }
}
