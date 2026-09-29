//! Explicit native pinned-command custody. Not policy-shadow authority itself.
mod elf;
mod image;
mod identity;
mod job;
mod process;
mod transport;
mod wire;
mod worker;
pub use elf::validate_static_amd64_elf_verifier;
pub use worker::run;
use crate::native_serving_privileges::{Association,Owner as Serving,Prepared as Privileged};
use serde::{Serialize,Deserialize};
use std::{path::PathBuf,os::fd::AsRawFd,sync::{Arc,Mutex,atomic::{AtomicBool,Ordering}}};
use wire::{require,now};
pub const UID:u32=64988;
pub const EXECUTABLE:&str="/usr/local/bin/serverware-native-shadow-worker";

#[derive(Debug,Clone,Copy,Eq,PartialEq,Serialize,Deserialize)]
#[serde(rename_all="lowercase")]
pub enum Purpose {Runtime,Webauthn,Publication}
impl Purpose {
    fn index(self)->usize {match self {Self::Runtime=>0,Self::Webauthn=>1,Self::Publication=>2}}
    fn maximum(self)->usize {if self==Self::Publication {2*1024*1024} else {65536}}
    fn input(self,value:&serde_json::Value)->Result<(),String> {
        let api=value.get("apiVersion").and_then(|v|v.as_str());let operation=value.get("operation").and_then(|v|v.as_str());
        require(match self {
            Self::Runtime=>api==Some("serverware.policyShadowRuntimeAttestationVerificationRequest/v1") && operation==Some("verify-generation-runtime"),
            Self::Webauthn=>api==Some("serverware.policyActivationWebAuthnVerificationRequest/v1") && operation==Some("resolve-and-verify-assertion-by-digest"),
            Self::Publication=>api==Some("serverware.policyShadowGenerationPublicationHandoff/v1") && matches!(operation,Some("prepare-or-recover"|"commit")),
        })
    }
}
#[derive(Debug,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Executable {pub path:PathBuf,pub sha256:String}
#[derive(Debug,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Configuration {api_version:String,executable:Executable}
impl Configuration {
    pub fn validate(&self)->Result<(),String> {
        require(self.api_version=="serverware.nativeShadowWorkers/v1" && self.executable.path==std::path::Path::new(EXECUTABLE)
            && wire::hash(&self.executable.sha256))
    }
}
struct Core {
    association:Association,process:process::Process,bootstrap:image::Sealed,
    images:[image::Image;3],worker:image::Image,nonce:String,deadline:u64,
    cohort:Arc<crate::StartedGuestCohort>,
}
impl Drop for Core {
    fn drop(&mut self) {
        // Cold failures may occur before the native lifetime can attach this
        // owner. Attempt the same bounded real reap; Drop cannot claim success.
        let _ = self.process.stop_and_reap();
    }
}
pub struct Prepared {core:Core}
pub struct Owner {core:Core,serving:Arc<Serving>,sequence:Mutex<u64>,poisoned:AtomicBool}
impl Prepared {
    pub fn launch(configuration:Configuration,commands:[Executable;3],prepared:&Privileged,
        cohort:Arc<crate::StartedGuestCohort>)->Result<Self,String> {
        use ring::rand::SecureRandom;
        use base64::Engine as _;
        configuration.validate()?;prepared.check()?;cohort.require_shadow_preparation(prepared)?;
        let association=Association::capture(prepared)?;
        let worker=image::Image::open(&configuration.executable.path,&configuration.executable.sha256)?;
        let [runtime,webauthn,publication]=commands;
        let paths=[runtime.path.to_str().ok_or("runtime path not UTF8")?.to_owned(),
            webauthn.path.to_str().ok_or("WebAuthn path not UTF8")?.to_owned(),
            publication.path.to_str().ok_or("publication path not UTF8")?.to_owned()];
        let images=[image::Image::open(&runtime.path,&runtime.sha256)?,image::Image::open(&webauthn.path,&webauthn.sha256)?,
            image::Image::open(&publication.path,&publication.sha256)?];
        let mut entropy=[0;32];ring::rand::SystemRandom::new().fill(&mut entropy).map_err(|_|"shadow nonce unavailable")?;
        require(entropy.iter().any(|v|*v!=0))?;
        let nonce=base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(entropy);
        let bootstrap=wire::Bootstrap {api_version:"serverware.nativeShadowWorkerBootstrap/v1".into(),channel_nonce:nonce.clone(),
            deadline_boottime_ns:prepared.deadline(),executable_sha256:std::array::from_fn(|i|images[i].sealed.sha256().to_owned()),executable_path:paths};
        bootstrap.validate()?;
        let bootstrap=image::Sealed::new(&wire::encode(&bootstrap)?,false)?;
        let process=process::Process::spawn(&worker.sealed,&bootstrap,&[&images[0].sealed,&images[1].sealed,&images[2].sealed],prepared)?;
        let core=Core {association,process,bootstrap,images,worker,nonce,deadline:prepared.deadline(),cohort};
        transport::wait(core.process.channel.as_raw_fd(),libc::POLLIN,&core.process.pidfd,core.deadline)?;
        let packet=transport::receive(core.process.channel.as_raw_fd(),0)?;core.process.authenticate(&packet)?;
        let initialized:wire::Initialized=wire::decode(&packet.bytes)?;
        require(initialized.api_version=="serverware.nativeShadowWorkerInitialized/v1" && initialized.channel_nonce==core.nonce
            && initialized.bootstrap_sha256==core.bootstrap.sha256())?;
        prepared.check()?;core.cohort.require_shadow_preparation(prepared)?;
        Ok(Self {core})
    }
    pub fn bind(self,serving:Arc<Serving>)->Result<Arc<Owner>,String> {
        self.core.association.require(&serving)?;self.core.cohort.require_serving(&serving)?;
        let result=Arc::new(Owner {core:self.core,serving,sequence:Mutex::new(0),poisoned:AtomicBool::new(false)});
        result.check()?;Ok(result)
    }
}
impl Owner {
    pub fn deadline(&self)->u64 {self.core.deadline}
    pub fn require_serving(&self,serving:&Serving)->Result<(),String> {
        self.core.association.require(serving)?;require(std::ptr::eq(self.serving.as_ref(),serving))?;self.check()
    }
    pub fn check(&self)->Result<(),String> {
        let result=(|| {
            require(!self.poisoned.load(Ordering::Acquire) && now()?<self.core.deadline)?;
            self.core.association.require(&self.serving)?;self.core.cohort.require_serving(&self.serving)?;
            self.core.process.check()?;self.core.bootstrap.check()?;self.core.worker.check()?;
            for image in &self.core.images {image.check()?;}Ok(())
        })();
        if result.is_err() {self.poisoned.store(true,Ordering::Release);self.core.process.stop();}result
    }
    /// One source-owned call, no queued work or retry after an uncertain send.
    /// Returned bytes remain untrusted until the existing signed-result checks.
    pub fn execute(&self,purpose:Purpose,input:&serde_json::Value)->Result<Vec<u8>,String> {
        self.check()?;purpose.input(input)?;
        let mut sequence=self.sequence.try_lock().map_err(|_|"native shadow command owner busy")?;
        let started=now()?;
        let deadline=self.core.deadline.min(started.checked_add(wire::WINDOW).ok_or("shadow deadline overflow")?);
        let result=(|| {
            let bytes=wire::encode(input)?;require(!bytes.is_empty() && bytes.len()<=wire::MAX_INPUT)?;
            let original=image::Sealed::new(&bytes,false)?;
            *sequence=sequence.checked_add(1).ok_or("shadow command sequence exhausted")?;
            let request=wire::Request {api_version:"serverware.nativeShadowWorkerRequest/v1".into(),sequence:*sequence,purpose,
                input_sha256:original.sha256().to_owned(),input_bytes:original.length(),deadline_boottime_ns:deadline,
                channel_nonce:self.core.nonce.clone(),bootstrap_sha256:self.core.bootstrap.sha256().to_owned()};
            transport::wait(self.core.process.channel.as_raw_fd(),libc::POLLOUT,&self.core.process.pidfd,deadline)?;
            self.check()?;require(now()?<deadline)?;
            transport::send(self.core.process.channel.as_raw_fd(),&wire::encode(&request)?,Some(original.file.as_raw_fd()))?;
            transport::wait(self.core.process.channel.as_raw_fd(),libc::POLLIN,&self.core.process.pidfd,deadline)?;
            let packet=transport::receive(self.core.process.channel.as_raw_fd(),1)?;self.core.process.authenticate(&packet)?;
            let response:wire::Response=wire::decode(&packet.bytes)?;
            require(response.api_version=="serverware.nativeShadowWorkerResponse/v1" && response.request==request
                && response.result.status=="process-exited-zero" && response.result.output_bytes>0
                && response.result.output_bytes<=purpose.maximum() as u64)?;
            let output=image::Sealed::receive(std::fs::File::from(packet.descriptor.ok_or("shadow output original absent")?),UID,
                response.result.output_bytes,&response.result.output_sha256,false)?;
            original.check()?;self.check()?;require(now()?<deadline)?;
            let bytes=output.bytes()?;require(now()?<deadline)?;Ok(bytes)
        })();
        if result.is_err() {self.poisoned.store(true,Ordering::Release);self.core.process.stop();}result
    }
    pub fn request_stop(&self) {self.poisoned.store(true,Ordering::Release);self.core.process.stop();}
    pub fn stop_and_reap(&self)->Result<(),String> {self.request_stop();self.core.process.stop_and_reap()}
}
