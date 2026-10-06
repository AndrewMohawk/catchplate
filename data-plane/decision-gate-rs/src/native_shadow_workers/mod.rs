//! Explicit native pinned-command custody. Not policy-shadow authority itself.
mod elf;
mod image;
mod identity;
mod job;
mod process;
mod transport;
mod wire;
mod worker;
pub mod publication_resources;
pub mod runtime_resources;
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
pub struct LegacyConfiguration {api_version:String,executable:Executable}
#[derive(Debug,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct PublicationConfiguration {api_version:String,executable:Executable,resources:publication_resources::Configuration}
#[derive(Debug,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct RuntimeConfiguration {
    api_version:String,executable:Executable,runtime_resources:runtime_resources::Configuration,
    #[serde(default,deserialize_with="present_publication_resources")]
    publication_resources:Option<publication_resources::Configuration>,
}
fn present_publication_resources<'de,D:serde::Deserializer<'de>>(d:D)->Result<Option<publication_resources::Configuration>,D::Error> {
    publication_resources::Configuration::deserialize(d).map(Some)
}
#[derive(Debug,Deserialize)]
#[serde(untagged)]
pub enum Configuration {Legacy(LegacyConfiguration),Publication(PublicationConfiguration),Runtime(RuntimeConfiguration)}
impl Configuration {
    pub fn validate(&self)->Result<(),String> {
        let executable=match self {
            Self::Legacy(v)=>{require(v.api_version=="serverware.nativeShadowWorkers/v1")?;&v.executable},
            Self::Publication(v)=>{require(v.api_version=="serverware.nativeShadowWorkers/v2"
                && !v.resources.runtime_verification_required())?;v.resources.validate()?;&v.executable},
            Self::Runtime(v)=>{
                require(v.api_version=="serverware.nativeShadowWorkers/v3")?;v.runtime_resources.validate()?;
                if let Some(publication)=&v.publication_resources {
                    publication.validate()?;
                    require(v.runtime_resources.inherited_fds().iter().all(|fd| !publication.inherited_fds().contains(fd)))?;
                }
                &v.executable
            },
        };
        require(executable.path==std::path::Path::new(EXECUTABLE) && wire::hash(&executable.sha256))
    }
    pub fn publication_resources(&self)->bool {
        matches!(self,Self::Publication(_)) || matches!(self,Self::Runtime(v) if v.publication_resources.is_some())
    }
    pub fn runtime_resources(&self)->bool {matches!(self,Self::Runtime(_))}
    pub fn validate_legacy(&self)->Result<(),String> {self.validate()?;require(matches!(self,Self::Legacy(_)))}
    fn into_parts(self)->(Executable,Option<publication_resources::Configuration>,Option<runtime_resources::Configuration>) {
        match self {
            Self::Legacy(v)=>(v.executable,None,None),Self::Publication(v)=>(v.executable,Some(v.resources),None),
            Self::Runtime(v)=>(v.executable,v.publication_resources,Some(v.runtime_resources)),
        }
    }
}
struct Core {
    association:Association,process:process::Process,bootstrap:image::Sealed,
    images:[Option<image::Image>;3],worker:image::Image,nonce:String,deadline:u64,
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
        Self::launch_inner(configuration,commands.map(Some),prepared,cohort,None,None)
    }
    pub fn launch_with_publication(configuration:Configuration,commands:[Executable;3],prepared:&Privileged,
        cohort:Arc<crate::StartedGuestCohort>,pins:publication_resources::PublicationAuthorityPins)->Result<Self,String> {
        Self::launch_inner(configuration,commands.map(Some),prepared,cohort,Some(pins),None)
    }
    pub fn launch_with_runtime(configuration:Configuration,commands:[Executable;3],prepared:&Privileged,
        cohort:Arc<crate::StartedGuestCohort>,runtime_pins:runtime_resources::RuntimeAuthorityPins,
        publication_pins:Option<publication_resources::PublicationAuthorityPins>)->Result<Self,String> {
        Self::launch_inner(configuration,commands.map(Some),prepared,cohort,publication_pins,Some(runtime_pins))
    }
    pub fn launch_native_activation(configuration:Configuration,commands:[Executable;2],prepared:&Privileged,
        cohort:Arc<crate::StartedGuestCohort>,runtime_pins:runtime_resources::RuntimeAuthorityPins,
        publication_pins:publication_resources::PublicationAuthorityPins)->Result<Self,String> {
        require(configuration.runtime_resources() && configuration.publication_resources())?;
        let [runtime,publication]=commands;
        Self::launch_inner(configuration,[Some(runtime),None,Some(publication)],prepared,cohort,
            Some(publication_pins),Some(runtime_pins))
    }
    fn launch_inner(configuration:Configuration,commands:[Option<Executable>;3],prepared:&Privileged,
        cohort:Arc<crate::StartedGuestCohort>,pins:Option<publication_resources::PublicationAuthorityPins>,
        runtime_pins:Option<runtime_resources::RuntimeAuthorityPins>)->Result<Self,String> {
        use ring::rand::SecureRandom;
        use base64::Engine as _;
        configuration.validate()?;prepared.check()?;cohort.require_shadow_preparation(prepared)?;
        let [runtime,webauthn,publication]=commands;
        let runtime=runtime.ok_or("runtime command is required")?;
        let publication=publication.ok_or("publication command is required")?;
        require(webauthn.is_some() || pins.is_some() && runtime_pins.is_some())?;
        let association=Association::capture(prepared)?;
        let (executable,resources,runtime_config)=configuration.into_parts();
        if let Some(pins)=&runtime_pins {
            require(runtime.path==std::path::Path::new(runtime_resources::EXECUTABLE)
                && runtime.sha256==pins.verifier_executable_sha256)?;
        }
        let runtime_resources=match (runtime_config,runtime_pins) {
            (Some(config),Some(pins))=>Some(runtime_resources::ColdResources::open(config,pins,prepared.deadline())?),
            (None,None)=>None,
            _=>return Err("runtime resources require the independently admitted policy/key/checkpoint pins".into()),
        };
        let resources=match (resources,pins) {
            (Some(config),Some(pins))=>{
                let verification=if config.runtime_verification_required() {
                    Some(runtime_resources.as_ref().ok_or("Nitro publication requires the retained runtime verifier owner")?
                        .publication_verification()?)
                } else {None};
                Some(publication_resources::ColdResources::open(config,pins,prepared.deadline(),verification)?)
            },
            (None,None)=>None,
            _=>return Err("publication resources require the independently admitted trust profile".into()),
        };
        let worker=image::Image::open(&executable.path,&executable.sha256)?;
        if resources.is_some() {
            require(publication.path==std::path::Path::new("/usr/local/bin/serverware-native-publication-handoff"))?;
        }
        let runtime_path=runtime.path.to_str().ok_or("runtime path not UTF8")?.to_owned();
        let publication_path=publication.path.to_str().ok_or("publication path not UTF8")?.to_owned();
        let webauthn_path=webauthn.as_ref().map(|command|command.path.to_str()
            .map(str::to_owned).ok_or("WebAuthn path not UTF8")).transpose()?;
        let runtime_image=image::Image::open(&runtime.path,&runtime.sha256)?;
        let webauthn_image=webauthn.as_ref().map(|command|image::Image::open(&command.path,&command.sha256)).transpose()?;
        let publication_image=image::Image::open(&publication.path,&publication.sha256)?;
        let mut entropy=[0;32];ring::rand::SystemRandom::new().fill(&mut entropy).map_err(|_|"shadow nonce unavailable")?;
        require(entropy.iter().any(|v|*v!=0))?;
        let nonce=base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(entropy);
        let bootstrap=if let Some(webauthn)=&webauthn_image {
            let bootstrap=wire::Bootstrap {api_version:"serverware.nativeShadowWorkerBootstrap/v1".into(),channel_nonce:nonce.clone(),
                deadline_boottime_ns:prepared.deadline(),executable_sha256:[runtime_image.sealed.sha256().to_owned(),
                    webauthn.sealed.sha256().to_owned(),publication_image.sealed.sha256().to_owned()],
                executable_path:[runtime_path,webauthn_path.ok_or("WebAuthn command path absent")?,publication_path]};
            match (runtime_resources.as_ref(),resources.as_ref()) {
            (Some(runtime),publication)=>wire::WorkerBootstrap::Runtime(wire::RuntimeBootstrap {
                api_version:"serverware.nativeShadowWorkerBootstrap/v3".into(),worker:bootstrap,
                runtime_resources_sha256:runtime.bootstrap.sha256().to_owned(),
                publication_resources_sha256:publication.map(|value|value.bootstrap.sha256().to_owned()),
            }),
            (None,None)=>wire::WorkerBootstrap::Legacy(bootstrap),
            (None,Some(value))=>wire::WorkerBootstrap::Publication(wire::PublicationBootstrap {
                api_version:"serverware.nativeShadowWorkerBootstrap/v2".into(),worker:bootstrap,
                publication_resources_sha256:value.bootstrap.sha256().to_owned(),
            }),
            }
        } else {
            let runtime=runtime_resources.as_ref().ok_or("native-only runtime resources absent")?;
            let publication=resources.as_ref().ok_or("native-only publication resources absent")?;
            wire::WorkerBootstrap::NativeActivation(wire::NativeActivationBootstrap {
                api_version:"serverware.nativeShadowWorkerBootstrap/v4".into(),channel_nonce:nonce.clone(),
                deadline_boottime_ns:prepared.deadline(),
                executable_sha256:[runtime_image.sealed.sha256().to_owned(),publication_image.sealed.sha256().to_owned()],
                executable_path:[runtime_path,publication_path],
                runtime_resources_sha256:runtime.bootstrap.sha256().to_owned(),
                publication_resources_sha256:publication.bootstrap.sha256().to_owned(),
            })
        };
        bootstrap.validate()?;
        let bootstrap=image::Sealed::new(&wire::encode(&bootstrap)?,false)?;
        let images=[Some(runtime_image),webauthn_image,Some(publication_image)];
        let command_images=std::array::from_fn(|i|images[i].as_ref().map(|image|&image.sealed));
        let process=process::Process::spawn(&worker.sealed,&bootstrap,&command_images,prepared,resources.as_ref(),runtime_resources.as_ref())?;
        drop(resources);drop(runtime_resources);
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
            for image in self.core.images.iter().flatten() {image.check()?;}Ok(())
        })();
        if result.is_err() {self.poisoned.store(true,Ordering::Release);self.core.process.stop();}result
    }
    /// One source-owned call, no queued work or retry after an uncertain send.
    /// Returned bytes remain untrusted until the existing signed-result checks.
    pub fn execute(&self,purpose:Purpose,input:&serde_json::Value)->Result<Vec<u8>,String> {
        self.check()?;purpose.input(input)?;
        require(self.core.images[purpose.index()].is_some())?;
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
