//! Purpose-fixed immutable filesystem mechanism, NOT custody authorization.
//! The policy-shadow caller must retain its independently admitted delivery
//! and signed native assignment. No broker child or key operation is exposed.
use super::{image::{Image, Purpose}, ImageConfiguration};
use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd};

pub const IMAGE_PATH: &str = "/opt/catchplate/native-shadow-custody-runtime.squashfs";
pub const EXECUTABLE_PATH: &str = "/usr/local/bin/catchplate-policy-shadow-custody-guest";
pub const SECCOMP_PATH: &str = "/opt/catchplate/native-shadow-custody/seccomp.bpf";
pub const CONFIGURATION_PATH: &str = "/opt/catchplate/native-shadow-custody/runtime.json";
pub const LOCK_PATH: &str = "/opt/catchplate/native-shadow-custody/Cargo.lock";
pub const RECIPE_PATH: &str = "/opt/catchplate/native-shadow-custody/build-recipe.json";
pub const PROVENANCE_PATH: &str = "/opt/catchplate/native-shadow-custody/provenance.json";

/// Retains actual sealed image, readonly loop/mount and closed image originals.
/// This mechanism's scalar deadline never substitutes for a caller's owner.
pub struct ShadowImage { image:Image, artifacts:[File;5] }
impl ShadowImage {
    pub fn open(image_sha256:&str, executable_sha256:&str, pins:[&str;5], deadline:u64)->Result<Self,String> {
        let image=Image::open_for(&ImageConfiguration {
            profile:"sealed-memfd-squashfs-v1".into(), image_path:IMAGE_PATH.into(),
            image_sha256:image_sha256.into(), interpreter_sha256:executable_sha256.into(), helper_sha256:pins[0].into(),
        },deadline,Purpose::ShadowCustody)?;
        let artifacts=[
            image.retain_artifact(SECCOMP_PATH,pins[0],deadline)?,
            image.retain_artifact(CONFIGURATION_PATH,pins[1],deadline)?,
            image.retain_artifact(LOCK_PATH,pins[2],deadline)?,
            image.retain_artifact(RECIPE_PATH,pins[3],deadline)?,
            image.retain_artifact(PROVENANCE_PATH,pins[4],deadline)?,
        ];
        Ok(Self {image,artifacts})
    }
    pub fn check(&self,deadline:u64)->Result<(),String> {self.image.check(deadline)}
    pub fn root(&self)->BorrowedFd<'_> {self.image.root.as_fd()}
    pub fn executable(&self)->&File {&self.image.interpreter}
    pub fn seccomp(&self)->&File {&self.artifacts[0]}
    pub fn configuration(&self)->&File {&self.artifacts[1]}
}
