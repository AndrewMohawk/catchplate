//! Three fixed independent Setup purposes. This owner admits protected files
//! and actual boot/lifetime only; the unchanged Python issuer verifies authority.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role { Hardware, Proxy, Final }
impl Role {
    pub(crate) fn name(self) -> &'static str { match self {
        Self::Hardware => "hardware-verifier", Self::Proxy => "proxy-verifier", Self::Final => "final-authority",
    } }
    fn launch_name(self) -> &'static str { match self {
        Self::Hardware => "setup-native-hardware-verifier-launch.json",
        Self::Proxy => "setup-native-proxy-verifier-launch.json",
        Self::Final => "setup-native-final-authority-launch.json",
    } }
    fn configuration_name(self) -> &'static str { match self {
        Self::Hardware => "setup-native-hardware-verifier.json",
        Self::Proxy => "setup-native-proxy-verifier.json",
        Self::Final => "setup-native-final-authority.json",
    } }
    pub(super) fn configuration_path(self) -> &'static str { match self {
        Self::Hardware => "/etc/catchplate/setup-native-hardware-verifier.json",
        Self::Proxy => "/etc/catchplate/setup-native-proxy-verifier.json",
        Self::Final => "/etc/catchplate/setup-native-final-authority.json",
    } }
    pub(crate) fn image_path(self) -> &'static str { match self {
        Self::Hardware => "/opt/catchplate/setup-native-hardware-verifier-runtime.squashfs",
        Self::Proxy => "/opt/catchplate/setup-native-proxy-verifier-runtime.squashfs",
        Self::Final => "/opt/catchplate/setup-native-final-authority-runtime.squashfs",
    } }
    pub(super) fn entrypoint(self) -> &'static str { match self {
        Self::Hardware => "/opt/catchplate/scripts/verify_native_setup_hardware.py",
        Self::Proxy => "/opt/catchplate/scripts/verify_native_setup_proxy.py",
        Self::Final => "/opt/catchplate/scripts/issue_native_setup_final.py",
    } }
    pub(super) fn image_purpose(self) -> Purpose { match self {
        Self::Hardware => Purpose::ExternalSetupHardware,
        Self::Proxy => Purpose::ExternalSetupProxy,
        Self::Final => Purpose::ExternalSetupFinal,
    } }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SetupLaunch {
    api_version: String, role: String, runtime_image: RuntimeImage,
    issuer_configuration_sha256: String,
}
/// Retained SAME public files and external process/time origin through result
/// emission after image retirement. No paths, copied policy or new deadline.
pub(crate) struct PublicOriginals { launch:Original, configuration:Original, origin:Origin, issued:u64, deadline:u64 }
impl PublicOriginals {
    pub(crate) fn check(&self)->Result<(),String> {
        self.origin.check()?; self.launch.check()?; self.configuration.check()?;
        within(self.issued,self.deadline)
    }
}
impl RuntimeAdmission {
    pub(crate) fn retain_setup_originals(&self)->Result<PublicOriginals,String> {
        self.check()?;
        ensure(matches!(self.policy.profile,Profile::Setup(_)),"Setup original retention purpose differs")?;
        let owner=PublicOriginals { launch:self.launch.retain()?,configuration:self.configuration.retain()?,
            origin:self.origin.retain()?,issued:self.policy.issued,deadline:self.policy.deadline };
        owner.check()?; Ok(owner)
    }
}
pub(super) fn open(role: Role) -> Result<RuntimeAdmission, String> {
    let origin = Origin::capture()?;
    let launch = Original::open(role.launch_name(), 16384)?;
    let selected: SetupLaunch = serde_json::from_value(document(&launch.bytes, 16384)?)
        .map_err(|_| "Setup launch shape differs")?;
    ensure(selected.api_version == "catchplate.setupNativeIndependentIssuerLaunch/v1"
        && selected.role == role.name() && selected.runtime_image.profile == "sealed-memfd-squashfs-v1"
        && selected.runtime_image.image_path == role.image_path(), "Setup launch purpose differs")?;
    for pin in [&selected.issuer_configuration_sha256, &selected.runtime_image.image_sha256,
        &selected.runtime_image.interpreter_sha256, &selected.runtime_image.entrypoint_sha256] { digest(pin)?; }
    let configuration = Original::open(role.configuration_name(), 4 * 1024 * 1024)?;
    ensure(hash(&configuration.bytes) == selected.issuer_configuration_sha256, "Setup configuration pin differs")?;
    let value = document(&configuration.bytes, 4 * 1024 * 1024)?;
    let fields = value.as_object().ok_or("Setup configuration not object")?;
    let expected = ["apiVersion", "role", "uid", "gid", "operation", "authorityRootPublicKeyPem",
        "authorityConfigurationOriginal", "authorityConfigurationSha256", "controlPlaneConfigurationDigest"];
    ensure(fields.len() == expected.len() && expected.iter().all(|key| fields.contains_key(*key))
        && value["apiVersion"] == "catchplate.setupNativeIndependentVerifierConfiguration/v1"
        && value["role"] == role.name(), "Setup configuration purpose/shape differs")?;
    let uid = value["uid"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or("Setup UID invalid")?;
    let gid = value["gid"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or("Setup GID invalid")?;
    ensure([uid, gid].iter().all(|v| *v > 0 && *v < u32::MAX && ![64988,64989,64990,65534].contains(v)),
        "Setup identity is reserved or root")?;
    let op: Operation = serde_json::from_value(value["operation"].clone()).map_err(|_| "Setup operation shape differs")?;
    ensure(op.boot_id_base64url == origin.boot && op.time_namespace_device > 0 && op.time_namespace_inode > 0
        && origin.time_identity()? == (op.time_namespace_device, op.time_namespace_inode), "Setup boot/time namespace differs")?;
    let issued = decimal(&op.issued_at_boottime_ns)?;
    let deadline = decimal(&op.deadline_boottime_ns)?;
    ensure(deadline.checked_sub(issued).is_some_and(|v| v > 0 && v <= 30_000_000_000), "Setup original interval differs")?;
    within(issued, deadline)?;
    let image_config = ImageConfiguration { profile: selected.runtime_image.profile,
        image_path: selected.runtime_image.image_path, image_sha256: selected.runtime_image.image_sha256,
        interpreter_sha256: selected.runtime_image.interpreter_sha256, helper_sha256: selected.runtime_image.entrypoint_sha256 };
    let owner = RuntimeAdmission { launch, configuration, origin,
        policy: Policy { uid, gid, issued, deadline, purpose: None, profile: Profile::Setup(role) }, image_config };
    owner.check()?;
    Ok(owner)
}
