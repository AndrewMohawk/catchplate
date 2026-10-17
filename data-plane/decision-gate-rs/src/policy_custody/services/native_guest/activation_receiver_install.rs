//! Explicit cold/v2 installation authority for one bounded public-file roster.
//! No credential, executable or journal is installed, adopted, removed or reset.
//! Partial publication is terminal: this owner never deletes or retries it.
use super::*;
use std::ffi::CString;
use std::fs::File;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{FileExt, MetadataExt};

const DOMAIN: &str = "catchplate.nativeShadowActivationReceiverInstallation.signature/v1";
const NAMESPACE: &str = "/etc/catchplate/native-activation-inputs";
const LAUNCH: &str = "/etc/catchplate/native-shadow-guest-launch.json";
const VERIFIER: &str = "/etc/catchplate/native-shadow-public-exchange.json";
const MAX_TOTAL: usize = 720 * 1024;
const ROSTER: [(&str, usize); 13] = [
    ("/etc/catchplate/native-activation-inputs/activation-authority.json", 512 * 1024),
    ("/etc/catchplate/native-activation-inputs/activation.json", 65536),
    ("/etc/catchplate/native-activation-inputs/admission.json", 65536),
    ("/etc/catchplate/native-activation-inputs/assignment.json", 512 * 1024),
    ("/etc/catchplate/native-activation-inputs/closure.json", 512 * 1024),
    ("/etc/catchplate/native-activation-inputs/delivery.json", 65536),
    ("/etc/catchplate/native-activation-inputs/encrypted-keys.json", 65536),
    ("/etc/catchplate/native-activation-inputs/keys.json", 65536),
    ("/etc/catchplate/native-activation-inputs/runtime.json", 512 * 1024),
    ("/etc/catchplate/native-activation-inputs/time-bootstrap.json", 65536),
    ("/etc/catchplate/native-activation-inputs/trust.json", 512 * 1024),
    (LAUNCH, 32768), (VERIFIER, 32768),
];

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Completion { api_version: String, installation: Installation }
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Installation { payload: Payload, signature: CanonicalEd25519Signature }
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Payload {
    api_version: String, purpose: String, observation_sha256: Sha256Digest,
    configuration_sha256: Sha256Digest, delivery_configuration_sha256: Sha256Digest,
    launch_sha256: Sha256Digest, issued_at_boottime_ns: String,
    startup_deadline_boottime_ns: String, files: Vec<Entry>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry { path: String, sha256: Sha256Digest, original_base64url: String }
struct PublicFile { path: &'static str, sha256: Sha256Digest, bytes: Vec<u8> }

fn public<'a>(files: &'a [PublicFile], path: &str, sha: &Sha256Digest) -> Result<&'a [u8], ShadowError> {
    let value = files.iter().find(|v| v.path == path).ok_or(ShadowError::BindingDrift)?;
    require(value.sha256 == *sha)?; Ok(&value.bytes)
}
fn pin(files: &[PublicFile], value: &Pin, name: &str) -> Result<(), ShadowError> {
    let path = format!("{NAMESPACE}/{name}.json");
    require(value.path == std::path::Path::new(&path))?;
    public(files, &path, &value.sha256)?; Ok(())
}
impl Completion {
    pub(super) fn install(self, cold: &super::super::activation_receiver::Cold,
        observation_sha: &Sha256Digest) -> Result<(Sha256Digest, Installed, process::Timer), ShadowError> {
        cold.check()?;
        let p = &self.installation.payload;
        require(self.api_version == "catchplate.nativeShadowActivationReceiverCompletion/v2"
            && p.api_version == "catchplate.nativeShadowActivationReceiverInstallation/v1"
            && p.purpose == "install-activation-public-originals"
            && p.observation_sha256 == *observation_sha
            && p.configuration_sha256 == cold.configuration_sha256()
            && p.delivery_configuration_sha256 == cold.delivery_configuration().sha256
            && p.files.len() == ROSTER.len())?;
        // This key is available only from independently provisioned cold/v2,
        // explicitly delegating the existing C9 key for this separate purpose.
        let key = cold.installation_key()?;
        key.verify_strict(&signature_preimage(DOMAIN, &canonical_json_bytes(p)?),
            &Signature::from_bytes(&self.installation.signature.decode()?))
            .map_err(|_| ShadowError::SignatureInvalid)?;
        cold.require_installation_window(&p.issued_at_boottime_ns, &p.startup_deadline_boottime_ns)?;
        // Bound even a blocking filesystem call by the same signed absolute
        // BOOTTIME deadline; callbacks alone cannot interrupt a stuck fsync.
        let timer = process::Timer::arm(decimal(&p.startup_deadline_boottime_ns)?)?;
        timer.check()?;
        let mut files = Vec::with_capacity(ROSTER.len());
        let mut total = 0usize;
        for (entry, (path, maximum)) in p.files.iter().zip(ROSTER) {
            require(entry.path == path && entry.original_base64url.len() <= maximum.div_ceil(3) * 4)?;
            let bytes = URL_SAFE_NO_PAD.decode(&entry.original_base64url).map_err(fail)?;
            total = total.checked_add(bytes.len()).ok_or(ShadowError::CounterOverflow)?;
            require(!bytes.is_empty() && bytes.len() <= maximum && total <= MAX_TOTAL && bytes.is_ascii()
                && URL_SAFE_NO_PAD.encode(&bytes) == entry.original_base64url
                && Sha256Digest::compute(&bytes) == entry.sha256)?;
            // Canonical public JSON only. Real downstream closed types and
            // independent signatures remain mandatory after installation.
            let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(fail)?;
            require(canonical_json_bytes(&value)? == bytes)?;
            files.push(PublicFile { path, sha256: entry.sha256.clone(), bytes });
        }
        let (selected, service) = selection(public(&files, LAUNCH, &p.launch_sha256)?)?;
        let service = match service { SelectedService::Activation(v) => v,
            _ => return Err(ShadowError::BindingDrift) };
        require(selected.delivery_configuration.path == cold.delivery_configuration().path
            && selected.delivery_configuration.sha256 == p.delivery_configuration_sha256)?;
        for (value, name) in [(&selected.delivery, "delivery"), (&selected.trust, "trust"),
            (&selected.time_bootstrap, "time-bootstrap"), (&selected.assignment, "assignment"),
            (&selected.closure, "closure"), (&selected.keys, "keys"),
            (&selected.encrypted_keys, "encrypted-keys"), (&selected.admission, "admission"),
            (&service, "activation")] { pin(&files, value, name)?; }
        let (verifier_path, verifier_sha) = selected.verifier_transport.retained_pin()?;
        require(verifier_path == VERIFIER)?; public(&files, verifier_path, verifier_sha)?;
        let delivery: guest::Envelope = exact(public(&files,
            &selected.delivery.path.to_string_lossy(), &selected.delivery.sha256)?)?;
        let d = &delivery.payload;
        require(delivery.api_version == "catchplate.policyCustodyGuestDelivery/v1"
            && d.authority_key_id == Sha256Digest::compute(key.as_bytes())
            && d.issued_at_boottime_ns == p.issued_at_boottime_ns
            && d.startup_deadline_boottime_ns == p.startup_deadline_boottime_ns)?;
        let signature = URL_SAFE_NO_PAD.decode(&delivery.signature_base64url).map_err(fail)?;
        require(signature.len() == 64 && URL_SAFE_NO_PAD.encode(&signature) == delivery.signature_base64url)?;
        let mut message = b"catchplate.policyCustodyGuestDelivery.signature/v1\0".to_vec();
        message.extend(canonical_json_bytes(d)?);
        key.verify_strict(&message, &Signature::from_bytes(&signature.try_into().map_err(fail)?))
            .map_err(|_| ShadowError::SignatureInvalid)?;
        cold.require_delivery(d)?;
        let runtime_path = format!("{NAMESPACE}/runtime.json");
        require(d.runtime_config.path == std::path::Path::new(&runtime_path))?;
        public(&files, &runtime_path, &d.runtime_config.sha256)?;
        let encrypted: serde_json::Value = serde_json::from_slice(public(&files,
            &selected.encrypted_keys.path.to_string_lossy(), &selected.encrypted_keys.sha256)?).map_err(fail)?;
        require(encrypted["apiVersion"] == "catchplate.nativeShadowEncryptedKeyDelivery/v1")?;
        let inventory_sha = encrypted["authorization"]["payload"]["transport"]["encryptedInventorySha256"]
            .as_str().ok_or(ShadowError::BindingDrift)?;
        let mut inventories = 0usize;
        for credential in &d.credentials {
            // Even the encrypted inventory remains a separately provisioned
            // C9 credential; this public channel cannot install it or a seed.
            require(!files.iter().any(|v| credential.original.path == std::path::Path::new(v.path))
                && !credential.original.path.starts_with(NAMESPACE)
                && !credential.name.starts_with("shadow-key-custody-"))?;
            if credential.name == "shadow-encrypted-role-inventory" {
                require(credential.signing.is_none() && credential.length > 0 && credential.length <= 32768
                    && credential.original.sha256.as_str() == inventory_sha)?;
                inventories += 1;
            }
        }
        require(inventories == 1)?;
        let service: ServiceOriginal = exact(public(&files,
            &service.path.to_string_lossy(), &service.sha256)?)?;
        let binding = GuestClosureBinding { configuration_sha256: d.configuration_sha256.clone(),
            delivery_sha256: selected.delivery.sha256.clone(), runtime_configuration_sha256: d.runtime_config.sha256.clone(),
            service_role: "production-bridge".into(), uid: d.uid, gid: d.gid,
            boot_id_base64url: d.boot_id_base64url.clone(), time_namespace_device: d.time_namespace_device,
            time_namespace_inode: d.time_namespace_inode, issued_at_boottime_ns: d.issued_at_boottime_ns.clone(),
            startup_deadline_boottime_ns: d.startup_deadline_boottime_ns.clone(),
            lifetime_deadline_boottime_ns: d.lifetime_deadline_boottime_ns.clone(), invocation_id: d.invocation_id.clone() };
        require(service.payload.api_version == "catchplate.nativeShadowActivationServiceAssignment/v2"
            && service.payload.purpose == "native-policy-activation-publication"
            && d.service_role == guest::Role::ProductionBridge && service.payload.guest == binding)?;
        service.signature.decode()?;
        pin(&files, &service.payload.authority, "activation-authority")?;
        // No effects above. Installation stays on the original signed startup
        // window, including every write, readback, fsync and permission change.
        let check = || { timer.check()?; cold.check()?; cold.require_installation_window(
            &p.issued_at_boottime_ns, &p.startup_deadline_boottime_ns) };
        check()?;
        let installed = Installed::write(files, &check)?;
        check()?; installed.check()?;
        Ok((p.launch_sha256.clone(), installed, timer))
    }
}

#[derive(PartialEq, Eq)]
struct FileIdentity { device: u64, inode: u64, mode: u32, uid: u32, gid: u32, links: u64, length: u64,
    mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64 }
fn file_identity(file: &File) -> Result<FileIdentity, ShadowError> {
    let m = file.metadata().map_err(fail)?;
    Ok(FileIdentity { device: m.dev(), inode: m.ino(), mode: m.mode(), uid: m.uid(), gid: m.gid(),
        links: m.nlink(), length: m.len(), mtime: m.mtime(), mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(), ctime_ns: m.ctime_nsec() })
}
struct Directory { file: File, device: u64, inode: u64, mode: u32 }
impl Directory {
    fn from(file: File) -> Result<Self, ShadowError> {
        let m = file.metadata().map_err(fail)?;
        require(m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0)?;
        Ok(Self { file, device: m.dev(), inode: m.ino(), mode: m.mode() })
    }
    fn open(parent: &Self, name: &str) -> Result<Self, ShadowError> {
        parent.check()?;
        let name = CString::new(name).map_err(fail)?;
        let fd = unsafe { libc::openat(parent.file.as_raw_fd(), name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        require(fd >= 0)?; Self::from(unsafe { File::from_raw_fd(fd) })
    }
    fn check(&self) -> Result<(), ShadowError> {
        let m = self.file.metadata().map_err(fail)?;
        require(m.is_dir() && m.dev() == self.device && m.ino() == self.inode
            && m.mode() == self.mode && m.uid() == 0 && m.gid() == 0)
    }
    fn child(&self, name: &str, device: u64, inode: u64) -> Result<(), ShadowError> {
        self.check()?; let name = CString::new(name).map_err(fail)?;
        let mut s: libc::stat = unsafe { std::mem::zeroed() };
        require(unsafe { libc::fstatat(self.file.as_raw_fd(), name.as_ptr(), &mut s, libc::AT_SYMLINK_NOFOLLOW) } == 0
            && s.st_dev == device && s.st_ino == inode)
    }
    fn absent(&self, name: &str) -> Result<(), ShadowError> {
        self.check()?; let name = CString::new(name).map_err(fail)?;
        let mut s: libc::stat = unsafe { std::mem::zeroed() };
        require(unsafe { libc::fstatat(self.file.as_raw_fd(), name.as_ptr(), &mut s, libc::AT_SYMLINK_NOFOLLOW) } < 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT))
    }
}
struct Held { original: Original, path: &'static str, identity: FileIdentity }
/// A retained file owner, not an admission receipt or a rollback claim. The
/// real parent holds it until its actual child has exited and been reaped.
pub(crate) struct Installed { directories: Vec<Directory>, files: Vec<Held> }
impl Installed {
    fn directory(&self, path: &str) -> &Directory {
        &self.directories[if path.starts_with(&format!("{NAMESPACE}/")) { 3 } else { 2 }]
    }
    fn write(files: Vec<PublicFile>, check: &impl Fn() -> Result<(), ShadowError>) -> Result<Self, ShadowError> {
        check()?;
        let fd = unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        require(fd >= 0)?;
        let root = Directory::from(unsafe { File::from_raw_fd(fd) })?;
        let etc = Directory::open(&root, "etc")?;
        let catchplate = Directory::open(&etc, "catchplate")?;
        catchplate.absent("native-activation-inputs")?;
        catchplate.absent("native-shadow-guest-launch.json")?;
        catchplate.absent("native-shadow-public-exchange.json")?;
        check()?;
        require(unsafe { libc::mkdirat(catchplate.file.as_raw_fd(), c"native-activation-inputs".as_ptr(), 0o700) } == 0)?;
        check()?;
        let namespace = Directory::open(&catchplate, "native-activation-inputs")?;
        require(namespace.mode & 0o7777 == 0o700)?;
        namespace.file.sync_all().map_err(fail)?; check()?;
        catchplate.file.sync_all().map_err(fail)?; check()?;
        let mut owner = Self { directories: vec![root, etc, catchplate, namespace], files: Vec::new() };
        // Publish launch last. Any partial installation remains on disk and
        // refuses a later exclusive attempt; it is never silently adopted.
        for item in files.iter().filter(|v| v.path != LAUNCH).chain(files.iter().filter(|v| v.path == LAUNCH)) {
            check()?; owner.check()?;
            let parent = owner.directory(item.path);
            let name = item.path.rsplit('/').next().ok_or(ShadowError::BindingDrift)?;
            let c_name = CString::new(name).map_err(fail)?;
            let fd = unsafe { libc::openat(parent.file.as_raw_fd(), c_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
            require(fd >= 0)?; let file = unsafe { File::from_raw_fd(fd) }; check()?;
            let initial = file_identity(&file)?;
            require(initial.mode & libc::S_IFMT == libc::S_IFREG && initial.links == 1 && initial.length == 0)?;
            let mut offset = 0;
            while offset < item.bytes.len() {
                check()?;
                let end = item.bytes.len().min(offset + 65536);
                let n = file.write_at(&item.bytes[offset..end], offset as u64).map_err(fail)?;
                require(n > 0)?; offset += n; check()?;
            }
            require(unsafe { libc::fchown(fd, 0, 0) } == 0)?; check()?;
            require(unsafe { libc::fchmod(fd, 0o400) } == 0)?; check()?;
            file.sync_all().map_err(fail)?; check()?;
            let final_identity = file_identity(&file)?;
            require(final_identity.device == initial.device && final_identity.inode == initial.inode
                && final_identity.mode == libc::S_IFREG | 0o400 && final_identity.uid == 0 && final_identity.gid == 0
                && final_identity.links == 1 && final_identity.length == item.bytes.len() as u64)?;
            let mut readback = vec![0; item.bytes.len()]; file.read_exact_at(&mut readback, 0).map_err(fail)?;
            check()?; require(readback == item.bytes && file_identity(&file)? == final_identity)?;
            parent.child(name, final_identity.device, final_identity.inode)?;
            parent.file.sync_all().map_err(fail)?; check()?;
            let original = Original::open(std::path::Path::new(item.path), 0, 0, item.bytes.len(), item.sha256.clone()).map_err(fail)?;
            require(original.identity() == (final_identity.device, final_identity.inode)
                && original.read(item.bytes.len()).map_err(fail)?.as_slice() == item.bytes.as_slice())?;
            drop(file);
            owner.files.push(Held { original, path: item.path, identity: final_identity });
            check()?; owner.check()?;
        }
        Ok(owner)
    }
    pub(crate) fn check(&self) -> Result<(), ShadowError> {
        require(unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0)?;
        for directory in &self.directories { directory.check()?; }
        for (parent, child, name) in [(0, 1, "etc"), (1, 2, "catchplate"), (2, 3, "native-activation-inputs")] {
            self.directories[parent].child(name, self.directories[child].device, self.directories[child].inode)?;
        }
        for value in &self.files {
            value.original.check().map_err(fail)?;
            self.directory(value.path).child(value.path.rsplit('/').next().ok_or(ShadowError::BindingDrift)?,
                value.identity.device, value.identity.inode)?;
        }
        Ok(())
    }
}
