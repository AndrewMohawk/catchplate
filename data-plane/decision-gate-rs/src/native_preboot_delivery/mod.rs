//! One signed data closure before the fixed native startup profile.
//! Parent routing and the public challenge are not attestation. The image's
//! independently selected public key admits only this boot's data delivery;
//! all existing native startup, KMS, quote and authority checks still apply.
mod closure;
mod materialize;
#[path = "../native_verifier/json.rs"]
mod json;

use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey, pkcs8::{DecodePublicKey, EncodePublicKey}};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use catchplate_decision_gate::enclave_vsock_v1::{VsockListenerV1, VsockStreamV1};
use catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PORT: u32 = 9100;
const TRUST_PATH: &str = "/usr/share/catchplate/native-delivery-authority.pem";
const SIGNED: &str = "catchplate.signedNativeConfigurationDelivery/v1";
const PAYLOAD: &str = "catchplate.nativeConfigurationDelivery/v1";
const MAX_FRAME: usize = 64 * 1024 * 1024;
const MAX_FILE: usize = 16 * 1024 * 1024;
const MAX_TOTAL: usize = 32 * 1024 * 1024;
const MAX_INTERVAL: u64 = 86_400_000_000_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Profile { StaticV24, RotationV25 }
const ROTATION_PROFILE: &str = "static-credential-rotation-v25";
impl Profile {
    fn payload(self) -> &'static str {
        match self { Self::StaticV24 => PAYLOAD, Self::RotationV25 => "catchplate.nativeConfigurationDelivery/v2" }
    }
    fn signed(self) -> &'static str {
        match self { Self::StaticV24 => SIGNED, Self::RotationV25 => "catchplate.signedNativeConfigurationDelivery/v2" }
    }
    fn challenge(self) -> &'static str {
        match self { Self::StaticV24 => "catchplate.nativeConfigurationDeliveryChallenge/v1",
            Self::RotationV25 => "catchplate.nativeConfigurationDeliveryChallenge/v2" }
    }
    fn configuration(self) -> &'static str {
        match self { Self::StaticV24 => "catchplate.nativeStartupConfiguration/v24",
            Self::RotationV25 => "catchplate.nativeStartupConfiguration/v25" }
    }
}

fn ensure(condition: bool, message: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.to_owned()) }
}
fn digest(bytes: &[u8]) -> String { format!("sha256:{:x}", Sha256::digest(bytes)) }
fn pin(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:")
        && value[7..].bytes().all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn clocks() -> Result<(u64, u64), String> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } == 0
        && time.tv_sec >= 0 && (0..1_000_000_000).contains(&time.tv_nsec), "delivery BOOTTIME unavailable")?;
    let boot = (time.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(time.tv_nsec as u64)).ok_or("delivery BOOTTIME overflow")?;
    // Sample BOOTTIME first so converting an existing wall expiry cannot grant
    // the time spent sampling, parsing or validating back to the operation.
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "delivery wall clock unavailable")?.as_nanos();
    Ok((boot, wall.try_into().map_err(|_| "delivery wall clock overflow")?))
}
fn boot_id() -> Result<String, String> {
    let mut value = String::new();
    File::open("/proc/sys/kernel/random/boot_id").map_err(|_| "delivery boot identity unavailable")?
        .take(38).read_to_string(&mut value).map_err(|_| "delivery boot identity unreadable")?;
    ensure(value.len() == 37 && value.ends_with('\n')
        && value[..36].bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) { b == b'-' }
            else { b.is_ascii_digit() || (b'a'..=b'f').contains(&b) }
        }), "delivery boot identity is not canonical")?;
    value.pop(); Ok(value)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Challenge {
    api_version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    startup_profile: Option<&'static str>,
    challenge_base64_url: String,
    boot_id: String,
    receiver_started_boottime_ns: u64,
    delivery_key_spki_sha256: String,
}

struct Owner {
    pid: u32,
    profile: Profile,
    challenge: Challenge,
    previous_boot: u64,
    previous_wall: u64,
    interval: Option<(u64, u64, u64)>,
}
impl Owner {
    fn new(key_id: String, profile: Profile) -> Result<Self, String> {
        let (boot, wall) = clocks()?;
        let mut random = [0u8; 32];
        SystemRandom::new().fill(&mut random).map_err(|_| "delivery challenge entropy unavailable")?;
        ensure(random != [0; 32], "delivery challenge entropy invalid")?;
        Ok(Self { pid: std::process::id(), profile, previous_boot: boot, previous_wall: wall, interval: None,
            challenge: Challenge { api_version: profile.challenge(),
                startup_profile: (profile == Profile::RotationV25).then_some(ROTATION_PROFILE),
                challenge_base64_url: URL_SAFE_NO_PAD.encode(random), boot_id: boot_id()?,
                receiver_started_boottime_ns: boot, delivery_key_spki_sha256: key_id } })
    }
    fn check(&mut self) -> Result<(), String> {
        ensure(self.pid == std::process::id() && self.challenge.boot_id == boot_id()?,
            "delivery process or boot changed")?;
        let (boot, wall) = clocks()?;
        ensure(self.previous_boot <= boot && self.previous_wall <= wall, "delivery clock regressed")?;
        if let Some((issued, expires, deadline)) = self.interval {
            ensure(issued <= wall && wall < expires && boot < deadline, "delivery original authorization expired")?;
        }
        self.previous_boot = boot; self.previous_wall = wall; Ok(())
    }
    fn admit(&mut self, payload: &Payload) -> Result<(), String> {
        self.check()?;
        ensure(self.interval.is_none() && payload.api_version == self.profile.payload()
            && payload.challenge_base64_url == self.challenge.challenge_base64_url
            && payload.boot_id == self.challenge.boot_id
            && payload.receiver_started_boottime_ns == self.challenge.receiver_started_boottime_ns
            && payload.delivery_key_spki_sha256 == self.challenge.delivery_key_spki_sha256
            && payload.issued_at_epoch_ns > 0 && payload.issued_at_epoch_ns <= self.previous_wall
            && self.previous_wall < payload.expires_at_epoch_ns
            && payload.expires_at_epoch_ns - payload.issued_at_epoch_ns <= MAX_INTERVAL
            && self.previous_boot < payload.deadline_boottime_ns
            && payload.deadline_boottime_ns - self.previous_boot <= MAX_INTERVAL,
            "delivery signature scope or original interval differs")?;
        let converted = self.previous_boot.checked_add(payload.expires_at_epoch_ns - self.previous_wall)
            .ok_or("delivery expiry conversion overflow")?;
        self.interval = Some((payload.issued_at_epoch_ns, payload.expires_at_epoch_ns,
            converted.min(payload.deadline_boottime_ns)));
        self.check()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Artifact { label: String, sha256: String, content_base64_url: String }
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Payload {
    api_version: String, challenge_base64_url: String, boot_id: String,
    receiver_started_boottime_ns: u64, delivery_key_spki_sha256: String,
    issued_at_epoch_ns: u64, expires_at_epoch_ns: u64, deadline_boottime_ns: u64,
    configuration_sha256: String, launch_sha256: String, artifacts: Vec<Artifact>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Signed { api_version: String, payload: Payload, signature_base64_url: String }

// Disjoint closed v2 input: v1 never accepts even a null startupProfile.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RotationPayload {
    api_version: String, startup_profile: String, challenge_base64_url: String, boot_id: String,
    receiver_started_boottime_ns: u64, delivery_key_spki_sha256: String,
    issued_at_epoch_ns: u64, expires_at_epoch_ns: u64, deadline_boottime_ns: u64,
    configuration_sha256: String, launch_sha256: String, artifacts: Vec<Artifact>,
}
impl RotationPayload {
    fn into_parts(self) -> Result<Payload, String> {
        ensure(self.startup_profile == ROTATION_PROFILE, "delivery rotation purpose differs")?;
        Ok(Payload { api_version: self.api_version, challenge_base64_url: self.challenge_base64_url,
            boot_id: self.boot_id, receiver_started_boottime_ns: self.receiver_started_boottime_ns,
            delivery_key_spki_sha256: self.delivery_key_spki_sha256,
            issued_at_epoch_ns: self.issued_at_epoch_ns, expires_at_epoch_ns: self.expires_at_epoch_ns,
            deadline_boottime_ns: self.deadline_boottime_ns, configuration_sha256: self.configuration_sha256,
            launch_sha256: self.launch_sha256, artifacts: self.artifacts })
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedRotation { api_version: String, payload: RotationPayload, signature_base64_url: String }

fn signed_parts(original: serde_json::Value, profile: Profile) -> Result<(Payload, Vec<u8>, String), String> {
    match profile {
        Profile::StaticV24 => {
            let signed: Signed = serde_json::from_value(original)
                .map_err(|_| "delivery signed envelope is not closed")?;
            ensure(signed.api_version == profile.signed(), "delivery signed purpose differs")?;
            let raw = canonical_ascii_bytes(&signed.payload)?;
            Ok((signed.payload, raw, signed.signature_base64_url))
        }
        Profile::RotationV25 => {
            let signed: SignedRotation = serde_json::from_value(original)
                .map_err(|_| "rotation delivery signed envelope is not closed")?;
            ensure(signed.api_version == profile.signed(), "rotation delivery signed purpose differs")?;
            // Sign/verify the entire v2 original, including startupProfile,
            // before using its source-local common resource projection.
            let raw = canonical_ascii_bytes(&signed.payload)?;
            Ok((signed.payload.into_parts()?, raw, signed.signature_base64_url))
        }
    }
}

struct Trust { file: File, original: Vec<u8>, identity: (u64,u64,u32,u32,u32,u64,u64,i64,i64,i64,i64) }
impl Trust {
    fn identity(file: &File) -> Result<(u64,u64,u32,u32,u32,u64,u64,i64,i64,i64,i64), String> {
        let m = file.metadata().map_err(|_| "delivery trust metadata unavailable")?;
        ensure(m.is_file() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o444
            && m.nlink() == 1 && m.len() > 0 && m.len() <= 4096, "delivery trust file is not fixed protected public input")?;
        Ok((m.dev(),m.ino(),m.mode(),m.uid(),m.gid(),m.nlink(),m.len(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec()))
    }
    fn acquire() -> Result<(Self, VerifyingKey, String), String> {
        // The path and all ancestors are in the measured image, never selected
        // by incoming data. Every actual component uses its held directory,
        // including after the path's source spelling has been checked.
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
        let fd = unsafe { libc::open(c"/".as_ptr(), flags | libc::O_DIRECTORY) };
        ensure(fd >= 0, "delivery trust root unavailable")?;
        let mut file = unsafe { File::from_raw_fd(fd) };
        let parts: Vec<_> = TRUST_PATH.split('/').skip(1).collect();
        for (i, name) in parts.iter().enumerate() {
            let m = file.metadata().map_err(|_| "delivery trust ancestor unavailable")?;
            ensure(m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
                "delivery trust ancestor is not protected")?;
            let name = std::ffi::CString::new(*name).map_err(|_| "delivery fixed trust component invalid")?;
            let next = unsafe { libc::openat(file.as_raw_fd(), name.as_ptr(), flags
                | if i + 1 == parts.len() { 0 } else { libc::O_DIRECTORY }) };
            ensure(next >= 0, "delivery trust component unavailable")?;
            file = unsafe { File::from_raw_fd(next) };
        }
        let identity = Self::identity(&file)?;
        let mut original = Vec::new();
        (&file).take(4097).read_to_end(&mut original).map_err(|_| "delivery trust original unreadable")?;
        ensure(original.len() as u64 == identity.6 && Self::identity(&file)? == identity,
            "delivery trust original changed")?;
        let pem = std::str::from_utf8(&original).map_err(|_| "delivery trust PEM invalid")?;
        let key = VerifyingKey::from_public_key_pem(pem).map_err(|_| "delivery trust requires Ed25519 SPKI")?;
        let der = key.to_public_key_der().map_err(|_| "delivery trust SPKI invalid")?;
        let canonical = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", STANDARD.encode(der.as_bytes()));
        ensure(!key.is_weak() && canonical.as_bytes() == original, "delivery trust PEM is not canonical or is weak")?;
        let id = digest(der.as_bytes());
        Ok((Self { file, original, identity }, key, id))
    }
    fn check(&self) -> Result<(), String> {
        use std::os::unix::fs::FileExt;
        ensure(Self::identity(&self.file)? == self.identity, "delivery trust owner changed")?;
        let mut bytes = vec![0u8; self.original.len() + 1];
        let n = self.file.read_at(&mut bytes, 0).map_err(|_| "delivery trust recheck failed")?;
        ensure(n == self.original.len() && bytes[..n] == self.original, "delivery trust bytes changed")?;
        let (named, _, _) = Self::acquire()?;
        ensure(named.identity == self.identity && named.original == self.original, "delivery trust name changed")
    }
}

fn read_once(stream: &mut VsockStreamV1, owner: &mut Owner, bytes: &mut [u8]) -> Result<usize, String> {
    loop {
        owner.check()?;
        match stream.try_read(bytes) {
            Ok(n) => { owner.check()?; return Ok(n); }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return Err("delivery socket read failed".into()),
        }
    }
}
fn read_exact(stream: &mut VsockStreamV1, owner: &mut Owner, mut bytes: &mut [u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        let n = read_once(stream, owner, bytes)?;
        ensure(n > 0, "delivery frame was incomplete")?; bytes = &mut bytes[n..];
    }
    Ok(())
}
fn write_exact(stream: &mut VsockStreamV1, owner: &mut Owner, mut bytes: &[u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        owner.check()?;
        match stream.try_write(bytes) {
            Ok(n) => { ensure(n > 0, "delivery challenge write stopped")?; bytes = &bytes[n..]; }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return Err("delivery challenge write failed".into()),
        }
    }
    owner.check()
}

pub(super) struct Delivered {
    materialized: materialize::Materialized,
    owner: Owner,
    trust: Trust,
    configuration_pin: String,
    launch_pin: String,
}
impl Delivered {
    pub(super) fn arguments(&self) -> Vec<OsString> {
        ["--configuration", "/run/catchplate-preboot/configuration.json", "--configuration-sha256",
            &self.configuration_pin, "--launch", "/run/catchplate-preboot/launch.json", "--launch-sha256",
            &self.launch_pin, "--response-proof-identity-vsock"].into_iter().map(OsString::from).collect()
    }
    pub(super) fn recheck(&mut self) -> Result<(), String> {
        self.trust.check()?;
        self.materialized.recheck(&mut || self.owner.check())?;
        self.owner.check()
    }
}

pub(super) fn receive() -> Result<Delivered, String> {
    receive_for(Profile::StaticV24)
}

pub(super) fn receive_rotation() -> Result<Delivered, String> {
    receive_for(Profile::RotationV25)
}

fn receive_for(profile: Profile) -> Result<Delivered, String> {
    let (trust, key, key_id) = Trust::acquire()?;
    let mut owner = Owner::new(key_id, profile)?;
    // No authority or secret has been acquired. A first parent connection may
    // await independent operator approval; no arbitrary setup timeout creates
    // replacement attempts. The signed original later supplies the deadline.
    let listener = VsockListenerV1::bind(PORT, 3, u64::MAX).map_err(|_| "delivery listener bind failed")?;
    let accepted = listener.accept(u64::MAX);
    drop(listener);
    let mut stream = accepted.map_err(|_| "delivery parent connection failed")?;
    owner.check()?;
    let raw = (|| {
        stream.verify_accepted_local_port(PORT, u64::MAX).map_err(|_| "delivery listener scope changed")?;
        let hello = canonical_ascii_bytes(&owner.challenge)?;
        write_exact(&mut stream, &mut owner, &(hello.len() as u32).to_be_bytes())?;
        write_exact(&mut stream, &mut owner, &hello)?;
        let mut length = [0; 4]; read_exact(&mut stream, &mut owner, &mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        ensure(length > 0 && length <= MAX_FRAME, "delivery frame exceeds bound")?;
        let mut raw = vec![0; length]; read_exact(&mut stream, &mut owner, &mut raw)?;
        let mut trailing = [0];
        ensure(read_once(&mut stream, &mut owner, &mut trailing)? == 0, "delivery frame has trailing bytes")?;
        stream.verify_connected_original(u64::MAX).map_err(|_| "delivery socket original changed")?;
        Ok::<_, String>(raw)
    })();
    let closed = stream.shutdown(); drop(stream);
    let raw = raw?; closed.map_err(|_| "delivery socket close failed")?;
    owner.check()?; trust.check()?;
    let original = json::parse(&raw, MAX_FRAME)?;
    let (p, payload_original, signature_original) = signed_parts(original, profile)?;
    let signature = URL_SAFE_NO_PAD.decode(&signature_original).map_err(|_| "delivery signature encoding")?;
    ensure(signature.len() == 64 && URL_SAFE_NO_PAD.encode(&signature) == signature_original,
        "delivery signature is not canonical")?;
    let mut preimage = profile.payload().as_bytes().to_vec(); preimage.push(0);
    preimage.extend(payload_original);
    key.verify_strict(&preimage, &Signature::from_slice(&signature).map_err(|_| "delivery signature length")?)
        .map_err(|_| "delivery signature refused")?;
    owner.admit(&p)?;
    ensure(pin(&p.configuration_sha256) && pin(&p.launch_sha256)
        && (2..=128).contains(&p.artifacts.len()), "delivery artifact inventory invalid")?;
    let mut artifacts = BTreeMap::new(); let mut total = 0usize;
    for artifact in p.artifacts {
        owner.check()?;
        ensure(!artifact.label.is_empty() && artifact.label.len() <= 128
            && artifact.label.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
            && pin(&artifact.sha256) && artifact.content_base64_url.len() <= (MAX_FILE * 4 + 2) / 3,
            "delivery artifact label or bound invalid")?;
        let bytes = URL_SAFE_NO_PAD.decode(&artifact.content_base64_url).map_err(|_| "delivery artifact encoding invalid")?;
        total = total.checked_add(bytes.len()).ok_or("delivery aggregate overflow")?;
        ensure(!bytes.is_empty() && bytes.len() <= MAX_FILE && total <= MAX_TOTAL
            && URL_SAFE_NO_PAD.encode(&bytes) == artifact.content_base64_url && digest(&bytes) == artifact.sha256
            && !artifacts.contains_key(&artifact.label), "delivery artifact pin or inventory differs")?;
        artifacts.insert(artifact.label, bytes);
    }
    let configuration = artifacts.remove("configuration").ok_or("delivery configuration missing")?;
    let launch = artifacts.remove("launch").ok_or("delivery launch missing")?;
    ensure(digest(&configuration) == p.configuration_sha256 && digest(&launch) == p.launch_sha256,
        "delivery full original pins differ")?;
    let launch_value = json::parse(&launch, 16 * 1024)?;
    let launch_deadline = launch_value.get("deadlineBoottimeNs").and_then(|v| v.as_u64())
        .ok_or("delivery launch original deadline absent")?;
    ensure(launch_deadline > owner.previous_boot && launch_deadline <= owner.interval.ok_or("delivery interval absent")?.2,
        "native launch would extend the signed delivery lifetime")?;
    let plan = closure::validate(&configuration, &launch, &artifacts, profile)?;
    trust.check()?; owner.check()?;
    let materialized = materialize::materialize(plan, &mut || owner.check())?;
    let mut delivered = Delivered { materialized, owner, trust,
        configuration_pin: p.configuration_sha256, launch_pin: p.launch_sha256 };
    delivered.recheck()?;
    Ok(delivered)
}
