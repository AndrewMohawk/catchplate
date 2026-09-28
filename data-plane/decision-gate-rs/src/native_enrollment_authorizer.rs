//! Dedicated cold public authorizer, not packet semantics or signing authority.
//!
//! Its exact originals and public proxy endpoint come from the independently
//! pinned native startup configuration. This owner neither discovers a root nor
//! borrows role-4 authority. Assignments arrive later: embedding their hashes in
//! the self-hashed static configuration would create a commitment cycle.

use serverware_decision_gate::{canonical_json_bytes, decode_canonical_json};
#[path = "native_enrollment_assignment_v1.rs"]
mod assignment;
pub(super) use assignment::VerifiedNativeEnrollmentAssignmentV1;

use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const SPKI_PREFIX: &[u8] = &[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
    0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

struct ClockState { wall_ns: u64, boot_ns: u64, failed: bool }

/// No Clone, Debug, deserializer, private key or root-selection callback. Only
/// startup can construct it; only the genuinely checked prepared state serves
/// it. Every assignment repeats the current actual policy signing-key join.
pub(super) struct NativeEnrollmentAuthorizer {
    public_key_pem: Box<[u8]>,
    public_key_pem_sha256: String,
    key_id: [u8; 32],
    response_key_id: [u8; 32],
    policy_key_id: [u8; 32],
    proxy_endpoint: SocketAddr,
    listener_port: u32,
    deadline: u64,
    owner_pid: libc::pid_t,
    clock: Mutex<ClockState>,
}

fn digest_field(value: &str) -> Result<[u8; 32], String> {
    let raw = value.strip_prefix("sha256:").ok_or("native authorizer digest prefix differs")?;
    if raw.len() != 64 || !raw.bytes().all(|byte|
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err("native authorizer digest is not canonical".to_owned());
    }
    let mut result = [0u8; 32];
    hex::decode_to_slice(raw, &mut result).map_err(|_| "native authorizer digest is invalid")?;
    if result == [0; 32] { return Err("native authorizer digest must be nonzero".to_owned()); }
    Ok(result)
}

fn key_id(key: &VerifyingKey) -> Result<[u8; 32], String> {
    if key.is_weak() { return Err("native authorizer exclusion key is weak".to_owned()); }
    let mut hash = Sha256::new();
    hash.update(SPKI_PREFIX);
    hash.update(key.as_bytes());
    Ok(hash.finalize().into())
}

fn clocks() -> Result<(u64, u64), String> {
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "native authorizer wall clock is invalid")?.as_nanos();
    let wall = u64::try_from(wall).map_err(|_| "native authorizer wall clock overflow")?;
    let mut observed: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut observed) } != 0
        || observed.tv_sec < 0 || !(0..1_000_000_000).contains(&observed.tv_nsec) {
        return Err("native authorizer boottime is invalid".to_owned());
    }
    let boot = u64::try_from(observed.tv_sec as u128 * 1_000_000_000 + observed.tv_nsec as u128)
        .map_err(|_| "native authorizer boottime overflow")?;
    if wall == 0 || boot == 0 { return Err("native authorizer clock must be positive".to_owned()); }
    Ok((wall, boot))
}

impl NativeEnrollmentAuthorizer {
    pub(super) fn from_original(public_key_pem: &[u8], public_key_pem_sha256: &str,
        proxy_endpoint: &str, listener_port: u32, control_plane_response_key: &VerifyingKey,
        expected_policy_key_id: &str, deadline: u64) -> Result<Self, String> {
        let owner_pid = unsafe { libc::getpid() };
        let (wall_ns, boot_ns) = clocks()?;
        if owner_pid <= 0 || boot_ns >= deadline || listener_port <= 1023 || listener_port == u32::MAX {
            return Err("native authorizer original startup deadline or listener port is invalid".to_owned());
        }
        // Same source as the request assignment verifier: exact canonical
        // Ed25519 SPKI PEM, independent exact-PEM pin and nonweak actual key.
        let key_id = assignment::validate_authorizer_original(public_key_pem, public_key_pem_sha256)?;
        let response_key_id = self::key_id(control_plane_response_key)?;
        let policy_key_id = digest_field(expected_policy_key_id)?;
        if key_id == response_key_id || key_id == policy_key_id {
            return Err("native enrollment authorizer must have a separate key role".to_owned());
        }
        let proxy_endpoint = assignment::validate_proxy_endpoint_original(proxy_endpoint)?;
        let result = Self { public_key_pem: public_key_pem.into(),
            public_key_pem_sha256: public_key_pem_sha256.to_owned(), key_id, response_key_id, policy_key_id,
            proxy_endpoint, listener_port, deadline, owner_pid,
            clock: Mutex::new(ClockState { wall_ns, boot_ns, failed: false }) };
        result.check()?;
        Ok(result)
    }

    pub(super) fn deadline(&self) -> u64 { self.deadline }
    pub(super) fn proxy_endpoint(&self) -> SocketAddr { self.proxy_endpoint }
    pub(super) fn listener_port(&self) -> u32 { self.listener_port }

    /// This is the original service lifetime, not a fresh per-request allowance.
    /// A short assignment request must not shorten the shared owner globally.
    pub(super) fn check(&self) -> Result<u64, String> {
        let mut clock = self.clock.lock().map_err(|_| "native authorizer clock owner is poisoned")?;
        if std::mem::replace(&mut clock.failed, true) || unsafe { libc::getpid() } != self.owner_pid {
            return Err("native authorizer owner is failed or changed process".to_owned());
        }
        let (wall, boot) = clocks()?;
        if wall < clock.wall_ns || boot < clock.boot_ns || boot >= self.deadline {
            return Err("native authorizer expired or a clock moved backwards".to_owned());
        }
        clock.wall_ns = wall;
        clock.boot_ns = boot;
        clock.failed = false;
        Ok(wall / 1_000_000_000)
    }

    pub(super) fn require_policy_key(&self, actual_policy_key: &VerifyingKey) -> Result<(), String> {
        self.check()?;
        let actual = key_id(actual_policy_key)?;
        if actual != self.policy_key_id || actual == self.key_id {
            return Err("native enrollment actual policy key differs or shares its role".to_owned());
        }
        self.check()?;
        Ok(())
    }

    pub(super) fn require_response_key(&self, actual_response_key: &VerifyingKey) -> Result<(), String> {
        self.check()?;
        let actual = key_id(actual_response_key)?;
        if actual != self.response_key_id || actual == self.key_id {
            return Err("native enrollment actual response key differs or shares its role".to_owned());
        }
        self.check()?;
        Ok(())
    }

    pub(super) fn verify_assignment(&self, assignment_original: &[u8], packet_original: &[u8],
        actual_policy_key: &VerifyingKey, deadline: u64)
        -> Result<VerifiedNativeEnrollmentAssignmentV1, String> {
        self.require_policy_key(actual_policy_key)?;
        let deadline = deadline.min(self.deadline);
        let mut verified = assignment::verify_original(assignment_original, &self.public_key_pem,
            &self.public_key_pem_sha256, packet_original, deadline)?;
        if verified.payload().proxy_endpoint != self.proxy_endpoint {
            return Err("native enrollment assignment differs from the cold proxy endpoint".to_owned());
        }
        self.require_policy_key(actual_policy_key)?;
        verified.check(deadline)?;
        Ok(verified)
    }
}
