//! Fixed original-only bootstrap acquisition, not enrollment or installation.

mod config;
mod http;
mod transport;
mod install;
// Internal egress ownership only. No configuration/CLI profile invokes it
// before cold cross-invocation admission and separate workload lifecycle scope.
#[allow(dead_code)]
mod egress;
#[path = "../native_ingress_client/identity.rs"]
mod identity;
#[path = "../native_startup_config/originals.rs"]
mod originals;
#[path = "../native_verifier/json.rs"]
mod json;
#[path = "../native_verifier/mod.rs"]
mod native_verifier;
#[path = "../native_enrollment_bootstrap_exchange_v1.rs"]
mod exchange;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use config::{Configuration, MAX_CONFIGURATION_BYTES};
use originals::{ArtifactV1, HeldOriginal};
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_CAPTURE_BYTES: usize = 1536 * 1024;
const SECOND: u64 = 1_000_000_000;

fn ensure(condition: bool, message: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.to_owned()) }
}

fn sample() -> Result<(u64, u64), String> {
    let wall = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "bootstrap client wall clock is invalid")?.as_nanos())
        .map_err(|_| "bootstrap client wall clock overflow")?;
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } == 0
        && value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec),
        "bootstrap client boottime clock is invalid")?;
    let boot = (value.tv_sec as u64).checked_mul(SECOND)
        .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64))
        .ok_or("bootstrap client boottime overflow")?;
    ensure(wall > 0 && boot > 0, "bootstrap client clocks must be positive")?;
    Ok((wall, boot))
}

struct ClockState {
    instant_deadline: Instant,
    boot_deadline: u64,
    last_wall: u64,
    last_boot: u64,
    until: u64,
    stopped: bool,
}

/// Only this invocation creates the owner, before argument/configuration reads.
/// Transport and receiver retain this same clock, not a callback or new budget.
pub(super) struct OriginalClock {
    pid: u32,
    started: Instant,
    opening_boot: u64,
    state: Mutex<ClockState>,
}

impl OriginalClock {
    fn start() -> Result<Arc<Self>, String> {
        let started = Instant::now();
        let (wall, boot) = sample()?;
        let clock = Arc::new(Self {
            pid: std::process::id(), started, opening_boot: boot,
            state: Mutex::new(ClockState {
                instant_deadline: started.checked_add(Duration::from_secs(30))
                    .ok_or("bootstrap client original deadline overflow")?,
                boot_deadline: boot.checked_add(30 * SECOND)
                    .ok_or("bootstrap client original boottime deadline overflow")?,
                last_wall: wall, last_boot: boot, until: u64::MAX, stopped: false,
            }),
        });
        clock.check()?;
        Ok(clock)
    }

    fn current(&self, state: &mut ClockState) -> Result<(), String> {
        ensure(!std::mem::replace(&mut state.stopped, true), "bootstrap client clock is stopped")?;
        let (wall, boot) = sample()?;
        ensure(std::process::id() == self.pid && wall >= state.last_wall && boot >= state.last_boot
            && Instant::now() < state.instant_deadline && boot < state.boot_deadline && wall < state.until,
            "bootstrap client original process, clock or interval ended")?;
        if state.until != u64::MAX {
            state.boot_deadline = state.boot_deadline.min(boot.checked_add(state.until - wall)
                .ok_or("bootstrap client retained interval overflow")?);
        }
        state.last_wall = wall;
        state.last_boot = boot;
        state.stopped = false;
        Ok(())
    }

    fn limit(&self, timeout: Duration) -> Result<(), String> {
        let mut state = self.state.lock().map_err(|_| "bootstrap client clock lock failed")?;
        self.current(&mut state)?;
        let nanos = u64::try_from(timeout.as_nanos()).map_err(|_| "bootstrap client timeout overflow")?;
        ensure((100_000_000..=30 * SECOND).contains(&nanos), "bootstrap client timeout exceeds bound")?;
        state.instant_deadline = state.instant_deadline.min(self.started.checked_add(timeout)
            .ok_or("bootstrap client deadline overflow")?);
        state.boot_deadline = state.boot_deadline.min(self.opening_boot.checked_add(nanos)
            .ok_or("bootstrap client boottime deadline overflow")?);
        self.current(&mut state)
    }

    pub(super) fn check(&self) -> Result<(), String> {
        let mut state = self.state.lock().map_err(|_| "bootstrap client clock lock failed")?;
        self.current(&mut state)
    }

    pub(super) fn instant_deadline(&self) -> Result<Instant, String> {
        let mut state = self.state.lock().map_err(|_| "bootstrap client clock lock failed")?;
        self.current(&mut state)?;
        Ok(state.instant_deadline)
    }

    pub(super) fn boottime_deadline(&self) -> Result<u64, String> {
        let mut state = self.state.lock().map_err(|_| "bootstrap client clock lock failed")?;
        self.current(&mut state)?;
        Ok(state.boot_deadline)
    }

    pub(super) fn restrict_until_epoch_ns(&self, until: u64) -> Result<(), String> {
        let mut state = self.state.lock().map_err(|_| "bootstrap client clock lock failed")?;
        self.current(&mut state)?;
        state.until = state.until.min(until);
        self.current(&mut state)
    }
}

fn arguments() -> Result<ArtifactV1, String> {
    let mut arguments = std::env::args_os().skip(1);
    let mut path = None;
    let mut pin = None;
    for _ in 0..2 {
        let flag = arguments.next().ok_or("bootstrap client requires pinned configuration flags")?;
        let value = arguments.next().ok_or("bootstrap client flag requires a value")?;
        match flag.to_str() {
            Some("--configuration") if path.is_none() => {
                ensure(value.len() <= 4096, "bootstrap client configuration path exceeds bound")?;
                let candidate = PathBuf::from(value);
                ensure(candidate.is_absolute(), "bootstrap client configuration path must be absolute")?;
                path = Some(candidate);
            }
            Some("--configuration-sha256") if pin.is_none() => {
                let candidate = value.into_string().map_err(|_| "bootstrap client pin is not UTF-8")?;
                ensure(super::is_sha256_digest(&candidate), "bootstrap client configuration pin is invalid")?;
                pin = Some(candidate);
            }
            _ => return Err("bootstrap client flag is unknown or repeated".to_owned()),
        }
    }
    ensure(arguments.next().is_none(), "bootstrap client has extra arguments")?;
    Ok(ArtifactV1 { path: path.ok_or("bootstrap client configuration path is absent")?,
        sha256: pin.ok_or("bootstrap client configuration pin is absent")? })
}

fn read(artifact: ArtifactV1, maximum: usize, clock: &OriginalClock,
    held: &mut Vec<HeldOriginal>) -> Result<Vec<u8>, String> {
    clock.check()?;
    let (original, raw) = HeldOriginal::read(artifact, maximum)?;
    clock.check()?;
    held.push(original);
    Ok(raw)
}

fn recheck(held: &mut [HeldOriginal], private: &mut HeldOriginal,
    clock: &OriginalClock) -> Result<(), String> {
    for original in held {
        clock.check()?;
        original.recheck()?;
        clock.check()?;
    }
    private.require_private()?;
    clock.check()?;
    private.recheck()?;
    private.require_private()?;
    clock.check()
}

pub(super) fn run() -> Result<(), String> {
    let clock = OriginalClock::start()?;
    let mut held = Vec::new();
    let configuration_raw = read(arguments()?, MAX_CONFIGURATION_BYTES, &clock, &mut held)?;
    let config = Configuration::parse_original(&configuration_raw)?;
    clock.limit(config.timeout)?;
    let startup = read(config.startup_evidence, 64 * 1024, &clock, &mut held)?;
    let startup_expectations = read(config.startup_expectations, 16 * 1024, &clock, &mut held)?;
    let scope = read(config.session_scope, 16 * 1024, &clock, &mut held)?;
    let roots = read(config.trust_roots, 1024 * 1024, &clock, &mut held)?;
    let delegation_pin = config.delegation_authorizer.sha256.clone();
    let setup_pin = config.setup_authorizer.sha256.clone();
    let delegation_root = read(config.delegation_authorizer, 16 * 1024, &clock, &mut held)?;
    let setup_root = read(config.setup_authorizer, 16 * 1024, &clock, &mut held)?;
    let caller_issuer = read(config.caller_issuer, 64 * 1024, &clock, &mut held)?;
    let request_raw = read(config.request, exchange::MAX_REQUEST_BYTES, &clock, &mut held)?;
    let sent = exchange::decode_original(&request_raw)?;
    clock.check()?;
    ensure(super::sha256_prefixed(sent.target_request_original()) == config.expected_target_request_sha256,
        "bootstrap client sent target request differs from its independent pin")?;

    // The private prepared owner replays original startup evidence, independent
    // scope and Nitro roots. No result dictionary or arbitrary TLS config enters.
    let prepared = transport::prepare(&startup, &startup_expectations, &scope, &roots,
        config.challenge, Arc::clone(&clock))?;
    let installation = match config.installation {
        Some(inputs) => Some(install::prepare(inputs, &clock, &mut held)?),
        None => None,
    };
    let authority = if prepared.host().contains(':') {
        format!("[{}]:{}", prepared.host(), config.endpoint.port())
    } else { format!("{}:{}", prepared.host(), config.endpoint.port()) };
    clock.check()?;
    let caller_issuer_der = identity::workload_issuer_original(&caller_issuer)?;
    let certificate = read(config.client_certificate, 64 * 1024, &clock, &mut held)?;
    clock.check()?;
    // No private key is read before genuine startup verification above.
    let (mut private_original, private_pem) = HeldOriginal::read_private(config.client_private_key, 16 * 1024)?;
    clock.check()?;
    recheck(&mut held, &mut private_original, &clock)?;
    let mut connection = prepared.connect(config.endpoint, &certificate, &private_pem)?;
    drop(private_pem);
    connection.check()?;
    let evidence = http::post(&mut connection, &authority, config.challenge, &request_raw)?;
    connection.check()?;
    if let Some(pending) = installation {
        let proof = connection.admit_installation(&evidence, &delegation_root, &delegation_pin,
            &setup_root, &setup_pin, &caller_issuer_der, &config.expected_caller_principal,
            &config.expected_target_principal, &config.expected_target_nonce,
            &config.expected_target_request_sha256, sent.delegation_original(),
            sent.setup_original(), sent.target_request_original())?;
        // This is output data only. The installation continuation retains the
        // genuine proof and original connection; the diagnostic grants nothing.
        let capture = json!({
            "apiVersion":"serverware.nativeBootstrapClientCapture/v2",
            "resultScope":"local-fixed-endpoint-bootstrap-and-host-installation",
            "okForAction":false,
            "configurationSha256":super::sha256_prefixed(&configuration_raw),
            "requestSha256":super::sha256_prefixed(&request_raw),
            "endpoint":config.endpoint.to_string(),
            "challengeSource":"independently-pinned",
            "evidenceBase64url":URL_SAFE_NO_PAD.encode(&evidence),
            "verification":json::parse(proof.diagnostic(), 4095)?,
            "installation":null,
        });
        recheck(&mut held, &mut private_original, &clock)?;
        return install::execute(pending, proof, connection, clock, held, private_original,
            &configuration_raw, capture);
    }
    let verified = connection.verify_bootstrap(&evidence, &delegation_root, &delegation_pin,
        &setup_root, &setup_pin, &caller_issuer_der, &config.expected_caller_principal,
        &config.expected_target_principal, &config.expected_target_nonce,
        &config.expected_target_request_sha256, sent.delegation_original(),
        sent.setup_original(), sent.target_request_original())?;
    connection.check()?;
    let result = json!({
        "apiVersion":"serverware.nativeBootstrapClientCapture/v1",
        "resultScope":"local-fixed-endpoint-bootstrap-originals-only",
        "okForAction":false,
        "configurationSha256":super::sha256_prefixed(&configuration_raw),
        "requestSha256":super::sha256_prefixed(&request_raw),
        "endpoint":config.endpoint.to_string(),
        "challengeSource":"independently-pinned",
        "evidenceBase64url":URL_SAFE_NO_PAD.encode(&evidence),
        "verification":json::parse(&verified, 4095)?,
    });
    let mut encoded = serde_json::to_vec(&result).map_err(|_| "encode bootstrap client capture")?;
    ensure(!encoded.is_empty() && encoded.len() < MAX_CAPTURE_BYTES
        && !encoded.contains(&b'\n') && !encoded.contains(&b'\r'),
        "bootstrap client capture exceeds its single-line bound")?;
    encoded.push(b'\n');
    recheck(&mut held, &mut private_original, &clock)?;
    connection.check()?;
    // Public originals only. Blocking file/stdout calls need an outer watchdog.
    // A partial line or nonzero exit is never a receipt or safe retry signal.
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    for chunk in encoded.chunks(16 * 1024) {
        connection.check()?;
        output.write_all(chunk).map_err(|_| "write bootstrap client capture")?;
        connection.check()?;
    }
    output.flush().map_err(|_| "flush bootstrap client capture")?;
    connection.check()?;
    recheck(&mut held, &mut private_original, &clock)?;
    connection.check()
}
