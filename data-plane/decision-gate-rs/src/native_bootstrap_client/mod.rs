//! Fixed bootstrap acquisition and explicitly selected local continuations.

mod config;
mod http;
mod transport;
mod install;
// V3 retains a never-executed child through firewall observation; V4 adds
// separately authorized network attachment. Neither profile starts a workload.
#[allow(dead_code)]
mod egress;
// V5/v6 explicitly select actual executable parents, claimed containment,
// same-child networking, guardian, consuming exec release and terminal cleanup.
#[allow(dead_code)]
mod execution;
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

fn arguments() -> Result<(ArtifactV1, bool), String> {
    let mut arguments = std::env::args_os().skip(1).peekable();
    let lookup = arguments.peek().is_some_and(|flag| flag.to_str() == Some("--inspect-native-outcome"));
    if lookup { arguments.next(); }
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
    Ok((ArtifactV1 { path: path.ok_or("bootstrap client configuration path is absent")?,
        sha256: pin.ok_or("bootstrap client configuration pin is absent")? }, lookup))
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
    let (artifact, lookup) = arguments()?;
    if lookup { return execution::lookup(artifact, &clock); }
    let mut held = Vec::new();
    let configuration_raw = read(artifact, MAX_CONFIGURATION_BYTES, &clock, &mut held)?;
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
    let setup_installation_observation = match config.setup_installation_observation {
        Some(inputs) => Some(install::Observation::open(inputs, Arc::clone(&clock),
            held.first().ok_or("host observation configuration is absent")?)?),
        None => None,
    };
    let mut attachment = match config.attachment {
        Some(inputs) => Some(egress::attachment::prepare(inputs, &clock, &mut held)?),
        None => None,
    };
    // Explicit v5/v6 selects execution before any network contact. V1-v4 cannot
    // obtain it by presenting newer signed bytes or a successful diagnostic.
    let retirement = config.retirement;
    let outcome = config.outcome;
    let application = config.application_proxy;
    let (execution, egress) = if let Some(inputs) = config.execution {
        let start = if application.is_some() {
            execution::PreparedStart::open_application(inputs, Arc::clone(&clock))?
        } else if outcome {
            execution::PreparedStart::open_outcome(inputs, Arc::clone(&clock), installation.is_some())?
        } else if retirement {
            execution::PreparedStart::open_retiring(inputs, Arc::clone(&clock), installation.is_some())?
        } else if installation.is_some() {
            execution::PreparedStart::open_with_trust(inputs, Arc::clone(&clock))?
        } else { execution::PreparedStart::open(inputs, Arc::clone(&clock))? };
        let network = attachment.take().ok_or("native execution requires its actual attachment original")?;
        let egress = config.egress.ok_or("native execution requires its actual egress original")?;
        let parents = if application.is_some() {egress::prepare_for_application(egress,network,&clock,&mut held)?}
            else {egress::prepare_for_start(egress, network, &clock, &mut held)?};
        (Some((start, parents)), None)
    } else { (None, match config.egress {
        Some(inputs) => Some(match attachment.as_ref() {
            Some(network) => egress::prepare_for_attachment(inputs, network, &clock, &mut held)?,
            None => egress::prepare(inputs, &clock, &mut held)?,
        }),
        None => None,
    }) };
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
    if let Some((mut start, pending)) = execution {
        let combined = installation.is_some();
        let proof = connection.admit_installation(&evidence, &delegation_root, &delegation_pin,
            &setup_root, &setup_pin, &caller_issuer_der, &config.expected_caller_principal,
            &config.expected_target_principal, &config.expected_target_nonce,
            &config.expected_target_request_sha256, sent.delegation_original(),
            sent.setup_original(), sent.target_request_original())?;
        let mut capture = json!({
            "apiVersion":if application.is_some() { "catchplate.nativeBootstrapClientCapture/v9" }
                else if outcome { "catchplate.nativeBootstrapClientCapture/v8" }
                else if retirement { "catchplate.nativeBootstrapClientCapture/v7" }
                else if combined { "catchplate.nativeBootstrapClientCapture/v6" }
                else { "catchplate.nativeBootstrapClientCapture/v5" },
            "resultScope":if application.is_some() { "local-fixed-endpoint-bootstrap-application-proxy-observation" }
                else if outcome { "local-fixed-endpoint-bootstrap-execution-outcome-observation" }
                else if retirement { "local-fixed-endpoint-bootstrap-execution-retirement-observation" }
                else if combined { "local-fixed-endpoint-bootstrap-ca-and-execution-observation" }
                else { "local-fixed-endpoint-bootstrap-and-execution-observation" },
            "okForAction":false,
            "configurationSha256":super::sha256_prefixed(&configuration_raw),
            "requestSha256":super::sha256_prefixed(&request_raw),
            "endpoint":config.endpoint.to_string(),
            "challengeSource":"independently-pinned",
            "evidenceBase64url":URL_SAFE_NO_PAD.encode(&evidence),
            "verification":json::parse(proof.diagnostic(), 4095)?,
            "execution":null,
        });
        if combined || retirement { capture["installation"] = serde_json::Value::Null; }
        if outcome { capture["outcome"] = serde_json::Value::Null; }
        let provisional = serde_json::to_vec(&capture).map_err(|_| "encode execution capture reservation")?;
        let reserved = if outcome { 36 * 1024 } else if retirement { 32 * 1024 }
            else if combined { 24 * 1024 } else { 16 * 1024 };
        ensure(!provisional.is_empty() && provisional.len() < MAX_CAPTURE_BYTES - reserved,
            "native execution capture cannot reserve its bounded terminal observation")?;
        recheck(&mut held, &mut private_original, &clock)?;
        let parents = egress::bind_for_start(pending, proof, connection, clock, held,
            private_original, &configuration_raw)?;
        if let Some(pending) = installation {
            let pending = install::bind_for_execution(pending, Arc::clone(&parents), &configuration_raw)?;
            capture["installation"] = start.install_ca(pending)?;
        }
        let observation = execution::execute(start, parents,application).map_err(|error| if combined {
            format!("native CA installation completed; execution failed without rollback or retry: {error}")
        } else { error })?;
        let succeeded = observation.workload_succeeded();
        // Retiring observations retain actual host originals, shared flock,
        // removed leaf FD and original claims until bounded output finishes.
        let observed = serde_json::to_value(&observation).map_err(|_| "encode native execution observation")?;
        ensure(serde_json::to_vec(&observed).map_err(|_| "measure native execution observation")?.len()
            <= if retirement { 24 * 1024 } else { 16 * 1024 },
            "native execution observation exceeds its reserved bound")?;
        capture["execution"] = observed;
        if outcome {
            let receipt = observation.outcome_receipt().ok_or("native durable outcome receipt absent")?;
            let receipt = serde_json::to_value(receipt).map_err(|_| "encode native outcome receipt")?;
            ensure(serde_json::to_vec(&receipt).map_err(|_| "measure native outcome receipt")?.len() <= 4096,
                "native outcome receipt exceeds its reserved bound")?;
            capture["outcome"] = receipt;
        }
        let mut encoded = serde_json::to_vec(&capture).map_err(|_| "encode native execution capture")?;
        ensure(!encoded.is_empty() && encoded.len() < MAX_CAPTURE_BYTES
            && !encoded.contains(&b'\n') && !encoded.contains(&b'\r'),
            "native execution capture exceeds its single-line bound")?;
        encoded.push(b'\n');
        // All workload/guardian reaps and empty-leaf observations precede
        // this data-only output. Do not renew the expired admission clock to
        // print a receipt, nor keep a running child behind a blocked writer.
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        output.write_all(&encoded).map_err(|_| "write completed native execution capture")?;
        output.flush().map_err(|_| "flush completed native execution capture")?;
        ensure(succeeded, "native workload exited unsuccessfully; exact terminal capture was written")?;
        return Ok(());
    }
    if let Some(pending) = egress {
        let proof = connection.admit_installation(&evidence, &delegation_root, &delegation_pin,
            &setup_root, &setup_pin, &caller_issuer_der, &config.expected_caller_principal,
            &config.expected_target_principal, &config.expected_target_nonce,
            &config.expected_target_request_sha256, sent.delegation_original(),
            sent.setup_original(), sent.target_request_original())?;
        // Reserve output capacity before the separate durable creation claim.
        // Neither this diagnostic nor the later observation authorizes effects.
        let mut capture = json!({
            "apiVersion":"catchplate.nativeBootstrapClientCapture/v3",
            "resultScope":"local-fixed-endpoint-bootstrap-and-egress-observation",
            "okForAction":false,
            "configurationSha256":super::sha256_prefixed(&configuration_raw),
            "requestSha256":super::sha256_prefixed(&request_raw),
            "endpoint":config.endpoint.to_string(),
            "challengeSource":"independently-pinned",
            "evidenceBase64url":URL_SAFE_NO_PAD.encode(&evidence),
            "verification":json::parse(proof.diagnostic(), 4095)?,
            "egress":null,
        });
        let observation_capacity = if attachment.is_some() {
            capture["apiVersion"] = json!("catchplate.nativeBootstrapClientCapture/v4");
            capture["resultScope"] = json!("local-fixed-endpoint-bootstrap-and-network-attachment-observation");
            capture["attachment"] = json!(null);
            16 * 1024
        } else { 8192 };
        let provisional = serde_json::to_vec(&capture).map_err(|_| "encode egress capture reservation")?;
        ensure(!provisional.is_empty() && provisional.len() < MAX_CAPTURE_BYTES - observation_capacity,
            "egress capture cannot reserve its bounded observation")?;
        recheck(&mut held, &mut private_original, &clock)?;
        let guard = egress::bind(pending, proof, connection, clock, held, private_original,
            &configuration_raw)?;
        let mut installed = guard.install()?;
        let mut observation = serde_json::to_value(guard.observation()?)
            .map_err(|_| "encode native egress creation observation")?;
        let fields = observation.as_object_mut().ok_or("native egress observation shape differs")?;
        ensure(fields.len() == 4, "native egress creation observation field count differs")?;
        fields.insert("apiVersion".to_owned(), json!("catchplate.nativeEgressObservation/v1"));
        fields.insert("resultScope".to_owned(), json!("local-authorized-egress-observed-before-owner-teardown"));
        fields.insert("okForAction".to_owned(), json!(false));
        fields.insert("status".to_owned(), json!(if installed.created() {
            "observed-created"
        } else { "observed-complete" }));
        for (name, digest) in [("kernelSemanticSha256", installed.semantic_sha256()),
            ("kernelEvidenceSha256", installed.evidence_sha256())]
        {
            let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            fields.insert(name.to_owned(), json!(format!("sha256:{hex}")));
        }
        let observation_raw = serde_json::to_vec(&observation)
            .map_err(|_| "encode native egress observation")?;
        ensure(!observation_raw.is_empty() && observation_raw.len() <= 8191,
            "native egress observation exceeds its bound")?;
        capture["egress"] = observation;
        if let Some(pending) = attachment {
            return egress::attachment::execute(pending, &guard, installed, capture);
        }
        let mut encoded = serde_json::to_vec(&capture).map_err(|_| "encode native egress capture")?;
        ensure(!encoded.is_empty() && encoded.len() < MAX_CAPTURE_BYTES
            && !encoded.contains(&b'\n') && !encoded.contains(&b'\r'),
            "native egress capture exceeds its single-line bound")?;
        encoded.push(b'\n');
        installed.check()?;
        guard.check()?;
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        for chunk in encoded.chunks(16 * 1024) {
            guard.check()?;
            output.write_all(chunk).map_err(|_| "write native egress capture")?;
            guard.check()?;
        }
        output.flush().map_err(|_| "flush native egress capture")?;
        guard.check()?;
        // The exact semantic snapshot above is an observation, not a promise
        // that kernel state cannot change during output. Do not mint a query
        // allowance or repeatedly dump through the same bounded transcript.
        // Both owners remain alive through flush/final checks. Dropping them
        // tears down this never-executed child; the capture grants no lifecycle.
        return Ok(());
    }
    if let Some(pending) = installation {
        let proof = connection.admit_installation(&evidence, &delegation_root, &delegation_pin,
            &setup_root, &setup_pin, &caller_issuer_der, &config.expected_caller_principal,
            &config.expected_target_principal, &config.expected_target_nonce,
            &config.expected_target_request_sha256, sent.delegation_original(),
            sent.setup_original(), sent.target_request_original())?;
        // This is output data only. The installation continuation retains the
        // genuine proof and original connection; the diagnostic grants nothing.
        let mut capture = json!({
            "apiVersion":if setup_installation_observation.is_some() { "catchplate.nativeBootstrapClientCapture/v10" }
                else { "catchplate.nativeBootstrapClientCapture/v2" },
            "resultScope":if setup_installation_observation.is_some() { "local-authenticated-setup-ca-readback" }
                else { "local-fixed-endpoint-bootstrap-and-host-installation" },
            "okForAction":false,
            "configurationSha256":super::sha256_prefixed(&configuration_raw),
            "requestSha256":super::sha256_prefixed(&request_raw),
            "endpoint":config.endpoint.to_string(),
            "challengeSource":"independently-pinned",
            "evidenceBase64url":URL_SAFE_NO_PAD.encode(&evidence),
            "verification":json::parse(proof.diagnostic(), 4095)?,
            "installation":null,
        });
        if setup_installation_observation.is_some() { capture["setupInstallationObservationOriginal"] = serde_json::Value::Null; }
        recheck(&mut held, &mut private_original, &clock)?;
        return install::execute(pending, proof, connection, clock, held, private_original,
            &configuration_raw, capture, setup_installation_observation);
    }
    let verified = connection.verify_bootstrap(&evidence, &delegation_root, &delegation_pin,
        &setup_root, &setup_pin, &caller_issuer_der, &config.expected_caller_principal,
        &config.expected_target_principal, &config.expected_target_nonce,
        &config.expected_target_request_sha256, sent.delegation_original(),
        sent.setup_original(), sent.target_request_original())?;
    connection.check()?;
    let result = json!({
        "apiVersion":"catchplate.nativeBootstrapClientCapture/v1",
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
