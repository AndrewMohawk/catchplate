//! One fixed-endpoint native ingress evidence exchange, never arbitrary proxying.
//!
//! All file originals remain pinned/held through final publication. The private
//! TLS configuration is built only after startup-original verification; a new
//! full session then supplies fresh original evidence. Results stay local and
//! non-actionable. Blocking filesystem/stdout still needs an outer watchdog.

mod config;
mod http;
mod identity;
mod transport;
#[path = "../native_verifier/mod.rs"]
mod native_verifier;
#[path = "../native_verifier/json.rs"]
mod json;
#[path = "../native_startup_config/originals.rs"]
mod originals;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use config::{ConfigurationV1, MAX_CONFIGURATION_BYTES};
use originals::{ArtifactV1, HeldOriginal};
use rustls::pki_types::ServerName;
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

const MAX_CAPTURE: usize = 144 * 1024;

fn ensure(condition: bool, message: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.to_owned()) }
}

fn arguments() -> Result<ArtifactV1, String> {
    let mut arguments = std::env::args_os().skip(1);
    let mut path = None;
    let mut pin = None;
    for _ in 0..2 {
        let flag = arguments.next().ok_or("native client requires pinned configuration flags")?;
        let value = arguments.next().ok_or("native client flag requires a value")?;
        match flag.to_str() {
            Some("--configuration") if path.is_none() => {
                ensure(value.len() <= 4096, "native client configuration path exceeds its bound")?;
                let candidate = PathBuf::from(value);
                ensure(candidate.is_absolute(), "native client configuration path must be absolute")?;
                path = Some(candidate);
            }
            Some("--configuration-sha256") if pin.is_none() => {
                let candidate = value.into_string().map_err(|_| "native client pin is not UTF-8")?;
                ensure(super::is_sha256_digest(&candidate)
                    && candidate.as_bytes()[7..].iter().any(|byte| *byte != b'0'),
                    "native client configuration pin is invalid")?;
                pin = Some(candidate);
            }
            _ => return Err("native client flag is unknown or repeated".to_owned()),
        }
    }
    ensure(arguments.next().is_none(), "native client has extra arguments")?;
    Ok(ArtifactV1 { path: path.ok_or("native client configuration path is missing")?,
        sha256: pin.ok_or("native client configuration pin is missing")? })
}

fn live(deadline: Instant, pid: u32) -> Result<(), String> {
    ensure(std::process::id() == pid && Instant::now() < deadline,
        "native client original process or deadline ended")
}

fn read(artifact: ArtifactV1, bound: usize, deadline: Instant, pid: u32)
    -> Result<(HeldOriginal, Vec<u8>), String> {
    live(deadline, pid)?;
    let result = HeldOriginal::read(artifact, bound)?;
    live(deadline, pid)?;
    Ok(result)
}

fn recheck(held: &mut [&mut HeldOriginal], deadline: Instant, pid: u32) -> Result<(), String> {
    for original in held {
        live(deadline, pid)?;
        original.recheck()?;
        live(deadline, pid)?;
    }
    Ok(())
}

pub(super) fn run() -> Result<(), String> {
    let started = Instant::now();
    let pid = std::process::id();
    let (mut configuration_original, configuration_raw) =
        HeldOriginal::read(arguments()?, MAX_CONFIGURATION_BYTES)?;
    let config = ConfigurationV1::parse_original(&configuration_raw)?;
    let deadline = started.checked_add(config.timeout).ok_or("native client deadline overflow")?;
    live(deadline, pid)?;
    let (mut startup_original, startup) = read(config.startup_evidence, 64 * 1024, deadline, pid)?;
    let (mut startup_expectations_original, startup_expectations) =
        read(config.startup_expectations, 16 * 1024, deadline, pid)?;
    let (mut session_expectations_original, session_expectations) =
        read(config.session_expectations, 16 * 1024, deadline, pid)?;
    let (mut roots_original, roots) = read(config.trust_roots, 1024 * 1024, deadline, pid)?;
    let bootstrap = native_verifier::prepare_ingress_client(
        &startup, &startup_expectations, &session_expectations, &roots)?;
    live(deadline, pid)?;

    // No client private key is loaded or network contacted before the actual
    // startup quote/certificate and complete independent scope checks above.
    let (mut certificate_original, certificate_pem) =
        read(config.client_certificate, 64 * 1024, deadline, pid)?;
    live(deadline, pid)?;
    let (mut key_original, private_pem) = HeldOriginal::read_private(config.client_private_key, 16 * 1024)?;
    live(deadline, pid)?;
    key_original.require_private()?;
    let tls_config = identity::configuration(&bootstrap.ca, &certificate_pem, &private_pem)?;
    drop(private_pem);
    let name = ServerName::try_from(bootstrap.host.clone())
        .map_err(|_| "native client verified TLS name is invalid")?;
    let authority = if bootstrap.host.contains(':') {
        format!("[{}]:{}", bootstrap.host, config.endpoint.port())
    } else { format!("{}:{}", bootstrap.host, config.endpoint.port()) };
    recheck(&mut [&mut configuration_original, &mut startup_original,
        &mut startup_expectations_original, &mut session_expectations_original,
        &mut roots_original, &mut certificate_original, &mut key_original], deadline, pid)?;
    key_original.require_private()?;
    let mut connection = transport::connect(config.endpoint, tls_config, name, deadline)?;
    // Use only the verified startup's exact peer identity before sending the
    // attestation request. The fresh response later binds these same originals.
    let peers = connection.client().peer_certificates().ok_or("native client peer chain is absent")?;
    ensure(peers.len() == 2 && peers[0].as_ref() == bootstrap.leaf.as_slice()
        && peers[1].as_ref() == bootstrap.ca.as_slice(),
        "native client connected peer differs from verified startup originals")?;
    let evidence = http::exchange(&mut connection, &authority, bootstrap.challenge)?;
    let verified = native_verifier::verify_ingress_session(
        &evidence, &session_expectations, &roots, connection.client())?;
    connection.check()?;
    // Recheck startup freshness after the exchange. This initial bootstrap
    // does not silently extend the pinned 1..300 second age. Verdict timestamps
    // record these checks, not a transferable future admission window.
    let final_bootstrap = native_verifier::prepare_ingress_client(
        &startup, &startup_expectations, &session_expectations, &roots)?;
    connection.check()?;
    let result = json!({
        "apiVersion":"serverware.nativeIngressClientCapture/v1",
        "resultScope":"local-fixed-endpoint-session-and-quote-only", "okForAction":false,
        "configurationSha256":super::sha256_prefixed(&configuration_raw),
        "endpoint":config.endpoint.to_string(),
        "clientCertificateSha256":super::sha256_prefixed(&certificate_pem),
        "sessionEvidenceBase64url":URL_SAFE_NO_PAD.encode(&evidence),
        "startupVerification":final_bootstrap.verification,
        "sessionVerification":json::parse(&verified, 4095)?,
    });
    let mut encoded = serde_json::to_vec(&result).map_err(|_| "encode native client capture")?;
    ensure(!encoded.is_empty() && encoded.len() < MAX_CAPTURE
        && !encoded.contains(&b'\n') && !encoded.contains(&b'\r'),
        "native client capture exceeds its single-line bound")?;
    encoded.push(b'\n');
    recheck(&mut [&mut configuration_original, &mut startup_original,
        &mut startup_expectations_original, &mut session_expectations_original,
        &mut roots_original, &mut certificate_original, &mut key_original], deadline, pid)?;
    key_original.require_private()?;
    connection.check()?;
    // Public-only output; failure/expiry may leave a partial line, which is not
    // a successful receipt. The invoker must check exit status and own its IO.
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    live(deadline, pid)?;
    output.write_all(&encoded).map_err(|_| "write native client capture")?;
    output.flush().map_err(|_| "flush native client capture")?;
    connection.check()?;
    Ok(())
}
