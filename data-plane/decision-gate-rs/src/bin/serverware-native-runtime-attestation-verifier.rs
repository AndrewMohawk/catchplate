//! Purpose-fixed Runtime job. A trusted-host-local sealed signer is not TEE key
//! custody; hardwareAttested describes only the genuinely verified Nitro runtime.
#[path = "../policy_shadow.rs"]
mod policy_shadow;
#[path = "../policy_shadow_generation_publication_protocol.rs"]
mod policy_shadow_generation_publication_protocol;
#[path = "../native_verifier/mod.rs"]
mod native_verifier;
#[path = "../policy_shadow_runtime_attestation.rs"]
mod policy_shadow_runtime_attestation;

fn sha256_prefixed(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    use std::io::{Read, Write};
    use policy_shadow_runtime_attestation::{handle, Authority, MAX_INPUT};
    use serverware_decision_gate::native_shadow_workers::runtime_resources::JobResources;
    if std::env::args_os().count() != 1 || std::env::vars_os().count() != 3
        || std::env::var("LANG").as_deref() != Ok("C")
        || std::env::var("LC_ALL").as_deref() != Ok("C")
        || std::env::var("TZ").as_deref() != Ok("UTC") {
        return Err("runtime job invocation differs".into());
    }
    let resources = JobResources::admit()?;
    let mut original = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin().lock().take((MAX_INPUT + 1) as u64)
        .read_to_end(&mut original).map_err(|_| "runtime input unavailable")?;
    if original.is_empty() || original.len() > MAX_INPUT {
        return Err("runtime original input exceeds bound".into());
    }
    resources.require_input(&original)?;
    let pins = resources.pins();
    let check = || resources.check();
    let response = handle(&original, resources.policy_original(), resources.trust_roots_original(), Authority {
        key: resources.key(), key_id: &pins.key_id, key_spki_sha256: &pins.key_spki_sha256,
        policy_sha256: &pins.policy_sha256, trust_checkpoint_sha256: &pins.trust_checkpoint_sha256,
        revocation_generation: pins.revocation_generation, revocation_root_sha256: &pins.revocation_root_sha256,
        not_before_unix_nanos: pins.not_before_unix_nanos, not_after_unix_nanos: pins.not_after_unix_nanos,
        verifier_executable_sha256: &pins.verifier_executable_sha256, check: &check,
    })?;
    if resources.check()? >= response.expires_at_unix_nanos { return Err("runtime evidence expired".into()); }
    let mut output = std::io::stdout().lock();
    output.write_all(&response.original).and_then(|_| output.flush())
        .map_err(|_| "runtime output unavailable")?;
    if resources.check()? >= response.expires_at_unix_nanos { return Err("runtime evidence expired during output".into()); }
    Ok(())
}

#[cfg(target_os = "linux")]
fn main() {
    // A partial output or uncertain exit is failure. No diagnostic includes
    // originals, key material or a copied result, and there is no retry.
    if run().is_err() { std::process::exit(1); }
}
#[cfg(not(target_os = "linux"))]
fn main() { std::process::exit(1); }
