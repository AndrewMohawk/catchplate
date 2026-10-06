//! Purpose-fixed local-durability publication job, selected by the cold owner.
//! No key paths, environment configuration, resource creation or retry exists.
#[path = "../policy_shadow.rs"]
mod policy_shadow;
#[path = "../policy_shadow_generation_publication_protocol.rs"]
mod policy_shadow_generation_publication_protocol;
#[path = "../policy_shadow_generation_publication_handoff.rs"]
mod policy_shadow_generation_publication_handoff;

fn sha256_prefixed(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    use std::io::{Read, Write};
    use policy_shadow::Sha256Digest;
    use policy_shadow_generation_publication_handoff::{handle, Authority};
    use serverware_decision_gate::native_shadow_workers::publication_resources::JobResources;

    const MAX_INPUT: usize = 32 * 1024 * 1024;
    if std::env::args_os().count() != 1 || std::env::vars_os().count() != 3
        || std::env::var("LANG").as_deref() != Ok("C")
        || std::env::var("LC_ALL").as_deref() != Ok("C")
        || std::env::var("TZ").as_deref() != Ok("UTC") {
        return Err("publication job invocation differs".into());
    }
    let resources = JobResources::admit()?;
    let mut original = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin().lock().take((MAX_INPUT + 1) as u64)
        .read_to_end(&mut original).map_err(|_| "publication input unavailable")?;
    if original.is_empty() || original.len() > MAX_INPUT {
        return Err("publication input exceeds its original bound".into());
    }
    resources.check()?;
    let pins = resources.pins();
    let key_id = Sha256Digest::parse(pins.key_id.clone()).map_err(|_| "publication key pin invalid")?;
    let key_spki = Sha256Digest::parse(pins.key_spki_sha256.clone()).map_err(|_| "publication SPKI pin invalid")?;
    let replay_store = Sha256Digest::parse(pins.replay_store_sha256.clone()).map_err(|_| "publication store pin invalid")?;
    let check = || resources.check();
    let response = zeroize::Zeroizing::new(handle(&original, resources.store(), Authority {
        key: resources.key(), signing_key_id: &key_id, signing_key_spki_sha256: &key_spki,
        replay_store_sha256: &replay_store, journal_limit_bytes: resources.journal_limit_bytes(), check: &check,
        runtime_verification: resources.runtime_verification(),
    })?);
    resources.check()?;
    let mut output = std::io::stdout().lock();
    output.write_all(&response).map_err(|_| "publication response unavailable")?;
    output.flush().map_err(|_| "publication response flush unavailable")?;
    resources.check()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn main() {
    // No private input in diagnostics, synthetic success, replacement resource,
    // or second signing attempt. The owning worker fences uncertain outcomes.
    if run().is_err() { std::process::exit(1); }
}

#[cfg(not(target_os = "linux"))]
fn main() { std::process::exit(1); }
